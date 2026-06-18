## show.nim - Visualization subcommands.
##
## Provides:
##   showMatrix   - zone policy matrix (terminal)
##   showRules    - rules drill-down per zone pair (terminal)
##   showTopology - zone topology diagram (dot/d2/mermaid/ascii)
##   showJson     - full state as JSON

import std/[options, tables, strutils, json, sequtils]
import ./types
import ./writer

proc countRulesForPair(state: FirewallState, src, dst: string): int =
  for rule in state.rules:
    if rule.src.zone != nil and rule.dst.zone != nil:
      if rule.src.zone.name == src and rule.dst.zone.name == dst:
        inc result

# ---------------------------------------------------------------------------
# show matrix -- zone policy grid
# ---------------------------------------------------------------------------

proc showMatrix*(state: FirewallState): string =
  var w = newWriter()
  var zoneNames: seq[string]
  for name, zone in state.zones:
    zoneNames.add name

  type ZPKey = tuple[src, dst: string]
  var policyMap: Table[ZPKey, (Action, bool)]
  for pol in state.policies:
    if pol.src.zone == nil or pol.dst.zone == nil: continue
    policyMap[(pol.src.zone.name, pol.dst.zone.name)] = (pol.action, pol.log)

  var ruleCount: Table[ZPKey, int]
  for rule in state.rules:
    if rule.src.zone == nil or rule.dst.zone == nil: continue
    let key: ZPKey = (rule.src.zone.name, rule.dst.zone.name)
    ruleCount[key] = ruleCount.getOrDefault(key, 0) + 1

  let colW = max(10, zoneNames.mapIt(it.len).max + 2)

  # Header
  w.add "  " & "src \\ dst".alignLeft(colW)
  for dst in zoneNames:
    w.add dst.alignLeft(colW)
  w.emptyLine()
  w.add "  " & "-".repeat(colW)
  for dst in zoneNames:
    w.add "-".repeat(colW)
  w.emptyLine()

  # Rows
  for src in zoneNames:
    w.add "  " & src.alignLeft(colW)
    for dst in zoneNames:
      if src == dst:
        w.add "--".alignLeft(colW)
        continue
      let key: ZPKey = (src, dst)
      let rc = ruleCount.getOrDefault(key, 0)
      if key in policyMap:
        let (action, logged) = policyMap[key]
        var cell = case action
          of actAccept: "ACPT"
          of actDrop: "DROP"
          of actReject: "REJ"
        if logged: cell = "* " & cell
        if rc > 0: cell &= " " & $rc & "r"
        w.add cell.alignLeft(colW)
      else:
        var cell = "drop"
        if rc > 0: cell = $rc & "r"
        w.add cell.alignLeft(colW)
    w.emptyLine()

  w.emptyLine()
  w.line "  ACPT=accept  DROP=drop  REJ=reject  *=logged  Nr=N rules"
  return w.result

# ---------------------------------------------------------------------------
# show rules -- drill-down per zone pair
# ---------------------------------------------------------------------------

proc resolveZone(state: FirewallState, name: string): Zone =
  if name in state.zones: return state.zones[name]
  if name in state.hosts: return state.hosts[name].zone
  return nil

proc showRules*(state: FirewallState, srcName, dstName: string): string =
  let srcZone = state.resolveZone(srcName)
  if srcZone == nil:
    return "error: unknown zone or host: " & srcName & "\n"
  let dstZone = state.resolveZone(dstName)
  if dstZone == nil:
    return "error: unknown zone or host: " & dstName & "\n"

  var w = newWriter()

  var policyStr = "drop (default)"
  var policyLogged = false
  for pol in state.policies:
    if pol.src.zone == srcZone and pol.dst.zone == dstZone:
      policyStr = $pol.action
      policyLogged = pol.log
      break
  if policyLogged: policyStr &= ", logged"

  w.line "  " & srcName & " -> " & dstName & " (policy: " & policyStr & ")"
  w.line "  " & "-".repeat(40)

  var idx = 0
  for rule in state.rules:
    if rule.src.zone != srcZone or rule.dst.zone != dstZone: continue
    inc idx
    var parts: seq[string]
    parts.add $idx & "."
    parts.add alignLeft($rule.action, 8)
    if rule.src.host.isSome: parts.add "from:" & rule.src.host.get.name
    if rule.dst.host.isSome: parts.add "to:" & rule.dst.host.get.name
    if rule.saddrList != "": parts.add "saddr @" & rule.saddrList
    if rule.service.isSome:
      let svc = rule.service.get
      var desc = svc.name & " ("
      for i, e in svc.entries:
        if i > 0: desc &= ", "
        desc &= e.proto
        if e.port != "": desc &= "/" & e.port
      desc &= ")"
      parts.add desc
    elif rule.proto.len > 0:
      for proto in rule.proto:
        var desc = proto
        if rule.port.len > 0: desc &= "/" & rule.port.join(",")
        parts.add desc
    if rule.rate.isSome: parts.add "rate:" & rule.rate.get.rate
    if rule.log != "": parts.add "log:" & rule.log
    w.line "  " & parts.join("  ")

  if idx == 0:
    w.line "  (no explicit rules)"

  return w.result

# ---------------------------------------------------------------------------
# show topology -- diagram output
# ---------------------------------------------------------------------------

proc showTopologyDot*(state: FirewallState): string =
  var w = newWriter()
  w.line "digraph matchstick {"
  w.line "    rankdir=LR;"
  w.line "    node [shape=box, style=\"rounded,filled\", fontname=\"sans-serif\"];"
  w.line "    edge [fontname=\"sans-serif\", fontsize=10];"
  w.emptyLine()

  for name, zone in state.zones:
    let color = if zone.interfaces.len == 0: "#ffffcc"
                elif name.contains("inet") or name.contains("wan"): "#ffcccc"
                elif name.contains("dock"): "#ccccff"
                else: "#ccffcc"
    let ifaces = if zone.interfaces.len > 0: "\\n" & zone.interfaces.join(", ")
                 else: "\\n(local)"
    w.line "    " & name & " [fillcolor=\"" & color & "\", label=\"" & name & ifaces & "\"];"

  w.emptyLine()

  for pol in state.policies:
    if pol.src.zone == nil or pol.dst.zone == nil: continue
    let src = pol.src.zone.name
    let dst = pol.dst.zone.name
    if src == dst: continue
    let (color, style, label) = case pol.action
      of actAccept: ("green", "solid", "ACCEPT")
      of actDrop: ("red", "dashed", "DROP")
      of actReject: ("orange", "dashed", "REJECT")
    let rc = countRulesForPair(state, src, dst)
    var edgeLabel = label
    if rc > 0: edgeLabel &= " (" & $rc & " rules)"
    w.line "    " & src & " -> " & dst & " [label=\"" & edgeLabel &
         "\", color=" & color & ", style=" & style & "];"

  w.line "}"
  return w.result

proc showTopologyMermaid*(state: FirewallState): string =
  var w = newWriter()
  w.line "graph LR"

  for name, zone in state.zones:
    let ifaces = if zone.interfaces.len > 0: "<br/>" & zone.interfaces.join(", ")
                 else: "<br/>local"
    w.line "    " & name & "[" & name & ifaces & "]"

  w.emptyLine()

  for pol in state.policies:
    if pol.src.zone == nil or pol.dst.zone == nil: continue
    let src = pol.src.zone.name
    let dst = pol.dst.zone.name
    if src == dst: continue
    let arrow = case pol.action
      of actAccept: " -->|ACCEPT| "
      of actDrop: " -.->|DROP| "
      of actReject: " -.->|REJECT| "
    w.line "    " & src & arrow & dst

  return w.result

proc showTopologyD2*(state: FirewallState): string =
  var w = newWriter()
  for name, zone in state.zones:
    let fillColor = if zone.interfaces.len == 0: "#ffffcc"
                    elif name.contains("inet") or name.contains("wan"): "#ffcccc"
                    elif name.contains("dock"): "#ccccff"
                    else: "#ccffcc"
    let ifaces = if zone.interfaces.len > 0: zone.interfaces.join(", ")
                 else: "local"
    w.line name & ": " & name & " (" & ifaces & ") {"
    w.line "  style.fill: \"" & fillColor & "\""
    w.line "}"
    w.emptyLine()

  for pol in state.policies:
    if pol.src.zone == nil or pol.dst.zone == nil: continue
    let src = pol.src.zone.name
    let dst = pol.dst.zone.name
    if src == dst: continue
    let rc = countRulesForPair(state, src, dst)
    let label = $pol.action & (if rc > 0: " (" & $rc & " rules)" else: "")
    let strokeColor = case pol.action
      of actAccept: "green"
      of actDrop: "red"
      of actReject: "orange"
    w.line src & " -> " & dst & ": " & label & " {"
    w.line "  style.stroke: " & strokeColor
    if pol.action in {actDrop, actReject}:
      w.line "  style.stroke-dash: 3"
    w.line "}"

  return w.result

proc showTopologyAscii*(state: FirewallState): string =
  var w = newWriter()
  var zoneNames: seq[string]
  for name, zone in state.zones:
    zoneNames.add name

  w.emptyLine()
  w.line "  Zones:"
  w.line "  ┌─────────────────────────────────────────────────┐"
  for name, zone in state.zones:
    let ifaces = if zone.interfaces.len > 0: zone.interfaces.join(", ")
                 else: "(local)"
    let prefix = "  │  [" & name & "]"
    w.line prefix & " ".repeat(max(1, 50 - prefix.len - ifaces.len)) & ifaces & " │"
  w.line "  └─────────────────────────────────────────────────┘"

  w.emptyLine()
  w.line "  Traffic Flow:"
  w.emptyLine()

  var accepts, drops, rejects: seq[string]
  for pol in state.policies:
    if pol.src.zone == nil or pol.dst.zone == nil: continue
    let src = pol.src.zone.name
    let dst = pol.dst.zone.name
    let rc = countRulesForPair(state, src, dst)
    var detail = ""
    if rc > 0: detail = " (" & $rc & " rules)"
    if pol.log: detail &= " [logged]"
    let arrow = case pol.action
      of actAccept: " ──▶ "
      of actDrop:   " ──╳ "
      of actReject: " ──! "
    let entry = "    " & src.alignLeft(6) & arrow
    let line = entry & dst.alignLeft(6) & " " & ($pol.action).alignLeft(8) & detail
    case pol.action
    of actAccept: accepts.add line
    of actDrop: drops.add line
    of actReject: rejects.add line

  if accepts.len > 0:
    w.line "  ── Allowed ──────────────────────────────────────"
    for line in accepts: w.line line
  if drops.len > 0:
    w.line "  ── Dropped ──────────────────────────────────────"
    for line in drops: w.line line
  if rejects.len > 0:
    w.line "  ── Rejected ─────────────────────────────────────"
    for line in rejects: w.line line
  w.emptyLine()

  return w.result

# ---------------------------------------------------------------------------
# show json -- full state dump
# ---------------------------------------------------------------------------

proc showStateJson*(state: FirewallState): string =
  var root = newJObject()

  var zones = newJArray()
  for name, zone in state.zones:
    zones.add %*{"name": name, "interfaces": zone.interfaces, "bridge": zone.bridge}
  root["zones"] = zones

  var hosts = newJArray()
  for name, host in state.hosts:
    hosts.add %*{"name": name, "zone": host.zone.name, "addr4": host.addr4}
  root["hosts"] = hosts

  var services = newJArray()
  for name, svc in state.services:
    var entries = newJArray()
    for e in svc.entries:
      entries.add %*{"proto": e.proto, "port": e.port}
    services.add %*{"name": name, "entries": entries}
  root["services"] = services

  var policies = newJArray()
  for pol in state.policies:
    var p = newJObject()
    if pol.src.zone != nil: p["from"] = newJString(pol.src.zone.name)
    if pol.dst.zone != nil: p["to"] = newJString(pol.dst.zone.name)
    p["action"] = newJString($pol.action)
    p["log"] = newJBool(pol.log)
    policies.add p
  root["policies"] = policies

  var rules = newJArray()
  for rule in state.rules:
    var r = newJObject()
    if rule.src.zone != nil: r["from_zone"] = newJString(rule.src.zone.name)
    if rule.src.host.isSome: r["from_host"] = newJString(rule.src.host.get.name)
    if rule.dst.zone != nil: r["to_zone"] = newJString(rule.dst.zone.name)
    if rule.dst.host.isSome: r["to_host"] = newJString(rule.dst.host.get.name)
    r["action"] = newJString($rule.action)
    if rule.service.isSome: r["service"] = newJString(rule.service.get.name)
    if rule.proto.len > 0: r["proto"] = %rule.proto
    if rule.port.len > 0: r["port"] = %rule.port
    if rule.saddrList != "": r["saddr_list"] = newJString(rule.saddrList)
    if rule.log != "": r["log"] = newJString(rule.log)
    rules.add r
  root["rules"] = rules

  var dnats = newJArray()
  for dnat in state.dnatRules:
    var d = newJObject()
    d["iface"] = newJString(dnat.iface.name)
    if dnat.daddr != "": d["daddr"] = newJString(dnat.daddr)
    if dnat.service.isSome: d["service"] = newJString(dnat.service.get.name)
    if dnat.proto.len > 0: d["proto"] = %dnat.proto
    if dnat.port.len > 0: d["port"] = %dnat.port
    d["dest"] = newJString(dnat.dest)
    if dnat.destPort > 0: d["dest_port"] = newJInt(dnat.destPort)
    dnats.add d
  root["dnat"] = dnats

  var snats = newJArray()
  for snat in state.snatRules:
    var s = newJObject()
    s["from"] = newJString(snat.fromNet)
    if snat.daddr != "": s["daddr"] = newJString(snat.daddr)
    s["oif"] = newJString(snat.oif)
    if snat.masquerade: s["masquerade"] = newJBool(true)
    if snat.addr4 != "": s["addr"] = newJString(snat.addr4)
    if snat.proto != "": s["proto"] = newJString(snat.proto)
    if snat.port.len > 0: s["port"] = %snat.port
    snats.add s
  root["snat"] = snats

  var iplists = newJArray()
  for name, ipl in state.ipLists:
    iplists.add %*{"name": name, "type": ipl.ipType, "flags": ipl.flags, "elements": ipl.elements}
  root["iplists"] = iplists

  root["config"] = %*{
    "table_name": state.config.tableName,
    "priority_offset": state.config.priorityOffset,
    "log_rate": state.config.logRate,
    "log_prefix": state.config.logPrefix,
    "log_level": state.config.logLevel,
    "family": state.config.family,
    "log_set_size": state.config.logSetSize,
    "log_set_timeout": state.config.logSetTimeout,
    "counter": state.config.counter,
    "input_policy": state.config.inputPolicy,
    "output_policy": state.config.outputPolicy,
  }

  return root.pretty() & "\n"
