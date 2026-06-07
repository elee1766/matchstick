## validate.nim - Validation logic for FirewallState.
##
## Runs after Lua config evaluation, before building the IR.
## Checks for:
##   - Shadowed rules (later rule can never fire due to earlier broader rule)
##   - Structural issues (empty zones, missing forward rules for DNAT, etc.)
##   - Port range validity
##   - Protocol validity

import std/[options, tables, strutils]
import ./types

type
  Severity* = enum
    svWarning = "warning"
    svError = "error"

  ValidationMsg* = object
    severity*: Severity
    msg*: string
    line*: int

proc validate*(state: FirewallState): seq[ValidationMsg] =
  var msgs: seq[ValidationMsg]

  # ------------------------------------------------------------------
  # Check: exactly one fw zone (no interfaces) must exist
  # ------------------------------------------------------------------
  var fwZoneCount = 0
  for name, zone in state.zones:
    if zone.interfaces.len == 0:
      fwZoneCount += 1
  if fwZoneCount == 0:
    msgs.add ValidationMsg(severity: svError,
      msg: "no fw zone defined (need exactly one zone with no interfaces, e.g. fw:zone(\"fw\"))",
      line: 0)
  elif fwZoneCount > 1:
    msgs.add ValidationMsg(severity: svError,
      msg: "multiple fw zones defined (only one zone with no interfaces is allowed)",
      line: 0)

  # ------------------------------------------------------------------
  # Check: duplicate interfaces across zones
  # ------------------------------------------------------------------
  for name, zone in state.zones:
    for name2, zone2 in state.zones:
      if name == name2: continue
      for iface in zone.interfaces:
        if iface in zone2.interfaces:
          msgs.add ValidationMsg(
            severity: svError,
            msg: "interface \"" & iface & "\" is in both zone \"" & name &
                 "\" and zone \"" & name2 & "\"",
            line: zone.line,
          )

  # ------------------------------------------------------------------
  # Check: DHCP zones must have interfaces
  # ------------------------------------------------------------------
  for dc in state.dhcp:
    if dc.zone.interfaces.len == 0:
      msgs.add ValidationMsg(
        severity: svError,
        msg: "fw:dhcp: zone \"" & dc.zone.name & "\" has no interfaces",
        line: dc.line,
      )

  # ------------------------------------------------------------------
  # Check: port validity in services
  # ------------------------------------------------------------------
  for name, svc in state.services:
    for entry in svc.entries:
      if entry.proto in ["icmp", "icmpv6"]:
        continue  # ICMP types are strings, not port numbers
      if entry.port == "":
        continue
      if '-' in entry.port:
        let parts = entry.port.split('-')
        if parts.len != 2:
          msgs.add ValidationMsg(severity: svError,
            msg: "service \"" & name & "\": invalid port range \"" & entry.port & "\"",
            line: svc.line)
        else:
          try:
            let lo = parseInt(parts[0])
            let hi = parseInt(parts[1])
            if lo > hi:
              msgs.add ValidationMsg(severity: svError,
                msg: "service \"" & name & "\": port range start > end: " & entry.port,
                line: svc.line)
            if lo < 1 or hi > 65535:
              msgs.add ValidationMsg(severity: svError,
                msg: "service \"" & name & "\": port out of range (1-65535): " & entry.port,
                line: svc.line)
          except ValueError:
            msgs.add ValidationMsg(severity: svError,
              msg: "service \"" & name & "\": non-numeric port: " & entry.port,
              line: svc.line)
      else:
        try:
          let p = parseInt(entry.port)
          if p < 1 or p > 65535:
            msgs.add ValidationMsg(severity: svError,
              msg: "service \"" & name & "\": port out of range: " & $p,
              line: svc.line)
        except ValueError:
          discard  # could be a named port like "echo-request"

  # ------------------------------------------------------------------
  # Check: protocol validity
  # ------------------------------------------------------------------
  let validProtos = ["tcp", "udp", "icmp", "icmpv6"]
  for name, svc in state.services:
    for entry in svc.entries:
      if entry.proto notin validProtos:
        msgs.add ValidationMsg(severity: svError,
          msg: "service \"" & name & "\": unknown protocol \"" & entry.proto & "\"",
          line: svc.line)

  for rule in state.rules:
    for proto in rule.proto:
      if proto notin validProtos:
        msgs.add ValidationMsg(severity: svError,
          msg: "rule: unknown protocol \"" & proto & "\"",
          line: rule.line)

  # ------------------------------------------------------------------
  # Check: SNAT masquerade/addr mutual exclusivity (already checked in lua_vm,
  # but double-check here)
  # ------------------------------------------------------------------
  for snat in state.snatRules:
    if snat.masquerade and snat.addr4 != "":
      msgs.add ValidationMsg(severity: svError,
        msg: "fw:snat: 'masquerade' and 'addr' are mutually exclusive",
        line: snat.line)
    if snat.port.len > 0 and snat.proto == "":
      msgs.add ValidationMsg(severity: svError,
        msg: "fw:snat: 'port' requires 'proto'",
        line: snat.line)

  # ------------------------------------------------------------------
  # Check: iplist references in rules must exist
  # ------------------------------------------------------------------
  for rule in state.rules:
    if rule.saddrList != "" and rule.saddrList notin state.ipLists:
      msgs.add ValidationMsg(severity: svError,
        msg: "rule references unknown iplist (saddr_list) \"" & rule.saddrList & "\"",
        line: rule.line)
    if rule.daddrList != "" and rule.daddrList notin state.ipLists:
      msgs.add ValidationMsg(severity: svError,
        msg: "rule references unknown iplist (daddr_list) \"" & rule.daddrList & "\"",
        line: rule.line)

  # ------------------------------------------------------------------
  # Check: connlimit must be positive if set
  # ------------------------------------------------------------------
  for rule in state.rules:
    if rule.connLimit < 0:
      msgs.add ValidationMsg(severity: svError,
        msg: "rule has negative connlimit: " & $rule.connLimit,
        line: rule.line)

  # ------------------------------------------------------------------
  # Check: redirect rules
  # ------------------------------------------------------------------
  for redir in state.redirectRules:
    if redir.iface == nil:
      msgs.add ValidationMsg(severity: svError,
        msg: "fw:redirect: missing iface", line: redir.line)
    elif redir.iface.interfaces.len == 0:
      msgs.add ValidationMsg(severity: svError,
        msg: "fw:redirect: zone \"" & redir.iface.name & "\" has no interfaces",
        line: redir.line)
    if redir.destPort < 1 or redir.destPort > 65535:
      msgs.add ValidationMsg(severity: svError,
        msg: "fw:redirect: dest_port out of range (1-65535): " & $redir.destPort,
        line: redir.line)
    if redir.proto.len == 0:
      msgs.add ValidationMsg(severity: svError,
        msg: "fw:redirect: missing proto", line: redir.line)

  # ------------------------------------------------------------------
  # Check: DNAT rules should have corresponding forward ACCEPT rules
  # ------------------------------------------------------------------
  for dnat in state.dnatRules:
    if dnat.iface == nil: continue
    # Find the destination zone (zone containing the dest host)
    var destZone: Zone
    for name, host in state.hosts:
      if host.addr4 == dnat.dest:
        destZone = host.zone
        break
    if destZone == nil:
      # dest is a raw IP not mapped to a host -- can't verify forward rules
      continue
    # Check if there's a forward rule or accept policy from iface zone to dest zone
    var hasForward = false
    for pol in state.policies:
      if pol.src.zone == dnat.iface and pol.dst.zone == destZone and pol.action == actAccept:
        hasForward = true
        break
    if not hasForward:
      for rule in state.rules:
        if rule.src.zone == dnat.iface and rule.dst.zone == destZone and rule.action == actAccept:
          hasForward = true
          break
    if not hasForward:
      msgs.add ValidationMsg(severity: svWarning,
        msg: "fw:dnat to " & dnat.dest & " via zone \"" & dnat.iface.name &
             "\" has no corresponding forward ACCEPT rule/policy to zone \"" &
             destZone.name & "\"",
        line: dnat.line)

  # ------------------------------------------------------------------
  # Check: zone and interface name validity (Linux naming rules)
  # ------------------------------------------------------------------
  # Linux interface names: max 15 chars, alphanumeric + hyphen + underscore + dot
  # nftables chain names: alphanumeric + underscore + hyphen + dot
  proc isValidIdentifier(s: string, maxLen: int): bool =
    if s.len == 0 or s.len > maxLen: return false
    for c in s:
      if c notin {'a'..'z', 'A'..'Z', '0'..'9', '_', '-', '.'}:
        return false
    return true

  for name, zone in state.zones:
    if not isValidIdentifier(name, 64):
      msgs.add ValidationMsg(severity: svError,
        msg: "zone name \"" & name & "\" is invalid (must be 1-64 chars, alphanumeric/hyphen/underscore/dot)",
        line: zone.line)
    for iface in zone.interfaces:
      if not isValidIdentifier(iface, 15):
        msgs.add ValidationMsg(severity: svError,
          msg: "interface \"" & iface & "\" in zone \"" & name &
               "\" is invalid (must be 1-15 chars, alphanumeric/hyphen/underscore/dot)",
          line: zone.line)

  for name, host in state.hosts:
    if not isValidIdentifier(name, 64):
      msgs.add ValidationMsg(severity: svError,
        msg: "host name \"" & name & "\" is invalid (must be 1-64 chars, alphanumeric/hyphen/underscore/dot)",
        line: host.line)

  # ------------------------------------------------------------------
  # Shadow detection
  # ------------------------------------------------------------------

  proc endpointShadows(earlier, later: Endpoint): bool =
    ## Does `earlier` endpoint shadow (match a superset of) `later`?
    if earlier.host.isNone and later.host.isSome:
      return later.zone == earlier.zone  # zone shadows host in that zone
    elif earlier.host.isNone and later.host.isNone:
      return true  # same zone
    elif earlier.host.isSome and later.host.isSome:
      return earlier.host.get.name == later.host.get.name
    return false
  # Group rules by zone pair (src zone name, dst zone name)
  type ZPKey = tuple[src, dst: string]
  var rulesByPair: Table[ZPKey, seq[Rule]]
  for rule in state.rules:
    if rule.src.zone == nil or rule.dst.zone == nil: continue
    let key: ZPKey = (rule.src.zone.name, rule.dst.zone.name)
    if key notin rulesByPair:
      rulesByPair[key] = @[]
    rulesByPair[key].add rule

  for key, rules in rulesByPair:
    for i in 0 ..< rules.len:
      for j in (i+1) ..< rules.len:
        let earlier = rules[i]
        let later = rules[j]

        # Check if later is shadowed by earlier:
        # 1. earlier's source is same or broader (zone vs host-in-zone)
        # 2. services/ports overlap
        # 3. same or broader action scope

        var portShadowed = false

        let srcShadowed = endpointShadows(earlier.src, later.src)
        let dstShadowed = endpointShadows(earlier.dst, later.dst)

        # Port/service overlap check
        # Rules with saddr_list are specific to that list -- don't shadow
        # unless the later rule also has the same saddr_list
        if earlier.saddrList != "" and later.saddrList != earlier.saddrList:
          continue  # different IP lists, not a shadow
        if later.saddrList != "" and earlier.saddrList != later.saddrList:
          continue

        # If earlier has no service/proto filter and no saddr_list, it matches everything
        if earlier.service.isNone and earlier.proto.len == 0 and earlier.saddrList == "":
          portShadowed = true
        elif earlier.service.isSome and later.service.isSome:
          if earlier.service.get.name == later.service.get.name:
            portShadowed = true
        elif earlier.proto == later.proto and earlier.port == later.port:
          if earlier.proto.len > 0:  # both have same non-empty proto/port
            portShadowed = true

        if srcShadowed and dstShadowed and portShadowed:
          msgs.add ValidationMsg(
            severity: svWarning,
            msg: "rule at line " & $later.line & " is shadowed by rule at line " &
                 $earlier.line & " (in " & key.src & " -> " & key.dst & ")",
            line: later.line,
          )

  return msgs
