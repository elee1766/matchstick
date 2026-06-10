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

const
  nftNameChars = {'a'..'z', 'A'..'Z', '0'..'9', '_', '-'}
  nftTokenChars = {'a'..'z', 'A'..'Z', '0'..'9', '_', '-', '.', ':', '/'}
  validProtos = ["tcp", "udp", "icmp", "icmpv6"]
  validIplistTypes = ["ipv4", "ipv6"]
  validIplistFlags = ["interval", "timeout", "dynamic"]

type
  Severity* = enum
    svWarning = "warning"
    svError = "error"

  ValidationMsg* = object
    severity*: Severity
    msg*: string
    line*: int

proc isSafeNftName(s: string): bool =
  if s.len == 0 or s.len > 64: return false
  for c in s:
    if c notin nftNameChars: return false
  true

proc isSafeNftToken(s: string): bool =
  if s.len == 0 or s.len > 128: return false
  for c in s:
    if c notin nftTokenChars: return false
  true

proc isPortOrRange(s: string): bool =
  if s.len == 0: return false
  let parts = s.split('-')
  if parts.len notin 1..2: return false
  try:
    let lo = parseInt(parts[0])
    let hi = if parts.len == 2: parseInt(parts[1]) else: lo
    return lo >= 1 and hi <= 65535 and lo <= hi
  except ValueError:
    return false

proc addError(msgs: var seq[ValidationMsg], msg: string, line: int) =
  msgs.add ValidationMsg(severity: svError, msg: msg, line: line)

proc validateTransportPorts(msgs: var seq[ValidationMsg], ctx, proto: string, ports: seq[string], line: int) =
  if proto notin ["tcp", "udp"]: return
  for port in ports:
    if not isPortOrRange(port):
      msgs.addError(ctx & ": invalid " & proto & " port/range \"" & port & "\" (must be 1-65535 or lo-hi)", line)

proc validateIcmpTypes(msgs: var seq[ValidationMsg], ctx, proto: string, ports: seq[string], line: int) =
  if proto notin ["icmp", "icmpv6"]: return
  for typ in ports:
    if not isSafeNftName(typ):
      msgs.addError(ctx & ": invalid " & proto & " type \"" & typ & "\"", line)

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
  # Check: port/token validity in services
  # ------------------------------------------------------------------
  for name, svc in state.services:
    if not isSafeNftName(name):
      msgs.addError("service name \"" & name & "\" is invalid", svc.line)
    for entry in svc.entries:
      if entry.proto notin validProtos:
        msgs.add ValidationMsg(severity: svError,
          msg: "service \"" & name & "\": unknown protocol \"" & entry.proto & "\"",
          line: svc.line)
        continue
      if entry.proto in ["icmp", "icmpv6"]:
        validateIcmpTypes(msgs, "service \"" & name & "\"", entry.proto, @[entry.port], svc.line)
        continue
      if not isPortOrRange(entry.port):
        msgs.addError("service \"" & name & "\": invalid " & entry.proto &
          " port/range \"" & entry.port & "\" (must be 1-65535 or lo-hi)", svc.line)

  # ------------------------------------------------------------------
  # Check: protocol validity
  # ------------------------------------------------------------------
  for rule in state.rules:
    for proto in rule.proto:
      if proto notin validProtos:
        msgs.add ValidationMsg(severity: svError,
          msg: "rule: unknown protocol \"" & proto & "\"",
          line: rule.line)
      validateTransportPorts(msgs, "rule", proto, rule.port, rule.line)
      validateIcmpTypes(msgs, "rule", proto, rule.port, rule.line)

  # ------------------------------------------------------------------
  # Check: NAT, redirect, and iplist fields are safe nftables atoms
  # ------------------------------------------------------------------
  for name, ipl in state.ipLists:
    if not isSafeNftName(name):
      msgs.addError("iplist name \"" & name & "\" is invalid", ipl.line)
    if ipl.ipType notin validIplistTypes:
      msgs.addError("iplist \"" & name & "\": type must be ipv4 or ipv6", ipl.line)
    if ipl.flags != "":
      for flag in ipl.flags.split(','):
        let f = flag.strip()
        if f notin validIplistFlags:
          msgs.addError("iplist \"" & name & "\": invalid flag \"" & f & "\"", ipl.line)
    for elem in ipl.elements:
      if not isSafeNftToken(elem):
        msgs.addError("iplist \"" & name & "\": invalid element \"" & elem & "\"", ipl.line)

  for dnat in state.dnatRules:
    if dnat.daddr != "" and not isSafeNftToken(dnat.daddr):
      msgs.addError("fw:dnat: invalid daddr \"" & dnat.daddr & "\"", dnat.line)
    if dnat.dest != "" and not isSafeNftToken(dnat.dest):
      msgs.addError("fw:dnat: invalid dest \"" & dnat.dest & "\"", dnat.line)
    if dnat.destPort < 0 or dnat.destPort > 65535:
      msgs.addError("fw:dnat: dest_port out of range (1-65535): " & $dnat.destPort, dnat.line)
    for proto in dnat.proto:
      if proto notin validProtos:
        msgs.addError("fw:dnat: unknown protocol \"" & proto & "\"", dnat.line)
      validateTransportPorts(msgs, "fw:dnat", proto, dnat.port, dnat.line)
      validateIcmpTypes(msgs, "fw:dnat", proto, dnat.port, dnat.line)

  for snat in state.snatRules:
    for (field, value) in [("from", snat.fromNet), ("daddr", snat.daddr), ("oif", snat.oif), ("addr", snat.addr4)]:
      if value != "" and not isSafeNftToken(value):
        msgs.addError("fw:snat: invalid " & field & " \"" & value & "\"", snat.line)
    if snat.proto != "" and snat.proto notin validProtos:
      msgs.addError("fw:snat: unknown protocol \"" & snat.proto & "\"", snat.line)
    validateTransportPorts(msgs, "fw:snat", snat.proto, snat.port, snat.line)

  for redir in state.redirectRules:
    for proto in redir.proto:
      if proto notin ["tcp", "udp"]:
        msgs.addError("fw:redirect: protocol must be tcp or udp, got \"" & proto & "\"", redir.line)
      validateTransportPorts(msgs, "fw:redirect", proto, redir.port, redir.line)

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
