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
import ./ipaddr

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

proc isValidIdentifier(s: string, maxLen: int): bool =
  if s.len == 0 or s.len > maxLen: return false
  for c in s:
    if c notin {'a'..'z', 'A'..'Z', '0'..'9', '_', '-', '.'}:
      return false
  return true

proc checkIpv6Addr(msgs: var seq[ValidationMsg], value, ctx: string, line: int) =
  if value != "" and isIpv6(value) and not validateIpv6(value):
    msgs.addError(ctx & ": invalid IPv6 address \"" & value & "\"", line)

proc validateStructure(msgs: var seq[ValidationMsg], state: FirewallState) =
  ## Structural checks: zones, interfaces, DHCP, redirects, connlimit.
  var fwZoneCount = 0
  for name, zone in state.zones:
    if zone.interfaces.len == 0: fwZoneCount += 1
  if fwZoneCount == 0:
    msgs.addError("no fw zone defined (need exactly one zone with no interfaces, e.g. fw:zone(\"fw\"))", 0)
  elif fwZoneCount > 1:
    msgs.addError("multiple fw zones defined (only one zone with no interfaces is allowed)", 0)

  for name, zone in state.zones:
    if not isValidIdentifier(name, 64):
      msgs.addError("zone name \"" & name & "\" is invalid (must be 1-64 chars, alphanumeric/hyphen/underscore/dot)", zone.line)
    for iface in zone.interfaces:
      if not isValidIdentifier(iface, 15):
        msgs.addError("interface \"" & iface & "\" in zone \"" & name &
             "\" is invalid (must be 1-15 chars, alphanumeric/hyphen/underscore/dot)", zone.line)
    for name2, zone2 in state.zones:
      if name == name2: continue
      for iface in zone.interfaces:
        if iface in zone2.interfaces:
          msgs.addError("interface \"" & iface & "\" is in both zone \"" & name &
               "\" and zone \"" & name2 & "\"", zone.line)

  for name, host in state.hosts:
    if not isValidIdentifier(name, 64):
      msgs.addError("host name \"" & name & "\" is invalid (must be 1-64 chars, alphanumeric/hyphen/underscore/dot)", host.line)

  for dc in state.dhcp:
    if dc.zone.interfaces.len == 0:
      msgs.addError("fw:dhcp: zone \"" & dc.zone.name & "\" has no interfaces", dc.line)

  for rule in state.rules:
    if rule.connLimit < 0:
      msgs.addError("rule has negative connlimit: " & $rule.connLimit, rule.line)
    if rule.saddrList != "" and rule.saddrList notin state.ipLists:
      msgs.addError("rule references unknown iplist (saddr_list) \"" & rule.saddrList & "\"", rule.line)
    if rule.daddrList != "" and rule.daddrList notin state.ipLists:
      msgs.addError("rule references unknown iplist (daddr_list) \"" & rule.daddrList & "\"", rule.line)

  for redir in state.redirectRules:
    if redir.iface == nil:
      msgs.addError("fw:redirect: missing iface", redir.line)
    elif redir.iface.interfaces.len == 0:
      msgs.addError("fw:redirect: zone \"" & redir.iface.name & "\" has no interfaces", redir.line)
    if redir.destPort < 1 or redir.destPort > 65535:
      msgs.addError("fw:redirect: dest_port out of range (1-65535): " & $redir.destPort, redir.line)
    if redir.proto.len == 0:
      msgs.addError("fw:redirect: missing proto", redir.line)

proc validateProtos(msgs: var seq[ValidationMsg], state: FirewallState) =
  ## Protocol, port, and token validity for services, rules, NAT, iplists.
  for name, svc in state.services:
    if not isSafeNftName(name):
      msgs.addError("service name \"" & name & "\" is invalid", svc.line)
    for entry in svc.entries:
      if entry.proto notin validProtos:
        msgs.addError("service \"" & name & "\": unknown protocol \"" & entry.proto & "\"", svc.line)
        continue
      if entry.proto in ["icmp", "icmpv6"]:
        validateIcmpTypes(msgs, "service \"" & name & "\"", entry.proto, @[entry.port], svc.line)
        continue
      if not isPortOrRange(entry.port):
        msgs.addError("service \"" & name & "\": invalid " & entry.proto &
          " port/range \"" & entry.port & "\" (must be 1-65535 or lo-hi)", svc.line)

  for rule in state.rules:
    for proto in rule.proto:
      if proto notin validProtos:
        msgs.addError("rule: unknown protocol \"" & proto & "\"", rule.line)
      validateTransportPorts(msgs, "rule", proto, rule.port, rule.line)
      validateIcmpTypes(msgs, "rule", proto, rule.port, rule.line)

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
    if snat.masquerade and snat.addr4 != "":
      msgs.addError("fw:snat: 'masquerade' and 'addr' are mutually exclusive", snat.line)
    if snat.port.len > 0 and snat.proto == "":
      msgs.addError("fw:snat: 'port' requires 'proto'", snat.line)
    validateTransportPorts(msgs, "fw:snat", snat.proto, snat.port, snat.line)

  for redir in state.redirectRules:
    for proto in redir.proto:
      if proto notin ["tcp", "udp"]:
        msgs.addError("fw:redirect: protocol must be tcp or udp, got \"" & proto & "\"", redir.line)
      validateTransportPorts(msgs, "fw:redirect", proto, redir.port, redir.line)

proc validateAddresses(msgs: var seq[ValidationMsg], state: FirewallState) =
  ## IPv6 validation and match-all CIDR warnings.
  for name, ipl in state.ipLists:
    if ipl.ipType == "ipv6":
      for elem in ipl.elements:
        if not validateIpv6(elem):
          msgs.addError("iplist \"" & name & "\": invalid IPv6 address/CIDR \"" & elem & "\"", ipl.line)
    for elem in ipl.elements:
      if elem == "0.0.0.0/0" or elem == "::/0":
        msgs.add ValidationMsg(severity: svWarning,
          msg: "iplist \"" & name & "\" contains match-all CIDR \"" & elem &
               "\" — this matches ALL traffic", line: ipl.line)

  for name, host in state.hosts:
    msgs.checkIpv6Addr(host.addr4, "host \"" & name & "\"", host.line)

  for dnat in state.dnatRules:
    msgs.checkIpv6Addr(dnat.daddr, "fw:dnat daddr", dnat.line)
    msgs.checkIpv6Addr(dnat.dest, "fw:dnat dest", dnat.line)
    if dnat.daddr == "":
      msgs.add ValidationMsg(severity: svWarning,
        msg: "fw:dnat to " & dnat.dest & " has no 'daddr' restriction — " &
             "will match traffic to ANY destination address on the interface",
        line: dnat.line)

  for snat in state.snatRules:
    msgs.checkIpv6Addr(snat.fromNet, "fw:snat from", snat.line)
    if snat.fromNet == "0.0.0.0/0" or snat.fromNet == "::/0":
      msgs.add ValidationMsg(severity: svWarning,
        msg: "fw:snat uses match-all CIDR \"" & snat.fromNet &
             "\" as source — this matches ALL traffic", line: snat.line)

  for rule in state.rules:
    msgs.checkIpv6Addr(rule.daddrRaw, "rule daddr", rule.line)
    if rule.daddrRaw in ["0.0.0.0/0", "::/0"]:
      msgs.add ValidationMsg(severity: svWarning,
        msg: "rule uses match-all CIDR \"" & rule.daddrRaw &
             "\" as daddr — this matches ALL traffic", line: rule.line)

proc validateDnatForwarding(msgs: var seq[ValidationMsg], state: FirewallState) =
  ## Check DNAT rules have corresponding forward ACCEPT rules.
  for dnat in state.dnatRules:
    if dnat.iface == nil: continue
    var destZone: Zone
    for name, host in state.hosts:
      if host.addr4 == dnat.dest:
        destZone = host.zone
        break
    if destZone == nil: continue
    var hasForward = false
    for pol in state.policies:
      if pol.src.zone == dnat.iface and pol.dst.zone == destZone and pol.action == actAccept:
        hasForward = true; break
    if not hasForward:
      for rule in state.rules:
        if rule.src.zone == dnat.iface and rule.dst.zone == destZone and rule.action == actAccept:
          hasForward = true; break
    if not hasForward:
      msgs.add ValidationMsg(severity: svWarning,
        msg: "fw:dnat to " & dnat.dest & " via zone \"" & dnat.iface.name &
             "\" has no corresponding forward ACCEPT rule/policy to zone \"" &
             destZone.name & "\"", line: dnat.line)

# ---------------------------------------------------------------------------
# Shadow detection
# ---------------------------------------------------------------------------

proc endpointShadows(earlier, later: Endpoint): bool =
  if earlier.host.isNone and later.host.isSome:
    return later.zone == earlier.zone
  elif earlier.host.isNone and later.host.isNone:
    return true
  elif earlier.host.isSome and later.host.isSome:
    return earlier.host.get.name == later.host.get.name
  return false

proc portRangesOverlap(a, b: string): bool =
  if a == "" or b == "": return false
  try:
    let aParts = a.split('-')
    let bParts = b.split('-')
    let aLo = parseInt(aParts[0])
    let aHi = if aParts.len == 2: parseInt(aParts[1]) else: aLo
    let bLo = parseInt(bParts[0])
    let bHi = if bParts.len == 2: parseInt(bParts[1]) else: bLo
    return aLo <= bHi and bLo <= aHi
  except ValueError:
    return false

proc serviceOverlaps(earlier, later: Rule): bool =
  if earlier.service.isNone and earlier.proto.len == 0 and earlier.saddrList == "":
    return true
  if earlier.service.isSome and later.service.isSome:
    if earlier.service.get.name == later.service.get.name: return true
  if earlier.proto == later.proto and earlier.port == later.port:
    if earlier.proto.len > 0: return true
  if earlier.proto.len > 0 and later.proto.len > 0:
    for ep in earlier.proto:
      if ep in later.proto:
        if earlier.port.len == 0 and later.port.len == 0: return true
        if earlier.port.len == 0: return true
        for ePort in earlier.port:
          if later.port.len == 0: return true
          for lPort in later.port:
            if portRangesOverlap(ePort, lPort): return true
  return false

proc validateShadows(msgs: var seq[ValidationMsg], state: FirewallState) =
  ## Shadow and permissive-shadow detection across zone-pair rule groups.
  type ZPKey = tuple[src, dst: string]
  var rulesByPair: Table[ZPKey, seq[Rule]]
  for rule in state.rules:
    if rule.src.zone == nil or rule.dst.zone == nil: continue
    let key: ZPKey = (rule.src.zone.name, rule.dst.zone.name)
    if key notin rulesByPair: rulesByPair[key] = @[]
    rulesByPair[key].add rule

  for key, rules in rulesByPair:
    for i in 0 ..< rules.len:
      for j in (i+1) ..< rules.len:
        let earlier = rules[i]
        let later = rules[j]

        if earlier.saddrList != "" and later.saddrList != earlier.saddrList: continue
        if later.saddrList != "" and earlier.saddrList != later.saddrList: continue
        if earlier.daddrList != later.daddrList: continue
        if earlier.daddrRaw != later.daddrRaw: continue

        let srcOk = endpointShadows(earlier.src, later.src)
        let dstOk = endpointShadows(earlier.dst, later.dst)
        let portOk = serviceOverlaps(earlier, later)

        if srcOk and dstOk and portOk:
          msgs.add ValidationMsg(severity: svWarning,
            msg: "rule at line " & $later.line & " is shadowed by rule at line " &
                 $earlier.line & " (in " & key.src & " -> " & key.dst & ")",
            line: later.line)

        if earlier.action == actAccept and later.action in {actDrop, actReject}:
          if srcOk and dstOk and portOk:
            msgs.add ValidationMsg(severity: svWarning,
              msg: "accept rule at line " & $earlier.line & " precedes " &
                   $(later.action) & " rule at line " & $later.line &
                   " with overlapping criteria — the " & $(later.action) &
                   " may be ineffective (in " & key.src & " -> " & key.dst & ")",
              line: later.line)

# ---------------------------------------------------------------------------
# Main validation entry point
# ---------------------------------------------------------------------------

proc validate*(state: FirewallState): seq[ValidationMsg] =
  var msgs: seq[ValidationMsg]
  msgs.validateStructure(state)
  msgs.validateProtos(state)
  msgs.validateAddresses(state)
  msgs.validateDnatForwarding(state)
  msgs.validateShadows(state)
  return msgs
