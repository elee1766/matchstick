## build.nim - Transform FirewallState into NftRuleset IR.

import std/[options, tables, strutils, sequtils, algorithm]
import ./types
import ./nft_ir
import ./ipaddr

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

proc chainName(src, dst: string): string = src & "_to_" & dst
proc priorityVal(base, offset: int): int = base + offset

proc actionToStmt(action: Action): Stmt =
  case action
  of actAccept: acceptStmt()
  of actDrop: dropStmt()
  of actReject: rejectStmt("icmpx", "admin-prohibited")

proc parsePortExpr(s: string): Expr =
  ## Parse a port string into an Expr. Handles ranges ("80-443"), integers, and names.
  if '-' in s:
    let p = s.split('-')
    rangeExpr(intExpr(parseInt(p[0])), intExpr(parseInt(p[1])))
  else:
    try: intExpr(parseInt(s)) except ValueError: strExpr(s)

proc logRateRule(fam, tn, chain, setName, proto, prefix: string): NftCmd =
  ## Build an nftables rule that rate-limits logging via a dynamic set.
  addRule(fam, tn, chain, @[
    updateStmt(setName, payloadExpr(proto, "saddr"),
      @[limitStmt(5, "minute", burst = 5)]),
    logStmt(prefix)])

# ---------------------------------------------------------------------------
# Build rule expressions from a matchstick Rule
# ---------------------------------------------------------------------------

type
  BuiltRule = object
    stmts: seq[Stmt]
    ipv4Only, ipv6Only: bool

proc buildServiceRules(state: FirewallState, svc: Service, action: Action,
                       saddrStmts, daddrStmts: seq[Stmt],
                       forceV4, forceV6: bool): seq[BuiltRule] =
  for entry in svc.entries:
    var stmts: seq[Stmt]
    stmts.add saddrStmts
    stmts.add daddrStmts
    var v4 = forceV4
    var v6 = forceV6
    if entry.proto == "icmp":
      stmts.add matchStmt(opEq, payloadExpr("icmp", "type"), strExpr(entry.port))
      v4 = true
    elif entry.proto == "icmpv6":
      stmts.add matchStmt(opEq, payloadExpr("icmpv6", "type"), strExpr(entry.port))
      v6 = true
    else:
      stmts.add matchStmt(opEq, payloadExpr(entry.proto, "dport"), parsePortExpr(entry.port))
    stmts.add actionToStmt(action)
    result.add BuiltRule(stmts: stmts, ipv4Only: v4, ipv6Only: v6)

proc buildRuleExprs(state: FirewallState, rule: Rule): seq[BuiltRule] =
  var saddrStmts, daddrStmts: seq[Stmt]
  var v4, v6 = false

  if rule.saddrList != "":
    if rule.saddrList in state.ipLists:
      let ipl = state.ipLists[rule.saddrList]
      if ipl.ipType == "ipv4":
        saddrStmts.add matchStmt(opEq, payloadExpr("ip", "saddr"), setRef(rule.saddrList))
        v4 = true
      else:
        saddrStmts.add matchStmt(opEq, payloadExpr("ip6", "saddr"), setRef(rule.saddrList))
        v6 = true

  if rule.src.host.isSome:
    let host = rule.src.host.get
    if host.addr4 != "" and isIpv4(host.addr4):
      saddrStmts.add matchStmt(opEq, payloadExpr("ip", "saddr"), strExpr(host.addr4))
      v4 = true

  if rule.dst.host.isSome:
    let host = rule.dst.host.get
    if host.addr4 != "" and isIpv4(host.addr4):
      daddrStmts.add matchStmt(opEq, payloadExpr("ip", "daddr"), strExpr(host.addr4))
      v4 = true

  if rule.daddrRaw != "":
    if isIpv4(rule.daddrRaw):
      daddrStmts.add matchStmt(opEq, payloadExpr("ip", "daddr"), strExpr(rule.daddrRaw))
      v4 = true
    else:
      daddrStmts.add matchStmt(opEq, payloadExpr("ip6", "daddr"), strExpr(rule.daddrRaw))
      v6 = true

  if rule.service.isSome:
    return buildServiceRules(state, rule.service.get, rule.action, saddrStmts, daddrStmts, v4, v6)

  if rule.proto.len > 0:
    let portExprs = rule.port.mapIt(parsePortExpr(it))
    let portExpr = if portExprs.len == 1: portExprs[0]
                   elif portExprs.len > 1: sortedAnonSetExpr(portExprs)
                   else: nil
    for proto in rule.proto:
      var stmts: seq[Stmt]
      stmts.add saddrStmts; stmts.add daddrStmts
      var rv4 = v4; var rv6 = v6
      if proto == "icmp":
        if portExpr != nil: stmts.add matchStmt(opEq, payloadExpr("icmp", "type"), portExpr)
        rv4 = true
      elif proto == "icmpv6":
        if portExpr != nil: stmts.add matchStmt(opEq, payloadExpr("icmpv6", "type"), portExpr)
        rv6 = true
      else:
        if portExpr != nil: stmts.add matchStmt(opEq, payloadExpr(proto, "dport"), portExpr)
      stmts.add actionToStmt(rule.action)
      result.add BuiltRule(stmts: stmts, ipv4Only: rv4, ipv6Only: rv6)
    return

  var stmts: seq[Stmt]
  stmts.add saddrStmts; stmts.add daddrStmts
  stmts.add actionToStmt(rule.action)
  result.add BuiltRule(stmts: stmts, ipv4Only: v4, ipv6Only: v6)

# ---------------------------------------------------------------------------
# Zone pair analysis
# ---------------------------------------------------------------------------

type
  ZonePair = object
    src, dst: Zone
    policy: Option[Policy]
    builtRules: seq[BuiltRule]

proc analyzeZonePairs(state: FirewallState): seq[ZonePair] =
  type Key = tuple[s, d: string]
  var pairMap: Table[Key, ZonePair]

  proc getOrCreate(src, dst: Zone): var ZonePair =
    let key: Key = (src.name, dst.name)
    if key notin pairMap: pairMap[key] = ZonePair(src: src, dst: dst)
    pairMap[key]

  for pol in state.policies:
    if pol.src.zone == nil or pol.dst.zone == nil: continue
    var pair = getOrCreate(pol.src.zone, pol.dst.zone)
    pair.policy = some(pol)
    pairMap[(pol.src.zone.name, pol.dst.zone.name)] = pair

  for rule in state.rules:
    if rule.src.zone == nil or rule.dst.zone == nil: continue
    var pair = getOrCreate(rule.src.zone, rule.dst.zone)
    pair.builtRules.add buildRuleExprs(state, rule)
    pairMap[(rule.src.zone.name, rule.dst.zone.name)] = pair

  for key, pair in pairMap: result.add pair
  result.sort(proc(a, b: ZonePair): int = cmp(a.src.name & a.dst.name, b.src.name & b.dst.name))

# ---------------------------------------------------------------------------
# Main build function
# ---------------------------------------------------------------------------

proc buildRuleset*(state: FirewallState): NftRuleset =
  var cmds: seq[NftCmd]
  let tn = state.config.tableName
  let fam = state.config.family
  let offset = state.config.priorityOffset
  let logPrefix = state.config.logPrefix
  let logSetSize = state.config.logSetSize
  let logSetTimeout = state.config.logSetTimeout
  let addCounter = state.config.counter
  let inputPolicy = state.config.inputPolicy
  let outputPolicy = state.config.outputPolicy

  var fwZone: Zone
  var ifaceZones: seq[Zone]
  for name, zone in state.zones:
    if zone.interfaces.len == 0: fwZone = zone
    else: ifaceZones.add zone

  let zonePairs = analyzeZonePairs(state)
  var defaultAction = actDrop
  for pol in state.policies:
    if pol.src.zone == nil and pol.dst.zone == nil: defaultAction = pol.action

  # Table
  cmds.add addTable(fam, tn)

  # IP list sets
  for name, ipl in state.ipLists:
    let nftType = if ipl.ipType == "ipv4": "ipv4_addr" else: "ipv6_addr"
    var flags: seq[string]
    if ipl.flags != "": flags.add ipl.flags
    var elems: seq[Expr]
    for e in ipl.elements: elems.add strExpr(e)
    cmds.add addSet(fam, tn, name, nftType, flags, elem = elems)

  # Log rate limiting sets
  cmds.add addSet(fam, tn, "_lograte_4", "ipv4_addr", @["dynamic", "timeout"], size = logSetSize, timeout = logSetTimeout)
  cmds.add addSet(fam, tn, "_lograte_6", "ipv6_addr", @["dynamic", "timeout"], size = logSetSize, timeout = logSetTimeout)

  # Verdict maps
  var inputElems: seq[NftMapElem]
  for z in ifaceZones:
    for iface in z.interfaces:
      inputElems.add NftMapElem(key: strExpr(iface), value: verdictExpr("jump", chainName(z.name, fwZone.name)))
  cmds.add addMap(fam, tn, "input_zones", "ifname", "verdict", elem = inputElems)

  var outputElems: seq[NftMapElem]
  for z in ifaceZones:
    for iface in z.interfaces:
      outputElems.add NftMapElem(key: strExpr(iface), value: verdictExpr("jump", chainName(fwZone.name, z.name)))
  cmds.add addMap(fam, tn, "output_zones", "ifname", "verdict", elem = outputElems)

  var fwdElems: seq[NftMapElem]
  for pair in zonePairs:
    if pair.src == fwZone or pair.dst == fwZone: continue
    for si in pair.src.interfaces:
      for di in pair.dst.interfaces:
        fwdElems.add NftMapElem(key: concatExpr(@[strExpr(si), strExpr(di)]),
                                value: verdictExpr("jump", chainName(pair.src.name, pair.dst.name)))
  cmds.add addMap(fam, tn, "forward_zones", "ifname . ifname", "verdict", elem = fwdElems)

  # Helper chains
  cmds.add addChain(fam, tn, "icmp_v4")
  cmds.add addRule(fam, tn, "icmp_v4", @[
    matchStmt(opEq, payloadExpr("icmp", "type"),
      anonSetExpr(@[strExpr("destination-unreachable"), strExpr("time-exceeded"), strExpr("parameter-problem")])),
    acceptStmt()])
  # Rate-limit echo-request (ping) to prevent ICMP flood
  cmds.add addRule(fam, tn, "icmp_v4", @[
    matchStmt(opEq, payloadExpr("icmp", "type"), strExpr("echo-request")),
    limitStmt(10, "second", burst = 5),
    acceptStmt()])

  cmds.add addChain(fam, tn, "icmp_v6")
  # NDP and essential ICMPv6 -- always accept (required for IPv6 operation)
  cmds.add addRule(fam, tn, "icmp_v6", @[
    matchStmt(opEq, payloadExpr("icmpv6", "type"),
      anonSetExpr(@[strExpr("nd-neighbor-solicit"), strExpr("nd-neighbor-advert"),
        strExpr("nd-router-solicit"), strExpr("nd-router-advert"),
        strExpr("mld-listener-query"), strExpr("mld-listener-report")])),
    acceptStmt()])
  # Error types -- accept without rate limit (important for PMTUD etc.)
  cmds.add addRule(fam, tn, "icmp_v6", @[
    matchStmt(opEq, payloadExpr("icmpv6", "type"),
      anonSetExpr(@[strExpr("destination-unreachable"), strExpr("packet-too-big"),
        strExpr("time-exceeded"), strExpr("parameter-problem")])),
    acceptStmt()])
  # Rate-limit echo-request (ping6)
  cmds.add addRule(fam, tn, "icmp_v6", @[
    matchStmt(opEq, payloadExpr("icmpv6", "type"), strExpr("echo-request")),
    limitStmt(10, "second", burst = 5),
    acceptStmt()])
  # Drop other ICMPv6
  cmds.add addRule(fam, tn, "icmp_v6", @[dropStmt()])

  # rpfilter
  if state.laundry.rpfilter:
    cmds.add addBaseChain(fam, tn, "rpfilter", "filter", "prerouting", priorityVal(0, offset), "accept")
    cmds.add addRule(fam, tn, "rpfilter", @[
      matchStmt(opEq, fibExpr("oif", @["saddr", "mark", "iif"]), strExpr("0")), dropStmt()])

  # anti_smurf
  cmds.add addChain(fam, tn, "anti_smurf")
  cmds.add addRule(fam, tn, "anti_smurf", @[matchStmt(opEq, fibExpr("type", @["saddr"]), strExpr("broadcast")), dropStmt()])
  cmds.add addRule(fam, tn, "anti_smurf", @[matchStmt(opEq, fibExpr("type", @["saddr"]), strExpr("multicast")), dropStmt()])

  # Input chain
  cmds.add addBaseChain(fam, tn, "input", "filter", "input", priorityVal(0, offset), inputPolicy)
  cmds.add addRule(fam, tn, "input", @[matchStmt(opEq, metaExpr("iif"), strExpr("lo")), acceptStmt()])
  cmds.add addRule(fam, tn, "input", @[matchStmt(opEq, ctExpr("state"), anonSetExpr(@[strExpr("established"), strExpr("related")])), acceptStmt()])
  cmds.add addRule(fam, tn, "input", @[matchStmt(opIn, ctExpr("state"), strExpr("invalid")), dropStmt()])
  cmds.add addRule(fam, tn, "input", @[jumpStmt("anti_smurf")])

  # DHCP
  for dc in state.dhcp:
    for iface in dc.zone.interfaces:
      case dc.role
      of dhcpClient:
        cmds.add addRule(fam, tn, "input", @[matchStmt(opEq, metaExpr("iifname"), strExpr(iface)),
          matchStmt(opEq, payloadExpr("udp", "sport"), intExpr(67)),
          matchStmt(opEq, payloadExpr("udp", "dport"), intExpr(68)), acceptStmt()])
      of dhcpServer:
        cmds.add addRule(fam, tn, "input", @[matchStmt(opEq, metaExpr("iifname"), strExpr(iface)),
          matchStmt(opEq, payloadExpr("udp", "sport"), intExpr(68)),
          matchStmt(opEq, payloadExpr("udp", "dport"), intExpr(67)), acceptStmt()])

  # TCP strict
  if state.laundry.tcpStrict:
    cmds.add addChain(fam, tn, "tcp_strict")
    let allFlagsList = listExpr(@[strExpr("fin"), strExpr("syn"), strExpr("rst"), strExpr("psh"), strExpr("ack"), strExpr("urg")])
    cmds.add addRule(fam, tn, "tcp_strict", @[matchStmt(opNot, payloadExpr("tcp", "flags"), allFlagsList), dropStmt()], "tcp-strict: null flags")
    let finSyn = binOpExpr("|", strExpr("fin"), strExpr("syn"))
    cmds.add addRule(fam, tn, "tcp_strict", @[matchStmt(opEq, binOpExpr("&", payloadExpr("tcp", "flags"), finSyn), finSyn), dropStmt()], "tcp-strict: fin+syn")
    let synRst = binOpExpr("|", strExpr("syn"), strExpr("rst"))
    cmds.add addRule(fam, tn, "tcp_strict", @[matchStmt(opEq, binOpExpr("&", payloadExpr("tcp", "flags"), synRst), synRst), dropStmt()], "tcp-strict: syn+rst")
    # XMAS tree: FIN+PSH+URG
    let finPshUrg = binOpExpr("|", strExpr("fin"), binOpExpr("|", strExpr("psh"), strExpr("urg")))
    cmds.add addRule(fam, tn, "tcp_strict", @[matchStmt(opEq, binOpExpr("&", payloadExpr("tcp", "flags"), finPshUrg), finPshUrg), dropStmt()], "tcp-strict: xmas")
    # New connection must have SYN only
    let synOnly = binOpExpr("|", strExpr("fin"), binOpExpr("|", strExpr("syn"), binOpExpr("|", strExpr("rst"), strExpr("ack"))))
    cmds.add addRule(fam, tn, "tcp_strict", @[
      matchStmt(opNeq, binOpExpr("&", payloadExpr("tcp", "flags"), synOnly), strExpr("syn")),
      matchStmt(opEq, ctExpr("state"), strExpr("new")),
      dropStmt()], "tcp-strict: new non-syn")
    cmds.add addRule(fam, tn, "input", @[jumpStmt("tcp_strict")])

  cmds.add addRule(fam, tn, "input", @[jumpStmt("icmp_v4")])
  cmds.add addRule(fam, tn, "input", @[jumpStmt("icmp_v6")])
  cmds.add addRule(fam, tn, "input", @[vmapStmt(metaExpr("iifname"), setRef("input_zones"))])
  cmds.add logRateRule(fam, tn, "input", "_lograte_4", "ip", logPrefix & " input DROP ")
  cmds.add logRateRule(fam, tn, "input", "_lograte_6", "ip6", logPrefix & " input DROP ")
  cmds.add addRule(fam, tn, "input", @[dropStmt()])

  # Forward chain
  cmds.add addBaseChain(fam, tn, "forward", "filter", "forward", priorityVal(0, offset), "drop")
  cmds.add addRule(fam, tn, "forward", @[matchStmt(opEq, ctExpr("state"), anonSetExpr(@[strExpr("established"), strExpr("related")])), acceptStmt()])
  cmds.add addRule(fam, tn, "forward", @[matchStmt(opIn, ctExpr("state"), strExpr("invalid")), dropStmt()])
  cmds.add addRule(fam, tn, "forward", @[jumpStmt("anti_smurf")])
  if state.laundry.tcpStrict:
    cmds.add addRule(fam, tn, "forward", @[jumpStmt("tcp_strict")])
  if state.laundry.broadcastDrop:
    cmds.add addRule(fam, tn, "forward", @[matchStmt(opEq, fibExpr("type", @["daddr"]), strExpr("broadcast")), dropStmt()])
    cmds.add addRule(fam, tn, "forward", @[matchStmt(opEq, fibExpr("type", @["daddr"]), strExpr("multicast")), dropStmt()])
  cmds.add addRule(fam, tn, "forward", @[vmapStmt(concatExpr(@[metaExpr("iifname"), metaExpr("oifname")]), setRef("forward_zones"))])
  cmds.add logRateRule(fam, tn, "forward", "_lograte_4", "ip", logPrefix & " forward DROP ")
  cmds.add addRule(fam, tn, "forward", @[dropStmt()])

  # Output chain
  cmds.add addBaseChain(fam, tn, "output", "filter", "output", priorityVal(0, offset), outputPolicy)
  for dc in state.dhcp:
    if dc.role == dhcpServer:
      for iface in dc.zone.interfaces:
        cmds.add addRule(fam, tn, "output", @[matchStmt(opEq, metaExpr("oifname"), strExpr(iface)),
          matchStmt(opEq, payloadExpr("udp", "sport"), intExpr(67)),
          matchStmt(opEq, payloadExpr("udp", "dport"), intExpr(68)), acceptStmt()])
  cmds.add addRule(fam, tn, "output", @[vmapStmt(metaExpr("oifname"), setRef("output_zones"))])

  # Zone-pair chains
  for pair in zonePairs:
    let cn = chainName(pair.src.name, pair.dst.name)
    let (polAction, polLog) = if pair.policy.isSome: (pair.policy.get.action, pair.policy.get.log)
                              else: (defaultAction, false)

    let needsSplit = pair.builtRules.anyIt(it.ipv4Only) or pair.builtRules.anyIt(it.ipv6Only)

    if pair.builtRules.len == 0 and polAction == actAccept:
      cmds.add addChain(fam, tn, cn)
      cmds.add addRule(fam, tn, cn, @[acceptStmt()])
      continue

    if not needsSplit:
      cmds.add addChain(fam, tn, cn)
      for br in pair.builtRules: cmds.add addRule(fam, tn, cn, br.stmts)
      if polLog:
        cmds.add logRateRule(fam, tn, cn, "_lograte_4", "ip", logPrefix & " " & cn & " " & $polAction & " ")
      cmds.add addRule(fam, tn, cn, @[actionToStmt(polAction)])
      continue

    let cn4 = cn & "_4"
    let cn6 = cn & "_6"
    cmds.add addChain(fam, tn, cn)
    cmds.add addRule(fam, tn, cn, @[vmapStmt(metaExpr("nfproto"),
      anonSetExpr(@[listExpr(@[strExpr("ipv4"), verdictExpr("jump", cn4)]),
                     listExpr(@[strExpr("ipv6"), verdictExpr("jump", cn6)])]))])

    cmds.add addChain(fam, tn, cn4)
    for br in pair.builtRules:
      if not br.ipv6Only: cmds.add addRule(fam, tn, cn4, br.stmts)
    if polLog:
      cmds.add logRateRule(fam, tn, cn4, "_lograte_4", "ip", logPrefix & " " & cn & " " & $polAction & " ")
    cmds.add addRule(fam, tn, cn4, @[actionToStmt(polAction)])

    cmds.add addChain(fam, tn, cn6)
    for br in pair.builtRules:
      if not br.ipv4Only: cmds.add addRule(fam, tn, cn6, br.stmts)
    if polLog:
      cmds.add logRateRule(fam, tn, cn6, "_lograte_6", "ip6", logPrefix & " " & cn & " " & $polAction & " ")
    cmds.add addRule(fam, tn, cn6, @[actionToStmt(polAction)])

  # NAT table
  if state.dnatRules.len > 0 or state.snatRules.len > 0:
    let natTn = tn & "_nat"
    cmds.add addTable(fam, natTn)

    if state.dnatRules.len > 0:
      cmds.add addBaseChain(fam, natTn, "prerouting", "nat", "prerouting", priorityVal(-100, offset), "accept")
      for dnat in state.dnatRules:
        var entries: seq[ServiceEntry]
        if dnat.service.isSome: entries = dnat.service.get.entries
        elif dnat.proto.len > 0:
          for proto in dnat.proto:
            for port in dnat.port: entries.add ServiceEntry(proto: proto, port: port)
        for entry in entries:
          var stmts: seq[Stmt]
          for iface in dnat.iface.interfaces:
            stmts.add matchStmt(opEq, metaExpr("iifname"), strExpr(iface))
          if dnat.daddr != "" and isIpv4(dnat.daddr):
            stmts.add matchStmt(opEq, payloadExpr("ip", "daddr"), strExpr(dnat.daddr))
          if entry.proto notin ["icmp", "icmpv6"]:
            stmts.add matchStmt(opEq, payloadExpr(entry.proto, "dport"), parsePortExpr(entry.port))
          let family = if isIpv4(dnat.dest): "ip" else: "ip6"
          stmts.add dnatStmt(dnat.dest, dnat.destPort, family)
          cmds.add addRule(fam, natTn, "prerouting", stmts)

    if state.snatRules.len > 0:
      cmds.add addBaseChain(fam, natTn, "postrouting", "nat", "postrouting", priorityVal(100, offset), "accept")
      for snat in state.snatRules:
        var stmts: seq[Stmt]
        if snat.fromNet != "":
          stmts.add matchStmt(opEq, payloadExpr("ip", "saddr"), strExpr(normalizeCidr(snat.fromNet)))
        if snat.daddr != "":
          stmts.add matchStmt(opEq, payloadExpr("ip", "daddr"), strExpr(snat.daddr))
        stmts.add matchStmt(opEq, metaExpr("oifname"), strExpr(snat.oif))
        if snat.proto != "" and snat.port.len > 0:
          let portExprs = snat.port.mapIt(parsePortExpr(it))
          let portExpr = if portExprs.len == 1: portExprs[0] else: sortedAnonSetExpr(portExprs)
          stmts.add matchStmt(opEq, payloadExpr(snat.proto, "dport"), portExpr)
        if snat.masquerade: stmts.add masqueradeStmt()
        else:
          let family = if isIpv4(snat.addr4): "ip" else: "ip6"
          stmts.add snatStmt(snat.addr4, family = family)
        cmds.add addRule(fam, natTn, "postrouting", stmts)

  # Add counters to all rules if configured
  if addCounter:
    for cmd in cmds.mitems:
      if cmd.kind == nckAdd and cmd.add.kind == nakRule:
        cmd.add.rule.expr.insert(counterStmt(), 0)

  # Reorder: metainfo first, then tables, chains, sets/maps, rules
  var ordered: seq[NftCmd]
  ordered.add metainfoCmd()
  for c in cmds:
    if c.kind == nckDelete: ordered.add c
  for c in cmds:
    if c.kind == nckAdd and c.add.kind == nakTable: ordered.add c
  for c in cmds:
    if c.kind == nckAdd and c.add.kind == nakChain: ordered.add c
  for c in cmds:
    if c.kind == nckAdd and c.add.kind in {nakSet, nakMap}: ordered.add c
  for c in cmds:
    if c.kind == nckAdd and c.add.kind == nakRule: ordered.add c

  result = NftRuleset(nftables: ordered)
