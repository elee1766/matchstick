## build.nim - Transform FirewallState into NftRuleset IR.
##
## This module translates the user's Lua declarations into typed nftables
## objects: tables, chains, verdict maps, sets, rules with proper IPv4/v6
## splitting.

import std/[options, tables, strutils, sequtils, algorithm]
import ./types
import ./nft_ir

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

proc isIpv4Addr(s: string): bool =
  '.' in s and ':' notin s

proc chainName(src, dst: string): string =
  src & "_to_" & dst

proc priorityVal(base: int, offset: int): int = base + offset

# ---------------------------------------------------------------------------
# Build rule expressions from a matchstick Rule
# ---------------------------------------------------------------------------

type
  ## A rendered rule with protocol affinity for IPv4/v6 splitting
  BuiltRule = object
    stmts: seq[Stmt]
    ipv4Only: bool
    ipv6Only: bool

proc actionToStmt(action: Action): Stmt =
  case action
  of actAccept: acceptStmt()
  of actDrop: dropStmt()
  of actReject: rejectStmt("icmpx", "admin-prohibited")

proc buildServiceRules(state: FirewallState, svc: Service, action: Action,
                       saddrStmts: seq[Stmt], daddrStmts: seq[Stmt],
                       forceV4: bool, forceV6: bool): seq[BuiltRule] =
  ## Expand a service into one BuiltRule per service entry.
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
      # Parse port -- could be single, range, or list
      let portExpr = if '-' in entry.port:
        let parts = entry.port.split('-')
        Expr(kind: ekRange, rangeMin: intExpr(parseInt(parts[0])),
             rangeMax: intExpr(parseInt(parts[1])))
      else:
        try: intExpr(parseInt(entry.port))
        except: strExpr(entry.port)
      stmts.add matchStmt(opEq, payloadExpr(entry.proto, "dport"), portExpr)

    stmts.add actionToStmt(action)
    result.add BuiltRule(stmts: stmts, ipv4Only: v4, ipv6Only: v6)

proc buildRuleExprs(state: FirewallState, rule: Rule): seq[BuiltRule] =
  ## Convert a matchstick Rule into one or more BuiltRules.
  var saddrStmts: seq[Stmt]
  var daddrStmts: seq[Stmt]
  var v4 = false
  var v6 = false

  # Source address (from IP list or host)
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
    if host.addr4 != "" and isIpv4Addr(host.addr4):
      saddrStmts.add matchStmt(opEq, payloadExpr("ip", "saddr"), strExpr(host.addr4))
      v4 = true

  # Dest address (from host)
  if rule.dst.host.isSome:
    let host = rule.dst.host.get
    if host.addr4 != "" and isIpv4Addr(host.addr4):
      daddrStmts.add matchStmt(opEq, payloadExpr("ip", "daddr"), strExpr(host.addr4))
      v4 = true

  # Service-based rules
  if rule.service.isSome:
    return buildServiceRules(state, rule.service.get, rule.action,
                             saddrStmts, daddrStmts, v4, v6)

  # Raw proto/port rules
  if rule.proto.len > 0:
    let portExprs = rule.port.mapIt(
      block:
        let p = it
        if '-' in p:
          let parts = p.split('-')
          Expr(kind: ekRange, rangeMin: intExpr(parseInt(parts[0])),
               rangeMax: intExpr(parseInt(parts[1])))
        else:
          try: intExpr(parseInt(p))
          except: strExpr(p)
    )
    let portExpr = if portExprs.len == 1: portExprs[0]
                   elif portExprs.len > 1: listExpr(portExprs)
                   else: nil

    for proto in rule.proto:
      var stmts: seq[Stmt]
      stmts.add saddrStmts
      stmts.add daddrStmts

      var rv4 = v4
      var rv6 = v6

      if proto == "icmp":
        if portExpr != nil:
          stmts.add matchStmt(opEq, payloadExpr("icmp", "type"), portExpr)
        rv4 = true
      elif proto == "icmpv6":
        if portExpr != nil:
          stmts.add matchStmt(opEq, payloadExpr("icmpv6", "type"), portExpr)
        rv6 = true
      else:
        if portExpr != nil:
          stmts.add matchStmt(opEq, payloadExpr(proto, "dport"), portExpr)

      stmts.add actionToStmt(rule.action)
      result.add BuiltRule(stmts: stmts, ipv4Only: rv4, ipv6Only: rv6)
    return

  # No service, no proto -- just saddr_list or similar
  var stmts: seq[Stmt]
  stmts.add saddrStmts
  stmts.add daddrStmts
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
  ## Collect all zone pairs that need chains.
  type Key = tuple[s, d: string]
  var pairMap: Table[Key, ZonePair]

  proc getOrCreate(src, dst: Zone): var ZonePair =
    let key: Key = (src.name, dst.name)
    if key notin pairMap:
      pairMap[key] = ZonePair(src: src, dst: dst)
    pairMap[key]

  # Assign policies
  for pol in state.policies:
    if pol.src.zone == nil or pol.dst.zone == nil: continue
    var pair = getOrCreate(pol.src.zone, pol.dst.zone)
    pair.policy = some(pol)
    pairMap[(pol.src.zone.name, pol.dst.zone.name)] = pair

  # Assign rules
  for rule in state.rules:
    if rule.src.zone == nil or rule.dst.zone == nil: continue
    var pair = getOrCreate(rule.src.zone, rule.dst.zone)
    let built = buildRuleExprs(state, rule)
    pair.builtRules.add built
    pairMap[(rule.src.zone.name, rule.dst.zone.name)] = pair

  # Sort for deterministic output
  for key, pair in pairMap:
    result.add pair
  result.sort(proc(a, b: ZonePair): int =
    cmp(a.src.name & a.dst.name, b.src.name & b.dst.name))

# ---------------------------------------------------------------------------
# Main build function
# ---------------------------------------------------------------------------

proc buildRuleset*(state: FirewallState): NftRuleset =
  var objs: seq[NftObject]

  let tn = state.config.tableName
  let fam = "inet"
  let offset = state.config.priorityOffset
  let logRate = state.config.logRate
  let logPrefix = state.config.logPrefix

  # Find fw zone (no interfaces) and interface zones
  var fwZone: Zone
  var ifaceZones: seq[Zone]
  for name, zone in state.zones:
    if zone.interfaces.len == 0:
      fwZone = zone
    else:
      ifaceZones.add zone

  let zonePairs = analyzeZonePairs(state)

  # Find default policy
  var defaultAction = actDrop
  for pol in state.policies:
    if pol.src.zone == nil and pol.dst.zone == nil:
      defaultAction = pol.action

  # =========================================================================
  # Filter table
  # =========================================================================
  objs.add nftTable(fam, tn)

  # --- IP list sets ---
  for name, ipl in state.ipLists:
    let nftType = if ipl.ipType == "ipv4": "ipv4_addr" else: "ipv6_addr"
    var flags: seq[string]
    if ipl.flags != "": flags.add ipl.flags
    var elems: seq[Expr]
    for e in ipl.elements:
      elems.add strExpr(e)
    objs.add nftSet(fam, tn, name, nftType, flags, elems = elems)

  # --- Log rate limiting sets ---
  objs.add nftSet(fam, tn, "_lograte_4", "ipv4_addr",
                  @["dynamic", "timeout"], size = 65535, timeout = 60)
  objs.add nftSet(fam, tn, "_lograte_6", "ipv6_addr",
                  @["dynamic", "timeout"], size = 65535, timeout = 60)

  # --- Verdict maps ---
  # Input: iifname -> zone_to_fw chain
  var inputElems: seq[tuple[key: Expr, value: Expr]]
  for z in ifaceZones:
    for iface in z.interfaces:
      let cn = chainName(z.name, fwZone.name)
      inputElems.add (strExpr(iface), strExpr("jump " & cn))
  objs.add nftMap(fam, tn, "input_zones", "ifname", "verdict",
                  elems = inputElems)

  # Output: oifname -> fw_to_zone chain
  var outputElems: seq[tuple[key: Expr, value: Expr]]
  for z in ifaceZones:
    for iface in z.interfaces:
      let cn = chainName(fwZone.name, z.name)
      outputElems.add (strExpr(iface), strExpr("jump " & cn))
  objs.add nftMap(fam, tn, "output_zones", "ifname", "verdict",
                  elems = outputElems)

  # Forward: iifname . oifname -> zone_to_zone chain
  var fwdElems: seq[tuple[key: Expr, value: Expr]]
  for pair in zonePairs:
    if pair.src == fwZone or pair.dst == fwZone: continue
    for si in pair.src.interfaces:
      for di in pair.dst.interfaces:
        let cn = chainName(pair.src.name, pair.dst.name)
        fwdElems.add (concatExpr(@[strExpr(si), strExpr(di)]),
                      strExpr("jump " & cn))
  objs.add nftMap(fam, tn, "forward_zones", "ifname . ifname", "verdict",
                  elems = fwdElems)

  # --- Helper chains ---
  # ICMP v4
  objs.add nftChain(fam, tn, "icmp_v4")
  objs.add nftRule(fam, tn, "icmp_v4", @[
    matchStmt(opEq, payloadExpr("icmp", "type"),
              listExpr(@[strExpr("destination-unreachable"),
                         strExpr("time-exceeded"),
                         strExpr("parameter-problem")])),
    acceptStmt(),
  ])

  # ICMP v6
  objs.add nftChain(fam, tn, "icmp_v6")
  objs.add nftRule(fam, tn, "icmp_v6", @[
    matchStmt(opEq, payloadExpr("icmpv6", "type"),
              listExpr(@[strExpr("destination-unreachable"),
                         strExpr("packet-too-big"),
                         strExpr("time-exceeded"),
                         strExpr("parameter-problem"),
                         strExpr("nd-neighbor-solicit"),
                         strExpr("nd-neighbor-advert"),
                         strExpr("nd-router-solicit"),
                         strExpr("nd-router-advert"),
                         strExpr("mld-listener-query"),
                         strExpr("mld-listener-report")])),
    acceptStmt(),
  ])

  # Reverse path filter
  if state.laundry.rpfilter:
    objs.add nftBaseChain(fam, tn, "rpfilter", nctFilter, nchPrerouting,
                          priorityVal(0, offset), ncpAccept)
    objs.add nftRule(fam, tn, "rpfilter", @[
      matchStmt(opEq, fibExpr("oif", @["saddr", "mark", "iif"]), intExpr(0)),
      dropStmt(),
    ])

  # Anti-smurf
  objs.add nftChain(fam, tn, "anti_smurf")
  objs.add nftRule(fam, tn, "anti_smurf", @[
    matchStmt(opEq, fibExpr("type", @["saddr"]), strExpr("broadcast")),
    dropStmt(),
  ])
  objs.add nftRule(fam, tn, "anti_smurf", @[
    matchStmt(opEq, fibExpr("type", @["saddr"]), strExpr("multicast")),
    dropStmt(),
  ])

  # --- Main input chain ---
  objs.add nftBaseChain(fam, tn, "input", nctFilter, nchInput,
                        priorityVal(0, offset), ncpDrop)

  # Loopback
  objs.add nftRule(fam, tn, "input", @[
    matchStmt(opEq, metaExpr("iif"), strExpr("lo")),
    acceptStmt(),
  ])
  # Conntrack
  objs.add nftRule(fam, tn, "input", @[
    matchStmt(opEq, ctExpr("state"),
              listExpr(@[strExpr("established"), strExpr("related")])),
    acceptStmt(),
  ])
  objs.add nftRule(fam, tn, "input", @[
    matchStmt(opEq, ctExpr("state"), strExpr("invalid")),
    dropStmt(),
  ])
  # Anti-smurf
  objs.add nftRule(fam, tn, "input", @[jumpStmt("anti_smurf")])

  # DHCP (before zone dispatch)
  for dc in state.dhcp:
    for iface in dc.zone.interfaces:
      case dc.role
      of dhcpClient:
        objs.add nftRule(fam, tn, "input", @[
          matchStmt(opEq, metaExpr("iifname"), strExpr(iface)),
          matchStmt(opEq, payloadExpr("udp", "dport"), intExpr(68)),
          matchStmt(opEq, payloadExpr("udp", "sport"), intExpr(67)),
          acceptStmt(),
        ])
      of dhcpServer:
        objs.add nftRule(fam, tn, "input", @[
          matchStmt(opEq, metaExpr("iifname"), strExpr(iface)),
          matchStmt(opEq, payloadExpr("udp", "dport"), intExpr(67)),
          matchStmt(opEq, payloadExpr("udp", "sport"), intExpr(68)),
          acceptStmt(),
        ])

  # TCP strict
  if state.laundry.tcpStrict:
    objs.add nftRule(fam, tn, "input", @[
      matchStmt(opEq, payloadExpr("tcp", "flags"),
                strExpr("& (fin|syn|rst|psh|ack|urg) == 0")),
      dropStmt(),
    ], "tcp-strict: null flags")
    objs.add nftRule(fam, tn, "input", @[
      matchStmt(opEq, payloadExpr("tcp", "flags"),
                strExpr("& (fin|syn) == (fin|syn)")),
      dropStmt(),
    ], "tcp-strict: fin+syn")
    objs.add nftRule(fam, tn, "input", @[
      matchStmt(opEq, payloadExpr("tcp", "flags"),
                strExpr("& (syn|rst) == (syn|rst)")),
      dropStmt(),
    ], "tcp-strict: syn+rst")

  # ICMP helper jumps
  objs.add nftRule(fam, tn, "input", @[jumpStmt("icmp_v4")])
  objs.add nftRule(fam, tn, "input", @[jumpStmt("icmp_v6")])

  # Verdict map dispatch
  objs.add nftRule(fam, tn, "input", @[
    vmapStmt(metaExpr("iifname"), setRef("input_zones")),
  ])

  # Default drop with rate-limited logging
  objs.add nftRule(fam, tn, "input", @[
    updateStmt("_lograte_4", payloadExpr("ip", "saddr"), @[
      limitStmt(5, "minute", burst = 5),
    ]),
    logStmt(logPrefix & " input DROP "),
  ])
  objs.add nftRule(fam, tn, "input", @[
    updateStmt("_lograte_6", payloadExpr("ip6", "saddr"), @[
      limitStmt(5, "minute", burst = 5),
    ]),
    logStmt(logPrefix & " input DROP "),
  ])
  objs.add nftRule(fam, tn, "input", @[dropStmt()])

  # --- Main forward chain ---
  objs.add nftBaseChain(fam, tn, "forward", nctFilter, nchForward,
                        priorityVal(0, offset), ncpDrop)
  objs.add nftRule(fam, tn, "forward", @[
    matchStmt(opEq, ctExpr("state"),
              listExpr(@[strExpr("established"), strExpr("related")])),
    acceptStmt(),
  ])
  objs.add nftRule(fam, tn, "forward", @[
    matchStmt(opEq, ctExpr("state"), strExpr("invalid")),
    dropStmt(),
  ])
  objs.add nftRule(fam, tn, "forward", @[jumpStmt("anti_smurf")])

  if state.laundry.broadcastDrop:
    objs.add nftRule(fam, tn, "forward", @[
      matchStmt(opEq, fibExpr("type", @["daddr"]), strExpr("broadcast")),
      dropStmt(),
    ])
    objs.add nftRule(fam, tn, "forward", @[
      matchStmt(opEq, fibExpr("type", @["daddr"]), strExpr("multicast")),
      dropStmt(),
    ])

  objs.add nftRule(fam, tn, "forward", @[
    vmapStmt(concatExpr(@[metaExpr("iifname"), metaExpr("oifname")]),
             setRef("forward_zones")),
  ])
  # Note: emit_text handles iifname/oifname without "meta" prefix
  objs.add nftRule(fam, tn, "forward", @[
    updateStmt("_lograte_4", payloadExpr("ip", "saddr"), @[
      limitStmt(5, "minute", burst = 5),
    ]),
    logStmt(logPrefix & " forward DROP "),
  ])
  objs.add nftRule(fam, tn, "forward", @[dropStmt()])

  # --- Main output chain ---
  objs.add nftBaseChain(fam, tn, "output", nctFilter, nchOutput,
                        priorityVal(0, offset), ncpAccept)
  # DHCP server output
  for dc in state.dhcp:
    if dc.role == dhcpServer:
      for iface in dc.zone.interfaces:
        objs.add nftRule(fam, tn, "output", @[
          matchStmt(opEq, metaExpr("oifname"), strExpr(iface)),
          matchStmt(opEq, payloadExpr("udp", "dport"), intExpr(68)),
          matchStmt(opEq, payloadExpr("udp", "sport"), intExpr(67)),
          acceptStmt(),
        ])
  objs.add nftRule(fam, tn, "output", @[
    vmapStmt(metaExpr("oifname"), setRef("output_zones")),
  ])

  # --- Per-zone-pair chains ---
  for pair in zonePairs:
    let cn = chainName(pair.src.name, pair.dst.name)

    let (polAction, polLog) = if pair.policy.isSome:
      (pair.policy.get.action, pair.policy.get.log)
    else:
      (defaultAction, false)

    let needsSplit = pair.builtRules.anyIt(it.ipv4Only) or
                     pair.builtRules.anyIt(it.ipv6Only)

    # Simple accept-only chains
    if pair.builtRules.len == 0 and polAction == actAccept:
      objs.add nftChain(fam, tn, cn)
      objs.add nftRule(fam, tn, cn, @[acceptStmt()])
      continue

    if not needsSplit:
      # No IPv4/v6 splitting needed
      objs.add nftChain(fam, tn, cn)
      for br in pair.builtRules:
        objs.add nftRule(fam, tn, cn, br.stmts)
      if polLog:
        objs.add nftRule(fam, tn, cn, @[
          updateStmt("_lograte_4", payloadExpr("ip", "saddr"), @[
            limitStmt(5, "minute", burst = 5),
          ]),
          logStmt(logPrefix & " " & cn & " " & $polAction & " "),
        ])
      objs.add nftRule(fam, tn, cn, @[actionToStmt(polAction)])
      continue

    # Need IPv4/v6 split
    let cn4 = cn & "_4"
    let cn6 = cn & "_6"

    # Dispatch chain: meta nfproto vmap { ipv4 : jump X_4, ipv6 : jump X_6 }
    # We use a special map object inline. The emitter handles this as a
    # special case for vmap with inline data.
    objs.add nftChain(fam, tn, cn)
    objs.add nftRule(fam, tn, cn, @[
      vmapStmt(metaExpr("nfproto"),
               listExpr(@[
                 strExpr("ipv4 : jump " & cn4),
                 strExpr("ipv6 : jump " & cn6),
               ])),
    ])

    # _4 chain
    objs.add nftChain(fam, tn, cn4)
    for br in pair.builtRules:
      if not br.ipv6Only:
        objs.add nftRule(fam, tn, cn4, br.stmts)
    if polLog:
      objs.add nftRule(fam, tn, cn4, @[
        updateStmt("_lograte_4", payloadExpr("ip", "saddr"), @[
          limitStmt(5, "minute", burst = 5),
        ]),
        logStmt(logPrefix & " " & cn & " " & $polAction & " "),
      ])
    objs.add nftRule(fam, tn, cn4, @[actionToStmt(polAction)])

    # _6 chain
    objs.add nftChain(fam, tn, cn6)
    for br in pair.builtRules:
      if not br.ipv4Only:
        objs.add nftRule(fam, tn, cn6, br.stmts)
    if polLog:
      objs.add nftRule(fam, tn, cn6, @[
        updateStmt("_lograte_6", payloadExpr("ip6", "saddr"), @[
          limitStmt(5, "minute", burst = 5),
        ]),
        logStmt(logPrefix & " " & cn & " " & $polAction & " "),
      ])
    objs.add nftRule(fam, tn, cn6, @[actionToStmt(polAction)])

  # =========================================================================
  # NAT table
  # =========================================================================
  if state.dnatRules.len > 0 or state.snatRules.len > 0:
    let natTn = tn & "_nat"
    objs.add nftTable(fam, natTn)

    # --- DNAT (prerouting) ---
    if state.dnatRules.len > 0:
      objs.add nftBaseChain(fam, natTn, "prerouting", nctNat, nchPrerouting,
                            priorityVal(-100, offset), ncpAccept)

      for dnat in state.dnatRules:
        var entries: seq[ServiceEntry]
        if dnat.service.isSome:
          entries = dnat.service.get.entries
        elif dnat.proto.len > 0:
          for proto in dnat.proto:
            for port in dnat.port:
              entries.add ServiceEntry(proto: proto, port: port)

        for entry in entries:
          var stmts: seq[Stmt]
          # Interface match
          for iface in dnat.iface.interfaces:
            stmts.add matchStmt(opEq, metaExpr("iifname"), strExpr(iface))

          # Original dest match (hairpin)
          if dnat.daddr != "":
            if isIpv4Addr(dnat.daddr):
              stmts.add matchStmt(opEq, payloadExpr("ip", "daddr"), strExpr(dnat.daddr))

          # Port match
          if entry.proto notin ["icmp", "icmpv6"]:
            let portExpr = if '-' in entry.port:
              let parts = entry.port.split('-')
              Expr(kind: ekRange, rangeMin: intExpr(parseInt(parts[0])),
                   rangeMax: intExpr(parseInt(parts[1])))
            else:
              try: intExpr(parseInt(entry.port))
              except: strExpr(entry.port)
            stmts.add matchStmt(opEq, payloadExpr(entry.proto, "dport"), portExpr)

          # DNAT target
          let family = if isIpv4Addr(dnat.dest): "ip" else: "ip6"
          stmts.add dnatStmt(dnat.dest, dnat.destPort, family)

          objs.add nftRule(fam, natTn, "prerouting", stmts)

    # --- SNAT (postrouting) ---
    if state.snatRules.len > 0:
      objs.add nftBaseChain(fam, natTn, "postrouting", nctNat, nchPostrouting,
                            priorityVal(100, offset), ncpAccept)

      for snat in state.snatRules:
        var stmts: seq[Stmt]

        # Source match
        if snat.fromNet != "":
          stmts.add matchStmt(opEq, payloadExpr("ip", "saddr"), strExpr(snat.fromNet))

        # Dest match
        if snat.daddr != "":
          stmts.add matchStmt(opEq, payloadExpr("ip", "daddr"), strExpr(snat.daddr))

        # Outgoing interface
        stmts.add matchStmt(opEq, metaExpr("oifname"), strExpr(snat.oif))

        # Protocol + port filter
        if snat.proto != "" and snat.port.len > 0:
          let portExprs = snat.port.mapIt(
            block:
              let p = it
              if '-' in p:
                let parts = p.split('-')
                Expr(kind: ekRange, rangeMin: intExpr(parseInt(parts[0])),
                     rangeMax: intExpr(parseInt(parts[1])))
              else:
                try: intExpr(parseInt(p))
                except: strExpr(p)
          )
          let portExpr = if portExprs.len == 1: portExprs[0]
                         else: listExpr(portExprs)
          stmts.add matchStmt(opEq, payloadExpr(snat.proto, "dport"), portExpr)

        # Action
        if snat.masquerade:
          stmts.add masqueradeStmt()
        else:
          let family = if isIpv4Addr(snat.addr4): "ip" else: "ip6"
          stmts.add snatStmt(snat.addr4, family = family)

        objs.add nftRule(fam, natTn, "postrouting", stmts)

  result = NftRuleset(objects: objs)
