## nft_ir.nim - Typed intermediate representation for nftables rulesets.
##
## Models the nftables JSON schema (libnftables-json(5)) as Nim object variants.
## The top-level structure is a flat seq[NftObject], matching the JSON
## `{"nftables": [...]}` array where tables, chains, rules, sets are siblings.
##
## Two output formats consume this IR:
##   emit_text.nim  → nftables text format (for `nft -f`)
##   emit_json.nim  → nftables JSON format (for `nft -j -f`)

## No imports needed -- pure type definitions + constructors.

type
  # =========================================================================
  # Expressions -- the building blocks of match conditions and values
  # =========================================================================

  ExprKind* = enum
    ekString          ## literal string ("eth0", "lo")
    ekInt             ## literal integer (22, 443)
    ekBool            ## literal boolean
    ekList            ## anonymous set: [22, 80, 443]
    ekPrefix          ## CIDR prefix: 192.168.0.0/24
    ekRange           ## range: 6881-6999
    ekConcat          ## concatenation: { iifname . oifname }
    ekPayload         ## payload field: tcp dport, ip saddr
    ekMeta            ## meta key: iifname, oifname, nfproto, l4proto
    ekCt              ## conntrack: ct state, ct mark
    ekFib             ## fib lookup: fib saddr . iif oif
    ekSet             ## named set reference: @setname
    ekMap             ## map lookup: vmap @mapname
    ekElem            ## set element with optional timeout/expiry

  Expr* = ref object
    case kind*: ExprKind
    of ekString:
      strVal*: string
    of ekInt:
      intVal*: int
    of ekBool:
      boolVal*: bool
    of ekList:
      listElems*: seq[Expr]
    of ekPrefix:
      prefixAddr*: string
      prefixLen*: int
    of ekRange:
      rangeMin*, rangeMax*: Expr
    of ekConcat:
      concatExprs*: seq[Expr]
    of ekPayload:
      payloadProto*: string    ## "tcp", "udp", "ip", "ip6", "icmp", "icmpv6"
      payloadField*: string    ## "dport", "sport", "saddr", "daddr", "type", "flags"
    of ekMeta:
      metaKey*: string         ## "iifname", "oifname", "nfproto", "l4proto", "iif", "mark"
    of ekCt:
      ctKey*: string           ## "state", "mark", "status", "direction"
      ctDir*: string           ## "original", "reply" (empty = no direction)
      ctFamily*: string        ## "ip", "ip6" (empty = auto)
    of ekFib:
      fibResult*: string       ## "oif", "type"
      fibFlags*: seq[string]   ## ["saddr", "iif"], ["saddr", "mark", "iif"]
    of ekSet:
      setName*: string         ## name of the named set (without @)
    of ekMap:
      mapKey*: Expr
      mapData*: string         ## named map reference (without @)
    of ekElem:
      elemVal*: Expr
      elemTimeout*: int        ## timeout in seconds (0 = none)

  # =========================================================================
  # Statements -- the items in a rule's expression list
  # =========================================================================

  StmtKind* = enum
    skMatch            ## match: left op right
    skAccept           ## accept verdict
    skDrop             ## drop verdict
    skReject           ## reject verdict
    skReturn           ## return verdict
    skJump             ## jump to chain
    skGoto             ## goto chain
    skCounter          ## counter
    skLog              ## log with prefix/level
    skLimit            ## rate limit
    skDnat             ## destination NAT
    skSnat             ## source NAT
    skMasquerade       ## masquerade
    skVmap             ## verdict map dispatch
    skMangle           ## set meta/ct fields
    skUpdate           ## update dynamic set (for per-IP rate limiting)

  MatchOp* = enum
    opEq  = "=="
    opNeq = "!="
    opLt  = "<"
    opGt  = ">"
    opLte = "<="
    opGte = ">="
    opIn  = "in"

  Stmt* = ref object
    case kind*: StmtKind
    of skMatch:
      matchOp*: MatchOp
      matchLeft*: Expr
      matchRight*: Expr
    of skAccept, skDrop, skReturn:
      discard
    of skReject:
      rejectType*: string      ## "icmpx", "icmp", "icmpv6", "tcp reset"
      rejectExpr*: string      ## "admin-prohibited", "host-unreachable", etc.
    of skJump:
      jumpTarget*: string
    of skGoto:
      gotoTarget*: string
    of skCounter:
      counterName*: string     ## empty for anonymous counter
    of skLog:
      logPrefix*: string
      logLevel*: string        ## "emerg".."debug"
      logFlags*: seq[string]   ## "tcp sequence", "ip options", etc.
    of skLimit:
      limitRate*: int
      limitPer*: string        ## "second", "minute", "hour", "day"
      limitBurst*: int
      limitInv*: bool          ## if true, match when rate exceeded
    of skDnat:
      dnatAddr*: string
      dnatPort*: int           ## 0 = no port remap
      dnatFamily*: string      ## "ip" or "ip6"
    of skSnat:
      snatAddr*: string
      snatPort*: int
      snatFamily*: string
    of skMasquerade:
      masqPort*: int           ## 0 = default
    of skVmap:
      vmapKey*: Expr
      vmapData*: Expr          ## reference to named map
    of skMangle:
      mangleKey*: Expr
      mangleValue*: Expr
    of skUpdate:
      updateSet*: string       ## set name
      updateKey*: Expr
      updateStmts*: seq[Stmt]  ## statements inside the update (limit, etc.)

  # =========================================================================
  # Top-level objects (flat list, matching nftables JSON structure)
  # =========================================================================

  NftObjectKind* = enum
    nokTable
    nokChain
    nokRule
    nokSet
    nokMap
    nokFlush
    nokDelete
    nokComment

  NftChainType* = enum
    nctFilter = "filter"
    nctNat = "nat"
    nctRoute = "route"

  NftChainHook* = enum
    nchPrerouting = "prerouting"
    nchInput = "input"
    nchForward = "forward"
    nchOutput = "output"
    nchPostrouting = "postrouting"

  NftChainPolicy* = enum
    ncpAccept = "accept"
    ncpDrop = "drop"

  NftSetType* = enum
    nstIpv4Addr = "ipv4_addr"
    nstIpv6Addr = "ipv6_addr"
    nstInetService = "inet_service"
    nstIfname = "ifname"
    nstInetProto = "inet_proto"
    nstMark = "mark"
    nstEtherAddr = "ether_addr"

  NftObject* = ref object
    case kind*: NftObjectKind
    of nokTable:
      tableFamily*: string     ## "inet", "ip", "ip6"
      tableName*: string
    of nokChain:
      chainFamily*: string
      chainTable*: string
      chainName*: string
      chainIsBase*: bool       ## true = has type/hook/prio/policy
      chainType*: NftChainType
      chainHook*: NftChainHook
      chainPrio*: int
      chainPolicy*: NftChainPolicy
    of nokRule:
      ruleFamily*: string
      ruleTable*: string
      ruleChain*: string
      ruleExprs*: seq[Stmt]
      ruleComment*: string
    of nokSet:
      setFamily*: string
      setTable*: string
      setName*: string
      setType*: string         ## "ipv4_addr", "ipv6_addr", etc. (or concat)
      setFlags*: seq[string]   ## "interval", "timeout", "dynamic"
      setElems*: seq[Expr]     ## initial elements
      setSize*: int            ## 0 = default
      setTimeout*: int         ## timeout in seconds, 0 = none
    of nokMap:
      mapFamily*: string
      mapTable*: string
      mapName*: string
      mapKeyType*: string      ## key type
      mapValueType*: string    ## value type (or "verdict" for vmaps)
      mapFlags*: seq[string]
      mapElems*: seq[tuple[key: Expr, value: Expr]]
    of nokFlush:
      flushWhat*: string       ## "ruleset", "table", "chain", "set"
      flushFamily*: string
      flushName*: string
    of nokDelete:
      deleteWhat*: string      ## "table"
      deleteFamily*: string
      deleteName*: string
    of nokComment:
      commentText*: string

  ## The full ruleset -- a flat list of objects
  NftRuleset* = object
    objects*: seq[NftObject]

# ---------------------------------------------------------------------------
# Convenience constructors
# ---------------------------------------------------------------------------

proc strExpr*(s: string): Expr = Expr(kind: ekString, strVal: s)
proc intExpr*(i: int): Expr = Expr(kind: ekInt, intVal: i)
proc boolExpr*(b: bool): Expr = Expr(kind: ekBool, boolVal: b)
proc listExpr*(elems: seq[Expr]): Expr = Expr(kind: ekList, listElems: elems)
proc prefixExpr*(addr4: string, len: int): Expr =
  Expr(kind: ekPrefix, prefixAddr: addr4, prefixLen: len)
proc rangeExpr*(lo, hi: Expr): Expr = Expr(kind: ekRange, rangeMin: lo, rangeMax: hi)
proc concatExpr*(exprs: seq[Expr]): Expr = Expr(kind: ekConcat, concatExprs: exprs)

proc payloadExpr*(proto, field: string): Expr =
  Expr(kind: ekPayload, payloadProto: proto, payloadField: field)

proc metaExpr*(key: string): Expr =
  Expr(kind: ekMeta, metaKey: key)

proc ctExpr*(key: string, dir: string = "", family: string = ""): Expr =
  Expr(kind: ekCt, ctKey: key, ctDir: dir, ctFamily: family)

proc fibExpr*(res: string, flags: seq[string]): Expr =
  Expr(kind: ekFib, fibResult: res, fibFlags: flags)

proc setRef*(name: string): Expr =
  Expr(kind: ekSet, setName: name)

proc matchStmt*(op: MatchOp, left, right: Expr): Stmt =
  Stmt(kind: skMatch, matchOp: op, matchLeft: left, matchRight: right)

proc acceptStmt*(): Stmt = Stmt(kind: skAccept)
proc dropStmt*(): Stmt = Stmt(kind: skDrop)
proc returnStmt*(): Stmt = Stmt(kind: skReturn)

proc rejectStmt*(typ: string = "icmpx", expr: string = "admin-prohibited"): Stmt =
  Stmt(kind: skReject, rejectType: typ, rejectExpr: expr)

proc jumpStmt*(target: string): Stmt =
  Stmt(kind: skJump, jumpTarget: target)

proc logStmt*(prefix: string = "", level: string = ""): Stmt =
  Stmt(kind: skLog, logPrefix: prefix, logLevel: level)

proc limitStmt*(rate: int, per: string, burst: int = 0, inv: bool = false): Stmt =
  Stmt(kind: skLimit, limitRate: rate, limitPer: per, limitBurst: burst, limitInv: inv)

proc dnatStmt*(addr4: string, port: int = 0, family: string = "ip"): Stmt =
  Stmt(kind: skDnat, dnatAddr: addr4, dnatPort: port, dnatFamily: family)

proc snatStmt*(addr4: string, port: int = 0, family: string = "ip"): Stmt =
  Stmt(kind: skSnat, snatAddr: addr4, snatPort: port, snatFamily: family)

proc masqueradeStmt*(port: int = 0): Stmt =
  Stmt(kind: skMasquerade, masqPort: port)

proc vmapStmt*(key: Expr, data: Expr): Stmt =
  Stmt(kind: skVmap, vmapKey: key, vmapData: data)

proc updateStmt*(setName: string, key: Expr, stmts: seq[Stmt]): Stmt =
  Stmt(kind: skUpdate, updateSet: setName, updateKey: key, updateStmts: stmts)

proc counterStmt*(name: string = ""): Stmt =
  Stmt(kind: skCounter, counterName: name)

# ---------------------------------------------------------------------------
# Top-level object constructors
# ---------------------------------------------------------------------------

proc nftTable*(family, name: string): NftObject =
  NftObject(kind: nokTable, tableFamily: family, tableName: name)

proc nftBaseChain*(family, table, name: string, typ: NftChainType,
                   hook: NftChainHook, prio: int,
                   policy: NftChainPolicy): NftObject =
  NftObject(kind: nokChain, chainFamily: family, chainTable: table,
            chainName: name, chainIsBase: true, chainType: typ,
            chainHook: hook, chainPrio: prio, chainPolicy: policy)

proc nftChain*(family, table, name: string): NftObject =
  NftObject(kind: nokChain, chainFamily: family, chainTable: table,
            chainName: name, chainIsBase: false)

proc nftRule*(family, table, chain: string, exprs: seq[Stmt],
              comment: string = ""): NftObject =
  NftObject(kind: nokRule, ruleFamily: family, ruleTable: table,
            ruleChain: chain, ruleExprs: exprs, ruleComment: comment)

proc nftSet*(family, table, name, setType: string,
             flags: seq[string] = @[], size: int = 0,
             timeout: int = 0, elems: seq[Expr] = @[]): NftObject =
  NftObject(kind: nokSet, setFamily: family, setTable: table,
            setName: name, setType: setType, setFlags: flags,
            setSize: size, setTimeout: timeout, setElems: elems)

proc nftMap*(family, table, name, keyType, valueType: string,
             flags: seq[string] = @[],
             elems: seq[tuple[key: Expr, value: Expr]] = @[]): NftObject =
  NftObject(kind: nokMap, mapFamily: family, mapTable: table,
            mapName: name, mapKeyType: keyType, mapValueType: valueType,
            mapFlags: flags, mapElems: elems)

proc nftDeleteTable*(family, name: string): NftObject =
  NftObject(kind: nokDelete, deleteWhat: "table",
            deleteFamily: family, deleteName: name)

proc nftComment*(text: string): NftObject =
  NftObject(kind: nokComment, commentText: text)
