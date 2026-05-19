## nft_ir.nim - Typed intermediate representation for nftables rulesets.
##
## Top-level objects (NftTable, NftChain, NftRule, NftSet, NftMap) are plain
## records that serialize to JSON automatically via jsony.
##
## Expr and Stmt are object variants that need custom dumpHook/parseHook
## because the nftables JSON schema uses key-based dispatch:
##   {"match": {...}} / {"accept": null} / {"jump": {"target": "..."}}

import std/[strutils, algorithm, options]

type
  # =========================================================================
  # Expressions -- object variants, need custom JSON hooks
  # =========================================================================

  ExprKind* = enum
    ekString, ekInt, ekBool,
    ekList, ekPrefix, ekRange, ekConcat,
    ekPayload, ekMeta, ekCt, ekFib,
    ekSet, ekMap, ekElem,
    ekVerdict, ekBinOp, ekAnonymousSet

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
      rangeMin*: Expr
      rangeMax*: Expr
    of ekConcat:
      concatExprs*: seq[Expr]
    of ekPayload:
      payloadProto*: string
      payloadField*: string
    of ekMeta:
      metaKey*: string
    of ekCt:
      ctKey*: string
      ctDir*: string
      ctFamily*: string
    of ekFib:
      fibResult*: string
      fibFlags*: seq[string]
    of ekSet:
      setName*: string
    of ekMap:
      mapKey*: Expr
      mapData*: string
    of ekElem:
      elemVal*: Expr
      elemTimeout*: int
    of ekVerdict:
      verdictKind*: string
      verdictTarget*: string
    of ekBinOp:
      binOp*: string
      binLeft*: Expr
      binRight*: Expr
    of ekAnonymousSet:
      anonSetElems*: seq[Expr]

  MatchOp* = enum
    opEq  = "=="
    opNeq = "!="
    opNot = "!"
    opLt  = "<"
    opGt  = ">"
    opLte = "<="
    opGte = ">="
    opIn  = "in"

  # =========================================================================
  # Statements -- object variants, need custom JSON hooks
  # =========================================================================

  StmtKind* = enum
    skMatch, skAccept, skDrop, skReject, skReturn,
    skJump, skGoto, skCounter, skLog, skLimit,
    skDnat, skSnat, skMasquerade, skVmap, skMangle, skUpdate

  Stmt* = ref object
    case kind*: StmtKind
    of skMatch:
      matchOp*: MatchOp
      matchLeft*: Expr
      matchRight*: Expr
    of skAccept, skDrop, skReturn:
      discard
    of skReject:
      rejectType*: string
      rejectExpr*: string
    of skJump:
      jumpTarget*: string
    of skGoto:
      gotoTarget*: string
    of skCounter:
      counterName*: string
    of skLog:
      logPrefix*: string
      logLevel*: string
      logFlags*: seq[string]
    of skLimit:
      limitRate*: int
      limitPer*: string
      limitBurst*: int
      limitInv*: bool
    of skDnat:
      dnatAddr*: string
      dnatPort*: int
      dnatFamily*: string
    of skSnat:
      snatAddr*: string
      snatPort*: int
      snatFamily*: string
    of skMasquerade:
      masqPort*: int
    of skVmap:
      vmapKey*: Expr
      vmapData*: Expr
    of skMangle:
      mangleKey*: Expr
      mangleValue*: Expr
    of skUpdate:
      updateSet*: string
      updateKey*: Expr
      updateStmts*: seq[Stmt]

  # =========================================================================
  # Top-level objects -- plain records, auto-serialize via jsony
  # =========================================================================

  NftTable* = object
    family*: string
    name*: string

  NftChain* = object
    family*: string
    table*: string
    name*: string
    # Base chain fields (omitted for regular chains via Option)
    chainType*: Option[string]   ## "filter", "nat", "route"  (JSON field: "type")
    hook*: Option[string]        ## "input", "output", "forward", "prerouting", "postrouting"
    prio*: Option[int]
    policy*: Option[string]      ## "accept", "drop"

  NftRule* = object
    family*: string
    table*: string
    chain*: string
    expr*: seq[Stmt]
    comment*: Option[string]

  NftSet* = object
    family*: string
    table*: string
    name*: string
    setType*: string             ## "ipv4_addr", "ipv6_addr", etc. (JSON field: "type")
    flags*: Option[seq[string]]
    size*: Option[int]
    timeout*: Option[int]
    elem*: Option[seq[Expr]]

  NftMapElem* = object
    key*: Expr
    value*: Expr

  NftMap* = object
    family*: string
    table*: string
    name*: string
    keyType*: string             ## key type (JSON field: "type") -- may be "ifname . ifname"
    mapType*: string             ## value type (JSON field: "map") -- "verdict" for vmaps
    flags*: Option[seq[string]]
    elem*: Option[seq[NftMapElem]]

  # =========================================================================
  # Command wrappers -- the actual JSON structure
  # =========================================================================

  NftCmdKind* = enum
    nckAdd, nckDelete, nckMetainfo

  NftAddKind* = enum
    nakTable, nakChain, nakRule, nakSet, nakMap

  NftAddObj* = object
    case kind*: NftAddKind
    of nakTable: table*: NftTable
    of nakChain: chain*: NftChain
    of nakRule:  rule*: NftRule
    of nakSet:   set*: NftSet
    of nakMap:   map*: NftMap

  NftDeleteObj* = object
    family*: string
    name*: string

  NftMetainfo* = object
    json_schema_version*: int

  NftCmd* = object
    case kind*: NftCmdKind
    of nckAdd:
      add*: NftAddObj
    of nckDelete:
      deleteWhat*: string
      delete*: NftDeleteObj
    of nckMetainfo:
      metainfo*: NftMetainfo

  NftRuleset* = object
    nftables*: seq[NftCmd]

# ---------------------------------------------------------------------------
# Convenience constructors for Expr
# ---------------------------------------------------------------------------

proc strExpr*(s: string): Expr = Expr(kind: ekString, strVal: s)
proc intExpr*(i: int): Expr = Expr(kind: ekInt, intVal: i)
proc boolExpr*(b: bool): Expr = Expr(kind: ekBool, boolVal: b)
proc listExpr*(elems: seq[Expr]): Expr = Expr(kind: ekList, listElems: elems)
proc prefixExpr*(a: string, l: int): Expr = Expr(kind: ekPrefix, prefixAddr: a, prefixLen: l)
proc rangeExpr*(lo, hi: Expr): Expr = Expr(kind: ekRange, rangeMin: lo, rangeMax: hi)
proc concatExpr*(exprs: seq[Expr]): Expr = Expr(kind: ekConcat, concatExprs: exprs)
proc payloadExpr*(proto, field: string): Expr = Expr(kind: ekPayload, payloadProto: proto, payloadField: field)
proc metaExpr*(key: string): Expr = Expr(kind: ekMeta, metaKey: key)
proc ctExpr*(key: string, dir = "", family = ""): Expr = Expr(kind: ekCt, ctKey: key, ctDir: dir, ctFamily: family)
proc fibExpr*(res: string, flags: seq[string]): Expr = Expr(kind: ekFib, fibResult: res, fibFlags: flags)
proc setRef*(name: string): Expr = Expr(kind: ekSet, setName: name)
proc verdictExpr*(kind: string, target = ""): Expr = Expr(kind: ekVerdict, verdictKind: kind, verdictTarget: target)
proc binOpExpr*(op: string, left, right: Expr): Expr = Expr(kind: ekBinOp, binOp: op, binLeft: left, binRight: right)
proc anonSetExpr*(elems: seq[Expr]): Expr = Expr(kind: ekAnonymousSet, anonSetElems: elems)

proc sortKey*(e: Expr): int =
  case e.kind
  of ekInt: e.intVal
  of ekRange: e.rangeMin.sortKey
  of ekString: (try: parseInt(e.strVal) except ValueError: high(int))
  else: high(int)

proc sortedAnonSetExpr*(elems: seq[Expr]): Expr =
  var sorted = elems
  sorted.sort(proc(a, b: Expr): int = cmp(a.sortKey, b.sortKey))
  Expr(kind: ekAnonymousSet, anonSetElems: sorted)

# ---------------------------------------------------------------------------
# Convenience constructors for Stmt
# ---------------------------------------------------------------------------

proc matchStmt*(op: MatchOp, left, right: Expr): Stmt = Stmt(kind: skMatch, matchOp: op, matchLeft: left, matchRight: right)
proc acceptStmt*(): Stmt = Stmt(kind: skAccept)
proc dropStmt*(): Stmt = Stmt(kind: skDrop)
proc returnStmt*(): Stmt = Stmt(kind: skReturn)
proc rejectStmt*(typ = "icmpx", expr = "admin-prohibited"): Stmt = Stmt(kind: skReject, rejectType: typ, rejectExpr: expr)
proc jumpStmt*(target: string): Stmt = Stmt(kind: skJump, jumpTarget: target)
proc logStmt*(prefix = "", level = ""): Stmt = Stmt(kind: skLog, logPrefix: prefix, logLevel: level)
proc limitStmt*(rate: int, per: string, burst = 0, inv = false): Stmt = Stmt(kind: skLimit, limitRate: rate, limitPer: per, limitBurst: burst, limitInv: inv)
proc dnatStmt*(a: string, port = 0, family = "ip"): Stmt = Stmt(kind: skDnat, dnatAddr: a, dnatPort: port, dnatFamily: family)
proc snatStmt*(a: string, port = 0, family = "ip"): Stmt = Stmt(kind: skSnat, snatAddr: a, snatPort: port, snatFamily: family)
proc masqueradeStmt*(port = 0): Stmt = Stmt(kind: skMasquerade, masqPort: port)
proc vmapStmt*(key, data: Expr): Stmt = Stmt(kind: skVmap, vmapKey: key, vmapData: data)
proc updateStmt*(setName: string, key: Expr, stmts: seq[Stmt]): Stmt = Stmt(kind: skUpdate, updateSet: setName, updateKey: key, updateStmts: stmts)
proc counterStmt*(name = ""): Stmt = Stmt(kind: skCounter, counterName: name)

# ---------------------------------------------------------------------------
# Convenience constructors for top-level commands
# ---------------------------------------------------------------------------

proc addTable*(family, name: string): NftCmd =
  NftCmd(kind: nckAdd, add: NftAddObj(kind: nakTable, table: NftTable(family: family, name: name)))

proc addChain*(family, table, name: string): NftCmd =
  NftCmd(kind: nckAdd, add: NftAddObj(kind: nakChain, chain: NftChain(family: family, table: table, name: name)))

proc addBaseChain*(family, table, name, typ, hook: string, prio: int, policy: string): NftCmd =
  NftCmd(kind: nckAdd, add: NftAddObj(kind: nakChain, chain: NftChain(
    family: family, table: table, name: name,
    chainType: some(typ), hook: some(hook), prio: some(prio), policy: some(policy))))

proc addRule*(family, table, chain: string, expr: seq[Stmt], comment = ""): NftCmd =
  let c = if comment != "": some(comment) else: none(string)
  NftCmd(kind: nckAdd, add: NftAddObj(kind: nakRule, rule: NftRule(
    family: family, table: table, chain: chain, expr: expr, comment: c)))

proc addSet*(family, table, name, setType: string,
             flags: seq[string] = @[], size = 0, timeout = 0,
             elem: seq[Expr] = @[]): NftCmd =
  let f = if flags.len > 0: some(flags) else: none(seq[string])
  let s = if size > 0: some(size) else: none(int)
  let t = if timeout > 0: some(timeout) else: none(int)
  let e = if elem.len > 0: some(elem) else: none(seq[Expr])
  NftCmd(kind: nckAdd, add: NftAddObj(kind: nakSet, set: NftSet(
    family: family, table: table, name: name, setType: setType,
    flags: f, size: s, timeout: t, elem: e)))

proc addMap*(family, table, name, keyType, mapType: string,
             flags: seq[string] = @[],
             elem: seq[NftMapElem] = @[]): NftCmd =
  let f = if flags.len > 0: some(flags) else: none(seq[string])
  let e = if elem.len > 0: some(elem) else: none(seq[NftMapElem])
  NftCmd(kind: nckAdd, add: NftAddObj(kind: nakMap, map: NftMap(
    family: family, table: table, name: name,
    keyType: keyType, mapType: mapType, flags: f, elem: e)))

proc deleteTable*(family, name: string): NftCmd =
  NftCmd(kind: nckDelete, deleteWhat: "table", delete: NftDeleteObj(family: family, name: name))

proc metainfoCmd*(): NftCmd =
  NftCmd(kind: nckMetainfo, metainfo: NftMetainfo(json_schema_version: 1))
