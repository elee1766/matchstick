## nft_ir.nim - Typed intermediate representation for nftables rulesets.
##
## Top-level objects (NftTable, NftChain, NftRule, NftSet, NftMap) are records
## that serialize to JSON via custom dumpHooks in emit_json.nim.
##
## NftChain and NftSet are object variants -- the variant arm determines which
## fields are present, and the JSON emitter only writes those fields. This
## avoids `Option[T] = none` rendering as `"field": null` (which nftables JSON
## rejects).

import std/[strutils, algorithm, json]

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
    skMatch, skAccept, skDrop, skReject, skReturn, skNotrack,
    skJump, skGoto, skCounter, skLog, skLimit,
    skDnat, skSnat, skMasquerade, skRedirect, skTproxy, skVmap, skMangle, skUpdate,
    skConnLimit, skMssClamp, skQueue, skDup, skQuota,
    skRaw

  Stmt* = ref object
    case kind*: StmtKind
    of skMatch:
      matchOp*: MatchOp
      matchLeft*: Expr
      matchRight*: Expr
    of skAccept, skDrop, skReturn, skNotrack:
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
    of skRedirect:
      redirectPort*: int
      redirectFamily*: string
    of skTproxy:
      tproxyAddr*: string
      tproxyPort*: int
      tproxyFamily*: string
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
    of skConnLimit:
      connLimitCount*: int
      connLimitFlags*: string     ## "inverse" or "" for normal
    of skMssClamp:
      mssClampSize*: int          ## 0 = use "rt mtu" (PMTUD)
    of skQueue:
      queueNum*: int
      queueFlags*: string         ## "bypass", "fanout", or ""
    of skDup:
      dupAddr*: string
      dupDev*: string
    of skQuota:
      quotaVal*: int
      quotaUnit*: string          ## "bytes", "kbytes", "mbytes"
      quotaInv*: bool             ## true = "over" (inverse match)
    of skRaw:
      rawJson*: JsonNode          ## nftables JSON statement object

  # =========================================================================
  # Top-level objects
  # =========================================================================

  NftTable* = object
    family*: string
    name*: string

  NftChainKind* = enum
    chkRegular   ## user-defined chain (no hook, no policy)
    chkBase      ## base chain attached to a netfilter hook

  NftChain* = object
    family*: string
    table*: string
    name*: string
    case kind*: NftChainKind
    of chkRegular:
      discard
    of chkBase:
      `type`*: string      ## "filter" | "nat" | "route"
      hook*: string        ## "input" | "output" | "forward" | "prerouting" | "postrouting"
      prio*: int
      policy*: string      ## "accept" | "drop"

  NftRule* = object
    family*: string
    table*: string
    chain*: string
    expr*: seq[Stmt]
    comment*: string       ## "" means no comment

  NftSetKind* = enum
    setkPlain      ## anonymous/literal -- elements directly, no flags/size/timeout
    setkNamed      ## named set with optional flags/size/timeout

  NftSet* = object
    family*: string
    table*: string
    name*: string
    `type`*: string              ## "ipv4_addr", "ipv6_addr", etc.
    case kind*: NftSetKind
    of setkPlain:
      plainElem*: seq[Expr]
    of setkNamed:
      flags*: seq[string]        ## empty = absent
      size*: int                 ## 0 = absent
      timeout*: int              ## 0 = absent
      elem*: seq[Expr]           ## may be empty

  NftMapElem* = object
    key*: Expr
    value*: Expr

  NftMap* = object
    family*: string
    table*: string
    name*: string
    `type`*: string              ## key type -- may be "ifname . ifname"
    `map`*: string               ## value type -- "verdict" for vmaps
    flags*: seq[string]          ## empty = absent
    elem*: seq[NftMapElem]       ## may be empty

  # =========================================================================
  # Command wrappers -- the actual JSON structure
  # =========================================================================

  NftCmdKind* = enum
    nckAdd, nckDelete, nckMetainfo, nckRaw

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
    of nckRaw:
      rawCmds*: seq[JsonNode]     ## nftables JSON command objects

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
proc redirectStmt*(port: int, family = "ip"): Stmt = Stmt(kind: skRedirect, redirectPort: port, redirectFamily: family)
proc connLimitStmt*(count: int, flags = ""): Stmt = Stmt(kind: skConnLimit, connLimitCount: count, connLimitFlags: flags)
proc mssClampStmt*(size = 0): Stmt = Stmt(kind: skMssClamp, mssClampSize: size)
proc notrackStmt*(): Stmt = Stmt(kind: skNotrack)
proc tproxyStmt*(a: string, port: int, family = "ip"): Stmt = Stmt(kind: skTproxy, tproxyAddr: a, tproxyPort: port, tproxyFamily: family)
proc queueStmt*(num: int, flags = ""): Stmt = Stmt(kind: skQueue, queueNum: num, queueFlags: flags)
proc dupStmt*(a: string, dev = ""): Stmt = Stmt(kind: skDup, dupAddr: a, dupDev: dev)
proc quotaStmt*(val: int, unit = "bytes", inv = false): Stmt = Stmt(kind: skQuota, quotaVal: val, quotaUnit: unit, quotaInv: inv)
proc rawStmt*(j: JsonNode): Stmt = Stmt(kind: skRaw, rawJson: j)

# ---------------------------------------------------------------------------
# Convenience constructors for top-level commands
# ---------------------------------------------------------------------------

proc addTable*(family, name: string): NftCmd =
  NftCmd(kind: nckAdd, add: NftAddObj(kind: nakTable, table: NftTable(family: family, name: name)))

proc addChain*(family, table, name: string): NftCmd =
  NftCmd(kind: nckAdd, add: NftAddObj(kind: nakChain, chain: NftChain(
    family: family, table: table, name: name, kind: chkRegular)))

proc addBaseChain*(family, table, name, typ, hook: string, prio: int, policy: string): NftCmd =
  NftCmd(kind: nckAdd, add: NftAddObj(kind: nakChain, chain: NftChain(
    family: family, table: table, name: name,
    kind: chkBase,
    `type`: typ, hook: hook, prio: prio, policy: policy)))

proc addRule*(family, table, chain: string, expr: seq[Stmt], comment = ""): NftCmd =
  NftCmd(kind: nckAdd, add: NftAddObj(kind: nakRule, rule: NftRule(
    family: family, table: table, chain: chain, expr: expr, comment: comment)))

proc addSet*(family, table, name, typ: string,
             flags: seq[string] = @[], size = 0, timeout = 0,
             elem: seq[Expr] = @[]): NftCmd =
  NftCmd(kind: nckAdd, add: NftAddObj(kind: nakSet, set: NftSet(
    family: family, table: table, name: name, `type`: typ,
    kind: setkNamed,
    flags: flags, size: size, timeout: timeout, elem: elem)))

proc addPlainSet*(family, table, name, typ: string, elems: seq[Expr]): NftCmd =
  NftCmd(kind: nckAdd, add: NftAddObj(kind: nakSet, set: NftSet(
    family: family, table: table, name: name, `type`: typ,
    kind: setkPlain, plainElem: elems)))

proc addMap*(family, table, name, typ, mapVal: string,
             flags: seq[string] = @[],
             elem: seq[NftMapElem] = @[]): NftCmd =
  NftCmd(kind: nckAdd, add: NftAddObj(kind: nakMap, map: NftMap(
    family: family, table: table, name: name,
    `type`: typ, `map`: mapVal, flags: flags, elem: elem)))

proc deleteTable*(family, name: string): NftCmd =
  NftCmd(kind: nckDelete, deleteWhat: "table", delete: NftDeleteObj(family: family, name: name))

proc metainfoCmd*(): NftCmd =
  NftCmd(kind: nckMetainfo, metainfo: NftMetainfo(json_schema_version: 1))

proc rawCmd*(cmds: seq[JsonNode]): NftCmd =
  NftCmd(kind: nckRaw, rawCmds: cmds)
