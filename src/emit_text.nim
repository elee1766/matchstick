## emit_text.nim - Serialize NftRuleset to nftables text format.
##
## Each NftObject kind has an `emit` proc. The top-level `emitText` walks
## the flat object list and groups them by table for proper nesting.

import std/[strutils, tables, sequtils]
import ./nft_ir
import ./writer

# ---------------------------------------------------------------------------
# Expression emission
# ---------------------------------------------------------------------------

proc emitExpr(w: var Writer, e: Expr)  # forward decl

proc emitExprInline(e: Expr): string =
  ## Emit an expression as an inline string (no Writer state needed).
  case e.kind
  of ekString: return "\"" & e.strVal & "\""
  of ekInt: return $e.intVal
  of ekBool: return if e.boolVal: "1" else: "0"
  of ekPrefix: return e.prefixAddr & "/" & $e.prefixLen
  of ekRange: return emitExprInline(e.rangeMin) & "-" & emitExprInline(e.rangeMax)
  of ekSet: return "@" & e.setName
  of ekList:
    if e.listElems.len == 1:
      return emitExprInline(e.listElems[0])
    return "{ " & e.listElems.mapIt(emitExprInline(it)).join(", ") & " }"
  of ekConcat:
    return e.concatExprs.mapIt(emitExprInline(it)).join(" . ")
  of ekPayload:
    return e.payloadProto & " " & e.payloadField
  of ekMeta:
    return "meta " & e.metaKey
  of ekCt:
    result = "ct"
    if e.ctDir != "":
      result &= " " & e.ctDir
    result &= " " & e.ctKey
  of ekFib:
    result = "fib " & e.fibFlags.join(" . ") & " " & e.fibResult
  of ekMap:
    return emitExprInline(e.mapKey) & " map @" & e.mapData
  of ekElem:
    return emitExprInline(e.elemVal)

proc emitExpr(w: var Writer, e: Expr) =
  w.add emitExprInline(e)

# ---------------------------------------------------------------------------
# Emit a value for the right side of a match (handles sets, ranges, etc.)
# ---------------------------------------------------------------------------

proc emitMatchRight(e: Expr): string =
  ## Like emitExprInline but without quoting plain strings (they're values like "established").
  case e.kind
  of ekString: return e.strVal
  of ekInt: return $e.intVal
  of ekBool: return if e.boolVal: "1" else: "0"
  of ekPrefix: return e.prefixAddr & "/" & $e.prefixLen
  of ekRange: return emitMatchRight(e.rangeMin) & "-" & emitMatchRight(e.rangeMax)
  of ekSet: return "@" & e.setName
  of ekList:
    if e.listElems.len == 1:
      return emitMatchRight(e.listElems[0])
    return "{ " & e.listElems.mapIt(emitMatchRight(it)).join(", ") & " }"
  of ekConcat:
    return e.concatExprs.mapIt(emitMatchRight(it)).join(" . ")
  else:
    return emitExprInline(e)

# ---------------------------------------------------------------------------
# Emit left side of match (payload, meta, ct -- unquoted)
# ---------------------------------------------------------------------------

proc emitMetaKey(key: string): string =
  ## Emit a meta key -- common keys omit the "meta" prefix in nftables text.
  case key
  of "iifname", "oifname", "iif", "oif", "iiftype", "oiftype":
    return key
  else:
    return "meta " & key

proc emitMatchLeft(e: Expr): string =
  case e.kind
  of ekPayload:
    return e.payloadProto & " " & e.payloadField
  of ekMeta:
    return emitMetaKey(e.metaKey)
  of ekCt:
    result = "ct"
    if e.ctDir != "":
      result &= " " & e.ctDir
    result &= " " & e.ctKey
  of ekFib:
    return "fib " & e.fibFlags.join(" . ") & " " & e.fibResult
  of ekConcat:
    # Concat of match-left expressions: "iifname . oifname"
    return e.concatExprs.mapIt(emitMatchLeft(it)).join(" . ")
  else:
    return emitExprInline(e)

# ---------------------------------------------------------------------------
# Statement emission
# ---------------------------------------------------------------------------

proc emitStmt(w: var Writer, s: Stmt) =
  case s.kind
  of skMatch:
    let left = emitMatchLeft(s.matchLeft)
    let right = emitMatchRight(s.matchRight)
    # nftables text omits "==" operator -- it's implied
    if s.matchOp == opEq:
      w.add left & " " & right
    elif s.matchOp == opNeq:
      w.add left & " != " & right
    else:
      w.add left & " " & $s.matchOp & " " & right
  of skAccept:
    w.add "accept"
  of skDrop:
    w.add "drop"
  of skReturn:
    w.add "return"
  of skReject:
    w.add "reject"
    if s.rejectType != "":
      w.add " with " & s.rejectType
      if s.rejectExpr != "":
        w.add " " & s.rejectExpr
  of skJump:
    w.add "jump " & s.jumpTarget
  of skGoto:
    w.add "goto " & s.gotoTarget
  of skCounter:
    if s.counterName != "":
      w.add "counter name " & s.counterName
    else:
      w.add "counter"
  of skLog:
    w.add "log"
    if s.logPrefix != "":
      w.add " prefix \"" & s.logPrefix & "\""
    if s.logLevel != "":
      w.add " level " & s.logLevel
  of skLimit:
    w.add "limit rate "
    if s.limitInv:
      w.add "over "
    w.add $s.limitRate & "/" & s.limitPer
    if s.limitBurst > 0:
      w.add " burst " & $s.limitBurst & " packets"
  of skDnat:
    w.add "dnat " & s.dnatFamily & " to " & s.dnatAddr
    if s.dnatPort > 0:
      w.add ":" & $s.dnatPort
  of skSnat:
    w.add "snat " & s.snatFamily & " to " & s.snatAddr
    if s.snatPort > 0:
      w.add ":" & $s.snatPort
  of skMasquerade:
    w.add "masquerade"
    if s.masqPort > 0:
      w.add " to :" & $s.masqPort
  of skVmap:
    let key = emitMatchLeft(s.vmapKey)
    w.add key & " vmap " & emitMatchRight(s.vmapData)
  of skMangle:
    w.add "meta " & emitExprInline(s.mangleKey) & " set " & emitExprInline(s.mangleValue)
  of skUpdate:
    w.add "update @" & s.updateSet & " { " & emitMatchLeft(s.updateKey)
    for sub in s.updateStmts:
      w.add " "
      w.emitStmt(sub)
    w.add " }"

proc emitRuleExprs(w: var Writer, exprs: seq[Stmt]) =
  ## Emit a rule's statement list as a single line.
  for i, s in exprs:
    if i > 0:
      w.add " "
    w.emitStmt(s)

# ---------------------------------------------------------------------------
# Top-level: group objects by table and emit nested text
# ---------------------------------------------------------------------------

type
  TableGroup = object
    table: NftObject
    chains: seq[NftObject]
    rules: seq[NftObject]       # grouped by chain below
    sets: seq[NftObject]
    maps: seq[NftObject]

proc emitText*(rs: NftRuleset): string =
  var w = newWriter()

  # First pass: emit any delete/flush commands and comments at top level
  for obj in rs.objects:
    case obj.kind
    of nokDelete:
      w.line(obj.deleteWhat & " " & obj.deleteFamily & " " & obj.deleteName)
    of nokComment:
      w.line("# " & obj.commentText)
    else:
      discard

  # Group objects by table
  type TableKey = tuple[family, name: string]
  var tableOrder: seq[TableKey]
  var groups: Table[TableKey, TableGroup]

  for obj in rs.objects:
    case obj.kind
    of nokTable:
      let key: TableKey = (obj.tableFamily, obj.tableName)
      if key notin groups:
        tableOrder.add key
        groups[key] = TableGroup(table: obj)
    of nokChain:
      let key: TableKey = (obj.chainFamily, obj.chainTable)
      if key in groups:
        groups[key].chains.add obj
    of nokRule:
      let key: TableKey = (obj.ruleFamily, obj.ruleTable)
      if key in groups:
        groups[key].rules.add obj
    of nokSet:
      let key: TableKey = (obj.setFamily, obj.setTable)
      if key in groups:
        groups[key].sets.add obj
    of nokMap:
      let key: TableKey = (obj.mapFamily, obj.mapTable)
      if key in groups:
        groups[key].maps.add obj
    else:
      discard

  # Emit each table
  for key in tableOrder:
    let g = groups[key]
    let tbl = g.table

    # Atomic replacement: declare table, delete, re-declare with contents
    w.line("table " & tbl.tableFamily & " " & tbl.tableName)
    w.line("delete table " & tbl.tableFamily & " " & tbl.tableName)
    w.emptyLine()

    w.braced("table " & tbl.tableFamily & " " & tbl.tableName):
      # Sets
      for s in g.sets:
        w.emptyLine()
        w.braced("set " & s.setName):
          w.line("type " & s.setType)
          if s.setFlags.len > 0:
            w.line("flags " & s.setFlags.join(", "))
          if s.setSize > 0:
            w.line("size " & $s.setSize)
          if s.setTimeout > 0:
            w.line("timeout " & $s.setTimeout & "s")
          if s.setElems.len > 0:
            w.line("elements = { " & s.setElems.mapIt(emitMatchRight(it)).join(", ") & " }")

      # Maps
      for m in g.maps:
        w.emptyLine()
        w.braced("map " & m.mapName):
          if m.mapValueType == "verdict":
            w.line("type " & m.mapKeyType & " : verdict")
          else:
            w.line("type " & m.mapKeyType & " : " & m.mapValueType)
          if m.mapFlags.len > 0:
            w.line("flags " & m.mapFlags.join(", "))
          if m.mapElems.len > 0:
            w.line("elements = {")
            w.indented:
              for i, elem in m.mapElems:
                let kStr = emitExprInline(elem.key)  # keys need quoting
                let vStr = emitMatchRight(elem.value) # values like "jump X" don't
                let comma = if i < m.mapElems.len - 1: "," else: ""
                w.line(kStr & " : " & vStr & comma)
            w.line("}")

      # Group rules by chain for emission
      var chainRules: Table[string, seq[NftObject]]
      for r in g.rules:
        if r.ruleChain notin chainRules:
          chainRules[r.ruleChain] = @[]
        chainRules[r.ruleChain].add r

      # Chains + their rules
      for c in g.chains:
        let rules = chainRules.getOrDefault(c.chainName, @[])

        # Optimize: single-statement chains on one line
        if not c.chainIsBase and rules.len == 1 and rules[0].ruleExprs.len == 1:
          let onlyStmt = rules[0].ruleExprs[0]
          if onlyStmt.kind in {skAccept, skDrop}:
            var inline = ""
            case onlyStmt.kind
            of skAccept: inline = "accept"
            of skDrop: inline = "drop"
            else: discard
            w.emptyLine()
            w.bracedOneline("chain " & c.chainName, inline)
            continue

        w.emptyLine()
        w.braced("chain " & c.chainName):
          # Base chain header
          if c.chainIsBase:
            # Map priority to named base + offset
            # Standard named priorities: filter=0, dstnat=-100, srcnat=100
            let (baseName, baseVal) = case c.chainHook
              of nchPrerouting:
                if c.chainType == nctNat: ("dstnat", -100)
                else: ("filter", 0)
              of nchPostrouting:
                if c.chainType == nctNat: ("srcnat", 100)
                else: ("filter", 0)
              else: ("filter", 0)
            let diff = c.chainPrio - baseVal
            let prio = if diff == 0: baseName
                       elif diff > 0: baseName & " + " & $diff
                       else: baseName & " - " & $(-diff)
            w.line("type " & $c.chainType & " hook " & $c.chainHook &
                   " priority " & prio & "; policy " & $c.chainPolicy & ";")

          # Rules
          for r in rules:
            w.add ""
            w.emitRuleExprs(r.ruleExprs)
            if r.ruleComment != "":
              w.add " comment \"" & r.ruleComment & "\""
            w.buf.add '\n'
            w.atLineStart = true

    w.emptyLine()

  result = w.result()
