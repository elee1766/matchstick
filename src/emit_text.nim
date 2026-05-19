## emit_text.nim - nftables text format emission from IR.

import std/[strutils, tables, sequtils, options]
import ./nft_ir
import ./writer

# ---------------------------------------------------------------------------
# Expr → text
# ---------------------------------------------------------------------------

proc toText*(e: Expr): string =
  if e == nil: return "null"
  case e.kind
  of ekString:   e.strVal
  of ekInt:      $e.intVal
  of ekBool:     (if e.boolVal: "1" else: "0")
  of ekPrefix:   e.prefixAddr & "/" & $e.prefixLen
  of ekRange:    e.rangeMin.toText & "-" & e.rangeMax.toText
  of ekSet:      "@" & e.setName
  of ekList:
    if e.listElems.len == 1: e.listElems[0].toText
    else: "{ " & e.listElems.mapIt(it.toText).join(", ") & " }"
  of ekConcat:   e.concatExprs.mapIt(it.toText).join(" . ")
  of ekPayload:  e.payloadProto & " " & e.payloadField
  of ekMeta:
    case e.metaKey
    of "iifname", "oifname", "iif", "oif", "iiftype", "oiftype": e.metaKey
    else: "meta " & e.metaKey
  of ekCt:
    var r = "ct"
    if e.ctDir != "": r &= " " & e.ctDir
    r & " " & e.ctKey
  of ekFib:      "fib " & e.fibFlags.join(" . ") & " " & e.fibResult
  of ekMap:      e.mapKey.toText & " map @" & e.mapData
  of ekElem:     e.elemVal.toText
  of ekVerdict:
    if e.verdictTarget != "": e.verdictKind & " " & e.verdictTarget
    else: e.verdictKind
  of ekBinOp:
    if e.binOp == "|": e.binLeft.toText & "|" & e.binRight.toText
    else: e.binLeft.toText & " " & e.binOp & " " & e.binRight.toText
  of ekAnonymousSet:
    if e.anonSetElems.len == 1: e.anonSetElems[0].toText
    elif e.anonSetElems.len > 0 and e.anonSetElems[0].kind == ekList:
      var parts: seq[string]
      for elem in e.anonSetElems:
        if elem.kind == ekList and elem.listElems.len == 2:
          parts.add elem.listElems[0].toText & " : " & elem.listElems[1].toText
        else: parts.add elem.toText
      "{ " & parts.join(", ") & " }"
    else:
      "{ " & e.anonSetElems.mapIt(it.toText).join(", ") & " }"

proc toMatchLeft*(e: Expr): string =
  if e == nil: return "null"
  case e.kind
  of ekBinOp:
    if e.binOp == "&":
      let r = if e.binRight.kind == ekList:
                "(" & e.binRight.listElems.mapIt(it.toText).join("|") & ")"
              else: "(" & e.binRight.toText & ")"
      e.binLeft.toMatchLeft & " & " & r
    else: e.binLeft.toMatchLeft & " " & e.binOp & " " & e.binRight.toText
  of ekConcat: e.concatExprs.mapIt(it.toMatchLeft).join(" . ")
  else: e.toText

proc toQuoted*(e: Expr): string =
  if e == nil: return "null"
  case e.kind
  of ekString: "\"" & e.strVal & "\""
  else: e.toText

# ---------------------------------------------------------------------------
# Stmt → text
# ---------------------------------------------------------------------------

proc emitStmt*(w: var Writer, s: Stmt) =
  case s.kind
  of skMatch:
    let left = s.matchLeft.toMatchLeft
    let right = s.matchRight.toText
    case s.matchOp
    of opEq, opIn: w.add left & " " & right
    of opNot:
      if s.matchRight.kind == ekList:
        w.add left & " ! " & s.matchRight.listElems.mapIt(it.toText).join(",")
      else: w.add left & " ! " & right
    of opNeq: w.add left & " != " & right
    else: w.add left & " " & $s.matchOp & " " & right
  of skAccept:     w.add "accept"
  of skDrop:       w.add "drop"
  of skReturn:     w.add "return"
  of skReject:
    w.add "reject"
    if s.rejectType != "": w.add " with " & s.rejectType
    if s.rejectExpr != "": w.add " " & s.rejectExpr
  of skJump:       w.add "jump " & s.jumpTarget
  of skGoto:       w.add "goto " & s.gotoTarget
  of skCounter:
    if s.counterName != "": w.add "counter name " & s.counterName
    else: w.add "counter"
  of skLog:
    w.add "log"
    if s.logPrefix != "": w.add " prefix \"" & s.logPrefix & "\""
    if s.logLevel != "": w.add " level " & s.logLevel
  of skLimit:
    w.add "limit rate "
    if s.limitInv: w.add "over "
    w.add $s.limitRate & "/" & s.limitPer
    if s.limitBurst > 0: w.add " burst " & $s.limitBurst & " packets"
  of skDnat:
    w.add "dnat " & s.dnatFamily & " to " & s.dnatAddr
    if s.dnatPort > 0: w.add ":" & $s.dnatPort
  of skSnat:
    w.add "snat " & s.snatFamily & " to " & s.snatAddr
    if s.snatPort > 0: w.add ":" & $s.snatPort
  of skMasquerade:
    w.add "masquerade"
    if s.masqPort > 0: w.add " to :" & $s.masqPort
  of skVmap:    w.add s.vmapKey.toMatchLeft & " vmap " & s.vmapData.toText
  of skMangle:  w.add s.mangleKey.toText & " set " & s.mangleValue.toText
  of skUpdate:
    w.add "update @" & s.updateSet & " { " & s.updateKey.toMatchLeft
    for sub in s.updateStmts: w.add " "; w.emitStmt(sub)
    w.add " }"

proc emitRuleLine(w: var Writer, stmts: seq[Stmt], comment: string) =
  w.addIndent()
  for i, s in stmts:
    if i > 0: w.add " "
    w.emitStmt(s)
  if comment != "": w.add " comment \"" & comment & "\""
  w.buf.add '\n'
  w.atLineStart = true

# ---------------------------------------------------------------------------
# Priority formatting
# ---------------------------------------------------------------------------

proc priorityText(hook, chainType: string, prio: int): string =
  let (baseName, baseVal) = case hook
    of "prerouting":
      if chainType == "nat": ("dstnat", -100) else: ("filter", 0)
    of "postrouting":
      if chainType == "nat": ("srcnat", 100) else: ("filter", 0)
    else: ("filter", 0)
  let diff = prio - baseVal
  if diff == 0: baseName
  elif diff > 0: baseName & " + " & $diff
  else: baseName & " - " & $(-diff)

# ---------------------------------------------------------------------------
# Top-level: NftRuleset → text
# ---------------------------------------------------------------------------

proc emitText*(rs: NftRuleset): string =
  var w = newWriter()

  # Group by table
  type TK = tuple[family, name: string]
  var tableOrder: seq[TK]
  var chains: Table[TK, seq[NftChain]]
  var rules: Table[TK, seq[NftRule]]
  var sets: Table[TK, seq[NftSet]]
  var maps: Table[TK, seq[NftMap]]

  for cmd in rs.nftables:
    if cmd.kind != nckAdd: continue
    case cmd.add.kind
    of nakTable:
      let t = cmd.add.table
      let key: TK = (t.family, t.name)
      if key notin chains:
        tableOrder.add key
        chains[key] = @[]; rules[key] = @[]; sets[key] = @[]; maps[key] = @[]
    of nakChain:
      let c = cmd.add.chain
      let key: TK = (c.family, c.table)
      if key in chains: chains[key].add c
    of nakRule:
      let r = cmd.add.rule
      let key: TK = (r.family, r.table)
      if key in rules: rules[key].add r
    of nakSet:
      let s = cmd.add.set
      let key: TK = (s.family, s.table)
      if key in sets: sets[key].add s
    of nakMap:
      let m = cmd.add.map
      let key: TK = (m.family, m.table)
      if key in maps: maps[key].add m

  for key in tableOrder:
    let (fam, name) = key
    let tblId = fam & " " & name

    w.line("table " & tblId)
    w.line("delete table " & tblId)
    w.emptyLine()

    w.braced("table " & tblId):
      for s in sets[key]:
        w.emptyLine()
        w.braced("set " & s.name):
          w.line("type " & s.setType)
          if s.flags.isSome: w.line("flags " & s.flags.get.join(", "))
          if s.size.isSome: w.line("size " & $s.size.get)
          if s.timeout.isSome: w.line("timeout " & $s.timeout.get & "s")
          if s.elem.isSome:
            w.line("elements = { " & s.elem.get.mapIt(it.toText).join(", ") & " }")

      for m in maps[key]:
        w.emptyLine()
        w.braced("map " & m.name):
          let typeStr = if m.mapType == "verdict": m.keyType & " : verdict"
                        else: m.keyType & " : " & m.mapType
          w.line("type " & typeStr)
          if m.flags.isSome: w.line("flags " & m.flags.get.join(", "))
          if m.elem.isSome:
            w.line("elements = {")
            w.indented:
              let elems = m.elem.get
              for i, elem in elems:
                let comma = if i < elems.len - 1: "," else: ""
                w.line(elem.key.toQuoted & " : " & elem.value.toText & comma)
            w.line("}")

      # Group rules by chain
      var chainRules: Table[string, seq[NftRule]]
      for r in rules[key]:
        if r.chain notin chainRules: chainRules[r.chain] = @[]
        chainRules[r.chain].add r

      for c in chains[key]:
        let cRules = chainRules.getOrDefault(c.name, @[])
        w.emptyLine()
        w.braced("chain " & c.name):
          if c.chainType.isSome:
            let prio = priorityText(c.hook.get, c.chainType.get, c.prio.get)
            w.line("type " & c.chainType.get & " hook " & c.hook.get &
                   " priority " & prio & "; policy " & c.policy.get & ";")
          for r in cRules:
            let comment = if r.comment.isSome: r.comment.get else: ""
            w.emitRuleLine(r.expr, comment)

    w.emptyLine()

  w.result()
