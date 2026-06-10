## emit_text.nim - nftables text format emission from IR.

import std/[strutils, tables, sequtils, json]
import ./nft_ir
import ./writer

# ---------------------------------------------------------------------------
# String escaping for nftables text output
# ---------------------------------------------------------------------------

proc escapeNftString*(s: string): string =
  ## Escape a string for safe inclusion in nftables quoted contexts.
  ## Prevents injection via embedded quotes, backslashes, or newlines.
  result = newStringOfCap(s.len)
  for c in s:
    case c
    of '"':  result.add '\\'; result.add '"'
    of '\\': result.add '\\'; result.add '\\'
    of '\n': result.add '\\'; result.add 'n'
    of '\r': result.add '\\'; result.add 'r'
    of '\0': discard  # strip null bytes
    else:    result.add c

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
  of ekString: "\"" & escapeNftString(e.strVal) & "\""
  else: e.toText

# ---------------------------------------------------------------------------
# nftables JSON → text (for raw passthrough)
# ---------------------------------------------------------------------------

proc nftJsonToText*(j: JsonNode): string =
  ## Convert an nftables JSON node (statement or expression) to text.
  ## Handles the common nftables JSON schema structures.
  if j == nil or j.kind == JNull:
    return ""
  case j.kind
  of JString: return j.getStr()
  of JInt: return $j.getInt()
  of JFloat: return $j.getFloat()
  of JBool: return (if j.getBool(): "1" else: "0")
  of JArray:
    var parts: seq[string]
    for elem in j: parts.add nftJsonToText(elem)
    return parts.join(" ")
  of JObject:
    # Handle known nftables JSON structures
    if "match" in j:
      let m = j["match"]
      let left = nftJsonToText(m.getOrDefault("left"))
      let right = nftJsonToText(m.getOrDefault("right"))
      let op = m.getOrDefault("op").getStr("==")
      return left & " " & op & " " & right
    if "accept" in j: return "accept"
    if "drop" in j: return "drop"
    if "return" in j: return "return"
    if "reject" in j:
      let r = j["reject"]
      var s = "reject"
      if "type" in r: s &= " with " & r["type"].getStr()
      if "expr" in r: s &= " " & r["expr"].getStr()
      return s
    if "jump" in j:
      let t = j["jump"]
      return "jump " & t.getOrDefault("target").getStr()
    if "goto" in j:
      let t = j["goto"]
      return "goto " & t.getOrDefault("target").getStr()
    if "counter" in j: return "counter"
    if "log" in j:
      let l = j["log"]
      var s = "log"
      if "prefix" in l: s &= " prefix \"" & escapeNftString(l["prefix"].getStr()) & "\""
      if "level" in l: s &= " level " & l["level"].getStr()
      return s
    if "limit" in j:
      let l = j["limit"]
      var s = "limit rate "
      if l.getOrDefault("inv").getBool(false): s &= "over "
      s &= $l.getOrDefault("rate").getInt() & "/" & l.getOrDefault("per").getStr()
      let burst = l.getOrDefault("burst").getInt()
      if burst > 0: s &= " burst " & $burst & " packets"
      return s
    if "payload" in j:
      let p = j["payload"]
      return p.getOrDefault("protocol").getStr() & " " & p.getOrDefault("field").getStr()
    if "meta" in j:
      let m = j["meta"]
      let key = m.getOrDefault("key").getStr()
      case key
      of "iifname", "oifname", "iif", "oif", "iiftype", "oiftype": return key
      else: return "meta " & key
    if "ct" in j:
      let c = j["ct"]
      var s = "ct"
      if "dir" in c: s &= " " & c["dir"].getStr()
      s &= " " & c.getOrDefault("key").getStr()
      return s
    if "prefix" in j:
      let p = j["prefix"]
      return p.getOrDefault("addr").getStr() & "/" & $p.getOrDefault("len").getInt()
    if "range" in j:
      let r = j["range"]
      if r.kind == JArray and r.len == 2:
        return nftJsonToText(r[0]) & "-" & nftJsonToText(r[1])
    if "concat" in j:
      let c = j["concat"]
      if c.kind == JArray:
        var parts: seq[string]
        for elem in c: parts.add nftJsonToText(elem)
        return parts.join(" . ")
    if "set" in j:
      let s = j["set"]
      if s.kind == JArray:
        var parts: seq[string]
        for elem in s: parts.add nftJsonToText(elem)
        return "{ " & parts.join(", ") & " }"
      elif s.kind == JString:
        return "@" & s.getStr()
    if "mangle" in j:
      let m = j["mangle"]
      return nftJsonToText(m.getOrDefault("key")) & " set " & nftJsonToText(m.getOrDefault("value"))
    if "dnat" in j:
      let d = j["dnat"]
      var s = "dnat " & d.getOrDefault("family").getStr("ip") & " to " & d.getOrDefault("addr").getStr()
      let port = d.getOrDefault("port").getInt()
      if port > 0: s &= ":" & $port
      return s
    if "snat" in j:
      let sn = j["snat"]
      var s = "snat " & sn.getOrDefault("family").getStr("ip") & " to " & sn.getOrDefault("addr").getStr()
      let port = sn.getOrDefault("port").getInt()
      if port > 0: s &= ":" & $port
      return s
    if "masquerade" in j: return "masquerade"
    # Fallback: render as compact JSON (better than nothing)
    return $j
  else:
    return $j

proc nftJsonCmdToText*(w: var Writer, j: JsonNode) =
  ## Render a top-level nftables JSON command object as text.
  if j == nil or j.kind != JObject: return
  if "add" in j:
    let add = j["add"]
    if "chain" in add:
      let c = add["chain"]
      let name = c.getOrDefault("name").getStr()
      w.braced("chain " & name):
        if "type" in c:
          let prio = c.getOrDefault("prio").getInt()
          let hook = c.getOrDefault("hook").getStr()
          let typ = c.getOrDefault("type").getStr()
          let policy = c.getOrDefault("policy").getStr("accept")
          w.line("type " & typ & " hook " & hook & " priority " & $prio & "; policy " & policy & ";")
    if "rule" in add:
      let r = add["rule"]
      if "expr" in r and r["expr"].kind == JArray:
        var parts: seq[string]
        for expr in r["expr"]:
          parts.add nftJsonToText(expr)
        w.line(parts.join(" "))
    if "set" in add:
      let s = add["set"]
      let name = s.getOrDefault("name").getStr()
      w.braced("set " & name):
        if "type" in s: w.line("type " & s["type"].getStr())
        if "flags" in s and s["flags"].kind == JArray:
          var flags: seq[string]
          for f in s["flags"]: flags.add f.getStr()
          w.line("flags " & flags.join(", "))

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
    if s.logPrefix != "": w.add " prefix \"" & escapeNftString(s.logPrefix) & "\""
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
  of skRedirect:
    w.add "redirect to :" & $s.redirectPort
  of skVmap:    w.add s.vmapKey.toMatchLeft & " vmap " & s.vmapData.toText
  of skMangle:  w.add s.mangleKey.toText & " set " & s.mangleValue.toText
  of skUpdate:
    w.add "update @" & s.updateSet & " { " & s.updateKey.toMatchLeft
    for sub in s.updateStmts: w.add " "; w.emitStmt(sub)
    w.add " }"
  of skConnLimit:
    w.add "ct count "
    if s.connLimitFlags == "inverse": w.add "over "
    w.add $s.connLimitCount
  of skMssClamp:
    if s.mssClampSize > 0:
      w.add "tcp option maxseg size set " & $s.mssClampSize
    else:
      w.add "tcp option maxseg size set rt mtu"
  of skRaw:
    w.add nftJsonToText(s.rawJson)

proc emitRuleLine(w: var Writer, stmts: seq[Stmt], comment: string) =
  w.addIndent()
  for i, s in stmts:
    if i > 0: w.add " "
    w.emitStmt(s)
  if comment != "": w.add " comment \"" & escapeNftString(comment) & "\""
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

  var rawJsonCmds: Table[TK, seq[JsonNode]]

  for cmd in rs.nftables:
    case cmd.kind
    of nckAdd:
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
    of nckRaw:
      # Associate raw JSON commands with the most recently added table
      if tableOrder.len > 0:
        let key = tableOrder[^1]
        for rawCmd in cmd.rawCmds:
          rawJsonCmds.mgetOrPut(key, @[]).add rawCmd
    else: discard

  for key in tableOrder:
    let (fam, name) = key
    let tblId = fam & " " & name

    w.line("table " & tblId)
    w.line("delete table " & tblId)
    w.emptyLine()

    w.braced("table " & tblId):
      # Raw nftables JSON commands (injected via fw:raw_nft)
      let raws = rawJsonCmds.getOrDefault(key, @[])
      for rawJ in raws:
        w.emptyLine()
        w.nftJsonCmdToText(rawJ)

      for s in sets[key]:
        w.emptyLine()
        w.braced("set " & s.name):
          w.line("type " & s.`type`)
          case s.kind
          of setkPlain:
            if s.plainElem.len > 0:
              w.line("elements = { " & s.plainElem.mapIt(it.toText).join(", ") & " }")
          of setkNamed:
            if s.flags.len > 0: w.line("flags " & s.flags.join(", "))
            if s.size > 0: w.line("size " & $s.size)
            if s.timeout > 0: w.line("timeout " & $s.timeout & "s")
            if s.elem.len > 0:
              w.line("elements = { " & s.elem.mapIt(it.toText).join(", ") & " }")

      for m in maps[key]:
        w.emptyLine()
        w.braced("map " & m.name):
          let typeStr = if m.`map` == "verdict": m.`type` & " : verdict"
                        else: m.`type` & " : " & m.`map`
          w.line("type " & typeStr)
          if m.flags.len > 0: w.line("flags " & m.flags.join(", "))
          if m.elem.len > 0:
            w.line("elements = {")
            w.indented:
              for i, elem in m.elem:
                let comma = if i < m.elem.len - 1: "," else: ""
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
          case c.kind
          of chkRegular: discard
          of chkBase:
            let prio = priorityText(c.hook, c.`type`, c.prio)
            w.line("type " & c.`type` & " hook " & c.hook &
                   " priority " & prio & "; policy " & c.policy & ";")
          for r in cRules:
            w.emitRuleLine(r.expr, r.comment)

    w.emptyLine()

  w.result()
