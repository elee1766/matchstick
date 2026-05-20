## emit_json.nim - nftables JSON serialization via jsony.
##
## Custom dumpHooks for Expr/Stmt (key-based variant dispatch)
## and top-level records (field renames like setType→type).
##
## Uses auto-comma helpers: jsonObj/jsonFieldVal handle comma insertion
## automatically. No manual comma tracking needed.

import std/[strutils, options, json]
import jsony
import ./nft_ir

# ---------------------------------------------------------------------------
# Auto-comma JSON builder helpers
# ---------------------------------------------------------------------------

var jFieldCount {.threadvar.}: int

template jsonObj(s: var string, body: untyped) =
  s.add '{'
  let saved = jFieldCount
  jFieldCount = 0
  body
  jFieldCount = saved
  s.add '}'

template jsonArr(s: var string, body: untyped) =
  s.add '['
  body
  s.add ']'

template jsonField(s: var string, key: string, body: untyped) =
  ## Write "key": <body>  with auto comma before if not first field
  if jFieldCount > 0: s.add ','
  s.dumpHook(key)
  s.add ':'
  body
  inc jFieldCount

template jsonFieldVal(s: var string, key: string, val: untyped) =
  ## Write "key": val  with auto comma
  if jFieldCount > 0: s.add ','
  s.dumpHook(key)
  s.add ':'
  s.dumpHook(val)
  inc jFieldCount

template jsonItems[T](s: var string, items: openArray[T]) =
  for i, item in items:
    if i > 0: s.add ','
    s.dumpHook(item)

# ---------------------------------------------------------------------------
# Expr dumpHook
# ---------------------------------------------------------------------------

proc dumpHook*(s: var string, e: Expr) =
  if e == nil:
    s.add "null"
    return
  case e.kind
  of ekString:
    if '/' in e.strVal and ('.' in e.strVal or ':' in e.strVal):
      let parts = e.strVal.split('/')
      if parts.len == 2:
        try:
          let plen = parseInt(parts[1])
          s.jsonObj:
            s.jsonField("prefix"):
              s.jsonObj:
                s.jsonFieldVal("addr", parts[0])
                s.jsonFieldVal("len", plen)
          return
        except ValueError: discard
    s.dumpHook(e.strVal)
  of ekInt:       s.dumpHook(e.intVal)
  of ekBool:      s.dumpHook(e.boolVal)
  of ekList:
    s.jsonArr:
      s.jsonItems(e.listElems)
  of ekPrefix:
    s.jsonObj:
      s.jsonField("prefix"):
        s.jsonObj:
          s.jsonFieldVal("addr", e.prefixAddr)
          s.jsonFieldVal("len", e.prefixLen)
  of ekRange:
    s.jsonObj:
      s.jsonField("range"):
        s.jsonArr:
          s.dumpHook(e.rangeMin)
          s.add ','
          s.dumpHook(e.rangeMax)
  of ekConcat:
    s.jsonObj:
      s.jsonField("concat"):
        s.jsonArr: s.jsonItems(e.concatExprs)
  of ekPayload:
    s.jsonObj:
      s.jsonField("payload"):
        s.jsonObj:
          s.jsonFieldVal("protocol", e.payloadProto)
          s.jsonFieldVal("field", e.payloadField)
  of ekMeta:
    s.jsonObj:
      s.jsonField("meta"):
        s.jsonObj:
          s.jsonFieldVal("key", e.metaKey)
  of ekCt:
    s.jsonObj:
      s.jsonField("ct"):
        s.jsonObj:
          s.jsonFieldVal("key", e.ctKey)
          if e.ctDir != "": s.jsonFieldVal("dir", e.ctDir)
          if e.ctFamily != "": s.jsonFieldVal("family", e.ctFamily)
  of ekFib:
    s.jsonObj:
      s.jsonField("fib"):
        s.jsonObj:
          s.jsonFieldVal("result", e.fibResult)
          s.jsonField("flags"):
            s.jsonArr: s.jsonItems(e.fibFlags)
  of ekSet:       s.dumpHook("@" & e.setName)
  of ekMap:
    s.jsonObj:
      s.jsonField("map"):
        s.jsonObj:
          s.jsonFieldVal("key", e.mapKey)
          s.jsonFieldVal("data", "@" & e.mapData)
  of ekElem:
    if e.elemTimeout > 0:
      s.jsonObj:
        s.jsonField("elem"):
          s.jsonObj:
            s.jsonFieldVal("val", e.elemVal)
            s.jsonFieldVal("timeout", e.elemTimeout)
    else:
      s.dumpHook(e.elemVal)
  of ekVerdict:
    s.jsonObj:
      case e.verdictKind
      of "accept", "drop", "return":
        s.jsonField(e.verdictKind): s.add "null"
      of "jump", "goto":
        s.jsonField(e.verdictKind):
          s.jsonObj: s.jsonFieldVal("target", e.verdictTarget)
      else:
        s.jsonField(e.verdictKind): s.add "null"
  of ekBinOp:
    s.jsonObj:
      s.jsonField(e.binOp):
        s.jsonArr:
          s.dumpHook(e.binLeft)
          s.add ','
          s.dumpHook(e.binRight)
  of ekAnonymousSet:
    s.jsonObj:
      s.jsonField("set"):
        s.jsonArr: s.jsonItems(e.anonSetElems)

# ---------------------------------------------------------------------------
# Stmt dumpHook
# ---------------------------------------------------------------------------

proc dumpHook*(s: var string, st: Stmt) =
  if st == nil:
    s.add "null"
    return
  case st.kind
  of skMatch:
    s.jsonObj:
      s.jsonField("match"):
        s.jsonObj:
          s.jsonFieldVal("op", $st.matchOp)
          s.jsonFieldVal("left", st.matchLeft)
          s.jsonFieldVal("right", st.matchRight)
  of skAccept:
    s.jsonObj:
      s.jsonField("accept"): s.add "null"
  of skDrop:
    s.jsonObj:
      s.jsonField("drop"): s.add "null"
  of skReturn:
    s.jsonObj:
      s.jsonField("return"): s.add "null"
  of skReject:
    s.jsonObj:
      s.jsonField("reject"):
        s.jsonObj:
          if st.rejectType != "": s.jsonFieldVal("type", st.rejectType)
          if st.rejectExpr != "": s.jsonFieldVal("expr", st.rejectExpr)
  of skJump:
    s.jsonObj:
      s.jsonField("jump"):
        s.jsonObj: s.jsonFieldVal("target", st.jumpTarget)
  of skGoto:
    s.jsonObj:
      s.jsonField("goto"):
        s.jsonObj: s.jsonFieldVal("target", st.gotoTarget)
  of skCounter:
    s.jsonObj:
      if st.counterName != "":
        s.jsonFieldVal("counter", st.counterName)
      else:
        s.jsonField("counter"):
          s.jsonObj:
            s.jsonFieldVal("packets", 0.int)
            s.jsonFieldVal("bytes", 0.int)
  of skLog:
    s.jsonObj:
      s.jsonField("log"):
        s.jsonObj:
          if st.logPrefix != "": s.jsonFieldVal("prefix", st.logPrefix)
          if st.logLevel != "": s.jsonFieldVal("level", st.logLevel)
          if st.logFlags.len > 0:
            s.jsonField("flags"):
              s.jsonArr: s.jsonItems(st.logFlags)
  of skLimit:
    s.jsonObj:
      s.jsonField("limit"):
        s.jsonObj:
          s.jsonFieldVal("rate", st.limitRate)
          s.jsonFieldVal("per", st.limitPer)
          if st.limitBurst > 0: s.jsonFieldVal("burst", st.limitBurst)
          if st.limitInv: s.jsonFieldVal("inv", true)
  of skDnat:
    s.jsonObj:
      s.jsonField("dnat"):
        s.jsonObj:
          s.jsonFieldVal("addr", st.dnatAddr)
          s.jsonFieldVal("family", st.dnatFamily)
          if st.dnatPort > 0: s.jsonFieldVal("port", st.dnatPort)
  of skSnat:
    s.jsonObj:
      s.jsonField("snat"):
        s.jsonObj:
          s.jsonFieldVal("addr", st.snatAddr)
          s.jsonFieldVal("family", st.snatFamily)
          if st.snatPort > 0: s.jsonFieldVal("port", st.snatPort)
  of skMasquerade:
    s.jsonObj:
      if st.masqPort > 0:
        s.jsonField("masquerade"):
          s.jsonObj: s.jsonFieldVal("port", st.masqPort)
      else:
        s.jsonField("masquerade"): s.add "null"
  of skVmap:
    s.jsonObj:
      s.jsonField("vmap"):
        s.jsonObj:
          s.jsonFieldVal("key", st.vmapKey)
          s.jsonFieldVal("data", st.vmapData)
  of skMangle:
    s.jsonObj:
      s.jsonField("mangle"):
        s.jsonObj:
          s.jsonFieldVal("key", st.mangleKey)
          s.jsonFieldVal("value", st.mangleValue)
  of skUpdate:
    s.jsonObj:
      s.jsonField("set"):
        s.jsonObj:
          s.jsonFieldVal("op", "update")
          s.jsonFieldVal("elem", st.updateKey)
          s.jsonFieldVal("set", "@" & st.updateSet)
          s.jsonField("stmt"):
            s.jsonArr: s.jsonItems(st.updateStmts)

# ---------------------------------------------------------------------------
# NftMapElem dumpHook
# ---------------------------------------------------------------------------

proc dumpHook*(s: var string, e: NftMapElem) =
  s.jsonArr:
    s.dumpHook(e.key)
    s.add ','
    s.dumpHook(e.value)

# ---------------------------------------------------------------------------
# Top-level record dumpHooks
# ---------------------------------------------------------------------------

proc dumpHook*(s: var string, t: NftTable) =
  s.jsonObj:
    s.jsonFieldVal("family", t.family)
    s.jsonFieldVal("name", t.name)

proc dumpHook*(s: var string, c: NftChain) =
  s.jsonObj:
    s.jsonFieldVal("family", c.family)
    s.jsonFieldVal("table", c.table)
    s.jsonFieldVal("name", c.name)
    if c.chainType.isSome: s.jsonFieldVal("type", c.chainType.get)
    if c.hook.isSome: s.jsonFieldVal("hook", c.hook.get)
    if c.prio.isSome: s.jsonFieldVal("prio", c.prio.get)
    if c.policy.isSome: s.jsonFieldVal("policy", c.policy.get)

proc dumpHook*(s: var string, r: NftRule) =
  s.jsonObj:
    s.jsonFieldVal("family", r.family)
    s.jsonFieldVal("table", r.table)
    s.jsonFieldVal("chain", r.chain)
    s.jsonField("expr"):
      s.jsonArr: s.jsonItems(r.expr)
    if r.comment.isSome: s.jsonFieldVal("comment", r.comment.get)

proc dumpHook*(s: var string, st: NftSet) =
  s.jsonObj:
    s.jsonFieldVal("family", st.family)
    s.jsonFieldVal("table", st.table)
    s.jsonFieldVal("name", st.name)
    s.jsonFieldVal("type", st.setType)
    if st.flags.isSome:
      s.jsonField("flags"):
        s.jsonArr: s.jsonItems(st.flags.get)
    if st.size.isSome: s.jsonFieldVal("size", st.size.get)
    if st.timeout.isSome: s.jsonFieldVal("timeout", st.timeout.get)
    if st.elem.isSome:
      s.jsonField("elem"):
        s.jsonArr: s.jsonItems(st.elem.get)

proc dumpHook*(s: var string, m: NftMap) =
  s.jsonObj:
    s.jsonFieldVal("family", m.family)
    s.jsonFieldVal("table", m.table)
    s.jsonFieldVal("name", m.name)
    if " . " in m.keyType:
      s.jsonField("type"):
        s.jsonArr:
          let parts = m.keyType.split(" . ")
          s.jsonItems(parts)
    else:
      s.jsonFieldVal("type", m.keyType)
    s.jsonFieldVal("map", m.mapType)
    if m.flags.isSome:
      s.jsonField("flags"):
        s.jsonArr: s.jsonItems(m.flags.get)
    if m.elem.isSome:
      s.jsonField("elem"):
        s.jsonArr: s.jsonItems(m.elem.get)

# ---------------------------------------------------------------------------
# NftCmd dumpHook
# ---------------------------------------------------------------------------

proc dumpHook*(s: var string, cmd: NftCmd) =
  case cmd.kind
  of nckMetainfo:
    s.jsonObj:
      s.jsonField("metainfo"):
        s.jsonObj:
          s.jsonFieldVal("json_schema_version", cmd.metainfo.json_schema_version)
  of nckAdd:
    s.jsonObj:
      s.jsonField("add"):
        s.jsonObj:
          case cmd.add.kind
          of nakTable: s.jsonFieldVal("table", cmd.add.table)
          of nakChain: s.jsonFieldVal("chain", cmd.add.chain)
          of nakRule:  s.jsonFieldVal("rule", cmd.add.rule)
          of nakSet:   s.jsonFieldVal("set", cmd.add.set)
          of nakMap:   s.jsonFieldVal("map", cmd.add.map)
  of nckDelete:
    s.jsonObj:
      s.jsonField("delete"):
        s.jsonObj:
          s.jsonField(cmd.deleteWhat):
            s.jsonObj:
              s.jsonFieldVal("family", cmd.delete.family)
              s.jsonFieldVal("name", cmd.delete.name)

# ---------------------------------------------------------------------------
# NftRuleset dumpHook
# ---------------------------------------------------------------------------

proc dumpHook*(s: var string, rs: NftRuleset) =
  s.jsonObj:
    s.jsonField("nftables"):
      s.jsonArr: s.jsonItems(rs.nftables)

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

proc emitJson*(rs: NftRuleset, pretty: bool = true): string =
  let compact = rs.toJson()
  if pretty:
    return parseJson(compact).pretty() & "\n"
  else:
    return compact & "\n"
