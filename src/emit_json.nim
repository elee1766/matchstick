## emit_json.nim - nftables JSON serialization via jsony.
##
## Expr and Stmt have custom dumpHooks (key-based variant dispatch).
## Top-level records (NftTable, NftChain, etc.) also need hooks because
## jsony's default uses the discriminator field for variants.
## NftCmd and NftRuleset use hooks to produce the nftables command format.

import std/[strutils, options, json]
import jsony
import ./nft_ir

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
          s.add "{\"prefix\":{\"addr\":"
          s.dumpHook(parts[0])
          s.add ",\"len\":" & $plen & "}}"
          return
        except ValueError: discard
    s.dumpHook(e.strVal)
  of ekInt:       s.dumpHook(e.intVal)
  of ekBool:      s.dumpHook(e.boolVal)
  of ekList:
    s.add "["
    for i, el in e.listElems:
      if i > 0: s.add ","
      s.dumpHook(el)
    s.add "]"
  of ekPrefix:
    s.add "{\"prefix\":{\"addr\":"
    s.dumpHook(e.prefixAddr)
    s.add ",\"len\":" & $e.prefixLen & "}}"
  of ekRange:
    s.add "{\"range\":["
    s.dumpHook(e.rangeMin)
    s.add ","
    s.dumpHook(e.rangeMax)
    s.add "]}"
  of ekConcat:
    s.add "{\"concat\":["
    for i, el in e.concatExprs:
      if i > 0: s.add ","
      s.dumpHook(el)
    s.add "]}"
  of ekPayload:
    s.add "{\"payload\":{\"protocol\":"
    s.dumpHook(e.payloadProto)
    s.add ",\"field\":"
    s.dumpHook(e.payloadField)
    s.add "}}"
  of ekMeta:
    s.add "{\"meta\":{\"key\":"
    s.dumpHook(e.metaKey)
    s.add "}}"
  of ekCt:
    s.add "{\"ct\":{\"key\":"
    s.dumpHook(e.ctKey)
    if e.ctDir != "": s.add ",\"dir\":"; s.dumpHook(e.ctDir)
    if e.ctFamily != "": s.add ",\"family\":"; s.dumpHook(e.ctFamily)
    s.add "}}"
  of ekFib:
    s.add "{\"fib\":{\"result\":"
    s.dumpHook(e.fibResult)
    s.add ",\"flags\":["
    for i, f in e.fibFlags:
      if i > 0: s.add ","
      s.dumpHook(f)
    s.add "]}}"
  of ekSet:     s.dumpHook("@" & e.setName)
  of ekMap:
    s.add "{\"map\":{\"key\":"
    s.dumpHook(e.mapKey)
    s.add ",\"data\":"
    s.dumpHook("@" & e.mapData)
    s.add "}}"
  of ekElem:
    if e.elemTimeout > 0:
      s.add "{\"elem\":{\"val\":"
      s.dumpHook(e.elemVal)
      s.add ",\"timeout\":" & $e.elemTimeout & "}}"
    else:
      s.dumpHook(e.elemVal)
  of ekVerdict:
    case e.verdictKind
    of "accept": s.add "{\"accept\":null}"
    of "drop":   s.add "{\"drop\":null}"
    of "return": s.add "{\"return\":null}"
    of "jump":
      s.add "{\"jump\":{\"target\":"
      s.dumpHook(e.verdictTarget)
      s.add "}}"
    of "goto":
      s.add "{\"goto\":{\"target\":"
      s.dumpHook(e.verdictTarget)
      s.add "}}"
    else: s.add "{"; s.dumpHook(e.verdictKind); s.add ":null}"
  of ekBinOp:
    s.add "{"
    s.dumpHook(e.binOp)
    s.add ":["
    s.dumpHook(e.binLeft)
    s.add ","
    s.dumpHook(e.binRight)
    s.add "]}"
  of ekAnonymousSet:
    s.add "{\"set\":["
    for i, el in e.anonSetElems:
      if i > 0: s.add ","
      s.dumpHook(el)
    s.add "]}"

# ---------------------------------------------------------------------------
# Stmt dumpHook
# ---------------------------------------------------------------------------

proc dumpHook*(s: var string, st: Stmt) =
  if st == nil:
    s.add "null"
    return
  case st.kind
  of skMatch:
    s.add "{\"match\":{\"op\":"
    s.dumpHook($st.matchOp)
    s.add ",\"left\":"
    s.dumpHook(st.matchLeft)
    s.add ",\"right\":"
    s.dumpHook(st.matchRight)
    s.add "}}"
  of skAccept: s.add "{\"accept\":null}"
  of skDrop:   s.add "{\"drop\":null}"
  of skReturn: s.add "{\"return\":null}"
  of skReject:
    s.add "{\"reject\":{"
    var first = true
    if st.rejectType != "":
      s.add "\"type\":"; s.dumpHook(st.rejectType); first = false
    if st.rejectExpr != "":
      if not first: s.add ","
      s.add "\"expr\":"; s.dumpHook(st.rejectExpr)
    s.add "}}"
  of skJump:
    s.add "{\"jump\":{\"target\":"; s.dumpHook(st.jumpTarget); s.add "}}"
  of skGoto:
    s.add "{\"goto\":{\"target\":"; s.dumpHook(st.gotoTarget); s.add "}}"
  of skCounter:
    if st.counterName != "":
      s.add "{\"counter\":"; s.dumpHook(st.counterName); s.add "}"
    else:
      s.add "{\"counter\":{\"packets\":0,\"bytes\":0}}"
  of skLog:
    s.add "{\"log\":{"
    var first = true
    if st.logPrefix != "":
      s.add "\"prefix\":"; s.dumpHook(st.logPrefix); first = false
    if st.logLevel != "":
      if not first: s.add ","
      s.add "\"level\":"; s.dumpHook(st.logLevel); first = false
    if st.logFlags.len > 0:
      if not first: s.add ","
      s.add "\"flags\":[";
      for i, f in st.logFlags: (if i > 0: s.add ","); s.dumpHook(f)
      s.add "]"
    s.add "}}"
  of skLimit:
    s.add "{\"limit\":{\"rate\":" & $st.limitRate & ",\"per\":"
    s.dumpHook(st.limitPer)
    if st.limitBurst > 0: s.add ",\"burst\":" & $st.limitBurst
    if st.limitInv: s.add ",\"inv\":true"
    s.add "}}"
  of skDnat:
    s.add "{\"dnat\":{\"addr\":"; s.dumpHook(st.dnatAddr)
    s.add ",\"family\":"; s.dumpHook(st.dnatFamily)
    if st.dnatPort > 0: s.add ",\"port\":" & $st.dnatPort
    s.add "}}"
  of skSnat:
    s.add "{\"snat\":{\"addr\":"; s.dumpHook(st.snatAddr)
    s.add ",\"family\":"; s.dumpHook(st.snatFamily)
    if st.snatPort > 0: s.add ",\"port\":" & $st.snatPort
    s.add "}}"
  of skMasquerade:
    if st.masqPort > 0: s.add "{\"masquerade\":{\"port\":" & $st.masqPort & "}}"
    else: s.add "{\"masquerade\":null}"
  of skVmap:
    s.add "{\"vmap\":{\"key\":"; s.dumpHook(st.vmapKey)
    s.add ",\"data\":"; s.dumpHook(st.vmapData)
    s.add "}}"
  of skMangle:
    s.add "{\"mangle\":{\"key\":"; s.dumpHook(st.mangleKey)
    s.add ",\"value\":"; s.dumpHook(st.mangleValue)
    s.add "}}"
  of skUpdate:
    s.add "{\"set\":{\"op\":\"update\",\"elem\":"
    s.dumpHook(st.updateKey)
    s.add ",\"set\":"; s.dumpHook("@" & st.updateSet)
    s.add ",\"stmt\":[";
    for i, sub in st.updateStmts: (if i > 0: s.add ","); s.dumpHook(sub)
    s.add "]}}"

# ---------------------------------------------------------------------------
# NftMapElem dumpHook -- [key, value] pair
# ---------------------------------------------------------------------------

proc dumpHook*(s: var string, e: NftMapElem) =
  s.add "["
  s.dumpHook(e.key)
  s.add ","
  s.dumpHook(e.value)
  s.add "]"

# ---------------------------------------------------------------------------
# Top-level object dumpHooks -- needed because of field renames
# (setType→type, chainType→type, keyType→type, mapType→map)
# ---------------------------------------------------------------------------

proc dumpHook*(s: var string, t: NftTable) =
  s.add "{\"family\":"; s.dumpHook(t.family)
  s.add ",\"name\":"; s.dumpHook(t.name)
  s.add "}"

proc dumpHook*(s: var string, c: NftChain) =
  s.add "{\"family\":"; s.dumpHook(c.family)
  s.add ",\"table\":"; s.dumpHook(c.table)
  s.add ",\"name\":"; s.dumpHook(c.name)
  if c.chainType.isSome:
    s.add ",\"type\":"; s.dumpHook(c.chainType.get)
  if c.hook.isSome:
    s.add ",\"hook\":"; s.dumpHook(c.hook.get)
  if c.prio.isSome:
    s.add ",\"prio\":" & $c.prio.get
  if c.policy.isSome:
    s.add ",\"policy\":"; s.dumpHook(c.policy.get)
  s.add "}"

proc dumpHook*(s: var string, r: NftRule) =
  s.add "{\"family\":"; s.dumpHook(r.family)
  s.add ",\"table\":"; s.dumpHook(r.table)
  s.add ",\"chain\":"; s.dumpHook(r.chain)
  s.add ",\"expr\":["
  for i, e in r.expr:
    if i > 0: s.add ","
    s.dumpHook(e)
  s.add "]"
  if r.comment.isSome:
    s.add ",\"comment\":"; s.dumpHook(r.comment.get)
  s.add "}"

proc dumpHook*(s: var string, st: NftSet) =
  s.add "{\"family\":"; s.dumpHook(st.family)
  s.add ",\"table\":"; s.dumpHook(st.table)
  s.add ",\"name\":"; s.dumpHook(st.name)
  s.add ",\"type\":"; s.dumpHook(st.setType)
  if st.flags.isSome:
    s.add ",\"flags\":[";
    for i, f in st.flags.get: (if i > 0: s.add ","); s.dumpHook(f)
    s.add "]"
  if st.size.isSome: s.add ",\"size\":" & $st.size.get
  if st.timeout.isSome: s.add ",\"timeout\":" & $st.timeout.get
  if st.elem.isSome:
    s.add ",\"elem\":[";
    for i, e in st.elem.get: (if i > 0: s.add ","); s.dumpHook(e)
    s.add "]"
  s.add "}"

proc dumpHook*(s: var string, m: NftMap) =
  s.add "{\"family\":"; s.dumpHook(m.family)
  s.add ",\"table\":"; s.dumpHook(m.table)
  s.add ",\"name\":"; s.dumpHook(m.name)
  # Concat types → JSON array
  if " . " in m.keyType:
    s.add ",\"type\":["
    let parts = m.keyType.split(" . ")
    for i, p in parts: (if i > 0: s.add ","); s.dumpHook(p)
    s.add "]"
  else:
    s.add ",\"type\":"; s.dumpHook(m.keyType)
  s.add ",\"map\":"; s.dumpHook(m.mapType)
  if m.flags.isSome:
    s.add ",\"flags\":[";
    for i, f in m.flags.get: (if i > 0: s.add ","); s.dumpHook(f)
    s.add "]"
  if m.elem.isSome:
    s.add ",\"elem\":[";
    for i, e in m.elem.get: (if i > 0: s.add ","); s.dumpHook(e)
    s.add "]"
  s.add "}"

# ---------------------------------------------------------------------------
# NftCmd dumpHook -- produces {"add": {"table": ...}} etc.
# ---------------------------------------------------------------------------

proc dumpHook*(s: var string, cmd: NftCmd) =
  case cmd.kind
  of nckMetainfo:
    s.add "{\"metainfo\":{\"json_schema_version\":" & $cmd.metainfo.json_schema_version & "}}"
  of nckAdd:
    s.add "{\"add\":{"
    case cmd.add.kind
    of nakTable: s.add "\"table\":"; s.dumpHook(cmd.add.table)
    of nakChain: s.add "\"chain\":"; s.dumpHook(cmd.add.chain)
    of nakRule:  s.add "\"rule\":"; s.dumpHook(cmd.add.rule)
    of nakSet:   s.add "\"set\":"; s.dumpHook(cmd.add.set)
    of nakMap:   s.add "\"map\":"; s.dumpHook(cmd.add.map)
    s.add "}}"
  of nckDelete:
    s.add "{\"delete\":{"; s.dumpHook(cmd.deleteWhat)
    s.add ":{\"family\":"; s.dumpHook(cmd.delete.family)
    s.add ",\"name\":"; s.dumpHook(cmd.delete.name)
    s.add "}}}"

# ---------------------------------------------------------------------------
# NftRuleset dumpHook -- {"nftables": [...]}
# ---------------------------------------------------------------------------

proc dumpHook*(s: var string, rs: NftRuleset) =
  s.add "{\"nftables\":["
  for i, cmd in rs.nftables:
    if i > 0: s.add ","
    s.dumpHook(cmd)
  s.add "]}"

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

proc emitJson*(rs: NftRuleset, pretty: bool = true): string =
  let compact = rs.toJson()
  if pretty:
    # Re-parse and pretty-print (small cost for config-size output)
    return parseJson(compact).pretty() & "\n"
  else:
    return compact & "\n"
