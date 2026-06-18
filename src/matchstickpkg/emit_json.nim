## emit_json.nim - nftables JSON serialization via std/json.
## Builds JsonNode trees from IR types, then uses std/json for formatting.

import std/[strutils, json]
import ./nft_ir

# ---------------------------------------------------------------------------
# Expr → JsonNode
# ---------------------------------------------------------------------------

proc toJsonNode*(e: Expr): JsonNode =
  if e == nil: return newJNull()
  case e.kind
  of ekString:
    if '/' in e.strVal and ('.' in e.strVal or ':' in e.strVal):
      let parts = e.strVal.split('/')
      if parts.len == 2:
        try:
          let plen = parseInt(parts[1])
          return %*{"prefix": {"addr": parts[0], "len": plen}}
        except ValueError: discard
    return newJString(e.strVal)
  of ekInt:    return newJInt(e.intVal)
  of ekBool:   return newJBool(e.boolVal)
  of ekList:
    var arr = newJArray()
    for el in e.listElems: arr.add el.toJsonNode()
    return arr
  of ekPrefix:
    return %*{"prefix": {"addr": e.prefixAddr, "len": e.prefixLen}}
  of ekRange:
    return %*{"range": [e.rangeMin.toJsonNode(), e.rangeMax.toJsonNode()]}
  of ekConcat:
    var arr = newJArray()
    for el in e.concatExprs: arr.add el.toJsonNode()
    return %*{"concat": arr}
  of ekPayload:
    return %*{"payload": {"protocol": e.payloadProto, "field": e.payloadField}}
  of ekMeta:
    return %*{"meta": {"key": e.metaKey}}
  of ekCt:
    var ct = %*{"key": e.ctKey}
    if e.ctDir != "": ct["dir"] = newJString(e.ctDir)
    if e.ctFamily != "": ct["family"] = newJString(e.ctFamily)
    return %*{"ct": ct}
  of ekFib:
    var flags = newJArray()
    for f in e.fibFlags: flags.add newJString(f)
    return %*{"fib": {"result": e.fibResult, "flags": flags}}
  of ekSet:
    return newJString("@" & e.setName)
  of ekMap:
    return %*{"map": {"key": e.mapKey.toJsonNode(), "data": newJString("@" & e.mapData)}}
  of ekElem:
    if e.elemTimeout > 0:
      return %*{"elem": {"val": e.elemVal.toJsonNode(), "timeout": e.elemTimeout}}
    else:
      return e.elemVal.toJsonNode()
  of ekVerdict:
    case e.verdictKind
    of "accept", "drop", "return":
      return %*{e.verdictKind: newJNull()}
    of "jump", "goto":
      return %*{e.verdictKind: {"target": e.verdictTarget}}
    else:
      return %*{e.verdictKind: newJNull()}
  of ekBinOp:
    return %*{e.binOp: [e.binLeft.toJsonNode(), e.binRight.toJsonNode()]}
  of ekAnonymousSet:
    var arr = newJArray()
    for el in e.anonSetElems: arr.add el.toJsonNode()
    return %*{"set": arr}

# ---------------------------------------------------------------------------
# Stmt → JsonNode
# ---------------------------------------------------------------------------

proc toJsonNode*(st: Stmt): JsonNode =
  if st == nil: return newJNull()
  case st.kind
  of skMatch:
    return %*{"match": {
      "op": $st.matchOp,
      "left": st.matchLeft.toJsonNode(),
      "right": st.matchRight.toJsonNode()
    }}
  of skAccept:  return %*{"accept": newJNull()}
  of skDrop:    return %*{"drop": newJNull()}
  of skReturn:  return %*{"return": newJNull()}
  of skNotrack: return %*{"notrack": newJNull()}
  of skReject:
    var r = newJObject()
    if st.rejectType != "": r["type"] = newJString(st.rejectType)
    if st.rejectExpr != "": r["expr"] = newJString(st.rejectExpr)
    return %*{"reject": r}
  of skJump:
    return %*{"jump": {"target": st.jumpTarget}}
  of skGoto:
    return %*{"goto": {"target": st.gotoTarget}}
  of skCounter:
    if st.counterName != "":
      return %*{"counter": st.counterName}
    else:
      return %*{"counter": {"packets": 0, "bytes": 0}}
  of skLog:
    var log = newJObject()
    if st.logPrefix != "": log["prefix"] = newJString(st.logPrefix)
    if st.logLevel != "": log["level"] = newJString(st.logLevel)
    if st.logFlags.len > 0:
      var flags = newJArray()
      for f in st.logFlags: flags.add newJString(f)
      log["flags"] = flags
    return %*{"log": log}
  of skLimit:
    var lim = %*{"rate": st.limitRate, "per": st.limitPer}
    if st.limitBurst > 0: lim["burst"] = newJInt(st.limitBurst)
    if st.limitInv: lim["inv"] = newJBool(true)
    return %*{"limit": lim}
  of skDnat:
    var d = %*{"addr": st.dnatAddr, "family": st.dnatFamily}
    if st.dnatPort > 0: d["port"] = newJInt(st.dnatPort)
    return %*{"dnat": d}
  of skSnat:
    var sn = %*{"addr": st.snatAddr, "family": st.snatFamily}
    if st.snatPort > 0: sn["port"] = newJInt(st.snatPort)
    return %*{"snat": sn}
  of skMasquerade:
    if st.masqPort > 0:
      return %*{"masquerade": {"port": st.masqPort}}
    else:
      return %*{"masquerade": newJNull()}
  of skRedirect:
    return %*{"redirect": {"port": st.redirectPort}}
  of skTproxy:
    var t = %*{"family": st.tproxyFamily}
    if st.tproxyAddr != "": t["addr"] = newJString(st.tproxyAddr)
    if st.tproxyPort > 0: t["port"] = newJInt(st.tproxyPort)
    return %*{"tproxy": t}
  of skVmap:
    return %*{"vmap": {
      "key": st.vmapKey.toJsonNode(),
      "data": st.vmapData.toJsonNode()
    }}
  of skMangle:
    return %*{"mangle": {
      "key": st.mangleKey.toJsonNode(),
      "value": st.mangleValue.toJsonNode()
    }}
  of skUpdate:
    var stmts = newJArray()
    for sub in st.updateStmts: stmts.add sub.toJsonNode()
    return %*{"set": {
      "op": "update",
      "elem": st.updateKey.toJsonNode(),
      "set": "@" & st.updateSet,
      "stmt": stmts
    }}
  of skConnLimit:
    var cl = %*{"val": st.connLimitCount}
    if st.connLimitFlags == "inverse": cl["inv"] = newJBool(true)
    return %*{"ct count": cl}
  of skMssClamp:
    if st.mssClampSize > 0:
      return %*{"mangle": {"key": {"tcp option": {"name": "maxseg", "field": "size"}}, "value": st.mssClampSize}}
    else:
      return %*{"mangle": {"key": {"tcp option": {"name": "maxseg", "field": "size"}}, "value": {"rt": {"key": "mtu"}}}}
  of skQueue:
    var q = %*{"num": st.queueNum}
    if st.queueFlags != "": q["flags"] = newJString(st.queueFlags)
    return %*{"queue": q}
  of skDup:
    var d = %*{"addr": st.dupAddr}
    if st.dupDev != "": d["dev"] = newJString(st.dupDev)
    return %*{"dup": d}
  of skQuota:
    var q = %*{"val": st.quotaVal, "val_unit": st.quotaUnit}
    if st.quotaInv: q["inv"] = newJBool(true)
    return %*{"quota": q}
  of skRaw:
    # Raw nftables JSON statement -- pass through directly
    return st.rawJson

# ---------------------------------------------------------------------------
# NftMapElem → JsonNode
# ---------------------------------------------------------------------------

proc toJsonNode*(e: NftMapElem): JsonNode =
  return %*[e.key.toJsonNode(), e.value.toJsonNode()]

# ---------------------------------------------------------------------------
# Top-level records → JsonNode
# ---------------------------------------------------------------------------

proc toJsonNode*(t: NftTable): JsonNode =
  return %*{"family": t.family, "name": t.name}

proc toJsonNode*(c: NftChain): JsonNode =
  var j = %*{"family": c.family, "table": c.table, "name": c.name}
  case c.kind
  of chkRegular: discard
  of chkBase:
    j["type"] = newJString(c.`type`)
    j["hook"] = newJString(c.hook)
    j["prio"] = newJInt(c.prio)
    j["policy"] = newJString(c.policy)
  return j

proc toJsonNode*(r: NftRule): JsonNode =
  var exprs = newJArray()
  for e in r.expr: exprs.add e.toJsonNode()
  var j = %*{"family": r.family, "table": r.table, "chain": r.chain, "expr": exprs}
  if r.comment != "": j["comment"] = newJString(r.comment)
  return j

proc toJsonNode*(st: NftSet): JsonNode =
  var j = %*{"family": st.family, "table": st.table, "name": st.name, "type": st.`type`}
  case st.kind
  of setkPlain:
    if st.plainElem.len > 0:
      var arr = newJArray()
      for e in st.plainElem: arr.add e.toJsonNode()
      j["elem"] = arr
  of setkNamed:
    if st.flags.len > 0:
      var arr = newJArray()
      for f in st.flags: arr.add newJString(f)
      j["flags"] = arr
    if st.size > 0: j["size"] = newJInt(st.size)
    if st.timeout > 0: j["timeout"] = newJInt(st.timeout)
    if st.elem.len > 0:
      var arr = newJArray()
      for e in st.elem: arr.add e.toJsonNode()
      j["elem"] = arr
  return j

proc toJsonNode*(m: NftMap): JsonNode =
  var j = %*{"family": m.family, "table": m.table, "name": m.name}
  if " . " in m.`type`:
    var arr = newJArray()
    for part in m.`type`.split(" . "): arr.add newJString(part)
    j["type"] = arr
  else:
    j["type"] = newJString(m.`type`)
  j["map"] = newJString(m.`map`)
  if m.flags.len > 0:
    var arr = newJArray()
    for f in m.flags: arr.add newJString(f)
    j["flags"] = arr
  if m.elem.len > 0:
    var arr = newJArray()
    for e in m.elem: arr.add e.toJsonNode()
    j["elem"] = arr
  return j

# ---------------------------------------------------------------------------
# NftCmd → JsonNode
# ---------------------------------------------------------------------------

proc toJsonNode*(cmd: NftCmd): JsonNode =
  case cmd.kind
  of nckMetainfo:
    return %*{"metainfo": {"json_schema_version": cmd.metainfo.json_schema_version}}
  of nckAdd:
    case cmd.add.kind
    of nakTable: return %*{"add": {"table": cmd.add.table.toJsonNode()}}
    of nakChain: return %*{"add": {"chain": cmd.add.chain.toJsonNode()}}
    of nakRule:  return %*{"add": {"rule": cmd.add.rule.toJsonNode()}}
    of nakSet:   return %*{"add": {"set": cmd.add.set.toJsonNode()}}
    of nakMap:   return %*{"add": {"map": cmd.add.map.toJsonNode()}}
  of nckDelete:
    return %*{"delete": {cmd.deleteWhat: {
      "family": cmd.delete.family, "name": cmd.delete.name}}}
  of nckRaw:
    # Raw nftables JSON commands -- pass through directly
    # Return the first one; the rest are handled by the ruleset emitter
    if cmd.rawCmds.len > 0:
      return cmd.rawCmds[0]
    return newJNull()

# ---------------------------------------------------------------------------
# NftRuleset → JsonNode
# ---------------------------------------------------------------------------

proc toJsonNode*(rs: NftRuleset): JsonNode =
  var arr = newJArray()
  for cmd in rs.nftables:
    if cmd.kind == nckRaw:
      # Raw commands may contain multiple JSON command objects
      for rawCmd in cmd.rawCmds:
        arr.add rawCmd
    else:
      arr.add cmd.toJsonNode()
  return %*{"nftables": arr}

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

proc emitJson*(rs: NftRuleset, pretty: bool = true): string =
  let j = rs.toJsonNode()
  if pretty:
    return j.pretty() & "\n"
  else:
    return $j & "\n"
