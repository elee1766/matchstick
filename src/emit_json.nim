## emit_json.nim - Serialize NftRuleset to nftables JSON format.
##
## Produces JSON matching the libnftables-json(5) schema, suitable for
## loading via `nft -j -f` or the libnftables C API with NFT_CTX_INPUT_JSON.
##
## The output format wraps each object in {"add": ...} commands:
##   {"nftables": [{"add": {"table": ...}}, {"add": {"chain": ...}}, ...]}

import std/[json, sequtils, strutils]
import ./nft_ir

# ---------------------------------------------------------------------------
# Expression to JSON
# ---------------------------------------------------------------------------

proc exprToJson(e: Expr): JsonNode =
  case e.kind
  of ekString:
    return newJString(e.strVal)
  of ekInt:
    return newJInt(e.intVal)
  of ekBool:
    return newJBool(e.boolVal)
  of ekList:
    var arr = newJArray()
    for elem in e.listElems:
      arr.add exprToJson(elem)
    return arr
  of ekPrefix:
    return %*{"prefix": {"addr": e.prefixAddr, "len": e.prefixLen}}
  of ekRange:
    return %*{"range": [exprToJson(e.rangeMin), exprToJson(e.rangeMax)]}
  of ekConcat:
    return %*{"concat": e.concatExprs.mapIt(exprToJson(it))}
  of ekPayload:
    return %*{"payload": {"protocol": e.payloadProto, "field": e.payloadField}}
  of ekMeta:
    return %*{"meta": {"key": e.metaKey}}
  of ekCt:
    var obj = %*{"ct": {"key": e.ctKey}}
    if e.ctDir != "":
      obj["ct"]["dir"] = newJString(e.ctDir)
    if e.ctFamily != "":
      obj["ct"]["family"] = newJString(e.ctFamily)
    return obj
  of ekFib:
    return %*{"fib": {"result": e.fibResult, "flags": e.fibFlags.mapIt(%it)}}
  of ekSet:
    return newJString("@" & e.setName)
  of ekMap:
    return %*{"map": {"key": exprToJson(e.mapKey), "data": "@" & e.mapData}}
  of ekElem:
    if e.elemTimeout > 0:
      return %*{"elem": {"val": exprToJson(e.elemVal), "timeout": e.elemTimeout}}
    return exprToJson(e.elemVal)

# ---------------------------------------------------------------------------
# Statement to JSON
# ---------------------------------------------------------------------------

proc stmtToJson(s: Stmt): JsonNode =
  case s.kind
  of skMatch:
    return %*{"match": {
      "op": $s.matchOp,
      "left": exprToJson(s.matchLeft),
      "right": exprToJson(s.matchRight),
    }}
  of skAccept:
    return %*{"accept": newJNull()}
  of skDrop:
    return %*{"drop": newJNull()}
  of skReturn:
    return %*{"return": newJNull()}
  of skReject:
    var obj = %*{"reject": newJObject()}
    if s.rejectType != "":
      obj["reject"]["type"] = newJString(s.rejectType)
    if s.rejectExpr != "":
      obj["reject"]["expr"] = newJString(s.rejectExpr)
    return obj
  of skJump:
    return %*{"jump": {"target": s.jumpTarget}}
  of skGoto:
    return %*{"goto": {"target": s.gotoTarget}}
  of skCounter:
    if s.counterName != "":
      return %*{"counter": s.counterName}
    return %*{"counter": {"packets": 0, "bytes": 0}}
  of skLog:
    var obj = newJObject()
    if s.logPrefix != "":
      obj["prefix"] = newJString(s.logPrefix)
    if s.logLevel != "":
      obj["level"] = newJString(s.logLevel)
    if s.logFlags.len > 0:
      obj["flags"] = %s.logFlags
    return %*{"log": obj}
  of skLimit:
    var obj = %*{"limit": {
      "rate": s.limitRate,
      "per": s.limitPer,
    }}
    if s.limitBurst > 0:
      obj["limit"]["burst"] = newJInt(s.limitBurst)
    if s.limitInv:
      obj["limit"]["inv"] = newJBool(true)
    return obj
  of skDnat:
    var obj = %*{"dnat": {"addr": s.dnatAddr, "family": s.dnatFamily}}
    if s.dnatPort > 0:
      obj["dnat"]["port"] = newJInt(s.dnatPort)
    return obj
  of skSnat:
    var obj = %*{"snat": {"addr": s.snatAddr, "family": s.snatFamily}}
    if s.snatPort > 0:
      obj["snat"]["port"] = newJInt(s.snatPort)
    return obj
  of skMasquerade:
    if s.masqPort > 0:
      return %*{"masquerade": {"port": s.masqPort}}
    return %*{"masquerade": newJNull()}
  of skVmap:
    return %*{"vmap": {
      "key": exprToJson(s.vmapKey),
      "data": exprToJson(s.vmapData),
    }}
  of skMangle:
    return %*{"mangle": {
      "key": exprToJson(s.mangleKey),
      "value": exprToJson(s.mangleValue),
    }}
  of skUpdate:
    # nftables JSON doesn't have a direct "update" statement --
    # it uses set element addition with an expression. For now, emit
    # as a custom extension that documents the intent.
    var stmts = newJArray()
    for sub in s.updateStmts:
      stmts.add stmtToJson(sub)
    return %*{"update": {
      "set": s.updateSet,
      "key": exprToJson(s.updateKey),
      "stmts": stmts,
    }}

# ---------------------------------------------------------------------------
# Top-level object to JSON
# ---------------------------------------------------------------------------

proc objectToJson(obj: NftObject): JsonNode =
  case obj.kind
  of nokTable:
    return %*{"table": {
      "family": obj.tableFamily,
      "name": obj.tableName,
    }}
  of nokChain:
    var chain = %*{
      "family": obj.chainFamily,
      "table": obj.chainTable,
      "name": obj.chainName,
    }
    if obj.chainIsBase:
      chain["type"] = newJString($obj.chainType)
      chain["hook"] = newJString($obj.chainHook)
      chain["prio"] = newJInt(obj.chainPrio)
      chain["policy"] = newJString($obj.chainPolicy)
    return %*{"chain": chain}
  of nokRule:
    var rule = %*{
      "family": obj.ruleFamily,
      "table": obj.ruleTable,
      "chain": obj.ruleChain,
      "expr": obj.ruleExprs.mapIt(stmtToJson(it)),
    }
    if obj.ruleComment != "":
      rule["comment"] = newJString(obj.ruleComment)
    return %*{"rule": rule}
  of nokSet:
    var s = %*{
      "family": obj.setFamily,
      "table": obj.setTable,
      "name": obj.setName,
      "type": obj.setType,
    }
    if obj.setFlags.len > 0:
      s["flags"] = %obj.setFlags
    if obj.setSize > 0:
      s["size"] = newJInt(obj.setSize)
    if obj.setTimeout > 0:
      s["timeout"] = newJInt(obj.setTimeout)
    if obj.setElems.len > 0:
      var elems = newJArray()
      for e in obj.setElems:
        elems.add exprToJson(e)
      s["elem"] = elems
    return %*{"set": s}
  of nokMap:
    var m = %*{
      "family": obj.mapFamily,
      "table": obj.mapTable,
      "name": obj.mapName,
    }
    # Concat types like "ifname . ifname" become arrays in JSON
    if " . " in obj.mapKeyType:
      m["type"] = %obj.mapKeyType.split(" . ")
    else:
      m["type"] = newJString(obj.mapKeyType)
    m["map"] = newJString(obj.mapValueType)
    if obj.mapFlags.len > 0:
      m["flags"] = %obj.mapFlags
    if obj.mapElems.len > 0:
      var elems = newJArray()
      for elem in obj.mapElems:
        elems.add %*[exprToJson(elem.key), exprToJson(elem.value)]
      m["elem"] = elems
    return %*{"map": m}
  of nokFlush:
    case obj.flushWhat
    of "ruleset":
      return %*{"flush": {"ruleset": newJNull()}}
    else:
      return %*{"flush": {obj.flushWhat: {
        "family": obj.flushFamily,
        "name": obj.flushName,
      }}}
  of nokDelete:
    return %*{"delete": {obj.deleteWhat: {
      "family": obj.deleteFamily,
      "name": obj.deleteName,
    }}}
  of nokComment:
    return %*{"comment": obj.commentText}

# ---------------------------------------------------------------------------
# Top-level: emit the full ruleset as JSON
# ---------------------------------------------------------------------------

proc emitJson*(rs: NftRuleset, pretty: bool = true): string =
  ## Emit the ruleset as nftables JSON format.
  ## Each object is wrapped in {"add": ...} for loading via `nft -j -f`.
  var arr = newJArray()

  # Metainfo
  arr.add %*{"metainfo": {"json_schema_version": 1}}

  for obj in rs.objects:
    case obj.kind
    of nokDelete:
      arr.add %*{"delete": objectToJson(obj)[obj.deleteWhat]}
    of nokComment:
      # JSON doesn't have comments -- skip or use a custom field
      continue
    else:
      arr.add %*{"add": objectToJson(obj)}

  let root = %*{"nftables": arr}
  if pretty:
    return root.pretty() & "\n"
  else:
    return $root & "\n"
