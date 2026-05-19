## Test JSON emission via jsony dumpHooks -- comprehensive coverage

import unittest
import std/[json, strutils]
import jsony
import ../src/nft_ir
import ../src/emit_json

suite "Expr JSON: literals":
  test "string": check parseJson(strExpr("eth0").toJson()).getStr == "eth0"
  test "int": check parseJson(intExpr(443).toJson()).getInt == 443
  test "bool true": check parseJson(boolExpr(true).toJson()).getBool == true
  test "bool false": check parseJson(boolExpr(false).toJson()).getBool == false

suite "Expr JSON: CIDR/prefix":
  test "CIDR becomes prefix":
    let j = parseJson(strExpr("192.168.0.0/24").toJson())
    check j["prefix"]["addr"].getStr == "192.168.0.0"
    check j["prefix"]["len"].getInt == 24
  test "plain IP stays string":
    check parseJson(strExpr("192.168.0.1").toJson()).getStr == "192.168.0.1"
  test "prefix expr direct":
    let j = parseJson(prefixExpr("10.0.0.0", 8).toJson())
    check j["prefix"]["addr"].getStr == "10.0.0.0"
    check j["prefix"]["len"].getInt == 8

suite "Expr JSON: collections":
  test "list":
    let j = parseJson(listExpr(@[intExpr(1), intExpr(2)]).toJson())
    check j.len == 2
    check j[0].getInt == 1
  test "range":
    let j = parseJson(rangeExpr(intExpr(100), intExpr(200)).toJson())
    check j["range"][0].getInt == 100
    check j["range"][1].getInt == 200
  test "concat":
    let j = parseJson(concatExpr(@[strExpr("a"), strExpr("b")]).toJson())
    check j["concat"].len == 2
  test "anonymous set":
    let j = parseJson(anonSetExpr(@[intExpr(22), intExpr(80)]).toJson())
    check j["set"][0].getInt == 22
  test "sorted anonymous set":
    let j = parseJson(sortedAnonSetExpr(@[intExpr(443), intExpr(80), intExpr(22)]).toJson())
    check j["set"][0].getInt == 22
    check j["set"][1].getInt == 80
    check j["set"][2].getInt == 443

suite "Expr JSON: nftables types":
  test "payload": check parseJson(payloadExpr("tcp", "dport").toJson())["payload"]["protocol"].getStr == "tcp"
  test "meta": check parseJson(metaExpr("iifname").toJson())["meta"]["key"].getStr == "iifname"
  test "ct state": check parseJson(ctExpr("state").toJson())["ct"]["key"].getStr == "state"
  test "ct with dir":
    let j = parseJson(ctExpr("saddr", dir = "original", family = "ip").toJson())
    check j["ct"]["dir"].getStr == "original"
    check j["ct"]["family"].getStr == "ip"
  test "fib":
    let j = parseJson(fibExpr("oif", @["saddr", "mark", "iif"]).toJson())
    check j["fib"]["result"].getStr == "oif"
    check j["fib"]["flags"].len == 3
  test "set ref": check parseJson(setRef("myset").toJson()).getStr == "@myset"
  test "map lookup":
    let j = parseJson(Expr(kind: ekMap, mapKey: metaExpr("iifname"), mapData: "mymap").toJson())
    check j["map"]["data"].getStr == "@mymap"
  test "elem with timeout":
    let j = parseJson(Expr(kind: ekElem, elemVal: strExpr("1.2.3.4"), elemTimeout: 3600).toJson())
    check j["elem"]["timeout"].getInt == 3600

suite "Expr JSON: operators":
  test "verdict accept": check parseJson(verdictExpr("accept").toJson()).hasKey("accept")
  test "verdict drop": check parseJson(verdictExpr("drop").toJson()).hasKey("drop")
  test "verdict return": check parseJson(verdictExpr("return").toJson()).hasKey("return")
  test "verdict jump":
    check parseJson(verdictExpr("jump", "ch").toJson())["jump"]["target"].getStr == "ch"
  test "verdict goto":
    check parseJson(verdictExpr("goto", "ch").toJson())["goto"]["target"].getStr == "ch"
  test "binop |":
    let j = parseJson(binOpExpr("|", strExpr("fin"), strExpr("syn")).toJson())
    check j["|"][0].getStr == "fin"
  test "binop &":
    let j = parseJson(binOpExpr("&", payloadExpr("tcp", "flags"), binOpExpr("|", strExpr("fin"), strExpr("syn"))).toJson())
    check j["&"][0].hasKey("payload")

suite "Stmt JSON: all variants":
  test "accept": check parseJson(acceptStmt().toJson()).hasKey("accept")
  test "drop": check parseJson(dropStmt().toJson()).hasKey("drop")
  test "return": check parseJson(returnStmt().toJson()).hasKey("return")
  test "reject":
    let j = parseJson(rejectStmt("icmpx", "admin-prohibited").toJson())
    check j["reject"]["type"].getStr == "icmpx"
    check j["reject"]["expr"].getStr == "admin-prohibited"
  test "jump": check parseJson(jumpStmt("ch").toJson())["jump"]["target"].getStr == "ch"
  test "goto":
    let s = Stmt(kind: skGoto, gotoTarget: "ch")
    check parseJson(s.toJson())["goto"]["target"].getStr == "ch"
  test "counter anonymous":
    let j = parseJson(counterStmt().toJson())
    check j["counter"]["packets"].getInt == 0
  test "counter named":
    let j = parseJson(counterStmt("myctr").toJson())
    check j["counter"].getStr == "myctr"
  test "log prefix":
    let j = parseJson(logStmt("DROP: ").toJson())
    check j["log"]["prefix"].getStr == "DROP: "
  test "log level":
    let j = parseJson(logStmt("", "warn").toJson())
    check j["log"]["level"].getStr == "warn"
  test "log flags":
    let s = Stmt(kind: skLog, logPrefix: "X", logFlags: @["tcp sequence", "ip options"])
    let j = parseJson(s.toJson())
    check j["log"]["flags"].len == 2
  test "limit":
    let j = parseJson(limitStmt(5, "minute", burst = 10).toJson())
    check j["limit"]["rate"].getInt == 5
    check j["limit"]["per"].getStr == "minute"
    check j["limit"]["burst"].getInt == 10
  test "limit inv":
    let j = parseJson(limitStmt(100, "second", inv = true).toJson())
    check j["limit"]["inv"].getBool == true
  test "dnat":
    let j = parseJson(dnatStmt("10.0.0.1", 8080, "ip").toJson())
    check j["dnat"]["addr"].getStr == "10.0.0.1"
    check j["dnat"]["port"].getInt == 8080
  test "snat":
    let j = parseJson(snatStmt("1.2.3.4", 0, "ip").toJson())
    check j["snat"]["addr"].getStr == "1.2.3.4"
    check not j["snat"].hasKey("port")
  test "masquerade": check parseJson(masqueradeStmt().toJson()).hasKey("masquerade")
  test "masquerade with port":
    check parseJson(masqueradeStmt(1024).toJson())["masquerade"]["port"].getInt == 1024
  test "vmap":
    let s = vmapStmt(metaExpr("iifname"), setRef("mymap"))
    let j = parseJson(s.toJson())
    check j["vmap"]["key"]["meta"]["key"].getStr == "iifname"
  test "mangle":
    let s = Stmt(kind: skMangle, mangleKey: metaExpr("mark"), mangleValue: intExpr(1))
    let j = parseJson(s.toJson())
    check j["mangle"]["key"]["meta"]["key"].getStr == "mark"
  test "update":
    let s = updateStmt("rl", payloadExpr("ip", "saddr"), @[limitStmt(5, "minute")])
    let j = parseJson(s.toJson())
    check j["set"]["op"].getStr == "update"
    check j["set"]["set"].getStr == "@rl"
  test "match eq":
    let j = parseJson(matchStmt(opEq, payloadExpr("tcp", "dport"), intExpr(22)).toJson())
    check j["match"]["op"].getStr == "=="
  test "match in":
    let j = parseJson(matchStmt(opIn, ctExpr("state"), strExpr("invalid")).toJson())
    check j["match"]["op"].getStr == "in"
  test "match not":
    let j = parseJson(matchStmt(opNot, payloadExpr("tcp", "flags"), listExpr(@[strExpr("fin")])).toJson())
    check j["match"]["op"].getStr == "!"
  test "match neq":
    let j = parseJson(matchStmt(opNeq, metaExpr("iifname"), strExpr("lo")).toJson())
    check j["match"]["op"].getStr == "!="

suite "Top-level JSON":
  test "add table": check parseJson(addTable("inet", "t").toJson())["add"]["table"]["name"].getStr == "t"
  test "add base chain":
    let j = parseJson(addBaseChain("inet", "t", "c", "filter", "input", 5, "drop").toJson())
    check j["add"]["chain"]["prio"].getInt == 5
  test "add regular chain":
    let j = parseJson(addChain("inet", "t", "c").toJson())
    check not j["add"]["chain"].hasKey("type")
  test "add rule with comment":
    let j = parseJson(addRule("inet", "t", "c", @[acceptStmt()], "hi").toJson())
    check j["add"]["rule"]["comment"].getStr == "hi"
  test "add set with elements":
    let j = parseJson(addSet("inet", "t", "s", "ipv4_addr", @["timeout"], elem = @[strExpr("1.2.3.4")]).toJson())
    check j["add"]["set"]["elem"].len == 1
  test "add map with verdict elems":
    let e = @[NftMapElem(key: strExpr("eth0"), value: verdictExpr("jump", "ch"))]
    let j = parseJson(addMap("inet", "t", "m", "ifname", "verdict", elem = e).toJson())
    check j["add"]["map"]["elem"][0][1]["jump"]["target"].getStr == "ch"
  test "add map concat type":
    let j = parseJson(addMap("inet", "t", "m", "ifname . ifname", "verdict").toJson())
    check j["add"]["map"]["type"].len == 2
  test "delete table":
    let j = parseJson(deleteTable("inet", "t").toJson())
    check j["delete"]["table"]["name"].getStr == "t"
  test "metainfo":
    check parseJson(metainfoCmd().toJson())["metainfo"]["json_schema_version"].getInt == 1
  test "ruleset wrapper":
    let rs = NftRuleset(nftables: @[metainfoCmd(), addTable("inet", "t")])
    let j = parseJson(rs.toJson())
    check j["nftables"].len == 2
