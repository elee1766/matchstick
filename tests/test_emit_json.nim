## Test JSON emission via std/json -- comprehensive coverage

import unittest
import std/json
import ../src/matchstickpkg/nft_ir
import ../src/matchstickpkg/emit_json

suite "Expr JSON: literals":
  test "string": check strExpr("eth0").toJsonNode().getStr == "eth0"
  test "int": check intExpr(443).toJsonNode().getInt == 443
  test "bool true": check boolExpr(true).toJsonNode().getBool == true
  test "bool false": check boolExpr(false).toJsonNode().getBool == false

suite "Expr JSON: CIDR/prefix":
  test "CIDR becomes prefix":
    let j = strExpr("192.168.0.0/24").toJsonNode()
    check j["prefix"]["addr"].getStr == "192.168.0.0"
    check j["prefix"]["len"].getInt == 24
  test "plain IP stays string":
    check strExpr("192.168.0.1").toJsonNode().getStr == "192.168.0.1"
  test "prefix expr direct":
    let j = prefixExpr("10.0.0.0", 8).toJsonNode()
    check j["prefix"]["addr"].getStr == "10.0.0.0"
    check j["prefix"]["len"].getInt == 8

suite "Expr JSON: collections":
  test "list":
    let j = listExpr(@[intExpr(1), intExpr(2)]).toJsonNode()
    check j.len == 2
    check j[0].getInt == 1
  test "range":
    let j = rangeExpr(intExpr(100), intExpr(200)).toJsonNode()
    check j["range"][0].getInt == 100
    check j["range"][1].getInt == 200
  test "concat":
    let j = concatExpr(@[strExpr("a"), strExpr("b")]).toJsonNode()
    check j["concat"].len == 2
  test "anonymous set":
    let j = anonSetExpr(@[intExpr(22), intExpr(80)]).toJsonNode()
    check j["set"][0].getInt == 22
  test "sorted anonymous set":
    let j = sortedAnonSetExpr(@[intExpr(443), intExpr(80), intExpr(22)]).toJsonNode()
    check j["set"][0].getInt == 22
    check j["set"][1].getInt == 80
    check j["set"][2].getInt == 443

suite "Expr JSON: nftables types":
  test "payload": check payloadExpr("tcp", "dport").toJsonNode()["payload"]["protocol"].getStr == "tcp"
  test "meta": check metaExpr("iifname").toJsonNode()["meta"]["key"].getStr == "iifname"
  test "ct state": check ctExpr("state").toJsonNode()["ct"]["key"].getStr == "state"
  test "ct with dir":
    let j = ctExpr("saddr", dir = "original", family = "ip").toJsonNode()
    check j["ct"]["dir"].getStr == "original"
    check j["ct"]["family"].getStr == "ip"
  test "fib":
    let j = fibExpr("oif", @["saddr", "mark", "iif"]).toJsonNode()
    check j["fib"]["result"].getStr == "oif"
    check j["fib"]["flags"].len == 3
  test "set ref": check setRef("myset").toJsonNode().getStr == "@myset"
  test "map lookup":
    let j = Expr(kind: ekMap, mapKey: metaExpr("iifname"), mapData: "mymap").toJsonNode()
    check j["map"]["data"].getStr == "@mymap"
  test "elem with timeout":
    let j = Expr(kind: ekElem, elemVal: strExpr("1.2.3.4"), elemTimeout: 3600).toJsonNode()
    check j["elem"]["timeout"].getInt == 3600

suite "Expr JSON: operators":
  test "verdict accept": check verdictExpr("accept").toJsonNode().hasKey("accept")
  test "verdict drop": check verdictExpr("drop").toJsonNode().hasKey("drop")
  test "verdict return": check verdictExpr("return").toJsonNode().hasKey("return")
  test "verdict jump":
    check verdictExpr("jump", "ch").toJsonNode()["jump"]["target"].getStr == "ch"
  test "verdict goto":
    check verdictExpr("goto", "ch").toJsonNode()["goto"]["target"].getStr == "ch"
  test "binop |":
    let j = binOpExpr("|", strExpr("fin"), strExpr("syn")).toJsonNode()
    check j["|"][0].getStr == "fin"
  test "binop &":
    let j = binOpExpr("&", payloadExpr("tcp", "flags"), binOpExpr("|", strExpr("fin"), strExpr("syn"))).toJsonNode()
    check j["&"][0].hasKey("payload")

suite "Stmt JSON: all variants":
  test "accept": check acceptStmt().toJsonNode().hasKey("accept")
  test "drop": check dropStmt().toJsonNode().hasKey("drop")
  test "return": check returnStmt().toJsonNode().hasKey("return")
  test "reject":
    let j = rejectStmt("icmpx", "admin-prohibited").toJsonNode()
    check j["reject"]["type"].getStr == "icmpx"
    check j["reject"]["expr"].getStr == "admin-prohibited"
  test "jump": check jumpStmt("ch").toJsonNode()["jump"]["target"].getStr == "ch"
  test "goto":
    let s = Stmt(kind: skGoto, gotoTarget: "ch")
    check s.toJsonNode()["goto"]["target"].getStr == "ch"
  test "counter anonymous":
    let j = counterStmt().toJsonNode()
    check j["counter"]["packets"].getInt == 0
  test "counter named":
    let j = counterStmt("myctr").toJsonNode()
    check j["counter"].getStr == "myctr"
  test "log prefix":
    let j = logStmt("DROP: ").toJsonNode()
    check j["log"]["prefix"].getStr == "DROP: "
  test "log level":
    let j = logStmt("", "warn").toJsonNode()
    check j["log"]["level"].getStr == "warn"
  test "log flags":
    let s = Stmt(kind: skLog, logPrefix: "X", logFlags: @["tcp sequence", "ip options"])
    let j = s.toJsonNode()
    check j["log"]["flags"].len == 2
  test "limit":
    let j = limitStmt(5, "minute", burst = 10).toJsonNode()
    check j["limit"]["rate"].getInt == 5
    check j["limit"]["per"].getStr == "minute"
    check j["limit"]["burst"].getInt == 10
  test "limit inv":
    let j = limitStmt(100, "second", inv = true).toJsonNode()
    check j["limit"]["inv"].getBool == true
  test "dnat":
    let j = dnatStmt("10.0.0.1", 8080, "ip").toJsonNode()
    check j["dnat"]["addr"].getStr == "10.0.0.1"
    check j["dnat"]["port"].getInt == 8080
  test "snat":
    let j = snatStmt("1.2.3.4", 0, "ip").toJsonNode()
    check j["snat"]["addr"].getStr == "1.2.3.4"
    check not j["snat"].hasKey("port")
  test "masquerade": check masqueradeStmt().toJsonNode().hasKey("masquerade")
  test "masquerade with port":
    check masqueradeStmt(1024).toJsonNode()["masquerade"]["port"].getInt == 1024
  test "vmap":
    let s = vmapStmt(metaExpr("iifname"), setRef("mymap"))
    let j = s.toJsonNode()
    check j["vmap"]["key"]["meta"]["key"].getStr == "iifname"
  test "mangle":
    let s = Stmt(kind: skMangle, mangleKey: metaExpr("mark"), mangleValue: intExpr(1))
    let j = s.toJsonNode()
    check j["mangle"]["key"]["meta"]["key"].getStr == "mark"
  test "update":
    let s = updateStmt("rl", payloadExpr("ip", "saddr"), @[limitStmt(5, "minute")])
    let j = s.toJsonNode()
    check j["set"]["op"].getStr == "update"
    check j["set"]["set"].getStr == "@rl"
  test "match eq":
    let j = matchStmt(opEq, payloadExpr("tcp", "dport"), intExpr(22)).toJsonNode()
    check j["match"]["op"].getStr == "=="
  test "match in":
    let j = matchStmt(opIn, ctExpr("state"), strExpr("invalid")).toJsonNode()
    check j["match"]["op"].getStr == "in"
  test "match not":
    let j = matchStmt(opNot, payloadExpr("tcp", "flags"), listExpr(@[strExpr("fin")])).toJsonNode()
    check j["match"]["op"].getStr == "!"
  test "match neq":
    let j = matchStmt(opNeq, metaExpr("iifname"), strExpr("lo")).toJsonNode()
    check j["match"]["op"].getStr == "!="

suite "Top-level JSON":
  test "add table": check addTable("inet", "t").toJsonNode()["add"]["table"]["name"].getStr == "t"
  test "add base chain":
    let j = addBaseChain("inet", "t", "c", "filter", "input", 5, "drop").toJsonNode()
    check j["add"]["chain"]["prio"].getInt == 5
  test "add regular chain":
    let j = addChain("inet", "t", "c").toJsonNode()
    check not j["add"]["chain"].hasKey("type")
  test "add rule with comment":
    let j = addRule("inet", "t", "c", @[acceptStmt()], "hi").toJsonNode()
    check j["add"]["rule"]["comment"].getStr == "hi"
  test "add set with elements":
    let j = addSet("inet", "t", "s", "ipv4_addr", @["timeout"], elem = @[strExpr("1.2.3.4")]).toJsonNode()
    check j["add"]["set"]["elem"].len == 1
  test "add map with verdict elems":
    let e = @[NftMapElem(key: strExpr("eth0"), value: verdictExpr("jump", "ch"))]
    let j = addMap("inet", "t", "m", "ifname", "verdict", elem = e).toJsonNode()
    check j["add"]["map"]["elem"][0][1]["jump"]["target"].getStr == "ch"
  test "add map concat type":
    let j = addMap("inet", "t", "m", "ifname . ifname", "verdict").toJsonNode()
    check j["add"]["map"]["type"].len == 2
  test "delete table":
    let j = deleteTable("inet", "t").toJsonNode()
    check j["delete"]["table"]["name"].getStr == "t"
  test "metainfo":
    check metainfoCmd().toJsonNode()["metainfo"]["json_schema_version"].getInt == 1
  test "ruleset wrapper":
    let rs = NftRuleset(nftables: @[metainfoCmd(), addTable("inet", "t")])
    let j = rs.toJsonNode()
    check j["nftables"].len == 2
