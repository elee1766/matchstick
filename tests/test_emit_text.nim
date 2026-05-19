## Test text emission -- comprehensive coverage of all Expr and Stmt types

import unittest
import std/[strutils]
import ../src/nft_ir
import ../src/emit_text
import ../src/writer

suite "Expr toText: all variants":
  test "string": check strExpr("eth0").toText == "eth0"
  test "int": check intExpr(443).toText == "443"
  test "bool true": check boolExpr(true).toText == "1"
  test "bool false": check boolExpr(false).toText == "0"
  test "prefix": check prefixExpr("10.0.0.0", 8).toText == "10.0.0.0/8"
  test "range": check rangeExpr(intExpr(100), intExpr(200)).toText == "100-200"
  test "set ref": check setRef("myset").toText == "@myset"
  test "verdict jump": check verdictExpr("jump", "ch").toText == "jump ch"
  test "verdict accept": check verdictExpr("accept").toText == "accept"
  test "verdict drop": check verdictExpr("drop").toText == "drop"
  test "verdict return": check verdictExpr("return").toText == "return"
  test "verdict goto": check verdictExpr("goto", "ch").toText == "goto ch"
  test "binop |": check binOpExpr("|", strExpr("fin"), strExpr("syn")).toText == "fin|syn"
  test "binop &": check binOpExpr("&", strExpr("a"), strExpr("b")).toText == "a & b"
  test "payload": check payloadExpr("tcp", "dport").toText == "tcp dport"
  test "meta iifname": check metaExpr("iifname").toText == "iifname"
  test "meta nfproto": check metaExpr("nfproto").toText == "meta nfproto"
  test "ct state": check ctExpr("state").toText == "ct state"
  test "ct with dir": check ctExpr("saddr", "original").toText == "ct original saddr"
  test "fib": check fibExpr("oif", @["saddr", "iif"]).toText == "fib saddr . iif oif"
  test "map lookup":
    let e = Expr(kind: ekMap, mapKey: metaExpr("iifname"), mapData: "mymap")
    check e.toText == "iifname map @mymap"
  test "elem": check Expr(kind: ekElem, elemVal: strExpr("1.2.3.4"), elemTimeout: 0).toText == "1.2.3.4"

  test "list single": check listExpr(@[intExpr(22)]).toText == "22"
  test "list multi": check listExpr(@[intExpr(22), intExpr(80)]).toText == "{ 22, 80 }"
  test "concat": check concatExpr(@[strExpr("a"), strExpr("b")]).toText == "a . b"

  test "anonymous set single": check anonSetExpr(@[intExpr(22)]).toText == "22"
  test "anonymous set multi":
    check anonSetExpr(@[intExpr(22), intExpr(80)]).toText == "{ 22, 80 }"
  test "anonymous set vmap pairs":
    let e = anonSetExpr(@[
      listExpr(@[strExpr("ipv4"), verdictExpr("jump", "c4")]),
      listExpr(@[strExpr("ipv6"), verdictExpr("jump", "c6")])])
    check e.toText == "{ ipv4 : jump c4, ipv6 : jump c6 }"

suite "Expr toMatchLeft":
  test "meta shorthand": check metaExpr("iifname").toMatchLeft == "iifname"
  test "meta oifname": check metaExpr("oifname").toMatchLeft == "oifname"
  test "meta long": check metaExpr("nfproto").toMatchLeft == "meta nfproto"
  test "payload": check payloadExpr("ip", "saddr").toMatchLeft == "ip saddr"
  test "binop & with |":
    let e = binOpExpr("&", payloadExpr("tcp", "flags"), binOpExpr("|", strExpr("fin"), strExpr("syn")))
    check e.toMatchLeft == "tcp flags & (fin|syn)"
  test "binop & with list":
    let e = binOpExpr("&", payloadExpr("tcp", "flags"), listExpr(@[strExpr("fin"), strExpr("syn")]))
    check e.toMatchLeft == "tcp flags & (fin|syn)"
  test "concat":
    check concatExpr(@[metaExpr("iifname"), metaExpr("oifname")]).toMatchLeft == "iifname . oifname"

suite "Expr toQuoted":
  test "string gets quotes": check strExpr("eth0").toQuoted == "\"eth0\""
  test "int no quotes": check intExpr(22).toQuoted == "22"

suite "Stmt text: all variants":
  test "accept":
    var w = newWriter(); w.emitStmt(acceptStmt()); check w.result == "accept"
  test "drop":
    var w = newWriter(); w.emitStmt(dropStmt()); check w.result == "drop"
  test "return":
    var w = newWriter(); w.emitStmt(returnStmt()); check w.result == "return"
  test "reject":
    var w = newWriter(); w.emitStmt(rejectStmt("icmpx", "admin-prohibited"))
    check w.result == "reject with icmpx admin-prohibited"
  test "jump":
    var w = newWriter(); w.emitStmt(jumpStmt("ch")); check w.result == "jump ch"
  test "goto":
    var w = newWriter(); w.emitStmt(Stmt(kind: skGoto, gotoTarget: "ch"))
    check w.result == "goto ch"
  test "counter anonymous":
    var w = newWriter(); w.emitStmt(counterStmt()); check w.result == "counter"
  test "counter named":
    var w = newWriter(); w.emitStmt(counterStmt("myctr"))
    check w.result == "counter name myctr"
  test "log prefix":
    var w = newWriter(); w.emitStmt(logStmt("DROP: "))
    check w.result == "log prefix \"DROP: \""
  test "log level":
    var w = newWriter(); w.emitStmt(logStmt("", "warn"))
    check w.result == "log level warn"
  test "limit":
    var w = newWriter(); w.emitStmt(limitStmt(5, "minute", burst = 10))
    check w.result == "limit rate 5/minute burst 10 packets"
  test "limit inv":
    var w = newWriter(); w.emitStmt(limitStmt(100, "second", inv = true))
    check w.result == "limit rate over 100/second"
  test "dnat":
    var w = newWriter(); w.emitStmt(dnatStmt("10.0.0.1", 0, "ip"))
    check w.result == "dnat ip to 10.0.0.1"
  test "dnat with port":
    var w = newWriter(); w.emitStmt(dnatStmt("10.0.0.1", 8080, "ip"))
    check w.result == "dnat ip to 10.0.0.1:8080"
  test "snat":
    var w = newWriter(); w.emitStmt(snatStmt("1.2.3.4", 0, "ip"))
    check w.result == "snat ip to 1.2.3.4"
  test "snat with port":
    var w = newWriter(); w.emitStmt(snatStmt("1.2.3.4", 1024, "ip"))
    check w.result == "snat ip to 1.2.3.4:1024"
  test "masquerade":
    var w = newWriter(); w.emitStmt(masqueradeStmt()); check w.result == "masquerade"
  test "masquerade with port":
    var w = newWriter(); w.emitStmt(masqueradeStmt(1024))
    check w.result == "masquerade to :1024"
  test "vmap":
    var w = newWriter(); w.emitStmt(vmapStmt(metaExpr("iifname"), setRef("mymap")))
    check w.result == "iifname vmap @mymap"
  test "mangle":
    var w = newWriter()
    w.emitStmt(Stmt(kind: skMangle, mangleKey: metaExpr("mark"), mangleValue: intExpr(1)))
    check w.result == "meta mark set 1"
  test "update":
    var w = newWriter()
    w.emitStmt(updateStmt("rl", payloadExpr("ip", "saddr"), @[limitStmt(5, "minute", burst = 5)]))
    check "update @rl" in w.result
    check "limit rate 5/minute burst 5 packets" in w.result

suite "Stmt text: match operators":
  test "match eq":
    var w = newWriter(); w.emitStmt(matchStmt(opEq, payloadExpr("tcp", "dport"), intExpr(22)))
    check w.result == "tcp dport 22"
  test "match in":
    var w = newWriter(); w.emitStmt(matchStmt(opIn, ctExpr("state"), strExpr("invalid")))
    check w.result == "ct state invalid"
  test "match neq":
    var w = newWriter(); w.emitStmt(matchStmt(opNeq, metaExpr("iifname"), strExpr("lo")))
    check w.result == "iifname != lo"
  test "match not (flags)":
    var w = newWriter()
    w.emitStmt(matchStmt(opNot, payloadExpr("tcp", "flags"),
      listExpr(@[strExpr("fin"), strExpr("syn"), strExpr("rst")])))
    check w.result == "tcp flags ! fin,syn,rst"
  test "match lt":
    var w = newWriter(); w.emitStmt(matchStmt(opLt, payloadExpr("ip", "length"), intExpr(100)))
    check "< 100" in w.result
  test "match gt":
    var w = newWriter(); w.emitStmt(matchStmt(opGt, payloadExpr("ip", "ttl"), intExpr(0)))
    check "> 0" in w.result
  test "match with anonymous set":
    var w = newWriter()
    w.emitStmt(matchStmt(opEq, payloadExpr("tcp", "dport"),
      anonSetExpr(@[intExpr(22), intExpr(80), intExpr(443)])))
    check w.result == "tcp dport { 22, 80, 443 }"
  test "match with range":
    var w = newWriter()
    w.emitStmt(matchStmt(opEq, payloadExpr("udp", "dport"),
      rangeExpr(intExpr(10000), intExpr(10100))))
    check w.result == "udp dport 10000-10100"
