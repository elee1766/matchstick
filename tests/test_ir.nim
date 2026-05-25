## Test nft_ir module: expression and statement construction

import unittest
import ../src/nft_ir

suite "Expr constructors":
  test "string expr":
    let e = strExpr("eth0")
    check e.kind == ekString
    check e.strVal == "eth0"

  test "int expr":
    let e = intExpr(443)
    check e.kind == ekInt
    check e.intVal == 443

  test "payload expr":
    let e = payloadExpr("tcp", "dport")
    check e.kind == ekPayload
    check e.payloadProto == "tcp"
    check e.payloadField == "dport"

  test "verdict expr":
    let e = verdictExpr("jump", "mychain")
    check e.kind == ekVerdict
    check e.verdictKind == "jump"
    check e.verdictTarget == "mychain"

  test "anonymous set sorted":
    let e = sortedAnonSetExpr(@[intExpr(443), intExpr(80), intExpr(8448)])
    check e.kind == ekAnonymousSet
    check e.anonSetElems[0].intVal == 80
    check e.anonSetElems[1].intVal == 443
    check e.anonSetElems[2].intVal == 8448

  test "range expr":
    let e = rangeExpr(intExpr(6881), intExpr(6999))
    check e.kind == ekRange
    check e.rangeMin.intVal == 6881
    check e.rangeMax.intVal == 6999

  test "binop expr":
    let e = binOpExpr("|", strExpr("fin"), strExpr("syn"))
    check e.kind == ekBinOp
    check e.binOp == "|"

suite "Stmt constructors":
  test "accept":
    let s = acceptStmt()
    check s.kind == skAccept

  test "match":
    let s = matchStmt(opEq, payloadExpr("tcp", "dport"), intExpr(22))
    check s.kind == skMatch
    check s.matchOp == opEq

  test "jump":
    let s = jumpStmt("mychain")
    check s.kind == skJump
    check s.jumpTarget == "mychain"

  test "reject":
    let s = rejectStmt("icmpx", "admin-prohibited")
    check s.kind == skReject
    check s.rejectType == "icmpx"

  test "dnat":
    let s = dnatStmt("192.168.0.86", 0, "ip")
    check s.kind == skDnat
    check s.dnatAddr == "192.168.0.86"

  test "masquerade":
    let s = masqueradeStmt()
    check s.kind == skMasquerade
    check s.masqPort == 0

suite "Command constructors":
  test "addTable":
    let cmd = addTable("inet", "matchstick")
    check cmd.kind == nckAdd
    check cmd.add.kind == nakTable
    check cmd.add.table.family == "inet"
    check cmd.add.table.name == "matchstick"

  test "addBaseChain":
    let cmd = addBaseChain("inet", "matchstick", "input", "filter", "input", 5, "drop")
    check cmd.kind == nckAdd
    check cmd.add.kind == nakChain
    check cmd.add.chain.kind == chkBase
    check cmd.add.chain.chainType == "filter"
    check cmd.add.chain.hook == "input"
    check cmd.add.chain.prio == 5
    check cmd.add.chain.policy == "drop"

  test "addChain (regular)":
    let cmd = addChain("inet", "matchstick", "mychain")
    check cmd.add.chain.kind == chkRegular

  test "addRule":
    let cmd = addRule("inet", "matchstick", "input", @[acceptStmt()], "test rule")
    check cmd.add.kind == nakRule
    check cmd.add.rule.expr.len == 1
    check cmd.add.rule.comment == "test rule"

  test "addSet":
    let cmd = addSet("inet", "matchstick", "myset", "ipv4_addr", @["timeout"], size = 65535)
    check cmd.add.kind == nakSet
    check cmd.add.set.kind == setkNamed
    check cmd.add.set.setType == "ipv4_addr"
    check cmd.add.set.flags == @["timeout"]
    check cmd.add.set.size == 65535

  test "addMap":
    let cmd = addMap("inet", "matchstick", "mymap", "ifname", "verdict",
      elem = @[NftMapElem(key: strExpr("eth0"), value: verdictExpr("jump", "mychain"))])
    check cmd.add.kind == nakMap
    check cmd.add.map.elem.len == 1
