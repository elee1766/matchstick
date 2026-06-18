## Network probe integration tests.
##
## Renders matchstick configs, applies the nftables ruleset inside isolated
## network namespaces, then sends real TCP probes to verify that accept /
## drop / reject verdicts work at the packet level.
##
## Input tests (two-namespace topology):
##   [client netns] -- veth -- [firewall netns + nftables]
##
## Forward/NAT tests (three-namespace topology):
##   [client netns] -- veth_lan -- [firewall netns] -- veth_wan -- [server netns]
##
## Uses probe_helper.py (pure stdlib Python 3, no pip dependencies) for the
## namespace/veth plumbing. Requires: nft, unshare, python3.

import unittest
import std/[json, os, osproc, strutils]

const projectRoot = currentSourcePath().parentDir().parentDir().parentDir()
const matchstickBin = projectRoot / "matchstick"
const probeHelper = projectRoot / "tests" / "integration" / "probe_helper.py"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

type
  ProbeVerdict* = enum
    pvAccept = "accept"
    pvDrop = "drop"
    pvReject = "reject"

  Probe* = object
    port: int
    expect: ProbeVerdict

  ForwardProbe* = object
    destIp: string
    destPort: int
    expectSrcIp: string
    expectBlocked: bool

  ProbeResult = object
    port: int
    expect, got: string
    ok: bool

proc renderConfig(config: string, flags = ""): tuple[text: string, ok: bool] =
  let tmpFile = getTempDir() / "matchstick_probe.lua"
  writeFile(tmpFile, config)
  defer: removeFile(tmpFile)
  let cmd = matchstickBin & " render " & flags & " " & quoteShell(tmpFile) & " 2>/dev/null"
  let (output, exitCode) = execCmdEx(cmd)
  return (output, exitCode == 0)

proc runHelper(ruleset: string, spec: JsonNode): seq[ProbeResult] =
  ## Write ruleset + spec to temp files, invoke probe_helper.py via unshare.
  let rulesetFile = getTempDir() / "matchstick_probe.nft"
  let specFile = getTempDir() / "matchstick_probe_spec.json"
  writeFile(rulesetFile, ruleset)
  writeFile(specFile, $spec)
  defer:
    removeFile(rulesetFile)
    removeFile(specFile)

  let cmd = "unshare --user --net --map-root-user -- python3 " &
    quoteShell(probeHelper) & " " &
    quoteShell(rulesetFile) & " " &
    quoteShell(specFile) & " 2>/dev/null"
  let (output, exitCode) = execCmdEx(cmd)

  if exitCode != 0 or output.strip().len == 0:
    return @[ProbeResult(port: 0, expect: "run", got: "helper failed: " & $exitCode, ok: false)]

  try:
    let j = parseJson(output.strip())
    if not j["ok"].getBool():
      return @[ProbeResult(port: 0, expect: "ok", got: j.getOrDefault("error").getStr("unknown"), ok: false)]
    for r in j["results"]:
      result.add ProbeResult(
        port: r["port"].getInt(), expect: r["expect"].getStr(),
        got: r["got"].getStr(), ok: r["pass"].getBool())
  except:
    result.add ProbeResult(port: 0, expect: "parse", got: output.strip()[0..min(200, output.len-1)], ok: false)

proc runInputProbes(ruleset: string, vethHost, hostAddr, clientAddr: string,
                    listenPorts: seq[int], probes: seq[Probe],
                    extraSetup: seq[string] = @[]): seq[ProbeResult] =
  var probeArr = newJArray()
  for p in probes:
    probeArr.add(%*{"proto": "tcp", "port": p.port, "expect": $p.expect})
  var listenArr = newJArray()
  for port in listenPorts: listenArr.add(%port)
  var setupArr = newJArray()
  for cmd in extraSetup: setupArr.add(%cmd)

  let spec = %*{
    "host_addr": hostAddr, "client_addr": clientAddr,
    "veth_host": vethHost, "listen_ports": listenArr,
    "probes": probeArr, "extra_setup": setupArr,
  }
  return runHelper(ruleset, spec)

proc runForwardProbes(ruleset: string,
                      lanIface, lanHostAddr, lanClientAddr,
                      wanIface, wanHostAddr, wanServerAddr: string,
                      serverPort: int, probes: seq[ForwardProbe],
                      extraSetup: seq[string] = @[]): seq[ProbeResult] =
  var probeArr = newJArray()
  for p in probes:
    var pj = %*{"dest_ip": p.destIp, "dest_port": p.destPort, "expect_src_ip": p.expectSrcIp}
    if p.expectBlocked: pj["expect_blocked"] = %true
    probeArr.add(pj)
  var setupArr = newJArray()
  for cmd in extraSetup: setupArr.add(%cmd)

  let spec = %*{
    "mode": "forward",
    "lan_host_addr": lanHostAddr, "lan_client_addr": lanClientAddr, "lan_iface": lanIface,
    "wan_host_addr": wanHostAddr, "wan_server_addr": wanServerAddr, "wan_iface": wanIface,
    "server_port": serverPort, "probes": probeArr, "extra_setup": setupArr,
  }
  return runHelper(ruleset, spec)

proc checkAllPass(results: seq[ProbeResult]) =
  for r in results:
    if not r.ok:
      echo "  FAIL port ", r.port, ": expected ", r.expect, " got ", r.got
    check r.ok

# ---------------------------------------------------------------------------
# Prerequisites
# ---------------------------------------------------------------------------

let (_, nftEc) = execCmdEx("which nft 2>/dev/null")
let (_, unsEc) = execCmdEx("unshare --user --net --map-root-user -- true 2>/dev/null")
let (_, pyEc) = execCmdEx("which python3 2>/dev/null")
let canProbe = nftEc == 0 and unsEc == 0 and pyEc == 0

# ---------------------------------------------------------------------------
# Configs
# ---------------------------------------------------------------------------

const cfgSimple = """
local ssh = fw:service("ssh", "tcp", 22)
local http = fw:service("http", "tcp", 80)
local self = fw:zone("fw")
local wan = fw:zone("wan", "eth0")
fw:policy(wan, self, "drop")
fw:rule(wan, self, "accept", ssh)
fw:rule(wan, self, "accept", http)
"""

const cfgTwoZone = """
local ssh = fw:service("ssh", "tcp", 22)
local http = fw:service("http", "tcp", 80)
local dns = fw:service("dns", {"tcp", "udp"}, 53)
local self = fw:zone("fw")
local wan = fw:zone("wan", "eth0")
local lan = fw:zone("lan", "eth1")
fw:policy(wan, self, "drop")
fw:policy(lan, self, "reject")
fw:policy(lan, wan, "accept")
fw:policy("*", "*", "reject")
fw:rule(wan, self, "accept", ssh)
fw:rule(lan, self, "accept", dns)
fw:rule(lan, self, "accept", http)
"""

const cfgHosts = """
local ssh = fw:service("ssh", "tcp", 22)
local http = fw:service("http", "tcp", 80)
local self = fw:zone("fw")
local lan = fw:zone("lan", "eth1")
local admin = fw:host("admin", { zone = lan, addr = "172.16.0.10" })
local guest = fw:host("guest", { zone = lan, addr = "172.16.0.20" })
fw:policy(lan, self, "drop")
fw:rule(admin, self, "accept", ssh)
fw:rule(lan, self, "accept", http)
fw:rule(guest, self, "drop")
"""

const cfgPorts = """
local self = fw:zone("fw")
local wan = fw:zone("wan", "eth0")
fw:policy(wan, self, "drop")
fw:rule(wan, self, "accept", { proto = "tcp", port = { 80, 443, 8080 } })
fw:rule(wan, self, "accept", { proto = "tcp", port = "9000-9002" })
"""

const cfgWildcard = """
local ssh = fw:service("ssh", "tcp", 22)
local self = fw:zone("fw")
local wan = fw:zone("wan", "eth0")
local lan = fw:zone("lan", "eth1")
fw:policy("*", "*", "reject")
fw:rule(wan, self, "accept", ssh)
fw:rule(lan, self, "accept", ssh)
"""

const cfgBareRule = """
local self = fw:zone("fw")
local lan = fw:zone("lan", "eth1")
local guest = fw:host("guest", { zone = lan, addr = "172.16.0.20" })
fw:policy(lan, self, "accept")
fw:rule(guest, self, "drop")
"""

const cfgIpList = """
local self = fw:zone("fw")
local wan = fw:zone("wan", "eth0")
fw:iplist("blocked", { type = "ipv4", elements = { "10.0.0.50" } })
fw:policy(wan, self, "drop")
fw:rule(wan, self, "drop", { saddr_list = "blocked" })
fw:rule(wan, self, "accept", { proto = "tcp", port = 80 })
"""

const cfgMultiIface = """
local ssh = fw:service("ssh", "tcp", 22)
local self = fw:zone("fw")
local lan = fw:zone("lan", { "eth1", "eth2" })
fw:policy(lan, self, "drop")
fw:rule(lan, self, "accept", ssh)
"""

const cfgSnat = """
local self = fw:zone("fw")
local wan = fw:zone("wan", "eth0")
local lan = fw:zone("lan", "eth1")
fw:policy(wan, self, "drop")
fw:policy(lan, wan, "accept")
fw:policy("*", "*", "reject")
fw:snat({ from = "10.0.0.0/24", oif = "eth0", masquerade = true })
"""

const cfgNoSnat = """
local self = fw:zone("fw")
local wan = fw:zone("wan", "eth0")
local lan = fw:zone("lan", "eth1")
fw:policy(wan, self, "drop")
fw:policy(lan, wan, "accept")
fw:policy("*", "*", "reject")
"""

const cfgStaticSnat = """
local self = fw:zone("fw")
local wan = fw:zone("wan", "eth0")
local lan = fw:zone("lan", "eth1")
fw:policy(lan, wan, "accept")
fw:policy("*", "*", "reject")
fw:snat({ from = "10.0.0.0/24", oif = "eth0", addr = "192.168.1.100" })
"""

const cfgForwardZones = """
local self = fw:zone("fw")
local lan = fw:zone("lan", "eth1")
local dmz = fw:zone("dmz", "eth2")
fw:policy(lan, dmz, "accept")
fw:policy(dmz, lan, "drop")
fw:policy("*", "*", "reject")
fw:snat({ from = "10.0.0.0/24", oif = "eth2", masquerade = true })
"""

const cfgDnatForward = """
local http = fw:service("http", "tcp", 80)
local self = fw:zone("fw")
local wan = fw:zone("wan", "eth0")
local dmz = fw:zone("dmz", "eth2")
local webserver = fw:host("webserver", { zone = dmz, addr = "172.16.0.10" })
fw:policy(wan, self, "drop")
fw:policy(wan, dmz, "drop")
fw:policy("*", "*", "reject")
fw:dnat({ iface = wan, service = http, dest = webserver })
fw:rule(wan, webserver, "accept", http)
fw:snat({ from = "192.168.1.0/24", oif = "eth2", masquerade = true })
"""

const cfgDnatRemap = """
local self = fw:zone("fw")
local wan = fw:zone("wan", "eth0")
local dmz = fw:zone("dmz", "eth2")
local webserver = fw:host("webserver", { zone = dmz, addr = "172.16.0.10" })
fw:policy(wan, self, "drop")
fw:policy(wan, dmz, "drop")
fw:policy("*", "*", "reject")
fw:dnat({ iface = wan, proto = "tcp", port = 8080, dest = webserver, dest_port = 80 })
fw:rule(wan, webserver, "accept", { proto = "tcp", port = 80 })
fw:snat({ from = "192.168.1.0/24", oif = "eth2", masquerade = true })
"""

const cfgDnatNoRule = """
local self = fw:zone("fw")
local wan = fw:zone("wan", "eth0")
local dmz = fw:zone("dmz", "eth2")
local webserver = fw:host("webserver", { zone = dmz, addr = "172.16.0.10" })
fw:policy(wan, self, "drop")
fw:policy(wan, dmz, "drop")
fw:policy("*", "*", "reject")
fw:dnat({ iface = wan, proto = "tcp", port = 8080, dest = webserver, dest_port = 80 })
fw:snat({ from = "192.168.1.0/24", oif = "eth2", masquerade = true })
"""

# ---------------------------------------------------------------------------
# Tests: input chain
# ---------------------------------------------------------------------------

suite "probe: basic accept/drop":
  test "accepted ports connect, dropped ports time out":
    if not canProbe: skip()
    else:
      let (text, ok) = renderConfig(cfgSimple)
      check ok
      if ok:
        checkAllPass runInputProbes(text, "eth0", "10.0.0.1/24", "10.0.0.2/24",
          @[22, 80, 443, 8080],
          @[Probe(port: 22, expect: pvAccept), Probe(port: 80, expect: pvAccept),
            Probe(port: 443, expect: pvDrop), Probe(port: 8080, expect: pvDrop)])

suite "probe: drop vs reject":
  test "WAN drops, LAN rejects":
    if not canProbe: skip()
    else:
      let (text, ok) = renderConfig(cfgTwoZone)
      check ok
      if ok:
        checkAllPass runInputProbes(text, "eth0", "10.0.0.1/24", "10.0.0.2/24",
          @[22, 80, 443],
          @[Probe(port: 22, expect: pvAccept), Probe(port: 80, expect: pvDrop),
            Probe(port: 443, expect: pvDrop)],
          extraSetup = @["ip link add eth1 type dummy", "ip link set eth1 up",
                          "ip addr add 172.16.0.1/24 dev eth1"])

  test "LAN: dns+http accepted, others rejected":
    if not canProbe: skip()
    else:
      let (text, ok) = renderConfig(cfgTwoZone)
      check ok
      if ok:
        checkAllPass runInputProbes(text, "eth1", "172.16.0.1/24", "172.16.0.2/24",
          @[22, 53, 80, 443],
          @[Probe(port: 53, expect: pvAccept), Probe(port: 80, expect: pvAccept),
            Probe(port: 22, expect: pvReject), Probe(port: 443, expect: pvReject)],
          extraSetup = @["ip link add eth0 type dummy", "ip link set eth0 up",
                          "ip addr add 10.0.0.1/24 dev eth0"])

suite "probe: host-specific rules":
  test "admin gets SSH":
    if not canProbe: skip()
    else:
      let (text, ok) = renderConfig(cfgHosts)
      check ok
      if ok:
        checkAllPass runInputProbes(text, "eth1", "172.16.0.1/24", "172.16.0.10/24",
          @[22, 80, 443],
          @[Probe(port: 22, expect: pvAccept), Probe(port: 80, expect: pvAccept),
            Probe(port: 443, expect: pvDrop)])

  test "guest is blocked except HTTP":
    if not canProbe: skip()
    else:
      let (text, ok) = renderConfig(cfgHosts)
      check ok
      if ok:
        checkAllPass runInputProbes(text, "eth1", "172.16.0.1/24", "172.16.0.20/24",
          @[22, 80, 443],
          @[Probe(port: 80, expect: pvAccept), Probe(port: 22, expect: pvDrop),
            Probe(port: 443, expect: pvDrop)])

  test "random LAN host gets zone-level rules only":
    if not canProbe: skip()
    else:
      let (text, ok) = renderConfig(cfgHosts)
      check ok
      if ok:
        checkAllPass runInputProbes(text, "eth1", "172.16.0.1/24", "172.16.0.99/24",
          @[22, 80, 443],
          @[Probe(port: 80, expect: pvAccept), Probe(port: 22, expect: pvDrop),
            Probe(port: 443, expect: pvDrop)])

suite "probe: multi-port and port ranges":
  test "multi-port set and port range":
    if not canProbe: skip()
    else:
      let (text, ok) = renderConfig(cfgPorts)
      check ok
      if ok:
        checkAllPass runInputProbes(text, "eth0", "10.0.0.1/24", "10.0.0.2/24",
          @[22, 80, 443, 8080, 9000, 9001, 9002, 9003],
          @[Probe(port: 80, expect: pvAccept), Probe(port: 443, expect: pvAccept),
            Probe(port: 8080, expect: pvAccept), Probe(port: 9000, expect: pvAccept),
            Probe(port: 9001, expect: pvAccept), Probe(port: 9002, expect: pvAccept),
            Probe(port: 9003, expect: pvDrop), Probe(port: 22, expect: pvDrop)])

suite "probe: wildcard default policy":
  test "wildcard reject for unlisted zone pairs":
    if not canProbe: skip()
    else:
      let (text, ok) = renderConfig(cfgWildcard)
      check ok
      if ok:
        checkAllPass runInputProbes(text, "eth0", "10.0.0.1/24", "10.0.0.2/24",
          @[22, 80, 443],
          @[Probe(port: 22, expect: pvAccept), Probe(port: 80, expect: pvReject),
            Probe(port: 443, expect: pvReject)],
          extraSetup = @["ip link add eth1 type dummy", "ip link set eth1 up"])

suite "probe: bare rule (no service)":
  test "bare drop blocks all traffic from host":
    if not canProbe: skip()
    else:
      let (text, ok) = renderConfig(cfgBareRule)
      check ok
      if ok:
        # Guest: bare drop blocks everything
        checkAllPass runInputProbes(text, "eth1", "172.16.0.1/24", "172.16.0.20/24",
          @[22, 80], @[Probe(port: 22, expect: pvDrop), Probe(port: 80, expect: pvDrop)])
        # Non-guest: zone policy accept
        checkAllPass runInputProbes(text, "eth1", "172.16.0.1/24", "172.16.0.99/24",
          @[22, 80], @[Probe(port: 22, expect: pvAccept), Probe(port: 80, expect: pvAccept)])

suite "probe: IP list / saddr_list":
  test "blocked IP is dropped before accept rule":
    if not canProbe: skip()
    else:
      let (text, ok) = renderConfig(cfgIpList)
      check ok
      if ok:
        # Blocked source: port 80 dropped by blocklist before accept rule
        checkAllPass runInputProbes(text, "eth0", "10.0.0.1/24", "10.0.0.50/24",
          @[80], @[Probe(port: 80, expect: pvDrop)])
        # Normal source: port 80 accepted
        checkAllPass runInputProbes(text, "eth0", "10.0.0.1/24", "10.0.0.2/24",
          @[80], @[Probe(port: 80, expect: pvAccept)])

suite "probe: multiple interfaces per zone":
  test "both interfaces get same rules":
    if not canProbe: skip()
    else:
      let (text, ok) = renderConfig(cfgMultiIface)
      check ok
      if ok:
        # Via eth1
        checkAllPass runInputProbes(text, "eth1", "172.16.0.1/24", "172.16.0.2/24",
          @[22, 80], @[Probe(port: 22, expect: pvAccept), Probe(port: 80, expect: pvDrop)],
          extraSetup = @["ip link add eth2 type dummy", "ip link set eth2 up"])
        # Via eth2
        checkAllPass runInputProbes(text, "eth2", "172.16.0.1/24", "172.16.0.2/24",
          @[22, 80], @[Probe(port: 22, expect: pvAccept), Probe(port: 80, expect: pvDrop)],
          extraSetup = @["ip link add eth1 type dummy", "ip link set eth1 up"])

# ---------------------------------------------------------------------------
# Tests: forward chain / NAT
# ---------------------------------------------------------------------------

suite "probe: SNAT/masquerade":
  test "masquerade rewrites source IP":
    if not canProbe: skip()
    else:
      let (text, ok) = renderConfig(cfgSnat)
      check ok
      if ok:
        checkAllPass runForwardProbes(text,
          "eth1", "10.0.0.1/24", "10.0.0.2/24",
          "eth0", "192.168.1.1/24", "192.168.1.2/24", 8888,
          @[ForwardProbe(destIp: "192.168.1.2", destPort: 8888, expectSrcIp: "192.168.1.1")])

  test "without masquerade, original source IP preserved":
    if not canProbe: skip()
    else:
      let (text, ok) = renderConfig(cfgNoSnat)
      check ok
      if ok:
        checkAllPass runForwardProbes(text,
          "eth1", "10.0.0.1/24", "10.0.0.2/24",
          "eth0", "192.168.1.1/24", "192.168.1.2/24", 8888,
          @[ForwardProbe(destIp: "192.168.1.2", destPort: 8888, expectSrcIp: "10.0.0.2")])

suite "probe: static SNAT":
  test "static SNAT rewrites to specified address":
    if not canProbe: skip()
    else:
      let (text, ok) = renderConfig(cfgStaticSnat)
      check ok
      if ok:
        checkAllPass runForwardProbes(text,
          "eth1", "10.0.0.1/24", "10.0.0.2/24",
          "eth0", "192.168.1.1/24", "192.168.1.2/24", 8888,
          @[ForwardProbe(destIp: "192.168.1.2", destPort: 8888, expectSrcIp: "192.168.1.100")],
          extraSetup = @["ip addr add 192.168.1.100/24 dev eth0"])

suite "probe: forward between non-fw zones":
  test "LAN to DMZ forwarding":
    if not canProbe: skip()
    else:
      let (text, ok) = renderConfig(cfgForwardZones)
      check ok
      if ok:
        checkAllPass runForwardProbes(text,
          "eth1", "10.0.0.1/24", "10.0.0.2/24",
          "eth2", "172.16.0.1/24", "172.16.0.10/24", 8888,
          @[ForwardProbe(destIp: "172.16.0.10", destPort: 8888, expectSrcIp: "172.16.0.1")])

suite "probe: DNAT forwarding":
  test "DNAT + masquerade forwards to internal server":
    if not canProbe: skip()
    else:
      let (text, ok) = renderConfig(cfgDnatForward)
      check ok
      if ok:
        checkAllPass runForwardProbes(text,
          "eth0", "192.168.1.1/24", "192.168.1.2/24",
          "eth2", "172.16.0.1/24", "172.16.0.10/24", 80,
          @[ForwardProbe(destIp: "192.168.1.1", destPort: 80, expectSrcIp: "172.16.0.1")])

  test "DNAT with port remap (8080 -> 80)":
    if not canProbe: skip()
    else:
      let (text, ok) = renderConfig(cfgDnatRemap)
      check ok
      if ok:
        checkAllPass runForwardProbes(text,
          "eth0", "192.168.1.1/24", "192.168.1.2/24",
          "eth2", "172.16.0.1/24", "172.16.0.10/24", 80,
          @[ForwardProbe(destIp: "192.168.1.1", destPort: 8080, expectSrcIp: "172.16.0.1")])

  test "DNAT without forward rule is blocked":
    if not canProbe: skip()
    else:
      let (text, ok) = renderConfig(cfgDnatNoRule)
      check ok
      if ok:
        checkAllPass runForwardProbes(text,
          "eth0", "192.168.1.1/24", "192.168.1.2/24",
          "eth2", "172.16.0.1/24", "172.16.0.10/24", 80,
          @[ForwardProbe(destIp: "192.168.1.1", destPort: 8080, expectBlocked: true)])
