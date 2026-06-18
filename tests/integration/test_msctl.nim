## Integration tests for msctl — the matchstick firewall control script.
##
## Tests that msctl enable/disable/status/check/diff/show work correctly
## inside user+net namespaces, and that rules applied via msctl's JSON
## pipeline actually filter traffic.

import unittest
import std/[json, os, osproc, strutils]

const projectRoot = currentSourcePath().parentDir().parentDir().parentDir()
const matchstickBin = projectRoot / "matchstick"
const msctlBin = projectRoot / "msctl"
const probeHelper = projectRoot / "tests" / "integration" / "probe_helper.py"
const testdataDir = projectRoot / "tests" / "testdata"

const setupIfaces = """
ip link add eth0 type dummy 2>/dev/null;
ip link add eth1 type dummy 2>/dev/null;
ip link add eth2 type dummy 2>/dev/null;
ip link add docker0 type dummy 2>/dev/null;
"""

proc msctlCmd(config: string, cmd: string, extraEnv = ""): tuple[output: string, exitCode: int] =
  ## Run msctl inside a user+net namespace with dummy interfaces.
  let tmpConfig = getTempDir() / "matchstick_msctl_test.lua"
  writeFile(tmpConfig, config)
  defer: removeFile(tmpConfig)
  let env = "MATCHSTICK=" & quoteShell(matchstickBin) &
            " MATCHSTICK_CONFIG=" & quoteShell(tmpConfig) &
            " " & extraEnv
  let fullCmd = "unshare --user --net --map-root-user -- sh -c " &
    quoteShell(setupIfaces & env & " " & quoteShell(msctlBin) & " " & cmd & " 2>&1")
  result = execCmdEx(fullCmd)

proc msctlSequence(config: string, cmds: seq[string]): tuple[output: string, exitCode: int] =
  ## Run a sequence of msctl commands in a single namespace.
  let tmpConfig = getTempDir() / "matchstick_msctl_test.lua"
  writeFile(tmpConfig, config)
  defer: removeFile(tmpConfig)
  let env = "MATCHSTICK=" & quoteShell(matchstickBin) &
            " MATCHSTICK_CONFIG=" & quoteShell(tmpConfig)
  var script = setupIfaces
  for cmd in cmds:
    script &= env & " " & quoteShell(msctlBin) & " " & cmd & " 2>&1\necho '---SEPARATOR---'\n"
  let fullCmd = "unshare --user --net --map-root-user -- sh -c " & quoteShell(script)
  result = execCmdEx(fullCmd)

proc runInNamespace(script: string): tuple[output: string, exitCode: int] =
  ## Run an arbitrary shell script in a user+net namespace with dummy interfaces.
  let fullCmd = "unshare --user --net --map-root-user -- sh -c " &
    quoteShell(setupIfaces & script)
  result = execCmdEx(fullCmd)

# Check prerequisites
let (_, nftEc) = execCmdEx("which nft 2>/dev/null")
let (_, unsEc) = execCmdEx("unshare --user --net --map-root-user -- true 2>/dev/null")
let (_, pyEc) = execCmdEx("which python3 2>/dev/null")
let canRun = nftEc == 0 and unsEc == 0
let canProbe = canRun and pyEc == 0

const cfgSimple = """
local ssh = fw:service("ssh", "tcp", 22)
local self = fw:zone("fw")
local wan = fw:zone("wan", "eth0")
fw:policy(wan, self, "drop")
fw:rule(wan, self, "accept", ssh)
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

const cfgInvalid = """
local self = fw:zone("fw")
local self2 = fw:zone("fw")
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

# SSH + HTTP (for re-apply config change tests)
const cfgSshHttp = """
local ssh = fw:service("ssh", "tcp", 22)
local http = fw:service("http", "tcp", 80)
local self = fw:zone("fw")
local wan = fw:zone("wan", "eth0")
fw:policy(wan, self, "drop")
fw:rule(wan, self, "accept", ssh)
fw:rule(wan, self, "accept", http)
"""

# HTTP only (for verifying old rules are replaced, not accumulated)
const cfgHttpOnly = """
local http = fw:service("http", "tcp", 80)
local self = fw:zone("fw")
local wan = fw:zone("wan", "eth0")
fw:policy(wan, self, "drop")
fw:rule(wan, self, "accept", http)
"""

# ---------------------------------------------------------------------------
# Tests: msctl check
# ---------------------------------------------------------------------------

suite "msctl check":
  test "valid config passes":
    if not canRun: skip()
    else:
      let (output, ec) = msctlCmd(cfgSimple, "check")
      check ec == 0
      check "ok:" in output

  test "invalid config fails":
    if not canRun: skip()
    else:
      let (output, ec) = msctlCmd(cfgInvalid, "check")
      check ec != 0

# ---------------------------------------------------------------------------
# Tests: msctl enable / disable / status
# ---------------------------------------------------------------------------

suite "msctl enable":
  test "applies rules successfully":
    if not canRun: skip()
    else:
      let (output, ec) = msctlCmd(cfgSimple, "enable")
      check ec == 0
      check "ok: rules applied" in output

  test "enable then status shows rules":
    if not canRun: skip()
    else:
      let (output, ec) = msctlSequence(cfgSimple, @["enable", "status"])
      check ec == 0
      check "matchstick" in output
      check "wan_to_fw" in output
      check "tcp dport 22 accept" in output

  test "enable then disable removes rules":
    if not canRun: skip()
    else:
      let (output, ec) = msctlSequence(cfgSimple, @["enable", "disable", "status"])
      check ec == 0
      check "not active" in output

  test "enable with NAT creates both tables":
    if not canRun: skip()
    else:
      let (output, ec) = msctlSequence(cfgSnat, @["enable", "status"])
      check ec == 0
      check "matchstick" in output
      check "masquerade" in output

  test "invalid config rejected by enable":
    if not canRun: skip()
    else:
      let (output, ec) = msctlCmd(cfgInvalid, "enable")
      check ec != 0

suite "msctl disable":
  test "disable without enable is harmless":
    if not canRun: skip()
    else:
      let (output, ec) = msctlCmd(cfgSimple, "disable")
      check ec == 0
      check "not found" in output

suite "msctl status":
  test "status without enable shows not active":
    if not canRun: skip()
    else:
      let (output, ec) = msctlCmd(cfgSimple, "status")
      check ec == 0
      check "not active" in output

# ---------------------------------------------------------------------------
# Tests: msctl show
# ---------------------------------------------------------------------------

suite "msctl show":
  test "show matrix":
    if not canRun: skip()
    else:
      let (output, ec) = msctlCmd(cfgTwoZone, "show matrix")
      check ec == 0
      check "DROP" in output or "ACCEPT" in output

  test "show render":
    if not canRun: skip()
    else:
      let (output, ec) = msctlCmd(cfgSimple, "show render")
      check ec == 0
      check "table inet matchstick" in output

  test "show sysctl":
    if not canRun: skip()
    else:
      let (output, ec) = msctlCmd(cfgTwoZone, "show sysctl")
      check ec == 0
      check "net.ipv4" in output

  test "show json":
    if not canRun: skip()
    else:
      let (output, ec) = msctlCmd(cfgSimple, "show json")
      check ec == 0
      check "\"zones\"" in output

# ---------------------------------------------------------------------------
# Tests: msctl enable + network probes (rules actually work)
# ---------------------------------------------------------------------------

suite "msctl probe: enable applies working rules":
  test "msctl enable then probe input chain":
    if not canProbe: skip()
    else:
      # Write config to a temp file the msctl apply_cmd can use
      let tmpConfig = getTempDir() / "matchstick_msctl_probe.lua"
      writeFile(tmpConfig, cfgSimple)
      defer: removeFile(tmpConfig)

      let applyCmd = "MATCHSTICK=" & quoteShell(matchstickBin) &
                     " MATCHSTICK_CONFIG=" & quoteShell(tmpConfig) &
                     " " & quoteShell(msctlBin) & " enable"

      # We pass an empty ruleset since msctl does its own render+apply.
      # The apply_cmd overrides the default nft -f path.
      let specFile = getTempDir() / "matchstick_msctl_probe_spec.json"
      let rulesetFile = getTempDir() / "matchstick_msctl_probe.nft"
      writeFile(rulesetFile, "")  # unused, msctl renders its own

      var probeArr = newJArray()
      probeArr.add(%*{"proto": "tcp", "port": 22, "expect": "accept"})
      probeArr.add(%*{"proto": "tcp", "port": 80, "expect": "drop"})
      probeArr.add(%*{"proto": "tcp", "port": 443, "expect": "drop"})

      let spec = %*{
        "host_addr": "10.0.0.1/24",
        "client_addr": "10.0.0.2/24",
        "veth_host": "eth0",
        "listen_ports": [22, 80, 443],
        "probes": probeArr,
        "apply_cmd": applyCmd,
      }
      writeFile(specFile, $spec)
      defer:
        removeFile(specFile)
        removeFile(rulesetFile)

      let cmd = "unshare --user --net --map-root-user -- python3 " &
        quoteShell(probeHelper) & " " &
        quoteShell(rulesetFile) & " " &
        quoteShell(specFile) & " 2>/dev/null"
      let (output, exitCode) = execCmdEx(cmd)
      check exitCode == 0
      if output.strip().len > 0:
        let j = parseJson(output.strip())
        check j["ok"].getBool()
        if j.hasKey("results"):
          for r in j["results"]:
            if not r["pass"].getBool():
              echo "  FAIL port ", r["port"], ": expected ", r["expect"], " got ", r["got"]
            check r["pass"].getBool()

  test "msctl enable with two zones then probe both sides":
    if not canProbe: skip()
    else:
      let tmpConfig = getTempDir() / "matchstick_msctl_probe2.lua"
      writeFile(tmpConfig, cfgTwoZone)
      defer: removeFile(tmpConfig)

      let applyCmd = "MATCHSTICK=" & quoteShell(matchstickBin) &
                     " MATCHSTICK_CONFIG=" & quoteShell(tmpConfig) &
                     " " & quoteShell(msctlBin) & " enable"

      # WAN side: SSH accepted, others dropped
      let specFile = getTempDir() / "matchstick_msctl_probe2_spec.json"
      let rulesetFile = getTempDir() / "matchstick_msctl_probe2.nft"
      writeFile(rulesetFile, "")

      var probeArr = newJArray()
      probeArr.add(%*{"proto": "tcp", "port": 22, "expect": "accept"})
      probeArr.add(%*{"proto": "tcp", "port": 80, "expect": "drop"})

      let spec = %*{
        "host_addr": "10.0.0.1/24",
        "client_addr": "10.0.0.2/24",
        "veth_host": "eth0",
        "listen_ports": [22, 80],
        "probes": probeArr,
        "apply_cmd": applyCmd,
        "extra_setup": ["ip link add eth1 type dummy", "ip link set eth1 up",
                         "ip addr add 172.16.0.1/24 dev eth1"],
      }
      writeFile(specFile, $spec)
      defer:
        removeFile(specFile)
        removeFile(rulesetFile)

      let cmd = "unshare --user --net --map-root-user -- python3 " &
        quoteShell(probeHelper) & " " &
        quoteShell(rulesetFile) & " " &
        quoteShell(specFile) & " 2>/dev/null"
      let (output, exitCode) = execCmdEx(cmd)
      check exitCode == 0
      if output.strip().len > 0:
        let j = parseJson(output.strip())
        check j["ok"].getBool()
        if j.hasKey("results"):
          for r in j["results"]:
            if not r["pass"].getBool():
              echo "  FAIL port ", r["port"], ": expected ", r["expect"], " got ", r["got"]
            check r["pass"].getBool()

# ---------------------------------------------------------------------------
# Tests: re-apply, config changes, disable/re-enable
# ---------------------------------------------------------------------------

suite "msctl re-apply":
  test "re-apply same config does not duplicate rules":
    if not canRun: skip()
    else:
      let tmpConfig = getTempDir() / "matchstick_msctl_reapply.lua"
      writeFile(tmpConfig, cfgSimple)
      defer: removeFile(tmpConfig)
      let env = "MATCHSTICK=" & quoteShell(matchstickBin) &
                " MATCHSTICK_CONFIG=" & quoteShell(tmpConfig)
      let (output, ec) = runInNamespace(
        env & " " & quoteShell(msctlBin) & " enable >/dev/null 2>&1\n" &
        env & " " & quoteShell(msctlBin) & " enable >/dev/null 2>&1\n" &
        "nft list table inet matchstick 2>&1\n")
      check ec == 0
      check output.count("chain wan_to_fw") == 1
      check output.count("tcp dport 22 accept") == 1

  test "config change replaces old rules":
    if not canRun: skip()
    else:
      let tmpConfig = getTempDir() / "matchstick_msctl_change.lua"
      writeFile(tmpConfig, cfgSimple)
      defer: removeFile(tmpConfig)
      let env = "MATCHSTICK=" & quoteShell(matchstickBin) &
                " MATCHSTICK_CONFIG=" & quoteShell(tmpConfig)
      let (output, ec) = runInNamespace(
        env & " " & quoteShell(msctlBin) & " enable >/dev/null 2>&1\n" &
        "cat > " & quoteShell(tmpConfig) & " << 'LUAEOF'\n" & cfgSshHttp & "LUAEOF\n" &
        env & " " & quoteShell(msctlBin) & " enable >/dev/null 2>&1\n" &
        "nft list table inet matchstick 2>&1\n")
      check ec == 0
      check "tcp dport 22 accept" in output
      check "tcp dport 80 accept" in output
      check output.count("chain wan_to_fw") == 1

  test "config change removes old rules no longer present":
    if not canRun: skip()
    else:
      let tmpConfig = getTempDir() / "matchstick_msctl_remove.lua"
      writeFile(tmpConfig, cfgSshHttp)
      defer: removeFile(tmpConfig)
      let env = "MATCHSTICK=" & quoteShell(matchstickBin) &
                " MATCHSTICK_CONFIG=" & quoteShell(tmpConfig)
      let (output, ec) = runInNamespace(
        env & " " & quoteShell(msctlBin) & " enable >/dev/null 2>&1\n" &
        "cat > " & quoteShell(tmpConfig) & " << 'LUAEOF'\n" & cfgHttpOnly & "LUAEOF\n" &
        env & " " & quoteShell(msctlBin) & " enable >/dev/null 2>&1\n" &
        "nft list table inet matchstick 2>&1\n")
      check ec == 0
      check "tcp dport 80 accept" in output
      check "tcp dport 22 accept" notin output

suite "msctl disable and re-enable":
  test "disable removes all tables cleanly":
    if not canRun: skip()
    else:
      let tmpConfig = getTempDir() / "matchstick_msctl_disclean.lua"
      writeFile(tmpConfig, cfgSnat)
      defer: removeFile(tmpConfig)
      let env = "MATCHSTICK=" & quoteShell(matchstickBin) &
                " MATCHSTICK_CONFIG=" & quoteShell(tmpConfig)
      let (output, ec) = runInNamespace(
        env & " " & quoteShell(msctlBin) & " enable >/dev/null 2>&1\n" &
        env & " " & quoteShell(msctlBin) & " disable >/dev/null 2>&1\n" &
        "nft list ruleset 2>&1\n")
      check ec == 0
      check "matchstick" notin output

  test "re-enable after disable restores rules":
    if not canRun: skip()
    else:
      let tmpConfig = getTempDir() / "matchstick_msctl_reen.lua"
      writeFile(tmpConfig, cfgSimple)
      defer: removeFile(tmpConfig)
      let env = "MATCHSTICK=" & quoteShell(matchstickBin) &
                " MATCHSTICK_CONFIG=" & quoteShell(tmpConfig)
      let (output, ec) = runInNamespace(
        env & " " & quoteShell(msctlBin) & " enable >/dev/null 2>&1\n" &
        env & " " & quoteShell(msctlBin) & " disable >/dev/null 2>&1\n" &
        env & " " & quoteShell(msctlBin) & " enable >/dev/null 2>&1\n" &
        "nft list table inet matchstick 2>&1\n")
      check ec == 0
      check "chain wan_to_fw" in output
      check "tcp dport 22 accept" in output

suite "msctl probe: re-apply config change":
  test "new port becomes reachable after re-apply":
    if not canProbe: skip()
    else:
      let tmpConfig = getTempDir() / "matchstick_msctl_reprobe.lua"
      let tmpScript = getTempDir() / "matchstick_msctl_reprobe.sh"
      let tmpConfig2 = getTempDir() / "matchstick_msctl_reprobe2.lua"
      writeFile(tmpConfig, cfgSimple)
      writeFile(tmpConfig2, cfgSshHttp)
      # Script: apply first config, overwrite with second, re-apply
      writeFile(tmpScript, "#!/bin/sh\n" &
        "MATCHSTICK=" & quoteShell(matchstickBin) &
        " MATCHSTICK_CONFIG=" & quoteShell(tmpConfig) &
        " " & quoteShell(msctlBin) & " enable >/dev/null 2>&1 && " &
        "cp " & quoteShell(tmpConfig2) & " " & quoteShell(tmpConfig) & " && " &
        "MATCHSTICK=" & quoteShell(matchstickBin) &
        " MATCHSTICK_CONFIG=" & quoteShell(tmpConfig) &
        " " & quoteShell(msctlBin) & " enable >/dev/null 2>&1\n")
      defer: removeFile(tmpConfig); removeFile(tmpConfig2); removeFile(tmpScript)
      let specFile = getTempDir() / "matchstick_msctl_reprobe_spec.json"
      let rulesetFile = getTempDir() / "matchstick_msctl_reprobe.nft"
      writeFile(rulesetFile, "")
      var probeArr = newJArray()
      probeArr.add(%*{"proto": "tcp", "port": 22, "expect": "accept"})
      probeArr.add(%*{"proto": "tcp", "port": 80, "expect": "accept"})
      writeFile(specFile, $(%*{
        "host_addr": "10.0.0.1/24", "client_addr": "10.0.0.2/24",
        "veth_host": "eth0", "listen_ports": [22, 80],
        "probes": probeArr, "apply_cmd": "sh " & tmpScript}))
      defer: removeFile(specFile); removeFile(rulesetFile)
      let (output, exitCode) = execCmdEx(
        "unshare --user --net --map-root-user -- python3 " &
        quoteShell(probeHelper) & " " & quoteShell(rulesetFile) & " " &
        quoteShell(specFile) & " 2>/dev/null")
      check exitCode == 0
      if output.strip().len > 0:
        let j = parseJson(output.strip())
        check j["ok"].getBool()
        for r in j["results"]:
          if not r["pass"].getBool():
            echo "  FAIL port ", r["port"], ": expected ", r["expect"], " got ", r["got"]
          check r["pass"].getBool()

  test "removed port becomes unreachable after re-apply":
    if not canProbe: skip()
    else:
      let tmpConfig = getTempDir() / "matchstick_msctl_reprobe_rm.lua"
      let tmpScript = getTempDir() / "matchstick_msctl_reprobe_rm.sh"
      let tmpConfig2 = getTempDir() / "matchstick_msctl_reprobe_rm2.lua"
      writeFile(tmpConfig, cfgSshHttp)
      writeFile(tmpConfig2, cfgHttpOnly)
      # Script: apply SSH+HTTP, overwrite with HTTP-only, re-apply
      writeFile(tmpScript, "#!/bin/sh\n" &
        "MATCHSTICK=" & quoteShell(matchstickBin) &
        " MATCHSTICK_CONFIG=" & quoteShell(tmpConfig) &
        " " & quoteShell(msctlBin) & " enable >/dev/null 2>&1 && " &
        "cp " & quoteShell(tmpConfig2) & " " & quoteShell(tmpConfig) & " && " &
        "MATCHSTICK=" & quoteShell(matchstickBin) &
        " MATCHSTICK_CONFIG=" & quoteShell(tmpConfig) &
        " " & quoteShell(msctlBin) & " enable >/dev/null 2>&1\n")
      defer: removeFile(tmpConfig); removeFile(tmpConfig2); removeFile(tmpScript)
      let specFile = getTempDir() / "matchstick_msctl_reprobe_rm_spec.json"
      let rulesetFile = getTempDir() / "matchstick_msctl_reprobe_rm.nft"
      writeFile(rulesetFile, "")
      var probeArr = newJArray()
      probeArr.add(%*{"proto": "tcp", "port": 80, "expect": "accept"})
      probeArr.add(%*{"proto": "tcp", "port": 22, "expect": "drop"})
      writeFile(specFile, $(%*{
        "host_addr": "10.0.0.1/24", "client_addr": "10.0.0.2/24",
        "veth_host": "eth0", "listen_ports": [22, 80],
        "probes": probeArr, "apply_cmd": "sh " & tmpScript}))
      defer: removeFile(specFile); removeFile(rulesetFile)
      let (output, exitCode) = execCmdEx(
        "unshare --user --net --map-root-user -- python3 " &
        quoteShell(probeHelper) & " " & quoteShell(rulesetFile) & " " &
        quoteShell(specFile) & " 2>/dev/null")
      check exitCode == 0
      if output.strip().len > 0:
        let j = parseJson(output.strip())
        check j["ok"].getBool()
        for r in j["results"]:
          if not r["pass"].getBool():
            echo "  FAIL port ", r["port"], ": expected ", r["expect"], " got ", r["got"]
          check r["pass"].getBool()
