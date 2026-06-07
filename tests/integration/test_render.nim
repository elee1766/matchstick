## Integration tests: run the matchstick binary and check outputs.
## Requires the binary to be built first (nimble build).

import unittest
import std/[os, osproc, strutils]

const projectRoot = currentSourcePath().parentDir().parentDir().parentDir()
const matchstickBin = projectRoot / "matchstick"
const testConfig = projectRoot / "tests" / "testdata" / "full.lua"
const testdataDir = projectRoot / "tests" / "testdata"

proc runMatchstick(args: varargs[string]): tuple[output: string, exitCode: int] =
  ## Run matchstick, capturing stdout only (stderr goes to /dev/null).
  var cmd = matchstickBin
  for a in args:
    cmd &= " " & quoteShell(a)
  cmd &= " 2>/dev/null"
  let (output, exitCode) = execCmdEx(cmd)
  (output, exitCode)

proc runMatchstickFull(args: varargs[string]): tuple[output: string, exitCode: int] =
  ## Run matchstick, capturing both stdout and stderr.
  var cmd = matchstickBin
  for a in args:
    cmd &= " " & quoteShell(a)
  cmd &= " 2>&1"
  let (output, exitCode) = execCmdEx(cmd)
  (output, exitCode)

suite "Golden file: text output":
  test "full.lua renders to expected nftables text":
    let (output, exitCode) = runMatchstick("render", testConfig)
    check exitCode == 0
    let expected = readFile(testdataDir / "full.expected.nft")
    if output != expected:
      let outLines = output.splitLines()
      let expLines = expected.splitLines()
      for i in 0 ..< min(outLines.len, expLines.len):
        if outLines[i] != expLines[i]:
          echo "First diff at line ", i + 1, ":"
          echo "  expected: ", expLines[i]
          echo "  got:      ", outLines[i]
          break
      if outLines.len != expLines.len:
        echo "Line count: expected=", expLines.len, " got=", outLines.len
    check output == expected

suite "Small configs render successfully":
  for name in ["config", "multi_iface", "include_main", "docker", "named_rate", "minimal",
                "hooks", "custom_chain", "raw_nft", "exceptions", "tier2_features"]:
    test name & ".lua renders":
      let cfg = testdataDir / (name & ".lua")
      let (output, exitCode) = runMatchstick("render", cfg)
      check exitCode == 0
      check output.len > 0

    test name & ".lua JSON renders":
      let cfg = testdataDir / (name & ".lua")
      let (output, exitCode) = runMatchstick("render", "--json", cfg)
      check exitCode == 0
      check output.strip().startsWith("{")

suite "Config customization":
  test "custom table name in output":
    let (output, exitCode) = runMatchstick("render", testdataDir / "config.lua")
    check exitCode == 0
    check "table inet custom_table" in output
    check "priority filter + 10" in output

  test "custom log prefix in output":
    let (output, exitCode) = runMatchstick("render", testdataDir / "config.lua")
    check exitCode == 0
    check "CUSTOM" in output

  test "include resolves correctly":
    let (output, exitCode) = runMatchstick("render", testdataDir / "include_main.lua")
    check exitCode == 0
    check "tcp dport 22" in output  # ssh service from included file

  test "multi-interface zone creates multiple vmap entries":
    let (output, exitCode) = runMatchstick("render", testdataDir / "multi_iface.lua")
    check exitCode == 0
    check "eth1" in output
    check "eth2" in output

  test "minimal config produces valid output":
    let (output, exitCode) = runMatchstick("render", testdataDir / "minimal.lua")
    check exitCode == 0
    check "table inet matchstick" in output

suite "Golden file: JSON output":
  test "full.lua JSON is valid and parseable":
    let (output, exitCode) = runMatchstick("render", "--json", testConfig)
    check exitCode == 0
    check output.strip().startsWith("{")
    check "\"nftables\"" in output
    check "\"match\"" in output
    check "\"accept\"" in output

suite "Check command":
  test "full.lua passes check":
    let (output, exitCode) = runMatchstickFull("check", testConfig)
    check exitCode == 0
    check "ok:" in output

  test "reports shadow warnings":
    let (output, exitCode) = runMatchstickFull("check", testConfig)
    check exitCode == 0
    check "warning:" in output  # should have shadow warnings

  test "nonexistent file fails":
    let (output, exitCode) = runMatchstickFull("check", "/tmp/nonexistent.lua")
    check exitCode == 1

suite "Show commands":
  test "show matrix":
    let (output, exitCode) = runMatchstick("show", "matrix", testConfig)
    check exitCode == 0
    check "ACPT" in output
    check "DROP" in output
    check "REJ" in output

  test "show rules wan->fw":
    let (output, exitCode) = runMatchstick("show", "rules", testConfig, "wan", "fw")
    check exitCode == 0
    check "wan -> fw" in output
    check "drop" in output
    check "blocklist4" in output

  test "show rules admin->fw (host)":
    let (output, exitCode) = runMatchstick("show", "rules", testConfig, "admin", "fw")
    check exitCode == 0
    check "from:admin" in output or "admin" in output

  test "show topology ascii":
    let (output, exitCode) = runMatchstick("show", "topology", testConfig)
    check exitCode == 0
    check "[fw]" in output
    check "[wan]" in output
    check "[lan]" in output
    check "[dmz]" in output
    check "[dock]" in output

  test "show topology dot":
    let (output, exitCode) = runMatchstick("show", "topology", testConfig, "--format=dot")
    check exitCode == 0
    check "digraph" in output

  test "show topology mermaid":
    let (output, exitCode) = runMatchstick("show", "topology", testConfig, "--format=mermaid")
    check exitCode == 0
    check "graph LR" in output

  test "show topology d2":
    let (output, exitCode) = runMatchstick("show", "topology", testConfig, "--format=d2")
    check exitCode == 0
    check "style.fill" in output

  test "show json":
    let (output, exitCode) = runMatchstick("show", "json", testConfig)
    check exitCode == 0
    check "\"zones\"" in output
    check "\"rules\"" in output
    check "\"hosts\"" in output
    check "\"services\"" in output

suite "Custom chains (fw:chain)":
  test "custom chain appears in output":
    let (output, exitCode) = runMatchstick("render", testdataDir / "custom_chain.lua")
    check exitCode == 0
    check "custom_filter_prerouting_0" in output

  test "custom chain has correct hook and priority":
    let (output, exitCode) = runMatchstick("render", testdataDir / "custom_chain.lua")
    check exitCode == 0
    check "hook prerouting" in output
    # mangle priority = -150, offset = 5, so -145
    check "filter - 145" in output

  test "custom chain contains rules from JSON":
    let (output, exitCode) = runMatchstick("render", testdataDir / "custom_chain.lua")
    check exitCode == 0
    check "iifname" in output
    check "mark set" in output
    check "tcp dport" in output

  test "custom chain JSON output is valid":
    let (output, exitCode) = runMatchstick("render", "--json", testdataDir / "custom_chain.lua")
    check exitCode == 0
    check output.strip().startsWith("{")

suite "Raw nftables escape hatch (fw:raw_nft)":
  test "raw nft JSON commands appear in text output":
    let (output, exitCode) = runMatchstick("render", testdataDir / "raw_nft.lua")
    check exitCode == 0
    check "chain my_custom_chain" in output
    check "accept" in output

  test "raw nft JSON commands pass through to JSON output":
    let (output, exitCode) = runMatchstick("render", "--json", testdataDir / "raw_nft.lua")
    check exitCode == 0
    check "my_custom_chain" in output
    check "12345" in output

suite "Chain exceptions (fw:exception)":
  test "invalid chain created with exceptions":
    let (output, exitCode) = runMatchstick("render", testdataDir / "exceptions.lua")
    check exitCode == 0
    check "chain invalid {" in output
    check "tcp dport 443 accept" in output
    check "udp dport 443 accept" in output
    check "udp dport 8080 accept" in output

  test "input chain jumps to invalid instead of inline drop":
    let (output, exitCode) = runMatchstick("render", testdataDir / "exceptions.lua")
    check exitCode == 0
    check "ct state invalid jump invalid" in output

  test "anti_smurf has exceptions before drops":
    let (output, exitCode) = runMatchstick("render", testdataDir / "exceptions.lua")
    check exitCode == 0
    # The exception should appear before the fib drops
    let antiSmurfStart = output.find("chain anti_smurf {")
    check antiSmurfStart >= 0
    let dhcpExc = output.find("udp dport { 67, 68 } accept", antiSmurfStart)
    let fibDrop = output.find("fib saddr type broadcast drop", antiSmurfStart)
    check dhcpExc >= 0
    check fibDrop >= 0
    check dhcpExc < fibDrop  # exception comes before drop

suite "Tier 2 features":
  test "MSS clamping chain":
    let (output, exitCode) = runMatchstick("render", testdataDir / "tier2_features.lua")
    check exitCode == 0
    check "mss_clamp_forward" in output
    check "tcp flags syn" in output
    check "maxseg size set rt mtu" in output

  test "connection limiting":
    let (output, exitCode) = runMatchstick("render", testdataDir / "tier2_features.lua")
    check exitCode == 0
    check "ct count 10" in output

  test "MAC address matching":
    let (output, exitCode) = runMatchstick("render", testdataDir / "tier2_features.lua")
    check exitCode == 0
    check "ether saddr aa:bb:cc:dd:ee:ff" in output

  test "redirect (local port redirect)":
    let (output, exitCode) = runMatchstick("render", testdataDir / "tier2_features.lua")
    check exitCode == 0
    check "redirect to :3128" in output
    check "matchstick_nat" in output

  test "daddr_list (destination IP list matching)":
    let (output, exitCode) = runMatchstick("render", testdataDir / "tier2_features.lua")
    check exitCode == 0
    check "@allowed_countries" in output
    check "ip daddr" in output

  test "iplist with URL field accepted":
    let (output, exitCode) = runMatchstick("check", testdataDir / "tier2_features.lua")
    check exitCode == 0

suite "Sysctl derivation":
  test "host firewall has no ip_forward":
    let (output, exitCode) = runMatchstick("show", "sysctl", testdataDir / "minimal.lua")
    check exitCode == 0
    check "ip_forward" notin output  # minimal config has no forwarding
    check "arp_announce" in output   # hardening always present

  test "router config derives ip_forward":
    let (output, exitCode) = runMatchstick("show", "sysctl", testdataDir / "full.lua")
    check exitCode == 0
    check "net.ipv4.conf.all.forwarding = 1" in output
    check "net.ipv6.conf.all.forwarding = 1" in output

  test "sysctl count shown in check":
    let (output, exitCode) = runMatchstickFull("check", testdataDir / "full.lua")
    check exitCode == 0
    check "sysctls:" in output

suite "Sysctl unset":
  test "fw:sysctl(key, false) removes derived entry":
    # Write a config that would normally derive ip_forward, then unset it
    let tmpFile = getTempDir() / "matchstick_sysctl_unset.lua"
    writeFile(tmpFile, """
      local self = fw:zone("fw")
      local wan = fw:zone("wan", "eth0")
      local lan = fw:zone("lan", "eth1")
      fw:policy(lan, wan, "accept")
      -- This config has forwarding, so ip_forward would be derived
      -- But we explicitly unset it
      fw:sysctl("net.ipv4.conf.all.forwarding", false)
      fw:sysctl("net.ipv6.conf.all.forwarding", false)
    """)
    let (output, exitCode) = runMatchstick("show", "sysctl", tmpFile)
    removeFile(tmpFile)
    check exitCode == 0
    check "forwarding" notin output  # should be removed
    check "arp_announce" in output   # other defaults still present
