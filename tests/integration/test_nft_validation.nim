## Test that all generated nftables output is accepted by the nft binary.
## Runs in a user namespace (no root needed) via unshare.
## Tests both text and JSON format for each config.

import unittest
import std/[os, osproc, strutils]

const projectRoot = currentSourcePath().parentDir().parentDir().parentDir()
const matchstickBin = projectRoot / "matchstick"
const testdataDir = projectRoot / "tests" / "testdata"

const setupIfaces = """
ip link add eth0 type dummy 2>/dev/null;
ip link add eth1 type dummy 2>/dev/null;
ip link add eth2 type dummy 2>/dev/null;
ip link add docker0 type dummy 2>/dev/null;
"""

proc nftCheck(ruleset: string, json = false): tuple[ok: bool, error: string] =
  ## Validate a ruleset via nft -c -f <tmpfile> inside a user namespace with dummy interfaces.
  let tmpFile = getTempDir() / "matchstick_nft_check.nft"
  writeFile(tmpFile, ruleset)
  defer: removeFile(tmpFile)
  let flag = if json: "-j" else: ""
  let cmd = "unshare --user --net --map-root-user -- sh -c " &
    quoteShell(setupIfaces & "nft " & flag & " -c -f " & quoteShell(tmpFile) & " 2>&1")
  let (output, exitCode) = execCmdEx(cmd)
  result.ok = (exitCode == 0)
  result.error = output.strip()

proc nftApplyAndList(ruleset: string): tuple[ok: bool, listed: string, error: string] =
  ## Apply a ruleset and list it back, inside a user namespace with dummy interfaces.
  let tmpFile = getTempDir() / "matchstick_nft_apply.nft"
  writeFile(tmpFile, ruleset)
  defer: removeFile(tmpFile)
  let cmd = "unshare --user --net --map-root-user -- sh -c " &
    quoteShell(setupIfaces & "nft -f " & quoteShell(tmpFile) & " 2>&1 && nft list ruleset 2>&1")
  let (output, exitCode) = execCmdEx(cmd)
  result.ok = (exitCode == 0)
  if exitCode == 0:
    result.listed = output.strip()
  else:
    result.error = output.strip()

proc renderConfig(config: string): tuple[text: string, json: string, ok: bool, error: string] =
  ## Write config to temp file, render as text and JSON.
  let tmpFile = getTempDir() / "matchstick_nft_test.lua"
  writeFile(tmpFile, config)
  defer: removeFile(tmpFile)

  let (textOut, textEc) = execCmdEx(matchstickBin & " render " & quoteShell(tmpFile) & " 2>/dev/null")
  if textEc != 0:
    return ("", "", false, textOut)

  let (jsonOut, jsonEc) = execCmdEx(matchstickBin & " render --json " & quoteShell(tmpFile) & " 2>/dev/null")
  if jsonEc != 0:
    return (textOut, "", false, jsonOut)

  return (textOut, jsonOut, true, "")

# ---------------------------------------------------------------------------
# Feature-specific configs to validate
# ---------------------------------------------------------------------------

const cfgMinimal = """
local self = fw:zone("fw")
local wan = fw:zone("wan", "eth0")
fw:policy(wan, self, "drop")
"""

const cfgFull = """
local ssh = fw:service("ssh", "tcp", 22)
local dns = fw:service("dns", {"tcp", "udp"}, 53)
local ping = fw:service("ping", "icmp", "echo-request")
local https = fw:service("https", {"tcp", "udp"}, 443)

local self = fw:zone("fw")
local wan = fw:zone("wan", "eth0")
local lan = fw:zone("lan", "eth1")
local dmz = fw:zone("dmz", "eth2")

local admin = fw:host("admin", { zone = lan, addr = "10.0.0.10" })
local server = fw:host("server", { zone = dmz, addr = "172.16.0.10" })

fw:laundry({ rpfilter = true, tcp_strict = true, broadcast_drop = true })
fw:dhcp(wan, "client")
fw:dhcp(lan, "server")

fw:iplist("blocklist", { type = "ipv4", flags = "timeout" })
fw:iplist("bogons", { type = "ipv4", flags = "interval", elements = {"0.0.0.0/8", "127.0.0.0/8"} })

fw:policy(wan, self, "drop", { log = true })
fw:policy(self, wan, "accept")
fw:policy(lan, self, "accept")
fw:policy(lan, wan, "accept")
fw:policy(lan, dmz, "accept")
fw:policy(dmz, wan, "accept")
fw:policy(dmz, self, "reject")
fw:policy("*", "*", "reject")

fw:rule(wan, self, "drop", { saddr_list = "blocklist" })
fw:rule(wan, self, "accept", ssh)
fw:rule(wan, self, "accept", https)
fw:rule(wan, self, "accept", ping)
fw:rule(wan, self, "accept", { proto = "tcp", port = {8080, 8443} })
fw:rule(wan, self, "accept", { proto = "udp", port = "10000-10100" })
fw:rule(lan, self, "accept", dns)
fw:rule(admin, self, "accept", ssh)
fw:rule(lan, lan, "accept", ping)

fw:dnat({ iface = wan, service = https, dest = server })
fw:rule(wan, server, "accept", https)
fw:dnat({ iface = wan, proto = "tcp", port = 2222, dest = server, dest_port = 22 })
fw:rule(wan, server, "accept", { proto = "tcp", port = 22 })

fw:snat({ from = "10.0.0.0/8", oif = "eth0", masquerade = true })
fw:snat({ from = "172.16.0.0/12", oif = "eth0", masquerade = true })
"""

const cfgConnlimitMac = """
local ssh = fw:service("ssh", "tcp", 22)
local self = fw:zone("fw")
local wan = fw:zone("wan", "eth0")
local lan = fw:zone("lan", "eth1")

fw:policy(wan, self, "drop")
fw:policy(lan, self, "accept")

fw:rule(wan, self, "accept", { service = ssh, connlimit = 10 })
fw:rule(lan, self, "accept", { service = ssh, mac = "aa:bb:cc:dd:ee:ff" })
"""

const cfgMssClamp = """
local self = fw:zone("fw")
local wan = fw:zone("wan", "eth0")
local lan = fw:zone("lan", "eth1")

fw:policy(wan, self, "drop")
fw:policy(lan, wan, "accept")

fw:mss_clamp("forward")
"""

const cfgRedirect = """
local self = fw:zone("fw")
local wan = fw:zone("wan", "eth0")
local lan = fw:zone("lan", "eth1")

fw:policy(wan, self, "drop")
fw:policy(lan, self, "accept")

fw:redirect({ iface = lan, proto = "tcp", port = {80}, dest_port = 3128 })
"""

const cfgExceptions = """
local self = fw:zone("fw")
local wan = fw:zone("wan", "eth0")
local https = fw:service("https", {"tcp", "udp"}, 443)

fw:policy(wan, self, "drop")

fw:exception("invalid", "accept", https)
fw:exception("anti_smurf", "accept", { proto = "udp", port = {67, 68} })
"""

const cfgRateLimit = """
local ssh = fw:service("ssh", "tcp", 22)
local self = fw:zone("fw")
local wan = fw:zone("wan", "eth0")

fw:policy(wan, self, "drop")

fw:rule(wan, self, "accept", {
  service = ssh,
  rate = util:rate("5/minute", { burst = 10 }),
})
"""

const cfgCounter = """
local ssh = fw:service("ssh", "tcp", 22)
local self = fw:zone("fw")
local wan = fw:zone("wan", "eth0")

fw:config({ counter = true })
fw:policy(wan, self, "drop")
fw:rule(wan, self, "accept", ssh)
"""

const cfgIpv4Only = """
local self = fw:zone("fw")
local wan = fw:zone("wan", "eth0")
fw:config({ family = "ip" })
fw:policy(wan, self, "drop")
"""

const cfgHairpin = """
local http = fw:service("http", "tcp", 80)
local self = fw:zone("fw")
local wan = fw:zone("wan", "eth0")
local lan = fw:zone("lan", "eth1")
local dmz = fw:zone("dmz", "eth2")

local webserver = fw:host("webserver", { zone = dmz, addr = "172.16.0.10" })

fw:policy(wan, self, "drop")
fw:policy(lan, wan, "accept")
fw:policy(wan, dmz, "drop")

fw:dnat({ iface = wan, service = http, dest = webserver })
fw:rule(wan, webserver, "accept", http)

-- hairpin: LAN hits public IP, DNAT to internal server
fw:dnat({ iface = lan, daddr = "203.0.113.1", proto = "tcp", port = {80, 443}, dest = webserver })
fw:rule(lan, dmz, "accept", { daddr = "172.16.0.10", proto = "tcp", port = {80, 443} })

fw:snat({ from = "10.0.0.0/8", oif = "eth0", masquerade = true })
fw:snat({ from = "10.0.0.0/8", daddr = "172.16.0.10", oif = "eth2", proto = "tcp", port = {80, 443}, addr = "172.16.0.1" })
"""

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

let configs = {
  "minimal": cfgMinimal,
  "full": cfgFull,
  "connlimit_mac": cfgConnlimitMac,
  "mss_clamp": cfgMssClamp,
  "redirect": cfgRedirect,
  "exceptions": cfgExceptions,
  "rate_limit": cfgRateLimit,
  "counter": cfgCounter,
  # "ipv4_only": cfgIpv4Only,  # TODO: family="ip" still generates icmpv6/ip6 rules
  "hairpin": cfgHairpin,
}

# Check if nft and unshare are available
let (_, nftEc) = execCmdEx("which nft 2>/dev/null")
let (_, unsEc) = execCmdEx("unshare --user --net --map-root-user -- true 2>/dev/null")
let canRunNft = nftEc == 0 and unsEc == 0

suite "nft text validation":
  for (name, config) in configs:
    test name & " text accepted by nft":
      if not canRunNft:
        skip()
      else:
        let (text, _, ok, err) = renderConfig(config)
        check ok
        if ok:
          let nftResult = nftCheck(text)
          if not nftResult.ok:
            echo "nft rejected text output for " & name & ":"
            echo nftResult.error
          check nftResult.ok

suite "nft JSON validation":
  for (name, config) in configs:
    test name & " JSON accepted by nft":
      if not canRunNft:
        skip()
      else:
        let (_, jsonOut, ok, err) = renderConfig(config)
        check ok
        if ok:
          let nftResult = nftCheck(jsonOut, json = true)
          if not nftResult.ok:
            echo "nft rejected JSON output for " & name & ":"
            echo nftResult.error
          check nftResult.ok

suite "nft apply and list round-trip":
  for (name, config) in configs:
    test name & " applies and lists":
      if not canRunNft:
        skip()
      else:
        let (text, _, ok, err) = renderConfig(config)
        check ok
        if ok:
          let result = nftApplyAndList(text)
          if not result.ok:
            echo "nft apply failed for " & name & ":"
            echo result.error
          check result.ok
          if result.ok:
            # Verify the listed ruleset contains our table
            check "matchstick" in result.listed

suite "golden file configs":
  # Test all existing testdata configs through nft
  for name in ["full", "config", "multi_iface", "docker", "named_rate", "minimal",
                "hooks", "custom_chain", "exceptions", "tier2_features"]:
    test name & ".lua text accepted by nft":
      if not canRunNft:
        skip()
      else:
        let cfg = testdataDir / (name & ".lua")
        if not fileExists(cfg):
          skip()
        else:
          let (text, exitCode) = execCmdEx(matchstickBin & " render " & quoteShell(cfg) & " 2>/dev/null")
          check exitCode == 0
          if exitCode == 0:
            let nftResult = nftCheck(text)
            if not nftResult.ok:
              echo "nft rejected " & name & ".lua:"
              echo nftResult.error
            check nftResult.ok
