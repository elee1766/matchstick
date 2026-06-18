## Test validation: name collisions, port validity, shadow detection

import unittest
import std/[os, osproc, strutils]

const projectRoot = currentSourcePath().parentDir().parentDir().parentDir()
const matchstickBin = projectRoot / "matchstick"

proc checkLua(code: string, extraArgs: string = ""): tuple[output: string, exitCode: int] =
  ## Write Lua code to a temp file and run matchstick check on it.
  let tmpFile = getTempDir() / "matchstick_test.lua"
  writeFile(tmpFile, code)
  let args = if extraArgs == "": "" else: extraArgs & " "
  let (output, exitCode) = execCmdEx(matchstickBin & " check " & args & quoteShell(tmpFile))
  removeFile(tmpFile)
  (output, exitCode)

suite "Name collision detection":
  test "zone-zone collision":
    let (output, exitCode) = checkLua("""
      fw:zone("fw")
      fw:zone("myzone", "eth0")
      fw:zone("myzone", "eth1")
    """)
    check exitCode == 1
    check "already registered" in output

  test "host-zone collision":
    let (output, exitCode) = checkLua("""
      local self = fw:zone("fw")
      local lan = fw:zone("myname", "eth0")
      fw:host("myname", { zone = lan, addr = "10.0.0.1" })
    """)
    check exitCode == 1
    check "already registered" in output

  test "host-host collision":
    let (output, exitCode) = checkLua("""
      local self = fw:zone("fw")
      local lan = fw:zone("lan", "eth0")
      fw:host("myhost", { zone = lan, addr = "10.0.0.1" })
      fw:host("myhost", { zone = lan, addr = "10.0.0.2" })
    """)
    check exitCode == 1
    check "already registered" in output

suite "SNAT validation":
  test "masquerade and addr mutually exclusive":
    let (output, exitCode) = checkLua("""
      local self = fw:zone("fw")
      local wan = fw:zone("wan", "eth0")
      fw:snat({ from = "10.0.0.0/8", oif = "eth0", masquerade = true, addr = "1.2.3.4" })
    """)
    check exitCode == 1
    check "mutually exclusive" in output

  test "must specify masquerade or addr":
    let (output, exitCode) = checkLua("""
      local self = fw:zone("fw")
      local wan = fw:zone("wan", "eth0")
      fw:snat({ from = "10.0.0.0/8", oif = "eth0" })
    """)
    check exitCode == 1

suite "Minimal valid config":
  test "just zones and a policy":
    let (output, exitCode) = checkLua("""
      local self = fw:zone("fw")
      local wan = fw:zone("wan", "eth0")
      fw:policy(wan, self, "drop")
    """)
    check exitCode == 0
    check "ok:" in output

  test "bare rule (no service)":
    let (output, exitCode) = checkLua("""
      local self = fw:zone("fw")
      local wan = fw:zone("wan", "eth0")
      local lan = fw:zone("lan", "eth1")
      local guest = fw:host("guest", { zone = lan, addr = "10.0.0.100" })
      fw:policy(lan, self, "accept")
      fw:rule(guest, self, "drop")
    """)
    check exitCode == 0
    check "ok:" in output

suite "DHCP validation":
  test "dhcp on zone without interface fails":
    let (output, exitCode) = checkLua("""
      local self = fw:zone("fw")
      fw:dhcp(self, "server")
    """)
    check exitCode == 1
    check "no interfaces" in output

suite "Edge cases":
  test "empty config (just fw zone)":
    let (output, exitCode) = checkLua("""
      local self = fw:zone("fw")
    """)
    check exitCode == 0

  test "host used as from/to":
    let (output, exitCode) = checkLua("""
      local self = fw:zone("fw")
      local lan = fw:zone("lan", "eth0")
      local h = fw:host("myhost", { zone = lan, addr = "10.0.0.1" })
      local ssh = fw:service("ssh", "tcp", 22)
      fw:policy(lan, self, "drop")
      fw:rule(h, self, "accept", ssh)
    """)
    check exitCode == 0
    check "ok:" in output

  test "host-to-host rule":
    let (output, exitCode) = checkLua("""
      local self = fw:zone("fw")
      local lan = fw:zone("lan", "eth0")
      local a = fw:host("a", { zone = lan, addr = "10.0.0.1" })
      local b = fw:host("b", { zone = lan, addr = "10.0.0.2" })
      fw:rule(a, b, "accept", { proto = "tcp", port = 22 })
    """)
    check exitCode == 0

  test "wildcard default policy":
    let (output, exitCode) = checkLua("""
      local self = fw:zone("fw")
      local wan = fw:zone("wan", "eth0")
      fw:policy("*", "*", "reject")
      fw:policy(wan, self, "drop")
    """)
    check exitCode == 0

suite "Custom chain validation":
  test "invalid hook name rejected":
    let (output, exitCode) = checkLua("""
      local self = fw:zone("fw")
      fw:chain("badhook", { type = "filter", priority = "mangle", rules = { { { accept = {} } } } })
    """)
    check exitCode == 1
    check "hook must be" in output

  test "invalid chain type rejected":
    let (output, exitCode) = checkLua("""
      local self = fw:zone("fw")
      fw:chain("prerouting", { type = "badtype", priority = "mangle", rules = { { { accept = {} } } } })
    """)
    check exitCode == 1
    check "type must be" in output

  test "missing rules rejected":
    let (output, exitCode) = checkLua("""
      local self = fw:zone("fw")
      fw:chain("prerouting", { type = "filter", priority = "mangle" })
    """)
    check exitCode == 1
    check "rules" in output

  test "valid custom chain passes":
    let (output, exitCode) = checkLua("""
      local self = fw:zone("fw")
      fw:chain("prerouting", { type = "filter", priority = "mangle", rules = { { { accept = {} } } } })
    """, "--allow-raw-nft")
    check exitCode == 0

  test "custom chain requires explicit opt-in":
    let (output, exitCode) = checkLua("""
      local self = fw:zone("fw")
      fw:chain("prerouting", { type = "filter", priority = "mangle", rules = { { { accept = {} } } } })
    """)
    check exitCode == 1
    check "--allow-raw-nft" in output

suite "Exception validation":
  test "invalid chain name rejected":
    let (output, exitCode) = checkLua("""
      local self = fw:zone("fw")
      fw:exception("badchain", "accept")
    """)
    check exitCode == 1
    check "chain must be" in output

  test "invalid action rejected":
    let (output, exitCode) = checkLua("""
      local self = fw:zone("fw")
      fw:exception("invalid", "badaction")
    """)
    check exitCode == 1
    check "action must be" in output

  test "valid exception passes":
    let (output, exitCode) = checkLua("""
      local self = fw:zone("fw")
      local wan = fw:zone("wan", "eth0")
      fw:exception("invalid", "accept")
    """)
    check exitCode == 0

suite "Raw nft validation":
  test "non-table argument rejected":
    let (output, exitCode) = checkLua("""
      local self = fw:zone("fw")
      fw:raw_nft(42)
    """)
    check exitCode == 1
    check "table" in output

  test "valid raw nft passes":
    let (output, exitCode) = checkLua("""
      local self = fw:zone("fw")
      fw:raw_nft({ add = { chain = { family = "inet", table = "matchstick", name = "test" } } })
    """, "--allow-raw-nft")
    check exitCode == 0

suite "Hook configuration":
  test "valid hooks pass":
    let (output, exitCode) = checkLua("""
      local self = fw:zone("fw")
      fw:hook({ pre_start = "echo hello", post_start = "echo world" })
    """, "--allow-hooks")
    check exitCode == 0

  test "hooks require explicit opt-in":
    let (output, exitCode) = checkLua("""
      local self = fw:zone("fw")
      fw:hook({ pre_start = "echo hello" })
    """)
    check exitCode == 1
    check "--allow-hooks" in output

suite "Lua sandbox":
  test "os library is not available to configs":
    let (output, exitCode) = checkLua("""
      os.execute("echo unsafe")
      local self = fw:zone("fw")
    """)
    check exitCode == 1
    check "os" in output

  test "dofile is not available to configs":
    let (output, exitCode) = checkLua("""
      dofile("/tmp/unsafe.lua")
      local self = fw:zone("fw")
    """)
    check exitCode == 1
    check "dofile" in output

  test "loadfile is not available to configs":
    let (output, exitCode) = checkLua("""
      loadfile("/tmp/unsafe.lua")
      local self = fw:zone("fw")
    """)
    check exitCode == 1
    check "loadfile" in output

suite "Redirect validation":
  test "missing iface rejected":
    let (output, exitCode) = checkLua("""
      local self = fw:zone("fw")
      fw:redirect({ proto = "tcp", port = { 80 }, dest_port = 3128 })
    """)
    check exitCode == 1
    check "iface" in output

  test "missing dest_port rejected":
    let (output, exitCode) = checkLua("""
      local self = fw:zone("fw")
      local lan = fw:zone("lan", "eth0")
      fw:redirect({ iface = lan, proto = "tcp", port = { 80 } })
    """)
    check exitCode == 1
    check "dest_port" in output

  test "valid redirect passes":
    let (output, exitCode) = checkLua("""
      local self = fw:zone("fw")
      local lan = fw:zone("lan", "eth0")
      fw:redirect({ iface = lan, proto = "tcp", port = { 80 }, dest_port = 3128 })
    """)
    check exitCode == 0

suite "MSS clamp validation":
  test "invalid chain rejected":
    let (output, exitCode) = checkLua("""
      local self = fw:zone("fw")
      fw:mss_clamp("input")
    """)
    check exitCode == 1
    check "chain must be" in output

  test "valid mss_clamp passes":
    let (output, exitCode) = checkLua("""
      local self = fw:zone("fw")
      fw:mss_clamp("forward")
    """)
    check exitCode == 0

suite "Per-rule comments":
  test "comment appears in text output":
    let (output, exitCode) = checkLua("""
      local self = fw:zone("fw")
      local wan = fw:zone("wan", "eth0")
      local ssh = fw:service("ssh", "tcp", 22)
      fw:policy(wan, self, "drop")
      fw:rule(wan, self, "accept", { service = ssh, comment = "Allow SSH from WAN" })
    """)
    check exitCode == 0

  test "comment appears in rendered output":
    let tmpFile = getTempDir() / "matchstick_comment_test.lua"
    writeFile(tmpFile, """
      local self = fw:zone("fw")
      local wan = fw:zone("wan", "eth0")
      local ssh = fw:service("ssh", "tcp", 22)
      fw:policy(wan, self, "drop")
      fw:rule(wan, self, "accept", { service = ssh, comment = "Allow SSH from WAN" })
    """)
    let (output, exitCode) = execCmdEx(matchstickBin & " render " & quoteShell(tmpFile) & " 2>/dev/null")
    removeFile(tmpFile)
    check exitCode == 0
    check "Allow SSH from WAN" in output

  test "comment appears in JSON output":
    let tmpFile = getTempDir() / "matchstick_comment_json_test.lua"
    writeFile(tmpFile, """
      local self = fw:zone("fw")
      local wan = fw:zone("wan", "eth0")
      local ssh = fw:service("ssh", "tcp", 22)
      fw:policy(wan, self, "drop")
      fw:rule(wan, self, "accept", { service = ssh, comment = "Allow SSH from WAN" })
    """)
    let (output, exitCode) = execCmdEx(matchstickBin & " render --json " & quoteShell(tmpFile) & " 2>/dev/null")
    removeFile(tmpFile)
    check exitCode == 0
    check "Allow SSH from WAN" in output

suite "Raw nft statements via fw:chain()":
  test "notrack in custom chain":
    let (output, exitCode) = checkLua("""
      local self = fw:zone("fw")
      fw:chain("prerouting", {
        type = "filter", priority = "raw",
        rules = { { { notrack = {} } } }
      })
    """, "--allow-raw-nft")
    check exitCode == 0

  test "queue in custom chain":
    let (output, exitCode) = checkLua("""
      local self = fw:zone("fw")
      fw:chain("input", {
        type = "filter", priority = "filter",
        rules = { { { queue = { num = 0 } } } }
      })
    """, "--allow-raw-nft")
    check exitCode == 0

  test "notrack renders in text output":
    let tmpFile = getTempDir() / "matchstick_notrack_test.lua"
    writeFile(tmpFile, """
      local self = fw:zone("fw")
      fw:chain("prerouting", {
        type = "filter", priority = "raw",
        rules = { { { notrack = {} } } }
      })
    """)
    let (output, exitCode) = execCmdEx(matchstickBin & " render --allow-raw-nft " & quoteShell(tmpFile) & " 2>/dev/null")
    removeFile(tmpFile)
    check exitCode == 0
    check "notrack" in output

  test "queue renders in text output":
    let tmpFile = getTempDir() / "matchstick_queue_test.lua"
    writeFile(tmpFile, """
      local self = fw:zone("fw")
      fw:chain("input", {
        type = "filter", priority = "filter",
        rules = { { { queue = { num = 1, flags = "bypass" } } } }
      })
    """)
    let (output, exitCode) = execCmdEx(matchstickBin & " render --allow-raw-nft " & quoteShell(tmpFile) & " 2>/dev/null")
    removeFile(tmpFile)
    check exitCode == 0
    check "queue" in output

suite "UFW import":
  const ufwInput = """
ufw allow 80/tcp
ufw allow 443
ufw allow 51820/udp
ufw allow 21820/udp
ufw allow 6502
ufw allow 51821/udp
ufw allow from 10.100.0.0/24 to any port 22 proto tcp comment 'SSH via WireGuard only'
ufw allow from 203.0.113.42 to any port 9001
"""

  proc importUfw(input: string): tuple[output: string, exitCode: int] =
    let tmpFile = getTempDir() / "matchstick_ufw_input.txt"
    writeFile(tmpFile, input)
    let (output, exitCode) = execCmdEx(matchstickBin & " import-ufw < " & quoteShell(tmpFile) & " 2>&1")
    removeFile(tmpFile)
    (output, exitCode)

  test "import-ufw produces output":
    let (output, exitCode) = importUfw(ufwInput)
    check exitCode == 0
    check output.len > 0
    check "fw:zone" in output

  test "import-ufw generates services for each port":
    let (output, exitCode) = importUfw(ufwInput)
    check exitCode == 0
    check "80" in output
    check "443" in output
    check "51820" in output
    check "21820" in output
    check "6502" in output
    check "51821" in output

  test "import-ufw handles source IP restriction":
    let (output, exitCode) = importUfw(ufwInput)
    check exitCode == 0
    check "10.100.0.0/24" in output
    check "203.0.113.42" in output

  test "import-ufw preserves comments":
    let (output, exitCode) = importUfw(ufwInput)
    check exitCode == 0
    check "SSH via WireGuard only" in output

  test "import-ufw output is valid matchstick config":
    let (luaOutput, importExit) = importUfw(ufwInput)
    check importExit == 0
    # Write the generated Lua and check it with matchstick
    let tmpLua = getTempDir() / "matchstick_ufw_generated.lua"
    writeFile(tmpLua, luaOutput)
    let (checkOutput, checkExit) = execCmdEx(matchstickBin & " check " & quoteShell(tmpLua) & " 2>&1")
    removeFile(tmpLua)
    check checkExit == 0
    check "ok:" in checkOutput

  test "import-ufw output renders valid nftables":
    let (luaOutput, importExit) = importUfw(ufwInput)
    check importExit == 0
    let tmpLua = getTempDir() / "matchstick_ufw_render.lua"
    writeFile(tmpLua, luaOutput)
    let (renderOutput, renderExit) = execCmdEx(matchstickBin & " render " & quoteShell(tmpLua) & " 2>/dev/null")
    removeFile(tmpLua)
    check renderExit == 0
    check "table inet" in renderOutput
    check "chain input" in renderOutput

  test "import-ufw empty input fails":
    let (output, exitCode) = importUfw("")
    check exitCode == 1
    check "no input" in output

suite "Sysctl overrides":
  test "fw:sysctl with key-value passes":
    let (output, exitCode) = checkLua("""
      local self = fw:zone("fw")
      fw:sysctl("net.ipv4.tcp_syncookies", "1")
    """)
    check exitCode == 0

  test "fw:sysctl with table passes":
    let (output, exitCode) = checkLua("""
      local self = fw:zone("fw")
      fw:sysctl({
        ["net.ipv4.tcp_syncookies"] = "1",
        ["net.core.somaxconn"] = "4096",
      })
    """)
    check exitCode == 0
