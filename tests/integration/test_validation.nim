## Test validation: name collisions, port validity, shadow detection

import unittest
import std/[os, osproc, strutils]

const projectRoot = currentSourcePath().parentDir().parentDir().parentDir()
const matchstickBin = projectRoot / "matchstick"

proc checkLua(code: string): tuple[output: string, exitCode: int] =
  ## Write Lua code to a temp file and run matchstick check on it.
  let tmpFile = getTempDir() / "matchstick_test.lua"
  writeFile(tmpFile, code)
  let (output, exitCode) = execCmdEx(matchstickBin & " check " & quoteShell(tmpFile))
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
