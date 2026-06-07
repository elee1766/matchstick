# Package
version       = "0.1.0"
author        = "elee1766"
description   = "Lua-based nftables firewall configuration tool"
license       = "AGPL-3.0"
srcDir        = "src"
bin           = @["matchstick"]

# Dependencies
requires "nim >= 2.2.0"

# Tasks
task test, "Run all tests":
  echo "=== Unit tests ==="
  for f in listFiles("tests"):
    if f.endsWith(".nim"):
      exec "nim c -r --hints:off --warnings:off " & f
  echo ""
  echo "=== Integration tests ==="
  for f in listFiles("tests/integration"):
    if f.endsWith(".nim"):
      exec "nim c -r --hints:off --warnings:off " & f
