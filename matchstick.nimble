# Package
version       = "0.1.0"
author        = "elee1766"
description   = "Lua-based nftables firewall configuration tool"
license       = "AGPL-3.0"
srcDir        = "src"
bin           = @["matchstick"]

# Dependencies
requires "nim >= 2.2.0"

# Optional: web frontend
requires "karax >= 1.3.3"
requires "mummy >= 0.4.2"

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

task web, "Build the web frontend":
  exec "nim c -d:release -o:matchstick_web web/server.nim"

task webrun, "Build and run the web frontend":
  exec "nim c -d:release -o:matchstick_web web/server.nim"
  exec "./matchstick_web"

task webdev, "Build and run with auto-reload on changes":
  exec "watchexec -r -w web/ -w src/ -e nim,css,js -- nim c -d:release -o:matchstick_web web/server.nim '&&' ./matchstick_web"
