# Package
version       = "0.1.0"
author        = "elee1766"
description   = "Lua-based nftables firewall configuration tool"
license       = "AGPL-3.0"
srcDir        = "src"
bin           = @["matchstick"]

# Dependencies
requires "nim >= 2.2.0"

# Static site / WASM playground
requires "karax >= 1.3.3"

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

task wasm, "Build WASM playground (requires Emscripten via mise)":
  exec "nim c --cpu:wasm32 -d:emscripten -d:noSystem -d:release " &
    "--cc:clang --clang.exe:emcc --clang.linkerexe:emcc " &
    "--passC:\"-s WASM=1\" " &
    "--passL:\"-s EXPORTED_FUNCTIONS=[_loadAndRender] " &
    "-s EXPORTED_RUNTIME_METHODS=[ccall,cwrap] " &
    "-s ALLOW_MEMORY_GROWTH=1 -s MODULARIZE=1 -s EXPORT_NAME=createMatchstick\" " &
    "-o:web/static/playground.js web/wasm/playground.nim"

task ssg, "Build static site to dist/":
  exec "nim c -d:release -d:ssg -r web/ssg.nim"


