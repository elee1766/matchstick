import std/os

# Lua 5.4 is vendored and compiled from C sources.
switch("passC", "-I" & (thisDir() / "vendor" / "lua55" / "src"))

# Harden compiled-in C code (vendored Lua).
switch("passC", "-fstack-protector-strong -D_FORTIFY_SOURCE=2")

# Use goto-based exceptions instead of setjmp/longjmp. This is faster,
# generates smaller binaries, and avoids conflicts with Lua's own longjmp
# error handling (see lua54/sandbox.nim).
switch("exceptions", "goto")

when not defined(emscripten):
  switch("passC", "-DLUA_USE_POSIX")
  switch("passL", "-lm")

  # Static build with musl for portable binary (works on glibc + musl systems)
  let muslGcc = findExe("musl-gcc")
  if muslGcc != "":
    switch("gcc.exe", muslGcc)
    switch("gcc.linkerexe", muslGcc)
    switch("passL", "-static")

# begin Nimble config (version 2)
when withDir(thisDir(), system.fileExists("nimble.paths")):
  include "nimble.paths"
# end Nimble config
