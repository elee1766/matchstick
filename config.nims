import std/os

# Lua 5.4 is vendored and compiled from C sources.
switch("passC", "-I" & (thisDir() / "vendor" / "lua54" / "src"))
switch("passC", "-DLUA_USE_POSIX")
switch("passL", "-lm")

# Static build with musl for portable binary (works on glibc + musl systems)
let muslGcc = findExe("musl-gcc")
if muslGcc != "":
  switch("gcc.exe", muslGcc)
  switch("gcc.linkerexe", muslGcc)
  switch("passL", "-static")

