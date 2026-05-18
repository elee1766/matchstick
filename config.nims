import std/os

# Lua 5.4 is vendored and compiled from C sources.
# Tell the C compiler where to find Lua headers.
switch("passC", "-I" & (thisDir() / "vendor" / "lua54" / "src"))

# Build Lua as a POSIX library (enables os/io/loadlib)
switch("passC", "-DLUA_USE_POSIX")

# Link math library (required by Lua)
switch("passL", "-lm")
