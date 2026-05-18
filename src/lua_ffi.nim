## Lua 5.4 FFI bindings.
## Compiles Lua from vendored C sources directly into the binary.

import std/os

const luaSrcDir = currentSourcePath.parentDir.parentDir / "vendor" / "lua54" / "src"

template luaSrc(file: string): string = luaSrcDir / file

# Compile all Lua 5.4 C sources (excluding lua.c and luac.c standalone binaries)
{.compile: luaSrc("lapi.c").}
{.compile: luaSrc("lauxlib.c").}
{.compile: luaSrc("lbaselib.c").}
{.compile: luaSrc("lcode.c").}
{.compile: luaSrc("lcorolib.c").}
{.compile: luaSrc("lctype.c").}
{.compile: luaSrc("ldblib.c").}
{.compile: luaSrc("ldebug.c").}
{.compile: luaSrc("ldo.c").}
{.compile: luaSrc("ldump.c").}
{.compile: luaSrc("lfunc.c").}
{.compile: luaSrc("lgc.c").}
{.compile: luaSrc("linit.c").}
{.compile: luaSrc("liolib.c").}
{.compile: luaSrc("llex.c").}
{.compile: luaSrc("lmathlib.c").}
{.compile: luaSrc("lmem.c").}
{.compile: luaSrc("loadlib.c").}
{.compile: luaSrc("lobject.c").}
{.compile: luaSrc("lopcodes.c").}
{.compile: luaSrc("loslib.c").}
{.compile: luaSrc("lparser.c").}
{.compile: luaSrc("lstate.c").}
{.compile: luaSrc("lstring.c").}
{.compile: luaSrc("lstrlib.c").}
{.compile: luaSrc("ltable.c").}
{.compile: luaSrc("ltablib.c").}
{.compile: luaSrc("ltm.c").}
{.compile: luaSrc("lundump.c").}
{.compile: luaSrc("lutf8lib.c").}
{.compile: luaSrc("lvm.c").}
{.compile: luaSrc("lzio.c").}

# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

type
  LuaState* = pointer
    ## Opaque pointer to a Lua state (lua_State*)

  LuaCFunction* = proc(L: LuaState): cint {.cdecl.}
    ## C function callable from Lua

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

const
  # Thread status / error codes
  LUA_OK*        = 0.cint
  LUA_YIELD*     = 1.cint
  LUA_ERRRUN*    = 2.cint
  LUA_ERRSYNTAX* = 3.cint
  LUA_ERRMEM*    = 4.cint
  LUA_ERRERR*    = 5.cint

  # Type tags
  LUA_TNONE*          = -1.cint
  LUA_TNIL*           = 0.cint
  LUA_TBOOLEAN*       = 1.cint
  LUA_TLIGHTUSERDATA* = 2.cint
  LUA_TNUMBER*        = 3.cint
  LUA_TSTRING*        = 4.cint
  LUA_TTABLE*         = 5.cint
  LUA_TFUNCTION*      = 6.cint
  LUA_TUSERDATA*      = 7.cint
  LUA_TTHREAD*        = 8.cint

  # Pseudo-indices
  LUA_REGISTRYINDEX* = -1001000.cint

  # Minimum stack size
  LUA_MINSTACK* = 20.cint

  # Multiple returns
  LUA_MULTRET* = -1.cint

# ---------------------------------------------------------------------------
# State management
# ---------------------------------------------------------------------------

proc luaL_newstate*(): LuaState {.importc, cdecl.}
proc lua_close*(L: LuaState) {.importc, cdecl.}
proc luaL_openlibs*(L: LuaState) {.importc, cdecl.}

# ---------------------------------------------------------------------------
# Loading and executing
# ---------------------------------------------------------------------------

proc luaL_loadfilex*(L: LuaState, filename: cstring, mode: cstring): cint {.importc, cdecl.}
proc luaL_loadstring*(L: LuaState, s: cstring): cint {.importc, cdecl.}
proc lua_pcallk*(L: LuaState, nargs, nresults, errfunc: cint,
                 ctx: cint, k: pointer): cint {.importc, cdecl.}

proc luaL_loadfile*(L: LuaState, filename: cstring): cint =
  luaL_loadfilex(L, filename, nil)

proc lua_pcall*(L: LuaState, nargs, nresults, errfunc: cint): cint =
  lua_pcallk(L, nargs, nresults, errfunc, 0, nil)

# ---------------------------------------------------------------------------
# Stack manipulation
# ---------------------------------------------------------------------------

proc lua_gettop*(L: LuaState): cint {.importc, cdecl.}
proc lua_settop*(L: LuaState, idx: cint) {.importc, cdecl.}
proc lua_pushvalue*(L: LuaState, idx: cint) {.importc, cdecl.}
proc lua_rotate*(L: LuaState, idx: cint, n: cint) {.importc, cdecl.}
proc lua_copy*(L: LuaState, fromidx, toidx: cint) {.importc, cdecl.}
proc lua_checkstack*(L: LuaState, n: cint): cint {.importc, cdecl.}
proc lua_absindex*(L: LuaState, idx: cint): cint {.importc, cdecl.}

proc lua_pop*(L: LuaState, n: cint) =
  lua_settop(L, -n - 1)

proc lua_remove*(L: LuaState, idx: cint) =
  lua_rotate(L, idx, -1)
  lua_pop(L, 1)

proc lua_insert*(L: LuaState, idx: cint) =
  lua_rotate(L, idx, 1)

# ---------------------------------------------------------------------------
# Push values onto the stack
# ---------------------------------------------------------------------------

proc lua_pushnil*(L: LuaState) {.importc, cdecl.}
proc lua_pushnumber*(L: LuaState, n: cdouble) {.importc, cdecl.}
proc lua_pushinteger*(L: LuaState, n: clonglong) {.importc, cdecl.}
proc lua_pushlstring*(L: LuaState, s: cstring, len: csize_t): cstring {.importc, cdecl.}
proc lua_pushstring*(L: LuaState, s: cstring): cstring {.importc, cdecl.}
proc lua_pushboolean*(L: LuaState, b: cint) {.importc, cdecl.}
proc lua_pushcclosure*(L: LuaState, fn: LuaCFunction, n: cint) {.importc, cdecl.}
proc lua_pushlightuserdata*(L: LuaState, p: pointer) {.importc, cdecl.}

proc lua_pushcfunction*(L: LuaState, fn: LuaCFunction) =
  lua_pushcclosure(L, fn, 0)

# ---------------------------------------------------------------------------
# Read values from the stack
# ---------------------------------------------------------------------------

proc lua_tonumberx*(L: LuaState, idx: cint, isnum: ptr cint): cdouble {.importc, cdecl.}
proc lua_tointegerx*(L: LuaState, idx: cint, isnum: ptr cint): clonglong {.importc, cdecl.}
proc lua_toboolean*(L: LuaState, idx: cint): cint {.importc, cdecl.}
proc lua_tolstring*(L: LuaState, idx: cint, len: ptr csize_t): cstring {.importc, cdecl.}
proc lua_rawlen*(L: LuaState, idx: cint): csize_t {.importc, cdecl.}
proc lua_tocfunction*(L: LuaState, idx: cint): LuaCFunction {.importc, cdecl.}
proc lua_touserdata*(L: LuaState, idx: cint): pointer {.importc, cdecl.}
proc lua_topointer*(L: LuaState, idx: cint): pointer {.importc, cdecl.}

proc lua_tonumber*(L: LuaState, idx: cint): cdouble =
  lua_tonumberx(L, idx, nil)

proc lua_tointeger*(L: LuaState, idx: cint): clonglong =
  lua_tointegerx(L, idx, nil)

proc lua_tostring*(L: LuaState, idx: cint): cstring =
  lua_tolstring(L, idx, nil)

# ---------------------------------------------------------------------------
# Type checking
# ---------------------------------------------------------------------------

proc lua_type*(L: LuaState, idx: cint): cint {.importc, cdecl.}
proc lua_typename*(L: LuaState, tp: cint): cstring {.importc, cdecl.}
proc lua_isnumber*(L: LuaState, idx: cint): cint {.importc, cdecl.}
proc lua_isstring*(L: LuaState, idx: cint): cint {.importc, cdecl.}
proc lua_iscfunction*(L: LuaState, idx: cint): cint {.importc, cdecl.}
proc lua_isinteger*(L: LuaState, idx: cint): cint {.importc, cdecl.}
proc lua_isuserdata*(L: LuaState, idx: cint): cint {.importc, cdecl.}

proc lua_isnil*(L: LuaState, idx: cint): bool =
  lua_type(L, idx) == LUA_TNIL

proc lua_isboolean*(L: LuaState, idx: cint): bool =
  lua_type(L, idx) == LUA_TBOOLEAN

proc lua_istable*(L: LuaState, idx: cint): bool =
  lua_type(L, idx) == LUA_TTABLE

proc lua_isfunction*(L: LuaState, idx: cint): bool =
  lua_type(L, idx) == LUA_TFUNCTION

proc lua_isnoneornil*(L: LuaState, idx: cint): bool =
  lua_type(L, idx) <= LUA_TNIL

# ---------------------------------------------------------------------------
# Table access
# ---------------------------------------------------------------------------

proc lua_getfield*(L: LuaState, idx: cint, k: cstring): cint {.importc, cdecl.}
proc lua_setfield*(L: LuaState, idx: cint, k: cstring) {.importc, cdecl.}
proc lua_gettable*(L: LuaState, idx: cint): cint {.importc, cdecl.}
proc lua_settable*(L: LuaState, idx: cint) {.importc, cdecl.}
proc lua_rawget*(L: LuaState, idx: cint): cint {.importc, cdecl.}
proc lua_rawset*(L: LuaState, idx: cint) {.importc, cdecl.}
proc lua_rawgeti*(L: LuaState, idx: cint, n: clonglong): cint {.importc, cdecl.}
proc lua_rawseti*(L: LuaState, idx: cint, n: clonglong) {.importc, cdecl.}
proc lua_next*(L: LuaState, idx: cint): cint {.importc, cdecl.}
proc lua_createtable*(L: LuaState, narr, nrec: cint) {.importc, cdecl.}
proc lua_newuserdatauv*(L: LuaState, sz: csize_t, nuvalue: cint): pointer {.importc, cdecl.}
proc lua_getmetatable*(L: LuaState, objindex: cint): cint {.importc, cdecl.}
proc lua_setmetatable*(L: LuaState, objindex: cint): cint {.importc, cdecl.}

proc lua_newtable*(L: LuaState) =
  lua_createtable(L, 0, 0)

proc lua_newuserdata*(L: LuaState, sz: csize_t): pointer =
  lua_newuserdatauv(L, sz, 1)

# ---------------------------------------------------------------------------
# Global table
# ---------------------------------------------------------------------------

proc lua_getglobal*(L: LuaState, name: cstring): cint {.importc, cdecl.}
proc lua_setglobal*(L: LuaState, name: cstring) {.importc, cdecl.}

# ---------------------------------------------------------------------------
# Auxiliary library (luaL_*)
# ---------------------------------------------------------------------------

proc luaL_newmetatable*(L: LuaState, tname: cstring): cint {.importc, cdecl.}
proc luaL_getmetatable*(L: LuaState, tname: cstring): cint =
  lua_getfield(L, LUA_REGISTRYINDEX, tname)

proc luaL_setmetatable*(L: LuaState, tname: cstring) {.importc, cdecl.}
proc luaL_testudata*(L: LuaState, ud: cint, tname: cstring): pointer {.importc, cdecl.}
proc luaL_checkudata*(L: LuaState, ud: cint, tname: cstring): pointer {.importc, cdecl.}
proc luaL_ref*(L: LuaState, t: cint): cint {.importc, cdecl.}
proc luaL_unref*(L: LuaState, t: cint, r: cint) {.importc, cdecl.}
proc luaL_error*(L: LuaState, fmt: cstring): cint {.importc, cdecl, varargs.}
proc luaL_argerror*(L: LuaState, arg: cint, extramsg: cstring): cint {.importc, cdecl.}
proc luaL_checklstring*(L: LuaState, n: cint, l: ptr csize_t): cstring {.importc, cdecl.}
proc luaL_checknumber*(L: LuaState, n: cint): cdouble {.importc, cdecl.}
proc luaL_checkinteger*(L: LuaState, n: cint): clonglong {.importc, cdecl.}
proc luaL_optinteger*(L: LuaState, n: cint, d: clonglong): clonglong {.importc, cdecl.}
proc luaL_optlstring*(L: LuaState, n: cint, d: cstring, l: ptr csize_t): cstring {.importc, cdecl.}

proc luaL_checkstring*(L: LuaState, n: cint): cstring =
  luaL_checklstring(L, n, nil)

proc luaL_optstring*(L: LuaState, n: cint, d: cstring): cstring =
  luaL_optlstring(L, n, d, nil)
proc luaL_checktype*(L: LuaState, arg: cint, t: cint) {.importc, cdecl.}
proc luaL_len*(L: LuaState, idx: cint): clonglong {.importc, cdecl.}

# Debug info
proc luaL_where*(L: LuaState, lvl: cint) {.importc, cdecl.}

# ---------------------------------------------------------------------------
# Nim convenience helpers
# ---------------------------------------------------------------------------

proc luaTypeNameAt*(L: LuaState, idx: cint): string =
  ## Get the type name of the value at stack index `idx`.
  $lua_typename(L, lua_type(L, idx))

proc luaCheckError*(L: LuaState, status: cint) =
  ## If status is not LUA_OK, read the error message from the stack and raise.
  if status != LUA_OK:
    let msg = if lua_type(L, -1) == LUA_TSTRING:
                $lua_tostring(L, -1)
              else:
                "unknown error (status " & $status & ")"
    lua_pop(L, 1)
    raise newException(CatchableError, msg)
