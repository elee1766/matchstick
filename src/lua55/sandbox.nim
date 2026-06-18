## lua55/sandbox.nim — Safe Lua↔Nim boundary.
##
## This module is the ONLY place that calls lua_pcall. It enforces one rule:
##
##   NEVER raise a Nim exception after lua_pcall returns.
##
## Why: Lua's error handling uses longjmp. When a CFunction (registered via
## setupLuaVM) calls luaL_error, Lua does a longjmp back to the lua_pcall
## setjmp point. This longjmp skips Nim stack frames without running their
## cleanup. Nim maintains a linked list of TFrame nodes for stack traces;
## longjmp leaves dangling pointers in this list. If Nim later tries to
## raise an exception (which walks the frame list for a stack trace), it
## follows a dangling pointer and segfaults.
##
## The fix is simple: after lua_pcall returns, read the error from the Lua
## stack as a plain string and return it. No Nim exceptions, no stack trace
## walking, no crash.
##
## CFunctions themselves are free to use luaL_error — that's the correct
## Lua C API pattern. lua_pcall catches the longjmp.

import ./ffi
import ../matchstickpkg/types
import ../matchstickpkg/lua/api

type
  LuaResult* = object
    ## Result of running a Lua config file.
    state*: FirewallState    ## nil on error
    error*: string           ## "" on success

const defaultInstructionLimit* = 10_000_000

proc runConfig*(configFile: string,
                instructionLimit: int = defaultInstructionLimit,
                memoryLimit: int = defaultLuaMemoryLimit): LuaResult =
  ## Load, sandbox, and execute a Lua firewall config file.
  ## Returns a LuaResult with either the parsed state or an error message.
  ## NEVER raises — all errors are returned as strings.
  var allocState: LuaAllocState
  let L = luaL_newstate_limited(addr allocState, memoryLimit)
  if L == nil:
    return LuaResult(error: "failed to create Lua state")
  defer: lua_close(L)

  luaL_openlibs_safe(L)
  luaSetInstructionLimit(L, instructionLimit)

  let state = newFirewallState()
  setupLuaVM(L, state, configFile)

  # Load the file. luaL_loadfile does NOT use longjmp on failure —
  # it returns an error status and pushes the message onto the stack.
  var status = luaL_loadfile(L, configFile.cstring)
  if status != LUA_OK:
    let msg = if lua_type(L, -1) == LUA_TSTRING: $lua_tostring(L, -1)
              else: "failed to load " & configFile
    return LuaResult(error: msg)

  # Save Nim's frame state BEFORE lua_pcall. If a CFunction calls
  # luaL_error, Lua's longjmp skips Nim frames without cleanup, leaving
  # dangling pointers in Nim's TFrame linked list. After lua_pcall returns,
  # we restore the frame state so subsequent Nim code doesn't crash.
  let savedFrameState = getFrameState()

  status = lua_pcall(L, 0, 0, 0)

  # Restore Nim's frame state. This is the critical safety operation:
  # lua_pcall's longjmp may have corrupted the TFrame chain.
  setFrameState(savedFrameState)

  if status != LUA_OK:
    let msg = if lua_type(L, -1) == LUA_TSTRING: $lua_tostring(L, -1)
              else: "config execution failed"
    return LuaResult(error: msg)

  return LuaResult(state: state)

proc runString*(code: string, sourceName: string = "input",
                instructionLimit: int = defaultInstructionLimit,
                memoryLimit: int = defaultLuaMemoryLimit): LuaResult =
  ## Load and execute a Lua config from a string. Same safety guarantees
  ## as runConfig. Used by the WASM playground and tests.
  var allocState: LuaAllocState
  let L = luaL_newstate_limited(addr allocState, memoryLimit)
  if L == nil:
    return LuaResult(error: "failed to create Lua state")
  defer: lua_close(L)

  luaL_openlibs_safe(L)
  luaSetInstructionLimit(L, instructionLimit)

  let state = newFirewallState()
  setupLuaVM(L, state, sourceName)

  var status = luaL_loadstring(L, code.cstring)
  if status != LUA_OK:
    let msg = if lua_type(L, -1) == LUA_TSTRING: $lua_tostring(L, -1)
              else: "failed to load config"
    return LuaResult(error: msg)

  let savedFrameState = getFrameState()
  status = lua_pcall(L, 0, 0, 0)
  setFrameState(savedFrameState)

  if status != LUA_OK:
    let msg = if lua_type(L, -1) == LUA_TSTRING: $lua_tostring(L, -1)
              else: "config execution failed"
    return LuaResult(error: msg)

  return LuaResult(state: state)
