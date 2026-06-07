## Compile Lua config strings at build time for doc examples.

import std/[os, tempfiles]
import ../../src/lua54/ffi
import ../../src/matchstickpkg/types
import ../../src/matchstickpkg/lua/api
import ../../src/matchstickpkg/build
import ../../src/matchstickpkg/emit_text
import ../../src/matchstickpkg/validate
import ../../src/matchstickpkg/sysctl

proc renderExample*(luaCode: string): string =
  ## Compile a Lua config string and return nftables text output.
  ## Returns error message on failure.
  let L = luaL_newstate()
  if L == nil: return "error: failed to create Lua state"
  defer: lua_close(L)
  luaL_openlibs(L)

  let state = newFirewallState()
  let (tmpFile, tmpPath) = createTempFile("matchstick_doc_", ".lua")
  tmpFile.write(luaCode)
  tmpFile.close()
  defer: removeFile(tmpPath)

  setupLuaVM(L, state, tmpPath)

  var status = luaL_loadfile(L, tmpPath.cstring)
  if status != LUA_OK:
    return "error: " & $lua_tostring(L, -1)

  status = lua_pcall(L, 0, 0, 0)
  if status != LUA_OK:
    return "error: " & $lua_tostring(L, -1)

  let msgs = validate(state)
  var warnings = ""
  for m in msgs:
    let prefix = if m.severity == svWarning: "warning" else: "error"
    warnings &= prefix & ": " & m.msg & "\n"

  let ruleset = buildRuleset(state)
  return warnings & emitText(ruleset)

proc renderSysctls*(luaCode: string): string =
  ## Compile and return derived sysctls.
  let L = luaL_newstate()
  if L == nil: return "error: failed to create Lua state"
  defer: lua_close(L)
  luaL_openlibs(L)

  let state = newFirewallState()
  let (tmpFile, tmpPath) = createTempFile("matchstick_doc_", ".lua")
  tmpFile.write(luaCode)
  tmpFile.close()
  defer: removeFile(tmpPath)

  setupLuaVM(L, state, tmpPath)

  var status = luaL_loadfile(L, tmpPath.cstring)
  if status != LUA_OK:
    return "error: " & $lua_tostring(L, -1)

  status = lua_pcall(L, 0, 0, 0)
  if status != LUA_OK:
    return "error: " & $lua_tostring(L, -1)

  let sysctls = deriveSysctls(state)
  return formatSysctls(sysctls)
