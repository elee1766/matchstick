## lua/helpers.nim - Shared helpers for the Lua VM API layer.
##
## Provides: state/config registry access, Lua argument readers,
## handle push, endpoint/service/host resolution, action parsing.

import std/[options, tables, strutils]
import ./ffi
import ../types

const
  ## Registry key for the FirewallState pointer
  stateRegistryKey* = "matchstick.state"

  ## Registry key for the directory of the currently executing config file
  configDirRegistryKey* = "matchstick.configdir"

  ## Metatable names for handle types
  zoneHandleMT*  = "matchstick.zone"
  hostHandleMT*  = "matchstick.host"
  serviceHandleMT* = "matchstick.service"

# ---------------------------------------------------------------------------
# Helpers: get state from Lua registry
# ---------------------------------------------------------------------------

proc getState*(L: LuaState): FirewallState =
  ## Retrieve the FirewallState pointer from the Lua registry.
  discard lua_getfield(L, LUA_REGISTRYINDEX, stateRegistryKey)
  result = cast[FirewallState](lua_touserdata(L, -1))
  lua_pop(L, 1)

proc getConfigDir*(L: LuaState): string =
  discard lua_getfield(L, LUA_REGISTRYINDEX, configDirRegistryKey)
  if lua_type(L, -1) == LUA_TSTRING:
    result = $lua_tostring(L, -1)
  lua_pop(L, 1)

proc setConfigDir*(L: LuaState, dir: string) =
  discard lua_pushstring(L, dir.cstring)
  lua_setfield(L, LUA_REGISTRYINDEX, configDirRegistryKey)

proc getCurrentLine*(L: LuaState): int =
  ## Get the current Lua source line number (for error messages).
  luaL_where(L, 1)
  let s = $lua_tostring(L, -1)
  lua_pop(L, 1)
  # Format is "filename:line: " -- extract the line number
  let parts = s.split(':')
  if parts.len >= 2:
    try: result = parseInt(parts[^2].strip())
    except ValueError: result = 0

# ---------------------------------------------------------------------------
# Helpers: read Lua arguments
# ---------------------------------------------------------------------------

proc getStringField*(L: LuaState, idx: cint, key: string): string =
  ## Read a string field from a table at stack index `idx`. Returns "" if not present.
  discard lua_getfield(L, idx, key.cstring)
  if lua_type(L, -1) == LUA_TSTRING:
    result = $lua_tostring(L, -1)
  lua_pop(L, 1)

proc getBoolField*(L: LuaState, idx: cint, key: string, default: bool): bool =
  ## Read a boolean field from a table. Returns `default` if not present.
  discard lua_getfield(L, idx, key.cstring)
  if lua_isboolean(L, -1):
    result = lua_toboolean(L, -1) != 0
  elif lua_isnoneornil(L, -1):
    result = default
  else:
    result = default
  lua_pop(L, 1)

proc getIntField*(L: LuaState, idx: cint, key: string, default: int): int =
  discard lua_getfield(L, idx, key.cstring)
  if lua_isinteger(L, -1) != 0:
    result = int(lua_tointeger(L, -1))
  elif lua_isnoneornil(L, -1):
    result = default
  else:
    result = default
  lua_pop(L, 1)

proc getStringArray*(L: LuaState, idx: cint): seq[string] =
  ## Read a value that's either a string, integer, or an array of strings/integers.
  let absIdx = lua_absindex(L, idx)
  if lua_type(L, absIdx) == LUA_TSTRING:
    result = @[$lua_tostring(L, absIdx)]
  elif lua_isinteger(L, absIdx) != 0:
    result = @[$lua_tointeger(L, absIdx)]
  elif lua_isnumber(L, absIdx) != 0:
    result = @[$int(lua_tonumber(L, absIdx))]
  elif lua_istable(L, absIdx):
    let len = luaL_len(L, absIdx)
    for i in 1..len:
      discard lua_rawgeti(L, absIdx, i.clonglong)
      if lua_type(L, -1) == LUA_TSTRING:
        result.add $lua_tostring(L, -1)
      elif lua_isinteger(L, -1) != 0:
        result.add $lua_tointeger(L, -1)
      lua_pop(L, 1)

proc getStringArrayField*(L: LuaState, idx: cint, key: string): seq[string] =
  discard lua_getfield(L, idx, key.cstring)
  if not lua_isnoneornil(L, -1):
    result = getStringArray(L, -1)
  lua_pop(L, 1)

proc parseAction*(L: LuaState, s: string, context: string): Action =
  ## Parse an action string ("accept"/"drop"/"reject") or raise a Lua error.
  case s
  of "accept": actAccept
  of "drop": actDrop
  of "reject": actReject
  else:
    discard luaL_error(L, "%s: action must be accept/drop/reject, got '%s'", context.cstring, s.cstring)
    actDrop

# ---------------------------------------------------------------------------
# Helpers: push handle tables back to Lua
# ---------------------------------------------------------------------------

proc pushHandle*(L: LuaState, name, typeName, metatable: string) =
  ## Push a handle table (zone/host/service) onto the Lua stack.
  lua_newtable(L)
  discard lua_pushstring(L, name.cstring)
  lua_setfield(L, -2, "__name")
  discard lua_pushstring(L, typeName.cstring)
  lua_setfield(L, -2, "__type")
  discard luaL_getmetatable(L, metatable)
  if lua_istable(L, -1):
    discard lua_setmetatable(L, -2)
  else:
    lua_pop(L, 1)

# ---------------------------------------------------------------------------
# Helpers: resolve endpoints (zone/host from handle or string)
# ---------------------------------------------------------------------------

proc resolveEndpoint*(L: LuaState, state: FirewallState, idx: cint): Endpoint =
  ## Resolve a Lua value at `idx` to an Endpoint.
  ## Accepts: zone handle, host handle, or string name.
  let absIdx = lua_absindex(L, idx)

  if lua_type(L, absIdx) == LUA_TSTRING:
    let name = $lua_tostring(L, absIdx)
    if name == "*":
      # Wildcard -- return a nil-zone endpoint (handled specially)
      return Endpoint()
    if name in state.zones:
      return Endpoint(zone: state.zones[name])
    elif name in state.hosts:
      let host = state.hosts[name]
      return Endpoint(zone: host.zone, host: some(host))
    else:
      discard luaL_error(L, "unknown zone or host: '%s'", name.cstring)

  elif lua_istable(L, absIdx):
    let typ = getStringField(L, absIdx, "__type")
    let name = getStringField(L, absIdx, "__name")
    if typ == "zone":
      if name in state.zones:
        return Endpoint(zone: state.zones[name])
      else:
        discard luaL_error(L, "zone handle refers to unknown zone: '%s'", name.cstring)
    elif typ == "host":
      if name in state.hosts:
        let host = state.hosts[name]
        return Endpoint(zone: host.zone, host: some(host))
      else:
        discard luaL_error(L, "host handle refers to unknown host: '%s'", name.cstring)
    else:
      discard luaL_error(L, "expected zone or host handle, got table with __type='%s'", typ.cstring)

  else:
    discard luaL_error(L, "expected zone/host handle or string, got %s",
                       lua_typename(L, lua_type(L, absIdx)))

proc resolveService*(L: LuaState, state: FirewallState, idx: cint): Option[Service] =
  ## Resolve a service handle or string at `idx`. Returns none if nil.
  let absIdx = lua_absindex(L, idx)
  if lua_isnoneornil(L, absIdx):
    return none(Service)
  if lua_type(L, absIdx) == LUA_TSTRING:
    let name = $lua_tostring(L, absIdx)
    if name in state.services:
      return some(state.services[name])
    else:
      discard luaL_error(L, "unknown service: '%s'", name.cstring)
  elif lua_istable(L, absIdx):
    let typ = getStringField(L, absIdx, "__type")
    let name = getStringField(L, absIdx, "__name")
    if typ == "service":
      if name in state.services:
        return some(state.services[name])
      else:
        discard luaL_error(L, "service handle refers to unknown service: '%s'", name.cstring)
  discard luaL_error(L, "expected service handle or string, got %s",
                     lua_typename(L, lua_type(L, absIdx)))

proc resolveHostAddr*(L: LuaState, state: FirewallState, idx: cint): string =
  ## Resolve a host handle or IP string to an address string.
  let absIdx = lua_absindex(L, idx)
  if lua_type(L, absIdx) == LUA_TSTRING:
    let s = $lua_tostring(L, absIdx)
    if s in state.hosts:
      return state.hosts[s].addr4
    return s  # raw IP string
  elif lua_istable(L, absIdx):
    let typ = getStringField(L, absIdx, "__type")
    let name = getStringField(L, absIdx, "__name")
    if typ == "host":
      if name in state.hosts:
        return state.hosts[name].addr4
  discard luaL_error(L, "expected host handle or IP string")
