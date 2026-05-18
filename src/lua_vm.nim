## lua_vm.nim - Sets up the Lua VM with fw:* and util:* API methods.
##
## The fw object is a Lua table whose methods are C functions (LuaCFunction).
## Each method retrieves the FirewallState from the Lua registry and operates on it.
##
## Zone/Host/Service handles returned to Lua are tables with a type tag
## so we can distinguish them when they're passed back as arguments.

import std/[os, options, tables, strutils]
import ./lua_ffi
import ./types

const
  ## Registry key for the FirewallState pointer
  stateRegistryKey = "matchstick.state"

  ## Registry key for the directory of the currently executing config file
  configDirRegistryKey = "matchstick.configdir"

  ## Metatable names for handle types
  zoneHandleMT*  = "matchstick.zone"
  hostHandleMT*  = "matchstick.host"
  serviceHandleMT* = "matchstick.service"

# ---------------------------------------------------------------------------
# Helpers: get state from Lua registry
# ---------------------------------------------------------------------------

proc getState(L: LuaState): FirewallState =
  ## Retrieve the FirewallState pointer from the Lua registry.
  discard lua_getfield(L, LUA_REGISTRYINDEX, stateRegistryKey)
  result = cast[FirewallState](lua_touserdata(L, -1))
  lua_pop(L, 1)

proc getConfigDir(L: LuaState): string =
  discard lua_getfield(L, LUA_REGISTRYINDEX, configDirRegistryKey)
  if lua_type(L, -1) == LUA_TSTRING:
    result = $lua_tostring(L, -1)
  lua_pop(L, 1)

proc setConfigDir(L: LuaState, dir: string) =
  discard lua_pushstring(L, dir.cstring)
  lua_setfield(L, LUA_REGISTRYINDEX, configDirRegistryKey)

proc getCurrentLine(L: LuaState): int =
  ## Get the current Lua source line number (for error messages).
  luaL_where(L, 1)
  let s = $lua_tostring(L, -1)
  lua_pop(L, 1)
  # Format is "filename:line: " -- extract the line number
  let parts = s.split(':')
  if parts.len >= 2:
    try: result = parseInt(parts[^2].strip())
    except: result = 0

# ---------------------------------------------------------------------------
# Helpers: read Lua arguments
# ---------------------------------------------------------------------------

proc getStringField(L: LuaState, idx: cint, key: string): string =
  ## Read a string field from a table at stack index `idx`. Returns "" if not present.
  discard lua_getfield(L, idx, key.cstring)
  if lua_type(L, -1) == LUA_TSTRING:
    result = $lua_tostring(L, -1)
  lua_pop(L, 1)

proc getBoolField(L: LuaState, idx: cint, key: string, default: bool): bool =
  ## Read a boolean field from a table. Returns `default` if not present.
  discard lua_getfield(L, idx, key.cstring)
  if lua_isboolean(L, -1):
    result = lua_toboolean(L, -1) != 0
  elif lua_isnoneornil(L, -1):
    result = default
  else:
    result = default
  lua_pop(L, 1)

proc getIntField(L: LuaState, idx: cint, key: string, default: int): int =
  discard lua_getfield(L, idx, key.cstring)
  if lua_isinteger(L, -1) != 0:
    result = int(lua_tointeger(L, -1))
  elif lua_isnoneornil(L, -1):
    result = default
  else:
    result = default
  lua_pop(L, 1)

proc getStringArray(L: LuaState, idx: cint): seq[string] =
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

proc getStringArrayField(L: LuaState, idx: cint, key: string): seq[string] =
  discard lua_getfield(L, idx, key.cstring)
  if not lua_isnoneornil(L, -1):
    result = getStringArray(L, -1)
  lua_pop(L, 1)

# ---------------------------------------------------------------------------
# Helpers: push handle tables back to Lua
# ---------------------------------------------------------------------------

proc pushZoneHandle(L: LuaState, zone: Zone) =
  ## Push a zone handle table onto the Lua stack.
  lua_newtable(L)
  discard lua_pushstring(L, zone.name.cstring)
  lua_setfield(L, -2, "__name")
  discard lua_pushstring(L, "zone")
  lua_setfield(L, -2, "__type")
  # Set the metatable so we can identify it
  discard luaL_getmetatable(L, zoneHandleMT)
  if lua_istable(L, -1):
    discard lua_setmetatable(L, -2)
  else:
    lua_pop(L, 1)

proc pushHostHandle(L: LuaState, host: Host) =
  lua_newtable(L)
  discard lua_pushstring(L, host.name.cstring)
  lua_setfield(L, -2, "__name")
  discard lua_pushstring(L, "host")
  lua_setfield(L, -2, "__type")
  discard luaL_getmetatable(L, hostHandleMT)
  if lua_istable(L, -1):
    discard lua_setmetatable(L, -2)
  else:
    lua_pop(L, 1)

proc pushServiceHandle(L: LuaState, svc: Service) =
  lua_newtable(L)
  discard lua_pushstring(L, svc.name.cstring)
  lua_setfield(L, -2, "__name")
  discard lua_pushstring(L, "service")
  lua_setfield(L, -2, "__type")
  discard luaL_getmetatable(L, serviceHandleMT)
  if lua_istable(L, -1):
    discard lua_setmetatable(L, -2)
  else:
    lua_pop(L, 1)

# ---------------------------------------------------------------------------
# Helpers: resolve endpoints (zone/host from handle or string)
# ---------------------------------------------------------------------------

proc resolveEndpoint(L: LuaState, state: FirewallState, idx: cint): Endpoint =
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

proc resolveService(L: LuaState, state: FirewallState, idx: cint): Option[Service] =
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

proc resolveHostAddr(L: LuaState, state: FirewallState, idx: cint): string =
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

# ---------------------------------------------------------------------------
# fw:zone(name, iface?, opts?)
# ---------------------------------------------------------------------------

proc fwZone(L: LuaState): cint {.cdecl.} =
  let state = getState(L)
  let line = getCurrentLine(L)

  # arg 1 is self (the fw table), arg 2 is name
  let name = $luaL_checkstring(L, 2)

  # Check name collision
  try:
    state.registerName(name, "zone", line)
  except CatchableError as e:
    discard luaL_error(L, e.msg.cstring)

  var zone = Zone(name: name, line: line)

  # arg 3: interface(s) -- string, array of strings, or absent (fw zone)
  if lua_type(L, 3) == LUA_TSTRING:
    zone.interfaces = @[$lua_tostring(L, 3)]
  elif lua_istable(L, 3):
    # Could be an array of strings (interfaces) or an options table
    # Check if it has string keys (options) or integer keys (array)
    discard lua_rawgeti(L, 3, 1)
    if lua_type(L, -1) == LUA_TSTRING:
      lua_pop(L, 1)
      # It's an array of interface names
      zone.interfaces = getStringArray(L, 3)
    else:
      lua_pop(L, 1)
      # It might be options table (for fw:zone("dock", "docker0", { bridge = true }))
      # but that's arg 4. If arg 3 is a table with no string[1], treat as empty.
      zone.bridge = getBoolField(L, 3, "bridge", false)
  # else: no interfaces (fw zone)

  # arg 4: options table (optional)
  if lua_istable(L, 4):
    zone.bridge = getBoolField(L, 4, "bridge", zone.bridge)

  state.zones[name] = zone
  pushZoneHandle(L, zone)
  return 1  # return the handle

# ---------------------------------------------------------------------------
# fw:host(name, { zone = z, addr = "..." })
# ---------------------------------------------------------------------------

proc fwHost(L: LuaState): cint {.cdecl.} =
  let state = getState(L)
  let line = getCurrentLine(L)

  let name = $luaL_checkstring(L, 2)
  luaL_checktype(L, 3, LUA_TTABLE)

  try:
    state.registerName(name, "host", line)
  except CatchableError as e:
    discard luaL_error(L, e.msg.cstring)

  # Resolve zone from opts.zone
  discard lua_getfield(L, 3, "zone")
  if lua_isnoneornil(L, -1):
    discard luaL_error(L, "fw:host '%s': missing 'zone' field", name.cstring)
  let ep = resolveEndpoint(L, state, -1)
  lua_pop(L, 1)

  let addr4 = getStringField(L, 3, "addr")
  if addr4 == "":
    discard luaL_error(L, "fw:host '%s': missing 'addr' field", name.cstring)

  var host = Host(
    name: name,
    zone: ep.zone,
    addr4: addr4,
    line: line,
  )

  state.hosts[name] = host
  pushHostHandle(L, host)
  return 1

# ---------------------------------------------------------------------------
# fw:service(name, proto, port?)
# ---------------------------------------------------------------------------

proc parseServiceArgs(L: LuaState, argStart: cint): seq[ServiceEntry] =
  ## Parse the proto and port arguments of fw:service().
  ## Supports:
  ##   fw:service("ssh", "tcp", 22)                      -- simple
  ##   fw:service("dns", {"tcp", "udp"}, 53)             -- multi-proto
  ##   fw:service("plex", {{"tcp", 32400}, {"udp", 1900}}) -- complex
  let protoIdx = argStart
  let portIdx = argStart + 1

  if lua_type(L, protoIdx) == LUA_TSTRING:
    # Simple or multi-proto: ("tcp", 22) or ("icmp", "echo-request")
    let proto = $lua_tostring(L, protoIdx)
    var port = ""
    if lua_isinteger(L, portIdx) != 0:
      port = $lua_tointeger(L, portIdx)
    elif lua_type(L, portIdx) == LUA_TSTRING:
      port = $lua_tostring(L, portIdx)
    result.add ServiceEntry(proto: proto, port: port)

  elif lua_istable(L, protoIdx):
    # Check first element to determine format
    discard lua_rawgeti(L, protoIdx, 1)
    if lua_type(L, -1) == LUA_TSTRING:
      lua_pop(L, 1)
      # Array of protocol strings: {"tcp", "udp"} with shared port
      let protos = getStringArray(L, protoIdx)
      var port = ""
      if lua_isinteger(L, portIdx) != 0:
        port = $lua_tointeger(L, portIdx)
      elif lua_type(L, portIdx) == LUA_TSTRING:
        port = $lua_tostring(L, portIdx)
      for p in protos:
        result.add ServiceEntry(proto: p, port: port)

    elif lua_istable(L, -1):
      lua_pop(L, 1)
      # Array of {proto, port} pairs: {{"tcp", 32400}, {"udp", 1900}}
      let len = luaL_len(L, protoIdx)
      for i in 1..len:
        discard lua_rawgeti(L, protoIdx, i.clonglong)
        if lua_istable(L, -1):
          discard lua_rawgeti(L, -1, 1)
          let proto = if lua_type(L, -1) == LUA_TSTRING: $lua_tostring(L, -1) else: ""
          lua_pop(L, 1)
          discard lua_rawgeti(L, -1, 2)
          var port = ""
          if lua_isinteger(L, -1) != 0:
            port = $lua_tointeger(L, -1)
          elif lua_type(L, -1) == LUA_TSTRING:
            port = $lua_tostring(L, -1)
          lua_pop(L, 1)
          if proto != "":
            result.add ServiceEntry(proto: proto, port: port)
        lua_pop(L, 1)
    else:
      lua_pop(L, 1)
      discard luaL_error(L, "fw:service: invalid protocol argument")

proc fwService(L: LuaState): cint {.cdecl.} =
  let state = getState(L)
  let line = getCurrentLine(L)

  let name = $luaL_checkstring(L, 2)
  let entries = parseServiceArgs(L, 3)

  if entries.len == 0:
    discard luaL_error(L, "fw:service '%s': no protocol/port entries", name.cstring)

  var svc = Service(name: name, entries: entries, line: line)
  state.services[name] = svc
  pushServiceHandle(L, svc)
  return 1

# ---------------------------------------------------------------------------
# fw:laundry({ rpfilter = true, ... })
# ---------------------------------------------------------------------------

proc fwLaundry(L: LuaState): cint {.cdecl.} =
  let state = getState(L)
  if lua_istable(L, 2):
    state.laundry.rpfilter = getBoolField(L, 2, "rpfilter", true)
    state.laundry.bogonDrop = getBoolField(L, 2, "bogon_drop", true)
    state.laundry.tcpStrict = getBoolField(L, 2, "tcp_strict", true)
    state.laundry.broadcastDrop = getBoolField(L, 2, "broadcast_drop", true)
  return 0

# ---------------------------------------------------------------------------
# fw:dhcp(zone, "client"/"server")
# ---------------------------------------------------------------------------

proc fwDhcp(L: LuaState): cint {.cdecl.} =
  let state = getState(L)
  let line = getCurrentLine(L)

  let ep = resolveEndpoint(L, state, 2)
  let roleStr = $luaL_checkstring(L, 3)

  let role = case roleStr
    of "client": dhcpClient
    of "server": dhcpServer
    else:
      discard luaL_error(L, "fw:dhcp: role must be 'client' or 'server', got '%s'", roleStr.cstring)
      dhcpClient  # unreachable

  if ep.zone == nil:
    discard luaL_error(L, "fw:dhcp: zone is required")
  if ep.zone.interfaces.len == 0:
    discard luaL_error(L, "fw:dhcp: zone '%s' has no interfaces", ep.zone.name.cstring)

  state.dhcp.add DhcpConfig(zone: ep.zone, role: role, line: line)
  return 0

# ---------------------------------------------------------------------------
# fw:policy(from, to, action, opts?)
# ---------------------------------------------------------------------------

proc fwPolicy(L: LuaState): cint {.cdecl.} =
  let state = getState(L)
  let line = getCurrentLine(L)

  let src = resolveEndpoint(L, state, 2)
  let dst = resolveEndpoint(L, state, 3)
  let actionStr = $luaL_checkstring(L, 4)

  let action = case actionStr
    of "accept": actAccept
    of "drop": actDrop
    of "reject": actReject
    else:
      discard luaL_error(L, "fw:policy: action must be accept/drop/reject, got '%s'", actionStr.cstring)
      actDrop

  var log = false
  if lua_istable(L, 5):
    log = getBoolField(L, 5, "log", false)

  state.policies.add Policy(src: src, dst: dst, action: action, log: log, line: line)
  return 0

# ---------------------------------------------------------------------------
# fw:rule(from, to, action, service_or_table)
# ---------------------------------------------------------------------------

proc fwRule(L: LuaState): cint {.cdecl.} =
  let state = getState(L)
  let line = getCurrentLine(L)

  let src = resolveEndpoint(L, state, 2)
  let dst = resolveEndpoint(L, state, 3)
  let actionStr = $luaL_checkstring(L, 4)

  let action = case actionStr
    of "accept": actAccept
    of "drop": actDrop
    of "reject": actReject
    else:
      discard luaL_error(L, "fw:rule: action must be accept/drop/reject, got '%s'", actionStr.cstring)
      actDrop

  var rule = Rule(src: src, dst: dst, action: action, line: line)

  # arg 5: service handle, service string, table with options, or absent (match all)
  if lua_isnoneornil(L, 5):
    discard  # No service/port filter = match all traffic (bare rule)

  elif lua_type(L, 5) == LUA_TSTRING:
    # String service name
    rule.service = resolveService(L, state, 5)

  elif lua_istable(L, 5):
    # Check if it's a service handle or an options table
    let typ = getStringField(L, 5, "__type")
    if typ == "service":
      rule.service = resolveService(L, state, 5)
    else:
      # Options table
      discard lua_getfield(L, 5, "service")
      if not lua_isnoneornil(L, -1):
        rule.service = resolveService(L, state, -1)
      lua_pop(L, 1)

      rule.proto = getStringArrayField(L, 5, "proto")
      rule.port = getStringArrayField(L, 5, "port")
      rule.saddrList = getStringField(L, 5, "saddr_list")
      rule.log = getStringField(L, 5, "log")

      # Rate limit
      discard lua_getfield(L, 5, "rate")
      if lua_istable(L, -1):
        let rate = RateLimit(
          rate: getStringField(L, -1, "rate"),
          burst: getIntField(L, -1, "burst", 0),
          name: getStringField(L, -1, "name"),
        )
        rule.rate = some(rate)
      lua_pop(L, 1)

  state.rules.add rule
  return 0

# ---------------------------------------------------------------------------
# fw:dnat({ iface = ..., proto = ..., port = ..., dest = ..., ... })
# ---------------------------------------------------------------------------

proc fwDnat(L: LuaState): cint {.cdecl.} =
  let state = getState(L)
  let line = getCurrentLine(L)
  luaL_checktype(L, 2, LUA_TTABLE)

  # Resolve iface (zone)
  discard lua_getfield(L, 2, "iface")
  if lua_isnoneornil(L, -1):
    discard luaL_error(L, "fw:dnat: missing 'iface' field")
  let ifaceEp = resolveEndpoint(L, state, -1)
  lua_pop(L, 1)

  # Resolve dest
  discard lua_getfield(L, 2, "dest")
  if lua_isnoneornil(L, -1):
    discard luaL_error(L, "fw:dnat: missing 'dest' field")
  let dest = resolveHostAddr(L, state, -1)
  lua_pop(L, 1)

  var dnat = DnatRule(
    iface: ifaceEp.zone,
    daddr: getStringField(L, 2, "daddr"),
    proto: getStringArrayField(L, 2, "proto"),
    port: getStringArrayField(L, 2, "port"),
    dest: dest,
    destPort: getIntField(L, 2, "dest_port", 0),
    line: line,
  )

  # Resolve service if present
  discard lua_getfield(L, 2, "service")
  if not lua_isnoneornil(L, -1):
    dnat.service = resolveService(L, state, -1)
  lua_pop(L, 1)

  state.dnatRules.add dnat
  return 0

# ---------------------------------------------------------------------------
# fw:snat({ from = ..., oif = ..., masquerade = true, ... })
# ---------------------------------------------------------------------------

proc fwSnat(L: LuaState): cint {.cdecl.} =
  let state = getState(L)
  let line = getCurrentLine(L)
  luaL_checktype(L, 2, LUA_TTABLE)

  var snat = SnatRule(
    fromNet: getStringField(L, 2, "from"),
    daddr: getStringField(L, 2, "daddr"),
    oif: getStringField(L, 2, "oif"),
    masquerade: getBoolField(L, 2, "masquerade", false),
    addr4: getStringField(L, 2, "addr"),
    proto: getStringField(L, 2, "proto"),
    port: getStringArrayField(L, 2, "port"),
    line: line,
  )

  if snat.fromNet == "":
    discard luaL_error(L, "fw:snat: missing 'from' field")
  if snat.oif == "":
    discard luaL_error(L, "fw:snat: missing 'oif' field")
  if snat.masquerade and snat.addr4 != "":
    discard luaL_error(L, "fw:snat: 'masquerade' and 'addr' are mutually exclusive")
  if not snat.masquerade and snat.addr4 == "":
    discard luaL_error(L, "fw:snat: must specify either 'masquerade = true' or 'addr'")
  if snat.port.len > 0 and snat.proto == "":
    discard luaL_error(L, "fw:snat: 'port' requires 'proto'")

  state.snatRules.add snat
  return 0

# ---------------------------------------------------------------------------
# fw:iplist(name, { type = "ipv4", flags = "timeout", elements = {...} })
# ---------------------------------------------------------------------------

proc fwIplist(L: LuaState): cint {.cdecl.} =
  let state = getState(L)
  let line = getCurrentLine(L)

  let name = $luaL_checkstring(L, 2)
  luaL_checktype(L, 3, LUA_TTABLE)

  var iplist = IpList(
    name: name,
    ipType: getStringField(L, 3, "type"),
    flags: getStringField(L, 3, "flags"),
    elements: getStringArrayField(L, 3, "elements"),
    line: line,
  )

  if iplist.ipType == "":
    discard luaL_error(L, "fw:iplist '%s': missing 'type' field", name.cstring)

  state.ipLists[name] = iplist
  return 0

# ---------------------------------------------------------------------------
# fw:docker({ bridges = {...}, backend = "nftables" })
# ---------------------------------------------------------------------------

proc fwDocker(L: LuaState): cint {.cdecl.} =
  let state = getState(L)
  luaL_checktype(L, 2, LUA_TTABLE)

  state.docker = some(DockerConfig(
    backend: getStringField(L, 2, "backend"),
    bridges: getStringArrayField(L, 2, "bridges"),
  ))
  return 0

# ---------------------------------------------------------------------------
# fw:config({ table_name = ..., priority_offset = ..., ... })
# ---------------------------------------------------------------------------

proc fwConfig(L: LuaState): cint {.cdecl.} =
  let state = getState(L)
  luaL_checktype(L, 2, LUA_TTABLE)

  let tn = getStringField(L, 2, "table_name")
  if tn != "": state.config.tableName = tn

  let po = getIntField(L, 2, "priority_offset", state.config.priorityOffset)
  state.config.priorityOffset = po

  let lr = getStringField(L, 2, "log_rate")
  if lr != "": state.config.logRate = lr

  let lp = getStringField(L, 2, "log_prefix")
  if lp != "": state.config.logPrefix = lp

  let ll = getStringField(L, 2, "log_level")
  if ll != "": state.config.logLevel = ll

  return 0

# ---------------------------------------------------------------------------
# fw:include("path.lua")
# ---------------------------------------------------------------------------

proc fwInclude(L: LuaState): cint {.cdecl.} =
  let state = getState(L)
  let path = $luaL_checkstring(L, 2)

  # Resolve relative to the current config file's directory
  let configDir = getConfigDir(L)
  let fullPath = if path.isAbsolute: path
                 else: configDir / path

  if not fileExists(fullPath):
    discard luaL_error(L, "fw:include: file not found: '%s'", fullPath.cstring)

  # Check for duplicate includes
  if fullPath in state.includedFiles:
    state.warnings.add "warning: file already included: " & fullPath
  state.includedFiles.add fullPath

  # Save current config dir, set new one
  let prevDir = configDir
  setConfigDir(L, fullPath.parentDir)

  # Load and execute the file
  var status = luaL_loadfile(L, fullPath.cstring)
  if status != LUA_OK:
    discard luaL_error(L, "fw:include: %s", lua_tostring(L, -1))

  status = lua_pcall(L, 0, LUA_MULTRET, 0)
  if status != LUA_OK:
    discard luaL_error(L, "fw:include: %s", lua_tostring(L, -1))

  # Restore previous config dir
  setConfigDir(L, prevDir)

  # Return whatever the included file returned
  return lua_gettop(L)

# ---------------------------------------------------------------------------
# util:rate("5/minute", { burst = 5, name = "ssh_limit" })
# ---------------------------------------------------------------------------

proc utilRate(L: LuaState): cint {.cdecl.} =
  let rateStr = $luaL_checkstring(L, 2)

  var burst = 0
  var name = ""
  if lua_istable(L, 3):
    burst = getIntField(L, 3, "burst", 0)
    name = getStringField(L, 3, "name")

  # Return a table with rate info (consumed by fw:rule)
  lua_newtable(L)
  discard lua_pushstring(L, rateStr.cstring)
  lua_setfield(L, -2, "rate")
  lua_pushinteger(L, burst.clonglong)
  lua_setfield(L, -2, "burst")
  if name != "":
    discard lua_pushstring(L, name.cstring)
    lua_setfield(L, -2, "name")

  return 1

# ---------------------------------------------------------------------------
# Register all APIs into a Lua state
# ---------------------------------------------------------------------------

proc registerMethod(L: LuaState, tableIdx: cint, name: string, fn: LuaCFunction) =
  let absIdx = lua_absindex(L, tableIdx)
  lua_pushcfunction(L, fn)
  lua_setfield(L, absIdx, name.cstring)

proc setupLuaVM*(L: LuaState, state: FirewallState, configFile: string) =
  ## Register fw and util globals, store state in registry.

  # Store FirewallState pointer in registry
  lua_pushlightuserdata(L, cast[pointer](state))
  lua_setfield(L, LUA_REGISTRYINDEX, stateRegistryKey)

  # Store config file directory in registry
  setConfigDir(L, configFile.absolutePath.parentDir)

  # Create metatables for handle types (for identification)
  discard luaL_newmetatable(L, zoneHandleMT)
  lua_pop(L, 1)
  discard luaL_newmetatable(L, hostHandleMT)
  lua_pop(L, 1)
  discard luaL_newmetatable(L, serviceHandleMT)
  lua_pop(L, 1)

  # Create the "fw" global table
  lua_newtable(L)
  registerMethod(L, -1, "zone", fwZone)
  registerMethod(L, -1, "host", fwHost)
  registerMethod(L, -1, "service", fwService)
  registerMethod(L, -1, "laundry", fwLaundry)
  registerMethod(L, -1, "dhcp", fwDhcp)
  registerMethod(L, -1, "policy", fwPolicy)
  registerMethod(L, -1, "rule", fwRule)
  registerMethod(L, -1, "dnat", fwDnat)
  registerMethod(L, -1, "snat", fwSnat)
  registerMethod(L, -1, "iplist", fwIplist)
  registerMethod(L, -1, "docker", fwDocker)
  registerMethod(L, -1, "config", fwConfig)
  registerMethod(L, -1, "include", fwInclude)
  lua_setglobal(L, "fw")

  # Create the "util" global table
  lua_newtable(L)
  registerMethod(L, -1, "rate", utilRate)
  lua_setglobal(L, "util")
