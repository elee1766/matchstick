## lua/api.nim - fw:* and util:* API method implementations.
##
## Each method is a LuaCFunction that retrieves FirewallState from the
## Lua registry and operates on it. setupLuaVM registers them all.

import std/[os, options, tables]
import ./ffi
import ./helpers
import ../types

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
  pushHandle(L, zone.name, "zone", zoneHandleMT)
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
  pushHandle(L, host.name, "host", hostHandleMT)
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
  pushHandle(L, svc.name, "service", serviceHandleMT)
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

  let action = parseAction(L, actionStr, "fw:policy")

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

  let action = parseAction(L, actionStr, "fw:rule")

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

      # Raw daddr (IP string for forward rules to specific destinations)
      let rawDaddr = getStringField(L, 5, "daddr")
      if rawDaddr != "":
        # Could be a host handle name or raw IP
        if rawDaddr in state.hosts:
          rule.daddrRaw = state.hosts[rawDaddr].addr4
        else:
          rule.daddrRaw = rawDaddr

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

  let fam = getStringField(L, 2, "family")
  if fam != "": state.config.family = fam

  state.config.logSetSize = getIntField(L, 2, "log_set_size", state.config.logSetSize)
  state.config.logSetTimeout = getIntField(L, 2, "log_set_timeout", state.config.logSetTimeout)
  state.config.counter = getBoolField(L, 2, "counter", state.config.counter)

  let ip = getStringField(L, 2, "input_policy")
  if ip != "": state.config.inputPolicy = ip

  let op = getStringField(L, 2, "output_policy")
  if op != "": state.config.outputPolicy = op

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
