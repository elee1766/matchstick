## lua/api.nim - fw:* and util:* API method implementations.
##
## Each method is a LuaCFunction that retrieves FirewallState from the
## Lua registry and operates on it. setupLuaVM registers them all.

import std/[os, options, tables, json, strutils, algorithm]
import ../../lua55/ffi
import ./helpers
import ../types

# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

const
  maxNameLen = 64
  maxStringLen = 256
  maxPortVal = 65535
  maxConnLimit = 1000000
  hexChars = {'0'..'9', 'a'..'f', 'A'..'F'}
  sysctlKeyChars = {'a'..'z', 'A'..'Z', '0'..'9', '_', '.'}

proc checkLen(L: LuaState, s: string, maxLen: int, ctx: string) =
  if s.len > maxLen:
    discard luaL_error(L, "%s: value too long (%d chars, max %d)", ctx.cstring, s.len.cint, maxLen.cint)

proc checkIdent(L: LuaState, s: string, ctx: string) =
  ## Validate identifier: 1-64 chars, alphanumeric + hyphen + underscore.
  if s.len == 0 or s.len > maxNameLen:
    discard luaL_error(L, "%s: name must be 1-%d chars, got %d", ctx.cstring, maxNameLen.cint, s.len.cint)
  for c in s:
    if c notin {'a'..'z', 'A'..'Z', '0'..'9', '_', '-'}:
      discard luaL_error(L, "%s: invalid character '%c' (alphanumeric, hyphen, underscore only)", ctx.cstring, c)

proc checkIface(L: LuaState, s: string, ctx: string) =
  ## Validate interface name: 1-15 chars, alphanumeric + hyphen + underscore + dot + plus (wildcard).
  if s.len == 0 or s.len > 15:
    discard luaL_error(L, "%s: interface name must be 1-15 chars, got '%s'", ctx.cstring, s.cstring)
  for c in s:
    if c notin {'a'..'z', 'A'..'Z', '0'..'9', '_', '-', '.', '+'}:
      discard luaL_error(L, "%s: invalid character '%c' in interface name", ctx.cstring, c)

proc checkNoShellMeta(L: LuaState, s: string, ctx: string) =
  ## Reject shell metacharacters that could enable injection.
  for c in s:
    if c in {';', '|', '&', '`', '$', '(', ')', '{', '}', '<', '>', '\n', '\r', '\0'}:
      discard luaL_error(L, "%s: contains unsafe character '%c'", ctx.cstring, c)

proc checkMac(L: LuaState, mac: string, ctx: string) =
  ## Validate MAC address format: aa:bb:cc:dd:ee:ff (17 chars, hex pairs with colons).
  var valid = mac.len == 17
  if valid:
    for i, c in mac:
      if i mod 3 == 2:
        if c != ':': valid = false; break
      else:
        if c notin hexChars: valid = false; break
  if not valid:
    discard luaL_error(L, "%s: invalid MAC address '%s' (expected aa:bb:cc:dd:ee:ff)", ctx.cstring, mac.cstring)

# ---------------------------------------------------------------------------
# fw:zone(name, iface?, opts?)
# ---------------------------------------------------------------------------

proc fwZone(L: LuaState): cint {.cdecl.} =
  let state = getState(L)
  let line = getCurrentLine(L)

  let name = $luaL_checkstring(L, 2)
  checkIdent(L, name, "fw:zone")

  # Check name collision
  try:
    state.registerName(name, "zone", line)
  except CatchableError as e:
    discard luaL_error(L, e.msg.cstring)

  var zone = Zone(name: name, line: line)

  # arg 3: interface(s) -- string, array of strings, or absent (fw zone)
  if lua_type(L, 3) == LUA_TSTRING:
    let iface = $lua_tostring(L, 3)
    checkIface(L, iface, "fw:zone '" & name & "'")
    zone.interfaces = @[iface]
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
  checkIdent(L, name, "fw:host")
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
  checkLen(L, addr4, 45, "fw:host '" & name & "' addr")  # max IPv6 length
  checkNoShellMeta(L, addr4, "fw:host '" & name & "' addr")

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
  checkIdent(L, name, "fw:service")
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
      if rule.saddrList != "":
        checkIdent(L, rule.saddrList, "fw:rule saddr_list")
      rule.daddrList = getStringField(L, 5, "daddr_list")
      if rule.daddrList != "":
        checkIdent(L, rule.daddrList, "fw:rule daddr_list")

      let mac = getStringField(L, 5, "mac")
      if mac != "":
        checkMac(L, mac, "fw:rule")
        rule.macAddr = mac

      let cl = getIntField(L, 5, "connlimit", 0)
      if cl < 0 or cl > maxConnLimit:
        discard luaL_error(L, "fw:rule: connlimit must be 0-%d, got %d", maxConnLimit.cint, cl.cint)
      rule.connLimit = cl

      rule.log = getStringField(L, 5, "log")
      if rule.log != "":
        checkLen(L, rule.log, maxStringLen, "fw:rule log")
        checkNoShellMeta(L, rule.log, "fw:rule log")

      # Raw daddr (IP string for forward rules to specific destinations)
      let rawDaddr = getStringField(L, 5, "daddr")
      if rawDaddr != "":
        checkLen(L, rawDaddr, 45, "fw:rule daddr")
        checkNoShellMeta(L, rawDaddr, "fw:rule daddr")
        if rawDaddr in state.hosts:
          rule.daddrRaw = state.hosts[rawDaddr].addr4
        else:
          rule.daddrRaw = rawDaddr

      rule.comment = getStringField(L, 5, "comment")
      if rule.comment != "":
        checkLen(L, rule.comment, maxStringLen, "fw:rule comment")

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
  checkIdent(L, name, "fw:iplist")
  luaL_checktype(L, 3, LUA_TTABLE)

  var iplist = IpList(
    name: name,
    ipType: getStringField(L, 3, "type"),
    flags: getStringField(L, 3, "flags"),
    elements: getStringArrayField(L, 3, "elements"),
    url: getStringField(L, 3, "url"),
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

const
  validPolicies = ["accept", "drop"]
  validFamilies = ["inet", "ip"]

proc fwConfig(L: LuaState): cint {.cdecl.} =
  let state = getState(L)
  luaL_checktype(L, 2, LUA_TTABLE)

  let tn = getStringField(L, 2, "table_name")
  if tn != "":
    checkIdent(L, tn, "fw:config table_name")
    state.config.tableName = tn

  let po = getIntField(L, 2, "priority_offset", state.config.priorityOffset)
  state.config.priorityOffset = po

  let lr = getStringField(L, 2, "log_rate")
  if lr != "":
    checkLen(L, lr, maxStringLen, "fw:config log_rate")
    checkNoShellMeta(L, lr, "fw:config log_rate")
    state.config.logRate = lr

  let lp = getStringField(L, 2, "log_prefix")
  if lp != "":
    # Validate no nftables-breaking characters
    for c in lp:
      if c in {'"', '\\', '\n', '\r'}:
        discard luaL_error(L, "fw:config: log_prefix must not contain quotes, backslashes, or newlines")
    state.config.logPrefix = lp

  let ll = getStringField(L, 2, "log_level")
  if ll != "":
    const validLogLevels = ["emerg", "alert", "crit", "err", "warn", "notice", "info", "debug"]
    if ll notin validLogLevels:
      discard luaL_error(L, "fw:config: log_level must be one of emerg/alert/crit/err/warn/notice/info/debug, got '%s'", ll.cstring)
    state.config.logLevel = ll

  let fam = getStringField(L, 2, "family")
  if fam != "":
    if fam notin validFamilies:
      discard luaL_error(L, "fw:config: family must be 'inet' or 'ip', got '%s'", fam.cstring)
    state.config.family = fam

  state.config.logSetSize = getIntField(L, 2, "log_set_size", state.config.logSetSize)
  state.config.logSetTimeout = getIntField(L, 2, "log_set_timeout", state.config.logSetTimeout)
  state.config.counter = getBoolField(L, 2, "counter", state.config.counter)

  let ip = getStringField(L, 2, "input_policy")
  if ip != "":
    if ip notin validPolicies:
      discard luaL_error(L, "fw:config: input_policy must be 'accept' or 'drop', got '%s'", ip.cstring)
    state.config.inputPolicy = ip

  let op = getStringField(L, 2, "output_policy")
  if op != "":
    if op notin validPolicies:
      discard luaL_error(L, "fw:config: output_policy must be 'accept' or 'drop', got '%s'", op.cstring)
    state.config.outputPolicy = op

  return 0

# ---------------------------------------------------------------------------
# fw:sysctl(key, value) or fw:sysctl({ key = value, ... })
# ---------------------------------------------------------------------------

const sysctlValueChars = {' ', '0'..'9', 'a'..'z', 'A'..'Z', '_', '-', '.', ','}
const maxSysctlValueLen = 256

const allowedSysctlPrefixes = [
  "net.ipv4.", "net.ipv6.", "net.core.", "net.bridge.", "net.netfilter.",
]

proc validateSysctlKey(L: LuaState, key: string) =
  if key.len == 0 or key.len > 256:
    discard luaL_error(L, "fw:sysctl: key must be 1-256 chars, got %d", key.len.cint)
  for c in key:
    if c notin sysctlKeyChars:
      discard luaL_error(L, "fw:sysctl: key '%s' contains invalid character '%c' (alphanumeric, underscore, dots only)", key.cstring, c)
  if key.startsWith(".") or key.endsWith(".") or ".." in key:
    discard luaL_error(L, "fw:sysctl: key '%s' has invalid dot placement", key.cstring)
  # Restrict to networking-related sysctl namespaces only.
  # Non-network sysctls (kernel.*, vm.*, etc.) can weaken system security
  # (e.g. disabling ASLR, enabling SysRq, changing core_pattern).
  var allowed = false
  for prefix in allowedSysctlPrefixes:
    if key.startsWith(prefix):
      allowed = true
      break
  if not allowed:
    discard luaL_error(L, "fw:sysctl: key '%s' is outside allowed namespaces (net.ipv4/ipv6/core/bridge/netfilter)", key.cstring)

proc validateSysctlValue(L: LuaState, key, value: string) =
  if value.len == 0 or value.len > maxSysctlValueLen:
    discard luaL_error(L, "fw:sysctl: value for '%s' must be 1-%d chars, got %d",
                       key.cstring, maxSysctlValueLen.cint, value.len.cint)
  for c in value:
    if c notin sysctlValueChars:
      discard luaL_error(L, "fw:sysctl: value for '%s' contains unsafe character (0x%02x)",
                         key.cstring, ord(c).cint)

proc fwSysctl(L: LuaState): cint {.cdecl.} =
  ## fw:sysctl("key", "value")  -- set a sysctl
  ## fw:sysctl("key", false)    -- unset (don't touch this sysctl)
  ## fw:sysctl({ key = "value", key2 = false, ... })  -- batch set/unset
  let state = getState(L)

  if lua_type(L, 2) == LUA_TSTRING:
    let key = $luaL_checkstring(L, 2)
    validateSysctlKey(L, key)
    if lua_isboolean(L, 3) and lua_toboolean(L, 3) == 0:
      # fw:sysctl("key", false) -- unset
      state.sysctlOverrides.add SysctlEntry(key: key, unset: true)
    elif lua_type(L, 3) == LUA_TSTRING:
      let value = $lua_tostring(L, 3)
      validateSysctlValue(L, key, value)
      state.sysctlOverrides.add SysctlEntry(key: key, value: value)
    elif lua_isinteger(L, 3) != 0:
      let value = $lua_tointeger(L, 3)
      validateSysctlValue(L, key, value)
      state.sysctlOverrides.add SysctlEntry(key: key, value: value)
    else:
      discard luaL_error(L, "fw:sysctl: value must be a string, integer, or false")
  elif lua_istable(L, 2):
    lua_pushnil(L)
    while lua_next(L, 2) != 0:
      if lua_type(L, -2) == LUA_TSTRING:
        let key = $lua_tostring(L, -2)
        validateSysctlKey(L, key)
        if lua_isboolean(L, -1) and lua_toboolean(L, -1) == 0:
          state.sysctlOverrides.add SysctlEntry(key: key, unset: true)
        elif lua_type(L, -1) == LUA_TSTRING:
          let value = $lua_tostring(L, -1)
          validateSysctlValue(L, key, value)
          state.sysctlOverrides.add SysctlEntry(key: key, value: value)
        elif lua_isinteger(L, -1) != 0:
          let value = $lua_tointeger(L, -1)
          validateSysctlValue(L, key, value)
          state.sysctlOverrides.add SysctlEntry(key: key, value: value)
      lua_pop(L, 1)
  else:
    discard luaL_error(L, "fw:sysctl: expected (key, value) strings or a table")

  return 0

# ---------------------------------------------------------------------------
# fw:redirect({ iface = ..., proto = ..., port = ..., dest_port = ... })
# ---------------------------------------------------------------------------

proc fwRedirect(L: LuaState): cint {.cdecl.} =
  let state = getState(L)
  let line = getCurrentLine(L)
  luaL_checktype(L, 2, LUA_TTABLE)

  discard lua_getfield(L, 2, "iface")
  if lua_isnoneornil(L, -1):
    discard luaL_error(L, "fw:redirect: missing 'iface' field")
  let ifaceEp = resolveEndpoint(L, state, -1)
  lua_pop(L, 1)

  let destPort = getIntField(L, 2, "dest_port", 0)
  if destPort == 0:
    discard luaL_error(L, "fw:redirect: missing 'dest_port' field")

  var redir = RedirectRule(
    iface: ifaceEp.zone,
    proto: getStringArrayField(L, 2, "proto"),
    port: getStringArrayField(L, 2, "port"),
    destPort: destPort,
    line: line,
  )

  if redir.proto.len == 0:
    discard luaL_error(L, "fw:redirect: missing 'proto' field")

  state.redirectRules.add redir
  return 0

# ---------------------------------------------------------------------------
# fw:mss_clamp(chain?, size?)
# ---------------------------------------------------------------------------

proc fwMssClamp(L: LuaState): cint {.cdecl.} =
  ## fw:mss_clamp()              -- clamp on forward chain, auto PMTUD
  ## fw:mss_clamp("forward")     -- clamp on specific chain
  ## fw:mss_clamp("forward", 1400) -- clamp to specific size (uncommon)
  let state = getState(L)

  var chain = "forward"
  if lua_type(L, 2) == LUA_TSTRING:
    chain = $lua_tostring(L, 2)

  if chain notin ["forward", "output", "postrouting"]:
    discard luaL_error(L, "fw:mss_clamp: chain must be forward/output/postrouting, got '%s'", chain.cstring)

  state.mssClamp.add chain
  return 0

# ---------------------------------------------------------------------------
# fw:hook({ pre_start = "...", post_start = "...", ... })
# ---------------------------------------------------------------------------

proc fwHook(L: LuaState): cint {.cdecl.} =
  let state = getState(L)
  luaL_checktype(L, 2, LUA_TTABLE)

  let ps = getStringField(L, 2, "pre_start")
  if ps != "": state.hooks.preStart = ps

  let pos = getStringField(L, 2, "post_start")
  if pos != "": state.hooks.postStart = pos

  let prs = getStringField(L, 2, "pre_stop")
  if prs != "": state.hooks.preStop = prs

  let post = getStringField(L, 2, "post_stop")
  if post != "": state.hooks.postStop = post

  return 0

# ---------------------------------------------------------------------------
# fw:chain(hook, { type = "filter", priority = "mangle", rules = {...} })
# ---------------------------------------------------------------------------

const validHooks = ["prerouting", "postrouting", "forward", "input", "output"]
const validChainTypes = ["filter", "nat", "route"]
const validPriorities = ["raw", "mangle", "filter", "security", "srcnat", "dstnat"]

proc fwChain(L: LuaState): cint {.cdecl.} =
  let state = getState(L)
  let line = getCurrentLine(L)

  let hook = $luaL_checkstring(L, 2)
  luaL_checktype(L, 3, LUA_TTABLE)

  if hook notin validHooks:
    discard luaL_error(L, "fw:chain: hook must be one of prerouting/postrouting/forward/input/output, got '%s'", hook.cstring)

  let chainType = getStringField(L, 3, "type")
  if chainType == "":
    discard luaL_error(L, "fw:chain: missing 'type' field (filter/nat/route)")
  if chainType notin validChainTypes:
    discard luaL_error(L, "fw:chain: type must be filter/nat/route, got '%s'", chainType.cstring)

  let priority = getStringField(L, 3, "priority")
  if priority == "":
    discard luaL_error(L, "fw:chain: missing 'priority' field (raw/mangle/filter/security/srcnat/dstnat or a number)")

  # Rules: array of nftables JSON rule expr objects (Lua tables)
  discard lua_getfield(L, 3, "rules")
  if lua_isnoneornil(L, -1):
    lua_pop(L, 1)
    discard luaL_error(L, "fw:chain: missing 'rules' field (array of nftables JSON rule objects)")
  if not lua_istable(L, -1):
    lua_pop(L, 1)
    discard luaL_error(L, "fw:chain: 'rules' must be a table (array of nftables JSON rule objects)")

  let rulesLen = luaL_len(L, -1)
  if rulesLen == 0:
    lua_pop(L, 1)
    discard luaL_error(L, "fw:chain: 'rules' must not be empty")

  var rules: seq[JsonNode]
  for i in 1..rulesLen:
    discard lua_rawgeti(L, -1, i.clonglong)
    if not lua_istable(L, -1):
      lua_pop(L, 2)
      discard luaL_error(L, "fw:chain: each rule must be a table (nftables JSON rule expr)")
    rules.add luaToJson(L, -1)
    lua_pop(L, 1)
  lua_pop(L, 1)  # pop rules table

  state.customChains.add CustomChain(
    hook: hook,
    chainType: chainType,
    priority: priority,
    rules: rules,
    line: line,
  )
  return 0

# ---------------------------------------------------------------------------
# fw:raw_nft("raw nftables line", ...)
# ---------------------------------------------------------------------------

proc fwRawNft(L: LuaState): cint {.cdecl.} =
  ## Accept nftables JSON command objects as Lua tables.
  ## Each argument should be a table representing a single nftables JSON command,
  ## e.g. { add = { chain = { family = "inet", table = "matchstick", name = "my_chain" } } }
  let state = getState(L)
  let nargs = lua_gettop(L)
  for i in 2.cint .. nargs:
    if lua_istable(L, i):
      state.rawNft.add luaToJson(L, i)
    else:
      discard luaL_error(L, "fw:raw_nft: argument %d must be a table (nftables JSON command object)", i - 1)
  return 0

# ---------------------------------------------------------------------------
# fw:exception(chain, action, service_or_opts?)
# ---------------------------------------------------------------------------

const validExceptionChains = ["invalid", "rpfilter", "anti_smurf"]

proc fwException(L: LuaState): cint {.cdecl.} =
  let state = getState(L)
  let line = getCurrentLine(L)

  let chain = $luaL_checkstring(L, 2)
  let actionStr = $luaL_checkstring(L, 3)

  if chain notin validExceptionChains:
    discard luaL_error(L, "fw:exception: chain must be one of invalid/rpfilter/anti_smurf, got '%s'", chain.cstring)

  let action = parseAction(L, actionStr, "fw:exception")

  var exc = ChainException(chain: chain, action: action, line: line)

  # arg 4: service handle, service string, or options table (optional)
  if not lua_isnoneornil(L, 4):
    if lua_type(L, 4) == LUA_TSTRING:
      exc.service = resolveService(L, state, 4)
    elif lua_istable(L, 4):
      let typ = getStringField(L, 4, "__type")
      if typ == "service":
        exc.service = resolveService(L, state, 4)
      else:
        discard lua_getfield(L, 4, "service")
        if not lua_isnoneornil(L, -1):
          exc.service = resolveService(L, state, -1)
        lua_pop(L, 1)
        exc.proto = getStringArrayField(L, 4, "proto")
        exc.port = getStringArrayField(L, 4, "port")

  state.chainExceptions.add exc
  return 0

# ---------------------------------------------------------------------------
# fw:include("path.lua")
# ---------------------------------------------------------------------------

const maxIncludeDepth = 8  # Each level uses ~10 Lua C stack slots; keep well under LUAI_MAXCSTACK

proc includeOneFile(L: LuaState, state: FirewallState, fullPath: string) =
  ## Load and execute a single Lua file. Handles depth limit, duplicate
  ## detection, config dir switching, and frame state safety.
  if state.includedFiles.len >= maxIncludeDepth:
    discard luaL_error(L, "fw:include: maximum include depth (%d) exceeded", maxIncludeDepth.cint)

  if fullPath in state.includedFiles:
    state.warnings.add "warning: file already included: " & fullPath
  state.includedFiles.add fullPath

  let prevDir = getConfigDir(L)
  setConfigDir(L, fullPath.parentDir)

  var status = luaL_loadfile(L, fullPath.cstring)
  if status != LUA_OK:
    discard luaL_error(L, "fw:include: %s", lua_tostring(L, -1))

  let savedFrameState = getFrameState()
  status = lua_pcall(L, 0, LUA_MULTRET, 0)
  setFrameState(savedFrameState)
  if status != LUA_OK:
    discard luaL_error(L, "fw:include: %s", lua_tostring(L, -1))

  setConfigDir(L, prevDir)

proc resolveIncludePath(L: LuaState, state: FirewallState, path, configDir: string): string =
  ## Resolve and validate an include path. Returns the absolute path.
  let fullPath = absolutePath(configDir / path)
  let configRoot = if state.includedFiles.len > 0:
                     state.includedFiles[0].parentDir
                   else: configDir
  let normalRoot = try: expandFilename(absolutePath(configRoot))
                   except OSError: absolutePath(configRoot)
  let resolvedPath = try: expandFilename(fullPath)
                     except OSError: fullPath
  if not resolvedPath.startsWith(normalRoot & "/") and resolvedPath != normalRoot:
    discard luaL_error(L, "fw:include: resolved path escapes config directory: '%s'", resolvedPath.cstring)
  return fullPath

proc fwInclude(L: LuaState): cint {.cdecl.} =
  let state = getState(L)
  let path = $luaL_checkstring(L, 2)

  checkLen(L, path, maxStringLen, "fw:include path")

  if path.isAbsolute:
    discard luaL_error(L, "fw:include: absolute paths are not allowed: '%s'", path.cstring)
  for component in path.split({'/', '\\'}):
    if component == "..":
      discard luaL_error(L, "fw:include: '..' path traversal is not allowed: '%s'", path.cstring)

  let configDir = getConfigDir(L)
  let base = lua_gettop(L)
  let isGlob = '*' in path or '?' in path or '[' in path

  if isGlob:
    # Glob include: match files, sort alphabetically, skip dotfiles.
    # No matches is not an error (like Shorewall).
    let dir = absolutePath(configDir / path.parentDir)
    let pattern = path.extractFilename
    var matches: seq[string]
    if dirExists(dir):
      for kind, p in walkDir(dir):
        if kind != pcFile: continue
        let name = p.extractFilename
        if name.startsWith("."): continue  # skip dotfiles
        # Simple glob matching
        var match = true
        var si, pi = 0
        while pi < pattern.len and si < name.len:
          if pattern[pi] == '*':
            if pi + 1 >= pattern.len: si = name.len; break
            pi += 1
            while si < name.len and name[si] != pattern[pi]: si += 1
          elif pattern[pi] == '?' or pattern[pi] == name[si]:
            pi += 1; si += 1
          else:
            match = false; break
        if pi < pattern.len and pattern[pi] != '*': match = false
        if match: matches.add p
    matches.sort()
    for m in matches:
      discard resolveIncludePath(L, state, m.relativePath(configDir), configDir)
      includeOneFile(L, state, m)
  else:
    # Single file include
    let fullPath = resolveIncludePath(L, state, path, configDir)
    if not fileExists(fullPath):
      discard luaL_error(L, "fw:include: file not found: '%s'", fullPath.cstring)
    includeOneFile(L, state, fullPath)

  return lua_gettop(L) - base

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
  registerMethod(L, -1, "sysctl", fwSysctl)
  registerMethod(L, -1, "redirect", fwRedirect)
  registerMethod(L, -1, "mss_clamp", fwMssClamp)
  registerMethod(L, -1, "hook", fwHook)
  registerMethod(L, -1, "chain", fwChain)
  registerMethod(L, -1, "raw_nft", fwRawNft)
  registerMethod(L, -1, "exception", fwException)
  lua_setglobal(L, "fw")

  # Create the "util" global table
  lua_newtable(L)
  registerMethod(L, -1, "rate", utilRate)
  lua_setglobal(L, "util")
