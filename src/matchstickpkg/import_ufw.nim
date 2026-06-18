## import_ufw.nim - Parse UFW rules and generate matchstick Lua config.
##
## Parses `ufw show added` output (lines starting with "ufw ").
##
## Usage:
##   sudo ufw show added | matchstick import-ufw
##   matchstick import-ufw < ufw-rules.txt

import std/[strutils, sequtils, tables, sets, os, options, hashes]
import ./writer

proc escapeLuaString(s: string): string =
  ## Escape a string for safe inclusion in a Lua double-quoted string literal.
  result = newStringOfCap(s.len)
  for c in s:
    case c
    of '"':  result.add '\\'  ; result.add '"'
    of '\\': result.add '\\'; result.add '\\'
    of '\n': result.add '\\'; result.add 'n'
    of '\r': result.add '\\'; result.add 'r'
    of '\0': discard  # strip null bytes
    else:    result.add c

type
  UfwAction = enum
    ufwAllow, ufwDeny, ufwReject, ufwLimit

  UfwDirection = enum
    ufwIn, ufwOut, ufwRoute

  UfwRule = object
    action: UfwAction
    direction: UfwDirection
    proto: string        ## "tcp", "udp", "" (any)
    port: string         ## "22", "60000:61000", "" (any)
    fromAddr: string     ## "192.168.0.0/16", "" (anywhere)
    toAddr: string       ## specific IP or "" (any)
    iface: string        ## interface name, "" if not specified
    comment: string

# ---------------------------------------------------------------------------
# Parse a single "ufw ..." line
# ---------------------------------------------------------------------------

proc parseUfwLine(line: string): Option[UfwRule] =
  ## Parse a line from `ufw show added` output.
  ## Examples:
  ##   ufw allow from 192.168.0.1
  ##   ufw allow 4010/udp
  ##   ufw allow from 192.168.0.0/16 to any port 22 proto tcp
  ##   ufw allow out on waydroid0 to any port 67 comment 'waydroid'
  ##   ufw route allow in on waydroid0 comment 'Waydroid'
  let trimmed = line.strip()
  if not trimmed.startsWith("ufw "):
    return none(UfwRule)

  var tokens: seq[string]
  var current = ""
  var inQuote = false
  var quoteChar = '\0'  # active quote delimiter when inQuote is true
  for c in trimmed:
    if inQuote:
      if c == quoteChar:
        inQuote = false
        tokens.add current
        current = ""
      else:
        current.add c
    elif c == '\'' or c == '"':
      inQuote = true
      quoteChar = c
      if current.len > 0:
        tokens.add current
        current = ""
    elif c == ' ':
      if current.len > 0:
        tokens.add current
        current = ""
    else:
      current.add c
  if current.len > 0:
    tokens.add current

  # tokens[0] = "ufw", skip it
  if tokens.len < 2: return none(UfwRule)
  var pos = 1

  var rule = UfwRule(direction: ufwIn)

  # Check for "route" prefix
  if pos < tokens.len and tokens[pos] == "route":
    rule.direction = ufwRoute
    pos += 1

  # Action
  if pos >= tokens.len: return none(UfwRule)
  case tokens[pos]
  of "allow": rule.action = ufwAllow
  of "deny": rule.action = ufwDeny
  of "reject": rule.action = ufwReject
  of "limit": rule.action = ufwLimit
  else: return none(UfwRule)
  pos += 1

  # Parse remaining tokens
  while pos < tokens.len:
    let tok = tokens[pos]
    case tok
    of "in":
      rule.direction = if rule.direction == ufwRoute: ufwRoute else: ufwIn
      pos += 1
    of "out":
      rule.direction = ufwOut
      pos += 1
    of "on":
      pos += 1
      if pos < tokens.len:
        rule.iface = tokens[pos]
        pos += 1
    of "from":
      pos += 1
      if pos < tokens.len:
        let a = tokens[pos]
        if a != "any":
          rule.fromAddr = a
        pos += 1
    of "to":
      pos += 1
      if pos < tokens.len:
        let a = tokens[pos]
        if a != "any":
          rule.toAddr = a
        pos += 1
    of "port":
      pos += 1
      if pos < tokens.len:
        rule.port = tokens[pos]
        pos += 1
    of "proto":
      pos += 1
      if pos < tokens.len:
        rule.proto = tokens[pos]
        pos += 1
    of "comment":
      pos += 1
      if pos < tokens.len:
        rule.comment = tokens[pos]
        pos += 1
    of "log", "log-all":
      pos += 1
    else:
      # Could be a simple port/proto: "22/tcp", "22", "ssh"
      if "/" in tok:
        let parts = tok.split("/")
        rule.port = parts[0]
        rule.proto = parts[1]
      elif tok.allCharsInSet({'0'..'9', ':', ','}):
        rule.port = tok
      # else unknown token, skip
      pos += 1

  return some(rule)

# ---------------------------------------------------------------------------
# Generate Lua output
# ---------------------------------------------------------------------------

proc generateLua*(rules: seq[UfwRule], inputPolicy, outputPolicy: string): string =
  var w = newWriter()

  w.line "---------------------------------------------------------------------------"
  w.line "-- matchstick firewall config (generated from UFW)"
  w.line "--"
  w.line "--   1. Zone names and interface assignments"
  w.line "--   2. Host names for source IP addresses"
  w.line "--   3. Service names for well-known ports"
  w.line "---------------------------------------------------------------------------"
  w.emptyLine()

  # Collect unique interfaces, source addresses, and port/proto combos
  var ifaces: OrderedSet[string]
  var sourceAddrs: OrderedSet[string]
  type PortProto = tuple[port, proto: string]
  var portProtos: OrderedSet[PortProto]

  for r in rules:
    if r.iface != "": ifaces.incl r.iface
    if r.fromAddr != "": sourceAddrs.incl r.fromAddr
    if r.port != "":
      portProtos.incl (r.port, r.proto)

  # Name well-known services
  proc serviceName(port, proto: string): string =
    case port
    of "22": "ssh"
    of "53": "dns"
    of "67": "dhcp_server"
    of "68": "dhcp_client"
    of "80": "http"
    of "443": "https"
    of "123": "ntp"
    of "25": "smtp"
    of "993": "imaps"
    of "5901": "vnc"
    else:
      var name = "svc_" & port.replace(":", "_").replace(",", "_")
      if proto != "": name &= "_" & proto
      name

  # Build service variable map, deduplicating same port with/without proto
  var svcMap: OrderedTable[PortProto, string]
  var usedSvcNames: HashSet[string]
  for pp in portProtos:
    var name = serviceName(pp.port, pp.proto)
    # If this name is already used (e.g. dhcp_server for 67/udp and 67/),
    # disambiguate or skip
    if name in usedSvcNames:
      if pp.proto == "":
        name &= "_any"
      else:
        name &= "_" & pp.proto
    svcMap[pp] = name
    usedSvcNames.incl name

  # Emit services
  w.line "---------------------------------------------------------------------------"
  w.line "-- Services"
  w.line "---------------------------------------------------------------------------"
  for pp, name in svcMap:
    let port = pp.port.replace(":", "-")  # UFW uses ":" for ranges, nftables uses "-"
    if pp.proto != "":
      w.line "local " & name & " = fw:service(\"" & escapeLuaString(name) & "\", \"" & escapeLuaString(pp.proto) & "\", \"" & escapeLuaString(port) & "\")"
    else:
      w.line "local " & name & " = fw:service(\"" & escapeLuaString(name) & "\", {\"tcp\", \"udp\"}, \"" & escapeLuaString(port) & "\")"
  w.emptyLine()

  # Emit zones
  w.line "---------------------------------------------------------------------------"
  w.line "-- Zones"
  w.line "---------------------------------------------------------------------------"
  w.line "local self = fw:zone(\"fw\")"

  # Zone naming
  var zoneNames: OrderedTable[string, string]
  if ifaces.len == 0:
    # No interface-specific rules, create a default
    zoneNames["eth0"] = "net"
    w.line "local net = fw:zone(\"net\", \"eth0\")  -- TODO: adjust interface"
  else:
    for iface in ifaces:
      let zn = case iface
        of "eth0": "net"
        of "eth1": "lan"
        of "wlan0": "wifi"
        of "docker0": "docker"
        else: iface.replace("-", "_").replace("+", "")
      zoneNames[iface] = zn
      w.line "local " & zn & " = fw:zone(\"" & escapeLuaString(zn) & "\", \"" & escapeLuaString(iface) & "\")"

  # If no interfaces from rules, we still need a default zone for non-interface rules
  let defaultZone = if zoneNames.len > 0: zoneNames.values.toSeq[0] else: "net"

  w.emptyLine()

  # Emit hosts for single IP sources
  var hostNames: OrderedTable[string, string]
  var subnetAddrs: seq[string]
  var usedHostNames: HashSet[string]

  for srcAddr in sourceAddrs:
    if "/" in srcAddr:
      subnetAddrs.add srcAddr
    else:
      let octets = srcAddr.split(".")
      var name = "host_" & octets[^1]
      # Disambiguate if same last octet from different subnets
      if name in usedHostNames:
        name = "host_" & octets[^2] & "_" & octets[^1]
      hostNames[srcAddr] = name
      usedHostNames.incl name

  if hostNames.len > 0 or subnetAddrs.len > 0:
    w.line "---------------------------------------------------------------------------"
    w.line "-- Hosts"
    w.line "---------------------------------------------------------------------------"
    for a, name in hostNames:
      w.line "local " & name & " = fw:host(\"" & escapeLuaString(name) & "\", { zone = " & defaultZone & ", addr = \"" & escapeLuaString(a) & "\" })"
    w.emptyLine()

  # Emit IP lists for subnets
  if subnetAddrs.len > 0:
    w.line "---------------------------------------------------------------------------"
    w.line "-- IP lists (for subnet-based source filtering)"
    w.line "---------------------------------------------------------------------------"
    for a in subnetAddrs:
      let octets = a.split("/")[0].split(".")
      let name = "net_" & octets[0] & "_" & octets[1]
      hostNames[a] = name  # reuse hostNames for lookup
      w.line "fw:iplist(\"" & escapeLuaString(name) & "\", { type = \"ipv4\", flags = \"interval\", elements = { \"" & escapeLuaString(a) & "\" } })"
    w.emptyLine()

  # Emit policies
  w.line "---------------------------------------------------------------------------"
  w.line "-- Policies"
  w.line "---------------------------------------------------------------------------"
  let inPol = inputPolicy.toLowerAscii.strip(chars = {'"', '\''})
  let outPol = outputPolicy.toLowerAscii.strip(chars = {'"', '\''})
  w.line "fw:policy(\"*\", self, \"" & inPol & "\", { log = true })"
  w.line "fw:policy(self, \"*\", \"" & outPol & "\")"
  w.line "fw:policy(\"*\", \"*\", \"drop\")"
  w.emptyLine()

  # Emit rules
  w.line "---------------------------------------------------------------------------"
  w.line "-- Rules"
  w.line "---------------------------------------------------------------------------"

  for r in rules:
    var commentStr = ""
    if r.comment != "":
      # Strip newlines from comments to prevent Lua code injection
      commentStr = "  -- " & r.comment.replace("\n", " ").replace("\r", " ")

    let action = case r.action
      of ufwAllow: "accept"
      of ufwDeny: "drop"
      of ufwReject: "reject"
      of ufwLimit: "accept"

    # Determine source expression
    var src: string
    if r.fromAddr != "":
      if r.fromAddr in hostNames:
        src = hostNames[r.fromAddr]
      else:
        src = "\"*\"  --[[ from " & r.fromAddr & " ]]"
    elif r.direction == ufwOut:
      src = "self"
    else:
      src = "\"*\""

    # Determine destination
    var dst: string
    if r.direction == ufwOut:
      dst = if r.iface != "" and r.iface in zoneNames: zoneNames[r.iface] else: "\"*\""
    elif r.direction == ufwRoute:
      # Forward rule
      let fromZone = if r.iface != "" and r.iface in zoneNames: zoneNames[r.iface] else: "\"*\""
      w.line "fw:rule(" & fromZone & ", \"*\", \"" & action & "\")" & commentStr
      continue
    else:
      dst = "self"

    # Determine service/port
    if r.port == "" and r.proto == "":
      # Bare rule
      w.line "fw:rule(" & src & ", " & dst & ", \"" & action & "\")" & commentStr
    else:
      let pp: PortProto = (r.port, r.proto)
      if pp in svcMap:
        let svcName = svcMap[pp]
        if r.action == ufwLimit:
          w.line "fw:rule(" & src & ", " & dst & ", \"" & action & "\", {"
          w.line "  service = " & svcName & ","
          w.line "  rate = util:rate(\"6/minute\", { burst = 6 }),"
          w.line "})" & commentStr
        elif r.fromAddr != "" and "/" in r.fromAddr and r.fromAddr in hostNames:
          # Subnet source needs saddr_list
          w.line "fw:rule(\"*\", " & dst & ", \"" & action & "\", { service = " & svcName & ", saddr_list = \"" & escapeLuaString(hostNames[r.fromAddr]) & "\" })" & commentStr
        else:
          w.line "fw:rule(" & src & ", " & dst & ", \"" & action & "\", " & svcName & ")" & commentStr
      else:
        w.line "fw:rule(" & src & ", " & dst & ", \"" & action & "\", { proto = \"" & escapeLuaString(r.proto) & "\", port = \"" & escapeLuaString(r.port.replace(":", "-")) & "\" })" & commentStr

  w.emptyLine()
  return w.result

# ---------------------------------------------------------------------------
# Read UFW defaults
# ---------------------------------------------------------------------------

proc readUfwDefaults*(): tuple[input, output: string] =
  result = ("DROP", "ACCEPT")
  let path = "/etc/default/ufw"
  if not fileExists(path): return
  try:
    for line in readFile(path).splitLines():
      let s = line.strip()
      if s.startsWith("DEFAULT_INPUT_POLICY="):
        result.input = s.split("=", 1)[1].strip(chars = {'"', '\''})
      elif s.startsWith("DEFAULT_OUTPUT_POLICY="):
        result.output = s.split("=", 1)[1].strip(chars = {'"', '\''})
  except IOError:
    discard

# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

proc importUfw*(input: string): string =
  ## Parse `ufw show added` output and generate matchstick Lua config.
  var rules: seq[UfwRule]

  for line in input.splitLines():
    let trimmed = line.strip()
    # Skip header line from `ufw show added`
    if trimmed.startsWith("Added user rules"):
      continue
    let parsed = parseUfwLine(trimmed)
    if parsed.isSome:
      rules.add parsed.get

  let defaults = readUfwDefaults()
  return generateLua(rules, defaults.input, defaults.output)
