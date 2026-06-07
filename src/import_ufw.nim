## import_ufw.nim - Parse UFW rules and generate matchstick Lua config.
##
## Parses `ufw show added` output (lines starting with "ufw ").
##
## Usage:
##   sudo ufw show added | matchstick import-ufw
##   matchstick import-ufw < ufw-rules.txt

import std/[strutils, sequtils, tables, sets, os, options]

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
  # Handle quoted strings (comments with spaces)
  var i = 0
  var current = ""
  var inQuote = false
  var quoteChar = ' '
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
  var lines: seq[string]

  lines.add "---------------------------------------------------------------------------"
  lines.add "-- matchstick firewall config (generated from UFW)"
  lines.add "--"
  lines.add "-- Review this file and adjust:"
  lines.add "--   1. Zone names and interface assignments"
  lines.add "--   2. Host names for source IP addresses"
  lines.add "--   3. Service names for well-known ports"
  lines.add "---------------------------------------------------------------------------"
  lines.add ""

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

  # Build service variable map
  var svcMap: OrderedTable[PortProto, string]
  for pp in portProtos:
    svcMap[pp] = serviceName(pp.port, pp.proto)

  # Emit services
  lines.add "---------------------------------------------------------------------------"
  lines.add "-- Services"
  lines.add "---------------------------------------------------------------------------"
  for pp, name in svcMap:
    let port = pp.port.replace(":", "-")  # UFW uses ":" for ranges, nftables uses "-"
    if pp.proto != "":
      lines.add "local " & name & " = fw:service(\"" & name & "\", \"" & pp.proto & "\", \"" & port & "\")"
    else:
      lines.add "local " & name & " = fw:service(\"" & name & "\", {\"tcp\", \"udp\"}, \"" & port & "\")"
  lines.add ""

  # Emit zones
  lines.add "---------------------------------------------------------------------------"
  lines.add "-- Zones"
  lines.add "---------------------------------------------------------------------------"
  lines.add "local self = fw:zone(\"fw\")"

  # Zone naming
  var zoneNames: OrderedTable[string, string]
  if ifaces.len == 0:
    # No interface-specific rules, create a default
    zoneNames["eth0"] = "net"
    lines.add "local net = fw:zone(\"net\", \"eth0\")  -- TODO: adjust interface"
  else:
    for iface in ifaces:
      let zn = case iface
        of "eth0": "net"
        of "eth1": "lan"
        of "wlan0": "wifi"
        of "docker0": "docker"
        else: iface.replace("-", "_").replace("+", "")
      zoneNames[iface] = zn
      lines.add "local " & zn & " = fw:zone(\"" & zn & "\", \"" & iface & "\")"

  # If no interfaces from rules, we still need a default zone for non-interface rules
  let defaultZone = if zoneNames.len > 0: zoneNames.values.toSeq[0] else: "net"

  lines.add ""

  # Emit hosts for single IP sources
  var hostNames: OrderedTable[string, string]
  var subnetAddrs: seq[string]

  for addr in sourceAddrs:
    if "/" in addr:
      subnetAddrs.add addr
    else:
      let octets = addr.split(".")
      let name = "host_" & octets[^1]
      hostNames[addr] = name

  if hostNames.len > 0 or subnetAddrs.len > 0:
    lines.add "---------------------------------------------------------------------------"
    lines.add "-- Hosts"
    lines.add "---------------------------------------------------------------------------"
    for addr, name in hostNames:
      lines.add "local " & name & " = fw:host(\"" & name & "\", { zone = " & defaultZone & ", addr = \"" & addr & "\" })"
    lines.add ""

  # Emit IP lists for subnets
  if subnetAddrs.len > 0:
    lines.add "---------------------------------------------------------------------------"
    lines.add "-- IP lists (for subnet-based source filtering)"
    lines.add "---------------------------------------------------------------------------"
    for addr in subnetAddrs:
      let octets = addr.split("/")[0].split(".")
      let name = "net_" & octets[0] & "_" & octets[1]
      hostNames[addr] = name  # reuse hostNames for lookup
      lines.add "fw:iplist(\"" & name & "\", { type = \"ipv4\", flags = \"interval\", elements = { \"" & addr & "\" } })"
    lines.add ""

  # Emit policies
  lines.add "---------------------------------------------------------------------------"
  lines.add "-- Policies"
  lines.add "---------------------------------------------------------------------------"
  let inPol = inputPolicy.toLowerAscii.strip(chars = {'"', '\''})
  let outPol = outputPolicy.toLowerAscii.strip(chars = {'"', '\''})
  lines.add "fw:policy(\"*\", self, \"" & inPol & "\", { log = true })"
  lines.add "fw:policy(self, \"*\", \"" & outPol & "\")"
  lines.add "fw:policy(\"*\", \"*\", \"drop\")"
  lines.add ""

  # Emit rules
  lines.add "---------------------------------------------------------------------------"
  lines.add "-- Rules"
  lines.add "---------------------------------------------------------------------------"

  for r in rules:
    var commentStr = ""
    if r.comment != "":
      commentStr = "  -- " & r.comment

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
      lines.add "fw:rule(" & fromZone & ", \"*\", \"" & action & "\")" & commentStr
      continue
    else:
      dst = "self"

    # Determine service/port
    if r.port == "" and r.proto == "":
      # Bare rule
      lines.add "fw:rule(" & src & ", " & dst & ", \"" & action & "\")" & commentStr
    else:
      let pp: PortProto = (r.port, r.proto)
      if pp in svcMap:
        let svcName = svcMap[pp]
        if r.action == ufwLimit:
          lines.add "fw:rule(" & src & ", " & dst & ", \"" & action & "\", {"
          lines.add "  service = " & svcName & ","
          lines.add "  rate = util:rate(\"6/minute\", { burst = 6 }),"
          lines.add "})" & commentStr
        elif r.fromAddr != "" and "/" in r.fromAddr and r.fromAddr in hostNames:
          # Subnet source needs saddr_list
          lines.add "fw:rule(\"*\", " & dst & ", \"" & action & "\", { service = " & svcName & ", saddr_list = \"" & hostNames[r.fromAddr] & "\" })" & commentStr
        else:
          lines.add "fw:rule(" & src & ", " & dst & ", \"" & action & "\", " & svcName & ")" & commentStr
      else:
        lines.add "fw:rule(" & src & ", " & dst & ", \"" & action & "\", { proto = \"" & r.proto & "\", port = \"" & r.port.replace(":", "-") & "\" })" & commentStr

  lines.add ""
  return lines.join("\n") & "\n"

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
