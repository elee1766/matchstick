## import_ufw.nim - Parse UFW rules and generate matchstick Lua config.
##
## Supports two input formats:
##   1. `ufw show added` output (lines starting with "ufw ")
##   2. `ufw status` output (the "To/Action/From" table format)
##
## Usage:
##   sudo ufw show added | matchstick import-ufw
##   sudo ufw status verbose | matchstick import-ufw
##   matchstick import-ufw /etc/default/ufw    # reads defaults + tries to run ufw

import std/[strutils, sequtils, tables, sets, os, osproc]

type
  UfwAction = enum
    ufwAllow, ufwDeny, ufwReject, ufwLimit

  UfwDirection = enum
    ufwIn, ufwOut, ufwFwd

  UfwRule = object
    action: UfwAction
    direction: UfwDirection
    proto: string        ## "tcp", "udp", "" (any), "tcp,udp" (both)
    port: string         ## "22", "80,443", "6881:6999", "" (any)
    fromAddr: string     ## "192.168.0.0/16", "Anywhere", ""
    toAddr: string       ## "any", specific IP, ""
    iface: string        ## interface name, "" if not specified
    comment: string
    ipv6Only: bool

# ---------------------------------------------------------------------------
# Parse "ufw status" table format
# ---------------------------------------------------------------------------

proc parseStatusLine(line: string): Option[UfwRule] =
  ## Parse a line from "ufw status" output like:
  ##   22/tcp                     ALLOW       192.168.0.0/16
  ##   Anywhere                   ALLOW       192.168.0.1
  ##   53 on waydroid0            ALLOW       Anywhere                   # waydroid
  ##   67                         ALLOW OUT   Anywhere on waydroid0      # waydroid
  ##   Anywhere                   ALLOW FWD   Anywhere on waydroid0      # Waydroid
  let trimmed = line.strip()
  if trimmed == "" or trimmed.startsWith("--") or trimmed.startsWith("To "):
    return none(UfwRule)

  # Extract comment
  var comment = ""
  var working = trimmed
  let commentIdx = working.find(" # ")
  if commentIdx >= 0:
    comment = working[commentIdx + 3 .. ^1].strip()
    working = working[0 ..< commentIdx].strip()

  # Skip v6 duplicate rules (they're just the v4 rule repeated for IPv6)
  let isV6 = "(v6)" in working
  if isV6:
    working = working.replace("(v6)", "").strip()
    working = working.replace("Anywhere ", "Anywhere ") # clean double spaces

  # Split into columns by multiple spaces
  var parts: seq[string]
  var current = ""
  var spaceCount = 0
  for c in working:
    if c == ' ':
      spaceCount += 1
      if spaceCount >= 2 and current.len > 0:
        parts.add current.strip()
        current = ""
        spaceCount = 0
    else:
      if spaceCount > 0 and spaceCount < 2:
        current &= ' '
      current &= c
      spaceCount = 0
  if current.strip().len > 0:
    parts.add current.strip()

  if parts.len < 3:
    return none(UfwRule)

  var rule = UfwRule(ipv6Only: isV6)

  # Parse action + direction (column 2)
  let actionCol = parts[1].toUpperAscii()
  if "ALLOW" in actionCol: rule.action = ufwAllow
  elif "DENY" in actionCol: rule.action = ufwDeny
  elif "REJECT" in actionCol: rule.action = ufwReject
  elif "LIMIT" in actionCol: rule.action = ufwLimit
  else: return none(UfwRule)

  if "FWD" in actionCol: rule.direction = ufwFwd
  elif "OUT" in actionCol: rule.direction = ufwOut
  else: rule.direction = ufwIn

  # Parse "To" column (column 1) - port/proto and optional interface
  var toCol = parts[0]
  if " on " in toCol:
    let onParts = toCol.split(" on ")
    toCol = onParts[0].strip()
    rule.iface = onParts[1].strip()

  if toCol == "Anywhere":
    discard  # no port filter
  elif "/" in toCol:
    let pp = toCol.split("/")
    rule.port = pp[0]
    rule.proto = pp[1]
  else:
    rule.port = toCol

  # Parse "From" column (column 3) - address and optional interface
  var fromCol = parts[2]
  if " on " in fromCol:
    let onParts = fromCol.split(" on ")
    fromCol = onParts[0].strip()
    if rule.iface == "":
      rule.iface = onParts[1].strip()

  if fromCol != "Anywhere":
    rule.fromAddr = fromCol

  rule.comment = comment

  return some(rule)

# ---------------------------------------------------------------------------
# Collect unique values for Lua generation
# ---------------------------------------------------------------------------

type
  LuaGen = object
    interfaces: OrderedTable[string, string]  ## iface -> zone name
    subnets: OrderedTable[string, string]     ## subnet -> host/group name
    rules: seq[UfwRule]
    inputPolicy: string
    outputPolicy: string
    forwardPolicy: string

proc inferZoneName(iface: string): string =
  ## Generate a zone name from interface name.
  case iface
  of "eth0": "wan"
  of "eth1": "lan"
  of "wlan0": "wifi"
  of "docker0": "docker"
  else:
    if iface.startsWith("br-"): "docker"
    elif iface.startsWith("wl"): "wifi"
    elif iface.startsWith("en"): iface
    else: iface.replace("-", "_").replace("+", "")

proc inferSubnetName(addr: string): string =
  ## Generate a name for a source address/subnet.
  if "/" in addr:
    let parts = addr.split("/")
    let octets = parts[0].split(".")
    if octets.len == 4:
      return "net_" & octets[0] & "_" & octets[1]
  # Single IP
  let octets = addr.split(".")
  if octets.len == 4:
    return "host_" & octets[^1]
  return addr.replace(".", "_").replace("/", "_").replace(":", "_")

# ---------------------------------------------------------------------------
# Generate Lua output
# ---------------------------------------------------------------------------

proc generateLua*(rules: seq[UfwRule], inputPolicy, outputPolicy, forwardPolicy: string): string =
  var lines: seq[string]

  lines.add "---------------------------------------------------------------------------"
  lines.add "-- matchstick config generated from UFW rules"
  lines.add "-- Review and adjust zone names, host names, and interface assignments"
  lines.add "---------------------------------------------------------------------------"
  lines.add ""

  # Collect unique interfaces and source addresses
  var ifaces: OrderedSet[string]
  var sources: OrderedSet[string]
  var serviceMap: OrderedTable[string, string]  ## "proto/port" -> service var name

  for r in rules:
    if r.iface != "": ifaces.incl r.iface
    if r.fromAddr != "": sources.incl r.fromAddr

  # Build service definitions from unique proto/port combos
  var svcIdx = 0
  for r in rules:
    if r.port == "" or r.ipv6Only: continue
    let key = r.proto & "/" & r.port
    if key notin serviceMap:
      # Try to name well-known services
      let name = case r.port
        of "22": "ssh"
        of "80": "http"
        of "443": "https"
        of "53": "dns"
        of "67": "dhcp_server"
        of "68": "dhcp_client"
        of "123": "ntp"
        of "25": "smtp"
        of "993": "imaps"
        of "5901": "vnc"
        else:
          if r.proto != "":
            "svc_" & r.proto & "_" & r.port.replace(":", "_").replace(",", "_")
          else:
            "svc_" & r.port.replace(":", "_").replace(",", "_")
          
      serviceMap[key] = name

  # Emit services
  if serviceMap.len > 0:
    lines.add "---------------------------------------------------------------------------"
    lines.add "-- Services"
    lines.add "---------------------------------------------------------------------------"
    for key, name in serviceMap:
      let parts = key.split("/")
      let proto = parts[0]
      let port = parts[1]
      if "," in port:
        # Multiple ports - need complex service form
        let ports = port.split(",")
        if proto != "":
          var entries: seq[string]
          for p in ports:
            entries.add "  {\"" & proto & "\", " & p & "}"
          lines.add "local " & name & " = fw:service(\"" & name & "\", {"
          lines.add entries.join(",\n")
          lines.add "})"
        else:
          lines.add "local " & name & " = fw:service(\"" & name & "\", \"tcp\", " & ports[0] & ")"
      elif ":" in port:
        # Port range
        let range = port.replace(":", "-")
        if proto != "":
          lines.add "local " & name & " = fw:service(\"" & name & "\", \"" & proto & "\", \"" & range & "\")"
        else:
          lines.add "local " & name & " = fw:service(\"" & name & "\", \"tcp\", \"" & range & "\")"
      else:
        if proto != "":
          lines.add "local " & name & " = fw:service(\"" & name & "\", \"" & proto & "\", " & port & ")"
        else:
          # No proto specified = both tcp and udp
          lines.add "local " & name & " = fw:service(\"" & name & "\", {\"tcp\", \"udp\"}, " & port & ")"
    lines.add ""

  # Emit zones
  lines.add "---------------------------------------------------------------------------"
  lines.add "-- Zones"
  lines.add "---------------------------------------------------------------------------"
  lines.add "local self = fw:zone(\"fw\")"

  if ifaces.len > 0:
    for iface in ifaces:
      let zname = inferZoneName(iface)
      lines.add "local " & zname & " = fw:zone(\"" & zname & "\", \"" & iface & "\")"
  else:
    # No interface-specific rules, create a generic zone
    lines.add "-- TODO: replace with your actual interface"
    lines.add "local net = fw:zone(\"net\", \"eth0\")"

  lines.add ""

  # Emit hosts for source addresses
  if sources.len > 0:
    lines.add "---------------------------------------------------------------------------"
    lines.add "-- Hosts / source addresses"
    lines.add "---------------------------------------------------------------------------"
    # Determine which zone each source belongs to (use first iface zone, or generic)
    let defaultZone = if ifaces.len > 0: inferZoneName(ifaces.toSeq[0]) else: "net"
    for src in sources:
      let name = inferSubnetName(src)
      if "/" in src:
        lines.add "-- Subnet: " & src & " (adjust zone if needed)"
        lines.add "-- To match a subnet, use saddr_list with an iplist, or host for single IPs"
      else:
        lines.add "local " & name & " = fw:host(\"" & name & "\", { zone = " & defaultZone & ", addr = \"" & src & "\" })"
    lines.add ""

  # Emit policies
  lines.add "---------------------------------------------------------------------------"
  lines.add "-- Policies (from UFW defaults)"
  lines.add "---------------------------------------------------------------------------"
  let inPol = case inputPolicy.toLowerAscii.strip(chars = {'"'})
    of "drop": "drop"
    of "reject": "reject"
    else: "accept"
  let outPol = case outputPolicy.toLowerAscii.strip(chars = {'"'})
    of "drop": "drop"
    of "reject": "reject"
    else: "accept"

  let defaultZone = if ifaces.len > 0: inferZoneName(ifaces.toSeq[0]) else: "net"

  lines.add "fw:policy(\"*\", self, \"" & inPol & "\", { log = true })  -- default incoming"
  lines.add "fw:policy(self, \"*\", \"" & outPol & "\")                  -- default outgoing"
  lines.add ""

  # Emit rules
  lines.add "---------------------------------------------------------------------------"
  lines.add "-- Rules"
  lines.add "---------------------------------------------------------------------------"

  for r in rules:
    if r.ipv6Only: continue  # skip v6 duplicates, matchstick handles dual-stack

    var commentStr = ""
    if r.comment != "":
      commentStr = "  -- " & r.comment

    let action = case r.action
      of ufwAllow: "accept"
      of ufwDeny: "drop"
      of ufwReject: "reject"
      of ufwLimit: "accept"

    # Determine source
    var src = "\"*\""
    if r.fromAddr != "":
      if "/" in r.fromAddr:
        src = "\"*\"  -- TODO: from " & r.fromAddr & " (use saddr_list)"
      else:
        src = inferSubnetName(r.fromAddr)

    # Determine dest zone
    var dst = "self"
    if r.direction == ufwOut:
      dst = defaultZone
      src = "self"
    elif r.direction == ufwFwd:
      # Forward rules
      if r.iface != "":
        let zn = inferZoneName(r.iface)
        lines.add "-- forward: allow from " & zn & commentStr
        lines.add "fw:rule(" & zn & ", \"*\", \"" & action & "\")"
        continue
      else:
        lines.add "-- forward rule (adjust zones)" & commentStr
        continue

    # Build rule
    if r.port == "" and r.proto == "":
      # Bare rule (allow/deny all from source)
      lines.add "fw:rule(" & src & ", " & dst & ", \"" & action & "\")" & commentStr
    else:
      let key = r.proto & "/" & r.port
      if key in serviceMap:
        let svcName = serviceMap[key]
        if r.action == ufwLimit:
          lines.add "fw:rule(" & src & ", " & dst & ", \"" & action & "\", {"
          lines.add "  service = " & svcName & ","
          lines.add "  rate = util:rate(\"6/30seconds\", { burst = 6 }),"
          lines.add "})" & commentStr
        else:
          lines.add "fw:rule(" & src & ", " & dst & ", \"" & action & "\", " & svcName & ")" & commentStr
      else:
        # Inline proto/port
        var opts: seq[string]
        if r.proto != "": opts.add "proto = \"" & r.proto & "\""
        if r.port != "":
          let port = r.port.replace(":", "-")
          opts.add "port = \"" & port & "\""
        if r.action == ufwLimit:
          opts.add "rate = util:rate(\"6/30seconds\", { burst = 6 })"
        lines.add "fw:rule(" & src & ", " & dst & ", \"" & action & "\", { " & opts.join(", ") & " })" & commentStr

  lines.add ""
  return lines.join("\n") & "\n"

# ---------------------------------------------------------------------------
# Read UFW defaults from /etc/default/ufw
# ---------------------------------------------------------------------------

proc readUfwDefaults(path: string): tuple[input, output, forward: string] =
  result = ("DROP", "ACCEPT", "DROP")
  if not fileExists(path): return
  for line in readFile(path).splitLines():
    let stripped = line.strip()
    if stripped.startsWith("DEFAULT_INPUT_POLICY="):
      result.input = stripped.split("=", 1)[1].strip(chars = {'"', '\''})
    elif stripped.startsWith("DEFAULT_OUTPUT_POLICY="):
      result.output = stripped.split("=", 1)[1].strip(chars = {'"', '\''})
    elif stripped.startsWith("DEFAULT_FORWARD_POLICY="):
      result.forward = stripped.split("=", 1)[1].strip(chars = {'"', '\''})

# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

proc importUfw*(input: string): string =
  ## Parse UFW status output and generate matchstick Lua.
  ## Accepts `ufw status` table format from stdin.
  var rules: seq[UfwRule]

  let defaults = readUfwDefaults("/etc/default/ufw")

  # Parse each line
  var inRules = false
  for line in input.splitLines():
    let trimmed = line.strip()

    # Detect start of rules table
    if trimmed.startsWith("To ") and "Action" in trimmed and "From" in trimmed:
      inRules = true
      continue
    if trimmed.startsWith("--") and inRules:
      continue  # separator line

    if inRules:
      if trimmed == "": 
        inRules = false
        continue
      let parsed = parseStatusLine(trimmed)
      if parsed.isSome:
        rules.add parsed.get

  return generateLua(rules, defaults.input, defaults.output, defaults.forward)
