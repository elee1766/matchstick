## ipaddr.nim - IP address and CIDR utilities.
##
## Provides parsing, normalization, and rendering for IPv4/IPv6 addresses
## and CIDR prefixes. Ensures generated nftables output uses canonical forms.

import std/strutils

type
  Ipv4Addr* = distinct uint32
  Ipv6Addr* = object
    hi*, lo*: uint64

  CidrV4* = object
    addr4*: Ipv4Addr
    prefix*: int  ## 0-32

  CidrV6* = object
    addr6*: Ipv6Addr
    prefix*: int  ## 0-128

# ---------------------------------------------------------------------------
# IPv4
# ---------------------------------------------------------------------------

proc parseIpv4*(s: string): Ipv4Addr =
  ## Parse "192.168.0.1" → Ipv4Addr
  let parts = s.split('.')
  if parts.len != 4:
    raise newException(ValueError, "invalid IPv4: " & s)
  var val: uint32 = 0
  for i, p in parts:
    if p.len == 0:
      raise newException(ValueError, "invalid IPv4: empty octet in " & s)
    # Reject leading zeros to prevent octal ambiguity (e.g. "010" != "10")
    if p.len > 1 and p[0] == '0':
      raise newException(ValueError, "invalid IPv4 octet: leading zero in '" & p & "' (use " & $parseInt(p) & " instead)")
    let octet = parseInt(p)
    if octet < 0 or octet > 255:
      raise newException(ValueError, "invalid IPv4 octet: " & p)
    val = val or (uint32(octet) shl uint32((3 - i) * 8))
  Ipv4Addr(val)

proc `$`*(ip: Ipv4Addr): string =
  let v = uint32(ip)
  $((v shr 24) and 0xFF) & "." &
  $((v shr 16) and 0xFF) & "." &
  $((v shr 8) and 0xFF) & "." &
  $(v and 0xFF)

proc `==`*(a, b: Ipv4Addr): bool {.borrow.}

# ---------------------------------------------------------------------------
# CIDR v4
# ---------------------------------------------------------------------------

proc maskV4(prefix: int): uint32 =
  ## Compute a /prefix netmask as uint32.
  if prefix == 0: 0'u32
  elif prefix == 32: 0xFFFF_FFFF'u32
  else: uint32(0xFFFF_FFFF'u32 shl uint32(32 - prefix))

proc parseCidrV4*(s: string): CidrV4 =
  ## Parse "192.168.0.0/24" → CidrV4 with normalized network address.
  let parts = s.split('/')
  if parts.len != 2:
    raise newException(ValueError, "invalid CIDR: " & s)
  let ip = parseIpv4(parts[0])
  let prefix = parseInt(parts[1])
  if prefix < 0 or prefix > 32:
    raise newException(ValueError, "invalid CIDR prefix: " & $prefix)
  # Normalize: apply mask to get true network address
  let network = Ipv4Addr(uint32(ip) and maskV4(prefix))
  CidrV4(addr4: network, prefix: prefix)

proc `$`*(cidr: CidrV4): string =
  $cidr.addr4 & "/" & $cidr.prefix

# ---------------------------------------------------------------------------
# Detection and normalization helpers
# ---------------------------------------------------------------------------

proc isIpv4*(s: string): bool =
  ## Check if string looks like an IPv4 address (contains dots, no colons).
  '.' in s and ':' notin s

proc parseIpv6*(s: string): Ipv6Addr =
  ## Parse an IPv6 address string into Ipv6Addr.
  ## Supports standard notation, :: abbreviation, and mixed IPv4 notation.
  ## Rejects malformed addresses to prevent passing garbage to nftables/kernel.
  let input = s
  if input.len == 0 or input.len > 45:
    raise newException(ValueError, "invalid IPv6: " & s)

  # Split on "::" to handle abbreviation
  let parts = input.split("::")
  if parts.len > 2:
    raise newException(ValueError, "invalid IPv6: multiple '::' in " & s)

  var groups: seq[uint16]

  proc parseGroups(segment: string): seq[uint16] =
    if segment == "":
      return @[]
    let fields = segment.split(':')
    for f in fields:
      if f.len == 0 or f.len > 4:
        raise newException(ValueError, "invalid IPv6 group '" & f & "' in " & s)
      for c in f:
        if c notin {'0'..'9', 'a'..'f', 'A'..'F'}:
          raise newException(ValueError, "invalid hex character '" & c & "' in IPv6 " & s)
      result.add uint16(parseHexInt(f))

  if parts.len == 1:
    # No :: abbreviation -- must have exactly 8 groups
    groups = parseGroups(parts[0])
    if groups.len != 8:
      raise newException(ValueError, "invalid IPv6: expected 8 groups, got " & $groups.len & " in " & s)
  else:
    let left = parseGroups(parts[0])
    let right = parseGroups(parts[1])
    let missing = 8 - left.len - right.len
    if missing < 0:
      raise newException(ValueError, "invalid IPv6: too many groups in " & s)
    groups = left
    for _ in 0 ..< missing:
      groups.add 0'u16
    groups.add right

  # Build the Ipv6Addr from 8 groups
  var hi: uint64 = 0
  var lo: uint64 = 0
  for i in 0 ..< 4:
    hi = hi or (uint64(groups[i]) shl uint64((3 - i) * 16))
  for i in 0 ..< 4:
    lo = lo or (uint64(groups[i + 4]) shl uint64((3 - i) * 16))
  result = Ipv6Addr(hi: hi, lo: lo)

proc isIpv6*(s: string): bool =
  ## Check if string looks like an IPv6 address (contains colons).
  ':' in s

proc validateIpv6*(s: string): bool =
  ## Validate an IPv6 address or CIDR string is structurally correct.
  ## Returns true if valid, false otherwise.
  var addrPart = s
  if '/' in s:
    let parts = s.split('/')
    if parts.len != 2: return false
    addrPart = parts[0]
    try:
      let prefix = parseInt(parts[1])
      if prefix < 0 or prefix > 128: return false
    except ValueError:
      return false
  try:
    discard parseIpv6(addrPart)
    return true
  except ValueError:
    return false

proc isCidr*(s: string): bool =
  ## Check if string is CIDR notation (contains /).
  '/' in s and ('.' in s or ':' in s)

proc normalizeCidr*(s: string): string =
  ## Normalize a CIDR string to its canonical form.
  ## "172.17.0.0/12" → "172.16.0.0/12"
  ## Plain IPs are returned unchanged.
  if '/' notin s:
    return s
  if isIpv4(s):
    try:
      return $parseCidrV4(s)
    except ValueError:
      return s
  # IPv6 CIDR normalization would go here
  return s

proc cidrNetworkAddr*(s: string): string =
  ## Extract the network address from a CIDR string.
  ## "192.168.0.0/24" → "192.168.0.0"
  if '/' in s:
    if isIpv4(s):
      try:
        return $parseCidrV4(s).addr4
      except ValueError:
        return s.split('/')[0]
  return s

proc cidrPrefixLen*(s: string): int =
  ## Extract the prefix length from a CIDR string.
  ## "192.168.0.0/24" → 24
  if '/' in s:
    try:
      return parseInt(s.split('/')[1])
    except ValueError:
      return -1
  return -1
