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

proc isIpv6*(s: string): bool =
  ## Check if string looks like an IPv6 address (contains colons).
  ':' in s

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
