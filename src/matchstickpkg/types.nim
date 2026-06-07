## Core types for matchstick's internal state.
## These are populated by the Lua VM callbacks and consumed by the renderer.

import std/[tables, options, json]

type
  Action* = enum
    actAccept = "accept"
    actDrop = "drop"
    actReject = "reject"

  DhcpRole* = enum
    dhcpClient = "client"
    dhcpServer = "server"

  # ------------------------------------------------------------------
  # Zones and hosts
  # ------------------------------------------------------------------

  Zone* = ref object
    name*: string
    interfaces*: seq[string]   ## empty for the "fw" zone
    bridge*: bool
    line*: int                 ## Lua source line where declared

  Host* = ref object
    name*: string
    zone*: Zone
    addr4*: string             ## IPv4 address (may be empty)
    addr6*: string             ## IPv6 address (may be empty)
    line*: int

  ## An Endpoint is either a zone or a host (used as from/to in rules).
  Endpoint* = object
    zone*: Zone
    host*: Option[Host]        ## If set, narrows to this host within the zone

  # ------------------------------------------------------------------
  # Services
  # ------------------------------------------------------------------

  ServiceEntry* = object
    proto*: string             ## "tcp", "udp", "icmp", "icmpv6"
    port*: string              ## port or range ("22", "80", "6881-6999", "echo-request")

  Service* = ref object
    name*: string
    entries*: seq[ServiceEntry]
    line*: int

  # ------------------------------------------------------------------
  # Rate limits
  # ------------------------------------------------------------------

  RateLimit* = ref object
    rate*: string              ## e.g. "5/minute"
    burst*: int                ## burst count (0 = no burst)
    name*: string              ## named rate for shared sets (empty = anonymous)

  # ------------------------------------------------------------------
  # Rules
  # ------------------------------------------------------------------

  Rule* = ref object
    src*: Endpoint
    dst*: Endpoint
    action*: Action
    service*: Option[Service]  ## resolved service handle
    proto*: seq[string]        ## raw protocol(s) if no service
    port*: seq[string]         ## raw port(s) if no service
    saddrList*: string         ## iplist reference (empty = none)
    daddrList*: string         ## iplist reference for daddr (empty = none)
    daddrRaw*: string          ## raw destination IP (for forward rules to specific IPs)
    macAddr*: string           ## MAC address match (empty = none)
    connLimit*: int            ## max concurrent connections (0 = no limit)
    rate*: Option[RateLimit]
    log*: string               ## log prefix (empty = no log)
    line*: int

  # ------------------------------------------------------------------
  # Policies
  # ------------------------------------------------------------------

  Policy* = ref object
    src*: Endpoint
    dst*: Endpoint
    action*: Action
    log*: bool
    line*: int

  # ------------------------------------------------------------------
  # NAT
  # ------------------------------------------------------------------

  DnatRule* = ref object
    iface*: Zone               ## incoming interface zone
    daddr*: string             ## original destination match (empty = any)
    service*: Option[Service]
    proto*: seq[string]
    port*: seq[string]
    dest*: string              ## destination IP or host addr
    destPort*: int             ## port remap (0 = same port)
    line*: int

  RedirectRule* = ref object
    iface*: Zone               ## incoming interface zone
    proto*: seq[string]
    port*: seq[string]         ## incoming port(s) to match
    destPort*: int             ## local port to redirect to
    line*: int

  SnatRule* = ref object
    fromNet*: string           ## source subnet
    daddr*: string             ## destination match (empty = any)
    oif*: string               ## outgoing interface name
    masquerade*: bool
    addr4*: string             ## static SNAT address (empty if masquerade)
    proto*: string             ## optional protocol filter
    port*: seq[string]         ## optional port filter
    line*: int

  # ------------------------------------------------------------------
  # IP lists
  # ------------------------------------------------------------------

  IpList* = ref object
    name*: string
    ipType*: string            ## "ipv4" or "ipv6"
    flags*: string             ## "timeout", "interval", etc.
    elements*: seq[string]     ## static elements (may be empty for dynamic)
    url*: string               ## URL for auto-refresh (empty = no refresh)
    line*: int

  # ------------------------------------------------------------------
  # DHCP
  # ------------------------------------------------------------------

  DhcpConfig* = ref object
    zone*: Zone
    role*: DhcpRole
    line*: int

  # ------------------------------------------------------------------
  # Docker
  # ------------------------------------------------------------------

  DockerConfig* = ref object
    backend*: string
    bridges*: seq[string]

  # ------------------------------------------------------------------
  # Hooks (lifecycle commands)
  # ------------------------------------------------------------------

  HookConfig* = object
    preStart*: string
    postStart*: string
    preStop*: string
    postStop*: string

  # ------------------------------------------------------------------
  # Custom chains (mangle / raw / route at arbitrary hooks)
  # ------------------------------------------------------------------

  CustomChain* = ref object
    hook*: string              ## "prerouting" | "postrouting" | "forward" | "input" | "output"
    chainType*: string         ## "filter" | "nat" | "route"
    priority*: string          ## "mangle" | "raw" | numeric, resolved at build time
    rules*: seq[JsonNode]      ## nftables JSON rule expr arrays
    line*: int

  # ------------------------------------------------------------------
  # Drop chain exceptions
  # ------------------------------------------------------------------

  ChainException* = ref object
    chain*: string             ## "invalid" | "rpfilter" | "anti_smurf"
    action*: Action
    service*: Option[Service]
    proto*: seq[string]
    port*: seq[string]
    line*: int

  # ------------------------------------------------------------------
  # Sysctl
  # ------------------------------------------------------------------

  SysctlEntry* = object
    key*: string               ## e.g. "net.ipv4.ip_forward"
    value*: string             ## e.g. "1"
    unset*: bool               ## if true, remove this key from derived set (don't touch it)

  # ------------------------------------------------------------------
  # Global config
  # ------------------------------------------------------------------

  GlobalConfig* = object
    tableName*: string
    priorityOffset*: int
    logRate*: string
    logPrefix*: string
    logLevel*: string
    family*: string            ## "inet" (dual-stack) or "ip" (IPv4 only)
    logSetSize*: int           ## max entries in log rate limiter sets
    logSetTimeout*: int        ## seconds before rate limit entry expires
    counter*: bool             ## add counters to all rules
    inputPolicy*: string       ## default input chain policy ("drop" or "reject")
    outputPolicy*: string      ## default output chain policy ("accept" or "drop")

  # ------------------------------------------------------------------
  # Laundry (packet hygiene)
  # ------------------------------------------------------------------

  LaundryConfig* = object
    rpfilter*: bool
    bogonDrop*: bool
    tcpStrict*: bool
    broadcastDrop*: bool

  # ------------------------------------------------------------------
  # Top-level firewall state
  # ------------------------------------------------------------------

  FirewallState* = ref object
    config*: GlobalConfig
    laundry*: LaundryConfig
    zones*: OrderedTable[string, Zone]
    hosts*: OrderedTable[string, Host]
    services*: OrderedTable[string, Service]
    policies*: seq[Policy]
    rules*: seq[Rule]
    dnatRules*: seq[DnatRule]
    snatRules*: seq[SnatRule]
    redirectRules*: seq[RedirectRule]
    mssClamp*: seq[string]         ## chain names to apply MSS clamping ("forward", "output")
    ipLists*: OrderedTable[string, IpList]
    dhcp*: seq[DhcpConfig]
    docker*: Option[DockerConfig]
    hooks*: HookConfig
    customChains*: seq[CustomChain]
    rawNft*: seq[JsonNode]         ## nftables JSON command objects injected into the ruleset
    chainExceptions*: seq[ChainException]
    sysctlOverrides*: seq[SysctlEntry]  ## explicit fw:sysctl() overrides
    ## Unified name registry -- all zone and host names.
    ## Used to detect collisions.
    names*: OrderedTable[string, string]  ## name -> "zone" or "host"
    includedFiles*: seq[string]
    warnings*: seq[string]

proc newFirewallState*(): FirewallState =
  result = FirewallState(
    config: GlobalConfig(
      tableName: "matchstick",
      priorityOffset: 5,
      logRate: "5/minute burst 5",
      logPrefix: "matchstick",
      logLevel: "info",
      family: "inet",
      logSetSize: 65535,
      logSetTimeout: 60,
      counter: false,
      inputPolicy: "drop",
      outputPolicy: "accept",
    ),
    laundry: LaundryConfig(
      rpfilter: true,
      bogonDrop: true,
      tcpStrict: true,
      broadcastDrop: true,
    ),
    zones: initOrderedTable[string, Zone](),
    hosts: initOrderedTable[string, Host](),
    services: initOrderedTable[string, Service](),
    ipLists: initOrderedTable[string, IpList](),
    names: initOrderedTable[string, string](),
  )

proc registerName*(state: FirewallState, name: string, kind: string, line: int) =
  ## Register a name in the unified namespace. Raises if already taken.
  if name in state.names:
    let existingKind = state.names[name]
    raise newException(CatchableError,
      "name \"" & name & "\" is already registered as a " & existingKind &
      ", cannot reuse as a " & kind & " (line " & $line & ")")
  state.names[name] = kind
