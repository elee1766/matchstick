-- tests/golden/full.lua
-- Comprehensive test config exercising every matchstick API feature.
-- Uses generic/example networks, not real infrastructure.

---------------------------------------------------------------------------
-- Services: all forms
---------------------------------------------------------------------------
-- Simple: proto, port
local ssh   = fw:service("ssh",   "tcp", 22)
local http  = fw:service("http",  "tcp", 80)
local ntp   = fw:service("ntp",   "udp", 123)

-- Multi-proto same port
local dns   = fw:service("dns",   { "tcp", "udp" }, 53)
local https = fw:service("https", { "tcp", "udp" }, 443)

-- ICMP
local ping  = fw:service("ping",  "icmp", "echo-request")

-- Complex: array of {proto, port} pairs with ranges
local media = fw:service("media", {
  { "tcp", 8080 },
  { "udp", 9000 },
  { "udp", "9100-9200" },
})

---------------------------------------------------------------------------
-- Zones: all forms
---------------------------------------------------------------------------
local self = fw:zone("fw")
local wan  = fw:zone("wan", "eth0")
local lan  = fw:zone("lan", "eth1")
local dmz  = fw:zone("dmz", "eth2")
local dock = fw:zone("dock", "docker0")

---------------------------------------------------------------------------
-- Hosts
---------------------------------------------------------------------------
local admin  = fw:host("admin",  { zone = lan, addr = "10.0.0.10" })
local server = fw:host("server", { zone = lan, addr = "10.0.0.20" })
local guest  = fw:host("guest",  { zone = lan, addr = "10.0.0.100" })
local webbox = fw:host("webbox", { zone = dmz, addr = "172.16.0.10" })

---------------------------------------------------------------------------
-- Packet hygiene
---------------------------------------------------------------------------
fw:laundry({
  rpfilter = true,
  bogon_drop = true,
  tcp_strict = true,
  broadcast_drop = true,
})

---------------------------------------------------------------------------
-- DHCP
---------------------------------------------------------------------------
fw:dhcp(wan, "client")
fw:dhcp(lan, "server")

---------------------------------------------------------------------------
-- IP lists
---------------------------------------------------------------------------
fw:iplist("blocklist4", { type = "ipv4", flags = "timeout" })
fw:iplist("blocklist6", { type = "ipv6", flags = "timeout" })
fw:iplist("bogons", {
  type = "ipv4",
  flags = "interval",
  elements = {
    "0.0.0.0/8",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "224.0.0.0/3",
  },
})

---------------------------------------------------------------------------
-- Docker
---------------------------------------------------------------------------
fw:docker({ bridges = { "docker0", "br-+" } })

---------------------------------------------------------------------------
-- Policies: full matrix with wildcard default
---------------------------------------------------------------------------
fw:policy(self, wan,  "accept")
fw:policy(self, lan,  "accept")
fw:policy(self, dmz,  "accept")
fw:policy(self, dock, "accept")

fw:policy(lan, wan,   "accept")
fw:policy(lan, self,  "accept")
fw:policy(lan, dmz,   "accept")

fw:policy(dmz, wan,   "accept")
fw:policy(dmz, self,  "reject")

fw:policy(dock, wan,  "accept")
fw:policy(dock, self, "reject")
fw:policy(dock, dock, "accept")

fw:policy(wan, self,  "drop", { log = true })
fw:policy(wan, lan,   "drop", { log = true })
fw:policy(wan, dmz,   "drop", { log = true })
fw:policy(wan, dock,  "reject")

fw:policy("*", "*",   "reject")  -- default for unspecified pairs

---------------------------------------------------------------------------
-- WAN -> FW: blocklists first, then services
---------------------------------------------------------------------------
fw:rule(wan, self, "drop", { saddr_list = "blocklist4" })
fw:rule(wan, self, "drop", { saddr_list = "blocklist6" })
fw:rule(wan, self, "accept", ping)
fw:rule(wan, self, "accept", https)
fw:rule(wan, self, "accept", ssh)

-- Rule with rate limit
fw:rule(wan, self, "accept", {
  service = ssh,
  rate = util:rate("3/minute", { burst = 5 }),
})

-- Rule with raw proto + multiple ports
fw:rule(wan, self, "accept", { proto = "tcp", port = { 8080, 8443, 9090 } })

-- Rule with port range
fw:rule(wan, self, "accept", { proto = "udp", port = "10000-10100" })

---------------------------------------------------------------------------
-- LAN -> FW: host-specific rules
---------------------------------------------------------------------------
fw:rule(lan, self, "accept", dns)
fw:rule(lan, self, "accept", ping)

-- Admin gets SSH
fw:rule(admin, self, "accept", ssh)

-- Admin gets extra ports
fw:rule(admin, self, "accept", { proto = "tcp", port = { 3000, 8080, 9090 } })

-- Guest is restricted: only DNS, block everything else
fw:rule(guest, self, "accept", dns)
fw:rule(guest, self, "drop")    -- bare rule: block all other traffic from guest

---------------------------------------------------------------------------
-- LAN -> LAN: internal traffic
---------------------------------------------------------------------------
fw:rule(lan, lan, "accept", ping)
fw:rule(admin, server, "accept", ssh)
fw:rule(admin, server, "accept", { proto = "tcp", port = 8384 })  -- syncthing
fw:rule(lan, lan, "accept", { proto = "udp", port = 1900 })       -- UPnP

---------------------------------------------------------------------------
-- LAN -> WAN
---------------------------------------------------------------------------
fw:rule(lan, wan, "accept", ping)

---------------------------------------------------------------------------
-- DMZ -> FW
---------------------------------------------------------------------------
fw:rule(dmz, self, "accept", dns)
fw:rule(dmz, self, "accept", ntp)

---------------------------------------------------------------------------
-- Docker -> FW
---------------------------------------------------------------------------
fw:rule(dock, self, "accept", dns)

---------------------------------------------------------------------------
-- DNAT: WAN port forwards to DMZ
---------------------------------------------------------------------------
fw:dnat({ iface = wan, service = https, dest = webbox })
fw:rule(wan, webbox, "accept", https)

fw:dnat({ iface = wan, service = media, dest = webbox })
fw:rule(wan, webbox, "accept", media)

-- DNAT with port remap
fw:dnat({ iface = wan, proto = "tcp", port = 2222, dest = server, dest_port = 22 })
fw:rule(wan, server, "accept", { proto = "tcp", port = 22 })

-- DNAT with daddr match (hairpin)
fw:dnat({ iface = lan, daddr = "203.0.113.1",
          proto = "tcp", port = { 80, 443 },
          dest = webbox })
fw:rule(lan, dmz, "accept", { daddr = "172.16.0.10", proto = "tcp", port = { 80, 443 } })

---------------------------------------------------------------------------
-- SNAT
---------------------------------------------------------------------------
-- Masquerade for outbound
fw:snat({ from = "10.0.0.0/8",     oif = "eth0", masquerade = true })
fw:snat({ from = "172.16.0.0/12",  oif = "eth0", masquerade = true })
fw:snat({ from = "172.17.0.0/12",  oif = "eth0", masquerade = true })

-- Port-specific hairpin SNAT
fw:snat({ from = "10.0.0.0/8", daddr = "172.16.0.10",
          oif = "eth2", proto = "tcp", port = { 80, 443 },
          addr = "172.16.0.1" })
