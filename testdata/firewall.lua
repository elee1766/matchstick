-- test/firewall.lua -- exercises the full matchstick API

---------------------------------------------------------------------------
-- Services
---------------------------------------------------------------------------
local ssh   = fw:service("ssh",   "tcp", 22)
local http  = fw:service("http",  "tcp", 80)
local https = fw:service("https", { "tcp", "udp" }, 443)
local dns   = fw:service("dns",   { "tcp", "udp" }, 53)
local ping  = fw:service("ping",  "icmp", "echo-request")

local plex = fw:service("plex", {
  { "tcp", 32400 },
  { "udp", 1900 },
  { "udp", "32410-32414" },
})

---------------------------------------------------------------------------
-- Zones
---------------------------------------------------------------------------
local self = fw:zone("fw")
local inet = fw:zone("inet", "eth1")
local home = fw:zone("home", "eth3")
local dock = fw:zone("dock", "docker0")

---------------------------------------------------------------------------
-- Hosts
---------------------------------------------------------------------------
local dog   = fw:host("dog",   { zone = home, addr = "192.168.0.67" })
local camel = fw:host("camel", { zone = home, addr = "192.168.0.86" })
local goog  = fw:host("goog",  { zone = home, addr = "192.168.0.44" })

---------------------------------------------------------------------------
-- Global
---------------------------------------------------------------------------
fw:laundry({
  rpfilter = true,
  bogon_drop = true,
  tcp_strict = true,
  broadcast_drop = true,
})

fw:dhcp(inet, "client")
fw:dhcp(home, "server")

fw:iplist("crowdsec4", { type = "ipv4", flags = "timeout" })
fw:iplist("crowdsec6", { type = "ipv6", flags = "timeout" })

---------------------------------------------------------------------------
-- WAN
---------------------------------------------------------------------------
fw:policy(inet, self, "drop", { log = true })
fw:policy(inet, home, "drop", { log = true })
fw:policy(self, inet, "accept")

fw:rule(inet, self, "drop", { saddr_list = "crowdsec4" })
fw:rule(inet, self, "drop", { saddr_list = "crowdsec6" })
fw:rule(inet, home, "drop", { saddr_list = "crowdsec4" })
fw:rule(inet, home, "drop", { saddr_list = "crowdsec6" })

fw:rule(inet, self, "accept", http)
fw:rule(inet, self, "accept", https)
fw:rule(inet, self, "accept", { proto = "tcp", port = 8448 })
fw:rule(inet, self, "accept", { proto = "udp", port = "52000-52100" })
fw:rule(inet, self, "accept", ping)

fw:snat({ from = "192.168.0.0/16", oif = "eth1", masquerade = true })

---------------------------------------------------------------------------
-- LAN
---------------------------------------------------------------------------
fw:policy(home, self, "accept")
fw:policy(home, inet, "accept")
fw:policy(self, home, "accept")

fw:rule(home, self, "accept", dns)
fw:rule(home, self, "accept", ping)
fw:rule(dog,  self, "accept", ssh)
fw:rule(dog,  self, "accept", { proto = "tcp", port = 3000 })
fw:rule(goog, self, "accept", { proto = "tcp", port = 3000 })

fw:rule(home, home, "accept", { proto = "udp", port = 1900 })
fw:rule(dog, camel, "accept", { proto = "tcp", port = 8384 })

---------------------------------------------------------------------------
-- Docker
---------------------------------------------------------------------------
fw:docker({ bridges = { "docker0", "br-+" } })

fw:policy(dock, self, "reject")
fw:policy(dock, inet, "accept")
fw:policy(dock, home, "accept")
fw:policy(dock, dock, "accept")
fw:policy(self, dock, "accept")

fw:rule(dock, self, "accept", dns)

fw:snat({ from = "172.17.0.0/12", oif = "eth1", masquerade = true })

---------------------------------------------------------------------------
-- Plex
---------------------------------------------------------------------------
fw:dnat({ iface = inet, service = plex, dest = camel })
fw:rule(inet, camel, "accept", plex)

---------------------------------------------------------------------------
-- Torrents
---------------------------------------------------------------------------
fw:dnat({ iface = inet, proto = { "tcp", "udp" }, port = "6881-6999",
          dest = camel })
fw:rule(inet, camel, "accept", {
  proto = { "tcp", "udp" }, port = "6881-6999",
})

---------------------------------------------------------------------------
-- Neko hairpin
---------------------------------------------------------------------------
fw:dnat({ iface = home, daddr = "108.210.198.229",
          proto = "udp", port = "52000-52100",
          dest = "172.17.0.3" })
fw:rule(home, dock, "accept", { proto = "udp", port = "52000-52100" })

fw:snat({ from = "192.168.0.0/16", daddr = "192.168.0.1",
          oif = "eth3", proto = "tcp", port = { 80, 443, 32400 },
          addr = "192.168.0.1" })
fw:snat({ from = "192.168.0.0/16", daddr = "172.17.0.3",
          oif = "docker0", proto = "udp", port = "52000-52100",
          addr = "172.17.0.1" })

-- Config loaded successfully (don't print to stdout -- it contaminates render output)
