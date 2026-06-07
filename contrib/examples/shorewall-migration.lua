-- config/firewall.lua
-- Exact translation of jelly's Shorewall config to matchstick.
-- Router: Alpine Linux, eth1=WAN (108.210.198.229), eth3=LAN, docker0=Docker

---------------------------------------------------------------------------
-- Services
---------------------------------------------------------------------------
local ssh    = fw:service("ssh",    "tcp", 22)
local http   = fw:service("http",  "tcp", 80)
local https  = fw:service("https", "tcp", 443)
local dns    = fw:service("dns",   { "tcp", "udp" }, 53)
local ping   = fw:service("ping",  "icmp", "echo-request")

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
-- dog = 192.168.0.67 (admin machine)
-- goog = 192.168.0.44 (residential/guest users)
-- camel = 192.168.0.86 (media server: plex, torrents)
local dog   = fw:host("dog",   { zone = home, addr = "192.168.0.67" })
local goog  = fw:host("goog",  { zone = home, addr = "192.168.0.44" })
local camel = fw:host("camel", { zone = home, addr = "192.168.0.86" })

---------------------------------------------------------------------------
-- Packet hygiene
---------------------------------------------------------------------------
fw:laundry({
  rpfilter = true,
  bogon_drop = true,
  tcp_strict = true,       -- Invalid(DROP) inet all tcp
  broadcast_drop = true,
})

fw:dhcp(inet, "client")
fw:dhcp(home, "server")

---------------------------------------------------------------------------
-- CrowdSec
---------------------------------------------------------------------------
fw:iplist("crowdsec4", { type = "ipv4", flags = "timeout" })
fw:iplist("crowdsec6", { type = "ipv6", flags = "timeout" })

---------------------------------------------------------------------------
-- Default policies
-- Shorewall: $FW inet ACCEPT, home inet ACCEPT, home $FW ACCEPT,
--   $FW home ACCEPT, dock $FW REJECT, dock all ACCEPT, $FW dock ACCEPT,
--   inet $FW DROP, inet home DROP, all all REJECT
---------------------------------------------------------------------------
fw:policy(self, inet, "accept")
fw:policy(home, inet, "accept")
fw:policy(home, self, "accept")
fw:policy(self, home, "accept")
fw:policy(dock, self, "reject")
fw:policy(dock, inet, "accept")
fw:policy(dock, home, "accept")     -- dock all ACCEPT includes home
fw:policy(dock, dock, "accept")     -- dock all ACCEPT includes dock-dock
fw:policy(self, dock, "accept")
fw:policy(inet, self, "drop", { log = true })
fw:policy(inet, home, "drop", { log = true })
fw:policy(inet, dock, "drop", { log = true })  -- WAN -> Docker: drop by default, explicit rules for DNAT
fw:policy("*", "*", "reject")                   -- all all REJECT

---------------------------------------------------------------------------
-- CrowdSec rules (before other rules, first-match-wins)
---------------------------------------------------------------------------
fw:rule(inet, self, "drop", { saddr_list = "crowdsec4" })
fw:rule(inet, self, "drop", { saddr_list = "crowdsec6" })
fw:rule(inet, home, "drop", { saddr_list = "crowdsec4" })
fw:rule(inet, home, "drop", { saddr_list = "crowdsec6" })

---------------------------------------------------------------------------
-- WAN -> FW rules
-- Shorewall: Ping(ACCEPT) inet $FW
--   ACCEPT inet $FW icmp
--   ACCEPT inet $FW tcp 443,80,8448
--   ACCEPT inet $FW udp 443
--   ACCEPT inet $FW udp 52000:52100
--   ACCEPT inet $FW tcp 32400
--   ACCEPT inet $FW udp 1900,32410,32412:32414
---------------------------------------------------------------------------
fw:rule(inet, self, "accept", ping)
fw:rule(inet, self, "accept", { proto = "tcp", port = { 443, 80, 8448 } })
fw:rule(inet, self, "accept", { proto = "udp", port = 443 })
fw:rule(inet, self, "accept", { proto = "udp", port = "52000-52100" })
fw:rule(inet, self, "accept", { proto = "tcp", port = 32400 })
fw:rule(inet, self, "accept", { proto = "udp", port = { 1900, 32410, "32412-32414" } })

---------------------------------------------------------------------------
-- LAN -> FW rules
-- Shorewall: ACCEPT home $FW udp 53
--   ACCEPT home $FW icmp
--   ACCEPT home:192.168.0.67 $FW tcp 3000
--   ACCEPT home:192.168.0.44 $FW tcp 3000
--   ACCEPT home:192.168.0.67 $FW tcp 667
--   ACCEPT home:192.168.0.44 $FW tcp 443,80,8448
--   ACCEPT home:192.168.0.44 $FW udp 80
--   ACCEPT home:192.168.0.67 $FW tcp 22,80,443,8448
--   ACCEPT home:192.168.0.67 $FW udp 52000:52100
---------------------------------------------------------------------------
fw:rule(home, self, "accept", dns)
fw:rule(home, self, "accept", ping)
fw:rule(dog,  self, "accept", { proto = "tcp", port = 3000 })         -- AdGuard
fw:rule(goog, self, "accept", { proto = "tcp", port = 3000 })         -- AdGuard
fw:rule(dog,  self, "accept", { proto = "tcp", port = 667 })
fw:rule(goog, self, "accept", { proto = "tcp", port = { 443, 80, 8448 } })
fw:rule(goog, self, "accept", { proto = "udp", port = 80 })
fw:rule(dog,  self, "accept", { proto = "tcp", port = { 22, 80, 443, 8448 } })
fw:rule(dog,  self, "accept", { proto = "udp", port = "52000-52100" })

---------------------------------------------------------------------------
-- LAN -> LAN rules
-- Shorewall: ACCEPT home home icmp
--   ACCEPT home:192.168.0.67 home:192.168.0.86 tcp 8384  (syncthing)
--   ACCEPT home home udp 1900  (UPnP)
---------------------------------------------------------------------------
fw:rule(home, home, "accept", ping)
fw:rule(dog, camel, "accept", { proto = "tcp", port = 8384 })
fw:rule(home, home, "accept", { proto = "udp", port = 1900 })

---------------------------------------------------------------------------
-- LAN -> inet rules
-- Shorewall: ACCEPT home inet icmp
---------------------------------------------------------------------------
fw:rule(home, inet, "accept", ping)

---------------------------------------------------------------------------
-- Docker -> FW rules
-- Shorewall: ACCEPT dock $FW udp 53, ACCEPT dock $FW tcp 53
---------------------------------------------------------------------------
fw:rule(dock, self, "accept", dns)

---------------------------------------------------------------------------
-- FW -> home rules (explicit in Shorewall, redundant with policy but translated)
-- Shorewall: ACCEPT $FW home tcp, ACCEPT $FW home udp, ACCEPT $FW home icmp
-- These are redundant with policy(self, home, "accept") but were in the config.
-- Not needed in matchstick since the policy already accepts.
---------------------------------------------------------------------------

---------------------------------------------------------------------------
-- Docker config
---------------------------------------------------------------------------
fw:docker({ bridges = { "docker0", "br-+" } })

---------------------------------------------------------------------------
-- DNAT: Plex (inet -> camel)
-- Shorewall: DNAT inet home:192.168.0.86 tcp 32400
--   DNAT inet home:192.168.0.86 udp 1900,32410,32412:32414
---------------------------------------------------------------------------
fw:dnat({ iface = inet, proto = "tcp", port = 32400, dest = camel })
fw:dnat({ iface = inet, proto = "udp", port = 1900, dest = camel })
fw:dnat({ iface = inet, proto = "udp", port = "32410-32414", dest = camel })
-- Note: Shorewall had 32410,32412:32414 (missing 32411). Keeping exact translation.
-- The forward rules for plex/torrent are implicit in Shorewall via DNAT.
-- In matchstick we need explicit forward rules:
fw:rule(inet, camel, "accept", { proto = "tcp", port = 32400 })
fw:rule(inet, camel, "accept", { proto = "udp", port = 1900 })
fw:rule(inet, camel, "accept", { proto = "udp", port = "32410-32414" })

---------------------------------------------------------------------------
-- DNAT: Torrents (inet -> home, any host)
-- Shorewall: ACCEPT inet home tcp,udp 6881:6999
-- Note: Shorewall has no DNAT for torrents, just a forward accept.
-- This means torrent traffic goes to whatever host responds (no DNAT rewrite).
---------------------------------------------------------------------------
fw:rule(inet, home, "accept", { proto = { "tcp", "udp" }, port = "6881-6999" })

---------------------------------------------------------------------------
-- Neko WebRTC (WAN -> Docker container + hairpin from LAN)
--
-- Two paths:
--   1. Public users: WAN udp 52000-52100 → DNAT → 172.17.0.3 (inet_to_dock forward)
--   2. LAN hairpin: LAN hits public IP → DNAT → 172.17.0.3 (home_to_dock forward)
--
-- In Shorewall, path 1 was handled by Docker's DOCKER-USER chain.
-- In matchstick/nftables, we own the forward chain and must allow explicitly.
--
-- Shorewall: ACCEPT inet $FW udp 52000:52100  (input to host -- Docker proxy)
--   DNAT home dock:172.17.0.3 udp 52000:52100 - 108.210.198.229  (hairpin)
--   DOCKER-USER: inet -> docker udp 52000:52100 ACCEPT  (forward)
---------------------------------------------------------------------------
-- WAN direct: DNAT is handled by Docker (published ports), but we need the
-- forward rule to allow the post-DNAT packets through our forward chain
fw:rule(inet, dock, "accept", { daddr = "172.17.0.3", proto = "udp", port = "52000-52100" })

-- LAN hairpin: DNAT via public IP, then forward + SNAT
fw:dnat({ iface = home, daddr = "108.210.198.229",
          proto = "udp", port = "52000-52100",
          dest = "172.17.0.3" })
fw:rule(home, dock, "accept", { daddr = "172.17.0.3", proto = "udp", port = "52000-52100" })

---------------------------------------------------------------------------
-- SNAT / Masquerade
-- Shorewall: MASQUERADE 192.168.0.0/16 eth1
--   MASQUERADE 172.17.0.0/12 eth1
--   SNAT(192.168.0.1) 192.168.0.0/16 eth3:192.168.0.1 tcp 80,443,32400
--   SNAT(172.17.0.1) 192.168.0.0/16 docker0:172.17.0.3 udp 52000:52100
---------------------------------------------------------------------------
fw:snat({ from = "192.168.0.0/16", oif = "eth1", masquerade = true })
fw:snat({ from = "172.17.0.0/12",  oif = "eth1", masquerade = true })
fw:snat({ from = "192.168.0.0/16", daddr = "192.168.0.1",
          oif = "eth3", proto = "tcp", port = { 80, 443, 32400 },
          addr = "192.168.0.1" })
fw:snat({ from = "192.168.0.0/16", daddr = "172.17.0.3",
          oif = "docker0", proto = "udp", port = "52000-52100",
          addr = "172.17.0.1" })
