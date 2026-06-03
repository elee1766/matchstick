---------------------------------------------------------------------------
-- matchstick example: Router Firewall
--
-- Three-zone router: WAN, LAN, DMZ
-- Requires IP forwarding: add to /etc/sysctl.d/50-ip-forwarding.conf:
--   net.ipv4.conf.all.forwarding = 1
--   net.ipv6.conf.all.forwarding = 1
---------------------------------------------------------------------------

---------------------------------------------------------------------------
-- Services
---------------------------------------------------------------------------
local ssh   = fw:service("ssh",   "tcp", 22)
local http  = fw:service("http",  "tcp", 80)
local https = fw:service("https", {"tcp", "udp"}, 443)
local dns   = fw:service("dns",   {"tcp", "udp"}, 53)
local ntp   = fw:service("ntp",   "udp", 123)
local ping  = fw:service("ping",  "icmp", "echo-request")
local smtp  = fw:service("smtp",  "tcp", 25)
local imaps = fw:service("imaps", "tcp", 993)

---------------------------------------------------------------------------
-- Zones
---------------------------------------------------------------------------
local self = fw:zone("fw")
local wan  = fw:zone("wan", "eth0")    -- internet-facing
local lan  = fw:zone("lan", "eth1")    -- internal network
local dmz  = fw:zone("dmz", "eth2")    -- DMZ / servers

---------------------------------------------------------------------------
-- Hosts
---------------------------------------------------------------------------
local webserver  = fw:host("webserver",  { zone = dmz, addr = "172.16.0.10" })
local mailserver = fw:host("mailserver", { zone = dmz, addr = "172.16.0.20" })
local admin      = fw:host("admin",      { zone = lan, addr = "10.0.0.10" })

---------------------------------------------------------------------------
-- Packet hygiene
---------------------------------------------------------------------------
fw:laundry({
  rpfilter       = true,
  tcp_strict     = true,
  broadcast_drop = true,
})

---------------------------------------------------------------------------
-- DHCP
---------------------------------------------------------------------------
fw:dhcp(wan, "client")   -- WAN gets IP via DHCP
fw:dhcp(lan, "server")   -- LAN serves DHCP

---------------------------------------------------------------------------
-- IP lists (for blocklisting)
---------------------------------------------------------------------------
fw:iplist("blocklist", { type = "ipv4", flags = "timeout" })

---------------------------------------------------------------------------
-- MSS clamping (needed for PPPoE / VPN tunnels)
---------------------------------------------------------------------------
fw:mss_clamp("forward")

---------------------------------------------------------------------------
-- Policies
---------------------------------------------------------------------------
-- Router itself: allow outbound to all
fw:policy(self, wan,  "accept")
fw:policy(self, lan,  "accept")
fw:policy(self, dmz,  "accept")

-- LAN: trusted, can go anywhere
fw:policy(lan, wan,   "accept")
fw:policy(lan, self,  "accept")
fw:policy(lan, dmz,   "accept")

-- DMZ: can reach internet, limited access to router
fw:policy(dmz, wan,   "accept")
fw:policy(dmz, self,  "reject")

-- WAN: hostile, drop by default
fw:policy(wan, self,  "drop", { log = true })
fw:policy(wan, lan,   "drop", { log = true })
fw:policy(wan, dmz,   "drop", { log = true })

-- Default for any unspecified pair
fw:policy("*", "*", "reject")

---------------------------------------------------------------------------
-- WAN -> FW: services on the router itself
---------------------------------------------------------------------------
fw:rule(wan, self, "drop", { saddr_list = "blocklist" })
fw:rule(wan, self, "accept", ping)
fw:rule(wan, self, "accept", ssh)

---------------------------------------------------------------------------
-- LAN -> FW
---------------------------------------------------------------------------
fw:rule(lan, self, "accept", dns)
fw:rule(lan, self, "accept", ping)
fw:rule(admin, self, "accept", ssh)

---------------------------------------------------------------------------
-- DMZ -> FW
---------------------------------------------------------------------------
fw:rule(dmz, self, "accept", dns)
fw:rule(dmz, self, "accept", ntp)

---------------------------------------------------------------------------
-- WAN -> DMZ: port forwards
---------------------------------------------------------------------------
fw:dnat({ iface = wan, service = https, dest = webserver })
fw:rule(wan, webserver, "accept", https)

fw:dnat({ iface = wan, service = http, dest = webserver })
fw:rule(wan, webserver, "accept", http)

fw:dnat({ iface = wan, service = smtp, dest = mailserver })
fw:rule(wan, mailserver, "accept", smtp)

fw:dnat({ iface = wan, service = imaps, dest = mailserver })
fw:rule(wan, mailserver, "accept", imaps)

---------------------------------------------------------------------------
-- SNAT: masquerade outbound traffic
---------------------------------------------------------------------------
fw:snat({ from = "10.0.0.0/8",     oif = "eth0", masquerade = true })
fw:snat({ from = "172.16.0.0/12",  oif = "eth0", masquerade = true })

---------------------------------------------------------------------------
-- Lifecycle hooks
---------------------------------------------------------------------------
fw:hook({
  post_start = "echo matchstick router firewall applied",
})
