---------------------------------------------------------------------------
-- matchstick example: Host Firewall
--
-- Simple firewall for a single server (no forwarding).
-- Drop all incoming traffic except the services you explicitly allow.
---------------------------------------------------------------------------

---------------------------------------------------------------------------
-- Services
---------------------------------------------------------------------------
local ssh   = fw:service("ssh",   "tcp", 22)
local http  = fw:service("http",  "tcp", 80)
local https = fw:service("https", {"tcp", "udp"}, 443)
local dns   = fw:service("dns",   {"tcp", "udp"}, 53)
local ping  = fw:service("ping",  "icmp", "echo-request")

---------------------------------------------------------------------------
-- Zones
---------------------------------------------------------------------------
local self   = fw:zone("fw")
local public = fw:zone("public", "eth0")    -- change to your interface

---------------------------------------------------------------------------
-- Packet hygiene (all enabled by default, shown here for reference)
---------------------------------------------------------------------------
fw:laundry({
  rpfilter       = true,     -- reverse path filtering
  tcp_strict     = true,     -- drop malformed TCP flags
  broadcast_drop = true,     -- drop broadcast/multicast
})

---------------------------------------------------------------------------
-- DHCP (uncomment if using DHCP on the public interface)
---------------------------------------------------------------------------
-- fw:dhcp(public, "client")

---------------------------------------------------------------------------
-- Policies
---------------------------------------------------------------------------
fw:policy(self, public, "accept")             -- outbound: allow all
fw:policy(public, self, "drop", { log = true }) -- inbound: drop + log

---------------------------------------------------------------------------
-- Inbound rules: allow specific services
---------------------------------------------------------------------------
fw:rule(public, self, "accept", ssh)
fw:rule(public, self, "accept", http)
fw:rule(public, self, "accept", https)
fw:rule(public, self, "accept", ping)

-- Rate-limit SSH to prevent brute force
fw:rule(public, self, "accept", {
  service = ssh,
  rate = util:rate("5/minute", { burst = 10 }),
})

---------------------------------------------------------------------------
-- Lifecycle hooks (optional)
---------------------------------------------------------------------------
-- fw:hook({ post_start = "echo matchstick firewall applied" })
