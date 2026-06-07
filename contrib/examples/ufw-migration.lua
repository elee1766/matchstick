---------------------------------------------------------------------------
-- matchstick example: UFW Migration
--
-- This config is a direct translation of a real UFW setup to matchstick.
-- It shows how matchstick can replace UFW as a declarative host firewall.
--
-- UFW equivalent:
--   Default: deny incoming, allow outgoing, deny forward
--   + per-port allow rules with source filtering
--
-- Key differences from UFW:
--   - All rules are in one file (version-controllable, reviewable)
--   - Services are named and reusable
--   - Zone model makes source filtering clearer
--   - NAT/forwarding are first-class (no editing before.rules)
--   - Sysctl settings are derived automatically
---------------------------------------------------------------------------

---------------------------------------------------------------------------
-- Services
---------------------------------------------------------------------------
local ssh       = fw:service("ssh",       "tcp", 22)
local vnc       = fw:service("vnc",       "tcp", 5901)
local dhcp_srv  = fw:service("dhcp-srv",  "udp", 67)
local dhcp_cli  = fw:service("dhcp-cli",  "udp", 68)
local mosh      = fw:service("mosh",      "udp", "60000-61000")

-- Steam Remote Play / In-Home Streaming
local steam_udp = fw:service("steam-udp", "udp", 27036)
local steam_tcp = fw:service("steam-tcp", "tcp", 27036)

-- Custom application ports
local app_udp_tcp = fw:service("app-42069", {
  {"udp", 42069},
  {"tcp", 42069},
})

---------------------------------------------------------------------------
-- Zones
--
-- In UFW, there are no zones -- everything is flat "allow from X to port Y".
-- In matchstick, we model the network topology explicitly.
---------------------------------------------------------------------------
local self = fw:zone("fw")

-- Primary LAN interface
local lan = fw:zone("lan", "eth0")  -- adjust interface name to match your system

---------------------------------------------------------------------------
-- Hosts (source address filtering -- replaces UFW's "from" clauses)
---------------------------------------------------------------------------
local router   = fw:host("router",   { zone = lan, addr = "192.168.0.1" })
local steambox = fw:host("steambox", { zone = lan, addr = "192.168.0.27" })
local winbox   = fw:host("winbox",   { zone = lan, addr = "192.168.0.111" })

---------------------------------------------------------------------------
-- Policies (replaces UFW's DEFAULT_*_POLICY)
--
-- UFW: DEFAULT_INPUT_POLICY="DROP"
--      DEFAULT_OUTPUT_POLICY="ACCEPT"
--      DEFAULT_FORWARD_POLICY="DROP"
---------------------------------------------------------------------------
fw:policy(lan, self,  "drop", { log = true })   -- deny incoming (log drops)
fw:policy(self, lan,  "accept")                  -- allow outgoing

-- Default for anything else
fw:policy("*", "*", "drop")

---------------------------------------------------------------------------
-- DHCP (replaces UFW's allow 67/udp + allow 68)
---------------------------------------------------------------------------
fw:dhcp(lan, "client")

---------------------------------------------------------------------------
-- Incoming rules: LAN -> FW
-- (replaces UFW's "ufw allow" rules)
---------------------------------------------------------------------------

-- Custom service from router (UFW: 5888/tcp ALLOW 192.168.0.1)
-- NOTE: In UFW this was a separate rule. Here we just allow everything
-- from the router, which is cleaner and what the original intent was.
-- If you only wanted port 5888: fw:rule(router, self, "accept", { proto = "tcp", port = "5888" })
fw:rule(router, self, "accept")

-- SSH from LAN subnet (UFW: 22/tcp ALLOW 192.168.0.0/16)
fw:rule(lan, self, "accept", ssh)

-- Mosh from LAN subnet (UFW: 60000:61000/udp ALLOW 192.168.0.0/16)
fw:rule(lan, self, "accept", mosh)

-- VNC from anywhere (UFW: 5901 ALLOW Anywhere)
fw:rule(lan, self, "accept", vnc)

-- WS-Discovery from LAN (UFW: 3702/udp ALLOW 192.168.0.0/16)
fw:rule(lan, self, "accept", { proto = "udp", port = "3702" })

-- Scream audio from winbox only (was: 4010/udp ALLOW Anywhere)
fw:rule(winbox, self, "accept", { proto = "udp", port = "4010" })

-- Custom app (UFW: 42069/udp+tcp ALLOW Anywhere)
fw:rule(lan, self, "accept", app_udp_tcp)

-- SSDP/UPnP from LAN (UFW: 44794/udp ALLOW 192.168.0.0/16)
fw:rule(lan, self, "accept", { proto = "udp", port = "44794" })

-- Steam Remote Play discovery
fw:rule(steambox, self, "accept", steam_udp)
fw:rule(winbox, self, "accept", steam_udp)
fw:rule(winbox, self, "accept", steam_tcp)

-- Steam streaming ports (UFW: 34037:60000/udp ALLOW 192.168.0.27)
fw:rule(steambox, self, "accept", { proto = "udp", port = "34037-60000" })

-- RTP/media ports (UFW: 52000:52100/udp ALLOW Anywhere)
fw:rule(lan, self, "accept", { proto = "udp", port = "52000-52100" })

---------------------------------------------------------------------------
-- Sysctl overrides
--
-- UFW's /etc/ufw/sysctl.conf had log_martians=0. Matchstick defaults to 1
-- (more secure). Override to match UFW behavior if needed:
---------------------------------------------------------------------------
-- fw:sysctl("net.ipv4.conf.all.log_martians", "0")
-- fw:sysctl("net.ipv4.conf.default.log_martians", "0")
