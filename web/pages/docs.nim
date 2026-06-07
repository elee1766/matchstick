## Documentation page.

import karax/[karaxdsl, vdom]
import ./layout

proc docsPage*(): string =
  let content = buildHtml(tdiv):
    h1: text "Documentation"

    # ----- Concepts -----
    section:
      h2: text "How It Works"
      p:
        text "Matchstick compiles a Lua configuration file into nftables rules. "
        text "You describe your network in terms of zones, hosts, services, policies, and rules. "
        text "Matchstick builds the nftables chains, sets, and verdict maps automatically."
      pre:
        code:
          text "firewall.lua  →  Lua VM  →  validate  →  nftables IR  →  text or JSON output"
      p:
        text "At apply time, matchstick also derives and sets kernel sysctl parameters "
        text "(IP forwarding, ARP hardening, etc.) based on your config."

    section:
      h2: text "Zones"
      p:
        text "A zone is a group of network interfaces that share the same trust level. "
        text "Every config needs exactly one zone with no interfaces — the firewall host itself."
      pre:
        code:
          text """local self = fw:zone("fw")              -- the firewall machine (no interface)
local wan  = fw:zone("wan", "eth0")     -- internet-facing
local lan  = fw:zone("lan", "eth1")     -- trusted LAN
local dmz  = fw:zone("dmz", "eth2")     -- servers

-- A zone can have multiple interfaces
local internal = fw:zone("internal", {"eth1", "eth2"})

-- Bridge zone (for Docker, LXC, etc.)
local dock = fw:zone("dock", "docker0", { bridge = true })"""
      p:
        text "Traffic between zones is controlled by policies and rules. "
        text "Matchstick uses nftables verdict maps to dispatch packets from base chains "
        text "to per-zone-pair chains, which is faster than linear rule matching."

    section:
      h2: text "Hosts"
      p:
        text "A host is a specific IP address within a zone. "
        text "Use hosts when you need per-machine rules instead of whole-zone rules."
      pre:
        code:
          text """local server = fw:host("server", { zone = lan, addr = "10.0.0.10" })
local admin  = fw:host("admin",  { zone = lan, addr = "10.0.0.50" })

-- Hosts can be used anywhere zones can be used
fw:rule(admin, self, "accept", ssh)   -- only admin gets SSH
fw:rule(server, dmz, "accept", http)  -- server can reach DMZ"""

    section:
      h2: text "Services"
      p:
        text "A service is a named protocol + port combination. "
        text "Define once, reuse everywhere."
      pre:
        code:
          text """-- Simple: one protocol, one port
local ssh  = fw:service("ssh", "tcp", 22)
local ntp  = fw:service("ntp", "udp", 123)

-- Multiple protocols, same port (e.g. DNS)
local dns  = fw:service("dns", {"tcp", "udp"}, 53)

-- Port range
local mosh = fw:service("mosh", "udp", "60000-61000")

-- ICMP type
local ping = fw:service("ping", "icmp", "echo-request")

-- Complex: multiple protocol/port pairs
local plex = fw:service("plex", {
  {"tcp", 32400},
  {"udp", 1900},
  {"udp", "32410-32414"},
})"""

    section:
      h2: text "Policies"
      p:
        text "A policy sets the default action for traffic between two zones. "
        text "Policies apply to all traffic that doesn't match a more specific rule."
      pre:
        code:
          text """fw:policy(wan, self, "drop", { log = true })  -- drop incoming, log it
fw:policy(self, wan, "accept")                -- allow outgoing
fw:policy(lan, wan, "accept")                 -- LAN can reach internet
fw:policy(lan, self, "accept")                -- LAN can reach firewall

-- Wildcard: default for any pair not explicitly listed
fw:policy("*", "*", "reject")"""
      p:
        text "Actions: \"accept\", \"drop\", \"reject\". "
        text "Reject sends an ICMP admin-prohibited response. "
        text "Drop silently discards the packet."

    section:
      h2: text "Rules"
      p:
        text "Rules allow or deny specific traffic between zones. "
        text "They are evaluated before the zone-pair policy."
      pre:
        code:
          text """-- Allow a service
fw:rule(wan, self, "accept", ssh)

-- Allow by protocol and port (no named service needed)
fw:rule(wan, self, "accept", { proto = "tcp", port = {80, 443} })

-- Port range
fw:rule(wan, self, "accept", { proto = "udp", port = "10000-10100" })

-- Rate-limited rule
fw:rule(wan, self, "accept", {
  service = ssh,
  rate = util:rate("5/minute", { burst = 10 }),
})

-- Connection limit (max concurrent connections)
fw:rule(wan, self, "accept", { service = ssh, connlimit = 10 })

-- MAC address filter
fw:rule(lan, self, "accept", { service = ssh, mac = "aa:bb:cc:dd:ee:ff" })

-- Source IP list (for blocklists, GeoIP, etc.)
fw:rule(wan, self, "drop", { saddr_list = "blocklist" })

-- Destination IP list
fw:rule(lan, wan, "accept", { service = http, daddr_list = "allowed_hosts" })

-- Bare rule (match all traffic, no port/proto filter)
fw:rule(guest, self, "drop")  -- block everything from guest"""

    section:
      h2: text "NAT"
      h3: text "DNAT (Port Forwarding)"
      p: text "Forward incoming traffic from one zone to a host in another zone."
      pre:
        code:
          text """fw:dnat({ iface = wan, service = http, dest = webserver })
fw:rule(wan, webserver, "accept", http)  -- also need a forward rule

-- With port remap
fw:dnat({ iface = wan, proto = "tcp", port = 2222, dest = server, dest_port = 22 })

-- Hairpin NAT (LAN accessing internal server via public IP)
fw:dnat({ iface = lan, daddr = "203.0.113.1", proto = "tcp", port = {80, 443}, dest = webserver })"""

      h3: text "SNAT / Masquerade"
      p: text "Rewrite the source address of outgoing traffic."
      pre:
        code:
          text """-- Masquerade (dynamic IP — most common for home/office)
fw:snat({ from = "10.0.0.0/8", oif = "eth0", masquerade = true })

-- Static SNAT (server with fixed IP)
fw:snat({ from = "10.0.0.0/8", oif = "eth0", addr = "203.0.113.1" })"""

      h3: text "Redirect"
      p: text "Redirect traffic to a local port (transparent proxy)."
      pre:
        code:
          text """fw:redirect({ iface = lan, proto = "tcp", port = {80}, dest_port = 3128 })"""

    section:
      h2: text "IP Lists"
      p:
        text "Named sets of IP addresses. Used for blocklists, allowlists, GeoIP, etc. "
        text "Sets are created in nftables and can be populated dynamically."
      pre:
        code:
          text """-- Dynamic set (populated externally, e.g. by CrowdSec or fail2ban)
fw:iplist("blocklist", { type = "ipv4", flags = "timeout" })

-- Static set with elements
fw:iplist("bogons", {
  type = "ipv4",
  flags = "interval",
  elements = { "0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16" },
})

-- Set with URL for auto-refresh (future: matchstick refresh)
fw:iplist("threats", { type = "ipv4", flags = "timeout", url = "https://example.com/blocklist.txt" })

-- Use in rules
fw:rule(wan, self, "drop", { saddr_list = "blocklist" })"""

    section:
      h2: text "Packet Hygiene"
      p:
        text "Automatic packet sanity checks. All enabled by default."
      pre:
        code:
          text """fw:laundry({
  rpfilter       = true,   -- reverse path filtering (anti-spoofing)
  tcp_strict     = true,   -- drop malformed TCP flag combinations
  broadcast_drop = true,   -- drop broadcast/multicast in forward chain
})"""
      p:
        text "Exceptions can be added to the drop chains:"
      pre:
        code:
          text """-- Accept IPVS traffic that enters the invalid chain
fw:exception("invalid", "accept", https)

-- Accept DHCP broadcasts past anti-smurf
fw:exception("anti_smurf", "accept", { proto = "udp", port = {67, 68} })"""

    section:
      h2: text "MSS Clamping"
      p: text "Required for PPPoE, VPN tunnels, or any path with reduced MTU."
      pre:
        code:
          text """fw:mss_clamp("forward")  -- clamp TCP SYN MSS to path MTU"""

    section:
      h2: text "DHCP"
      pre:
        code:
          text """fw:dhcp(wan, "client")   -- this machine gets IP via DHCP on wan
fw:dhcp(lan, "server")  -- this machine serves DHCP on lan"""

    section:
      h2: text "Docker"
      pre:
        code:
          text """fw:docker({ bridges = {"docker0", "br-+"} })"""

    section:
      h2: text "Sysctl"
      p:
        text "Matchstick automatically derives kernel sysctl settings from your config. "
        text "IP forwarding is enabled when forwarding rules exist. "
        text "ARP hardening, redirect protection, and source routing protection are always set."
      pre:
        code:
          text """-- Add custom sysctls
fw:sysctl("net.ipv4.tcp_syncookies", "1")

-- Batch form
fw:sysctl({
  ["net.netfilter.nf_conntrack_max"] = "262144",
  ["net.core.somaxconn"] = "4096",
})

-- Unset a derived default (matchstick won't touch it)
fw:sysctl("net.ipv4.conf.all.forwarding", false)"""

    section:
      h2: text "Hooks"
      p: text "Run commands before/after applying or removing firewall rules."
      pre:
        code:
          text """fw:hook({
  pre_start  = "echo starting",
  post_start = "sysctl -p /etc/sysctl.d/custom.conf",
})"""

    section:
      h2: text "Custom Chains"
      p:
        text "Create chains at arbitrary nftables hook points and priorities. "
        text "Rules are nftables JSON objects (Lua tables)."
      pre:
        code:
          text """fw:chain("prerouting", {
  type = "filter",
  priority = "mangle",
  rules = {
    {
      { match = { op = "==", left = { meta = { key = "iifname" } }, right = "eth1" } },
      { mangle = { key = { meta = { key = "mark" } }, value = 256 } },
    },
  },
})"""

    section:
      h2: text "Raw nftables"
      p: text "Escape hatch: inject nftables JSON command objects directly into the ruleset."
      pre:
        code:
          text """fw:raw_nft({
  add = { chain = {
    family = "inet", table = "matchstick", name = "my_chain",
    type = "filter", hook = "input", prio = 200, policy = "accept",
  }}
})"""

    section:
      h2: text "Global Config"
      pre:
        code:
          text """fw:config({
  table_name      = "matchstick",   -- nftables table name
  priority_offset = 5,              -- chain priority offset
  family          = "inet",         -- "inet" (dual-stack) or "ip" (v4 only)
  input_policy    = "drop",         -- base input chain policy
  output_policy   = "accept",       -- base output chain policy
  log_rate        = "5/minute burst 5",
  log_prefix      = "matchstick",
  counter         = false,          -- add counters to all rules
})"""

    section:
      h2: text "Includes"
      p: text "Split config across multiple files."
      pre:
        code:
          text """fw:include("services.lua")
fw:include("zones.lua")
fw:include("rules.lua")"""

    section:
      h2: text "Rate Limiting"
      pre:
        code:
          text """local rate = util:rate("5/minute", { burst = 10 })
local named_rate = util:rate("3/second", { burst = 5, name = "ssh_limit" })

fw:rule(wan, self, "accept", { service = ssh, rate = rate })"""

    # ----- CLI (small reference) -----
    section:
      h2: text "CLI Reference"
      table(class="doc-table"):
        tbody:
          tr:
            td: code: text "matchstick check config.lua"
            td: text "Validate"
          tr:
            td: code: text "matchstick render config.lua"
            td: text "Print nftables (text or --json)"
          tr:
            td: code: text "matchstick apply config.lua"
            td: text "Apply to kernel (--no-sysctl to skip)"
          tr:
            td: code: text "matchstick diff config.lua"
            td: text "Diff running vs generated"
          tr:
            td: code: text "matchstick show matrix|topology|sysctl|json"
            td: text "Visualize config"
          tr:
            td: code: text "matchstick import-ufw"
            td: text "Convert UFW rules (pipe from stdin)"

  layout("Docs", content)
