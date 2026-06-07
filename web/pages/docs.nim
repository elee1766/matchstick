## Documentation page.

import karax/[karaxdsl, vdom]
import ./layout

proc docsPage*(): string =
  let content = buildHtml(tdiv):
    h1: text "documentation"

    section:
      header: text "how it works"
      p:
        text "matchstick compiles a lua configuration file into nftables rules. "
        text "describe your network in terms of zones, hosts, services, policies, and rules. "
        text "matchstick builds the nftables chains, sets, and verdict maps automatically."
      pre:
        code:
          text "firewall.lua  →  lua vm  →  validate  →  nftables ir  →  text or json"
      p:
        text "at apply time, matchstick also derives and sets kernel sysctl parameters "
        text "(ip forwarding, arp hardening, etc.) based on your config."

    section:
      header: text "zones"
      p:
        text "a zone is a group of network interfaces that share the same trust level. "
        text "every config needs exactly one zone with no interfaces — the firewall host itself."
      pre:
        code:
          text """local self = fw:zone("fw")              -- the firewall machine (no interface)
local wan  = fw:zone("wan", "eth0")     -- internet-facing
local lan  = fw:zone("lan", "eth1")     -- trusted lan
local dmz  = fw:zone("dmz", "eth2")     -- servers

-- multiple interfaces
local internal = fw:zone("internal", {"eth1", "eth2"})

-- bridge zone
local dock = fw:zone("dock", "docker0", { bridge = true })"""

    section:
      header: text "hosts"
      p:
        text "a host is a specific ip address within a zone. "
        text "use hosts when you need per-machine rules."
      pre:
        code:
          text """local server = fw:host("server", { zone = lan, addr = "10.0.0.10" })
local admin  = fw:host("admin",  { zone = lan, addr = "10.0.0.50" })

fw:rule(admin, self, "accept", ssh)   -- only admin gets ssh
fw:rule(server, dmz, "accept", http)  -- server can reach dmz"""

    section:
      header: text "services"
      p: text "a named protocol + port combination. define once, reuse everywhere."
      pre:
        code:
          text """local ssh  = fw:service("ssh", "tcp", 22)
local dns  = fw:service("dns", {"tcp", "udp"}, 53)       -- multi-protocol
local mosh = fw:service("mosh", "udp", "60000-61000")    -- port range
local ping = fw:service("ping", "icmp", "echo-request")  -- icmp type

-- complex: multiple protocol/port pairs
local plex = fw:service("plex", {
  {"tcp", 32400},
  {"udp", 1900},
  {"udp", "32410-32414"},
})"""

    section:
      header: text "policies"
      p:
        text "the default action for traffic between two zones. "
        text "applies to all traffic that doesn't match a more specific rule."
      pre:
        code:
          text """fw:policy(wan, self, "drop", { log = true })  -- drop incoming, log it
fw:policy(self, wan, "accept")                -- allow outgoing
fw:policy(lan, wan, "accept")                 -- lan can reach internet
fw:policy("*", "*", "reject")                 -- default for everything else"""
      p:
        text "actions: \"accept\", \"drop\", \"reject\". "
        text "reject sends icmp admin-prohibited. drop silently discards."

    section:
      header: text "rules"
      p: text "allow or deny specific traffic. evaluated before the zone-pair policy."
      pre:
        code:
          text """fw:rule(wan, self, "accept", ssh)
fw:rule(wan, self, "accept", { proto = "tcp", port = {80, 443} })
fw:rule(wan, self, "accept", { proto = "udp", port = "10000-10100" })

-- rate-limited
fw:rule(wan, self, "accept", {
  service = ssh,
  rate = util:rate("5/minute", { burst = 10 }),
})

-- connection limit
fw:rule(wan, self, "accept", { service = ssh, connlimit = 10 })

-- mac address filter
fw:rule(lan, self, "accept", { service = ssh, mac = "aa:bb:cc:dd:ee:ff" })

-- ip list matching (source and destination)
fw:rule(wan, self, "drop", { saddr_list = "blocklist" })
fw:rule(lan, wan, "accept", { daddr_list = "allowed_hosts" })

-- bare rule (match all traffic)
fw:rule(guest, self, "drop")"""

    section:
      header: text "nat"
      h3: text "dnat (port forwarding)"
      pre:
        code:
          text """fw:dnat({ iface = wan, service = http, dest = webserver })
fw:rule(wan, webserver, "accept", http)  -- need a forward rule too

-- port remap
fw:dnat({ iface = wan, proto = "tcp", port = 2222, dest = server, dest_port = 22 })

-- hairpin nat
fw:dnat({ iface = lan, daddr = "203.0.113.1", proto = "tcp", port = {80, 443}, dest = webserver })"""

      h3: text "snat / masquerade"
      pre:
        code:
          text """fw:snat({ from = "10.0.0.0/8", oif = "eth0", masquerade = true })
fw:snat({ from = "10.0.0.0/8", oif = "eth0", addr = "203.0.113.1" })"""

      h3: text "redirect"
      pre:
        code:
          text """fw:redirect({ iface = lan, proto = "tcp", port = {80}, dest_port = 3128 })"""

    section:
      header: text "ip lists"
      p: text "named sets of ip addresses for blocklists, allowlists, geoip, etc."
      pre:
        code:
          text """fw:iplist("blocklist", { type = "ipv4", flags = "timeout" })

fw:iplist("bogons", {
  type = "ipv4", flags = "interval",
  elements = { "0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16" },
})

-- url for auto-refresh (future: matchstick refresh)
fw:iplist("threats", { type = "ipv4", flags = "timeout", url = "https://example.com/blocklist.txt" })"""

    section:
      header: text "packet hygiene"
      pre:
        code:
          text """fw:laundry({
  rpfilter       = true,   -- reverse path filtering (anti-spoofing)
  tcp_strict     = true,   -- drop malformed tcp flags
  broadcast_drop = true,   -- drop broadcast/multicast in forward
})

-- exceptions for drop chains
fw:exception("invalid", "accept", https)
fw:exception("anti_smurf", "accept", { proto = "udp", port = {67, 68} })"""

    section:
      header: text "other features"
      h3: text "mss clamping"
      pre:
        code:
          text """fw:mss_clamp("forward")  -- clamp tcp syn mss to path mtu"""

      h3: text "dhcp"
      pre:
        code:
          text """fw:dhcp(wan, "client")
fw:dhcp(lan, "server")"""

      h3: text "docker"
      pre:
        code:
          text """fw:docker({ bridges = {"docker0", "br-+"} })"""

      h3: text "sysctl"
      pre:
        code:
          text """fw:sysctl("net.ipv4.tcp_syncookies", "1")

fw:sysctl({ ["net.netfilter.nf_conntrack_max"] = "262144" })

-- unset a derived default
fw:sysctl("net.ipv4.conf.all.forwarding", false)"""

      h3: text "hooks"
      pre:
        code:
          text """fw:hook({ post_start = "echo applied" })"""

      h3: text "includes"
      pre:
        code:
          text """fw:include("services.lua")
fw:include("rules.lua")"""

      h3: text "rate limiting"
      pre:
        code:
          text """local rate = util:rate("5/minute", { burst = 10 })
local named = util:rate("3/second", { burst = 5, name = "ssh_limit" })"""

      h3: text "custom chains"
      pre:
        code:
          text """fw:chain("prerouting", {
  type = "filter", priority = "mangle",
  rules = { { { match = { op = "==",
    left = { meta = { key = "iifname" } }, right = "eth1" } },
    { mangle = { key = { meta = { key = "mark" } }, value = 256 } },
  } },
})"""

      h3: text "raw nftables"
      pre:
        code:
          text """fw:raw_nft({ add = { chain = {
  family = "inet", table = "matchstick", name = "my_chain",
  type = "filter", hook = "input", prio = 200, policy = "accept",
} } })"""

      h3: text "global config"
      pre:
        code:
          text """fw:config({
  table_name = "matchstick", priority_offset = 5,
  family = "inet", input_policy = "drop", output_policy = "accept",
  log_rate = "5/minute burst 5", log_prefix = "matchstick",
  counter = false,
})"""

    section:
      header: text "cli"
      table:
        tbody:
          tr:
            td: code: text "matchstick check config.lua"
            td: text "validate"
          tr:
            td: code: text "matchstick render config.lua"
            td: text "print nftables (text or --json)"
          tr:
            td: code: text "matchstick apply config.lua"
            td: text "apply to kernel (--no-sysctl to skip)"
          tr:
            td: code: text "matchstick diff config.lua"
            td: text "diff running vs generated"
          tr:
            td: code: text "matchstick show matrix|topology|sysctl|json"
            td: text "visualize config"
          tr:
            td: code: text "matchstick import-ufw"
            td: text "convert ufw rules (pipe from stdin)"

  layout("docs", content)
