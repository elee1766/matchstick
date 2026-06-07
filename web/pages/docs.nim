## Documentation page with sidebar TOC.

import karax/[karaxdsl, vdom]
import ./layout
import ./render

# -- live examples (compiled at build time) --

const exZonesAndPolicies = """local ssh  = fw:service("ssh", "tcp", 22)
local ping = fw:service("ping", "icmp", "echo-request")

local self = fw:zone("fw")
local wan  = fw:zone("wan", "eth0")
local lan  = fw:zone("lan", "eth1")

fw:policy(wan, self, "drop", { log = true })
fw:policy(self, wan, "accept")
fw:policy(lan, self, "accept")
fw:policy(lan, wan, "accept")

fw:rule(wan, self, "accept", ssh)
fw:rule(wan, self, "accept", ping)
fw:rule(lan, self, "accept", { proto = "tcp", port = {80, 443} })
"""

const exNat = """local http = fw:service("http", "tcp", 80)

local self = fw:zone("fw")
local wan  = fw:zone("wan", "eth0")
local lan  = fw:zone("lan", "eth1")
local dmz  = fw:zone("dmz", "eth2")

local webserver = fw:host("webserver", { zone = dmz, addr = "172.16.0.10" })

fw:policy(wan, self, "drop")
fw:policy(self, wan, "accept")
fw:policy(lan, wan, "accept")
fw:policy(wan, dmz, "drop")

fw:dnat({ iface = wan, service = http, dest = webserver })
fw:rule(wan, webserver, "accept", http)

fw:snat({ from = "10.0.0.0/8", oif = "eth0", masquerade = true })
fw:snat({ from = "172.16.0.0/12", oif = "eth0", masquerade = true })
"""

const exSysctl = """local self = fw:zone("fw")
local wan  = fw:zone("wan", "eth0")
local lan  = fw:zone("lan", "eth1")

fw:policy(lan, wan, "accept")

fw:sysctl("net.ipv4.tcp_syncookies", "1")
fw:sysctl("net.ipv4.conf.all.log_martians", false)
"""

# These run at startup, before Mummy's thread pool starts
var outZonesAndPolicies {.global.}: string
var outNat {.global.}: string
var outSysctl {.global.}: string

proc initExamples*() =
  outZonesAndPolicies = renderExample(exZonesAndPolicies)
  outNat = renderExample(exNat)
  outSysctl = renderSysctls(exSysctl)

proc docsPage*(): string =
  let content = buildHtml(tdiv(class="docs-layout")):
    nav(class="docs-toc"):
      span(class="toc-heading"): text "concepts"
      a(href="#how-it-works", class="toc-1"): text "how it works"
      a(href="#example", class="toc-1"): text "full example"
      a(href="#zones", class="toc-1"): text "zones"
      a(href="#hosts", class="toc-1"): text "hosts"
      a(href="#services", class="toc-1"): text "services"
      a(href="#policies", class="toc-1"): text "policies"
      a(href="#rules", class="toc-1"): text "rules"

      span(class="toc-heading"): text "nat"
      a(href="#nat", class="toc-1"): text "overview"
      a(href="#dnat", class="toc-2"): text "dnat"
      a(href="#snat", class="toc-2"): text "snat"
      a(href="#redirect", class="toc-2"): text "redirect"
      a(href="#nat-example", class="toc-2"): text "nat example"

      span(class="toc-heading"): text "features"
      a(href="#ip-lists", class="toc-1"): text "ip lists"
      a(href="#packet-hygiene", class="toc-1"): text "packet hygiene"
      a(href="#mss-clamping", class="toc-1"): text "mss clamping"
      a(href="#dhcp", class="toc-1"): text "dhcp"
      a(href="#docker", class="toc-1"): text "docker"
      a(href="#sysctl", class="toc-1"): text "sysctl"
      a(href="#hooks", class="toc-1"): text "hooks"
      a(href="#includes", class="toc-1"): text "includes"
      a(href="#rate-limiting", class="toc-1"): text "rate limiting"

      span(class="toc-heading"): text "advanced"
      a(href="#custom-chains", class="toc-1"): text "custom chains"
      a(href="#raw-nftables", class="toc-1"): text "raw nftables"
      a(href="#global-config", class="toc-1"): text "global config"

      span(class="toc-heading"): text "reference"
      a(href="#cli", class="toc-1"): text "cli"

    tdiv(class="docs-content"):
      h1: text "documentation"

      h2(id="how-it-works"): text "how it works"
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

      h2(id="example"): text "full example"
      p: text "this is a complete config with the generated nftables output:"
      details:
        summary: text "firewall.lua"
        pre:
          code: text exZonesAndPolicies
      details(open=""):
        summary: text "generated nftables output"
        pre:
          code: text outZonesAndPolicies

      h2(id="zones"): text "zones"
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

      h2(id="hosts"): text "hosts"
      p:
        text "a host is a specific ip address within a zone. "
        text "use hosts when you need per-machine rules."
      pre:
        code:
          text """local server = fw:host("server", { zone = lan, addr = "10.0.0.10" })
local admin  = fw:host("admin",  { zone = lan, addr = "10.0.0.50" })

fw:rule(admin, self, "accept", ssh)   -- only admin gets ssh
fw:rule(server, dmz, "accept", http)  -- server can reach dmz"""

      h2(id="services"): text "services"
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

      h2(id="policies"): text "policies"
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

      h2(id="rules"): text "rules"
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

      h2(id="nat"): text "nat"
      h3(id="dnat"): text "dnat (port forwarding)"
      pre:
        code:
          text """fw:dnat({ iface = wan, service = http, dest = webserver })
fw:rule(wan, webserver, "accept", http)  -- need a forward rule too

-- port remap
fw:dnat({ iface = wan, proto = "tcp", port = 2222, dest = server, dest_port = 22 })

-- hairpin nat
fw:dnat({ iface = lan, daddr = "203.0.113.1", proto = "tcp", port = {80, 443}, dest = webserver })"""

      h3(id="snat"): text "snat / masquerade"
      pre:
        code:
          text """fw:snat({ from = "10.0.0.0/8", oif = "eth0", masquerade = true })
fw:snat({ from = "10.0.0.0/8", oif = "eth0", addr = "203.0.113.1" })"""

      h3(id="redirect"): text "redirect"
      pre:
        code:
          text """fw:redirect({ iface = lan, proto = "tcp", port = {80}, dest_port = 3128 })"""

      h3(id="nat-example"): text "nat example"
      p: text "a complete nat config with dnat + snat and the generated output:"
      details:
        summary: text "firewall.lua"
        pre:
          code: text exNat
      details(open=""):
        summary: text "generated nftables output"
        pre:
          code: text outNat

      h2(id="ip-lists"): text "ip lists"
      p: text "named sets of ip addresses for blocklists, allowlists, geoip, etc."
      pre:
        code:
          text """fw:iplist("blocklist", { type = "ipv4", flags = "timeout" })

fw:iplist("bogons", {
  type = "ipv4", flags = "interval",
  elements = { "0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16" },
})

fw:iplist("threats", { type = "ipv4", flags = "timeout", url = "https://example.com/blocklist.txt" })"""

      h2(id="packet-hygiene"): text "packet hygiene"
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

      h2(id="mss-clamping"): text "mss clamping"
      pre:
        code:
          text """fw:mss_clamp("forward")  -- clamp tcp syn mss to path mtu"""

      h2(id="dhcp"): text "dhcp"
      pre:
        code:
          text """fw:dhcp(wan, "client")
fw:dhcp(lan, "server")"""

      h2(id="docker"): text "docker"
      pre:
        code:
          text """fw:docker({ bridges = {"docker0", "br-+"} })"""

      h2(id="sysctl"): text "sysctl"
      p:
        text "matchstick automatically derives kernel sysctl settings from your config. "
        text "ip forwarding is enabled when forwarding rules exist. "
        text "arp hardening, redirect protection, and source routing protection are always set."
      pre:
        code:
          text """fw:sysctl("net.ipv4.tcp_syncookies", "1")

fw:sysctl({
  ["net.netfilter.nf_conntrack_max"] = "262144",
  ["net.core.somaxconn"] = "4096",
})

-- unset a derived default (matchstick won't touch it)
fw:sysctl("net.ipv4.conf.all.forwarding", false)"""

      p: text "example: a router config with custom sysctl and an unset override:"
      details:
        summary: text "firewall.lua"
        pre:
          code: text exSysctl
      details(open=""):
        summary: text "derived sysctls"
        pre:
          code: text outSysctl

      h2(id="hooks"): text "hooks"
      pre:
        code:
          text """fw:hook({
  pre_start  = "echo starting",
  post_start = "sysctl -p /etc/sysctl.d/custom.conf",
})"""

      h2(id="includes"): text "includes"
      pre:
        code:
          text """fw:include("services.lua")
fw:include("rules.lua")"""

      h2(id="rate-limiting"): text "rate limiting"
      pre:
        code:
          text """local rate = util:rate("5/minute", { burst = 10 })
local named = util:rate("3/second", { burst = 5, name = "ssh_limit" })

fw:rule(wan, self, "accept", { service = ssh, rate = rate })"""

      h2(id="custom-chains"): text "custom chains"
      p: text "create chains at arbitrary nftables hook points and priorities. rules are nftables json objects."
      pre:
        code:
          text """fw:chain("prerouting", {
  type = "filter", priority = "mangle",
  rules = { {
    { match = { op = "==", left = { meta = { key = "iifname" } }, right = "eth1" } },
    { mangle = { key = { meta = { key = "mark" } }, value = 256 } },
  } },
})"""

      h2(id="raw-nftables"): text "raw nftables"
      p: text "escape hatch: inject nftables json command objects directly."
      pre:
        code:
          text """fw:raw_nft({ add = { chain = {
  family = "inet", table = "matchstick", name = "my_chain",
  type = "filter", hook = "input", prio = 200, policy = "accept",
} } })"""

      h2(id="global-config"): text "global config"
      pre:
        code:
          text """fw:config({
  table_name = "matchstick", priority_offset = 5,
  family = "inet", input_policy = "drop", output_policy = "accept",
  log_rate = "5/minute burst 5", log_prefix = "matchstick",
  counter = false,
})"""

      h2(id="cli"): text "cli"
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
