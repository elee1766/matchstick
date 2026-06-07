## Documentation page.

import karax/[karaxdsl, vdom]
import ./layout

proc docsPage*(): string =
  let content = buildHtml(tdiv):
    h1: text "Documentation"

    section:
      h2: text "CLI Commands"
      table(class="doc-table"):
        thead:
          tr:
            th: text "Command"
            th: text "Description"
        tbody:
          tr:
            td: code: text "matchstick check config.lua"
            td: text "Validate config and report errors"
          tr:
            td: code: text "matchstick render config.lua"
            td: text "Print nftables text output"
          tr:
            td: code: text "matchstick render --json config.lua"
            td: text "Print nftables JSON output"
          tr:
            td: code: text "matchstick apply config.lua"
            td: text "Apply rules to kernel + set sysctls"
          tr:
            td: code: text "matchstick apply --no-sysctl config.lua"
            td: text "Apply rules without sysctl changes"
          tr:
            td: code: text "matchstick diff config.lua"
            td: text "Diff running rules vs generated"
          tr:
            td: code: text "matchstick show matrix config.lua"
            td: text "Zone policy matrix"
          tr:
            td: code: text "matchstick show topology config.lua"
            td: text "Network topology diagram"
          tr:
            td: code: text "matchstick show sysctl config.lua"
            td: text "Show derived sysctl settings"
          tr:
            td: code: text "matchstick import-ufw"
            td: text "Import UFW rules from stdin"

    section:
      h2: text "Lua API"
      h3: text "Zones & Hosts"
      pre:
        code:
          text """local self = fw:zone("fw")              -- the firewall host (no interface)
local wan  = fw:zone("wan", "eth0")     -- zone with interface
local lan  = fw:zone("lan", {"eth1", "eth2"})  -- multiple interfaces

local server = fw:host("server", { zone = lan, addr = "10.0.0.10" })"""

      h3: text "Services"
      pre:
        code:
          text """local ssh   = fw:service("ssh", "tcp", 22)
local dns   = fw:service("dns", {"tcp", "udp"}, 53)
local media = fw:service("media", {{"tcp", 8080}, {"udp", "9000-9100"}})"""

      h3: text "Policies & Rules"
      pre:
        code:
          text """fw:policy(wan, self, "drop", { log = true })
fw:policy(self, wan, "accept")
fw:policy("*", "*", "reject")

fw:rule(wan, self, "accept", ssh)
fw:rule(wan, self, "accept", { proto = "tcp", port = {80, 443} })
fw:rule(wan, self, "accept", {
  service = ssh,
  rate = util:rate("5/minute", { burst = 10 }),
  connlimit = 10,
})"""

      h3: text "NAT"
      pre:
        code:
          text """fw:dnat({ iface = wan, service = http, dest = webserver })
fw:snat({ from = "10.0.0.0/8", oif = "eth0", masquerade = true })
fw:redirect({ iface = lan, proto = "tcp", port = {80}, dest_port = 3128 })"""

      h3: text "Advanced"
      pre:
        code:
          text """fw:laundry({ rpfilter = true, tcp_strict = true })
fw:dhcp(wan, "client")
fw:mss_clamp("forward")
fw:iplist("blocklist", { type = "ipv4", flags = "timeout" })
fw:docker({ bridges = {"docker0", "br-+"} })
fw:exception("invalid", "accept", https)
fw:sysctl("net.ipv4.tcp_syncookies", "1")
fw:hook({ post_start = "echo applied" })"""

  layout("Docs", content)
