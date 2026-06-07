## Home page.

import karax/[karaxdsl, vdom]
import ./layout

proc homePage*(): string =
  let content = buildHtml(tdiv):
    section(class="hero"):
      h1: text "matchstick"
      p(class="subtitle"):
        text "A Lua-based nftables firewall configuration tool."
      p:
        text "Compile firewall configs from Lua to nftables. "
        text "Zone-based, bidirectional, with automatic sysctl, Docker support, and more."
      tdiv(class="cta"):
        a(href="/playground", class="btn"): text "Try the Playground"
        a(href="/docs", class="btn btn-outline"): text "Read the Docs"

    section:
      h2: text "Features"
      tdiv(class="grid"):
        tdiv(class="card"):
          h3: text "Zone-based firewalling"
          p: text "Define zones, hosts, and policies. Bidirectional rules between any pair of zones."
        tdiv(class="card"):
          h3: text "Lua configuration"
          p: text "Full programming language for your firewall config. Variables, loops, conditionals, includes."
        tdiv(class="card"):
          h3: text "Native nftables"
          p: text "Generates clean nftables rulesets. Text and JSON output. No iptables compatibility shim."
        tdiv(class="card"):
          h3: text "Automatic sysctl"
          p: text "Derives kernel settings from your config. IP forwarding, ARP hardening, redirect protection."
        tdiv(class="card"):
          h3: text "Validation & visualization"
          p: text "Shadow rule detection, config validation, topology diagrams, zone policy matrix."
        tdiv(class="card"):
          h3: text "Docker & NAT"
          p: text "First-class Docker bridge support. DNAT, SNAT, masquerade, hairpin NAT, redirect."

    section:
      h2: text "Quick Start"
      pre:
        code:
          text """local ssh = fw:service("ssh", "tcp", 22)

local self = fw:zone("fw")
local wan  = fw:zone("wan", "eth0")

fw:policy(wan, self, "drop", { log = true })
fw:policy(self, wan, "accept")

fw:rule(wan, self, "accept", ssh)"""

    section:
      h2: text "Install"
      pre:
        code:
          text """git clone https://github.com/elee1766/matchstick
cd matchstick
make install"""

  layout("Home", content)
