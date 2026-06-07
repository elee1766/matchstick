## Home page.

import karax/[karaxdsl, vdom]
import ./layout

proc homePage*(): string =
  let content = buildHtml(tdiv):
    section:
      header: text "matchstick"
      h1: text "lua-based nftables firewall"
      p:
        text "compile firewall configs from lua to nftables. "
        text "zone-based, bidirectional, with automatic sysctl, docker support, and more."
      p:
        a(href="/playground"): button: text "playground"
        text " "
        a(href="/docs"): button(`data-variant`="soft"): text "documentation"

    tdiv(`data-grid`="3"):
      section:
        header: text "zones"
        p: text "define zones, hosts, and policies. bidirectional rules between any pair of zones with verdict map dispatch."

      section:
        header: text "lua config"
        p: text "full programming language. variables, loops, conditionals, includes. version-controllable config files."

      section:
        header: text "native nftables"
        p: text "generates clean nftables rulesets. text and json output. no iptables compat shim."

      section:
        header: text "auto sysctl"
        p: text "derives kernel settings from your config. ip forwarding, arp hardening, redirect protection."

      section:
        header: text "validation"
        p: text "shadow rule detection, config validation, topology diagrams, zone policy matrix, diff against running rules."

      section:
        header: text "nat & docker"
        p: text "dnat, snat, masquerade, hairpin nat, redirect. first-class docker bridge support."

    section:
      header: text "quick start"
      pre:
        code:
          text """local ssh = fw:service("ssh", "tcp", 22)

local self = fw:zone("fw")
local wan  = fw:zone("wan", "eth0")

fw:policy(wan, self, "drop", { log = true })
fw:policy(self, wan, "accept")

fw:rule(wan, self, "accept", ssh)"""

    section:
      header: text "install"
      pre:
        code:
          text """git clone https://github.com/elee1766/matchstick
cd matchstick
make install"""

  layout("home", content)
