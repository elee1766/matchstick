## Home page.

import karax/[karaxdsl, vdom]
import ./layout

proc homePage*(): string =
  let content = buildHtml(tdiv):
    h1: text "matchstick"
    p:
      text "a lua-based nftables firewall configuration tool. "
      text "compiles declarative firewall configs into native nftables rulesets "
      text "with automatic sysctl management, input validation, and shadow rule detection."

    p:
      text "matchstick replaces tools like ufw, shorewall, and firewalld with a single lua file "
      text "that is version-controllable, reviewable, and produces identical output every time."

    pre:
      code:
        text """local ssh  = fw:service("ssh", "tcp", 22)
local http = fw:service("http", "tcp", 80)
local ping = fw:service("ping", "icmp", "echo-request")

local self = fw:zone("fw")
local wan  = fw:zone("wan", "eth0")
local lan  = fw:zone("lan", "eth1")

fw:policy(wan, self, "drop", { log = true })
fw:policy(self, wan, "accept")
fw:policy(lan, self, "accept")
fw:policy(lan, wan, "accept")

fw:rule(wan, self, "accept", ssh)
fw:rule(wan, self, "accept", http)
fw:rule(wan, self, "accept", ping)

fw:snat({ from = "10.0.0.0/8", oif = "eth0", masquerade = true })"""

    p:
      a(href="/playground"): button: text "try it"
      text " "
      a(href="/docs"): button(`data-variant`="soft"): text "documentation"

    hr()

    h2: text "install"
    pre:
      code:
        text """git clone https://github.com/elee1766/matchstick
cd matchstick
make install"""

    h2: text "usage"
    pre:
      code:
        text """matchstick check firewall.lua       # validate
matchstick render firewall.lua      # print nftables output
matchstick apply firewall.lua       # apply to kernel + set sysctls
matchstick diff firewall.lua        # diff running vs generated
matchstick show matrix firewall.lua # zone policy matrix"""

    h2: text "migrating from ufw"
    pre:
      code:
        text """sudo ufw show added | matchstick import-ufw > firewall.lua
matchstick check firewall.lua
# edit firewall.lua to adjust zone/host names
matchstick apply firewall.lua"""

  layout("home", content)
