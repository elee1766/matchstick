-- Test fw:chain() custom mangle/filter chains
local self = fw:zone("fw")
local wan = fw:zone("wan", "eth0")
local lan = fw:zone("lan", "eth1")
fw:policy(wan, self, "drop")
fw:policy(lan, self, "accept")
fw:policy(lan, wan, "accept")

-- Mark incoming traffic for policy routing
fw:chain("prerouting", {
  type = "filter",
  priority = "mangle",
  rules = {
    "iifname eth1 mark set 0x100/0xff00",
    "iifname eth1 tcp dport 22 mark set 0x200/0xff00",
  },
})

-- MSS clamping on forwarded traffic
fw:chain("forward", {
  type = "filter",
  priority = "mangle",
  rules = {
    "tcp flags syn tcp option maxseg size set rt mtu",
  },
})
