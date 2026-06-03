-- Test fw:chain() custom mangle/filter chains
local self = fw:zone("fw")
local wan = fw:zone("wan", "eth0")
local lan = fw:zone("lan", "eth1")
fw:policy(wan, self, "drop")
fw:policy(lan, self, "accept")
fw:policy(lan, wan, "accept")

-- Mark incoming traffic for policy routing
-- Rules are nftables JSON expr arrays (each rule is a list of statement objects)
fw:chain("prerouting", {
  type = "filter",
  priority = "mangle",
  rules = {
    -- Rule 1: mark traffic from eth1
    {
      { match = { op = "==", left = { meta = { key = "iifname" } }, right = "eth1" } },
      { mangle = { key = { meta = { key = "mark" } }, value = 256 } },
    },
    -- Rule 2: mark SSH traffic from eth1 differently
    {
      { match = { op = "==", left = { meta = { key = "iifname" } }, right = "eth1" } },
      { match = { op = "==", left = { payload = { protocol = "tcp", field = "dport" } }, right = 22 } },
      { mangle = { key = { meta = { key = "mark" } }, value = 512 } },
    },
  },
})
