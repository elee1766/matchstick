-- Test: multiple interfaces per zone, bridge zone
local self = fw:zone("fw")
local lan = fw:zone("lan", { "eth1", "eth2" })
local dock = fw:zone("dock", "docker0", { bridge = true })
fw:policy(lan, self, "accept")
fw:policy(dock, self, "reject")
fw:rule(dock, self, "accept", fw:service("dns", {"tcp","udp"}, 53))
