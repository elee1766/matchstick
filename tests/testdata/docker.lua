-- Test: Docker bridge whitelisting
local self = fw:zone("fw")
local wan = fw:zone("wan", "eth0")
local dock = fw:zone("dock", "docker0")
fw:docker({ backend = "nftables", bridges = { "docker0", "br-+" } })
fw:policy(dock, self, "reject")
fw:policy(dock, wan, "accept")
fw:policy(self, dock, "accept")
fw:rule(dock, self, "accept", fw:service("dns", {"tcp","udp"}, 53))
