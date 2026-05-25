-- Test fw:exception() extensible drop chains
local self = fw:zone("fw")
local wan = fw:zone("wan", "eth0")
local lan = fw:zone("lan", "eth1")
local https = fw:service("https", {"tcp", "udp"}, 443)
fw:policy(wan, self, "drop")
fw:policy(lan, self, "accept")

-- IPVS load-balanced traffic enters invalid chain but should be accepted
fw:exception("invalid", "accept", https)

-- Also accept bare UDP on a specific port
fw:exception("invalid", "accept", { proto = "udp", port = "8080" })

-- Accept DHCP broadcasts that would normally be dropped as anti-smurf
fw:exception("anti_smurf", "accept", { proto = "udp", port = { 67, 68 } })
