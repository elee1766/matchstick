-- Test fw:raw_nft() escape hatch
local self = fw:zone("fw")
local wan = fw:zone("wan", "eth0")
fw:policy(wan, self, "drop")

-- Inject raw nftables lines into the table
fw:raw_nft("chain my_custom_chain {")
fw:raw_nft("    type filter hook input priority filter + 100; policy accept;")
fw:raw_nft("    tcp dport 12345 accept")
fw:raw_nft("}")
