-- Test fw:raw_nft() escape hatch with nftables JSON
local self = fw:zone("fw")
local wan = fw:zone("wan", "eth0")
fw:policy(wan, self, "drop")

-- Inject a raw chain + rule as nftables JSON command objects
fw:raw_nft(
  { add = { chain = {
    family = "inet",
    table = "matchstick",
    name = "my_custom_chain",
    type = "filter",
    hook = "input",
    prio = 100,
    policy = "accept",
  }}},
  { add = { rule = {
    family = "inet",
    table = "matchstick",
    chain = "my_custom_chain",
    expr = {
      { match = { op = "==", left = { payload = { protocol = "tcp", field = "dport" } }, right = 12345 } },
      { accept = {} },
    },
  }}}
)
