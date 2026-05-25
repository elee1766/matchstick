-- Test fw:hook() lifecycle commands
local self = fw:zone("fw")
local wan = fw:zone("wan", "eth0")
fw:policy(wan, self, "drop")

fw:hook({
  pre_start = "echo starting firewall",
  post_start = "sysctl -p /etc/sysctl.d/50-ip.forwarding.conf",
  pre_stop = "echo stopping firewall",
  post_stop = "echo firewall stopped",
})
