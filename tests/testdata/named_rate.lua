-- Test: util:rate with named shared rate
local self = fw:zone("fw")
local wan = fw:zone("wan", "eth0")
local ssh = fw:service("ssh", "tcp", 22)
fw:policy(wan, self, "drop")
fw:rule(wan, self, "accept", {
  service = ssh,
  rate = util:rate("3/minute", { burst = 5, name = "ssh_limit" }),
})
