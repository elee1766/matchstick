-- Test all tier 2 features: MSS clamp, connlimit, MAC, redirect, daddr_list
local self = fw:zone("fw")
local wan = fw:zone("wan", "eth0")
local lan = fw:zone("lan", "eth1")
local ssh = fw:service("ssh", "tcp", 22)
local http = fw:service("http", "tcp", 80)

fw:policy(wan, self, "drop")
fw:policy(lan, self, "accept")
fw:policy(lan, wan, "accept")

-- MSS clamping on forwarded traffic (needed for PPPoE/VPN)
fw:mss_clamp("forward")

-- Connection limiting: max 10 concurrent SSH connections
fw:rule(wan, self, "accept", {
  service = ssh,
  connlimit = 10,
})

-- MAC address filtering
fw:rule(lan, self, "accept", {
  service = ssh,
  mac = "aa:bb:cc:dd:ee:ff",
})

-- Redirect: local port redirect (transparent proxy)
fw:redirect({
  iface = lan,
  proto = "tcp",
  port = { 80 },
  dest_port = 3128,
})

-- IP list with URL for auto-refresh
fw:iplist("blocklist", {
  type = "ipv4",
  flags = "timeout",
  url = "https://example.com/blocklist.txt",
})

-- Rule using daddr_list (for GeoIP-style destination filtering)
fw:iplist("allowed_countries", {
  type = "ipv4",
  flags = "interval",
  elements = { "10.0.0.0/8", "172.16.0.0/12" },
})
fw:rule(lan, wan, "accept", {
  service = http,
  daddr_list = "allowed_countries",
})
