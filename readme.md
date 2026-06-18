# matchstick

[![CI](https://github.com/elee1766/matchstick/actions/workflows/ci.yml/badge.svg)](https://github.com/elee1766/matchstick/actions/workflows/ci.yml)

with shorewall slowly falling more and more out of maintainence, i wanted to try to make a tool for declarative config management.

so here is matchstick. it is a lua-based nftables firewall configuration tool.

you write lua code which gets compiled into nftables rulesets with some sysctl rules

similar projects: shorewall, awall, foomuuri

**[Documentation](https://elee1766.github.io/matchstick/)**

## Example

```lua
-- Services
local ssh   = fw:service("ssh",   "tcp", 22)
local http  = fw:service("http",  "tcp", 80)
local https = fw:service("https", { "tcp", "udp" }, 443)
local dns   = fw:service("dns",   { "tcp", "udp" }, 53)
local ping  = fw:service("ping",  "icmp", "echo-request")

-- Zones
local self = fw:zone("fw")
local wan  = fw:zone("wan", "eth0")
local lan  = fw:zone("lan", "eth1")

-- Hosts (named machines, usable directly in rules)
local admin = fw:host("admin", { zone = lan, addr = "10.0.0.10" })
local guest = fw:host("guest", { zone = lan, addr = "10.0.0.100" })

-- Global protections
fw:laundry({ rpfilter = true, tcp_strict = true, broadcast_drop = true })
fw:dhcp(wan, "client")
fw:dhcp(lan, "server")

-- Policies (default actions between zones)
fw:policy(wan, self, "drop", { log = true })
fw:policy(lan, self, "accept")
fw:policy(lan, wan,  "accept")
fw:policy(self, wan, "accept")
fw:policy(self, lan, "accept")

-- WAN rules
fw:rule(wan, self, "accept", https)
fw:rule(wan, self, "accept", ssh)

-- Admin gets full access, guest gets DNS only
fw:rule(admin, self, "accept", ssh)
fw:rule(guest, self, "accept", dns)
fw:rule(guest, self, "drop")          -- block everything else from guest

-- Port forward: HTTPS from WAN to a LAN server
local webserver = fw:host("web", { zone = lan, addr = "10.0.0.20" })
fw:dnat({ iface = wan, service = https, dest = webserver })
fw:rule(wan, webserver, "accept", https)

-- NAT
fw:snat({ from = "10.0.0.0/8", oif = "eth0", masquerade = true })
```

## Usage

matchstick is the nftables compiler and holds the core logic

msctl is the firewall tool which uses matchstick to interface with nft cli on a running system. it's just a wrapper script around matchstick

if you are using it to manage stuff on your machine, you would use msctl. if you are using it to create rules to use elsewhere, you would use matchstick

### msctl (system management)

```sh
msctl enable        # compile, validate, apply config to kernel
msctl disable       # remove all matchstick rules
msctl status        # show running rules
msctl diff          # diff running rules vs config
msctl check         # validate config without applying
msctl edit          # edit config, validate, and apply
msctl show          # zone policy matrix (default)
msctl show rules lan fw    # rules for a zone pair
msctl show topology        # ASCII topology diagram
msctl show render          # print nftables text
```

### matchstick (compiler)

```sh
matchstick check  firewall.lua           # validate config
matchstick render firewall.lua           # print nftables text
matchstick render --json firewall.lua    # print nftables JSON
matchstick diff old.lua new.lua          # diff two rulesets
matchstick show matrix firewall.lua      # zone policy grid
matchstick show rules  firewall.lua wan fw
matchstick show topology firewall.lua --format=dot
matchstick import-ufw                    # convert UFW rules from stdin
```

By default, configs run in a restricted Lua environment without `os`, `io`,
`package`, `debug`, `dofile`, or `loadfile`, and dangerous escape hatches are
rejected. Configs are still code that can define firewall policy and sysctl
overrides, so production configs should be fully trusted and root-owned. Use
these escape hatches only for trusted configs:

```sh
matchstick render --allow-hooks firewall.lua          # allow fw:hook shell commands
matchstick render --allow-raw-nft firewall.lua        # allow fw:chain/fw:raw_nft
```

## Build

```sh
nimble build
```

Requires Nim >= 2.2. Lua is vendored and compiled from C sources -- no external dependency.

The `matchstick` binary is pure computation — no root, no nft, no runtime
dependencies. `msctl` requires `nft` (nftables) on the target system to
apply rules to the kernel.

## Configuration

All settings have sensible defaults. Customize via `fw:config()`:

```lua
fw:config({
  table_name      = "matchstick",       -- nftables table name
  family          = "inet",             -- "inet" (dual-stack) or "ip" (IPv4 only)
  priority_offset = 5,                  -- offset from standard chain priorities
  log_rate        = "5/minute burst 5", -- rate limit for drop/reject logging
  log_prefix      = "matchstick",       -- syslog prefix
  counter         = false,              -- add packet counters to all rules
  input_policy    = "drop",             -- default input chain policy
  output_policy   = "accept",           -- default output chain policy
})
```

System config lives at `/etc/matchstick/firewall.lua`. Split into multiple files with `fw:include()`:

```lua
fw:include("services.lua")
fw:include("zones.lua")
fw:include("rules.lua")
```

## Testing

```sh
# unit tests
for t in tests/test_*.nim; do nim c -r "$t"; done

# integration tests (requires built binary)
for t in tests/integration/test_*.nim; do nim c -r "$t"; done

# validate against real nft (no root needed)
unshare --user --net --map-root-user -- \
  sh -c './matchstick render firewall.lua | nft -c -f -'
```
