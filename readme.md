# matchstick

[![CI](https://github.com/elee1766/matchstick/actions/workflows/ci.yml/badge.svg)](https://github.com/elee1766/matchstick/actions/workflows/ci.yml)

Lua-based nftables firewall configuration tool. Compiles declarative firewall configs into native nftables rulesets with automatic sysctl management, input validation, and shadow rule detection.

**[Documentation](https://elee1766.github.io/matchstick/docs/)** | **[Website](https://elee1766.github.io/matchstick/)**

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

```sh
matchstick check  firewall.lua           # validate config
matchstick render firewall.lua           # print nftables text
matchstick render --json firewall.lua    # print nftables JSON
matchstick apply  firewall.lua           # apply to kernel (root)
matchstick diff   firewall.lua           # diff running vs generated

matchstick show matrix   firewall.lua              # zone policy matrix
matchstick show rules    firewall.lua wan fw        # rules for a zone pair
matchstick show topology firewall.lua               # ASCII topology
matchstick show topology firewall.lua --format=dot  # Graphviz DOT
matchstick show topology firewall.lua --format=d2   # D2 diagram
matchstick show json     firewall.lua               # full state as JSON
```

By default, configs run in a sandboxed Lua environment without `os`, `io`,
`package`, or `debug`, and dangerous escape hatches are rejected. Use these only
for fully trusted, root-owned configs:

```sh
matchstick apply --allow-hooks firewall.lua          # allow fw:hook shell commands
matchstick apply --allow-raw-nft firewall.lua        # allow fw:chain/fw:raw_nft
```

## Build

```sh
nimble build
```

Requires Nim >= 2.2. Lua 5.4 is vendored and compiled from C sources -- no external dependency.

The binary runs anywhere with just libc. libnftables is loaded at runtime
only when needed (`apply`, `diff`). Install `nftables` on the target system
for those commands.

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
