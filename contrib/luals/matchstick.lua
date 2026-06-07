--- matchstick Lua API type definitions for lua-language-server (LuaLS).
---
--- Usage:
---   1. Copy this file (or symlink it) into your project, or
---   2. Add the path to your .luarc.json:
---      { "workspace.library": ["/path/to/matchstick/contrib/luals"] }
---
--- This provides autocompletion, hover docs, and type checking for
--- the fw:* and util:* APIs injected by the matchstick runtime.

---@meta

---@class ZoneHandle
---@field __name string
---@field __type "zone"

---@class HostHandle
---@field __name string
---@field __type "host"

---@class ServiceHandle
---@field __name string
---@field __type "service"

---@class RateHandle
---@field rate string
---@field burst integer
---@field name? string

---@alias Endpoint ZoneHandle | HostHandle | string

---@alias ServiceRef ServiceHandle | string

-- =========================================================================
-- fw table
-- =========================================================================

---@class fw
fw = {}

--- Declare a firewall zone.
---@param name string Zone name (use "fw" for the local host zone)
---@param iface? string|string[] Network interface(s), omit for the fw zone
---@param opts? { bridge?: boolean } Zone options
---@return ZoneHandle
function fw:zone(name, iface, opts) end

--- Declare a named host within a zone.
---@param name string Host name
---@param opts { zone: ZoneHandle|string, addr: string, addr6?: string } Host options
---@return HostHandle
function fw:host(name, opts) end

--- Declare a named service (protocol + port).
---@param name string Service name
---@param proto string|string[] Protocol ("tcp", "udp", "icmp") or array of protocols
---@param port? integer|string Port number, range ("80-443"), or ICMP type name
---@return ServiceHandle
---@overload fun(self: fw, name: string, entries: {[1]: string, [2]: integer|string}[]): ServiceHandle
function fw:service(name, proto, port) end

--- Configure packet hygiene (laundry) settings.
---@param opts { rpfilter?: boolean, bogon_drop?: boolean, tcp_strict?: boolean, broadcast_drop?: boolean }
function fw:laundry(opts) end

--- Configure DHCP pass-through on a zone.
---@param zone Endpoint Zone with interfaces
---@param role "client"|"server" DHCP role
function fw:dhcp(zone, role) end

--- Set default policy between zones.
---@param from Endpoint Source zone/host or "*" for wildcard
---@param to Endpoint Destination zone/host or "*" for wildcard
---@param action "accept"|"drop"|"reject" Default action
---@param opts? { log?: boolean } Policy options
function fw:policy(from, to, action, opts) end

---@class RuleOpts
---@field service? ServiceRef Service to match
---@field proto? string|string[] Protocol(s)
---@field port? integer|string|integer[]|string[] Port(s)
---@field saddr_list? string IP list name for source matching
---@field daddr_list? string IP list name for destination matching
---@field daddr? string|HostHandle Destination address or host
---@field mac? string Source MAC address (e.g. "aa:bb:cc:dd:ee:ff")
---@field connlimit? integer Max concurrent connections
---@field rate? RateHandle Rate limit (from util:rate)
---@field log? string Log prefix (empty = no log)

--- Add a firewall rule.
---@param from Endpoint Source zone/host or "*"
---@param to Endpoint Destination zone/host or "*"
---@param action "accept"|"drop"|"reject" Rule action
---@param service_or_opts? ServiceRef|RuleOpts Service handle, name, or options table
function fw:rule(from, to, action, service_or_opts) end

---@class DnatOpts
---@field iface ZoneHandle|string Incoming interface zone
---@field dest string|HostHandle Destination IP or host
---@field service? ServiceRef Service to match
---@field proto? string|string[] Protocol(s)
---@field port? integer|string|integer[] Port(s) to match
---@field daddr? string Original destination address match
---@field dest_port? integer Port remap (0 = same port)

--- Add a DNAT (port forwarding) rule.
---@param opts DnatOpts
function fw:dnat(opts) end

---@class SnatOpts
---@field from string Source subnet (CIDR)
---@field oif string Outgoing interface name
---@field masquerade? boolean Use masquerading (dynamic IP)
---@field addr? string Static SNAT address (mutually exclusive with masquerade)
---@field daddr? string Destination match
---@field proto? string Protocol filter
---@field port? integer|string|integer[] Port filter

--- Add an SNAT rule.
---@param opts SnatOpts
function fw:snat(opts) end

---@class RedirectOpts
---@field iface ZoneHandle|string Incoming interface zone
---@field proto string|string[] Protocol(s)
---@field port integer|string|integer[] Incoming port(s) to match
---@field dest_port integer Local port to redirect to

--- Add a redirect (local port redirect / transparent proxy) rule.
---@param opts RedirectOpts
function fw:redirect(opts) end

---@class IplistOpts
---@field type "ipv4"|"ipv6" Address family
---@field flags? string Set flags ("timeout", "interval", etc.)
---@field elements? string[] Static elements
---@field url? string URL for auto-refresh

--- Declare an IP set (for blocklists, allowlists, GeoIP, etc.).
---@param name string Set name
---@param opts IplistOpts
function fw:iplist(name, opts) end

--- Configure Docker bridge awareness.
---@param opts { bridges: string[], backend?: string }
function fw:docker(opts) end

---@class ConfigOpts
---@field table_name? string nftables table name (default: "matchstick")
---@field priority_offset? integer Chain priority offset (default: 5)
---@field log_rate? string Default log rate (default: "5/minute burst 5")
---@field log_prefix? string Log prefix (default: "matchstick")
---@field log_level? string Log level (default: "info")
---@field family? string Address family: "inet" or "ip" (default: "inet")
---@field log_set_size? integer Max entries in rate limit sets (default: 65535)
---@field log_set_timeout? integer Rate limit entry timeout in seconds (default: 60)
---@field counter? boolean Add counters to all rules (default: false)
---@field input_policy? string Input chain policy: "drop" or "reject" (default: "drop")
---@field output_policy? string Output chain policy: "accept" or "drop" (default: "accept")

--- Override global configuration.
---@param opts ConfigOpts
function fw:config(opts) end

--- Include another Lua config file.
---@param path string Path to Lua file (relative to current config dir)
function fw:include(path) end

--- Set or unset kernel sysctl values.
--- Use `false` as value to unset (don't touch) a derived default.
---@param key_or_table string|table<string, string|integer|false> Sysctl key or table of key=value pairs
---@param value? string|integer|false Sysctl value, or false to unset
---@overload fun(self: fw, tbl: table<string, string|integer|false>)
function fw:sysctl(key_or_table, value) end

--- Enable MSS clamping on a chain (needed for PPPoE/VPN/tunnels).
---@param chain? "forward"|"output"|"postrouting" Chain to clamp (default: "forward")
function fw:mss_clamp(chain) end

--- Set lifecycle hook commands.
---@param opts { pre_start?: string, post_start?: string, pre_stop?: string, post_stop?: string }
function fw:hook(opts) end

---@class ChainOpts
---@field type "filter"|"nat"|"route" Chain type
---@field priority string Named priority ("raw","mangle","filter","security","srcnat","dstnat") or number
---@field rules table[] Array of nftables JSON rule expr arrays

--- Create a custom chain at an arbitrary netfilter hook and priority.
---@param hook "prerouting"|"postrouting"|"forward"|"input"|"output"
---@param opts ChainOpts
function fw:chain(hook, opts) end

--- Inject raw nftables JSON command objects into the ruleset.
--- Each argument is a table representing a single nftables JSON command.
---@param ... table nftables JSON command objects
function fw:raw_nft(...) end

--- Add exception rules to drop chains (invalid, rpfilter, anti_smurf).
---@param chain "invalid"|"rpfilter"|"anti_smurf" Chain name
---@param action "accept"|"drop"|"reject" Action for matching packets
---@param service_or_opts? ServiceRef|{ service?: ServiceRef, proto?: string|string[], port?: integer|string|integer[] }
function fw:exception(chain, action, service_or_opts) end

-- =========================================================================
-- util table
-- =========================================================================

---@class util
util = {}

--- Create a rate limit object for use in fw:rule().
---@param rate string Rate expression (e.g. "5/minute", "3/second")
---@param opts? { burst?: integer, name?: string } Rate options
---@return RateHandle
function util:rate(rate, opts) end
