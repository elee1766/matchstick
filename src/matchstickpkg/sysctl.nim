## sysctl.nim - Derive and apply kernel sysctl settings from firewall config.
##
## Analyzes FirewallState to determine which sysctls are needed:
## - IP forwarding: enabled if any zone-to-zone forwarding exists
## - ARP hardening: secure defaults for all interfaces
## - Redirect protection: disabled on all interfaces
## - Source routing: disabled on all interfaces
## - Reverse path filter: set per-interface based on rpfilter config
## - Explicit overrides from fw:sysctl()
##
## At apply time, writes values to /proc/sys/ entries.

import std/[strutils, tables]
import ./types

const sysctlKeyChars = {'a'..'z', 'A'..'Z', '0'..'9', '_', '.'}

proc isValidSysctlKey*(key: string): bool =
  ## Validate that a sysctl key contains only safe characters.
  ## Prevents path traversal (e.g. "../../etc/shadow").
  if key.len == 0 or key.len > 256: return false
  if key.startsWith(".") or key.endsWith(".") or ".." in key: return false
  for c in key:
    if c notin sysctlKeyChars: return false
  return true

type
  SysctlSet* = object
    entries*: seq[SysctlEntry]

proc deriveSysctls*(state: FirewallState): SysctlSet =
  ## Analyze the firewall state and derive required sysctl settings.
  var entries: seq[SysctlEntry]

  # Collect all interface names
  var allIfaces: seq[string]
  for _, zone in state.zones:
    for iface in zone.interfaces:
      if iface notin allIfaces:
        allIfaces.add iface

  # --- IP forwarding ---
  # Enable if any non-fw zone-to-zone forwarding exists (policies or rules
  # between two zones that both have interfaces)
  var needsForward = false
  let fwZoneName = block:
    var n = ""
    for _, z in state.zones:
      if z.interfaces.len == 0:
        n = z.name
        break
    n

  for pol in state.policies:
    if pol.src.zone != nil and pol.dst.zone != nil:
      if pol.src.zone.name != fwZoneName and pol.dst.zone.name != fwZoneName:
        if pol.src.zone.interfaces.len > 0 and pol.dst.zone.interfaces.len > 0:
          needsForward = true
          break

  if not needsForward:
    for rule in state.rules:
      if rule.src.zone != nil and rule.dst.zone != nil:
        if rule.src.zone.name != fwZoneName and rule.dst.zone.name != fwZoneName:
          if rule.src.zone.interfaces.len > 0 and rule.dst.zone.interfaces.len > 0:
            needsForward = true
            break

  if not needsForward:
    # DNAT implies forwarding (traffic comes in one interface, goes to another)
    if state.dnatRules.len > 0:
      needsForward = true

  if needsForward:
    entries.add SysctlEntry(key: "net.ipv4.conf.all.forwarding", value: "1")
    entries.add SysctlEntry(key: "net.ipv6.conf.all.forwarding", value: "1")

  # --- ARP hardening ---
  entries.add SysctlEntry(key: "net.ipv4.conf.default.arp_announce", value: "2")
  entries.add SysctlEntry(key: "net.ipv4.conf.all.arp_announce", value: "2")
  entries.add SysctlEntry(key: "net.ipv4.conf.default.arp_ignore", value: "1")
  entries.add SysctlEntry(key: "net.ipv4.conf.all.arp_ignore", value: "1")
  entries.add SysctlEntry(key: "net.ipv4.conf.default.arp_filter", value: "1")
  entries.add SysctlEntry(key: "net.ipv4.conf.all.arp_filter", value: "1")

  # --- Redirect protection ---
  entries.add SysctlEntry(key: "net.ipv4.conf.default.accept_redirects", value: "0")
  entries.add SysctlEntry(key: "net.ipv4.conf.all.accept_redirects", value: "0")
  entries.add SysctlEntry(key: "net.ipv4.conf.default.send_redirects", value: "0")
  entries.add SysctlEntry(key: "net.ipv4.conf.all.send_redirects", value: "0")
  entries.add SysctlEntry(key: "net.ipv6.conf.default.accept_redirects", value: "0")
  entries.add SysctlEntry(key: "net.ipv6.conf.all.accept_redirects", value: "0")

  # --- Source routing protection ---
  entries.add SysctlEntry(key: "net.ipv4.conf.default.accept_source_route", value: "0")
  entries.add SysctlEntry(key: "net.ipv4.conf.all.accept_source_route", value: "0")
  entries.add SysctlEntry(key: "net.ipv6.conf.default.accept_source_route", value: "0")
  entries.add SysctlEntry(key: "net.ipv6.conf.all.accept_source_route", value: "0")

  # --- Log martians ---
  entries.add SysctlEntry(key: "net.ipv4.conf.default.log_martians", value: "1")
  entries.add SysctlEntry(key: "net.ipv4.conf.all.log_martians", value: "1")

  # --- Apply explicit overrides from fw:sysctl() ---
  # These go last so they can override or unset any derived value
  var seen: Table[string, int]  # key -> index in entries
  for i, e in entries:
    seen[e.key] = i

  for ovr in state.sysctlOverrides:
    if ovr.key in seen:
      if ovr.unset:
        # Mark for removal (we'll filter later)
        entries[seen[ovr.key]].unset = true
      else:
        entries[seen[ovr.key]] = ovr
    else:
      if not ovr.unset:
        entries.add ovr
        seen[ovr.key] = entries.len - 1

  # Filter out unset entries
  var filtered: seq[SysctlEntry]
  for e in entries:
    if not e.unset:
      filtered.add e

  result = SysctlSet(entries: filtered)

proc formatSysctls*(sysctls: SysctlSet): string =
  ## Format sysctls for display (check/render output).
  for entry in sysctls.entries:
    result.add entry.key & " = " & entry.value & "\n"
