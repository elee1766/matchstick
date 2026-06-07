## matchstick - Lua-based nftables firewall configuration tool

import std/[os, strformat, options, tables, parseopt, strutils]
import experimental/diff
import ./lua/ffi
import ./types
import ./lua/api
import ./build
import ./emit_text
import ./emit_json
import ./validate
import ./show
import ./nftables_ffi
import ./sysctl
import ./import_ufw

const
  defaultConfigPaths = [
    "/etc/matchstick/firewall.lua",
  ]

proc findConfig(): string =
  for path in defaultConfigPaths:
    if fileExists(path): return path
  return ""

proc usage() =
  stderr.writeLine """matchstick - Lua-based nftables firewall configuration tool

Usage:
  matchstick check  [config.lua]                    Validate config
  matchstick render [config.lua]                    Print nftables text
  matchstick render --json [config.lua]             Print nftables JSON
  matchstick apply  [config.lua]                    Apply to kernel
  matchstick apply  --no-sysctl [config.lua]        Apply without sysctl changes
  matchstick diff   [config.lua]                    Diff running vs generated

  matchstick show matrix   [config.lua]             Zone policy matrix
  matchstick show rules    [config.lua] <src> <dst> Rules for zone pair
  matchstick show topology [config.lua]             Topology diagram
    --format=dot|d2|mermaid|ascii                     (default: ascii)
  matchstick show json     [config.lua]             State as JSON
  matchstick show sysctl   [config.lua]             Show derived sysctls

  matchstick import-ufw                             Import UFW rules from stdin
                                                      sudo ufw show added | matchstick import-ufw

If no config file is specified, searches:"""
  for p in defaultConfigPaths:
    stderr.writeLine "  " & p
  quit(1)

proc loadConfig(configFile: string): FirewallState =
  let L = luaL_newstate()
  if L == nil:
    raise newException(CatchableError, "failed to create Lua state")
  defer: lua_close(L)

  luaL_openlibs(L)

  let state = newFirewallState()
  setupLuaVM(L, state, configFile)

  var status = luaL_loadfile(L, configFile.cstring)
  if status != LUA_OK:
    let msg = $lua_tostring(L, -1)
    raise newException(CatchableError, msg)

  status = lua_pcall(L, 0, 0, 0)
  if status != LUA_OK:
    let msg = $lua_tostring(L, -1)
    raise newException(CatchableError, msg)

  return state

proc printSummary(state: FirewallState) =
  stderr.writeLine &"""  zones:      {state.zones.len}
  hosts:      {state.hosts.len}
  services:   {state.services.len}
  policies:   {state.policies.len}
  rules:      {state.rules.len}
  dnat:       {state.dnatRules.len}
  snat:       {state.snatRules.len}
  iplists:    {state.ipLists.len}
  dhcp:       {state.dhcp.len}
  docker:     {state.docker.isSome}
  chains:     {state.customChains.len}
  raw_nft:    {state.rawNft.len}
  exceptions: {state.chainExceptions.len}"""

proc runValidation(state: FirewallState): bool =
  let msgs = validate(state)
  var hasErrors = false
  for m in msgs:
    let prefix = case m.severity
      of svWarning: "warning"
      of svError: "error"
    stderr.writeLine prefix & ": " & m.msg
    if m.severity == svError:
      hasErrors = true
  for w in state.warnings:
    stderr.writeLine "warning: " & w
  return not hasErrors

# ---------------------------------------------------------------------------
# Parse CLI
# ---------------------------------------------------------------------------

type
  CliOpts = object
    command: string       ## "check", "render", "apply", "diff", "show"
    showSub: string       ## "matrix", "rules", "topology", "json", "sysctl"
    configFile: string
    jsonOutput: bool
    noSysctl: bool        ## skip sysctl application
    format: string        ## topology format
    extraArgs: seq[string]

proc parseCli(): CliOpts =
  result.format = "ascii"

  var positionals: seq[string]
  var p = initOptParser(commandLineParams())

  for kind, key, val in p.getopt():
    case kind
    of cmdArgument:
      positionals.add key
    of cmdShortOption, cmdLongOption:
      case key
      of "json", "j": result.jsonOutput = true
      of "no-sysctl": result.noSysctl = true
      of "format": result.format = val
      of "help", "h": usage()
      else:
        stderr.writeLine "error: unknown option: --" & key
        usage()
    of cmdEnd: discard

  if positionals.len == 0:
    usage()

  result.command = positionals[0]
  var rest = positionals[1..^1]

  if result.command == "show":
    if rest.len == 0:
      usage()
    result.showSub = rest[0]
    rest = rest[1..^1]

  # Find config file among remaining positionals
  for i, arg in rest:
    if result.configFile == "" and fileExists(arg):
      result.configFile = arg
    else:
      result.extraArgs.add arg

  # Fall back to default config paths
  if result.configFile == "":
    result.configFile = findConfig()

proc requireConfig(opts: CliOpts) =
  if opts.configFile == "":
    stderr.writeLine "error: no config file specified and none found at default paths"
    for p in defaultConfigPaths:
      stderr.writeLine "  looked in: " & p
    quit(1)
  if not fileExists(opts.configFile):
    stderr.writeLine "error: file not found: " & opts.configFile
    quit(1)

# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

proc cmdCheck(opts: CliOpts) =
  let state = loadConfig(opts.configFile)
  let ok = runValidation(state)
  printSummary(state)
  let sysctls = deriveSysctls(state)
  stderr.writeLine &"  sysctls:    {sysctls.entries.len}"
  if ok:
    echo "ok: " & opts.configFile
  else:
    echo "FAIL: " & opts.configFile & " (has errors)"
    quit(1)

proc cmdRender(opts: CliOpts) =
  let state = loadConfig(opts.configFile)
  let ok = runValidation(state)
  if not ok:
    stderr.writeLine "error: config has validation errors"
    quit(1)
  let ruleset = buildRuleset(state)
  if opts.jsonOutput:
    stdout.write emitJson(ruleset)
  else:
    stdout.write emitText(ruleset)

proc cmdApply(opts: CliOpts) =
  let state = loadConfig(opts.configFile)
  let ok = runValidation(state)
  if not ok:
    stderr.writeLine "error: config has validation errors, refusing to apply"
    quit(1)
  let ruleset = buildRuleset(state)
  let text = emitText(ruleset)

  stderr.writeLine "validating..."
  let valResult = nftValidate(text)
  if not valResult.success:
    stderr.writeLine "error: nftables validation failed:"
    stderr.writeLine valResult.error
    quit(1)

  # Apply sysctl settings (before loading nftables rules)
  if not opts.noSysctl:
    let sysctls = deriveSysctls(state)
    if sysctls.entries.len > 0:
      stderr.writeLine "applying " & $sysctls.entries.len & " sysctl settings..."
      let errors = applySysctls(sysctls)
      for e in errors:
        stderr.writeLine "warning: sysctl: " & e
  else:
    stderr.writeLine "skipping sysctl (--no-sysctl)"

  if state.hooks.preStart != "":
    stderr.writeLine "running pre_start hook..."
    let hookResult = execShellCmd(state.hooks.preStart)
    if hookResult != 0:
      stderr.writeLine "warning: pre_start hook exited with code " & $hookResult

  stderr.writeLine "applying..."
  let applyResult = nftApply(text)
  if not applyResult.success:
    stderr.writeLine "error: nftables apply failed:"
    stderr.writeLine applyResult.error
    quit(1)

  if state.hooks.postStart != "":
    stderr.writeLine "running post_start hook..."
    let hookResult = execShellCmd(state.hooks.postStart)
    if hookResult != 0:
      stderr.writeLine "warning: post_start hook exited with code " & $hookResult

  echo "ok: rules applied"

proc unifiedDiff(a, b: string, labelA = "running", labelB = "generated", context = 3): string =
  ## Produce unified diff output in memory.
  let linesA = a.splitLines()
  let linesB = b.splitLines()
  let items = diffText(a, b)

  if items.len == 0: return ""

  result.add "--- " & labelA & "\n"
  result.add "+++ " & labelB & "\n"

  for item in items:
    # Context window around this change
    let startA = max(0, item.startA - context)
    let startB = max(0, item.startB - context)
    let endA = min(linesA.len, item.startA + item.deletedA + context)
    let endB = min(linesB.len, item.startB + item.insertedB + context)
    let countA = endA - startA
    let countB = endB - startB

    result.add &"@@ -{startA + 1},{countA} +{startB + 1},{countB} @@\n"

    # Leading context
    for i in startA ..< item.startA:
      result.add " " & linesA[i] & "\n"
    # Deletions
    for i in item.startA ..< item.startA + item.deletedA:
      result.add "-" & linesA[i] & "\n"
    # Insertions
    for i in item.startB ..< item.startB + item.insertedB:
      result.add "+" & linesB[i] & "\n"
    # Trailing context
    for i in item.startA + item.deletedA ..< endA:
      result.add " " & linesA[i] & "\n"

proc cmdDiff(opts: CliOpts) =
  let state = loadConfig(opts.configFile)
  discard runValidation(state)
  let ruleset = buildRuleset(state)
  let generated = emitText(ruleset)

  let tn = state.config.tableName
  let currentFilter = nftListTable("inet", tn)
  let currentNat = nftListTable("inet", tn & "_nat")

  var running = ""
  if currentFilter.success: running &= currentFilter.output
  if currentNat.success: running &= currentNat.output

  if running == "":
    stderr.writeLine "note: no running matchstick tables found (table inet " & tn & ")"
    echo "--- (no running rules)"
    echo "+++ (generated)"
    echo generated
  else:
    let d = unifiedDiff(running, generated)
    if d == "":
      echo "no differences"
    else:
      stdout.write d

proc cmdShow(opts: CliOpts) =
  let state = loadConfig(opts.configFile)
  discard runValidation(state)

  case opts.showSub
  of "matrix":
    showMatrix(state)
  of "rules":
    if opts.extraArgs.len < 2:
      stderr.writeLine "error: show rules requires <src> <dst> arguments"
      quit(1)
    showRules(state, opts.extraArgs[0], opts.extraArgs[1])
  of "topology":
    case opts.format
    of "dot": showTopologyDot(state)
    of "d2": showTopologyD2(state)
    of "mermaid": showTopologyMermaid(state)
    of "ascii": showTopologyAscii(state)
    else:
      stderr.writeLine "error: unknown format: " & opts.format
      quit(1)
  of "json":
    showStateJson(state)
  of "sysctl":
    let sysctls = deriveSysctls(state)
    stdout.write formatSysctls(sysctls)
  else:
    stderr.writeLine "error: unknown show subcommand: " & opts.showSub
    usage()

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

proc cmdImportUfw() =
  let input = stdin.readAll()
  if input.strip() == "":
    stderr.writeLine "error: no input. Usage: sudo ufw show added | matchstick import-ufw"
    quit(1)
  stdout.write importUfw(input)

proc main() =
  let opts = parseCli()

  # Commands that don't need a config file
  if opts.command == "import-ufw":
    try:
      cmdImportUfw()
    except CatchableError as e:
      stderr.writeLine "error: " & e.msg
      quit(1)
    return

  requireConfig(opts)

  try:
    case opts.command
    of "check":   cmdCheck(opts)
    of "render":  cmdRender(opts)
    of "apply":   cmdApply(opts)
    of "diff":    cmdDiff(opts)
    of "show":    cmdShow(opts)
    else:
      stderr.writeLine "error: unknown command: " & opts.command
      usage()
  except CatchableError as e:
    stderr.writeLine "error: " & e.msg
    quit(1)

when isMainModule:
  main()
