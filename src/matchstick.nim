## matchstick - Lua-based nftables firewall configuration tool

import std/[os, strformat, options, tables, parseopt, strutils]
import ./lua55/sandbox
import ./matchstickpkg/types
import ./matchstickpkg/build
import ./matchstickpkg/emit_text
import ./matchstickpkg/emit_json
import ./matchstickpkg/validate
import ./matchstickpkg/show
import ./matchstickpkg/sysctl
import ./matchstickpkg/import_ufw

import experimental/diff

when not defined(noSystem):
  import ./nftables_cli

# ---------------------------------------------------------------------------
# Version info (computed at compile time from git)
# ---------------------------------------------------------------------------
# git describe --tags --always --dirty produces:
#   v0.1.0                   exactly on a tag
#   v0.1.0-3-gabc1234        3 commits after v0.1.0
#   v0.1.0-3-gabc1234-dirty  same, with uncommitted changes
#   abc1234                   no tags at all
#   abc1234-dirty             no tags, uncommitted changes

const
  versionString* = block:
    let desc = staticExec("git describe --tags --always --dirty 2>/dev/null").strip()
    if desc.len > 0: desc else: "unknown"
  gitCommit* = staticExec("git rev-parse --short HEAD 2>/dev/null").strip()
  compileDate* = CompileDate & " " & CompileTime
  nimVersion* = NimVersion

const
  defaultConfigPaths = [
    "/etc/matchstick/firewall.lua",
  ]

proc findConfig(): string =
  for path in defaultConfigPaths:
    if fileExists(path): return path
  return ""

proc usage() =
  stderr.writeLine "matchstick " & versionString
  stderr.writeLine "Lua-based nftables firewall configuration tool"
  stderr.writeLine ""
  stderr.writeLine "Commands:"
  stderr.writeLine "  check   [config]              Validate config"
  stderr.writeLine "  render  [config]              Emit nftables text (--json for JSON)"
  stderr.writeLine "  diff    <fileA> <fileB>       Diff two rulesets (- for stdin)"
  when not defined(noSystem):
    stderr.writeLine "  apply   [config]              Apply to kernel (--no-sysctl to skip)"
  stderr.writeLine "  show    <sub> [config]        Visualize config (see below)"
  stderr.writeLine "  import-ufw                    Convert UFW rules from stdin"
  stderr.writeLine "  version                       Print build info"
  stderr.writeLine ""
  stderr.writeLine "Show subcommands:"
  stderr.writeLine "  matrix                        Zone policy grid"
  stderr.writeLine "  rules   <src> <dst>           Rules for a zone pair"
  stderr.writeLine "  topology                      Diagram (--format=dot|d2|mermaid|ascii)"
  stderr.writeLine "  json                          Full state as JSON"
  stderr.writeLine "  sysctl                        Derived sysctl settings"
  stderr.writeLine ""
  stderr.writeLine "Options:"
  stderr.writeLine "  --allow-hooks                 Allow fw:hook shell commands"
  stderr.writeLine "  --allow-raw-nft               Allow fw:chain/fw:raw_nft"
  stderr.writeLine "  --json, -j                    JSON output (render, apply)"
  stderr.writeLine "  --version, -v                 Print version"
  stderr.writeLine ""
  stderr.writeLine "Config is auto-detected from /etc/matchstick/firewall.lua if not specified."
  stderr.writeLine ".lua files in diff are rendered; other files and - are read as text."
  quit(1)

proc loadConfig(configFile: string): FirewallState =
  ## Load and execute a Lua firewall config.
  ## Calls through lua55/sandbox which handles Lua↔Nim boundary safely.
  let res = runConfig(configFile)
  if res.error != "":
    stderr.writeLine "error: " & res.error
    quit(1)
  return res.state

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
    allowHooks: bool      ## allow fw:hook shell commands
    allowRawNft: bool     ## allow fw:chain/fw:raw_nft escape hatches
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
      if key == "":
        # Bare "-" is treated as a positional (stdin convention)
        positionals.add "-"
      else:
        case key
        of "json", "j": result.jsonOutput = true
        of "no-sysctl": result.noSysctl = true
        of "allow-hooks": result.allowHooks = true
        of "allow-raw-nft": result.allowRawNft = true
        of "format": result.format = val
        of "help", "h": usage()
        of "version", "v", "V":
          echo "matchstick " & versionString
          quit(0)
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

  if result.command == "diff":
    # diff takes two positional args directly (not auto-detected config paths)
    if rest.len >= 2:
      result.configFile = rest[0]
      result.extraArgs = rest[1..^1]
    elif rest.len == 1:
      result.configFile = rest[0]
    else:
      result.configFile = ""
  else:
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

proc enforceEscapeHatches(opts: CliOpts, state: FirewallState) =
  if not opts.allowHooks and (state.hooks.preStart != "" or state.hooks.postStart != "" or
      state.hooks.preStop != "" or state.hooks.postStop != ""):
    stderr.writeLine "error: config uses fw:hook shell commands; rerun with --allow-hooks if this config is trusted"
    quit(1)
  if not opts.allowRawNft and (state.rawNft.len > 0 or state.customChains.len > 0):
    stderr.writeLine "error: config uses fw:chain/fw:raw_nft escape hatches; rerun with --allow-raw-nft if this config is trusted"
    quit(1)

# ---------------------------------------------------------------------------
# Commands: always available (pure computation)
# ---------------------------------------------------------------------------

proc cmdCheck(opts: CliOpts) =
  let state = loadConfig(opts.configFile)
  enforceEscapeHatches(opts, state)
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
  enforceEscapeHatches(opts, state)
  let ok = runValidation(state)
  if not ok:
    stderr.writeLine "error: config has validation errors"
    quit(1)
  let ruleset = buildRuleset(state)
  if opts.jsonOutput:
    stdout.write emitJson(ruleset)
  else:
    stdout.write emitText(ruleset)

proc cmdShow(opts: CliOpts) =
  let state = loadConfig(opts.configFile)
  enforceEscapeHatches(opts, state)
  discard runValidation(state)

  case opts.showSub
  of "matrix":
    stdout.write showMatrix(state)
  of "rules":
    if opts.extraArgs.len < 2:
      stderr.writeLine "error: show rules requires <src> <dst> arguments"
      quit(1)
    stdout.write showRules(state, opts.extraArgs[0], opts.extraArgs[1])
  of "topology":
    case opts.format
    of "dot": stdout.write showTopologyDot(state)
    of "d2": stdout.write showTopologyD2(state)
    of "mermaid": stdout.write showTopologyMermaid(state)
    of "ascii": stdout.write showTopologyAscii(state)
    else:
      stderr.writeLine "error: unknown format: " & opts.format
      quit(1)
  of "json":
    stdout.write showStateJson(state)
  of "sysctl":
    let sysctls = deriveSysctls(state)
    stdout.write formatSysctls(sysctls)
  else:
    stderr.writeLine "error: unknown show subcommand: " & opts.showSub
    usage()

proc cmdImportUfw() =
  let input = stdin.readAll()
  if input.strip() == "":
    stderr.writeLine "error: no input. Usage: sudo ufw show added | matchstick import-ufw"
    quit(1)
  stdout.write importUfw(input)

# ---------------------------------------------------------------------------
# Commands: system-only (require nft binary, root, /proc)
# ---------------------------------------------------------------------------

when not defined(noSystem):
  proc cmdApply(opts: CliOpts) =
    let state = loadConfig(opts.configFile)
    enforceEscapeHatches(opts, state)
    let ok = runValidation(state)
    if not ok:
      stderr.writeLine "error: config has validation errors, refusing to apply"
      quit(1)
    let ruleset = buildRuleset(state)
    let jsonStr = emitJson(ruleset, pretty = false)

    stderr.writeLine "validating..."
    let valResult = nftValidate(jsonStr)
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
    let applyResult = nftApply(jsonStr)
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

# ---------------------------------------------------------------------------
# Commands: diff (pure computation, no nft dependency)
# ---------------------------------------------------------------------------

proc unifiedDiff(a, b: string, labelA = "a", labelB = "b", context = 3): string =
  let linesA = a.splitLines()
  let linesB = b.splitLines()
  let items = diffText(a, b)

  if items.len == 0: return ""

  result.add "--- " & labelA & "\n"
  result.add "+++ " & labelB & "\n"

  for item in items:
    let startA = max(0, item.startA - context)
    let startB = max(0, item.startB - context)
    let endA = min(linesA.len, item.startA + item.deletedA + context)
    let endB = min(linesB.len, item.startB + item.insertedB + context)
    let countA = endA - startA
    let countB = endB - startB

    result.add &"@@ -{startA + 1},{countA} +{startB + 1},{countB} @@\n"

    for i in startA ..< item.startA:
      result.add " " & linesA[i] & "\n"
    for i in item.startA ..< item.startA + item.deletedA:
      result.add "-" & linesA[i] & "\n"
    for i in item.startB ..< item.startB + item.insertedB:
      result.add "+" & linesB[i] & "\n"
    for i in item.startA + item.deletedA ..< endA:
      result.add " " & linesA[i] & "\n"

proc readDiffInput(path: string): string =
  ## Read a diff input: "-" means stdin, ".lua" files are rendered, otherwise read as text.
  if path == "-":
    return stdin.readAll()
  elif not fileExists(path):
    stderr.writeLine "error: file not found: " & path
    quit(1)
  else:
    return readFile(path)

proc renderLuaConfig(path: string, opts: CliOpts): string =
  ## Load a .lua config, validate, and render to nftables text.
  let state = loadConfig(path)
  enforceEscapeHatches(opts, state)
  let ok = runValidation(state)
  if not ok:
    stderr.writeLine "error: config has validation errors"
    quit(1)
  let ruleset = buildRuleset(state)
  return emitText(ruleset)

proc cmdDiff(opts: CliOpts) =
  ## Diff two nftables rulesets. Each argument can be:
  ##   - A .lua config file (rendered to nftables text)
  ##   - A plain text file (used as-is)
  ##   - "-" for stdin
  ##
  ## Examples:
  ##   matchstick diff firewall.lua old.nft
  ##   nft list table inet matchstick | matchstick diff firewall.lua -
  ##   matchstick diff v1.lua v2.lua
  if opts.extraArgs.len < 1:
    stderr.writeLine "error: diff requires two arguments"
    stderr.writeLine "usage: matchstick diff <fileA> <fileB>"
    stderr.writeLine "  each file can be a .lua config, a text file, or - for stdin"
    stderr.writeLine "  example: nft list table inet matchstick | matchstick diff firewall.lua -"
    quit(1)

  let pathA = opts.configFile
  let pathB = if opts.extraArgs.len >= 1: opts.extraArgs[0] else: "-"

  if pathA == "-" and pathB == "-":
    stderr.writeLine "error: both inputs cannot be stdin"
    quit(1)

  let labelA = if pathA == "-": "(stdin)" else: pathA
  let labelB = if pathB == "-": "(stdin)" else: pathB

  let textA = if pathA.endsWith(".lua"): renderLuaConfig(pathA, opts)
              else: readDiffInput(pathA)
  let textB = if pathB.endsWith(".lua"): renderLuaConfig(pathB, opts)
              else: readDiffInput(pathB)

  let d = unifiedDiff(textA, textB, labelA, labelB)
  if d == "":
    echo "no differences"
  else:
    stdout.write d

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

proc main() =
  let opts = parseCli()

  # Commands that don't need a config file
  if opts.command == "version":
    echo "matchstick " & versionString
    echo "  commit:   " & gitCommit
    echo "  built:    " & compileDate
    echo "  nim:      " & nimVersion
    return

  if opts.command == "import-ufw":
    try:
      cmdImportUfw()
    except CatchableError as e:
      stderr.writeLine "error: " & e.msg
      quit(1)
    return

  # diff handles its own argument validation (two file args, not one config)
  if opts.command == "diff":
    try:
      cmdDiff(opts)
    except CatchableError as e:
      stderr.writeLine "error: " & e.msg
      quit(1)
    return

  requireConfig(opts)

  try:
    case opts.command
    of "check":   cmdCheck(opts)
    of "render":  cmdRender(opts)
    of "show":    cmdShow(opts)
    of "apply":
      when defined(noSystem):
        stderr.writeLine "error: 'apply' is not available in this build (compiled with -d:noSystem)"
        quit(1)
      else:
        cmdApply(opts)
    else:
      stderr.writeLine "error: unknown command: " & opts.command
      usage()
  except CatchableError as e:
    stderr.writeLine "error: " & e.msg
    quit(1)

when isMainModule:
  main()
