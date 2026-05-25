## matchstick - Lua-based nftables firewall configuration tool

import std/[os, strformat, options, tables, strutils]
import ./lua/ffi
import ./types
import ./lua/api
import ./build
import ./emit_text
import ./emit_json
import ./validate
import ./show
import ./nftables_ffi

const
  defaultConfigPaths = [
    "/etc/matchstick/firewall.lua",
  ]

proc findConfig(): string =
  ## Find the config file from default paths.
  for path in defaultConfigPaths:
    if fileExists(path):
      return path
  return ""

proc usage() =
  echo "matchstick - Lua-based nftables firewall configuration tool"
  echo ""
  echo "Usage:"
  echo "  matchstick check  [config.lua]                    Validate config"
  echo "  matchstick render [config.lua]                    Print nftables text"
  echo "  matchstick render --json [config.lua]             Print nftables JSON"
  echo "  matchstick apply  [config.lua]                    Apply to kernel"
  echo "  matchstick diff   [config.lua]                    Diff running vs generated"
  echo ""
  echo "  matchstick show matrix   [config.lua]             Zone policy matrix"
  echo "  matchstick show rules    [config.lua] <src> <dst> Rules for zone pair"
  echo "  matchstick show topology [config.lua]             Topology diagram"
  echo "    --format=dot|d2|mermaid|ascii                     (default: ascii)"
  echo "  matchstick show json     [config.lua]             State as JSON"
  echo ""
  echo "If no config file is specified, searches:"
  for p in defaultConfigPaths:
    echo "  " & p
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
  stderr.writeLine &"  zones:      {state.zones.len}"
  stderr.writeLine &"  hosts:      {state.hosts.len}"
  stderr.writeLine &"  services:   {state.services.len}"
  stderr.writeLine &"  policies:   {state.policies.len}"
  stderr.writeLine &"  rules:      {state.rules.len}"
  stderr.writeLine &"  dnat:       {state.dnatRules.len}"
  stderr.writeLine &"  snat:       {state.snatRules.len}"
  stderr.writeLine &"  iplists:    {state.ipLists.len}"
  stderr.writeLine &"  dhcp:       {state.dhcp.len}"
  stderr.writeLine &"  docker:     {state.docker.isSome}"
  stderr.writeLine &"  chains:     {state.customChains.len}"
  stderr.writeLine &"  raw_nft:    {state.rawNft.len}"
  stderr.writeLine &"  exceptions: {state.chainExceptions.len}"

proc runValidation(state: FirewallState): bool =
  ## Run validation and print messages. Returns true if no errors.
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

proc main() =
  let args = commandLineParams()
  if args.len < 2:
    usage()

  let command = args[0]

  # Handle "show" subcommand family
  if command == "show":
    if args.len < 3:
      usage()
    let subCmd = args[1]
    var configFile = ""
    var formatStr = "ascii"
    var extraArgs: seq[string]

    for i in 2 ..< args.len:
      if args[i].startsWith("--format="):
        formatStr = args[i].split("=", 1)[1]
      elif configFile == "" and fileExists(args[i]):
        configFile = args[i]
      else:
        extraArgs.add args[i]

    if configFile == "":
      stderr.writeLine "error: no config file specified"
      quit(1)

    try:
      let state = loadConfig(configFile)
      discard runValidation(state)

      case subCmd
      of "matrix":
        showMatrix(state)
      of "rules":
        if extraArgs.len < 2:
          stderr.writeLine "error: show rules requires <src> <dst> arguments"
          quit(1)
        showRules(state, extraArgs[0], extraArgs[1])
      of "topology":
        case formatStr
        of "dot": showTopologyDot(state)
        of "d2": showTopologyD2(state)
        of "mermaid": showTopologyMermaid(state)
        of "ascii": showTopologyAscii(state)
        else:
          stderr.writeLine "error: unknown format: " & formatStr
          quit(1)
      of "json":
        showStateJson(state)
      else:
        stderr.writeLine "error: unknown show subcommand: " & subCmd
        usage()
    except CatchableError as e:
      stderr.writeLine "error: " & e.msg
      quit(1)
    return

  # Regular commands
  var jsonOutput = false
  var configFile = ""
  for i in 1 ..< args.len:
    case args[i]
    of "--json", "-j":
      jsonOutput = true
    else:
      if configFile == "":
        configFile = args[i]

  # If no config file specified, search defaults
  if configFile == "":
    configFile = findConfig()
    if configFile == "":
      stderr.writeLine "error: no config file specified and none found at default paths"
      for p in defaultConfigPaths:
        stderr.writeLine "  looked in: " & p
      quit(1)

  if not fileExists(configFile):
    stderr.writeLine "error: file not found: " & configFile
    quit(1)

  case command
  of "check":
    try:
      let state = loadConfig(configFile)
      let ok = runValidation(state)
      printSummary(state)
      if ok:
        echo "ok: " & configFile
      else:
        echo "FAIL: " & configFile & " (has errors)"
        quit(1)
    except CatchableError as e:
      stderr.writeLine "error: " & e.msg
      quit(1)

  of "render":
    try:
      let state = loadConfig(configFile)
      let ok = runValidation(state)
      if not ok:
        stderr.writeLine "error: config has validation errors"
        quit(1)
      let ruleset = buildRuleset(state)
      if jsonOutput:
        stdout.write emitJson(ruleset)
      else:
        stdout.write emitText(ruleset)
    except CatchableError as e:
      stderr.writeLine "error: " & e.msg
      quit(1)

  of "apply":
    try:
      let state = loadConfig(configFile)
      let ok = runValidation(state)
      if not ok:
        stderr.writeLine "error: config has validation errors, refusing to apply"
        quit(1)
      let ruleset = buildRuleset(state)
      let text = emitText(ruleset)

      # First validate via dry-run
      stderr.writeLine "validating..."
      let valResult = nftValidate(text)
      if not valResult.success:
        stderr.writeLine "error: nftables validation failed:"
        stderr.writeLine valResult.error
        quit(1)

      # Run pre_start hook
      if state.hooks.preStart != "":
        stderr.writeLine "running pre_start hook..."
        let hookResult = execShellCmd(state.hooks.preStart)
        if hookResult != 0:
          stderr.writeLine "warning: pre_start hook exited with code " & $hookResult

      # Apply
      stderr.writeLine "applying..."
      let applyResult = nftApply(text)
      if not applyResult.success:
        stderr.writeLine "error: nftables apply failed:"
        stderr.writeLine applyResult.error
        quit(1)

      # Run post_start hook
      if state.hooks.postStart != "":
        stderr.writeLine "running post_start hook..."
        let hookResult = execShellCmd(state.hooks.postStart)
        if hookResult != 0:
          stderr.writeLine "warning: post_start hook exited with code " & $hookResult

      echo "ok: rules applied"
    except CatchableError as e:
      stderr.writeLine "error: " & e.msg
      quit(1)

  of "diff":
    try:
      let state = loadConfig(configFile)
      discard runValidation(state)
      let ruleset = buildRuleset(state)
      let generated = emitText(ruleset)

      # Get the running ruleset for our table
      let tn = state.config.tableName
      let currentFilter = nftListTable("inet", tn)
      let currentNat = nftListTable("inet", tn & "_nat")

      var running = ""
      if currentFilter.success:
        running &= currentFilter.output
      if currentNat.success:
        running &= currentNat.output

      if running == "":
        stderr.writeLine "note: no running matchstick tables found (table inet " & tn & ")"
        echo "--- (no running rules)"
        echo "+++ (generated)"
        echo generated
      else:
        # Write both to temp files and diff
        let tmpGen = getTempDir() / "matchstick-generated.nft"
        let tmpRun = getTempDir() / "matchstick-running.nft"
        writeFile(tmpGen, generated)
        writeFile(tmpRun, running)

        let diffCmd = "diff -u " & tmpRun & " " & tmpGen &
                      " --label running --label generated"
        let exitCode = execShellCmd(diffCmd)
        if exitCode == 0:
          echo "no differences"

        removeFile(tmpGen)
        removeFile(tmpRun)
    except CatchableError as e:
      stderr.writeLine "error: " & e.msg
      quit(1)

  else:
    stderr.writeLine "error: unknown command: " & command
    usage()

when isMainModule:
  main()
