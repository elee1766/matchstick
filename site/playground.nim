## WASM entry point for the playground.
## Exports loadAndRender() callable from JS via Module.ccall.

import std/[json, tables, sequtils, strutils]
import ../src/lua55/sandbox
import ../src/matchstickpkg/types
import ../src/matchstickpkg/build
import ../src/matchstickpkg/emit_text
import ../src/matchstickpkg/emit_json
import ../src/matchstickpkg/validate
import ../src/matchstickpkg/sysctl

const
  maxPlaygroundBytes = 64 * 1024
  playgroundInstructionLimit = 2_000_000
  playgroundMemoryLimit = 32 * 1024 * 1024  # 32 MB

proc loadAndRender(luaCode: cstring, format: cstring): cstring {.exportc, cdecl.} =
  let code = $luaCode
  let fmt = $format

  if code.len > maxPlaygroundBytes:
    return cstring($ %*{"error": "config is too large for the playground"})

  let result = runString(code, "playground.lua",
                         playgroundInstructionLimit, playgroundMemoryLimit)
  if result.error != "":
    return cstring($ %*{"error": result.error})

  let state = result.state
  let msgs = validate(state)
  var warnings: seq[string]
  for m in msgs:
    let prefix = if m.severity == svWarning: "warning" else: "error"
    warnings.add prefix & ": " & m.msg

  try:
    let output = case fmt
      of "json":
        emitJson(buildRuleset(state))
      of "sysctl":
        formatSysctls(deriveSysctls(state))
      of "check":
        var lines: seq[string]
        for w in warnings: lines.add w
        lines.add ""
        lines.add "zones:      " & $state.zones.len
        lines.add "hosts:      " & $state.hosts.len
        lines.add "services:   " & $state.services.len
        lines.add "policies:   " & $state.policies.len
        lines.add "rules:      " & $state.rules.len
        lines.add "sysctls:    " & $deriveSysctls(state).entries.len
        let hasErrors = warnings.anyIt(it.startsWith("error"))
        lines.add(if hasErrors: "\nFAIL" else: "\nok")
        lines.join("\n")
      else:
        emitText(buildRuleset(state))

    var resp = %*{"output": output}
    if warnings.len > 0:
      resp["warnings"] = %warnings
    return cstring($resp)
  except CatchableError as e:
    return cstring($ %*{"error": e.msg})
