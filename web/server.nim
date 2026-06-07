## matchstick web server — Mummy + Karax SSR

import std/[json, os, strutils, tables, options, tempfiles]
import mummy, mummy/routers
import ../src/lua54/ffi
import ../src/matchstickpkg/types
import ../src/matchstickpkg/lua/api
import ../src/matchstickpkg/build
import ../src/matchstickpkg/emit_text
import ../src/matchstickpkg/emit_json
import ../src/matchstickpkg/validate
import ../src/matchstickpkg/sysctl

import ./pages/home
import ./pages/docs
import ./pages/playground

# ---------------------------------------------------------------------------
# API: compile Lua config string → nftables output
# ---------------------------------------------------------------------------

proc loadConfigFromString(luaCode: string): FirewallState =
  let L = luaL_newstate()
  if L == nil:
    raise newException(CatchableError, "failed to create Lua state")
  defer: lua_close(L)

  luaL_openlibs(L)

  let state = newFirewallState()

  # Write config to temp file (luaL_loadfile needs a path)
  let (tmpFile, tmpPath) = createTempFile("matchstick_web_", ".lua")
  tmpFile.write(luaCode)
  tmpFile.close()
  defer: removeFile(tmpPath)

  setupLuaVM(L, state, tmpPath)

  var status = luaL_loadfile(L, tmpPath.cstring)
  if status != LUA_OK:
    let msg = $lua_tostring(L, -1)
    raise newException(CatchableError, msg)

  status = lua_pcall(L, 0, 0, 0)
  if status != LUA_OK:
    let msg = $lua_tostring(L, -1)
    raise newException(CatchableError, msg)

  return state

proc apiRender(request: Request) =
  var headers: HttpHeaders
  headers["Content-Type"] = "application/json"
  headers["Cache-Control"] = "no-store"

  try:
    let body = parseJson(request.body)
    let config = body["config"].getStr()
    let format = body.getOrDefault("format").getStr("text")

    let state = loadConfigFromString(config)

    let msgs = validate(state)
    var warnings: seq[string]
    for m in msgs:
      if m.severity == svWarning:
        warnings.add m.msg

    let output = case format
      of "json":
        let ruleset = buildRuleset(state)
        emitJson(ruleset)
      of "sysctl":
        let sysctls = deriveSysctls(state)
        formatSysctls(sysctls)
      else:
        let ruleset = buildRuleset(state)
        emitText(ruleset)

    var resp = %*{"output": output}
    if warnings.len > 0:
      resp["warnings"] = %warnings
    request.respond(200, headers, $resp)

  except CatchableError as e:
    request.respond(200, headers, $ %*{"error": e.msg})

proc apiCheck(request: Request) =
  var headers: HttpHeaders
  headers["Content-Type"] = "application/json"
  headers["Cache-Control"] = "no-store"

  try:
    let body = parseJson(request.body)
    let config = body["config"].getStr()

    let state = loadConfigFromString(config)
    let msgs = validate(state)

    var lines: seq[string]
    var hasErrors = false
    for m in msgs:
      let prefix = case m.severity
        of svWarning: "warning"
        of svError: "error"
      lines.add prefix & ": " & m.msg
      if m.severity == svError:
        hasErrors = true

    lines.add ""
    lines.add "zones:      " & $state.zones.len
    lines.add "hosts:      " & $state.hosts.len
    lines.add "services:   " & $state.services.len
    lines.add "policies:   " & $state.policies.len
    lines.add "rules:      " & $state.rules.len
    lines.add "dnat:       " & $state.dnatRules.len
    lines.add "snat:       " & $state.snatRules.len

    let sysctls = deriveSysctls(state)
    lines.add "sysctls:    " & $sysctls.entries.len

    if hasErrors:
      lines.add ""
      lines.add "FAIL: config has errors"
    else:
      lines.add ""
      lines.add "ok"

    request.respond(200, headers, $ %*{"output": lines.join("\n")})

  except CatchableError as e:
    request.respond(200, headers, $ %*{"error": e.msg})

# ---------------------------------------------------------------------------
# Static pages (cacheable)
# ---------------------------------------------------------------------------

proc serveStatic(request: Request, content: string, contentType = "text/html") {.gcsafe.} =
  var headers: HttpHeaders
  headers["Content-Type"] = contentType & "; charset=utf-8"
  headers["Cache-Control"] = "public, max-age=3600"
  request.respond(200, headers, content)

proc staticFile(request: Request) =
  let path = "web/static" / request.uri.replace("/static/", "")
  if not fileExists(path):
    request.respond(404)
    return
  let ext = path.splitFile().ext
  let ct = case ext
    of ".css": "text/css"
    of ".js": "application/javascript"
    of ".svg": "image/svg+xml"
    of ".png": "image/png"
    of ".ico": "image/x-icon"
    else: "application/octet-stream"
  var headers: HttpHeaders
  headers["Content-Type"] = ct
  headers["Cache-Control"] = "public, max-age=86400"
  request.respond(200, headers, readFile(path))

# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

initExamples()

# Pre-render pages (before Mummy starts threads)
var cachedHome {.global.} = ""
var cachedDocs {.global.} = ""
var cachedPlayground {.global.} = ""
cachedHome = homePage()
cachedDocs = docsPage()
cachedPlayground = playgroundPage()

proc serveCachedHome(request: Request) =
  {.cast(gcsafe).}: serveStatic(request, cachedHome)
proc serveCachedDocs(request: Request) =
  {.cast(gcsafe).}: serveStatic(request, cachedDocs)
proc serveCachedPlayground(request: Request) =
  {.cast(gcsafe).}: serveStatic(request, cachedPlayground)

var router: Router
router.addRoute("GET", "/", serveCachedHome)
router.addRoute("GET", "/docs", serveCachedDocs)
router.addRoute("GET", "/docs/", serveCachedDocs)
router.addRoute("GET", "/playground", serveCachedPlayground)
router.addRoute("GET", "/playground/", serveCachedPlayground)
router.addRoute("GET", "/static/*", staticFile)
router.addRoute("POST", "/api/render", apiRender)
router.addRoute("POST", "/api/check", apiCheck)

let port = parseInt(getEnv("PORT", "8080"))
echo "matchstick web server listening on http://localhost:" & $port
let server = newServer(router.toHandler())
server.serve(Port(port))
