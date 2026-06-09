## matchstick web server — Mummy + Karax SSR

import std/[os, strutils]
import mummy, mummy/routers

import ./pages/home
import ./pages/docs
import ./pages/playground

# ---------------------------------------------------------------------------
# Static pages (pre-rendered at startup)
# ---------------------------------------------------------------------------

proc serveStatic(request: Request, content: string, contentType = "text/html") {.gcsafe.} =
  var headers: HttpHeaders
  headers["Content-Type"] = contentType & "; charset=utf-8"
  headers["Cache-Control"] = "public, max-age=3600"
  request.respond(200, headers, content)

# Pre-render pages before threads start
import ./pages/docs as docsmod
docsmod.initExamples()

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

proc staticFile(request: Request) =
  let relPath = request.uri.replace("/static/", "")
  if ".." in relPath or relPath.startsWith("/"):
    request.respond(403)
    return
  let path = "web/static" / relPath
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
    of ".txt": "text/plain"
    of ".wasm": "application/wasm"
    else: "application/octet-stream"
  var headers: HttpHeaders
  headers["Content-Type"] = ct
  headers["Cache-Control"] = "public, max-age=86400"
  request.respond(200, headers, readFile(path))

# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

var router: Router
router.addRoute("GET", "/", serveCachedHome)
router.addRoute("GET", "/docs", serveCachedDocs)
router.addRoute("GET", "/docs/", serveCachedDocs)
router.addRoute("GET", "/playground", serveCachedPlayground)
router.addRoute("GET", "/playground/", serveCachedPlayground)
router.addRoute("GET", "/static/*", staticFile)

let port = parseInt(getEnv("PORT", "8888"))
echo "matchstick web server listening on http://localhost:" & $port
let server = newServer(router.toHandler())
server.serve(Port(port))
