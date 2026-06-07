## Static site generator — renders all pages to dist/
## Outputs directory-based URLs so /docs/ works on GitHub Pages.

import std/[os, strutils]
import ./pages/layout
import ./pages/home
import ./pages/docs
import ./pages/playground

const outDir = "dist"

proc writePage(dir, content: string) =
  let path = outDir / dir
  createDir(path)
  writeFile(path / "index.html", content)

proc main() =
  # Set base path from env or default for GitHub Pages
  basePath = getEnv("BASE_PATH", "/matchstick")
  removeDir(outDir)
  createDir(outDir)
  createDir(outDir / "static")

  # Pages — directory-based so /docs/ resolves to /docs/index.html
  writeFile(outDir / "index.html", homePage())
  writePage("docs", docsPage())
  writePage("playground", playgroundPage())

  # Static assets
  for f in walkDir("web/static"):
    if f.kind == pcFile:
      copyFile(f.path, outDir / "static" / f.path.extractFilename)

  # GitHub Pages needs .nojekyll to serve _ prefixed files
  writeFile(outDir / ".nojekyll", "")

  echo "static site built → " & outDir & "/"

when isMainModule:
  main()
