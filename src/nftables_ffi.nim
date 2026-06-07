## nftables_ffi.nim - nftables interaction via the `nft` CLI.
##
## Uses execProcess with explicit argument arrays -- no shell interpolation.
## render/check/show commands work without nft installed.

import std/[osproc, os, tempfiles, streams]

type
  NftResult* = object
    success*: bool
    output*: string
    error*: string

proc findNft(): string =
  let path = findExe("nft")
  if path != "": return path
  for p in ["/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft"]:
    if fileExists(p): return p
  return ""

proc ensureNft(): string =
  let nft = findNft()
  if nft == "":
    raise newException(CatchableError,
      "nft binary not found. Install nftables (e.g., apt install nftables) " &
      "or use 'matchstick render' to generate rules without applying them.")
  return nft

proc nftRunWithFile(args: seq[string], ruleset: string): NftResult =
  ## Write ruleset to temp file and run nft with given args + file path.
  let nft = ensureNft()
  let (tmpFile, tmpPath) = createTempFile("matchstick_", ".nft")
  tmpFile.write(ruleset)
  tmpFile.close()
  defer: removeFile(tmpPath)
  let p = startProcess(nft, args = args & @[tmpPath],
                       options = {poUsePath, poStdErrToStdOut})
  let output = p.outputStream.readAll()
  let exitCode = p.waitForExit()
  p.close()
  result.success = (exitCode == 0)
  if exitCode == 0:
    result.output = output
  else:
    result.error = output

proc nftValidate*(ruleset: string): NftResult =
  ## Validate a text ruleset via `nft -c -f <tmpfile>` (dry-run).
  nftRunWithFile(@["-c", "-f"], ruleset)

proc nftApply*(ruleset: string): NftResult =
  ## Apply a text ruleset via `nft -f <tmpfile>`. Requires root.
  nftRunWithFile(@["-f"], ruleset)

proc nftListTable*(family, name: string): NftResult =
  ## List a specific table from the running ruleset.
  ## Uses execProcess with argument array -- no shell interpolation.
  let nft = ensureNft()
  let p = startProcess(nft, args = @["list", "table", family, name],
                       options = {poUsePath, poStdErrToStdOut})
  let output = p.outputStream.readAll()
  let exitCode = p.waitForExit()
  p.close()
  result.success = (exitCode == 0)
  if exitCode == 0:
    result.output = output
  else:
    result.error = output
