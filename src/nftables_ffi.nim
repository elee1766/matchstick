## nftables_ffi.nim - nftables interaction via the `nft` CLI.
##
## Shells out to the `nft` binary for validation and application.
## No library dependency -- just needs `nft` in PATH for apply/diff commands.
## render/check/show commands work without nft installed.

import std/[osproc, strutils]

type
  NftResult* = object
    success*: bool
    output*: string
    error*: string

proc findNft(): string =
  ## Find the nft binary. Returns empty string if not found.
  let (output, exitCode) = execCmdEx("which nft 2>/dev/null")
  if exitCode == 0:
    return output.strip()
  # Common paths
  for path in ["/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft"]:
    let (_, ec) = execCmdEx("test -x " & path)
    if ec == 0: return path
  return ""

proc ensureNft(): string =
  let nft = findNft()
  if nft == "":
    raise newException(CatchableError,
      "nft binary not found. Install nftables (e.g., apt install nftables) " &
      "or use 'matchstick render' to generate rules without applying them.")
  return nft

proc nftValidate*(ruleset: string): NftResult =
  ## Validate a text ruleset via `nft -c -f -` (dry-run, no root needed in netns).
  let nft = ensureNft()
  let (output, exitCode) = execCmdEx("echo " & quoteShell(ruleset) & " | " & nft & " -c -f - 2>&1")
  result.success = (exitCode == 0)
  if exitCode == 0:
    result.output = output
  else:
    result.error = output

proc nftApply*(ruleset: string): NftResult =
  ## Apply a text ruleset via `nft -f -`. Requires root.
  let nft = ensureNft()
  let (output, exitCode) = execCmdEx("echo " & quoteShell(ruleset) & " | " & nft & " -f - 2>&1")
  result.success = (exitCode == 0)
  if exitCode == 0:
    result.output = output
  else:
    result.error = output

proc nftListTable*(family, name: string): NftResult =
  ## List a specific table from the running ruleset.
  let nft = ensureNft()
  let cmd = nft & " list table " & family & " " & name & " 2>&1"
  let (output, exitCode) = execCmdEx(cmd)
  result.success = (exitCode == 0)
  if exitCode == 0:
    result.output = output
  else:
    result.error = output
