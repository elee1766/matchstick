## nftables_ffi.nim - libnftables C FFI bindings.
##
## Dynamically links against libnftables.so for in-process validation
## and application of nftables rulesets.
##
## libnftables is only needed for `apply` and `check --validate` commands.
## The render/show commands work without it.

const
  NFT_CTX_OUTPUT_REVERSEDNS* = (1 shl 0).cuint
  NFT_CTX_OUTPUT_SERVICE*    = (1 shl 1).cuint
  NFT_CTX_OUTPUT_STATELESS*  = (1 shl 2).cuint
  NFT_CTX_OUTPUT_HANDLE*     = (1 shl 3).cuint
  NFT_CTX_OUTPUT_JSON*       = (1 shl 4).cuint
  NFT_CTX_OUTPUT_ECHO*       = (1 shl 5).cuint
  NFT_CTX_OUTPUT_GUID*       = (1 shl 6).cuint
  NFT_CTX_OUTPUT_NUMERIC_PROTO* = (1 shl 7).cuint
  NFT_CTX_OUTPUT_NUMERIC_PRIO* = (1 shl 8).cuint
  NFT_CTX_OUTPUT_NUMERIC_SYMBOL* = (1 shl 9).cuint
  NFT_CTX_OUTPUT_NUMERIC_TIME*  = (1 shl 10).cuint
  NFT_CTX_OUTPUT_NUMERIC_ALL*   = (NFT_CTX_OUTPUT_NUMERIC_PROTO.int or
                                   NFT_CTX_OUTPUT_NUMERIC_PRIO.int or
                                   NFT_CTX_OUTPUT_NUMERIC_SYMBOL.int or
                                   NFT_CTX_OUTPUT_NUMERIC_TIME.int).cuint
  NFT_CTX_OUTPUT_TERSE*      = (1 shl 11).cuint

  NFT_CTX_INPUT_NO_DNS*   = (1 shl 0).cuint
  NFT_CTX_INPUT_JSON*     = (1 shl 1).cuint

# Link against libnftables dynamically
{.passl: "-lnftables".}

type
  NftCtx* = pointer  ## Opaque nft_ctx*

proc nft_ctx_new*(flags: cuint): NftCtx {.importc, cdecl.}
proc nft_ctx_free*(ctx: NftCtx) {.importc, cdecl.}
proc nft_ctx_set_dry_run*(ctx: NftCtx, dry_run: bool) {.importc, cdecl.}
proc nft_ctx_output_get_flags*(ctx: NftCtx): cuint {.importc, cdecl.}
proc nft_ctx_output_set_flags*(ctx: NftCtx, flags: cuint) {.importc, cdecl.}
proc nft_ctx_input_get_flags*(ctx: NftCtx): cuint {.importc, cdecl.}
proc nft_ctx_input_set_flags*(ctx: NftCtx, flags: cuint) {.importc, cdecl.}
proc nft_ctx_buffer_output*(ctx: NftCtx): cint {.importc, cdecl.}
proc nft_ctx_buffer_error*(ctx: NftCtx): cint {.importc, cdecl.}
proc nft_ctx_get_output_buffer*(ctx: NftCtx): cstring {.importc, cdecl.}
proc nft_ctx_get_error_buffer*(ctx: NftCtx): cstring {.importc, cdecl.}
proc nft_run_cmd_from_buffer*(ctx: NftCtx, buf: cstring): cint {.importc, cdecl.}
proc nft_run_cmd_from_filename*(ctx: NftCtx, filename: cstring): cint {.importc, cdecl.}

# ---------------------------------------------------------------------------
# High-level Nim wrappers
# ---------------------------------------------------------------------------

type
  NftResult* = object
    success*: bool
    output*: string
    error*: string

proc runNft(cmd: string, dryRun = false, jsonInput = false): NftResult =
  ## Run an nftables command via libnftables, returning output and errors.
  let ctx = nft_ctx_new(0)
  if ctx == nil:
    return NftResult(success: false, error: "failed to create nft context")
  defer: nft_ctx_free(ctx)

  if dryRun: nft_ctx_set_dry_run(ctx, true)
  if jsonInput: nft_ctx_input_set_flags(ctx, NFT_CTX_INPUT_JSON)
  discard nft_ctx_buffer_output(ctx)
  discard nft_ctx_buffer_error(ctx)

  let rc = nft_run_cmd_from_buffer(ctx, cmd.cstring)
  result.success = (rc == 0)
  result.output = $nft_ctx_get_output_buffer(ctx)
  result.error = $nft_ctx_get_error_buffer(ctx)

proc nftValidate*(ruleset: string): NftResult =
  ## Validate an nftables ruleset (text format) via dry-run.
  runNft(ruleset, dryRun = true)

proc nftApply*(ruleset: string): NftResult =
  ## Apply an nftables ruleset (text format) to the kernel. Requires root.
  runNft(ruleset)

proc nftListTable*(family, name: string): NftResult =
  ## List a specific nftables table.
  runNft("list table " & family & " " & name)
