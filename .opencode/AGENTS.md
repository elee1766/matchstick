# Matchstick Agent Instructions

## Project structure

Two user-facing tools:
- **`matchstick`** — the nftables compiler. Pure computation, no root, no nft binary, no runtime deps. Takes Lua configs, produces nftables JSON/text.
- **`msctl`** — the system manager. Shell script (`./msctl`) that wraps `matchstick` + `nft` for day-to-day firewall ops (enable, disable, status, diff, edit). Requires root and nft.

matchstick never touches the kernel. msctl is the only thing that calls `nft`.

## Build & Test

```sh
make                  # nimble build -d:release
make test             # all unit + integration tests
nim c -r tests/test_ir.nim          # single unit test
nim c -r tests/integration/test_render.nim  # single integration test
```

Integration tests shell out to the compiled `matchstick` binary -- **`make` must succeed before running them**.

Golden file: `tests/testdata/full.expected.nft`. Regenerate after build output changes:
```sh
./matchstick render tests/testdata/full.lua > tests/testdata/full.expected.nft
```

## Architecture

```
firewall.lua --> Lua VM (CFunction callbacks) --> FirewallState --> NftRuleset (IR) --> text / JSON
                     ^                                                    |
                     |--- lua_pcall boundary (sandbox.nim) ---------------|

msctl enable:  matchstick render --json | nft -j -f -
               matchstick show sysctl   | apply to /proc/sys/
```

| File | Role |
|------|------|
| `src/matchstick.nim` | CLI entry point and command dispatch. |
| `src/matchstickpkg/types.nim` | All domain types. New features start here. |
| `src/matchstickpkg/lua/api.nim` | Lua `fw:*` and `util:*` CFunction callbacks. Register new methods in `setupLuaVM`. |
| `src/matchstickpkg/lua/helpers.nim` | Lua stack helpers, argument readers, `luaToJson`. |
| `src/lua55/ffi.nim` | Raw Lua 5.5 C FFI. Compiles vendored C sources via `{.compile:}`. Sandbox setup. |
| `src/lua55/sandbox.nim` | **The only place `lua_pcall` is called.** Owns the Lua↔Nim safety boundary. |
| `src/matchstickpkg/build.nim` | Transforms `FirewallState` → `NftRuleset` IR. |
| `src/matchstickpkg/nft_ir.nim` | Typed IR: `Expr`, `Stmt`, `NftCmd` with constructor procs. |
| `src/matchstickpkg/emit_text.nim` | IR → nftables text. Includes `njtHandlers` table for raw JSON passthrough. |
| `src/matchstickpkg/emit_json.nim` | IR → nftables JSON (canonical machine format, used by msctl for apply). |
| `src/matchstickpkg/validate.nim` | Post-parse validation, shadow detection, IPv6 validation. |
| `src/matchstickpkg/sysctl.nim` | Derives sysctl settings (pure computation, msctl applies them). |
| `msctl` | Shell script — system manager. The only thing that calls `nft`. |

## Lua↔Nim boundary (CRITICAL)

`luaL_error` uses C `longjmp` which corrupts Nim's `TFrame` stack trace chain. The rules:

1. **CFunctions use `luaL_error` directly** -- this is correct. `lua_pcall` catches the longjmp.
2. **`sandbox.nim` saves/restores `getFrameState()`/`setFrameState()` around every `lua_pcall`** -- this repairs the corrupted frame chain after longjmp.
3. **`fwInclude` has its own inner `lua_pcall`** -- it also saves/restores frame state.
4. **NEVER raise a Nim exception after `lua_pcall` returns** -- the frame chain may be corrupt. Return errors as values (`LuaResult`).
5. **`config.nims` sets `--exceptions:goto`** -- avoids setjmp/longjmp exception handling that conflicts with Lua's longjmp.

If you add a new entry point that runs Lua code, use `sandbox.runConfig` or `sandbox.runString`. Do not call `lua_pcall` directly.

## Lua sandbox

`luaL_openlibs_safe` in `ffi.nim` loads a restricted set of Lua libraries. Removed from globals: `os`, `io`, `debug`, `package`, `require`, `load`, `loadfile`, `dofile`, `collectgarbage`, `rawget`, `rawset`, `rawequal`, `rawlen`, `getmetatable`, `setmetatable`, `string.dump`, `string.rep`.

`fw:sysctl()` is restricted to `net.ipv4/ipv6/core/bridge/netfilter` namespaces. `fw:hook()` and `fw:raw_nft()`/`fw:chain()` require `--allow-hooks` / `--allow-raw-nft` CLI flags.

Memory is capped via custom allocator (`luaL_newstate_limited`). Instruction count is capped via `lua_sethook`.

## Adding a Lua API method

1. Add type to `types.nim`
2. Add IR stmt/expr if needed in `nft_ir.nim`
3. Add `proc fwFoo(L: LuaState): cint {.cdecl.}` in `lua/api.nim`
4. Register it in `setupLuaVM` at the bottom of `lua/api.nim`
5. Build rules in `build.nim`
6. Emit in **both** `emit_text.nim` and `emit_json.nim`
7. Update `contrib/luals/matchstick.lua` (LuaLS type stub for editor autocompletion)
8. Add validation in `validate.nim` if needed
9. Add test config in `tests/testdata/` and assertions in `tests/integration/`

## Key conventions

- `addr` is a Nim keyword -- use different names for address variables.
- `nftJsonToText` in `emit_text.nim` uses a handler table (`njtHandlers`) for JSON-to-text conversion. Add new nftables JSON types there.
- `build.nim` uses `addrFamilies` (an `AfDesc` seq) to iterate over IPv4/IPv6 instead of `if dualStack` branching.
- Atomic table replacement in the IR: `addTable → deleteTable → addTable → chains/sets/rules`. The reorder logic in `buildRuleset` ensures this sequence.
- The `site/` directory is plain HTML for GitHub Pages. The WASM playground (`site/playground.nim`) is the only Nim code there, built separately via `nimble wasm`.
- matchstick has zero runtime dependencies. msctl requires `nft` (nftables).
- `make` then `sudo make install` works correctly -- make builds as user, install only copies files.

## Lua 5.5

Vendored in `vendor/lua55/src/`. Compiled from C sources directly -- no system Lua dependency. `config.nims` sets the include path and `-DLUA_USE_POSIX`.
