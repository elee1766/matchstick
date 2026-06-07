# Matchstick Agent Instructions

## Build & Test

```sh
nimble build              # debug build
nimble build -d:release   # release build (auto-detects musl-gcc for static linking)
nimble test               # all unit + integration tests
nim c -r tests/test_ir.nim          # single unit test
nim c -r tests/integration/test_render.nim  # single integration test
```

Integration tests shell out to the compiled `matchstick` binary — **`nimble build` must succeed before running them**.

The golden file test compares `tests/testdata/full.lua` output against `tests/testdata/full.expected.nft`. If you change build output, regenerate it:
```sh
./matchstick render tests/testdata/full.lua > tests/testdata/full.expected.nft
```

## Architecture

```
firewall.lua → Lua 5.4 VM (callbacks) → FirewallState → NftRuleset (IR) → text / JSON
```

| File | Role |
|------|------|
| `src/types.nim` | All domain types. Every new feature starts here. |
| `src/lua/api.nim` | Lua `fw:*` and `util:*` callbacks. Register new methods in `setupLuaVM` at the bottom. |
| `src/lua/helpers.nim` | Lua stack helpers, argument readers, `luaToJson` converter. |
| `src/lua/ffi.nim` | Raw Lua 5.4 C FFI. Compiles vendored sources via `{.compile:}`. |
| `src/build.nim` | Transforms `FirewallState` → `NftRuleset` IR. Core rule generation logic. |
| `src/nft_ir.nim` | Typed IR: `Expr` (18 variants), `Stmt` (19 variants), `NftCmd`. |
| `src/emit_text.nim` | IR → nftables text format. |
| `src/emit_json.nim` | IR → nftables JSON format. |
| `src/sysctl.nim` | Derives kernel sysctl settings from firewall config. |
| `src/validate.nim` | Post-parse validation and shadow detection. |
| `src/matchstick.nim` | CLI entry point and command dispatch. |

## Adding a Lua API method

1. Add type to `src/types.nim`
2. Add IR stmt/expr if needed in `src/nft_ir.nim`
3. Add `proc fwFoo(L: LuaState): cint {.cdecl.}` in `src/lua/api.nim`
4. Register it in `setupLuaVM` at the bottom of `src/lua/api.nim`
5. Emit it in `src/build.nim`
6. Handle new stmts in **both** `src/emit_text.nim` and `src/emit_json.nim`
7. **Update `contrib/luals/matchstick.lua`** — this is the LuaLS type stub for editor autocompletion. It must stay in sync with the Lua API surface.
8. Add test config in `tests/testdata/` and assertions in `tests/integration/`

## Key conventions

- `addr` is a Nim keyword — use `a` or another name for local address variables.
- Object variants are used everywhere (Expr, Stmt, NftChain, NftSet). JSON emitters need a case for each variant.
- `fw:raw_nft()` and `fw:chain()` rules use **nftables JSON** (Lua tables), not raw text strings. This ensures both text and JSON output work.
- `fw:sysctl(key, false)` unsets a derived sysctl (removes it from the set entirely).
- The `testdata/` at repo root is legacy; active test data is in `tests/testdata/`.

## Lua 5.4

Vendored in `vendor/lua54/src/`. Compiled from C sources directly — no system Lua dependency. `config.nims` sets the include path and `-DLUA_USE_POSIX`.
