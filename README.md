# App — MemForge

The application workspace. MemForge is a single portable Windows `.exe` written in **C**, built with **CMake**, embedding **Lua 5.4** and **Zydis**. See the design doc at the repo root (`MemForge_Design_Document.md`) and `ARCHITECTURE.md` for the full picture.

Empty until Phase 1 starts — see the active exec plan in `docs/exec-plans/active/`.

## Intended layout (target — see `ARCHITECTURE.md`)

```
app/
  CMakeLists.txt        single memforge.exe target, static CRT, no runtime DLLs
  platform/             thin Win32 wrappers — the ONLY place that calls the Windows API
  core/                 engine, no console/UI calls
    process/            enumerate, attach, own the target handle
    memory/             bounded read/write/query/protect
    scanner/            value scan + iterative narrowing (Phase 2)
    address_table/      saved addresses + value locking (Phase 3)
    hexview/  disasm/  debugger/  injector/  pointer_scan/
    struct_dissector/  profiles/  speedhack/  lua_api/
  tui/                  console UI: sidebar, main panel, command palette
  vendor/               statically-linked deps (Lua 5.4, Zydis) — added when their phase lands
  test_target/          helper exe with known values, for validating scans/writes
```

## Boundaries (enforced — see `ARCHITECTURE.md`)

- Only `platform/` calls Win32 directly.
- `core/` must not call console/UI output — return data, let `tui/` render it.
- Lua scripts reach the engine only through `core/lua_api` (also the security boundary — see `docs/SECURITY.md`).
- No external runtime dependencies; everything vendored and statically linked to preserve the single-`.exe` goal.
