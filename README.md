# Poker Night Lua Hook via dinput8 Proxy Architecture

## How the DLL Gets Loaded

`CelebrityPoker.exe` imports `DINPUT8.dll` from its PE import table but ships no local copy, Windows normally resolves it from `C:\Windows\System32\dinput8.dll`. `dinput8.dll` is **not** in the Windows KnownDLLs registry list (`HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`), so a same-named DLL in the game folder takes precedence.

This DLL hijacking technique requires no special privileges and modifies no game files.

---

## Source Files

| File | Purpose |
|---|---|
| `TychosLuaHook/dinput8_proxy.c` | Single source file |
| `TychosLuaHook/Makefile` | Build rules for `dinput8.dll` |
| `TychosLuaHook/lua/src/` | Lua 5.2.3 source (bundled into the DLL) |

Build output: `TychosLuaHook/dinput8.dll` → copy to game folder.

---

## Build Instructions

Requirements:
- `x86_64-w64-mingw32-gcc` (MinGW-w64 cross-compiler)
- Lua 5.2.3 source extracted to `TychosLuaHook/lua/` (so `lua/src/lua.h` exists)

```bash
cd TychosLuaHook
make
```

---

## Installation

1. Build `dinput8.dll` (see above)
2. Copy `dinput8.dll` to the game folder (where `CelebrityPoker.exe` lives)
3. Launch the game, a console window opens automatically

**Rollback**: delete `dinput8.dll` from the game folder. No other files are changed.

---

## DLL Internals

### Thread Model

```
DllMain (loader thread)
└── CreateThread → worker_thread
    ├── Sleep(500ms)              let DllMain return before doing work
    ├── scan_for_lua_state()      retries every 500ms for up to 15s (30 attempts)
    ├── lua_sethook(count_hook, LUA_MASKCOUNT, 100)
    └── console_repl()            blocking REPL loop on this thread
        ├── AllocConsole()
        ├── ShowWindow / SetForegroundWindow   force visible on Windows 11
        ├── freopen("CONIN$", "r", stdin)
        ├── freopen("CONOUT$", "w", stdout)
        └── fgets loop

count_hook (game's Lua thread, every 100 VM instructions)
    increments g_hook_heartbeat, then if g_code_pending:
    walks call stack for _ENV, executes, writes g_result, sets g_result_ready
```

### Export Forwarding

The DLL exposes all 5 `dinput8.dll` exports as thin trampolines:

| Export | Notes |
|---|---|
| `DirectInput8Create` | Called by the game to initialise DirectInput |
| `DllCanUnloadNow` | COM server protocol |
| `DllGetClassObject` | COM server protocol |
| `DllRegisterServer` | COM registration (game doesn't call this) |
| `DllUnregisterServer` | COM registration (game doesn't call this) |

The real `C:\Windows\System32\dinput8.dll` is loaded by full absolute path at the top of `DllMain(DLL_PROCESS_ATTACH)` before the worker thread spawns. All 5 function pointers are stored globally. If the load fails, `DllMain` returns `FALSE` and the game will not start.

**Why runtime loading instead of .def forwarding**: GNU ld does not support absolute paths in `.def` export forwarding directives, and relative forwarding would recurse back into our proxy DLL.

---

## Finding the Lua State

`CelebrityPoker.exe` embeds a Lua 5.2.3 interpreter. The `lua_State*` is stored somewhere in the game's writable data sections but its address is not exported.

`scan_for_lua_state()` walks all writable, non-executable PE sections of the game image and tests each 8-byte-aligned pointer against the `lua_State` struct layout. Because the game initialises its Lua VM some time after the DLL loads, the worker thread retries the scan every 500ms for up to 15 seconds (30 attempts) before giving up.

| Offset | Field | Validation |
|---|---|---|
| 8 | `tt` (type tag) | Must be `LUA_TTHREAD` (8) |
| 10 | `status` | Must be 0–5 |
| 24 | `l_G` (global_State*) | Non-NULL, VirtualQuery → writable |
| 32 | `ci` (CallInfo*) | Non-NULL, VirtualQuery → committed |
| 56 | `stack` | Non-NULL, readable |
| 64 | `stacksize` | 20–65536 |
| 16 | `top` | `stack ≤ top ≤ stack + stacksize*16` |

This layout is confirmed compatible with the game's Lua version (see `documentation/lua_injection_findings.md`).

---

## Executing Lua Code

### The Hook Mechanism

Direct calls into the Lua VM from a background thread crash because the Lua VM is not thread-safe. Instead:

1. The REPL thread writes the code string to `g_pending_code` and sets `g_code_pending = 1` (with `MemoryBarrier` for ordering).
2. `count_hook` fires on the **game's own Lua thread** every 100 VM instructions. When it sees `g_code_pending`, it compiles and executes the code, writes the result to `g_result`, and sets `g_result_ready = 1`.
3. The REPL thread spins (up to 5 seconds) waiting for `g_result_ready`.

This eliminates the need for `SuspendThread` and avoids all VM thread-safety issues.

### _ENV Inheritance

Telltale runs game scripts in a sandboxed `_ENV` table, not in `_G`. `luaL_loadstring` sets the chunk's `_ENV` to `_G` by default, so game globals (`GameObject`, `kPlayer_Player`, etc.) would be invisible.

Fix: `count_hook` walks up to 5 levels of the Lua call stack looking for the innermost frame whose first upvalue is named `_ENV`, then replaces the compiled chunk's `_ENV` with that value before calling `lua_pcall`. Walking the stack (rather than always using level 1) is necessary because the game sometimes interposes callback wrapper frames — e.g. a frame whose first upvalue is `bRunningCallbacks` — between the hook firing point and the outer game chunk that actually holds `_ENV`. If no `_ENV` is found anywhere in the stack, execution proceeds with `_G`; commands guarded by `if GameObject then` no-op safely in that case.

### Hook Loss Recovery

When a new poker game starts, the game re-initialises its Lua state, clearing any installed hook. `exec_lua()` detects this via a 5-second timeout and needs to distinguish two failure modes:

- **Hook truly lost** (heartbeat unchanged during the wait): the hook stopped firing entirely — the `lua_State` was reset. `exec_lua()` calls `rescan_and_rehook()`, which rescans memory for the new `lua_State*`, reinstalls the hook, and returns `ERR: hook lost; reconnected -- retry`. The user retries the command once.
- **Hook alive but context-busy** (heartbeat advancing but no result): the hook is firing on every invocation but the call stack currently has no `_ENV`-bearing frame to execute against. `exec_lua()` returns `ERR: hook busy (wrong context); retry shortly` without triggering a rescan.

`g_hook_heartbeat` is a `volatile LONG` incremented on every hook invocation regardless of whether a command is pending. It is only ever compared across a ~5-second window, so integer overflow is not a concern.

The `rehook` REPL command forces an immediate rescan without waiting for a timeout.

---

## Critical Gotchas (Telltale Lua Compatibility)

### TValue Layout Mismatch

**This is the most important issue.** Telltale's Lua 5.2.3 has a reordered `TValue` struct (type tag before value, rather than after). Our compiled Lua 5.2.3 uses the standard layout. Consequences:

1. **Numeric literals passed to game C functions arrive as 0.**
   - Wrong: `p:SetChips(1000000)`
   - Correct: `p:SetChips(tonumber("1000000"))` pass as string, let Telltale's `tonumber` produce a correctly-laid-out TValue.

2. **Numbers fetched from game tables cannot be used as keys in table lookups from our code.**
   - Wrong: `Card.RANK_STRINGS[card[1]]` → always nil
   - Correct: `tostring(card[1])` → string-keyed lookup in a locally-defined table

3. **`tostring()` of numbers from our compiled code returns `"0"`.**
   - Wrong: `return tostring(1+1)`
   - Correct: `return tostring(someGameValue)` only works for values already on the game's stack

**Unaffected**: string values, booleans, nil, array-part table access (`cardList[1]` via direct offset), `pairs()` iteration, string equality.

### `GetPlayer()` Returns nil

`GameObject:GetTable():GetPlayer(kPlayer_Player)` is not supported in the remaster. Use `GetPlayers()` with `pairs()` and match by name:
```lua
for i, p in pairs(GameObject:GetTable():GetPlayers()) do
    if p:GetName() == "Player" then ... end
end
```

### `GetPlayers()` is a Proxy Table

`#GetPlayers()` returns 0. Always iterate with `pairs()`. Integer keys 1–5 are the five players: `[1]=Max [2]=Strongbad [3]=Heavy [4]=Tycho [5]=Player`.

### `CardContainer:Get(n)` Does Not Work

`p:GetHoleCards().cardList[1]` works (array-part direct access). `p:GetHoleCards():Get(1)` does not (TValue argument mismatch the index arrives as 0).

### Telltale's `error()` is a No-Op

`error("anything")` returns `LUA_OK` with nothing on the stack. Use `return tostring(x)` for diagnostics, never `error(tostring(x))`.

---

## REPL Commands

All commands are expanded by `expand_command()` into Lua strings before being submitted to `exec_lua()`.

| Command | Lua Expansion |
|---|---|
| `setchips <n> [name]` | Iterates `GetPlayers()`, finds player by name, calls `SetChips(tonumber("<n>"))` + `UpdateChipUI()` |
| `revealhands` | Iterates all non-Player players, reads `GetHoleCards().cardList[1/2]`, formats rank+suit via string-keyed tables |
| `forcefold <name>` | Finds player by name, calls `p:Fold()` behaviour in the remaster is unpredictable |
| `rehook` | Calls `rescan_and_rehook()` directly (not via exec_lua) |
| `help` | Prints command list locally |
| `exit` | Exits the REPL loop |
| anything else | Sent as raw Lua to `exec_lua()` |

---

## Log File

`dinput8_proxy.log` is written to the same directory as `dinput8.dll` (the game folder). It records:
- DLL load confirmation and PID
- Memory scan progress (section names, addresses)
- `lua_State*` found/not-found result
- Hook installation confirmation
- Hook recovery events (rescan attempts, results)
- Lua compile and runtime errors

