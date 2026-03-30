/*
 * dinput8_proxy.c — dinput8.dll proxy for Poker Night at the Inventory (2026 Skunkape remaster)
 *
 * This DLL is placed in the game folder. CelebrityPoker.exe imports DINPUT8.dll but ships
 * without a local copy — Windows resolves it from System32. Because dinput8.dll is not in
 * the KnownDLLs registry list, a same-named DLL in the game folder loads first.
 *
 * All 5 dinput8.dll exports are forwarded to the real C:\Windows\System32\dinput8.dll via
 * runtime LoadLibrary + GetProcAddress (not linker forwarding — GNU ld doesn't support
 * absolute paths in export forwarding directives).
 *
 * On DLL_PROCESS_ATTACH a worker thread is spawned that:
 *   1. Scans the game's writable data sections for the embedded lua_State*.
 *   2. Installs a Lua count hook (fires every 100 VM instructions on the game's thread).
 *   3. Opens a Win32 console window via AllocConsole().
 *   4. Runs an interactive REPL for sending commands to the Lua VM in-process.
 *
 * No injection, no separate executable, no named pipe.
 *
 * Build: see Makefile — requires Lua 5.2.3 source at lua_injector/lua/src/
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <imagehlp.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include "lua.h"
#include "lauxlib.h"

/* -------------------------------------------------------------------------
 * dinput8 proxy — real DLL handle and trampoline function pointers
 *
 * Loaded at the top of DllMain(DLL_PROCESS_ATTACH) by full absolute path.
 * All 5 exports forward through these pointers.
 * ---------------------------------------------------------------------- */

static HMODULE g_real_dinput8 = NULL;

typedef HRESULT (WINAPI *PFN_DirectInput8Create)(HINSTANCE, DWORD, const void *, void **, void *);
typedef HRESULT (WINAPI *PFN_DllCanUnloadNow)(void);
typedef HRESULT (WINAPI *PFN_DllGetClassObject)(const void *, const void *, void **);
typedef HRESULT (WINAPI *PFN_DllRegisterServer)(void);
typedef HRESULT (WINAPI *PFN_DllUnregisterServer)(void);

static PFN_DirectInput8Create  fp_DirectInput8Create  = NULL;
static PFN_DllCanUnloadNow     fp_DllCanUnloadNow     = NULL;
static PFN_DllGetClassObject   fp_DllGetClassObject   = NULL;
static PFN_DllRegisterServer   fp_DllRegisterServer   = NULL;
static PFN_DllUnregisterServer fp_DllUnregisterServer = NULL;

/* -------------------------------------------------------------------------
 * Module-level state
 * ---------------------------------------------------------------------- */

static lua_State *g_L = NULL;           /* found by scan_for_lua_state()      */
static char g_log_path[MAX_PATH];       /* absolute path to dinput8_proxy.log */

/* Shared between REPL thread (writer) and Lua hook (reader/writer).
   Protocol: REPL thread writes g_pending_code, MemoryBarrier,
   InterlockedExchange(&g_code_pending,1).  Hook reads g_code_pending,
   MemoryBarrier, reads g_pending_code, executes, writes g_result,
   MemoryBarrier, InterlockedExchange(&g_result_ready,1).  REPL thread
   loops on g_result_ready, MemoryBarrier, then reads g_result.

   The buffers are volatile to prevent the compiler caching their contents
   across the flag operations.  MemoryBarrier() / InterlockedExchange()
   provide the required store-release / load-acquire ordering on x86-64. */
static volatile LONG g_code_pending = 0;
static volatile char g_pending_code[1024];
static volatile LONG g_result_ready  = 0;
static volatile char g_result[1024];

/* -------------------------------------------------------------------------
 * Logging — writes to dinput8_proxy.log next to dinput8.dll
 * ---------------------------------------------------------------------- */

static void log_write(const char *fmt, ...) {
    if (!g_log_path[0]) return;
    FILE *f = fopen(g_log_path, "a");
    if (!f) return;
    va_list args;
    va_start(args, fmt);
    vfprintf(f, fmt, args);
    va_end(args);
    fputs("\n", f);
    fclose(f);
}

/* -------------------------------------------------------------------------
 * lua_State pattern scanner
 *
 * Lua 5.2.3 lua_State memory layout (x86-64 Windows ABI):
 *
 *   offset  0   GCObject *next      (8 bytes)
 *   offset  8   lu_byte tt          (1 byte)  — must be LUA_TTHREAD (8)
 *   offset  9   lu_byte marked      (1 byte)
 *   offset 10   lu_byte status      (1 byte)  — 0-5
 *   offset 11   (5 bytes padding to align next 8-byte field)
 *   offset 16   StkId top           (8 bytes)
 *   offset 24   global_State *l_G   (8 bytes) — non-NULL, writable
 *   offset 32   CallInfo *ci        (8 bytes) — non-NULL, readable
 *   offset 56   StkId stack         (8 bytes) — non-NULL, readable
 *   offset 64   int stacksize       (4 bytes) — 20..65536
 *
 * We scan all writable non-executable sections of the game image.
 * ---------------------------------------------------------------------- */

#define LUA_TTHREAD 8

static int is_valid_lua_state(void *ptr) {
    if (!ptr || (ULONG_PTR)ptr < 0x10000) return 0;

    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery(ptr, &mbi, sizeof(mbi))) return 0;
    if (mbi.State != MEM_COMMIT) return 0;
    DWORD prot = mbi.Protect & ~(PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE);
    if (!(prot & (PAGE_READWRITE | PAGE_WRITECOPY |
                  PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) return 0;

    /* Need at least 72 bytes for all the fields we check */
    if ((ULONG_PTR)ptr + 72 > (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize) return 0;

    unsigned char *b = (unsigned char *)ptr;

    /* tt must be LUA_TTHREAD */
    if (b[8] != LUA_TTHREAD) return 0;

    /* status: LUA_OK(0) .. LUA_ERRGCMM(5) */
    if (b[10] > 5) return 0;

    /* l_G at offset 24: non-NULL, writable (GC writes into it) */
    void *l_G;
    memcpy(&l_G, b + 24, sizeof(void *));
    if (!l_G || (ULONG_PTR)l_G < 0x10000) return 0;
    MEMORY_BASIC_INFORMATION mbi2;
    if (!VirtualQuery(l_G, &mbi2, sizeof(mbi2))) return 0;
    if (mbi2.State != MEM_COMMIT) return 0;
    DWORD prot2 = mbi2.Protect & ~(PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE);
    if (!(prot2 & (PAGE_READWRITE | PAGE_WRITECOPY |
                   PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) return 0;

    /* ci at offset 32: non-NULL, readable */
    void *ci;
    memcpy(&ci, b + 32, sizeof(void *));
    if (!ci || (ULONG_PTR)ci < 0x10000) return 0;
    MEMORY_BASIC_INFORMATION mbi3;
    if (!VirtualQuery(ci, &mbi3, sizeof(mbi3))) return 0;
    if (mbi3.State != MEM_COMMIT) return 0;

    /* stack at offset 56: non-NULL, readable */
    void *stack;
    memcpy(&stack, b + 56, sizeof(void *));
    if (!stack || (ULONG_PTR)stack < 0x10000) return 0;

    /* stacksize at offset 64: sanity range 20..65536 */
    int stacksize;
    memcpy(&stacksize, b + 64, sizeof(int));
    if (stacksize < 20 || stacksize > 65536) return 0;

    /* top at offset 16 must be >= stack and <= stack + stacksize*16 */
    void *top;
    memcpy(&top, b + 16, sizeof(void *));
    if ((ULONG_PTR)top < (ULONG_PTR)stack) return 0;
    if ((ULONG_PTR)top > (ULONG_PTR)stack + (ULONG_PTR)stacksize * 16) return 0;

    return 1;
}

static void scan_for_lua_state(void) {
    HMODULE hMod = GetModuleHandle(NULL);
    ULONG_PTR base = (ULONG_PTR)hMod;

    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) { log_write("[scan] bad DOS magic"); return; }
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) { log_write("[scan] bad NT signature"); return; }

    int nsec = nt->FileHeader.NumberOfSections;
    IMAGE_SECTION_HEADER *sections = IMAGE_FIRST_SECTION(nt);
    log_write("[scan] image base 0x%llx, %d sections", (unsigned long long)base, nsec);

    for (int i = 0; i < nsec && !g_L; i++) {
        DWORD chars = sections[i].Characteristics;
        if (!(chars & IMAGE_SCN_MEM_WRITE)) continue;   /* skip non-writable */
        if (chars & IMAGE_SCN_MEM_EXECUTE) continue;    /* skip code sections */

        ULONG_PTR sec_start = base + sections[i].VirtualAddress;
        DWORD sec_size = sections[i].Misc.VirtualSize;
        if (!sec_size) sec_size = sections[i].SizeOfRawData;

        char sname[9] = {0};
        memcpy(sname, sections[i].Name, 8);
        log_write("[scan] section '%s' at 0x%llx size 0x%lx",
                  sname, (unsigned long long)sec_start, (unsigned long)sec_size);

        for (ULONG_PTR addr = sec_start;
             addr + sizeof(void *) <= sec_start + sec_size && !g_L;
             addr += sizeof(void *)) {

            void *candidate = *(void **)addr;   /* safe: reading game's own mapped section */

            /* is_valid_lua_state validates all pointer fields with VirtualQuery
               before dereferencing them — sufficient protection for re-scan races. */
            if (is_valid_lua_state(candidate)) {
                g_L = (lua_State *)candidate;
                log_write("[scan] lua_State* FOUND: stored at 0x%llx -> 0x%llx",
                          (unsigned long long)addr,
                          (unsigned long long)(ULONG_PTR)candidate);
            }
        }
    }

    if (!g_L)
        log_write("[scan] lua_State* NOT FOUND after full scan");
}

/* Forward declaration — rescan_and_rehook() is defined after count_hook() */
static int rescan_and_rehook(void);

/* -------------------------------------------------------------------------
 * Lua hook — executes pending commands on the game's Lua thread
 *
 * Installed via lua_sethook(g_L, count_hook, LUA_MASKCOUNT, 100).
 * Fires every 100 VM instructions on the game's own Lua thread, at a safe
 * instruction boundary — no SuspendThread needed.
 * ---------------------------------------------------------------------- */

static void count_hook(lua_State *L, lua_Debug *ar) {
    (void)ar;
    if (!g_code_pending) return;

    /* MemoryBarrier ensures we read g_pending_code *after* the REPL thread's
       MemoryBarrier+g_code_pending=1 sequence — i.e. we see the complete
       buffer write that preceded the flag set. */
    MemoryBarrier();

    /* Copy code locally; clear the flag so the REPL thread can queue next cmd */
    char code[1024];
    strncpy(code, (const char *)g_pending_code, sizeof(code) - 1);
    code[sizeof(code) - 1] = '\0';
    InterlockedExchange(&g_code_pending, 0);

    /* Compile the Lua string into a chunk (pushes it on stack) */
    if (luaL_loadstring(L, code) != LUA_OK) {
        const char *err = lua_tostring(L, -1);
        snprintf((char *)g_result, sizeof(g_result), "ERR: (compile) %s", err ? err : "?");
        log_write("[hook] compile error: %s", err ? err : "?");
        lua_pop(L, 1);
        MemoryBarrier();
        InterlockedExchange(&g_result_ready, 1);
        return;
    }
    /* Stack: [chunk] */

    /* Inherit _ENV from the hooked function so that game globals are visible.
     *
     * Telltale runs game scripts in a sandboxed _ENV table, not in _G.
     * kPlayer_Player, GameObject, etc. live in that env, not _G.
     * luaL_loadstring sets the chunk's _ENV upvalue to _G by default;
     * we replace it with the _ENV of whatever function was executing
     * when the hook fired — that function is already in the game's env.
     *
     * lua_getstack(L, 1) = the Lua function that triggered the hook.
     * Its upvalue 1 is _ENV in any Lua 5.2 chunk/closure.
     */
    lua_Debug hook_ar;
    if (lua_getstack(L, 1, &hook_ar) && lua_getinfo(L, "f", &hook_ar)) {
        /* Stack: [chunk] [hooked_fn] */
        const char *upname = lua_getupvalue(L, -1, 1);
        log_write("[hook] upvalue[0] name: %s", upname ? upname : "NULL");
        if (upname) {
            /* Stack: [chunk] [hooked_fn] [upvalue] */
            if (strcmp(upname, "_ENV") == 0) {
                /* Replace chunk's upvalue 1 (_ENV) with hooked fn's _ENV */
                lua_setupvalue(L, -3, 1);
                /* Stack: [chunk] [hooked_fn] */
            } else {
                lua_pop(L, 1); /* upvalue wasn't _ENV, discard it */
            }
        }
        lua_pop(L, 1); /* pop hooked_fn */
    }
    /* Stack: [chunk] */

    /* Execute — capture up to one return value */
    if (lua_pcall(L, 0, 1, 0) != LUA_OK) {
        const char *err = lua_tostring(L, -1);
        snprintf((char *)g_result, sizeof(g_result), "ERR: %s", err ? err : "(runtime error)");
        log_write("[hook] lua error: %s", err ? err : "(unknown)");
        lua_pop(L, 1);
    } else {
        if (!lua_isnoneornil(L, -1)) {
            const char *ret = lua_tostring(L, -1);
            snprintf((char *)g_result, sizeof(g_result), "OK: %s", ret ? ret : "(non-string)");
        } else {
            strncpy((char *)g_result, "OK", sizeof(g_result));
        }
        lua_pop(L, 1);
    }
    /* Stack: back to entry depth */

    MemoryBarrier();
    InterlockedExchange(&g_result_ready, 1);
}

/* -------------------------------------------------------------------------
 * rescan_and_rehook — called when the hook stops responding (new game start)
 *
 * Resets g_L, re-runs the scan, and reinstalls the count hook if a valid
 * lua_State is found.  Returns 1 on success, 0 on failure.
 * Called from the REPL thread (not the game's Lua thread).
 * ---------------------------------------------------------------------- */

static int rescan_and_rehook(void) {
    lua_State *old_L = g_L;
    g_L = NULL;

    /* Brief pause: give the game time to finish initialising its new Lua state
       before we scan — improves first-attempt success rate after game reset. */
    Sleep(200);

    scan_for_lua_state();

    if (!g_L) {
        log_write("[recovery] rescan FAILED — no lua_State found (old g_L=0x%llx)",
                  (unsigned long long)(ULONG_PTR)old_L);
        return 0;
    }

    lua_sethook(g_L, count_hook, LUA_MASKCOUNT, 100);
    log_write("[recovery] hook reinstalled — old g_L=0x%llx, new g_L=0x%llx",
              (unsigned long long)(ULONG_PTR)old_L,
              (unsigned long long)(ULONG_PTR)g_L);
    return 1;
}

/* -------------------------------------------------------------------------
 * exec_lua — submit a command to the hook and wait for the result
 * ---------------------------------------------------------------------- */

static int exec_lua(const char *code, char *errbuf, size_t errbuf_sz) {
    if (!g_L) {
        if (errbuf && errbuf_sz) snprintf(errbuf, errbuf_sz, "lua_State not found");
        return 1;
    }

    strncpy((char *)g_pending_code, code, sizeof(g_pending_code) - 1);
    ((char *)g_pending_code)[sizeof(g_pending_code) - 1] = '\0';
    InterlockedExchange(&g_result_ready, 0);
    MemoryBarrier();    /* buffer write must be visible before flag is set */
    InterlockedExchange(&g_code_pending, 1);

    /* Wait up to 5 s (500 x 10 ms) for the hook to execute the command */
    for (int i = 0; i < 500 && !g_result_ready; i++)
        Sleep(10);

    if (!g_result_ready) {
        /* Hook stopped firing — game likely started a new round and reset its
           Lua state, clearing our installed hook.  Attempt auto-recovery. */
        InterlockedExchange(&g_code_pending, 0);  /* discard the stale pending cmd */
        int recovered = rescan_and_rehook();
        if (errbuf && errbuf_sz)
            snprintf(errbuf, errbuf_sz, recovered
                ? "hook lost; reconnected -- retry"
                : "hook lost; rescan failed -- wait and retry");
        return 1;
    }

    /* MemoryBarrier ensures we read g_result *after* the hook's
       MemoryBarrier+g_result_ready=1 sequence — i.e. we see the complete
       result write that preceded the flag set. */
    MemoryBarrier();

    if (strncmp((const char *)g_result, "ERR: ", 5) == 0) {
        if (errbuf && errbuf_sz)
            snprintf(errbuf, errbuf_sz, "%s", (const char *)g_result + 5);
        return 1;
    }

    return 0;
}

/* -------------------------------------------------------------------------
 * expand_command — ported from injector.c
 *
 * Expands recognised shorthands into full Lua strings, or passes raw Lua
 * through unchanged.  Returns NULL if the command was handled locally
 * (help/usage error) — caller must not call exec_lua for NULL returns.
 * ---------------------------------------------------------------------- */

static void print_help(void) {
    printf(
        "Commands:\n"
        "  setchips <n> [name]   set chips for player (default: Player)\n"
        "  revealhands           show all AI hole cards\n"
        "  forcefold <name>      force a fold WARNING: behaves unexpected\n"
        "  rehook                rescan and reinstall the Lua hook\n"
        "  help                  show this message\n"
        "  <lua>                 any other input is sent as raw Lua\n"
        "\n"
        "Valid player names: Max, Strongbad, Heavy, Tycho, Player\n"
    );
    fflush(stdout);
}

static const char *expand_command(const char *input, char *outbuf, size_t outbuf_sz) {
    /* Skip leading whitespace */
    while (*input == ' ' || *input == '\t') input++;

    /* help → print locally, no exec */
    if (_strnicmp(input, "help", 4) == 0 && (input[4] == '\0' || input[4] == ' ')) {
        print_help();
        return NULL;
    }

    /* setchips <amount> [name] → wrapped Lua string
       Amount must be all digits. Name is optional; defaults to "Player". */
    if (_strnicmp(input, "setchips", 8) == 0 && (input[8] == '\0' || input[8] == ' ')) {
        const char *p = input + 8;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '\0') {
            printf("usage: setchips <n> [name]\n");
            fflush(stdout);
            return NULL;
        }
        /* Extract amount token */
        const char *amount_start = p;
        while (*p && *p != ' ' && *p != '\t') p++;
        int valid = (p > amount_start);
        for (const char *q = amount_start; q < p; q++) {
            if (*q < '0' || *q > '9') { valid = 0; break; }
        }
        if (!valid) {
            printf("usage: setchips <n> [name]\n");
            fflush(stdout);
            return NULL;
        }
        char amount[64];
        int alen = (int)(p - amount_start);
        if (alen >= (int)sizeof(amount)) alen = (int)sizeof(amount) - 1;
        memcpy(amount, amount_start, alen);
        amount[alen] = '\0';
        /* Skip whitespace, get optional name (default "Player") */
        while (*p == ' ' || *p == '\t') p++;
        const char *name = (*p != '\0') ? p : "Player";
        /* GetPlayer(kPlayer_Player) returns nil in the remaster.
           Iterate GetPlayers() (1-indexed, 5 players) and find by name.
           Amount wrapped in tonumber() to avoid TValue layout mismatch. */
        snprintf(outbuf, outbuf_sz,
            "if GameObject then "
            "local ps = GameObject:GetTable():GetPlayers() "
            "for i,p in pairs(ps) do "
            "if p:GetName() == \"%s\" then "
            "p:SetChips(tonumber(\"%s\")) p:UpdateChipUI() break "
            "end end end",
            name, amount);
        return outbuf;
    }

    /* forcefold <name> → call p:Fold() on the named player */
    if (_strnicmp(input, "forcefold", 9) == 0 && (input[9] == '\0' || input[9] == ' ')) {
        const char *p = input + 9;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '\0') {
            printf("usage: forcefold <name>\n");
            fflush(stdout);
            return NULL;
        }
        snprintf(outbuf, outbuf_sz,
            "if GameObject then "
            "local ps=GameObject:GetTable():GetPlayers() "
            "for i,p in pairs(ps) do "
            "if p:GetName()==\"%s\" then p:Fold() break end "
            "end end",
            p);
        return outbuf;
    }

    /* revealhands → print all AI hole cards, one player per line */
    if (_strnicmp(input, "revealhands", 11) == 0 && (input[11] == '\0' || input[11] == ' ')) {
        snprintf(outbuf, outbuf_sz,
            "if GameObject then "
            "local F={[\"11\"]=\"J\",[\"12\"]=\"Q\",[\"13\"]=\"K\",[\"14\"]=\"A\"};"
            "local S={[\"1\"]=\"S\",[\"2\"]=\"H\",[\"3\"]=\"D\",[\"4\"]=\"C\"};"
            "local function cr(r,u) local rs=tostring(r);return(F[rs] or rs)..S[tostring(u)] end;"
            "local ps=GameObject:GetTable():GetPlayers();"
            "local s=\"\";"
            "for i,p in pairs(ps) do "
            "if p:GetName()~=\"Player\" then "
            "local cl=p:GetHoleCards().cardList;"
            "if cl[1] and cl[2] then "
            "s=s..p:GetName()..\" \"..cr(cl[1][1],cl[1][2])..\" \"..cr(cl[2][1],cl[2][2])..\"\\n\""
            "else s=s..p:GetName()..\" (no cards)\\n\" end end end;"
            "return s end");
        return outbuf;
    }

    /* Raw Lua passthrough */
    return input;
}

/* -------------------------------------------------------------------------
 * console_repl — allocates a console and runs the interactive REPL loop
 *
 * Called from worker_thread after hook installation.  Blocks until the
 * user types "exit" or stdin closes.
 * ---------------------------------------------------------------------- */

static void console_repl(void) {
    AllocConsole();
    /* Windows 11 / Windows Terminal: the console window can be created but
       remain hidden or minimised.  Force it visible. */
    HWND hwnd = GetConsoleWindow();
    if (hwnd) {
        ShowWindow(hwnd, SW_SHOW);
        SetForegroundWindow(hwnd);
    }
    freopen("CONIN$",  "r", stdin);
    freopen("CONOUT$", "w", stdout);

    printf("dinput8 proxy loaded\n");
    printf("Enter a command or Lua code. Type 'help' for commands. Use 'rehook' once you're in a poker game.\n");
    printf("> ");
    fflush(stdout);

    char line[1024];
    char expanded[1024];
    char errbuf[512];

    while (fgets(line, sizeof(line), stdin)) {
        /* Strip trailing CR/LF */
        int len = (int)strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
            line[--len] = '\0';

        if (strcmp(line, "exit") == 0) break;

        if (len == 0) {
            printf("> ");
            fflush(stdout);
            continue;
        }

        /* rehook: manual rescan + reinstall, handled directly (no exec_lua) */
        if (strcmp(line, "rehook") == 0) {
            int ok = rescan_and_rehook();
            printf("%s\n", ok ? "rehook succeeded" : "rehook failed -- no lua_State found");
            printf("> ");
            fflush(stdout);
            continue;
        }

        /* Expand shorthands or pass through as raw Lua */
        const char *to_send = expand_command(line, expanded, sizeof(expanded));
        if (!to_send) {
            /* Handled locally (help / usage error) */
            printf("> ");
            fflush(stdout);
            continue;
        }

        /* Submit to hook and wait for result */
        memset(errbuf, 0, sizeof(errbuf));
        int result = exec_lua(to_send, errbuf, sizeof(errbuf));

        if (result == 0) {
            /* g_result is "OK" or "OK: <value>" — strip the "OK: " prefix */
            const char *res = (const char *)g_result;
            if (strncmp(res, "OK: ", 4) == 0)
                printf("%s\n", res + 4);
            else
                printf("%s\n", res);
        } else {
            printf("ERR: %s\n", errbuf);
        }

        printf("> ");
        fflush(stdout);
    }
}

/* -------------------------------------------------------------------------
 * Worker thread
 * ---------------------------------------------------------------------- */

static DWORD WINAPI worker_thread(LPVOID param) {
    (void)param;

    Sleep(500);     /* let DllMain return before doing anything */

    log_write("[dinput8_proxy] DLL loaded (pid %lu), scanning for lua_State...",
              (unsigned long)GetCurrentProcessId());

    /* Retry loop: the game initialises its Lua state some time after startup.
       Scan every 500 ms for up to 15 s (30 attempts) before giving up. */
    for (int attempt = 0; attempt < 30 && !g_L; attempt++) {
        if (attempt > 0) {
            log_write("[dinput8_proxy] lua_State not found, retrying (%d/30)...", attempt + 1);
            Sleep(500);
        }
        scan_for_lua_state();
    }

    if (!g_L) {
        log_write("[dinput8_proxy] lua_State not found after 30 attempts — aborting");
        return 0;
    }

    /* Install hook: fires every 100 VM instructions on the game's Lua thread */
    lua_sethook(g_L, count_hook, LUA_MASKCOUNT, 100);
    log_write("[dinput8_proxy] hook installed, starting console REPL");

    console_repl();
    return 0;
}

/* -------------------------------------------------------------------------
 * DLL entry point
 *
 * Loads the real System32\dinput8.dll first (so trampolines are valid before
 * the game calls any DirectInput function), then spawns the worker thread.
 * Returns FALSE on failure to load the real DLL — game will not start.
 * ---------------------------------------------------------------------- */

BOOL WINAPI DllMain(HINSTANCE hInstDll, DWORD reason, LPVOID reserved) {
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hInstDll);

        /* Build log path: same directory as dinput8.dll */
        GetModuleFileNameA(hInstDll, g_log_path, sizeof(g_log_path));
        char *sep = strrchr(g_log_path, '\\');
        if (sep) strcpy(sep + 1, "dinput8_proxy.log");
        else      strcpy(g_log_path, "dinput8_proxy.log");

        /* Load the real dinput8.dll by full absolute path.
           It is already mapped (the game imported it), so LoadLibrary only
           increments the reference count — no loader-lock risk. */
        g_real_dinput8 = LoadLibraryA("C:\\Windows\\System32\\dinput8.dll");
        if (!g_real_dinput8) {
            log_write("[dinput8_proxy] FATAL: LoadLibrary(System32\\dinput8.dll) failed (error %lu)",
                      GetLastError());
            return FALSE;
        }

        /* Store function pointers for all 5 exports */
        fp_DirectInput8Create  = (PFN_DirectInput8Create) GetProcAddress(g_real_dinput8, "DirectInput8Create");
        fp_DllCanUnloadNow     = (PFN_DllCanUnloadNow)    GetProcAddress(g_real_dinput8, "DllCanUnloadNow");
        fp_DllGetClassObject   = (PFN_DllGetClassObject)  GetProcAddress(g_real_dinput8, "DllGetClassObject");
        fp_DllRegisterServer   = (PFN_DllRegisterServer)  GetProcAddress(g_real_dinput8, "DllRegisterServer");
        fp_DllUnregisterServer = (PFN_DllUnregisterServer)GetProcAddress(g_real_dinput8, "DllUnregisterServer");

        HANDLE ht = CreateThread(NULL, 0, worker_thread, NULL, 0, NULL);
        if (ht) CloseHandle(ht);
    }
    return TRUE;
}

/* -------------------------------------------------------------------------
 * Exported trampoline functions — forward to the real System32\dinput8.dll
 *
 * __declspec(dllexport) causes GNU ld to include these in the DLL export
 * table with their C names (no mangling on x86-64 with C linkage).
 * ---------------------------------------------------------------------- */

__declspec(dllexport) HRESULT WINAPI DirectInput8Create(
    HINSTANCE hinst, DWORD dwVersion, const void *riidltf,
    void **ppvOut, void *punkOuter)
{
    if (fp_DirectInput8Create)
        return fp_DirectInput8Create(hinst, dwVersion, riidltf, ppvOut, punkOuter);
    return E_NOTIMPL;
}

__declspec(dllexport) HRESULT WINAPI DllCanUnloadNow(void) {
    if (fp_DllCanUnloadNow) return fp_DllCanUnloadNow();
    return S_FALSE;
}

__declspec(dllexport) HRESULT WINAPI DllGetClassObject(
    const void *rclsid, const void *riid, void **ppv)
{
    if (fp_DllGetClassObject) return fp_DllGetClassObject(rclsid, riid, ppv);
    return CLASS_E_CLASSNOTAVAILABLE;
}

__declspec(dllexport) HRESULT WINAPI DllRegisterServer(void) {
    if (fp_DllRegisterServer) return fp_DllRegisterServer();
    return E_NOTIMPL;
}

__declspec(dllexport) HRESULT WINAPI DllUnregisterServer(void) {
    if (fp_DllUnregisterServer) return fp_DllUnregisterServer();
    return E_NOTIMPL;
}
