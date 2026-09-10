# LdrGen - Loader Generator

## Context
Curtin University cybersecurity project. All code is private and used only during class presentations.
LdrGen is a loader generator for simulated authorized red team and pentesting engagements.

## What it does
Generates shellcode loaders with mix-and-match payload, memory, and execution methods.
Pentesters pick options at compile time via `#ifdef` flags, and the generator produces a working loader.

Example combinations:
- `PAYLOAD_LOCAL_EMBED` + `MEMORY_BASIC_VIRTUAL_ALLOC` + `EXECUTION_CREATETHREAD_LOCAL`
- `PAYLOAD_REMOTE_HTTP` + `MEMORY_MAPPED_MEMORY` + `EXECUTION_QUEUE_APC_LOCAL`

## Architecture

### Unified context struct
Everything hangs off a single global `Ldr* g_ldr` defined in `core.h` / allocated in `core.c`.
Access pattern: `g_ldr->apis->VirtualAlloc`, `g_ldr->config->DelayBefore`.
Local aliases are fine for readability: `CoreApis* apis = g_ldr->apis;`

The `Ldr` struct also holds `hModule` — set to `NULL` for EXE (falls back to `GetModuleHandle(NULL)`), or `hinstDLL` for DLL builds. Used by payload methods that need the module base (e.g., rsrc).

### Execution flow
```
LoadMain(hModule)
  -> LoadCoreApis()           // resolve LocalAlloc via PEB walk, allocate g_ldr + sub-structs, resolve base APIs
  -> g_ldr->hModule = ...     // store module base
  -> ParseConfig()            // parse binary config blob into g_ldr->config
  -> payload_get()            // retrieve payload (embedded, rsrc, HTTP, etc.)
  -> memory_load_apis()       // resolve method-specific APIs (VirtualAlloc, CreateFileMapping, etc.)
  -> memory_run()             // allocate + write payload, returns MemoryInfo
  -> execution_load_apis()    // resolve method-specific APIs (CreateThread, QueueUserAPC, etc.)
  -> execution_run()          // execute payload
```

### Interface pattern
All payload, memory, and execution methods expose the same interface per category:

**Payload** (`src/payload/<local|remote>/payload_<method>.c`):
- `LPVOID payload_get(PDWORD PayloadSize)` — retrieve payload, return address + size

**Memory** (`src/memory/<local|remote>/memory_<method>.c`):
- `BOOL memory_load_apis()` — resolve APIs needed by this method
- `MemoryInfo memory_run(LPVOID PayloadAddress, SIZE_T PayloadSize)` — allocate and write payload

**Execution** (`src/execution/<local|remote>/execution_<method>.c`):
- `BOOL execution_load_apis()` — resolve APIs needed by this method
- `BOOL execution_run(MemoryInfo memInfo)` — execute the payload

Only one of each category is compiled in at a time via `#ifdef`.

### API resolution
No direct WinAPI imports. APIs are resolved at runtime via PEB walking (`GetModule`) and export table parsing (`GetProc`) using compile-time hashes. Resolved function pointers are stored in `g_ldr->apis` (`CoreApis` struct).

For non-default modules (e.g., winhttp.dll), use `LoadLibraryA` (already resolved) then `GetProc` against the loaded handle.

### Config format
Binary blob parsed by `ParseConfig()` into `g_ldr->config`. Layout:
- Fixed header: DebugChecks (4B), LocalOrRemote (1B)
- Conditional: `#ifdef REMOTE_PAYLOAD` — url/uri/port
- Timing: DelayBefore (4B), DelayBetween (4B)
- Per-method settings gated by `#ifdef` with HasX flag bytes for optional fields

The `Config` struct mirrors this with matching `#ifdef` guards.

### Project structure
```
main.c                                          # entry point (exe or DLL)
includes/
  core/core.h                                   # Ldr struct, g_ldr extern, LoadMain decl
  core/nt.h                                     # NT internals (PEB, LDR_DATA_TABLE_ENTRY, etc.)
  apis/apidefs.h                                # CoreApis struct, function pointer typedefs, API hashes
  apis/apis.h                                   # GetProc, GetModule, HasherA/W, LoadCoreApis decls
  config/config.h                               # Config struct
  payload/payload.h                             # payload_get decl
  memory/memory.h                               # MemoryInfo struct, memory interface decls
  execution/execution.h                         # execution interface decls
src/
  core/core.c                                   # g_ldr allocation, LoadMain, shellcode payload
  apis/apis.c                                   # PEB walk, export parsing, hash functions, LoadCoreApis
  config/config.c                               # binary config parser
  payload/local/                                # local payload methods
    payload_local_embed.c                       # .text/.rdata/.data embedded shellcode
    payload_local_rsrc.c                        # PE resource section
  payload/remote/                               # remote payload methods
    payload_remote_http.c                       # WinHTTP fetch over HTTPS
  memory/local/                                 # local memory methods
    memory_basicvirtualalloc_local.c
    memory_mappedmemory_local.c
  execution/local/                              # local execution methods
    execution_createthreadlocal.c
    execution_queueapc_local.c
```

### Include convention
`core.h` is the hub — it includes `apidefs.h` and `config.h`, so most `.c` files only need `core.h` plus their own method header. `payload.h` is only included in `core.c`.

### Build output
Controlled by `#ifdef`:
- `OUTPUT_DLL` — builds as DLL (DllMain spawns LoadMain via CreateThread with hinstDLL)
- Default — builds as EXE (main calls LoadMain with NULL)

### Compile flags
Payload selection:
- `PAYLOAD_LOCAL_EMBED` — embedded byte array
- `PAYLOAD_SECTION_TEXT`, `PAYLOAD_SECTION_RDATA`, `PAYLOAD_SECTION_DATA` — which PE section
- `PAYLOAD_LOCAL_RSRC` — PE resource section
- `PAYLOAD_REMOTE_HTTP` — fetch over HTTPS

Method selection:
- `MEMORY_BASIC_VIRTUAL_ALLOC`, `MEMORY_MAPPED_MEMORY`
- `EXECUTION_CREATETHREAD_LOCAL`, `EXECUTION_QUEUE_APC_LOCAL`

Other:
- `REMOTE_PAYLOAD` — enables HTTP config fields in Config struct
- `OUTPUT_DLL` — DLL output mode

### CLI tool (planned)
Python CLI (`ldrgen.py`) that generates the binary config blob and prints the required `#define` compile flags. Allows quick prototyping without manually crafting hex blobs.
