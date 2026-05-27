# zig-runtime-audit

A lightweight NTDLL hook scanner written in Zig. Detects in-memory modifications to `ntdll.dll` — the kind placed by EDR/AV software or malware to intercept system calls.

## What it does

Every Windows process loads its own copy of `ntdll.dll` into memory. Security software (EDRs) and malware both use the same technique to monitor or intercept system calls: they overwrite the first bytes of NTDLL functions with a `jmp` instruction pointing to their own code.

This tool finds those modifications by:

1. Locating the live `ntdll.dll` base address via `PEB → Ldr → InLoadOrderModuleList` (no WinAPI calls)
2. Opening the clean copy of `ntdll.dll` from disk
3. Parsing the PE headers to locate the `.text` section in both
4. Reading the in-memory `.text` via `ReadProcessMemory`
5. Comparing byte-by-byte — any difference is a potential hook

If NtReadVirtualMemory or NtAllocateVirtualMemory are hooked, ReadProcessMemory and the allocator will redirect through the hook — causing a crash or unexpected behavior. To bypass this, replace both calls with direct syscalls (using the syscall number obtained via Halo's Gate or a static table) or indirect calls through an unhooked stub, bypassing the NTDLL trampoline entirely.

## Test hooks


<img width="865" height="372" alt="image" src="https://github.com/user-attachments/assets/b89135f8-9513-4173-914a-bfd27cc4a6a5" />


## Example output


<img width="731" height="406" alt="image" src="https://github.com/user-attachments/assets/739223bb-b411-4495-b147-bbd094c35a8d" />


`0xe9` is the x86/x64 opcode for `jmp rel32` — the classic inline hook pattern.

## Technical details

**No imports for PEB access** — the PEB pointer is read directly from `gs:[0x60]` using inline assembly, bypassing any hooked WinAPI lookup functions.

**PE parsing from scratch** — DOS header → NT headers → section table, no external libraries.

**Why hooks break the scanner** — if `NtAllocateVirtualMemory` or `NtReadVirtualMemory` are hooked, the scanner itself may crash (the hooks redirect execution before the scanner reads memory). To test with a hook injector, leave those two functions unhooked.

## Build

Requires Zig 0.15+

```bash
zig build
```

Or directly:

```bash
zig build-exe src/main.zig -O ReleaseFast -target x86_64-windows
```

## Use cases

- Verifying whether an EDR has injected hooks into your process
- Testing custom hook injectors (paired with a hook injector tool)
- Learning PE structure and Windows internals in a practical context

## What this is not

This is a research and learning project. It scans the current process only — not other processes. It detects byte-level differences, not semantic hook analysis.
