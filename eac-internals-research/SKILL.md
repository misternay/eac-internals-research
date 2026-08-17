---
name: eac-internals-research
version: 1.0.0
author: kapi
license: MIT
description: Use when reversing EasyAntiCheat or kernel anti-cheats.
---

## When to Use

- Reversing/analyzing EAC (EasyAntiCheat), BattlEye, or other kernel anti-cheats for security research
- EAC blocks debugging/RE work on a target process (blacklisted tools, detection crashes)
- Researching UnKnoWnCheaTs threads on anti-cheat bypass/internals (Cloudflare workaround included)
- Understanding modern kernel detection: page-table walking, TPM attestation, VM obfuscation

# EAC Internals Research (security research knowledge base)

Knowledge distilled from public UnKnoWnCheaTs research threads (Dec 2025 – Mar 2026, EAC_EOS builds). Purpose: **understanding anti-cheat architecture for RE/defensive work**. Using bypasses on live games violates ToS and risks bans — keep research to offline/private/lab targets.

## 1. Architecture (EAC_EOS.sys)

- Kernel driver `\\Driver\\EasyAntiCheat_EOSSys` + usermode service. Ships **multiple builds with different crypto params** (static 23.3MB vs runtime 38.4MB observed — virtualized section unpacks at load). Never assume values from someone else's analysis match your build.
- Import table has only 2 static imports (`FltRegisterFilter`, `__chkstk`). ~200+ kernel APIs resolved at runtime via obfuscated resolver: RSA-style modexp with exponent 17, dual modulus (low/high 32 bits), then `api_ptr = ROR64(result, N) ^ const` (or `~result` NOT-variant). Find it: function taking QWORD ptr doing modular multiplication in a loop, ~500 call sites. Xref it = map of API usage.
- ~90% of driver is a **custom VM** (handler-chain model, dispatch through every GPR RAX–R15, computed jump targets). Most detection logic lives there — static analysis alone is painful; emulate or debug dynamically.
- Strings encrypted with PRNG-XOR (XorShift variants + LCG `state = 1140671485*state + 12820163`). Pattern: hardcoded seed → loop XOR memory → string compare right after.
- Pool tags randomized from ~46 legitimate Windows tags.
- Minifilter (`FltRegisterFilter`), `ObRegisterCallbacks` (object callbacks), kernel↔UM IPC via IOCTLs.

## 2. Detection mechanisms (what trips)

| Vector | Mechanism |
|---|---|
| Hidden memory | **Direct page-table walking** (CR3 → PML4→PDPT→PD→PT, handles large pages) — bypasses `MmIsAddressValid`/API hooks. Mismatch between page tables and VAD = flagged |
| Patched modules | **SHA-1 hash of driver/DLL code sections** (standard SHA-1 IVs, result marker 0x2C97497B). 12-byte ntdll trampoline detected in <2s |
| Injected DLL (persistent) | ANY persistent VAD with execute capability — even section-backed RW with NX cleared only in PTE. VAD flag spoofing, unlinking, physical remap all fail. Only allocation freed immediately after DllMain survived 5 min |
| Debug/tools | Process blacklist: `dbgview`, `devenv`, `tv_*`; drivers: `Dbgv.sys`, `PROCMON*.sys`, `dbk64.sys`. Remote debug from 2nd machine instead |
| Process masquerade | Validates system processes (explorer/svchost/audiodg/AppInfo.dll) by path + legitimacy, not just name |
| HWID / firmware | TPM via `tbs.sys` (Tbsi_Context_Create/Submit_Command imports) → measured boot/PCR attestation. Registry serial spoofing dead; "permanent spoof" is marketing. Vulnerable-BIOS tricks only |
| Embedded files | Scans memory for PNG magic+IHDR/IEND, FAT structures — targets overlay cheats |
| Telemetry | Every heartbeat: driver inventory, GPU vendor, certs, high-precision timestamps (SharedUserData.InterruptTime). Impossibly consistent timing = flag |

## 3. Crypto protocol (UM↔KM)

- IOCTL codes observed: `0x0022E023` (44B constant), `0x0022E017` (816B periodic), `0x00226013`, `0x0022E043` (40B).
- **AES-256-CBC + ECDSA-P256** via BCrypt with all params obfuscated (algorithm names stored as encrypted bytes, per-string seeds). Keys **rotate every update cycle**. Report packets likely encrypted+signed.
- Hooking the IOCTL handler (log + forward) works for traffic capture without breaking the driver.

## 4. Bypass taxonomy (2026 state, from UC consensus)

1. **BYOVD** (bring your own vulnerable driver) — load custom read-only driver via vuln driver before EAC starts, then unload loader. Works if driver not in MS blacklist/loldrivers. Most accessible.
2. **Attack the AC itself** (disable/neuter detection paths) — per top rep users "the only way to be UD on decent kernel ACs" for internal cheats; hard mode.
3. **Hypervisor-based** — hide everything below VT-x; heavy engineering.
4. **Kernel IRQL trick** — detection fns check `cr8 < DISPATCH_LEVEL` before running; raising IRQL skips those paths (careful: no pageable code/wait at DISPATCH).
5. **External read-only** — survives where internal hooks get banned fast (game close-in-seconds class detection).
6. Dead/dying: VAD spoofing, VAD unlinking, physical remap, registry HWID spoof, public CE/free bypasses (post-enforce), ntdll code patching.

## 5. RE workflow for anti-cheat-protected targets (lab use)

1. Get the driver file (game install) — note SHA256 + size; expect different params per build.
2. Static pass in IDA/Ghidra: find modexp resolver (×17 loop) → xref = API map. Decrypt strings (seed+XOR loop+cmp pattern).
3. Runtime: dump from kernel memory (differs from static!), map VM handlers one-op-then-jump chains.
4. Emulation options discussed: full driver emulation (Unicorn) / hypervisor / manual VM reduction — all "feasible, takes months".
5. Traffic: hook IRP_MJ_DEVICE_CONTROL, log IOCTL codes/buffers, forward originals.
6. Debug from a second machine (blacklisted local tools) or via the IRQL trick for short memory ops.
7. Discipline: claims must match dumps; different build ≠ same constants.

## 6. Research workflow on UnKnoWnCheaTs (practical)

- UC is behind **Cloudflare** → Firecrawl/curl get 403 "Just a moment". Use real Chrome via browser_exec (passes). SearXNG `site:unknowncheats.me <topic>` first to find threads, then open in browser.
- Highest-signal forums: *Anti-Cheat Bypass*, *General Programming and Reversing*. Quality marker: long "[Information] static/runtime analysis" posts by high-rep users (Helzky, moneyissogood, beck123x, JustAReverser) — treat vendor claims ("perma spoof") skeptically; community actively debunks.
- Related refs: igromanru/SM2-EAC-Bypass-Doc (offline/private matches, still maintained Jun 2026), loldrivers.io (blacklisted vuln driver DB), fearlessrevolution.com (CE tables, ban reports).

## Sources (read 2026-08-17)
- EAC_EOS.sys Static Analysis — Helzky (UC 731114)
- EAC_EOS Runtime Analysis — Helzky (UC 732015)
- Analysing EAC's Cryptographic Protocol — moneyissogood (UC 738562)
- Injecting DLL into EAC-protected process — Un1xCr3w test matrix (UC 739720)
- AC Detection in 2026: Fact vs Myth — OXYGENmase/JustAReverser (UC 744088)
- any modern ways to bypass EAC? (UC 723876)
- Raw thread dumps saved in workspace `cache/browser-use/workspace/*/eac_*.txt`
