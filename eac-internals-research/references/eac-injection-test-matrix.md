# EAC Kernel DLL Injection Test Matrix — raw thread dump
Source: https://www.unknowncheats.me/forum/arc-raiders/739720-injecting-dll-eac-protected-process-kernel.html
Author: Un1xCr3w + replies (beck123x rep ~10k, xuso15, R7flex2)
Read: 2026-08-17

Target: ARC Raiders (EAC-protected). Goal: kernel-driver DLL injection.

| Test | Method | Result |
|---|---|---|
| 1 | Manual map + InstrumentationCallback, free VAD right after DllMain | **SURVIVED 5 min** (only survivor — no persistent allocation) |
| 2 | Same but keep allocation | DETECTED in seconds — persistent MEM_MAPPED with exec |
| 3 | VAD flag spoof to PAGE_READONLY | DETECTED |
| 4 | VAD unlink from AVL tree | BSOD on teardown |
| 5 | Physical page remapping | DETECTED (VAD entry still exists) |
| 6 | Private VirtualAllocEx MEM_COMMIT | DETECTED faster than section |
| 7 | Section RW + NX clear in PTE only | DETECTED (VAD itself flagged) |
| 8 | LdrLoadDll 12-byte trampoline via kernel write | DETECTED <2s (ntdll checksum) + BSOD |

Poster got account banned just for testing injection methods (no cheat used).

beck123x (rep 9998): "Attack the anticheat, this is the only way of being UD on EAC or any other decent kernel AC nowadays... once they get process CR3 and walk every present page, and find one with no VAD, but PTE is somehow executable, that won't save you... this is not 2018 anymore. Or just abuse some signed DLL, although it's very hard on EAC."

xuso15: BYOVD approach — load custom read-only driver via vulnerable driver BEFORE EAC launch, then remove loader from Windows tables/registers. EAC unaware of kernel modification. External read-only software afterward. Keyword: BYOVD.

R7flex2 (banned, rep 7k): one-word answer "hypervisor".

YumikoImagwa: external (not internal) hooks survived for them; internal → instant ban.

Implication for RE work: any internal modification (even 12 bytes) or persistent exec VAD = detected. External read-only + BYOVD or hypervisor = current viable research approaches.
