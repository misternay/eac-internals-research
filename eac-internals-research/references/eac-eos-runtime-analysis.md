# EAC_EOS.sys Runtime Analysis — raw thread dump
Source: https://www.unknowncheats.me/forum/anti-cheat-bypass/732015-eac_eos-runtime-analysis.html
Author: Helzky (UC, banned but rep 33k) + community corrections
Read: 2026-08-17 via browser_exec (Cloudflare blocks curl)

## Key excerpts

Binary differences static vs runtime:
- Static: 23.3 MB, SHA256: 7e7f9cfd...
- Runtime: 38.4 MB, SHA256: 26da7d4b...
- Extra ~15MB = virtualized section unpacking at runtime + extra segment seg004 (24KB)
- VM section 21MB → 35MB loaded

API resolver confirmed (sub_FFFFF80251340000):
```c
uint64_t resolve_api(uint64_t* context) {
    uint32_t low = modexp(*context, 17, qword_FFFFF8025150D3B8);
    uint32_t high = modexp(value, 17, 0x8123AD9AFB36519);
    return ((uint64_t)high << 32) | low;
}
```
200+ call sites. Static build modulus was 0x199F07D3B49761CB (different!).

Import map highlights (from @Sternht):
- tbs.sys: Tbsi_Context_Create, Tbsip_Submit_Command, Tbsip_Cancel_Commands, Tbsip_Context_Close, Tbsi_GetDeviceInfo  ← TPM
- FLTMGR.SYS: FltQueryInformationFile, FltReadFile, FltGetRequestorProcess, FltStartFiltering, FltAllocatePoolAlignedWithTag, FltUnregisterFilter, FltFreePoolAlignedWithTag
- ntoskrnl: PsIsThreadTerminating, PsGetProcessCreateTimeQuadPart, PsReferenceProcessFilePointer, NtSetInformationProcess, SeCaptureSubjectContext, RtlCreateUserThread, PsGetProcessPeb, MmGetPhysicalAddress, NtOpenKey...

Physical memory read:
```c
for (i...) { if (MmIsAddressValid(page_base + (i << 12))) { map_physical_page; memcpy; unmap; } }
```

Page table walking (sub_FFFFF802513E6768):
```c
bool walk_page_tables(uint64_t virt_addr, uint64_t* phys_out, uint64_t* flags_out) {
    uint64_t cr3 = __readcr3();
    // PML4 -> PDPT -> PD -> PT, present-bit checks, large page PS bit
}
```
→ catches hidden memory MmIsAddressValid wouldn't see.

Module hash verification (sub_FFFFF802513BD87C): SHA-1 of code sections, standard IVs (0x67452301...), result marker 748112251 (0x2C97497B).

Embedded file detection (sub_FFFFF802513BD690): PNG magic 0xA1A0A0D474E5089 + IHDR + IEND scan; FAT/sector structure detection.

Watermark detection: embedded watermarks from known cheat tools (hash-based, not filename).

Telemetry: driver inventory, GPU vendor, certificates, per-heartbeat upload to Epic servers. SharedUserData.InterruptTime timestamps.

Still unmaped (per author): ObRegisterCallbacks targets, minifilter IRPs, kernel→user IPC mechanism, telemetry payload structure.

Community notes:
- 0AVX: obfuscation "not feasibly reducible" — recommend emulation (Unicorn/hypervisor) over devirtualization
- hernos (Hacked North Korea rank): agrees analysis approach; warns arbitrary kernel patching risks
- Detection of unsigned/mismatched drivers expected via Secure Kernel signature checks

Summary (author's):
- Different builds have different crypto parameters - don't assume universal
- Page table walking catches hidden memory that API hooks miss
- SHA-1 integrity checking on module code sections
- Embedded file detection targets overlay cheats
