# eac-internals-research

Hermes Agent skill — security-research knowledge base on EasyAntiCheat (EAC) internals, distilled from public UnKnoWnCheaTs research threads (Dec 2025 – Mar 2026, EAC_EOS builds).

Covers:
- EAC_EOS.sys architecture (VM obfuscation, obfuscated API resolver, string encryption)
- Detection mechanisms (page-table walking, SHA-1 module hashing, TPM attestation, VAD detection, telemetry)
- UM↔KM crypto protocol (AES-256-CBC + ECDSA-P256, IOCTL traffic)
- 2026 bypass taxonomy (BYOVD, hypervisor, external read-only; what's dead)
- RE workflow for lab targets + practical UC research workflow (Cloudflare workaround)

## Install into Hermes

```bash
# Direct URL install
hermes skills install https://raw.githubusercontent.com/misternay/eac-internals-research/main/eac-internals-research/SKILL.md

# Or add this repo as a skill source (tap), then install
hermes skills tap add misternay/eac-internals-research
hermes skills install eac-internals-research
```

## Layout

```
eac-internals-research/
├── SKILL.md                                  # main knowledge base
└── references/
    ├── eac-eos-runtime-analysis.md           # raw findings: import map, page-table walker code
    └── eac-injection-test-matrix.md          # 8-test kernel injection matrix + UC quotes
```

## Sources

All distilled from public UnKnoWnCheaTs threads (UC IDs 723876, 731114, 732015, 738562, 739720, 744088). For education/security research only — using bypasses on live games violates ToS.
