# ZuiControl Rules Lab

An independent upstream acquisition and compatibility lab for
[AsoulOpt](https://github.com/nakixii/Magisk_AsoulOpt), by nakixii.
This repository contains tooling and **derived analysis**. It claims no ownership of AsoulOpt.
It is not a Magisk module distribution or a ZuiControl source mirror.

Current result: **ANALYSIS_ONLY**. No production rule pack, online-sync endpoint contract or
automatic ZuiControl update is enabled. The frozen Backend and Integration branches are untouched.

The [R1 report](ASOULOPT_UPSTREAM_AUTOMATION_COMPATIBILITY_R1.md) explains the actual recovered model,
all 11 changed existing classifiers, 17 new packages, mode/rt, control markers and compatibility limits.
Machine-readable results are in `analysis/`; `output/latest.json` always exposes the production gate.
`reference/zuiopt.json` is a neutral factory projection anchored to Backend commit
`6d896f29812dab653e2e88c6ee989c972a343c97`, with hashes of the exact source inputs.
It is not a source checkout or a production-consumable rules pack.
`source_sha256` records the original Windows checkout bytes; canonical commit-blob hashes and
Git line-ending equivalence are explicitly bound in `reference/git_blob_provenance.json`.

## Acquisition and automation

Each run fetches the official
[AsoulOpt.json](https://raw.githubusercontent.com/nakixii/Magisk_AsoulOpt/main/AsoulOpt.json)
afresh and resolves its release tag/asset through GitHub's API. No release is hardcoded as forever latest.
VersionCode, tag, asset identity, size, digest and release time are compared to the last accepted acquisition.
Unchanged input emits **NO_UPSTREAM_CHANGE**, stops acquisition and preserves the published reports.
Changed input is size/digest verified, checked against module.prop and recovered statically.
The README corpus is pinned to the same metadata commit and checked against the ELF's declarations.

The proprietary ZIP exists only in memory; the ELF is held in a temporary directory for host LLVM disassembly
and is never executed. Neither is committed or uploaded. Only derived outputs and receipts are published.
The extractor qualifies one reviewed ELF fingerprint, not all future AArch64 binaries.
Unknown fingerprints, opcodes, categories, bounds or grammar cannot silently become production rules.
Network/provenance/consistency errors fail the job before publication. Unknown fingerprints produce explicit
unqualified analysis with `input_accepted=false`, requiring reverse-engineering review.

The original historical rule extractor could not be found after a narrow local/retained-archive search.
The surviving ELF-helper approach is reused; the search receipt is in `reference/historical_search.json`.

[GitHub Actions](https://github.com/xmy953538104/ZuiControl-Rules/actions/workflows/update-asoulopt.yml)
supports manual dispatch. A weekly schedule is added only after a successful full manual acquisition and
publication, recorded in `.github/qualification.json`. The workflow downloads no ROM and runs no product build.
It commits only `output/`, `analysis/`, `history/` and the derived report. Artifacts contain derived reports only.
Schedule checks can be delayed by GitHub; they are discovery checks, not a production update SLA.

Full manual qualification [37206202678](https://github.com/xmy953538104/ZuiControl-Rules/actions/runs/37206202678)
passed on 2026-10-04, including derived publication and a cross-host identical normalized-model hash.
The qualified weekly check runs Sunday 03:17 UTC (11:17 Asia/Shanghai).

## Local use

Python 3.12+ standard library and host `llvm-objdump` are sufficient. No Python dependencies.

```sh
python tools/run.py --local-review
python tools/test_lab.py
git diff --check
```

Pass `--objdump /path/to/llvm-objdump` if it is not on PATH. `--local-review` leaves input unaccepted,
so the initial manual workflow performs the complete acquisition even if local results are already present.
Run failures never authorize a ZuiControl source/runtime change.

## Compatibility and provenance

Package and thread matching, first-match order, category competition, marker effects, masks, global/per-game
mode/rt, realtime scheduler policy and unknown fields are classified separately. Literal classifier similarity
does not prove runtime equivalence. No supported lossless subset has been accepted in R1; `output/rules.conf`
is deliberately absent and unexpected presence fails the publication gate.

`history/<versionCode>-<digest-prefix>/` retains the first acquisition receipt and diffs for that asset identity.
Latest output retains release/download/ELF hashes, tool hashes and the frozen reference hash.
The first acquisition has no prior accepted upstream lab result; no historical diff is invented.
An owner must separately authorize any future supported-subset conversion and production integration.

Gitee: **DEFERRED**. This lab does not block Frontend+Backend Integration.
