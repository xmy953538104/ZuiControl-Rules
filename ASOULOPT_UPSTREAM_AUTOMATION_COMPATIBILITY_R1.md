# AsoulOpt upstream automation and compatibility R1

This independent public lab keeps ZuiControl Backend `6d896f29812dab653e2e88c6ee989c972a343c97` frozen.
The result is **ANALYSIS_ONLY**. No accepted lossless subset exists and no `rules.conf` is emitted.

## Provenance

Official [update metadata](https://raw.githubusercontent.com/nakixii/Magisk_AsoulOpt/main/AsoulOpt.json) resolves `Kana` / `284`.
[Release](https://github.com/nakixii/Magisk_AsoulOpt/releases/tag/Kana), published 2026-09-18T20:24:34Z.
Asset `Magisk_AsoulOpt_Kana.zip`, 19491 bytes, ZIP SHA256 `c571df3301fba596bc4dd0fa799146602d216e6b45a72db52744cbbc964736b0`.
Upstream API digest: `sha256:c571df3301fba596bc4dd0fa799146602d216e6b45a72db52744cbbc964736b0`. ELF SHA256 `2ac898071119f31ee9080df4eebe2df86dbb67c7e8c4a5b405cbad6000766cf8`.
README and metadata are pinned to `2e2de695ca4887fc353a13f170e4220bf910671e` during each fresh acquisition.
Tool and reference hashes are retained in machine receipts; the proprietary ZIP/ELF is transient and never published.

## Historical recovery

**HISTORICAL_EXTRACTOR_NOT_FOUND.** A bounded script search and 44 retained archive inventories
(1,159 Python members checked) found an ELF import parser and recovered-CSV adapters, not the original rule extractor.
Original helpers were preserved in local evidence. The ELF helper hash and assumptions are recorded in
`reference/historical_search.json`. Its PT_LOAD/PT_DYNAMIC address-mapping approach is reused.
The new static constructor abstraction is restricted to the reviewed ELF fingerprint; unknown input produces
an explicit unqualified analysis receipt. It does not run the module or claim whole-daemon/device equivalence.

## Exact comparison

The pinned README support strings and recovered ELF declarations agree: **333 packages**.
The exact frozen factory baseline has **316 mappings / 27 profiles / 48 rules**.
There are **17 new mappings, 0 removals and 11 changed existing ordered pattern/category classifiers**.
These counts describe the classifier projection, not full semantic equality of the other 305 mappings.
The recovered model has **29 derived templates / 53 template rules / 954 instantiated thread rules**.
Package matching is substring based; four overlap cases and their actual first-match winners are in `zuiopt_diff.json`.
No numerical upstream CPU-mask equivalence has been established on SM8650.

| Changed package | Factory profile | Added/reclassified pattern |
| --- | --- | --- |
| `com.krafton.dndm` | G07 | `Thread-` → category 2 |
| `com.kurogame.mingchao` | G07 | `Thread-` → category 2 |
| `com.kurogame.wutheringwaves.global` | G07 | `Thread-` → category 2 |
| `com.pubg` | G07 | `Thread-` → category 2 |
| `com.rekoo.pubgm` | G04 | `RenderThread` → category 1; `GameThread` → category 2 |
| `com.roblox.client` | G05 | `FunctionMarshal` → category 2 |
| `com.tencent.ig` | G07 | `Thread-` → category 2 |
| `com.tencent.ngr` | G07 | `Thread-` → category 2 |
| `com.tencent.tmgp.codev` | G07 | `Thread-` → category 2 |
| `com.tencent.tmgp.nz` | G07 | `Thread-` → category 2 |
| `com.tencent.tmgp.pubgmhd` | G04 | `RenderThread` → category 1; `GameThread` → category 2 |

G04 splits: two PUBG mappings gain RenderThread/category 1 and GameThread/category 2.
All eight G07 mappings gain Thread-/category 2. G05 Roblox changes FunctionMarshal from category 1 to 2;
RBX Worker remains category 2. The other G01–G27 classifiers have unchanged ordered pattern/category pairs.
Every factory profile's package/template comparison is retained in `zuiopt_diff.json`.

**Mingchao is not semantically equal**: `com.kurogame.mingchao` and the global variant gain
`Thread-` in category 2, competing with GameThread for the category representative.

### New mappings

- `com.HoYoverse.Nap`
- `com.PanikArcade.CloverPit`
- `com.devsisters.ck`
- `com.devsisters.cos`
- `com.feimo.astralpartyjpn`
- `com.kingnet.gundam`
- `com.megacrit.sts2re`
- `com.mindblocks.blocks`
- `com.morizero.milthm`
- `com.netease.cfxf`
- `com.netease.ywzh`
- `com.nianticlabs.pokemongo`
- `com.racoondigi.jqys`
- `com.rawfury.kingdom2crowns`
- `com.tencent.rmcn`
- `com.wg.wowslegends`
- `jp.co.cygames.ShadowverseWorldsBeyond`

## Semantic audit and gate

`mode` accepts 0..2 and indexes device-topology-dependent mask tuples. Mode 2 enters a conditional WALT/pipeline
path and can fall back to 0. Exact numerical mask tuples and every resolver/config edge case remain unqualified.
These values cannot be renamed to Uperf modes.

`rt != 0` sets selected representatives to **SCHED_RR | SCHED_RESET_ON_FORK (0x40000002), priority 1**
via `sched_setscheduler`; rt=0 restores SCHED_OTHER/priority 0 when needed.
rt does **not** mean competition rank. Linux policy constants were checked against the Android NDK Linux header.
Scheduler/WALT/cpuset/service effects are intentionally outside current ZUIopt's rule model.

Normal competition is per category over cumulative schedstat time (stat utime+stime fallback), not one winner
per literal thread pattern. ZUIopt class/rank represents the ordinary projection. It is **not sufficient for the full model**:
`__DummyMain` demotes the first category-2 winner to default and reselects; `__DoubleMain` internally relabels
the first candidate and reselects for the C1 placement slot: original first gets C2 placement, second gets C1.
G23's literal marker/rank:1 rules cannot reproduce this two-mask selection faithfully.
ZUIopt's safe empty-candidate behavior is also an intentional deviation. Marker package lists are in the machine diff.

| Feature | Classification | Recovered meaning / limit |
| --- | --- | --- |
| package_matching | PRODUCT_DECISION_REQUIRED | Case-sensitive strstr; first linked-list hit, reverse constructor order; includes incomplete package strings |
| profile_templates | COMPATIBLE_WITH_DETERMINISTIC_TRANSFORM | 29 derived classifier templates; no source G01-G27 labels; default category 0 |
| thread_matching | COMPATIBLE_WITH_DETERMINISTIC_TRANSFORM | Case-sensitive strstr on proc task comm; pointer-key ordered first match, including empty catch-all |
| literal_thread_patterns | DIRECT_SCHEMA2_COMPATIBLE | Recovered ASCII thread names and empty pattern |
| default_cpu_masks | UNKNOWN_NEEDS_REVERSE_ENGINEERING | Mode indexes three 12-byte tuples at state+0x48; selectors resolve through topology table, then sched_setaffinity |
| cpu_mask_semantics | UNKNOWN_NEEDS_REVERSE_ENGINEERING | sched_setaffinity uses a 4-byte mask; selected category 1/2 and other tasks differ; mode/topology selects masks |
| multiple_same_name_and_ranking | COMPATIBLE_WITH_DETERMINISTIC_TRANSFORM | Competition across category, not independently per pattern; greatest cumulative CPU time from schedstat or utime+stime; ordinary categories select one representative |
| dummy_main_marker | COMPATIBLE_WITH_DETERMINISTIC_TRANSFORM | __DummyMain is a control marker: demote category-2 winner to category 0 then select category-2 again |
| empty_category_fallback | PRODUCT_DECISION_REQUIRED | Representative helper can return a non-category candidate if that category is absent; dummy-main demotion can leave too few category-2 candidates |
| double_main_marker | UNSUPPORTED_BY_ZUIOPT | __DoubleMain internally relabels the first category-2 candidate to category 1, then reselects category 2 for the C1 placement slot. Original first candidate keeps C2 placement; the second gets C1 placement. Normal C1 competition is bypassed |
| mode | UNSUPPORTED_BY_ZUIOPT | Validated integer 0..2; indexes topology-dependent mask tuple. Mode 2 has conditional fallback to 0 and WALT/pipeline path; meanings of numerical mask tuples remain unqualified |
| rt | UNSUPPORTED_BY_ZUIOPT | Any nonzero rt selects SCHED_RR(2)|SCHED_RESET_ON_FORK(0x40000000), priority 1, for selected category representatives. rt=0 uses SCHED_OTHER/priority 0 when restoring prior RT state |
| priority_and_scheduler_policy | UNSUPPORTED_BY_ZUIOPT | sched_setscheduler priority 1 or 0 and policy 0x40000002 or 0; rule category values are not scheduler priorities |
| kernel_scheduler_and_cpuset_controls | UNSUPPORTED_BY_ZUIOPT | WALT per-task boost/reduce-affinity/pipeline interfaces, /dev/cpuset/asopt, scheduler rt_runtime_us/rt_period_us paths observed |
| per_game_overrides | UNSUPPORTED_BY_ZUIOPT | Config grammar %127s %d %d stores package + mode + rt; per-game resolver uses first contains match, else global mode=%d and rt=%d; effective owner-device values not sampled |
| global_modes | UNSUPPORTED_BY_ZUIOPT | Global mode/rt defaults and overrides influence per-game state |
| uclamp_nice | UNKNOWN_NEEDS_REVERSE_ENGINEERING | No uclamp/nice/setpriority interface observed in qualified imports/strings; this is not a whole-daemon absence proof |
| module_service_side_effects | UNSUPPORTED_BY_ZUIOPT | service.sh writes core_ctl and migt parameters before daemon launch |
| new_unknown_opcodes_flags | UNKNOWN_NEEDS_REVERSE_ENGINEERING | Only one exact ELF fingerprint and bounded constructor are qualified. Future ELF/opcode/category/grammar changes halt extraction |

No previous accepted upstream acquisition existed at initialization; historical upstream changes are not invented.
Future runs compare against the previous accepted lab model as well as the frozen factory projection.
Missing digest, changed metadata during resolution, unknown binary/opcode/category/grammar, invalid archive or
inconsistent counts cannot produce a production pack. Analysis records every unsupported/unknown feature.

## Automation and review

The workflow resolves official metadata afresh, compares versionCode/tag/asset/digest to the last accepted input,
and emits `NO_UPSTREAM_CHANGE` without downloading the ZIP when unchanged. A manual full-acquisition run qualifies
publication before the weekly schedule is added. Run results are uploaded as derived-only artifacts and summarized
in GitHub Actions. `.github/qualification.json` records the successful manual run once available.
Initial local review outputs are marked `input_accepted=false`, so the first manual run performs acquisition in full.

Only tooling, neutral structured rules, provenance, compatibility and diffs are published.
No proprietary archive, binary, disassembly, ZuiControl source mirror, production online sync, build/flash or device change.
Gitee is **DEFERRED**. The lab does not block Frontend+Backend Integration.

Ready for owner compatibility review; further reverse engineering/product decisions are required before any production conversion.
