"""Fresh acquisition -> bounded recovery -> consistent analysis-only publication."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import tempfile

from analyze_compatibility import analyze
from compare_zuiopt import compare, reference, upstream_diff
from extract_asoulopt import extract
from fetch_asoulopt import download, identity, require, resolve, sha256

ROOT = Path(__file__).resolve().parents[1]


def encode(value):
    return (json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode()


def unchanged(previous, meta):
    return bool(previous and previous.get("input_accepted") and
                identity(previous["upstream"]) == identity(meta))


def validate(model, diff, compatibility):
    require(compatibility["status"] == "ANALYSIS_ONLY" and not compatibility["lossless"] and
            not compatibility["production_rules_output"], "R1 production publication gate violated")
    if model["qualified"]:
        require(model["package_count"] == len(model["packages"]) == 333 and
                model["template_count"] == len(model["templates"]) == 29,
                "model count inconsistency")
        require(diff["local_package_count"] == 316 and
                diff["changed_mapping_count"] == diff["effective_changed_mapping_count"] == 11 and
                len(diff["new_packages"]) == 17 and not diff["removed_packages"],
                "reviewed baseline diff changed unexpectedly")
        require(not diff["mingchao"]["semantically_equal"], "Mingchao gate inconsistent")
        require(any(f["feature"] == "rt" and f["classification"] == "UNSUPPORTED_BY_ZUIOPT"
                    for f in compatibility["unsupported"]), "rt was silently dropped")


def report(meta, model, diff, comp):
    header = f"""# AsoulOpt upstream automation and compatibility R1

This independent public lab keeps ZuiControl Backend `{diff['backend_head']}` frozen.
The result is **ANALYSIS_ONLY**. No accepted lossless subset exists and no `rules.conf` is emitted.

## Provenance

Official [update metadata]({meta['metadata_url']}) resolves `{meta['version']}` / `{meta['version_code']}`.
[Release](https://github.com/{meta['repository']}/releases/tag/{meta['tag']}), published {meta['release_published_at']}.
Asset `{meta['asset_name']}`, {meta['asset_size']} bytes, ZIP SHA256 `{meta['download_sha256']}`.
Upstream API digest: `{meta['upstream_digest']}`. ELF SHA256 `{meta['binary_sha256']}`.
README and metadata are pinned to `{meta['metadata_commit']}` during each fresh acquisition.
Tool and reference hashes are retained in machine receipts; the proprietary ZIP/ELF is transient and never published.

## Historical recovery

**HISTORICAL_EXTRACTOR_NOT_FOUND.** A bounded script search and 44 retained archive inventories
(1,159 Python members checked) found an ELF import parser and recovered-CSV adapters, not the original rule extractor.
Original helpers were preserved in local evidence. The ELF helper hash and assumptions are recorded in
`reference/historical_search.json`. Its PT_LOAD/PT_DYNAMIC address-mapping approach is reused.
The new static constructor abstraction is restricted to the reviewed ELF fingerprint; unknown input produces
an explicit unqualified analysis receipt. It does not run the module or claim whole-daemon/device equivalence.

"""
    if not model["qualified"]:
        return header + "## Unqualified input\n\n" + model["reason"] + "\n\nOwner reverse-engineering review required.\n"
    changed = "\n".join(f"| `{x['package']}` | {x['baseline_profile']} | "
                        + "; ".join(f"`{p}` → category {c}" for p, c in x['added']) + " |"
                        for x in diff["changed_package_mappings"])
    feature_rows = "\n".join(f"| {f['feature']} | {f['classification']} | {f['upstream']} |"
                            for f in comp["features"])
    new = "\n".join("- `" + pkg + "`" for pkg in diff["new_packages"])
    return header + f"""## Exact comparison

The pinned README support strings and recovered ELF declarations agree: **333 packages**.
The exact frozen factory baseline has **316 mappings / 27 profiles / 48 rules**.
There are **17 new mappings, 0 removals and 11 changed existing ordered pattern/category classifiers**.
These counts describe the classifier projection, not full semantic equality of the other 305 mappings.
The recovered model has **29 derived templates / 53 template rules / 954 instantiated thread rules**.
Package matching is substring based; four overlap cases and their actual first-match winners are in `zuiopt_diff.json`.
No numerical upstream CPU-mask equivalence has been established on SM8650.

| Changed package | Factory profile | Added/reclassified pattern |
| --- | --- | --- |
{changed}

G04 splits: two PUBG mappings gain RenderThread/category 1 and GameThread/category 2.
All eight G07 mappings gain Thread-/category 2. G05 Roblox changes FunctionMarshal from category 1 to 2;
RBX Worker remains category 2. The other G01–G27 classifiers have unchanged ordered pattern/category pairs.
Every factory profile's package/template comparison is retained in `zuiopt_diff.json`.

**Mingchao is not semantically equal**: `com.kurogame.mingchao` and the global variant gain
`Thread-` in category 2, competing with GameThread for the category representative.

### New mappings

{new}

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
{feature_rows}

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
"""


def run(args):
    require(not (ROOT / "output/rules.conf").exists(), "Unexpected production rules output; manual review required")
    output = ROOT / "output/latest.json"
    previous_output = json.loads(output.read_bytes()) if output.exists() else None
    meta = resolve()
    checked_at = datetime.now(timezone.utc).isoformat()
    if unchanged(previous_output, meta):
        receipt = dict(result="NO_UPSTREAM_CHANGE", checked_at=checked_at,
                       upstream=meta, accepted_identity=identity(previous_output["upstream"]),
                       zip_downloaded=False, source_changed=False)
    else:
        binary, meta, readme_packages = download(meta)
        baseline = reference(ROOT)
        previous_path = ROOT / "analysis/latest.json"
        previous = json.loads(previous_path.read_bytes()) if (previous_output and
                     previous_output.get("input_accepted") and previous_path.exists()) else None
        with tempfile.TemporaryDirectory(prefix="asoulopt-lab-") as workdir:
            objdump = args.objdump or shutil.which("llvm-objdump")
            require(objdump is not None, "LLVM objdump required; no downloaded module is ever executed")
            model = extract(binary, workdir, objdump)
        if model["qualified"]:
            require(len(readme_packages) == len(set(readme_packages)) == model["package_count"] and
                    set(readme_packages) == {p["pattern"] for p in model["packages"]},
                    "pinned README and recovered ELF package corpus disagree")
        diff = compare(model, baseline)
        comp = analyze(meta, model, diff)
        validate(model, diff, comp)
        prior_diff = upstream_diff(previous, model)
        hashes = {path.name: sha256(path.read_bytes()) for path in sorted((ROOT / "tools").glob("*.py"))}
        accepted = model["qualified"] and not args.local_review
        latest = dict(status="ANALYSIS_ONLY", input_accepted=accepted, upstream=meta,
                      extraction_qualified=model["qualified"], lossless=False,
                      production_rules_output=False, accepted_supported_subset=None,
                      package_count=model.get("package_count"), template_count=model.get("template_count"),
                      tool_sha256=hashes, reference_sha256=sha256((ROOT / "reference/zuiopt.json").read_bytes()),
                      analysis_model_sha256=sha256(encode(model)))
        files = {"output/latest.json": latest, "analysis/latest.json": model,
                 "analysis/compatibility.json": comp, "analysis/zuiopt_diff.json": diff,
                 "analysis/upstream_diff.json": prior_diff,
                 "analysis/unsupported_features.json": dict(lossless=False, features=comp["unsupported"])}
        history = f"history/{meta['version_code']}-{meta['download_sha256'][:12]}"
        if not (ROOT / history).exists() or (args.local_review and not (
                previous_output and previous_output.get("input_accepted"))):
            files[history + "/metadata.json"] = dict(upstream=meta, tool_sha256=hashes,
                                                     extractor=model.get("extractor_version"),
                                                     model_sha256=sha256(encode(model)))
            files[history + "/compatibility.json"] = comp
            files[history + "/diff.json"] = dict(upstream=prior_diff, zuiopt=diff)
        # Publish only after every extraction/provenance/compatibility check above succeeds.
        for name, value in files.items():
            path = ROOT / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(encode(value))
        (ROOT / "ASOULOPT_UPSTREAM_AUTOMATION_COMPATIBILITY_R1.md").write_bytes(
            report(meta, model, diff, comp).encode("utf8"))
        receipt = dict(result="ANALYSIS_ONLY" if model["qualified"] else "UNQUALIFIED_UPSTREAM",
                       checked_at=checked_at, upstream=meta, input_accepted=accepted,
                       zip_downloaded=True, extraction_qualified=model["qualified"],
                       model_sha256=sha256(encode(model)), tool_sha256=hashes,
                       package_count=model.get("package_count"), lossless=False,
                       production_rules_output=False, source_changed=False)
    (ROOT / ".run_receipt.json").write_bytes(encode(receipt))
    print(json.dumps(receipt, sort_keys=True))
    return receipt


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--objdump", help="Host LLVM objdump executable")
    parser.add_argument("--local-review", action="store_true", help="Do not accept input before manual workflow qualification")
    run(parser.parse_args())
