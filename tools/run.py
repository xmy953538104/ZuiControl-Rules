"""Fresh reviewed acquisition -> canonical Schema3 publication; historical analysis retained."""
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




def run(args):
    from convert_runtime import compile_rules
    from publish_runtime import CAPABILITIES, publish
    import subprocess
    acquisition = ROOT / "analysis/acquisition.json"
    legacy = ROOT / "output/latest.json"
    previous_output = json.loads(acquisition.read_bytes()) if acquisition.exists() else None
    if previous_output is None and legacy.exists():
        value = json.loads(legacy.read_bytes())
        if value.get("status") == "ANALYSIS_ONLY":
            previous_output = value
            archived = ROOT / "history/cloud-schema3-migration/latest-analysis.json"
            if not archived.exists():
                archived.parent.mkdir(parents=True, exist_ok=True)
                archived.write_bytes(legacy.read_bytes())
    meta = resolve()
    checked_at = datetime.now(timezone.utc).isoformat()
    hashes = {path.name: sha256(path.read_bytes()) for path in sorted((ROOT / "tools").glob("*.py"))}
    previous_path = ROOT / "analysis/latest.json"
    cached = json.loads(previous_path.read_bytes()) if previous_path.exists() else None
    reuse = (unchanged(previous_output, meta) and cached is not None and
             sha256(encode(cached)) == previous_output.get("analysis_model_sha256") and
             previous_output.get("tool_sha256") == hashes and "runtime_masks_sm8650" in cached)
    if reuse:
        model = cached
        meta = {**previous_output["upstream"], **meta}
        acquired = False
    else:
        binary, meta, readme_packages = download(meta)
        with tempfile.TemporaryDirectory(prefix="asoulopt-lab-") as workdir:
            objdump = args.objdump or shutil.which("llvm-objdump")
            require(objdump is not None, "LLVM objdump required; no module execution")
            model = extract(binary, workdir, objdump)
        if model["qualified"]:
            require(len(readme_packages) == len(set(readme_packages)) == model["package_count"] and
                    set(readme_packages) == {p["pattern"] for p in model["packages"]},
                    "pinned README/recovered ELF package corpus disagree")
        acquired = True
    baseline = reference(ROOT)
    diff = compare(model, baseline);comp = analyze(meta, model, diff)
    validate(model, diff, comp)  # This comparison is against the immutable historical Backend.
    accepted = model["qualified"] and not args.local_review
    latest = dict(status="ANALYSIS_ONLY", input_accepted=accepted, upstream=meta,
                  extraction_qualified=model["qualified"], lossless=False,
                  production_rules_output=False, accepted_supported_subset=None,
                  package_count=model.get("package_count"), template_count=model.get("template_count"),
                  tool_sha256=hashes, reference_sha256=sha256((ROOT / "reference/zuiopt.json").read_bytes()),
                  analysis_model_sha256=sha256(encode(model)))
    files = {"analysis/acquisition.json":latest,"analysis/latest.json":model,
             "analysis/compatibility.json":comp,"analysis/zuiopt_diff.json":diff,
             "analysis/unsupported_features.json":dict(lossless=False,features=comp["unsupported"])}
    if acquired:
        files["analysis/upstream_diff.json"] = upstream_diff(cached, model)
    receipt = dict(result="LOCAL_REVIEW" if args.local_review else "UNQUALIFIED_UPSTREAM",
                   checked_at=checked_at, upstream=meta, input_accepted=accepted,
                   zip_downloaded=acquired, extraction_qualified=model["qualified"],
                   model_sha256=sha256(encode(model)),tool_sha256=hashes,
                   production_rules_output=False,source_changed=False)
    if model["qualified"]:
        rules, conversion = compile_rules(model, [], CAPABILITIES)
        files["analysis/runtime-conversion.json"] = {**conversion,
            "publication":"CLOUD_SCHEMA3_OWNER_AUTHORIZED", "device_feed_enabled":False,
            "binary_sha256":model["binary_sha256"],"model_sha256":sha256(encode(model)),
            "rules_schema":3,"converter_rules_sha256":sha256(rules)}
        if not args.local_review:
            commit = subprocess.check_output(["git","rev-parse","HEAD"],cwd=ROOT,text=True).strip()
            publication = publish(ROOT/"output",rules,meta,commit)
            receipt.update(result=publication["result"],manifest=publication["manifest"],production_rules_output=True)
    for name,value in files.items():
        path=ROOT/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(encode(value))
    (ROOT / ".run_receipt.json").write_bytes(encode(receipt))
    print(json.dumps(receipt,sort_keys=True))
    require(model["qualified"],"unqualified upstream; last published Schema3 preserved")
    return receipt


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--objdump", help="Host LLVM objdump executable")
    parser.add_argument("--local-review", action="store_true", help="Do not accept input before manual workflow qualification")
    run(parser.parse_args())
