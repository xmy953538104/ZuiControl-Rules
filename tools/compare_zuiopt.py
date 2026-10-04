"""Compare declared and effective substring classifiers to the pinned factory projection."""
import json
from pathlib import Path

from fetch_asoulopt import require, sha256

BACKEND_HEAD = "6d896f29812dab653e2e88c6ee989c972a343c97"
REFERENCE_SHA256 = "fb8d782a663e5d2f7b2673c2f177a51ed19dbf450d3c929907888a4d3ae881af"


def reference(root):
    data = (Path(root) / "reference/zuiopt.json").read_bytes()
    require(sha256(data) == REFERENCE_SHA256, "frozen normalized reference changed")
    result = json.loads(data)
    require(result["backend_head"] == BACKEND_HEAD and len(result["packages"]) == 316 and
            len(result["profiles"]) == 27, "frozen reference identity/count mismatch")
    return result


def classifier(model, mapping):
    return [(r["pattern"], r["category"]) for r in model["templates"][mapping["template"]]]


def compare(model, baseline):
    local = baseline["packages"]
    result = dict(backend_head=BACKEND_HEAD, comparison_scope="ordered pattern/category projection; NOT full runtime equivalence",
                  local_package_count=len(local), local_profile_count=len(baseline["profiles"]),
                  source_sha256=baseline["source_sha256"], changed_cpu_masks="UNKNOWN: topology-derived upstream mode masks are not qualified",
                  full_runtime_equivalence=False)
    if not model["qualified"]:
        return result | dict(status="UNKNOWN_NEEDS_REVERSE_ENGINEERING", new_packages=None,
                             removed_packages=None, changed_mapping_count=None)
    upstream = {p["pattern"]: p for p in model["packages"]}
    changed, effective_changed, overlaps = [], [], []
    groups = {g: dict(packages=[], changed_packages=[], upstream_templates=[])
              for g in baseline["profiles"]}
    for pkg, mapping in local.items():
        group = groups[mapping["profile"]]
        group["packages"].append(pkg)
        if pkg not in upstream:
            continue
        rules = baseline["profiles"][mapping["profile"]]["rules"]
        before = [(r["pattern"], int(r["class_"][1:])) for r in rules]
        after = classifier(model, upstream[pkg])
        group["upstream_templates"].append(upstream[pkg]["template"])
        if before != after:
            changed.append(dict(package=pkg, baseline_profile=mapping["profile"],
                                before=before, after=after,
                                added=[r for r in after if r not in before],
                                removed=[r for r in before if r not in after]))
            group["changed_packages"].append(pkg)
        candidates = [p for p in model["packages"] if p["pattern"] in pkg]
        require(candidates, "declared package has no effective match")
        winner = candidates[0]
        if len(candidates) > 1:
            overlaps.append(dict(package=pkg, winner=winner["pattern"],
                                 matches=[p["pattern"] for p in candidates]))
        if before != classifier(model, winner):
            effective_changed.append(pkg)
    for group in groups.values():
        group["upstream_templates"] = sorted(set(group["upstream_templates"]))
    markers = {}
    for marker in ("__DummyMain", "__DoubleMain"):
        markers[marker] = sorted(p["pattern"] for p in model["packages"]
                                if any(r["pattern"] == marker for r in model["templates"][p["template"]]))
    ming = next(x for x in changed if x["package"] == "com.kurogame.mingchao")
    return result | dict(status="STATIC_PROJECTION_DIFF", upstream_package_count=len(upstream),
                         new_packages=sorted(upstream.keys() - local.keys()),
                         removed_packages=sorted(local.keys() - upstream.keys()),
                         changed_mapping_count=len(changed), changed_package_mappings=changed,
                         effective_changed_mapping_count=len(effective_changed),
                         effective_changed_packages=effective_changed, package_overlaps=overlaps,
                         profile_diff=groups, marker_packages=markers,
                         mingchao=dict(semantically_equal=False, change=ming,
                                       reason="Added Thread- category 2; shares category-2 competition with GameThread; mode/rt also not representable"))


def upstream_diff(previous, model):
    if not previous or not previous.get("qualified"):
        return dict(status="NO_PREVIOUS_ACCEPTED_UPSTREAM", new_packages=None,
                    removed_packages=None, changed_packages=None,
                    note="Initial lab acquisition; factory comparison is separately in zuiopt_diff.json")
    if not model["qualified"]:
        return dict(status="UNQUALIFIED_CURRENT_UPSTREAM", new_packages=None,
                    removed_packages=None, changed_packages=None)
    before = {p["pattern"]: classifier(previous, p) for p in previous["packages"]}
    after = {p["pattern"]: classifier(model, p) for p in model["packages"]}
    return dict(status="COMPARED", previous_binary_sha256=previous["binary_sha256"],
                current_binary_sha256=model["binary_sha256"],
                new_packages=sorted(after.keys() - before.keys()),
                removed_packages=sorted(before.keys() - after.keys()),
                changed_packages=[dict(package=p, before=before[p], after=after[p])
                                  for p in sorted(before.keys() & after.keys()) if before[p] != after[p]],
                order_changed=[p["pattern"] for p in previous["packages"]] !=
                              [p["pattern"] for p in model["packages"]],
                runtime_semantics_comparison="Only reviewed fingerprint semantics; unknown new fingerprints require manual reverse engineering")
