"""Explicit feature-level gate. No accepted lossless subset exists in R1."""

DIRECT = "DIRECT_SCHEMA2_COMPATIBLE"
TRANSFORM = "COMPATIBLE_WITH_DETERMINISTIC_TRANSFORM"
DECISION = "PRODUCT_DECISION_REQUIRED"
UNSUPPORTED = "UNSUPPORTED_BY_ZUIOPT"
UNKNOWN = "UNKNOWN_NEEDS_REVERSE_ENGINEERING"


def analyze(meta, model, diff):
    features = []

    def feature(name, classification, upstream, schema2, evidence=None):
        features.append(dict(feature=name, classification=classification,
                             upstream=upstream, schema2=schema2, evidence=evidence))

    if not model["qualified"]:
        feature("unreviewed_binary", UNKNOWN, model["reason"], "No conversion permitted")
    else:
        e = model["semantic_evidence"]
        feature("package_matching", DECISION,
                "Case-sensitive strstr; first linked-list hit, reverse constructor order; includes incomplete package strings",
                "contains exists, but accepted factory uses exact mappings and authoritative package/UID boundaries. Widening requires owner decision", e["package_match"])
        feature("profile_templates", TRANSFORM,
                "29 derived classifier templates; no source G01-G27 labels; default category 0",
                "Content deduplication and explicit priorities can preserve classifier ordering")
        feature("thread_matching", TRANSFORM,
                "Case-sensitive strstr on proc task comm; pointer-key ordered first match, including empty catch-all",
                "contains plus priorities assigned by recovered pointer order; exact/prefix/glob not observed upstream", e["thread_match"])
        feature("literal_thread_patterns", DIRECT,
                "Recovered ASCII thread names and empty pattern", "Quoted contains patterns are expressible")
        feature("default_cpu_masks", UNKNOWN,
                "Mode indexes three 12-byte tuples at state+0x48; selectors resolve through topology table, then sched_setaffinity",
                "Factory general 2-6, C1 2-4, C2 7 on SM8650; upstream numerical tuple on this topology not proven", e["mode"])
        feature("cpu_mask_semantics", UNKNOWN,
                "sched_setaffinity uses a 4-byte mask; selected category 1/2 and other tasks differ; mode/topology selects masks",
                "Explicit CPU 0..7 sets supported; no qualified topology/mode-to-mask transform", "0x4fc0..0x50ac; 0x7c88..0x7cf4")
        feature("multiple_same_name_and_ranking", TRANSFORM,
                "Competition across category, not independently per pattern; greatest cumulative CPU time from schedstat or utime+stime; ordinary categories select one representative",
                "Shared class and rank:1 use cumulative schedstat/ticks with ascending-TID tie break. Projection only; empty-class fallback is an intentional ZUIopt deviation", e["ranking"])
        feature("dummy_main_marker", TRANSFORM,
                "__DummyMain is a control marker: demote category-2 winner to category 0 then select category-2 again",
                "C2 rank:2 approximates non-empty multi-candidate case; empty/one-candidate fallback differs; marker is not an ordinary name rule", e["dummy_main"])
        feature("empty_category_fallback", DECISION,
                "Representative helper can return a non-category candidate if that category is absent; dummy-main demotion can leave too few category-2 candidates",
                "ZUIopt explicitly returns no representative when rank exceeds candidate count. Preserve the safe deviation; do not call it lossless", e["ranking"])
        feature("double_main_marker", UNSUPPORTED,
                "__DoubleMain internally relabels the first category-2 candidate to category 1, then reselects category 2 for the C1 placement slot. Original first candidate keeps C2 placement; the second gets C1 placement. Normal C1 competition is bypassed",
                "Cannot faithfully split one pattern's ranked candidates across two masks with class-consistent rank/mask. Current G23 patterns alone do not encode this", e["double_main"])
        feature("mode", UNSUPPORTED,
                "Validated integer 0..2; indexes topology-dependent mask tuple. Mode 2 has conditional fallback to 0 and WALT/pipeline path; meanings of numerical mask tuples remain unqualified",
                "No mode field or WALT operations; cannot map to Uperf modes", e["mode"])
        feature("rt", UNSUPPORTED,
                "Any nonzero rt selects SCHED_RR(2)|SCHED_RESET_ON_FORK(0x40000000), priority 1, for selected category representatives. rt=0 uses SCHED_OTHER/priority 0 when restoring prior RT state",
                "No realtime/scheduler writes. rt is not competition rank", e["realtime"])
        feature("priority_and_scheduler_policy", UNSUPPORTED,
                "sched_setscheduler priority 1 or 0 and policy 0x40000002 or 0; rule category values are not scheduler priorities",
                "Rule priority controls classifier precedence only; no task scheduler policy", e["realtime"])
        feature("kernel_scheduler_and_cpuset_controls", UNSUPPORTED,
                "WALT per-task boost/reduce-affinity/pipeline interfaces, /dev/cpuset/asopt, scheduler rt_runtime_us/rt_period_us paths observed",
                "Intentionally not implemented by ZUIopt; exact full kernel write sequence remains outside qualified affinity projection")
        feature("per_game_overrides", UNSUPPORTED,
                "Config grammar %127s %d %d stores package + mode + rt; per-game resolver uses first contains match, else global mode=%d and rt=%d; effective owner-device values not sampled",
                "No per-game mode/rt fields. Resolver edge cases and reload timing not claimed equivalent", "0x38b0..0x3ef0; config formats recovered from ELF")
        feature("global_modes", UNSUPPORTED,
                "Global mode/rt defaults and overrides influence per-game state",
                "No global AsoulOpt mode/rt authority; effective runtime configuration is unknown")
        feature("uclamp_nice", UNKNOWN,
                "No uclamp/nice/setpriority interface observed in qualified imports/strings; this is not a whole-daemon absence proof",
                "No uclamp/nice fields or operations")
        feature("module_service_side_effects", UNSUPPORTED,
                "service.sh writes core_ctl and migt parameters before daemon launch",
                "Module installation/service behavior not representable in a rules pack")
        feature("new_unknown_opcodes_flags", UNKNOWN,
                "Only one exact ELF fingerprint and bounded constructor are qualified. Future ELF/opcode/category/grammar changes halt extraction",
                "Unknown data is never silently discarded")
    blockers = [f for f in features if f["classification"] in (DECISION, UNSUPPORTED, UNKNOWN)]
    return dict(upstream=meta, package_count=model.get("package_count"),
                profile_template_count=model.get("template_count"),
                thread_rule_count=model.get("thread_rule_count"),
                instantiated_thread_rule_count=model.get("instantiated_thread_rule_count"),
                backend_head=diff["backend_head"], extraction_qualified=model["qualified"],
                new_packages=diff.get("new_packages"), removed_packages=diff.get("removed_packages"),
                changed_package_mappings=diff.get("changed_package_mappings"),
                changed_thread_patterns=diff.get("changed_package_mappings"),
                changed_cpu_masks=diff["changed_cpu_masks"],
                new_rule_fields=["global mode", "global rt", "per-game mode", "per-game rt"],
                mode_semantics=next((f["upstream"] for f in features if f["feature"] == "mode"), UNKNOWN),
                rt_semantics=next((f["upstream"] for f in features if f["feature"] == "rt"), UNKNOWN),
                features=features, unsupported=blockers, lossless=False,
                lossless_schema2_compatibility="NO", accepted_supported_subset=None,
                rank_class_sufficient=False, production_rules_output=False, status="ANALYSIS_ONLY")
