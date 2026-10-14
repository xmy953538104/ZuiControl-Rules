"""Trust-boundary and semantic regression checks; no module execution or network."""
import io
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

from analyze_compatibility import analyze
from compare_zuiopt import compare, reference
from extract_asoulopt import ELF, extract
from fetch_asoulopt import identity, sha256, unpack_module
from run import ROOT, encode, unchanged, validate


class LabTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.model = json.loads((ROOT / "analysis/latest.json").read_bytes())
        acquisition = ROOT / "analysis/acquisition.json"
        cls.latest = json.loads((acquisition if acquisition.exists() else ROOT / "output/latest.json").read_bytes())
        cls.baseline = reference(ROOT)

    def test_semantic_diff_and_reproducibility(self):
        diff = compare(self.model, self.baseline)
        comp = analyze(self.latest["upstream"], self.model, diff)
        validate(self.model, diff, comp)
        self.assertEqual(json.loads(encode(diff)), json.loads((ROOT / "analysis/zuiopt_diff.json").read_bytes()))
        self.assertEqual(json.loads(encode(comp)), json.loads((ROOT / "analysis/compatibility.json").read_bytes()))
        self.assertEqual(sha256(encode(self.model)), self.latest["analysis_model_sha256"])
        if self.model["qualified"]:
            self.assertEqual(diff["changed_mapping_count"], 11)
            self.assertEqual(diff["mingchao"]["change"]["added"], [("Thread-", 2)])
            self.assertIn("SCHED_RR", comp["rt_semantics"])
            self.assertFalse(comp["rank_class_sufficient"])
            self.assertTrue(diff["marker_packages"]["__DoubleMain"])

    def test_fail_closed_unknown_binary_and_elf_bounds(self):
        with tempfile.TemporaryDirectory() as workdir:
            unknown = extract(b"future-unreviewed-ELF", workdir, "must-not-be-called")
        self.assertFalse(unknown["qualified"])
        self.assertEqual(unknown["status"], "UNKNOWN_NEEDS_REVERSE_ENGINEERING")
        with self.assertRaises(ValueError):
            ELF(b"\x7fELF\x02\x01")
        diff = compare(unknown, self.baseline)
        comp = analyze(self.latest["upstream"], unknown, diff)
        self.assertFalse(comp["lossless"])
        self.assertFalse(comp["production_rules_output"])

    def test_digest_and_archive_traversal_rejected(self):
        data = io.BytesIO()
        with zipfile.ZipFile(data, "w") as archive:
            archive.writestr("../outside", "unsafe")
            archive.writestr("AsoulOpt", "unused")
            archive.writestr("module.prop", "unused")
        raw = data.getvalue()
        meta = dict(asset_size=len(raw), upstream_digest="sha256:" + sha256(raw))
        with self.assertRaisesRegex(ValueError, "unsafe ZIP path"):
            unpack_module(raw, meta)
        meta["upstream_digest"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(ValueError, "SHA256 mismatch"):
            unpack_module(raw, meta)

    def test_unchanged_and_asset_replacement(self):
        meta = self.latest["upstream"]
        accepted = dict(input_accepted=True, upstream=meta)
        self.assertTrue(unchanged(accepted, meta))
        self.assertFalse(unchanged(dict(input_accepted=False, upstream=meta), meta))
        for field, value in (("upstream_digest", "sha256:" + "0" * 64), ("asset_id", -1),
                             ("tag", "next"), ("version_code", meta["version_code"] + 1)):
            self.assertFalse(unchanged(accepted, dict(meta, **{field: value})))
        self.assertEqual(identity(meta), identity(dict(meta, download_sha256="different receipt")))

    def test_publication_gate(self):
        self.assertEqual(self.latest["status"], "ANALYSIS_ONLY")
        self.assertFalse(self.latest["lossless"])
        self.assertIsNone(self.latest["accepted_supported_subset"])
        if (ROOT / "output/rules.conf").exists():
            from publish_runtime import read_manifest,validate
            model=validate(read_manifest(ROOT/'output/latest.json'),(ROOT/'output/rules.conf').read_bytes())
            self.assertEqual(model['schema'],3)
            self.assertEqual((model['mode'],model['rt']),(0,0))
            self.assertTrue(all(p['runtime'][:2]==(-1,-1) for p in model['profiles'].values()))
        for folder in ("analysis", "output", "history", "reference", "tools"):
            for path in (ROOT / folder).rglob("*"):
                if path.is_file() and "__pycache__" not in path.parts:
                    self.assertNotIn(path.suffix.lower(), (".zip", ".elf", ".bin"))
                    self.assertNotEqual(path.name, "AsoulOpt")


if __name__ == "__main__":
    unittest.main()
