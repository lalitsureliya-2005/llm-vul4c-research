"""End-to-end and unit tests for the multi-model evaluation pipeline.

No network, GPU, Docker, or real benchmark is needed: a tiny fake Vul4C case is
written to a temp directory and Docker is replaced by a simulated executor that
behaves like the Vul4C tool (exploit crashes unless the fix is present).
"""

import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from pipeline import run_experiment as rx
from pipeline.llm_clients import (
    AnthropicClient, GeminiClient, GenerationResult, LLMClient, LLMClientError,
    OpenAIClient, build_client,
)
from pipeline.metrics import detection_metrics, pass_at_k, repair_metrics
from pipeline.patch_manager import extract_regions, parse_region_answers, splice_regions
from pipeline.vul4c_runner import CaseSandbox, CommandResult, SandboxConfig, calibration_from

OLD = """#include <string.h>

static int helper(int x)
{
    return x * 2;
}

int parse_header(const char *buf, int n)
{
    char tmp[8];
    memcpy(tmp, buf, n);
    return tmp[0];
}

int main_entry(void)
{
    return helper(3);
}
"""
NEW = OLD.replace("    memcpy(tmp, buf, n);\n", "    if (n > 8)\n        return -1;\n    memcpy(tmp, buf, n);\n")
FIX_MARKER = "+    if (n > 8)"


def write_fake_benchmark(root: Path) -> None:
    case = root / "demo" / "CVE-2099-0001"
    case.mkdir(parents=True)
    (case / "CVE-2099-0001_CWE-787_foo.c_OLD.c").write_text(OLD)
    (case / "CVE-2099-0001_CWE-787_foo.c_NEW.c").write_text(NEW)
    import difflib
    diff = "".join(difflib.unified_diff(OLD.splitlines(True), NEW.splitlines(True), "a/src/foo.c", "b/src/foo.c"))
    (case / "CVE-2099-0001_CWE-787_foo.c.diff").write_text(diff)
    (case / "README.txt").write_text("Affected version: 1.0\n==1==ERROR: AddressSanitizer: stack-buffer-overflow\n")


class FakeDocker:
    """Simulates `docker` + the vul4c CLI inside a container (reproduce/test always exit 0, like vul4c)."""

    def __init__(self):
        import base64 as _b64
        self._b64 = _b64
        self.uploads = {}
        self.fixed = False
        self.broken = False
        self.calls = []

    def __call__(self, argv, timeout, input_text=None):
        import re as _re
        self.calls.append(argv)
        cmd = argv[-1] if argv[1] == "exec" else " ".join(argv[1:])
        if argv[1] in ("run", "rm", "network"):
            return CommandResult(0, "ok", 0.01)
        if cmd.startswith("base64 -d > "):
            self.uploads[cmd[len("base64 -d > "):].strip("'")] = self._b64.b64decode(input_text)
            return CommandResult(0, "", 0.01)
        if "pristine_backup" in cmd and cmd.startswith("rm -rf") and "/case" in cmd.split("&&")[0]:
            self.fixed = self.broken = False  # restore pristine checkout
            return CommandResult(0, "", 0.01)
        if "sha256sum" in cmd:
            m = _re.search(r"cp (\S+) \"\$f\"", cmd)
            data = self.uploads.get(m.group(1).strip("'"), b"")
            self.fixed = self.fixed or b"if (n > 8)" in data
            self.broken = self.broken or b"BROKEN" in data
            return CommandResult(0, "VUL4C_EVAL: replaced src/foo.c", 0.01)
        if cmd.startswith("vul4c compile"):
            return CommandResult(1 if self.broken else 0, "error: expected ';'" if self.broken else "build ok", 0.01)
        if cmd.startswith("vul4c reproduce"):
            out = "program exited normally" if self.fixed else "==7==ERROR: AddressSanitizer: stack-buffer-overflow"
            return CommandResult(0, out, 0.01)
        if cmd.startswith("vul4c test"):
            return CommandResult(0, "PASS: t1\n# TOTAL: 4\n# PASS:  4\n# FAIL:  0\n# ERROR: 0\n", 0.01)
        return CommandResult(0, "", 0.01)


class ScriptedClient(LLMClient):
    """Fake model returning a fixed answer per task."""

    provider = "scripted"

    def __init__(self, spec):
        super().__init__(spec)
        self.answers = spec["answers"]

    def generate(self, messages, max_tokens, temperature=0.0, response_prefix="",
                 stop_on_json_close=False, context=None):
        is_detection = "is_vulnerable" in messages[-1]["content"]
        return GenerationResult(text=self.answers["detection" if is_detection else "repair"],
                                prompt_tokens=10, completion_tokens=5)


def factory(spec):
    return ScriptedClient(spec) if spec["provider"] == "scripted" else build_client(spec)


class TestEndToEndPipeline(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        write_fake_benchmark(self.tmp / "bench")
        broken_fix = NEW.replace("return -1;", "return -1 BROKEN")
        bad_region = "int parse_header(const char *buf, int n)\n{\n    char tmp[8];\n    strcpy(tmp, buf);\n    return tmp[0];\n}\n"
        self.cfg = rx._merge(rx.DEFAULTS, {
            "experiment_name": "t", "output_dir": str(self.tmp / "out"),
            "benchmark_root": str(self.tmp / "bench"), "cases": ["demo/CVE-2099-0001"],
            "static_analysis": {"enabled": True, "tools": ["cppcheck", "flawfinder"]},
            "models": [
                {"name": "oracle", "provider": "oracle"},
                {"name": "identity", "provider": "identity"},
                {"name": "broken", "provider": "scripted", "answers": {
                    "detection": "not json at all",
                    "repair": "```c\n" + "".join(broken_fix.splitlines(True)[7:13]) + "```"}},
                {"name": "unsafe", "provider": "scripted", "answers": {
                    "detection": '{"is_vulnerable": true, "cwe": "CWE-120", "evidence": null, "reasoning": "r"}',
                    "repair": "```c\n" + bad_region + "```"}},
            ],
        })
        self.out = Path(self.cfg["output_dir"]) / "t"
        self.out.mkdir(parents=True)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_full_pipeline(self):
        cases, skipped = rx.prepare_cases(self.cfg)
        self.assertEqual(len(cases), 1, skipped)
        self.assertEqual(cases[0].regions[0].kind, "function")
        self.assertIn("parse_header", cases[0].regions[0].old_code)
        self.assertNotIn("helper", cases[0].regions[0].old_code)

        rx.run_generation(self.cfg, cases, self.out, client_factory=factory)
        gens = rx.read_jsonl(self.out / "generations.jsonl")
        self.assertEqual(len(gens), 4 * 3)  # 4 models x (2 detection + 1 repair)

        # Resumability: second run adds nothing
        rx.run_generation(self.cfg, cases, self.out, client_factory=factory)
        self.assertEqual(len(rx.read_jsonl(self.out / "generations.jsonl")), 12)

        fake = FakeDocker()
        rx.run_evaluation(self.cfg, cases, self.out,
                          sandbox_factory=lambda c, cve: CaseSandbox(c, cve, executor=fake))
        cal = rx.read_jsonl(self.out / "calibration.jsonl")
        self.assertTrue(cal[0]["calibrated"], cal[0]["reasons"])

        evs = {e["model"]: e for e in rx.read_jsonl(self.out / "evaluations.jsonl")}
        self.assertTrue(evs["oracle"]["secure_and_functional"])
        self.assertTrue(evs["oracle"]["identical_to_reference"])
        self.assertEqual(evs["identity"]["exploit_outcome"], "crash")
        self.assertFalse(evs["identity"]["changed"])
        self.assertFalse(evs["broken"]["compiled"])
        self.assertEqual(evs["broken"]["status"], "compile_failed")
        # 'unsafe' removes memcpy but adds strcpy: exploit "blocked" in the fake, yet static analysis flags it
        if shutil.which("flawfinder") or shutil.which("cppcheck"):
            self.assertGreater(evs["unsafe"]["static"]["introduced_count"], 0)

        # No docker re-run for already-evaluated candidates
        n_calls = len(fake.calls)
        rx.run_evaluation(self.cfg, cases, self.out,
                          sandbox_factory=lambda c, cve: CaseSandbox(c, cve, executor=fake))
        self.assertEqual(len(fake.calls), n_calls)

        summary = rx.run_report(self.cfg, self.out)
        det = {r["model"]: r for r in summary["detection"]}
        rep = {r["model"]: r for r in summary["repair"]}
        self.assertEqual(det["oracle"]["pair_accuracy"], 1.0)
        self.assertEqual(det["identity"]["recall"], 1.0)
        self.assertEqual(det["identity"]["pair_accuracy"], 0.0)
        self.assertEqual(det["broken"]["valid_output_rate"], 0.0)
        self.assertEqual(rep["oracle"]["secure_and_functional_rate"], 1.0)
        self.assertEqual(rep["identity"]["exploit_blocked_rate"], 0.0)
        self.assertTrue((self.out / "report.md").exists())
        self.assertTrue((self.out / "repair_summary.csv").exists())

    def test_static_only_mode(self):
        cases, _ = rx.prepare_cases(self.cfg)
        rx.run_generation(self.cfg, cases, self.out, client_factory=factory)
        rx.run_evaluation(self.cfg, cases, self.out, use_docker=False)
        evs = rx.read_jsonl(self.out / "evaluations.jsonl")
        self.assertTrue(all(e["status"] == "not_run" for e in evs))
        rx.run_report(self.cfg, self.out)


class TestSandboxCalibration(unittest.TestCase):

    def test_uncalibrated_when_exploit_does_not_reproduce(self):
        from pipeline.vul4c_runner import VariantResult
        vuln = VariantResult("v", "ok", compiled=True, exploit_outcome="no_crash")
        ref = VariantResult("r", "ok", applied=True, compiled=True, exploit_outcome="no_crash")
        cal = calibration_from(vuln, ref)
        self.assertFalse(cal["calibrated"])
        self.assertIn("vulnerable version", cal["reasons"][0])

    def test_container_is_network_isolated_and_limited(self):
        fake = FakeDocker()
        cfg = SandboxConfig(cpus="1", memory="2g")
        with CaseSandbox(cfg, "CVE-2099-0001", executor=fake):
            pass
        run_call = next(c for c in fake.calls if c[1] == "run")
        self.assertIn("--memory", run_call)
        self.assertTrue(any(c[1:3] == ["network", "disconnect"] for c in fake.calls))
        self.assertTrue(any(c[1:3] == ["rm", "-f"] for c in fake.calls))


class TestVul4CFormatHandling(unittest.TestCase):

    def test_test_summary_and_preservation(self):
        from pipeline.vul4c_runner import parse_test_summary, tests_preserved
        out = "PASS: a\nFAIL: b\n# TOTAL: 5\n# PASS:  4\n# FAIL:  1\n# ERROR: 0\n"
        s = parse_test_summary(out)
        self.assertEqual(s["pass"], 4)
        self.assertEqual(s["fail"], 1)
        self.assertIsNone(parse_test_summary("make: Nothing to be done"))
        self.assertTrue(tests_preserved({"pass": 4, "fail": 1}, {"pass": 4, "fail": 1}))
        self.assertFalse(tests_preserved({"pass": 3, "fail": 2}, {"pass": 4, "fail": 1}))
        self.assertIsNone(tests_preserved(None, {"pass": 4}))

    def test_indexed_pairs_merged_and_repo_paths_resolved(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            case = tmp / "bench" / "demo" / "CVE-2099-0002"
            case.mkdir(parents=True)
            v1 = "int a(int x)\n{\n    return x;\n}\n"
            v2 = v1.replace("return x;", "if (x < 0) return 0;\n    return x;")
            v3 = v2.replace("return 0;", "return -1;")
            (case / "CVE-2099-0002_CWE-119_sf.c_OLD-1.c").write_text(v1)
            (case / "CVE-2099-0002_CWE-119_sf.c_NEW-1.c").write_text(v2)
            (case / "CVE-2099-0002_CWE-119_sf.c_OLD-2.c").write_text(v2)
            (case / "CVE-2099-0002_CWE-119_sf.c_NEW-2.c").write_text(v3)
            (case / "CVE-2099-0002_CWE-119_sf.c-1.diff").write_text("diff --git a/cmds/sf.c b/cmds/sf.c\n--- a/cmds/sf.c\n+++ b/cmds/sf.c\n")
            # Latin-1 byte in a comment must survive byte-exact
            latin = "/* caf\xe9 */\nint b(void)\n{\n    return 1;\n}\n".encode("latin-1")
            (case / "CVE-2099-0002_CWE-119_lib.c_OLD.c").write_bytes(latin)
            (case / "CVE-2099-0002_CWE-119_lib.c_NEW.c").write_bytes(latin.replace(b"return 1;", b"return 2;"))
            (tmp / "bench" / "Vul4C_Src").mkdir()
            ds = tmp / "Vul4C_Src"
            ds.mkdir()
            (ds / "Vul4C.json").write_text(json.dumps({"CVE-2099-0002": {"file_name": "src/lib.c"}}))
            cfg = rx._merge(rx.DEFAULTS, {"benchmark_root": str(tmp / "bench"), "cases": ["demo/CVE-2099-0002"]})
            cases, skipped = rx.prepare_cases(cfg)
            self.assertEqual(skipped, [])
            files = {f["file_name"]: f for f in cases[0].files}
            self.assertEqual(set(files), {"sf.c", "lib.c"})
            self.assertEqual(files["sf.c"]["merged_patches"], 2)
            self.assertEqual(files["sf.c"]["new_text"], v3)
            self.assertEqual(files["sf.c"]["repo_path"], "cmds/sf.c")
            self.assertEqual(files["lib.c"]["repo_path"], "src/lib.c")
            self.assertEqual(files["lib.c"]["encoding"], "latin-1")
            ref = {p.file_name: p for p in rx.reference_payload(cases[0])}
            self.assertEqual(ref["lib.c"].content, latin.replace(b"return 1;", b"return 2;"))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestApiClients(unittest.TestCase):

    def _capture(self, response):
        seen = {}

        def post(url, headers, body, timeout):
            seen.update(url=url, headers=headers, body=body)
            return response
        return seen, post

    def test_missing_key_raises(self):
        with self.assertRaises(LLMClientError):
            AnthropicClient({"name": "c", "model": "m", "api_key_env": "SURELY_UNSET_KEY_123"})

    def test_anthropic(self):
        import os
        os.environ["TEST_KEY_A"] = "k"
        seen, post = self._capture({"content": [{"type": "text", "text": "hi"}], "stop_reason": "max_tokens",
                                    "usage": {"input_tokens": 3, "output_tokens": 1}})
        c = AnthropicClient({"name": "c", "model": "m", "api_key_env": "TEST_KEY_A"}, http_post=post)
        r = c.generate([{"role": "system", "content": "S"}, {"role": "user", "content": "U"}], 10)
        self.assertEqual(r.text, "hi")
        self.assertEqual(r.finish_reason, "length")
        self.assertEqual(seen["body"]["system"], "S")
        self.assertEqual(seen["headers"]["x-api-key"], "k")

    def test_openai(self):
        import os
        os.environ["TEST_KEY_O"] = "k"
        seen, post = self._capture({"choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}],
                                    "usage": {"prompt_tokens": 4, "completion_tokens": 2}})
        c = OpenAIClient({"name": "o", "model": "m", "api_key_env": "TEST_KEY_O"}, http_post=post)
        r = c.generate([{"role": "user", "content": "U"}], 10)
        self.assertEqual(r.text, "ok")
        self.assertIn("max_completion_tokens", seen["body"])
        self.assertTrue(seen["url"].endswith("/chat/completions"))

    def test_gemini(self):
        import os
        os.environ["TEST_KEY_G"] = "k"
        seen, post = self._capture({"candidates": [{"content": {"parts": [{"text": "g"}]}, "finishReason": "STOP"}]})
        c = GeminiClient({"name": "g", "model": "m", "api_key_env": "TEST_KEY_G"}, http_post=post)
        r = c.generate([{"role": "system", "content": "S"}, {"role": "user", "content": "U"}], 10)
        self.assertEqual(r.text, "g")
        self.assertIn("systemInstruction", seen["body"])

    def test_http_error_is_reported_not_raised(self):
        import os
        import urllib.error
        os.environ["TEST_KEY_O"] = "k"

        def post(url, headers, body, timeout):
            raise urllib.error.HTTPError(url, 400, "bad", {}, None)
        c = OpenAIClient({"name": "o", "model": "m", "api_key_env": "TEST_KEY_O", "max_retries": 0}, http_post=post)
        r = c.generate([{"role": "user", "content": "U"}], 10)
        self.assertEqual(r.finish_reason, "error")


class TestRegionsAndMetrics(unittest.TestCase):

    def test_multi_region_answers_spliced_bottom_up(self):
        old = "".join(f"int f{i}(void)\n{{\n    return {i};\n}}\n\n" for i in range(30))
        new = old.replace("return 2;", "return 20;").replace("return 25;", "return 250;")
        regs = extract_regions(old, new, "x.c", window_lines=2)
        self.assertEqual(len(regs), 2)
        answer = "### REGION 1\n```c\n" + regs[0].new_code + "```\n### REGION 2\n```c\n" + regs[1].new_code + "```"
        parsed, warnings = parse_region_answers(answer, 2)
        self.assertEqual(warnings, [])
        self.assertEqual(splice_regions(old, regs, parsed), new)

    def test_pass_at_k(self):
        self.assertEqual(pass_at_k(5, 0, 1), 0.0)
        self.assertEqual(pass_at_k(5, 5, 1), 1.0)
        self.assertAlmostEqual(pass_at_k(5, 1, 1), 0.2)

    def test_cwe_family_credit(self):
        recs = [{"case_key": "a", "version": "vulnerable", "label_vulnerable": True, "true_cwe": "CWE-787",
                 "parse_status": "valid", "parsed_output": {"is_vulnerable": True, "cwe": "CWE-122"}}]
        m = detection_metrics(recs)
        self.assertEqual(m["cwe_exact"], 0.0)
        self.assertEqual(m["cwe_family"], 1.0)

    def test_tests_unknown_do_not_count_as_failures(self):
        evs = [{"case_key": "a", "case_calibrated": True, "compiled": True, "exploit_outcome": "no_crash",
                "tests_preserved": None, "static": {"introduced_high_count": 0}, "generation_ok": True}]
        m = repair_metrics(evs)
        self.assertEqual(m["secure_and_functional_rate"], 1.0)
        self.assertEqual(m["tests_unknown"], 1)


if __name__ == "__main__":
    unittest.main()
