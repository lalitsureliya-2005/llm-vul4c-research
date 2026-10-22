"""Multi-model evaluation of LLM vulnerability detection and repair on Vul4C.

Stages (run all, or one at a time; every stage is resumable):

  generate  Ask every enabled model to (a) classify the vulnerable and the fixed
            version of each case and (b) repair the vulnerable version.
  evaluate  Validate repairs: sandboxed Vul4C build + exploit + test suite in
            Docker (with per-case calibration), plus differential static
            analysis (cppcheck, flawfinder) on the host.
  report    Compute metrics and write CSV + Markdown comparison tables.

Usage:
  python3 pipeline/run_experiment.py --config config/experiment.json --stage all
  python3 pipeline/run_experiment.py --config config/experiment.json --stage generate --models qwen2.5-coder-1.5b
  python3 pipeline/run_experiment.py --config config/experiment.json --stage evaluate --no-docker

Outputs (results/experiments/<experiment_name>/):
  cases.json          prepared cases and skipped cases with reasons
  generations.jsonl   one record per model x task x case x version x sample
  calibration.jsonl   one record per case (does the PoC reproduce / does the human fix block it)
  evaluations.jsonl   one record per repair candidate
  report.md, detection_summary.csv, repair_summary.csv, summary.json
"""

import argparse
import csv
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import logging
from pathlib import Path
import re
import sys
import time
from typing import Any, Dict, Iterable, List, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from pipeline.case_manager import CaseManager, CaseManagerError  # noqa: E402
from pipeline.inference import DETECTION_RESPONSE_PREFIX  # noqa: E402
from pipeline.llm_clients import LLMClient, build_client  # noqa: E402
from pipeline.metrics import (  # noqa: E402
    cwe_family, cwe_number, detection_metrics, group_by, repair_metrics, secure_and_functional,
)
from pipeline.output_parser import parse_detection_output  # noqa: E402
from pipeline.patch_manager import (  # noqa: E402
    CodeRegion, diff_headers, extract_regions, make_unified_diff, normalize_code,
    parse_region_answers, splice_regions,
)
from pipeline.static_analysis import analyze_patch, available_tools  # noqa: E402
from pipeline.task_prompts import (  # noqa: E402
    build_detection_messages, build_repair_messages, identity_repair_answer,
    oracle_repair_answer, sanity_detection_answer,
)
from pipeline.vul4c_runner import (  # noqa: E402
    CaseSandbox, PatchedFile, SandboxConfig, calibration_from, tests_preserved,
)

logger = logging.getLogger("run_experiment")

DEFAULTS: Dict[str, Any] = {
    "experiment_name": "vul4c_multi_model",
    "output_dir": "results/experiments",
    "benchmark_root": None,
    "cases": [],             # [] = every case under benchmark_root
    "max_cases": None,
    "tasks": ["detection", "repair"],
    "samples_per_case": 1,
    "temperature": 0.0,
    "seed": 42,
    "pass_at_k": [1],
    "detection": {"max_output_tokens": 512, "use_json_prefill": True},
    "repair": {"max_output_tokens": 4096, "hints": {"cwe": True, "sanitizer_report": False}},
    "context": {"max_region_lines": 300, "window_lines": 30, "max_total_region_lines": 600},
    "static_analysis": {"enabled": True, "tools": ["cppcheck", "flawfinder"]},
    "sandbox": {"enabled": True, "evaluate_uncalibrated": False},
    "models": [],
}


def _merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(base)
    for k, v in override.items():
        out[k] = _merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out


def load_config(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        return _merge(DEFAULTS, json.load(fh))


# --------------------------------------------------------------------------- #
# JSONL helpers
# --------------------------------------------------------------------------- #

def read_jsonl(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    out = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    logger.warning("Skipping corrupt line in %s", path)
    return out


def append_jsonl(path: Path, record: Dict[str, Any]) -> None:
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")


def gen_key(model: str, task: str, case_key: str, version: str, sample: int) -> str:
    return f"{model}|{task}|{case_key}|{version}|{sample}"


# --------------------------------------------------------------------------- #
# Case preparation
# --------------------------------------------------------------------------- #

@dataclass
class PreparedCase:
    case_key: str
    project: str
    cve_id: str
    cwe_id: Optional[str]
    sanitizer_issue: Optional[str]
    # file_name, repo_path, encoding, old_text, new_text, old_sha256, header_old, header_new
    files: List[Dict[str, Any]]
    regions: List[CodeRegion] = field(default_factory=list)
    region_file_index: List[int] = field(default_factory=list)
    reference_patch: str = ""


def _decode(data: bytes) -> (str, str):
    """Decode source bytes losslessly: UTF-8 when valid, else Latin-1 (byte-exact round trip)."""
    try:
        return data.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        return data.decode("latin-1"), "latin-1"


def _encode(text: str, encoding: str) -> bytes:
    return text.encode(encoding, errors="replace")


def discover_case_keys(root: Path) -> List[str]:
    return sorted(
        f"{d.parent.name}/{d.name}" for d in root.glob("*/*")
        if d.is_dir() and not d.name.startswith(".") and not d.parent.name.startswith(".")
    )


def load_vul4c_dataset(cfg: Dict[str, Any], benchmark_root: Path) -> Dict[str, Any]:
    """Vul4C_Src/Vul4C.json holds the repository path of the patched file per case."""
    path = Path(cfg.get("vul4c_dataset_json") or benchmark_root.parent / "Vul4C_Src" / "Vul4C.json")
    if not path.exists():
        logger.warning("Vul4C.json not found at %s; repository paths will be resolved inside the "
                       "container by file name.", path)
        return {}
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


_INDEX_SUFFIX = re.compile(r"^(.*?)-(\d+)$")


def _repo_path_for(file_name: str, case_info: Dict[str, Any], diff_text: Optional[str]) -> Optional[str]:
    base = file_name.split("/")[-1]
    ds_path = (case_info or {}).get("file_name") or ""
    if ds_path and ds_path.split("/")[-1] == base:
        return ds_path
    if diff_text:
        h_old, _ = diff_headers(diff_text, file_name)
        if h_old.startswith("a/") and h_old.split("/")[-1] == base:
            return h_old[2:]
    return None  # resolved inside the container with `git ls-files`


def prepare_cases(cfg: Dict[str, Any]) -> (List[PreparedCase], List[Dict[str, str]]):
    root = cfg.get("benchmark_root")
    manager = CaseManager(root)
    dataset = load_vul4c_dataset(cfg, manager.benchmark_root)
    keys = cfg.get("cases") or discover_case_keys(manager.benchmark_root)
    if cfg.get("max_cases"):
        keys = keys[: int(cfg["max_cases"])]
    ctx = cfg["context"]
    prepared: List[PreparedCase] = []
    skipped: List[Dict[str, str]] = []
    for key in keys:
        try:
            meta = manager.load_case(key)
        except CaseManagerError as err:
            skipped.append({"case": key, "reason": f"load_error: {err}"})
            continue
        case_info = dataset.get(meta.cve_id or meta.case_id, {})

        # Indexed pairs of the same file (e.g. sfconvert.c-1, sfconvert.c-2) are successive
        # patches to ONE file: evaluate from the first OLD to the last NEW.
        groups: Dict[str, List[Any]] = {}
        for pair in meta.source_pairs:
            m = _INDEX_SUFFIX.match(pair.file_name)
            name, idx = (m.group(1), int(m.group(2))) if m else (pair.file_name, 0)
            groups.setdefault(name, []).append((idx, pair))

        files, regions, region_idx = [], [], []
        for name, items in groups.items():
            items.sort(key=lambda x: x[0])
            first, last = items[0][1], items[-1][1]
            old_bytes, new_bytes = first.old_path.read_bytes(), last.new_path.read_bytes()
            old_text, encoding = _decode(old_bytes)
            new_text, _ = _decode(new_bytes)
            diff_text = _decode(first.diff_path.read_bytes())[0] if first.diff_path else None
            repo_path = _repo_path_for(name, case_info, diff_text)
            label = repo_path or name
            fi = len(files)
            files.append({
                "file_name": name, "repo_path": repo_path, "encoding": encoding,
                "old_text": old_text, "new_text": new_text,
                "old_sha256": hashlib.sha256(old_bytes).hexdigest(),
                "header_old": f"a/{label}", "header_new": f"b/{label}",
                "merged_patches": len(items),
            })
            for r in extract_regions(old_text, new_text, name, ctx["max_region_lines"], ctx["window_lines"]):
                regions.append(r)
                region_idx.append(fi)
        total_lines = sum(r.old_end - r.old_start for r in regions)
        if not regions:
            skipped.append({"case": key, "reason": "no_code_difference_between_OLD_and_NEW"})
            continue
        if total_lines > ctx["max_total_region_lines"]:
            skipped.append({"case": key, "reason": f"regions_too_large ({total_lines} lines)"})
            continue
        ref_patch = "".join(make_unified_diff(f["old_text"], f["new_text"], f["header_old"], f["header_new"])
                            for f in files)
        prepared.append(PreparedCase(
            case_key=f"{meta.project}/{meta.case_id}", project=meta.project,
            cve_id=meta.cve_id or meta.case_id, cwe_id=meta.cwe_id,
            sanitizer_issue=meta.sanitizer_issue, files=files, regions=regions,
            region_file_index=region_idx, reference_patch=ref_patch,
        ))
    return prepared, skipped


def _match_newlines(code: str, like: str) -> str:
    """Use CRLF in model output when the original file uses CRLF."""
    if "\r\n" in like:
        return code.replace("\r\n", "\n").replace("\n", "\r\n")
    return code


def build_candidate(case: PreparedCase, answers: Dict[int, str]) -> Dict[str, Any]:
    """Splice region answers into files; return patch, per-file texts and sandbox payloads."""
    patch_parts, cand_files, payload = [], [], []
    identical = True
    changed = False
    for fi, f in enumerate(case.files):
        idxs = [i for i, x in enumerate(case.region_file_index) if x == fi]
        regs = [case.regions[i] for i in idxs]
        local_answers = {j: _match_newlines(answers[i], f["old_text"]) for j, i in enumerate(idxs) if i in answers}
        cand_text = splice_regions(f["old_text"], regs, local_answers)
        if cand_text != f["old_text"]:
            changed = True
            diff = make_unified_diff(f["old_text"], cand_text, f["header_old"], f["header_new"])
            patch_parts.append(diff)
            payload.append(PatchedFile(
                file_name=f["file_name"], repo_path=f["repo_path"], old_sha256=f["old_sha256"],
                content=_encode(cand_text, f["encoding"]), diff=diff,
            ))
        if normalize_code(cand_text) != normalize_code(f["new_text"]):
            identical = False
        cand_files.append({"file_name": f["file_name"], "old_text": f["old_text"], "candidate_text": cand_text})
    patch = "".join(patch_parts)
    return {"patch": patch, "files": cand_files, "payload": payload, "changed": changed,
            "identical_to_reference": identical}


def reference_payload(case: PreparedCase) -> List[PatchedFile]:
    """The developer fix as sandbox payload (NEW content for every file)."""
    return [
        PatchedFile(
            file_name=f["file_name"], repo_path=f["repo_path"], old_sha256=f["old_sha256"],
            content=_encode(f["new_text"], f["encoding"]),
            diff=make_unified_diff(f["old_text"], f["new_text"], f["header_old"], f["header_new"]),
        )
        for f in case.files
    ]


# --------------------------------------------------------------------------- #
# Stage 1: generation
# --------------------------------------------------------------------------- #

def _seed(seed: int) -> None:
    try:
        import random

        random.seed(seed)
        import torch

        torch.manual_seed(seed)
    except ImportError:
        pass


def run_generation(cfg: Dict[str, Any], cases: List[PreparedCase], out: Path,
                   model_filter: Optional[List[str]] = None,
                   client_factory=build_client) -> None:
    gen_path = out / "generations.jsonl"
    done = {r["key"] for r in read_jsonl(gen_path) if r.get("finish_reason") != "error"}
    models = [m for m in cfg["models"] if m.get("enabled", True)]
    if model_filter:
        models = [m for m in cfg["models"] if m["name"] in model_filter]
    if not models:
        logger.error("No enabled models. Set \"enabled\": true for at least one model in the config.")
        return
    samples = int(cfg["samples_per_case"])
    temperature = float(cfg["temperature"])
    det_cfg, rep_cfg = cfg["detection"], cfg["repair"]

    for spec in models:
        name = spec["name"]
        todo = []
        for case in cases:
            for s in range(samples):
                if "detection" in cfg["tasks"]:
                    for version in ("vulnerable", "fixed"):
                        if gen_key(name, "detection", case.case_key, version, s) not in done:
                            todo.append(("detection", case, version, s))
                if "repair" in cfg["tasks"]:
                    if gen_key(name, "repair", case.case_key, "vulnerable", s) not in done:
                        todo.append(("repair", case, "vulnerable", s))
        if not todo:
            logger.info("[%s] nothing to generate (all done).", name)
            continue
        logger.info("[%s] %d generations to run.", name, len(todo))
        client: LLMClient = client_factory(spec)
        try:
            for n, (task, case, version, s) in enumerate(todo, 1):
                _seed(int(cfg["seed"]) + s)
                record = _generate_one(client, spec, task, case, version, s, temperature, det_cfg, rep_cfg)
                append_jsonl(gen_path, record)
                logger.info("[%s] %d/%d %s %s %s s%d -> %s", name, n, len(todo), task, case.case_key,
                            version, s, record.get("parse_status") or record.get("finish_reason"))
        finally:
            client.close()


def _generate_one(client: LLMClient, spec, task, case: PreparedCase, version, s, temperature,
                  det_cfg, rep_cfg) -> Dict[str, Any]:
    base = {
        "key": gen_key(spec["name"], task, case.case_key, version, s),
        "model": spec["name"], "provider": spec.get("provider"), "model_id": spec.get("model"),
        "task": task, "case_key": case.case_key, "project": case.project, "cve_id": case.cve_id,
        "true_cwe": case.cwe_id, "version": version, "sample": s,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    if task == "detection":
        label = version == "vulnerable"
        messages = build_detection_messages(case.project, case.regions, use_new=not label)
        prefix = DETECTION_RESPONSE_PREFIX if (client.supports_prefill and det_cfg.get("use_json_prefill", True)) else ""
        context = {"oracle_answer": sanity_detection_answer(label, case.cwe_id),
                   "identity_answer": sanity_detection_answer(True, case.cwe_id)}
        res = client.generate(messages, int(spec.get("detection_max_output_tokens", det_cfg["max_output_tokens"])),
                              temperature, response_prefix=prefix, stop_on_json_close=bool(prefix), context=context)
        parsed, status, perr = parse_detection_output(res.text) if res.finish_reason != "error" else (None, "generation_error", res.error)
        base.update({
            "label_vulnerable": label, "output": res.text, "parsed_output": parsed,
            "parse_status": status, "parse_error": perr,
        })
    else:
        hints = rep_cfg.get("hints", {})
        messages = build_repair_messages(
            case.project, case.regions,
            cwe=case.cwe_id if hints.get("cwe") else None,
            sanitizer_report=case.sanitizer_issue if hints.get("sanitizer_report") else None,
        )
        context = {"oracle_answer": oracle_repair_answer(case.regions),
                   "identity_answer": identity_repair_answer(case.regions)}
        res = client.generate(messages, int(spec.get("repair_max_output_tokens", rep_cfg["max_output_tokens"])),
                              temperature, context=context)
        answers, warnings = parse_region_answers(res.text, len(case.regions)) if res.finish_reason != "error" else ({}, ["generation_error"])
        cand = build_candidate(case, answers)
        base.update({
            "output": res.text,
            "regions": [r.label for r in case.regions],
            "generation_ok": res.finish_reason != "error" and len(answers) == len(case.regions),
            "parse_warnings": warnings,
            "patch": cand["patch"],
            "patch_sha256": hashlib.sha256(cand["patch"].encode()).hexdigest(),
            "changed": cand["changed"],
            "identical_to_reference": cand["identical_to_reference"],
            "parse_status": "ok" if answers else "no_code",
        })
    base.update({
        "prompt_tokens": res.prompt_tokens, "completion_tokens": res.completion_tokens,
        "latency_seconds": res.latency_seconds, "finish_reason": res.finish_reason, "error": res.error,
    })
    return base


# --------------------------------------------------------------------------- #
# Stage 2: evaluation
# --------------------------------------------------------------------------- #

def _slim(variant) -> Dict[str, Any]:
    d = variant.to_dict()
    d["logs"] = {k: v[-1500:] for k, v in d.get("logs", {}).items()}
    return d


def run_evaluation(cfg: Dict[str, Any], cases: List[PreparedCase], out: Path,
                   use_docker: bool = True, sandbox_factory=CaseSandbox) -> None:
    gen_path, cal_path, eval_path = out / "generations.jsonl", out / "calibration.jsonl", out / "evaluations.jsonl"
    repair_gens = [g for g in read_jsonl(gen_path) if g["task"] == "repair"]
    evaluated = {e["key"] for e in read_jsonl(eval_path)}
    calibration = {c["case_key"]: c for c in read_jsonl(cal_path)}
    by_case = group_by([g for g in repair_gens if g["key"] not in evaluated], "case_key")
    case_map = {c.case_key: c for c in cases}
    sa_cfg = cfg["static_analysis"]
    tools = sa_cfg["tools"] if sa_cfg.get("enabled", True) else []
    if tools:
        avail = available_tools(tools)
        missing = [t for t, ok in avail.items() if not ok]
        if missing:
            logger.warning("Static analysis tools not found (skipped): %s", ", ".join(missing))
    sandbox_cfg = SandboxConfig.from_dict({k: v for k, v in cfg["sandbox"].items()
                                           if k not in ("enabled", "evaluate_uncalibrated")})
    use_docker = use_docker and cfg["sandbox"].get("enabled", True)
    sa_cache: Dict[Any, Any] = {}

    for case_key, gens in by_case.items():
        case = case_map.get(case_key)
        if case is None:
            logger.warning("Case %s is in generations but not in the current case list; skipping.", case_key)
            continue
        logger.info("Evaluating %d candidate(s) for %s", len(gens), case_key)
        sandbox = None
        variant_cache: Dict[str, Any] = {}
        try:
            if use_docker:
                sandbox = sandbox_factory(sandbox_cfg, case.cve_id)
                try:
                    sandbox.start()
                except Exception as err:
                    logger.error("Sandbox start failed for %s: %s", case_key, err)
                    if case_key not in calibration:
                        calibration[case_key] = {"case_key": case_key, "calibrated": False,
                                                 "reasons": [f"sandbox_start_failed: {err}"]}
                        append_jsonl(cal_path, calibration[case_key])
                    sandbox = None
                need_vuln = case_key not in calibration or any(not g.get("changed") for g in gens)
                if sandbox is not None and need_vuln:
                    vuln = sandbox.evaluate("vulnerable", None)
                    variant_cache["__vulnerable__"] = vuln
                    if case_key not in calibration:
                        ref = sandbox.evaluate("reference", reference_payload(case))
                        cal = {"case_key": case_key, "cve_id": case.cve_id,
                               **calibration_from(vuln, ref),
                               "vulnerable": _slim(vuln), "reference": _slim(ref),
                               "timestamp": datetime.now(timezone.utc).isoformat()}
                        calibration[case_key] = cal
                        append_jsonl(cal_path, cal)
                        logger.info("Calibration %s: %s %s", case_key, cal["calibrated"], cal["reasons"])

            cal = calibration.get(case_key, {})
            calibrated = bool(cal.get("calibrated"))
            ref_summary = cal.get("reference_test_summary")

            for g in gens:
                ev: Dict[str, Any] = {
                    "key": g["key"], "model": g["model"], "case_key": case_key, "cve_id": case.cve_id,
                    "true_cwe": case.cwe_id, "cwe_family": cwe_family(cwe_number(case.cwe_id)),
                    "sample": g["sample"], "generation_ok": g.get("generation_ok"),
                    "changed": g.get("changed"), "identical_to_reference": g.get("identical_to_reference"),
                    "case_calibrated": calibrated, "patch_sha256": g.get("patch_sha256"),
                }
                answers, _ = parse_region_answers(g.get("output", ""), len(case.regions))
                cand = build_candidate(case, answers)
                # Static analysis on the host
                if tools and g.get("changed"):
                    ev["static"] = analyze_patch(cand["files"], tools, cache=sa_cache)
                else:
                    ev["static"] = {"introduced_count": 0, "introduced_high_count": 0, "introduced": [],
                                    "skipped": "no_change" if not g.get("changed") else "disabled"}

                # Dynamic validation
                variant = None
                if sandbox is not None and (calibrated or cfg["sandbox"].get("evaluate_uncalibrated")):
                    if not g.get("changed"):
                        variant = variant_cache.get("__vulnerable__")
                        ev["dynamic_note"] = "unchanged code; reused vulnerable-version result"
                    elif g["patch_sha256"] in variant_cache:
                        variant = variant_cache[g["patch_sha256"]]
                        ev["dynamic_note"] = "identical patch already evaluated for this case"
                    else:
                        variant = sandbox.evaluate(f"{g['model']}_s{g['sample']}", cand["payload"])
                        variant_cache[g["patch_sha256"]] = variant
                if variant is not None:
                    ev.update({
                        "status": variant.status, "applied": variant.applied if g.get("changed") else True,
                        "compiled": variant.compiled, "exploit_outcome": variant.exploit_outcome,
                        "tests_passed": variant.tests_passed, "test_summary": variant.test_summary,
                        "durations": variant.durations, "logs": {k: v[-1500:] for k, v in variant.logs.items()},
                    })
                    ev["apply_mode"] = variant.apply_mode
                    # Compared with the human fix's test summary; None when either summary is missing.
                    ev["tests_preserved"] = tests_preserved(variant.test_summary, ref_summary)
                else:
                    ev["status"] = "not_run" if not use_docker else ("case_not_calibrated" if not calibrated else "not_run")
                ev["secure_and_functional"] = secure_and_functional(ev) if calibrated else None
                ev["timestamp"] = datetime.now(timezone.utc).isoformat()
                append_jsonl(eval_path, ev)
        finally:
            if sandbox is not None:
                sandbox.stop()


# --------------------------------------------------------------------------- #
# Stage 3: report
# --------------------------------------------------------------------------- #

def _fmt(v: Any) -> str:
    if v is None:
        return "-"
    if isinstance(v, float):
        return f"{v * 100:.1f}%" if 0 <= v <= 1 else f"{v:.2f}"
    return str(v)


def _table(rows: List[Dict[str, Any]], cols: List[str], pct_cols: Iterable[str]) -> str:
    pct = set(pct_cols)
    head = "| " + " | ".join(cols) + " |\n|" + "|".join("---" for _ in cols) + "|\n"
    body = ""
    for r in rows:
        body += "| " + " | ".join(_fmt(r.get(c)) if c in pct else str(r.get(c, "-")) for c in cols) + " |\n"
    return head + body


def _write_csv(path: Path, rows: List[Dict[str, Any]]) -> None:
    if not rows:
        return
    cols = list(rows[0].keys())
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)


def run_report(cfg: Dict[str, Any], out: Path) -> Dict[str, Any]:
    gens = read_jsonl(out / "generations.jsonl")
    evals = read_jsonl(out / "evaluations.jsonl")
    cals = read_jsonl(out / "calibration.jsonl")
    ks = cfg.get("pass_at_k", [1])

    det_rows = []
    for model, recs in sorted(group_by([g for g in gens if g["task"] == "detection"], "model").items()):
        det_rows.append({"model": model, **detection_metrics(recs)})
    rep_rows = []
    for model, recs in sorted(group_by(evals, "model").items()):
        rep_rows.append({"model": model, **repair_metrics(recs, ks)})
    fam_rows = []
    for model, recs in sorted(group_by(evals, "model").items()):
        for fam, frecs in sorted(group_by(recs, "cwe_family").items()):
            m = repair_metrics(frecs, ks)
            fam_rows.append({"model": model, "cwe_family": fam, "calibrated_candidates": m["calibrated_candidates"],
                             "exploit_blocked_rate": m["exploit_blocked_rate"],
                             "secure_and_functional_rate": m["secure_and_functional_rate"]})

    _write_csv(out / "detection_summary.csv", det_rows)
    _write_csv(out / "repair_summary.csv", rep_rows)
    _write_csv(out / "repair_by_cwe_family.csv", fam_rows)

    n_cal = sum(1 for c in cals if c.get("calibrated"))
    pct_det = ["valid_output_rate", "accuracy", "precision", "recall", "f1", "false_positive_rate",
               "pair_accuracy", "cwe_exact", "cwe_family"]
    pct_rep = ["generated_rate", "applied_rate", "compiled_rate", "exploit_blocked_rate",
               "tests_preserved_rate", "new_high_static_issue_rate", "secure_and_functional_rate",
               "identical_to_reference_rate"] + [f"pass@{k}" for k in ks]
    lines = [
        f"# {cfg['experiment_name']}: model comparison",
        "",
        f"Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}.",
        "",
        "## Calibration",
        f"{n_cal} of {len(cals)} evaluated cases calibrated (vulnerability reproduces in the sandbox and the "
        "human fix blocks it). Dynamic repair metrics use calibrated cases only.",
        "",
    ]
    bad = [c for c in cals if not c.get("calibrated")]
    if bad:
        lines += ["Cases excluded from dynamic metrics:", ""]
        lines += [f"- `{c['case_key']}`: {'; '.join(c.get('reasons', [])) or 'unknown'}" for c in bad[:50]]
        lines.append("")
    if det_rows:
        lines += ["## Detection", "",
                  "Each case is asked twice: vulnerable version (label = vulnerable) and developer-fixed version "
                  "(label = not vulnerable). Invalid answers count as 'not flagged'. `pair_accuracy` = both versions "
                  "correct.", "",
                  _table(det_rows, ["model", "samples"] + pct_det, pct_det)]
    if rep_rows:
        lines += ["## Repair", "",
                  "`secure_and_functional` = compiles, the proof-of-concept exploit no longer crashes, the test "
                  "suite still passes (when it passes for the human fix), and no new high-severity static "
                  "analysis findings.", "",
                  _table(rep_rows, ["model", "candidates", "calibrated_candidates"] + pct_rep, pct_rep)]
    if fam_rows:
        lines += ["## Repair by CWE family", "",
                  _table(fam_rows, ["model", "cwe_family", "calibrated_candidates", "exploit_blocked_rate",
                                    "secure_and_functional_rate"],
                         ["exploit_blocked_rate", "secure_and_functional_rate"])]
    lines += ["## Sanity models", "",
              "`oracle` returns the human fix and `identity` returns the unchanged vulnerable code. On calibrated "
              "cases, oracle should be ~100% exploit-blocked and identity ~0%. If not, fix the pipeline before "
              "trusting other numbers. For detection, `identity` always answers 'vulnerable' and shows the "
              "score of a model with no discrimination ability.", ""]
    (out / "report.md").write_text("\n".join(lines), encoding="utf-8")
    summary = {"detection": det_rows, "repair": rep_rows, "repair_by_cwe_family": fam_rows,
               "calibrated_cases": n_cal, "evaluated_cases": len(cals)}
    (out / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", required=True)
    ap.add_argument("--stage", choices=["generate", "evaluate", "report", "all"], default="all")
    ap.add_argument("--models", nargs="+", help="Only these model names (overrides 'enabled').")
    ap.add_argument("--cases", nargs="+", help="Only these cases, e.g. audiofile/CVE-2017-6832")
    ap.add_argument("--max-cases", type=int)
    ap.add_argument("--benchmark-root")
    ap.add_argument("--no-docker", action="store_true", help="Skip sandboxed build/exploit/test (static analysis only).")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="[%(asctime)s] [%(levelname)s] %(name)s: %(message)s")
    cfg = load_config(args.config)
    if args.cases:
        cfg["cases"] = args.cases
    if args.max_cases:
        cfg["max_cases"] = args.max_cases
    if args.benchmark_root:
        cfg["benchmark_root"] = args.benchmark_root

    out = Path(cfg["output_dir"]) / cfg["experiment_name"]
    out.mkdir(parents=True, exist_ok=True)
    (out / "config_used.json").write_text(json.dumps(cfg, indent=2), encoding="utf-8")

    t0 = time.perf_counter()
    if args.stage in ("generate", "evaluate", "all"):
        cases, skipped = prepare_cases(cfg)
        (out / "cases.json").write_text(json.dumps({
            "prepared": [{"case": c.case_key, "cwe": c.cwe_id, "regions": [r.label for r in c.regions]} for c in cases],
            "skipped": skipped}, indent=2), encoding="utf-8")
        logger.info("Prepared %d case(s); skipped %d (see cases.json).", len(cases), len(skipped))
        if args.stage in ("generate", "all"):
            run_generation(cfg, cases, out, model_filter=args.models)
        if args.stage in ("evaluate", "all") and "repair" in cfg["tasks"]:
            run_evaluation(cfg, cases, out, use_docker=not args.no_docker)
    if args.stage in ("report", "all"):
        summary = run_report(cfg, out)
        print((out / "report.md").read_text(encoding="utf-8"))
        logger.info("Report: %s | %d detection rows, %d repair rows", out / "report.md",
                    len(summary["detection"]), len(summary["repair"]))
    logger.info("Done in %.1fs. Outputs in %s", time.perf_counter() - t0, out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
