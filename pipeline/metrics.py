"""Metrics for comparing models on vulnerability detection and repair.

Detection (each case contributes a vulnerable and a fixed version):
  - valid_output_rate: share of answers that are a valid JSON assessment
  - accuracy / precision / recall / F1 / false-positive rate, where an invalid
    answer counts as "not flagged" (a missed detection, never a free point)
  - pair_accuracy: cases where BOTH versions are classified correctly
    (vulnerable flagged AND fixed version not flagged); a model that always
    answers "vulnerable" scores 0 here even though its recall is 100%
  - cwe_exact / cwe_family: CWE agreement on correctly flagged vulnerable code

Repair (only cases whose calibration succeeded count for dynamic metrics):
  - generated: model produced usable code for every region
  - applied, compiled
  - exploit_blocked (plausible): compiled AND the PoC no longer crashes
  - tests_preserved: test suite passes whenever it passed for the human fix
  - new_static_issues: patch introduces high-severity static findings
  - secure_and_functional: plausible AND tests not broken AND no new high
    static findings  (the headline metric)
  - pass@k for secure_and_functional when several samples per case exist
"""

from collections import defaultdict
from math import comb
import re
from typing import Any, Dict, Iterable, List, Optional

# Coarse CWE families for "related CWE" credit. Edit to suit your taxonomy.
CWE_FAMILIES: Dict[str, set] = {
    "bounds": {119, 120, 121, 122, 123, 124, 125, 126, 127, 129, 131, 170, 193, 786, 787, 788, 805, 806},
    "integer": {128, 189, 190, 191, 192, 194, 195, 196, 197, 369, 680, 681, 682},
    "lifetime": {415, 416, 562, 590, 672, 761, 762, 763, 825},
    "null": {476, 690},
    "resource": {399, 400, 401, 404, 770, 772, 834, 835, 674},
    "input_validation": {20, 1284, 1285, 1287},
    "uninitialized": {457, 665, 824, 908, 909},
    "format": {134},
    "race": {362, 366, 367},
}


def cwe_number(cwe: Optional[str]) -> Optional[int]:
    if not cwe:
        return None
    m = re.match(r"^\s*CWE-(\d+)\s*$", str(cwe), re.I)
    return int(m.group(1)) if m else None


def cwe_family(num: Optional[int]) -> Optional[str]:
    if num is None:
        return None
    for name, members in CWE_FAMILIES.items():
        if num in members:
            return name
    return None


def _rate(num: int, den: int) -> Optional[float]:
    return round(num / den, 4) if den else None


def detection_metrics(records: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    recs = list(records)
    tp = fp = tn = fn = valid = 0
    cwe_eval = cwe_exact = cwe_family_hits = 0
    by_case: Dict[tuple, Dict[str, bool]] = defaultdict(dict)
    for r in recs:
        label = r["label_vulnerable"]
        parsed = r.get("parsed_output") if r.get("parse_status") == "valid" else None
        if parsed is not None:
            valid += 1
        predicted = bool(parsed and parsed.get("is_vulnerable"))
        correct = predicted == label
        by_case[(r["case_key"], r.get("sample", 0))][r["version"]] = correct
        if label and predicted:
            tp += 1
            true_num = cwe_number(r.get("true_cwe"))
            if true_num is not None:
                cwe_eval += 1
                pred_num = cwe_number(parsed.get("cwe"))
                if pred_num == true_num:
                    cwe_exact += 1
                    cwe_family_hits += 1
                elif pred_num is not None and cwe_family(pred_num) and cwe_family(pred_num) == cwe_family(true_num):
                    cwe_family_hits += 1
        elif label:
            fn += 1
        elif predicted:
            fp += 1
        else:
            tn += 1
    n = len(recs)
    precision = _rate(tp, tp + fp)
    recall = _rate(tp, tp + fn)
    f1 = round(2 * precision * recall / (precision + recall), 4) if precision and recall else (0.0 if precision is not None and recall is not None else None)
    pairs = [v for v in by_case.values() if "vulnerable" in v and "fixed" in v]
    return {
        "samples": n,
        "valid_output_rate": _rate(valid, n),
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "accuracy": _rate(tp + tn, n),
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positive_rate": _rate(fp, fp + tn),
        "pairs": len(pairs),
        "pair_accuracy": _rate(sum(1 for v in pairs if v["vulnerable"] and v["fixed"]), len(pairs)),
        "cwe_evaluated": cwe_eval,
        "cwe_exact": _rate(cwe_exact, cwe_eval),
        "cwe_family": _rate(cwe_family_hits, cwe_eval),
    }


def pass_at_k(n: int, c: int, k: int) -> float:
    if n - c < k:
        return 1.0
    return 1.0 - comb(n - c, k) / comb(n, k)


def secure_and_functional(e: Dict[str, Any]) -> bool:
    return bool(
        e.get("compiled") and e.get("exploit_outcome") == "no_crash"
        and e.get("tests_preserved") is not False
        and (e.get("static") or {}).get("introduced_high_count", 0) == 0
    )


def repair_metrics(evaluations: Iterable[Dict[str, Any]], ks: Iterable[int] = (1,)) -> Dict[str, Any]:
    evs = list(evaluations)
    dyn = [e for e in evs if e.get("case_calibrated")]
    n_dyn = len(dyn)

    def count(pred, pool) -> int:
        return sum(1 for e in pool if pred(e))

    tests_known = [e for e in dyn if e.get("tests_preserved") is not None]
    out = {
        "candidates": len(evs),
        "cases": len({e["case_key"] for e in evs}),
        "calibrated_candidates": n_dyn,
        "calibrated_cases": len({e["case_key"] for e in dyn}),
        "generated_rate": _rate(count(lambda e: e.get("generation_ok"), evs), len(evs)),
        "changed_code_rate": _rate(count(lambda e: e.get("changed"), evs), len(evs)),
        "applied_rate": _rate(count(lambda e: e.get("applied"), dyn), n_dyn),
        "compiled_rate": _rate(count(lambda e: e.get("compiled"), dyn), n_dyn),
        "exploit_blocked_rate": _rate(count(lambda e: e.get("compiled") and e.get("exploit_outcome") == "no_crash", dyn), n_dyn),
        "tests_preserved_rate": _rate(count(lambda e: e.get("tests_preserved") is True, tests_known), len(tests_known)),
        "tests_unknown": n_dyn - len(tests_known),
        "new_high_static_issue_rate": _rate(count(lambda e: (e.get("static") or {}).get("introduced_high_count", 0) > 0, evs), len(evs)),
        "secure_and_functional_rate": _rate(count(secure_and_functional, dyn), n_dyn),
        "identical_to_reference_rate": _rate(count(lambda e: e.get("identical_to_reference"), evs), len(evs)),
    }
    per_case: Dict[str, List[bool]] = defaultdict(list)
    for e in dyn:
        per_case[e["case_key"]].append(secure_and_functional(e))
    for k in ks:
        vals = [pass_at_k(len(v), sum(v), k) for v in per_case.values() if len(v) >= k]
        out[f"pass@{k}"] = round(sum(vals) / len(vals), 4) if vals else None
    return out


def group_by(records: Iterable[Dict[str, Any]], key: str) -> Dict[str, List[Dict[str, Any]]]:
    groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for r in records:
        groups[r.get(key) or "unknown"].append(r)
    return dict(groups)
