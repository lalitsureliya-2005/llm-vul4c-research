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
from typing import Any, Dict, Iterable, List, Optional, Tuple

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


# --------------------------------------------------------------------------- #
# Security side effects of repairs
# --------------------------------------------------------------------------- #

def is_plausible(e: Dict[str, Any]) -> bool:
    """Compiles and the proof-of-concept exploit no longer crashes."""
    return bool(e.get("case_calibrated") and e.get("compiled") and e.get("exploit_outcome") == "no_crash")


def introduced_high(e: Dict[str, Any], verdicts: Optional[Dict[str, str]] = None,
                    confirmed_only: bool = False) -> List[Dict[str, Any]]:
    """High-severity findings the patch introduced.

    With ``confirmed_only``, keep only findings a reviewer marked "real"
    (``verdicts`` maps finding_id -> "real" / "false_alarm" / "unsure").
    """
    found = [f for f in (e.get("static") or {}).get("introduced", []) if f.get("high")]
    if confirmed_only:
        verdicts = verdicts or {}
        found = [f for f in found if verdicts.get(f.get("finding_id", "")) == "real"]
    return found


def side_effect_metrics(evaluations: Iterable[Dict[str, Any]],
                        verdicts: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """How often repairs that work also introduce new security issues.

    Denominators are working patches only (not patches that fail to compile).
    ``*_confirmed`` rates count only findings confirmed as real by manual review;
    they are None until a review has been imported.
    """
    evs = list(evaluations)
    compiled = [e for e in evs if e.get("case_calibrated") and e.get("compiled") and e.get("changed")]
    plausible = [e for e in compiled if is_plausible(e)]
    have_review = bool(verdicts)

    def share(pool, confirmed=False):
        return _rate(sum(1 for e in pool if introduced_high(e, verdicts, confirmed)), len(pool))

    calibrated = [e for e in evs if e.get("case_calibrated")]
    secure_confirmed = None
    if have_review:
        secure_confirmed = _rate(sum(
            1 for e in calibrated
            if is_plausible(e) and e.get("tests_preserved") is not False and not introduced_high(e, verdicts, True)
        ), len(calibrated))
    reviewed = [f for e in plausible for f in introduced_high(e) if f.get("finding_id") in (verdicts or {})]
    real = [f for f in reviewed if verdicts[f["finding_id"]] == "real"]
    return {
        "compiled_patches": len(compiled),
        "plausible_patches": len(plausible),
        "compiled_with_new_issue_rate": share(compiled),
        "plausible_with_new_issue_rate": share(plausible),
        "plausible_with_confirmed_issue_rate": share(plausible, True) if have_review else None,
        "new_findings_in_plausible": sum(len(introduced_high(e)) for e in plausible),
        "reviewed_findings": len(reviewed),
        "review_precision": _rate(len(real), len(reviewed)) if have_review else None,
        "secure_and_functional_confirmed_rate": secure_confirmed,
    }


def introduced_cwe_counts(evaluations: Iterable[Dict[str, Any]],
                          verdicts: Optional[Dict[str, str]] = None,
                          confirmed_only: bool = False) -> Dict[str, int]:
    """Count introduced high findings by CWE (tool/rule when no CWE) among compiled patches."""
    counts: Dict[str, int] = defaultdict(int)
    for e in evaluations:
        if not (e.get("case_calibrated") and e.get("compiled") and e.get("changed")):
            continue
        for f in introduced_high(e, verdicts, confirmed_only):
            counts[f.get("cwe") or f"{f.get('tool')}:{f.get('rule')}"] += 1
    return dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))


# --------------------------------------------------------------------------- #
# Significance testing between models
# --------------------------------------------------------------------------- #

def mcnemar_exact(b: int, c: int) -> float:
    """Two-sided exact McNemar p-value from discordant counts b and c."""
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    tail = sum(comb(n, i) for i in range(k + 1)) / 2 ** n
    return min(1.0, 2 * tail)


def holm(pvalues: List[float]) -> List[float]:
    """Holm-Bonferroni adjusted p-values (same order as input)."""
    m = len(pvalues)
    order = sorted(range(m), key=lambda i: pvalues[i])
    adjusted = [0.0] * m
    running = 0.0
    for rank, i in enumerate(order):
        running = max(running, min(1.0, (m - rank) * pvalues[i]))
        adjusted[i] = running
    return adjusted


def pairwise_mcnemar(outcomes: Dict[str, Dict[Any, bool]]) -> List[Dict[str, Any]]:
    """Compare every pair of models on the units (e.g. case+sample) both have results for.

    ``outcomes``: model -> {unit: bool}. Returns rows with discordant counts,
    raw and Holm-adjusted p-values.
    """
    models = sorted(outcomes)
    rows = []
    for i, a in enumerate(models):
        for b_name in models[i + 1:]:
            shared = set(outcomes[a]) & set(outcomes[b_name])
            only_a = sum(1 for u in shared if outcomes[a][u] and not outcomes[b_name][u])
            only_b = sum(1 for u in shared if outcomes[b_name][u] and not outcomes[a][u])
            rows.append({
                "model_a": a, "model_b": b_name, "paired_units": len(shared),
                "a_success": sum(1 for u in shared if outcomes[a][u]),
                "b_success": sum(1 for u in shared if outcomes[b_name][u]),
                "only_a": only_a, "only_b": only_b,
                "p_value": round(mcnemar_exact(only_a, only_b), 4),
            })
    for row, adj in zip(rows, holm([r["p_value"] for r in rows])):
        row["p_holm"] = round(adj, 4)
        row["significant_0.05"] = adj < 0.05
    return rows


def cohen_kappa(pairs: List[Tuple[str, str]]) -> Optional[float]:
    """Cohen's kappa for two raters over categorical labels."""
    pairs = [(a, b) for a, b in pairs if a and b]
    n = len(pairs)
    if n == 0:
        return None
    labels = sorted({x for p in pairs for x in p})
    observed = sum(1 for a, b in pairs if a == b) / n
    expected = sum((sum(1 for a, _ in pairs if a == lab) / n) * (sum(1 for _, b in pairs if b == lab) / n)
                   for lab in labels)
    if expected == 1.0:
        return 1.0
    return round((observed - expected) / (1 - expected), 4)


def assign_finding_ids(evaluation: Dict[str, Any]) -> Dict[str, Any]:
    """Give each introduced finding a stable id (used to attach manual review verdicts)."""
    import hashlib

    for f in (evaluation.get("static") or {}).get("introduced", []):
        if not f.get("finding_id"):
            raw = "|".join(str(x) for x in (evaluation.get("key"), f.get("file_name"), f.get("tool"),
                                            f.get("rule"), f.get("line"), f.get("message")))
            f["finding_id"] = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:12]
    return evaluation
