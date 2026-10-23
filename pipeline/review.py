"""Manual review of security issues introduced by model patches.

Static analysers report false alarms, so tool-reported "new issues" should be
confirmed by people before they are claimed in a paper. This module supports a
two-reviewer workflow:

  1. export   Write review/review_sheet.csv (one row per introduced finding) and
              review/review_packet.html (the finding, the surrounding code and the
              full patch for each row). Model names are replaced by codes and rows
              are shuffled, so reviewers judge findings without knowing which model
              produced them (the key is kept in review/model_key.json).
  2. review   Two people fill the reviewer_1 / reviewer_2 columns independently with
              real / false_alarm / unsure. Disagreements are settled in "final".
  3. import   Read the sheet back: verdicts and Cohen's kappa are written to
              review/verdicts.json, which the report uses for *_confirmed metrics.

Usage:
  python3 scripts/review_findings.py export --config config/experiment.json
  python3 scripts/review_findings.py import --config config/experiment.json
"""

import argparse
import csv
import html
import json
from datetime import datetime, timezone
from pathlib import Path
import random
import sys
from typing import Any, Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from pipeline import run_experiment as rx  # noqa: E402
from pipeline.metrics import assign_finding_ids, cohen_kappa, introduced_high, is_plausible  # noqa: E402
from pipeline.patch_manager import parse_region_answers  # noqa: E402

SHEET_COLUMNS = [
    "finding_id", "item", "case", "case_cwe", "model_code", "plausible_patch", "tool", "rule",
    "finding_cwe", "severity", "file", "line", "message", "reviewer_1", "reviewer_2", "final", "notes",
]
VERDICT_COLUMNS = ("reviewer_1", "reviewer_2", "final", "notes")

_LABELS = {
    "real": "real", "r": "real", "yes": "real", "y": "real", "true": "real", "tp": "real", "1": "real",
    "false_alarm": "false_alarm", "false alarm": "false_alarm", "fa": "false_alarm", "no": "false_alarm",
    "n": "false_alarm", "false": "false_alarm", "fp": "false_alarm", "0": "false_alarm",
    "unsure": "unsure", "u": "unsure", "?": "unsure",
}


def normalize_label(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    v = value.strip().lower()
    if not v:
        return None
    if v not in _LABELS:
        raise ValueError(f"Unknown verdict '{value}'. Use real, false_alarm or unsure.")
    return _LABELS[v]


def _context(text: str, line: int, radius: int) -> str:
    lines = text.splitlines()
    lo, hi = max(1, line - radius), min(len(lines), line + radius)
    width = len(str(hi))
    return "\n".join(f"{'>>' if n == line else '  '} {str(n).rjust(width)} | {lines[n - 1]}" for n in range(lo, hi + 1))


def collect_items(cfg: Dict[str, Any], out: Path, include: str = "plausible",
                  context_lines: int = 6) -> List[Dict[str, Any]]:
    """One item per introduced high-severity finding, with code context and patch."""
    evals = [assign_finding_ids(e) for e in rx.read_jsonl(out / "evaluations.jsonl")]
    gens = {g["key"]: g for g in rx.read_jsonl(out / "generations.jsonl")}
    sanity = {m["name"] for m in cfg.get("models", []) if m.get("provider") in ("oracle", "identity")}
    wanted = [e for e in evals if e["model"] not in sanity and introduced_high(e)]
    if include == "plausible":
        wanted = [e for e in wanted if is_plausible(e)]
    elif include == "compiled":
        wanted = [e for e in wanted if e.get("compiled")]

    case_keys = sorted({e["case_key"] for e in wanted})
    cases = {}
    if case_keys:
        prepared, _ = rx.prepare_cases(dict(cfg, cases=case_keys, max_cases=None))
        cases = {c.case_key: c for c in prepared}

    items = []
    for e in wanted:
        gen = gens.get(e["key"], {})
        case = cases.get(e["case_key"])
        texts: Dict[str, str] = {}
        if case is not None:
            answers, _ = parse_region_answers(gen.get("output", ""), len(case.regions))
            texts = {f["file_name"]: f["candidate_text"] for f in rx.build_candidate(case, answers)["files"]}
        for f in introduced_high(e):
            items.append({
                "finding_id": f["finding_id"], "case": e["case_key"], "case_cwe": e.get("true_cwe") or "",
                "model": e["model"], "plausible_patch": is_plausible(e), "tool": f.get("tool"),
                "rule": f.get("rule"), "finding_cwe": f.get("cwe") or "", "severity": f.get("severity"),
                "file": f.get("file_name"), "line": f.get("line"), "message": f.get("message"),
                "context": _context(texts.get(f.get("file_name"), ""), int(f.get("line") or 0), context_lines),
                "patch": gen.get("patch", ""),
            })
    return items


def _read_sheet(path: Path) -> List[Dict[str, str]]:
    with open(path, "r", encoding="utf-8-sig", newline="") as fh:
        return list(csv.DictReader(fh))


def export_review(cfg: Dict[str, Any], out: Path, include: str = "plausible", blind: bool = True,
                  seed: int = 13, context_lines: int = 6) -> Dict[str, Any]:
    review_dir = out / "review"
    review_dir.mkdir(parents=True, exist_ok=True)
    sheet_path = review_dir / "review_sheet.csv"
    key_path = review_dir / "model_key.json"

    items = collect_items(cfg, out, include, context_lines)
    rng = random.Random(seed)
    rng.shuffle(items)

    # Keep model codes stable across re-exports, and keep verdicts already entered.
    key: Dict[str, str] = json.loads(key_path.read_text()) if key_path.exists() else {}
    models = sorted({i["model"] for i in items} - set(key))
    rng.shuffle(models)
    for m in models:
        key[m] = f"M{len(key) + 1}"
    key_path.write_text(json.dumps(key, indent=2))
    previous = {r["finding_id"]: r for r in _read_sheet(sheet_path)} if sheet_path.exists() else {}

    rows = []
    for n, it in enumerate(items, 1):
        row = {c: it.get(c, "") for c in SHEET_COLUMNS}
        row["item"] = n
        row["model_code"] = key[it["model"]] if blind else it["model"]
        for c in VERDICT_COLUMNS:
            row[c] = previous.get(it["finding_id"], {}).get(c, "")
        rows.append(row)
    with open(sheet_path, "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=SHEET_COLUMNS)
        w.writeheader()
        w.writerows(rows)

    parts = []
    for n, it in enumerate(items, 1):
        who = key[it["model"]] if blind else it["model"]
        parts.append(
            f"<section id='item{n}'><h2>Item {n} <small>{html.escape(it['finding_id'])}</small></h2>"
            f"<p><b>Case</b> {html.escape(it['case'])} ({html.escape(it['case_cwe'])}) · <b>Model</b> {html.escape(who)}"
            f" · <b>Patch blocks exploit</b> {'yes' if it['plausible_patch'] else 'no'}</p>"
            f"<p><b>{html.escape(str(it['tool']))}</b> {html.escape(str(it['rule']))} "
            f"{html.escape(str(it['finding_cwe']))} ({html.escape(str(it['severity']))}) at "
            f"{html.escape(str(it['file']))}:{it['line']}<br>{html.escape(str(it['message']))}</p>"
            f"<h3>Code around the finding (patched file)</h3><pre>{html.escape(it['context'])}</pre>"
            f"<details><summary>Full patch</summary><pre>{html.escape(it['patch'])}</pre></details></section>"
        )
    page = (
        "<!doctype html><html><head><meta charset='utf-8'><title>Finding review packet</title>"
        "<style>body{font-family:system-ui,sans-serif;max-width:1000px;margin:auto;padding:16px}"
        "pre{background:#f4f4f4;padding:8px;overflow:auto;font-size:12px}section{border-bottom:1px solid #ccc;"
        "padding:12px 0}small{color:#888;font-weight:normal}</style></head><body>"
        "<h1>Review packet</h1><p>For each item decide whether the reported issue is a real new security "
        "problem introduced by the patch (<b>real</b>), a false alarm (<b>false_alarm</b>), or <b>unsure</b>. "
        "Enter verdicts in review_sheet.csv; reviewers work independently.</p>"
        + "".join(parts) + "</body></html>"
    )
    (review_dir / "review_packet.html").write_text(page, encoding="utf-8")
    return {"items": len(items), "sheet": str(sheet_path), "packet": str(review_dir / "review_packet.html"),
            "kept_verdicts": sum(1 for r in rows if any(r[c] for c in VERDICT_COLUMNS[:3]))}


def import_review(out: Path) -> Dict[str, Any]:
    review_dir = out / "review"
    rows = _read_sheet(review_dir / "review_sheet.csv")
    verdicts: Dict[str, str] = {}
    pairs = []
    unresolved = []
    for r in rows:
        r1, r2, final = (normalize_label(r.get(c)) for c in ("reviewer_1", "reviewer_2", "final"))
        if r1 and r2:
            pairs.append((r1, r2))
        decided = final or (r1 if r1 and (r1 == r2 or not r2) else None) or (r2 if r2 and not r1 else None)
        if decided:
            verdicts[r["finding_id"]] = decided
        elif r1 or r2:
            unresolved.append(r["finding_id"])
    result = {
        "verdicts": verdicts,
        "reviewed": len(verdicts),
        "real": sum(1 for v in verdicts.values() if v == "real"),
        "false_alarm": sum(1 for v in verdicts.values() if v == "false_alarm"),
        "unsure": sum(1 for v in verdicts.values() if v == "unsure"),
        "double_reviewed": len(pairs),
        "kappa": cohen_kappa(pairs),
        "unresolved_disagreements": unresolved,
        "imported_at": datetime.now(timezone.utc).isoformat(),
    }
    (review_dir / "verdicts.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("action", choices=["export", "import"])
    ap.add_argument("--config", required=True)
    ap.add_argument("--include", choices=["plausible", "compiled", "all"], default="plausible",
                    help="Which patches to review (default: plausible = compiled and blocks the exploit).")
    ap.add_argument("--no-blind", action="store_true", help="Show real model names to reviewers.")
    ap.add_argument("--context-lines", type=int, default=6)
    args = ap.parse_args(argv)
    cfg = rx.load_config(args.config)
    out = Path(cfg["output_dir"]) / cfg["experiment_name"]
    if args.action == "export":
        res = export_review(cfg, out, args.include, blind=not args.no_blind, context_lines=args.context_lines)
        print(f"Exported {res['items']} findings ({res['kept_verdicts']} with existing verdicts kept).")
        print(f"  Sheet : {res['sheet']}\n  Packet: {res['packet']}")
    else:
        res = import_review(out)
        print(f"Imported {res['reviewed']} verdicts: {res['real']} real, {res['false_alarm']} false alarms, "
              f"{res['unsure']} unsure. Cohen's kappa = {res['kappa']} over {res['double_reviewed']} double-reviewed.")
        if res["unresolved_disagreements"]:
            print(f"  {len(res['unresolved_disagreements'])} disagreements have no 'final' verdict yet.")
        print("Re-run the report stage to include confirmed rates.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
