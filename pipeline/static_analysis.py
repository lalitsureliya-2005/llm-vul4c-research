"""Differential static security analysis of candidate patches.

Each changed file is analysed three times with the same tools:
  vulnerable original (OLD), reference fix (NEW), and the model's candidate.

Findings are compared by (tool, rule, normalized source line), not by line
number, so moved code is not mistaken for a new issue. A finding counts as
*introduced* by a patch when it appears more often in the candidate than in
the vulnerable original.

Supported tools (run on the host; each is optional and skipped if missing):
  - cppcheck   (apt install cppcheck)
  - flawfinder (pip install flawfinder)
"""

import csv
from collections import Counter
from dataclasses import asdict, dataclass
import io
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from typing import Any, Dict, List, Optional, Sequence, Tuple


@dataclass
class Finding:
    tool: str
    rule: str
    severity: str
    line: int
    message: str
    cwe: Optional[str] = None
    high: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def available_tools(tools: Sequence[str]) -> Dict[str, bool]:
    return {t: shutil.which(t) is not None for t in tools}


def _analysis_suffix(file_name: str) -> str:
    lower = file_name.lower()
    for ext in (".cpp", ".cc", ".cxx", ".hpp", ".hh"):
        if lower.endswith(ext):
            return ext
    if lower.endswith(".h") or lower.endswith(".h.in"):
        return ".h"
    return ".c"


NON_SECURITY_RULES = {"syntaxError", "internalAstError", "unknownMacro", "preprocessorErrorDirective",
                      "cppcheckError", "internalError"}


def run_cppcheck(path: Path, timeout: int = 300) -> List[Finding]:
    template = "{line}|{severity}|{id}|{cwe}|{message}"
    argv = ["cppcheck", "--enable=warning,style,performance,portability", "--inconclusive",
            "--quiet", f"--template={template}"]
    if path.suffix in (".cpp", ".cc", ".cxx", ".hpp", ".hh"):
        argv.append("--language=c++")
    elif path.suffix in (".c", ".h"):
        argv.append("--language=c")
    proc = subprocess.run(argv + [str(path)], capture_output=True, text=True, timeout=timeout, errors="replace")
    findings = []
    for line in (proc.stderr + proc.stdout).splitlines():
        parts = line.split("|", 4)
        if len(parts) != 5 or not parts[0].strip().isdigit():
            continue
        ln, sev, rule, cwe, msg = parts
        findings.append(Finding(
            tool="cppcheck", rule=rule.strip(), severity=sev.strip(), line=int(ln),
            message=msg.strip(), cwe=f"CWE-{cwe.strip()}" if cwe.strip() not in ("", "0") else None,
            # Parse failures are already captured as compile failures, not security issues.
            high=sev.strip() in ("error", "warning") and rule.strip() not in NON_SECURITY_RULES,
        ))
    return findings


def run_flawfinder(path: Path, timeout: int = 300) -> List[Finding]:
    proc = subprocess.run(["flawfinder", "--csv", "--minlevel=1", str(path)],
                          capture_output=True, text=True, timeout=timeout, errors="replace")
    findings = []
    for row in csv.DictReader(io.StringIO(proc.stdout)):
        try:
            level = int(row.get("Level") or 0)
            ln = int(row.get("Line") or 0)
        except ValueError:
            continue
        findings.append(Finding(
            tool="flawfinder", rule=f"{row.get('Category', '')}/{row.get('Name', '')}",
            severity=f"level{level}", line=ln, message=(row.get("Warning") or "").strip(),
            cwe=(row.get("CWEs") or "").split(",")[0].strip() or None, high=level >= 3,
        ))
    return findings


RUNNERS = {"cppcheck": run_cppcheck, "flawfinder": run_flawfinder}


def analyze_text(text: str, file_name: str, tools: Sequence[str]) -> Tuple[List[Finding], List[str]]:
    errors: List[str] = []
    findings: List[Finding] = []
    with tempfile.TemporaryDirectory(prefix="sa_") as tmp:
        path = Path(tmp) / ("code" + _analysis_suffix(file_name))
        path.write_text(text, encoding="utf-8")
        for tool in tools:
            if tool not in RUNNERS or shutil.which(tool) is None:
                continue
            try:
                findings.extend(RUNNERS[tool](path))
            except subprocess.TimeoutExpired:
                errors.append(f"{tool}: timeout")
            except Exception as err:  # pragma: no cover - environment specific
                errors.append(f"{tool}: {err}")
    return findings, errors


def _key(f: Finding, lines: List[str]) -> Tuple[str, str, str]:
    src = lines[f.line - 1] if 0 < f.line <= len(lines) else ""
    return (f.tool, f.rule, re.sub(r"\s+", "", src))


def introduced_findings(base: List[Finding], base_text: str,
                        cand: List[Finding], cand_text: str) -> List[Finding]:
    """Findings present in ``cand`` beyond those already in ``base``."""
    base_lines, cand_lines = base_text.splitlines(), cand_text.splitlines()
    remaining = Counter(_key(f, base_lines) for f in base)
    new = []
    for f in cand:
        k = _key(f, cand_lines)
        if remaining[k] > 0:
            remaining[k] -= 1
        else:
            new.append(f)
    return new


def analyze_patch(files: List[Dict[str, str]], tools: Sequence[str],
                  cache: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Analyse candidate files against their vulnerable originals.

    ``files``: [{"file_name", "old_text", "candidate_text"}].
    ``cache``: optional dict reused across calls to avoid re-analysing originals.
    """
    cache = cache if cache is not None else {}
    introduced: List[Dict[str, Any]] = []
    removed = 0
    errors: List[str] = []
    for f in files:
        key = ("old", f["file_name"], hash(f["old_text"]))
        if key not in cache:
            cache[key] = analyze_text(f["old_text"], f["file_name"], tools)
        old_findings, err_old = cache[key]
        cand_findings, err_cand = analyze_text(f["candidate_text"], f["file_name"], tools)
        errors += err_old + err_cand
        new = introduced_findings(old_findings, f["old_text"], cand_findings, f["candidate_text"])
        gone = introduced_findings(cand_findings, f["candidate_text"], old_findings, f["old_text"])
        removed += len(gone)
        introduced += [dict(n.to_dict(), file_name=f["file_name"]) for n in new]
    return {
        "tools": [t for t in tools if shutil.which(t)],
        "introduced": introduced,
        "introduced_count": len(introduced),
        "introduced_high_count": sum(1 for x in introduced if x["high"]),
        "removed_count": removed,
        "errors": errors,
    }
