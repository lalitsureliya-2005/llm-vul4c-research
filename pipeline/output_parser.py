"""Structured output parsing and validation for vulnerability detection.

Small instruction-tuned models (e.g. Qwen2.5-Coder-1.5B) frequently produce
output that *looks* like JSON but is not a usable assessment, for example:

- echoing the schema description instead of filling it in
  (``{"is_vulnerable": boolean, "cwe": string or null, ...}``),
- emitting only part of the object (generation cut off, or the model stops
  after one or two fields),
- wrapping the object in markdown fences or adding prose around it.

This module extracts the first JSON object from the generated text, validates
it against the detection schema, and reports a machine-readable status so that
invalid generations are counted as such during evaluation instead of being
silently treated as predictions.

It can also be run as a script to re-validate an existing predictions file:

    python3 pipeline/output_parser.py results/<run>_predictions.jsonl
"""

import argparse
from collections import Counter
import json
from pathlib import Path
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

REQUIRED_FIELDS = ("is_vulnerable", "cwe", "evidence", "reasoning")

# Text the model sometimes copies from the instructions instead of answering.
_SCHEMA_ECHO_PATTERNS = (
    re.compile(r"^\s*(boolean|bool|string|str|null|none|true\s*/\s*false)\s*$", re.I),
    re.compile(r"\bstring\s+or\s+null\b", re.I),
    re.compile(r"\bboolean\s*\(", re.I),
    re.compile(r"^\s*<[^>]*>\s*$"),  # e.g. "<CWE id>"
    re.compile(r"^\s*\.\.\.\s*$"),
)
# Bare (unquoted) type words used as JSON values: {"is_vulnerable": boolean}
_BARE_TYPE_VALUE = re.compile(
    r'"\s*:\s*(boolean|bool|string(\s+or\s+null)?|str|integer|int)\s*[,}\n(]', re.I
)
# Numeric CWEs plus the NVD placeholders used by some benchmark labels.
_CWE_RE = re.compile(r"^(?:NVD-)?CWE-(?:\d+|Other|noinfo)$", re.I)

STATUS_VALID = "valid"
STATUS_EMPTY = "empty"
STATUS_NO_JSON = "no_json_object"
STATUS_TRUNCATED = "truncated_json"
STATUS_INVALID_JSON = "invalid_json"
STATUS_SCHEMA_ECHO = "schema_echo"
STATUS_MISSING_FIELDS = "missing_fields"
STATUS_WRONG_TYPES = "wrong_types"


def _strip_code_fences(text: str) -> str:
    text = text.strip()
    fence = re.match(r"^```[a-zA-Z0-9_-]*\s*\n?(.*?)\n?```\s*$", text, re.S)
    if fence:
        return fence.group(1).strip()
    return text


def extract_first_json_object(text: str) -> Tuple[Optional[str], bool]:
    """Return (object_text, is_complete) for the first ``{...}`` in text.

    Brace matching is string-aware, so braces inside string values (common in
    C code quoted as evidence) do not confuse the scanner. If an opening brace
    is found but never closed, returns the partial text with is_complete=False.
    """
    start = text.find("{")
    if start == -1:
        return None, False

    depth = 0
    in_string = False
    escape = False
    for idx in range(start, len(text)):
        ch = text[idx]
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start:idx + 1], True
    return text[start:], False


def _looks_like_schema_echo(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    return any(p.search(value) for p in _SCHEMA_ECHO_PATTERNS)


def validate_detection_object(obj: Any) -> Tuple[Optional[Dict[str, Any]], str, Optional[str]]:
    """Validate a decoded object against the detection schema."""
    if not isinstance(obj, dict):
        return None, STATUS_WRONG_TYPES, f"Top-level JSON is {type(obj).__name__}, expected object"

    missing = [f for f in REQUIRED_FIELDS if f not in obj]
    if missing:
        return None, STATUS_MISSING_FIELDS, f"Missing required field(s): {', '.join(missing)}"

    echoed = [f for f in REQUIRED_FIELDS if _looks_like_schema_echo(obj.get(f))]
    if echoed:
        return None, STATUS_SCHEMA_ECHO, (
            f"Field(s) contain schema descriptions instead of values: {', '.join(echoed)}"
        )

    errors: List[str] = []
    if not isinstance(obj["is_vulnerable"], bool):
        errors.append("is_vulnerable must be a boolean")
    cwe = obj["cwe"]
    if cwe is not None and not (isinstance(cwe, str) and _CWE_RE.match(cwe.strip())):
        errors.append("cwe must be null or a string like 'CWE-120'")
    if obj["evidence"] is not None and not isinstance(obj["evidence"], str):
        errors.append("evidence must be a string or null")
    if not isinstance(obj["reasoning"], str) or not obj["reasoning"].strip():
        errors.append("reasoning must be a non-empty string")
    if errors:
        return None, STATUS_WRONG_TYPES, "; ".join(errors)

    normalized = {
        "is_vulnerable": obj["is_vulnerable"],
        "cwe": cwe.strip().upper() if isinstance(cwe, str) else None,
        "evidence": obj["evidence"],
        "reasoning": obj["reasoning"].strip(),
    }
    return normalized, STATUS_VALID, None


def parse_detection_output(text: Optional[str]) -> Tuple[Optional[Dict[str, Any]], str, Optional[str]]:
    """Parse generated detection text.

    Returns (parsed_assessment_or_None, status, error_message_or_None).
    ``status`` is ``"valid"`` only for a complete object with all four fields
    holding real values of the correct types.
    """
    if text is None or not text.strip():
        return None, STATUS_EMPTY, "Generated text is empty"

    cleaned = _strip_code_fences(text)
    obj_text, complete = extract_first_json_object(cleaned)
    if obj_text is None:
        return None, STATUS_NO_JSON, "No JSON object found in generated text"
    if not complete:
        return None, STATUS_TRUNCATED, "JSON object was never closed (generation incomplete)"

    try:
        # strict=False tolerates raw newlines/tabs inside strings, which models
        # often emit when quoting source code as evidence.
        obj = json.loads(obj_text, strict=False)
    except json.JSONDecodeError as err:
        if _BARE_TYPE_VALUE.search(obj_text):
            return None, STATUS_SCHEMA_ECHO, "Object uses type names (e.g. boolean, string) as values"
        return None, STATUS_INVALID_JSON, f"JSON decode error: {err}"

    return validate_detection_object(obj)


def summarize_predictions(path: Path) -> Dict[str, Any]:
    """Re-validate detection records in a predictions JSONL file."""
    counts: Counter = Counter()
    examples: Dict[str, str] = {}
    total = 0
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            rec = json.loads(line)
            if rec.get("task_type") != "detection":
                continue
            total += 1
            _, status, err = parse_detection_output(rec.get("generated_text"))
            counts[status] += 1
            if status != STATUS_VALID and status not in examples:
                examples[status] = f"{rec.get('sample_id')}: {err}"
    return {"detection_records": total, "status_counts": dict(counts), "first_failure_per_status": examples}


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Validate detection outputs in a predictions JSONL file.")
    parser.add_argument("predictions_file", type=str)
    args = parser.parse_args(argv)
    path = Path(args.predictions_file)
    if not path.exists():
        print(f"File not found: {path}", file=sys.stderr)
        return 1
    print(json.dumps(summarize_predictions(path), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
