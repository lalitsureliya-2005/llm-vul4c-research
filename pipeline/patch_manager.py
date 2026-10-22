"""Code-region extraction, repair splicing, and patch generation.

Vul4C source files can be thousands of lines long, far more than a small local
model can read or rewrite. Following common automated-vulnerability-repair
practice (perfect fault localization), the model is shown only the code
*regions* that the developer fix touched: the enclosing function(s), or a
fixed-size line window when no function boundary is found.

The same regions are used for every model, so all models see identical input
regardless of their context length.

Pipeline:
    regions = extract_regions(old_text, new_text, file_name)
    prompt shows region.old_code  (detection on the fixed version uses region.new_code)
    model returns fixed code for each region
    candidate_text = splice_regions(old_text, regions, fixed_codes)
    patch = make_unified_diff(old_text, candidate_text, header_old, header_new)
"""

from dataclasses import asdict, dataclass
import difflib
import re
from typing import Dict, List, Optional, Sequence, Tuple


@dataclass
class CodeRegion:
    """A contiguous code region (0-based, half-open line ranges)."""
    file_name: str
    old_start: int
    old_end: int
    new_start: int
    new_end: int
    old_code: str
    new_code: str
    kind: str  # "function" or "window"

    def to_dict(self) -> Dict:
        return asdict(self)

    @property
    def label(self) -> str:
        return f"{self.file_name} (lines {self.old_start + 1}-{self.old_end})"


# --------------------------------------------------------------------------- #
# Brace structure
# --------------------------------------------------------------------------- #

def _brace_spans(lines: Sequence[str]) -> List[Tuple[int, int, int]]:
    """Return (open_line, close_line, depth) for every {...} block.

    Skips braces inside string/char literals and comments. Preprocessor lines
    are scanned normally, which is adequate for locating function bodies.
    """
    spans: List[Tuple[int, int, int]] = []
    stack: List[int] = []
    in_block_comment = False
    for ln, line in enumerate(lines):
        i = 0
        n = len(line)
        in_str: Optional[str] = None
        while i < n:
            ch = line[i]
            nxt = line[i + 1] if i + 1 < n else ""
            if in_block_comment:
                if ch == "*" and nxt == "/":
                    in_block_comment = False
                    i += 2
                    continue
                i += 1
                continue
            if in_str:
                if ch == "\\":
                    i += 2
                    continue
                if ch == in_str:
                    in_str = None
                i += 1
                continue
            if ch == "/" and nxt == "/":
                break
            if ch == "/" and nxt == "*":
                in_block_comment = True
                i += 2
                continue
            if ch in ("\"", "'"):
                in_str = ch
            elif ch == "{":
                stack.append(ln)
            elif ch == "}" and stack:
                open_ln = stack.pop()
                spans.append((open_ln, ln, len(stack)))
            i += 1
    return spans


def _signature_start(lines: Sequence[str], open_line: int, max_up: int = 12) -> int:
    """Walk upward from a block's opening brace to include its signature."""
    start = open_line
    for k in range(open_line - 1, max(-1, open_line - 1 - max_up), -1):
        s = lines[k].strip()
        if not s or s.endswith(";") or s.endswith("}") or s.startswith("#") or s.endswith("*/"):
            break
        start = k
    return start


_CONTROL_WORDS = {"if", "else", "for", "while", "switch", "do", "case", "return", "sizeof"}
_FUNC_TAIL_RE = re.compile(
    r"\)\s*(?:const|noexcept|override|final|volatile|throw\s*\([^)]*\)|->\s*[\w:<>*&\s]+|\s)*$"
)


def _is_function_header(lines: Sequence[str], sig_start: int, open_line: int) -> bool:
    """True if the text before a '{' looks like a function definition header."""
    header = "".join(lines[sig_start:open_line + 1])
    header = header[:header.find("{")] if "{" in header else header
    header = re.sub(r"/\*.*?\*/|//[^\n]*", " ", header, flags=re.S).strip()
    if "(" not in header or not _FUNC_TAIL_RE.search(header):
        return False
    name_part = header[:header.find("(")].strip()
    words = re.findall(r"[A-Za-z_]\w*", name_part)
    if not words or words[-1] in _CONTROL_WORDS or words[0] in _CONTROL_WORDS:
        return False
    return "=" not in name_part  # excludes initialisers / lambdas assigned to variables


def _changed_old_ranges(opcodes) -> List[Tuple[int, int]]:
    ranges = []
    for tag, i1, i2, j1, j2 in opcodes:
        if tag == "equal":
            continue
        if i1 == i2:  # pure insertion: anchor on surrounding lines
            ranges.append((max(0, i1 - 1), i1 + 1))
        else:
            ranges.append((i1, i2))
    return ranges


def _map_boundary(b: int, opcodes, side_end: bool) -> int:
    for tag, i1, i2, j1, j2 in opcodes:
        if tag == "equal" and i1 <= b <= i2:
            return j1 + (b - i1)
        if tag != "equal" and b == i1 and not side_end:
            return j1
        if tag != "equal" and b == i2 and side_end:
            return j2
    # Fallback (should not happen after snapping)
    return b


def _snap(start: int, end: int, opcodes) -> Tuple[int, int]:
    """Expand [start, end) so its boundaries never fall inside a changed block."""
    changed = True
    while changed:
        changed = False
        for tag, i1, i2, _, _ in opcodes:
            if tag == "equal":
                continue
            if i1 < start < i2:
                start, changed = i1, True
            if i1 < end < i2:
                end, changed = i2, True
    return start, end


def extract_regions(
    old_text: str,
    new_text: str,
    file_name: str,
    max_region_lines: int = 300,
    window_lines: int = 30,
) -> List[CodeRegion]:
    """Locate the regions of ``old_text`` changed by the reference fix."""
    old_lines = old_text.splitlines(keepends=True)
    new_lines = new_text.splitlines(keepends=True)
    opcodes = difflib.SequenceMatcher(a=old_lines, b=new_lines, autojunk=False).get_opcodes()
    changes = _changed_old_ranges(opcodes)
    if not changes:
        return []

    spans = _brace_spans(old_lines)
    raw: List[Tuple[int, int, str]] = []
    for c_start, c_end in changes:
        last = max(c_start, c_end - 1)
        # Outermost block containing the change that is not larger than the cap
        # (a function body, or a function inside a namespace / extern "C" block).
        candidates = []
        for open_ln, close_ln, _depth in spans:
            if open_ln <= c_start and close_ln >= last:
                s = _signature_start(old_lines, open_ln)
                if close_ln + 1 - s <= max_region_lines and _is_function_header(old_lines, s, open_ln):
                    candidates.append((s, close_ln + 1))
        best = max(candidates, key=lambda se: se[1] - se[0]) if candidates else None
        if best is not None:
            raw.append((best[0], best[1], "function"))
        else:
            raw.append((max(0, c_start - window_lines), min(len(old_lines), c_end + window_lines), "window"))

    # Merge overlapping / adjacent regions.
    raw.sort()
    merged: List[List] = []
    for s, e, kind in raw:
        if merged and s <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], e)
            if kind == "window":
                merged[-1][2] = "window"
        else:
            merged.append([s, e, kind])

    regions: List[CodeRegion] = []
    for s, e, kind in merged:
        s, e = _snap(s, e, opcodes)
        ns = _map_boundary(s, opcodes, side_end=False)
        ne = _map_boundary(e, opcodes, side_end=True)
        regions.append(CodeRegion(
            file_name=file_name,
            old_start=s, old_end=e, new_start=ns, new_end=ne,
            old_code="".join(old_lines[s:e]),
            new_code="".join(new_lines[ns:ne]),
            kind=kind,
        ))
    return regions


# --------------------------------------------------------------------------- #
# Model output parsing and splicing
# --------------------------------------------------------------------------- #

_FENCE_RE = re.compile(r"```[ \t]*([A-Za-z0-9_+#.-]*)[ \t]*\n(.*?)(?:\n```|```)", re.S)
_REGION_HEADING_RE = re.compile(r"REGION\s+(\d+)", re.I)


def extract_code_blocks(text: str) -> List[str]:
    return [m.group(2) for m in _FENCE_RE.finditer(text or "")]


def parse_region_answers(text: str, n_regions: int) -> Tuple[Dict[int, str], List[str]]:
    """Map region index (0-based) -> code from a model answer.

    Accepted formats:
      * "### REGION 1" heading followed by a fenced code block (one per region)
      * a single fenced block (when there is exactly one region)
      * bare code with no fence (when there is exactly one region)
    Returns (answers, warnings).
    """
    warnings: List[str] = []
    answers: Dict[int, str] = {}
    text = text or ""

    headings = list(_REGION_HEADING_RE.finditer(text))
    if headings:
        for idx, h in enumerate(headings):
            seg_end = headings[idx + 1].start() if idx + 1 < len(headings) else len(text)
            blocks = extract_code_blocks(text[h.end():seg_end])
            num = int(h.group(1)) - 1
            if blocks and 0 <= num < n_regions and num not in answers:
                answers[num] = blocks[0]
    if not answers:
        blocks = extract_code_blocks(text)
        if n_regions == 1:
            if blocks:
                answers[0] = max(blocks, key=len)
            elif text.strip():
                answers[0] = text.strip("\n")
                warnings.append("no_code_fence")
        elif len(blocks) == n_regions:
            answers = {i: b for i, b in enumerate(blocks)}
            warnings.append("regions_matched_by_order")
    missing = [i + 1 for i in range(n_regions) if i not in answers]
    if missing:
        warnings.append(f"missing_regions:{','.join(map(str, missing))}")
    return answers, warnings


def splice_regions(old_text: str, regions: List[CodeRegion], answers: Dict[int, str]) -> str:
    """Replace each region of ``old_text`` with the model's code (bottom-up)."""
    lines = old_text.splitlines(keepends=True)
    order = sorted(range(len(regions)), key=lambda i: regions[i].old_start, reverse=True)
    for i in order:
        if i not in answers:
            continue
        code = answers[i]
        if code and not code.endswith("\n"):
            code += "\n"
        r = regions[i]
        lines[r.old_start:r.old_end] = code.splitlines(keepends=True)
    return "".join(lines)


# --------------------------------------------------------------------------- #
# Diffs
# --------------------------------------------------------------------------- #

def diff_headers(diff_text: Optional[str], fallback_name: str) -> Tuple[str, str]:
    """Take '---' / '+++' paths from the benchmark's human diff when available."""
    old_h, new_h = f"a/{fallback_name}", f"b/{fallback_name}"
    if diff_text:
        for line in diff_text.splitlines():
            if line.startswith("--- ") and old_h == f"a/{fallback_name}":
                old_h = line[4:].split("\t")[0].strip()
            elif line.startswith("+++ "):
                new_h = line[4:].split("\t")[0].strip()
                break
    return old_h, new_h


def make_unified_diff(old_text: str, new_text: str, old_header: str, new_header: str,
                      context: int = 3) -> str:
    old_lines = old_text.splitlines(keepends=True)
    new_lines = new_text.splitlines(keepends=True)
    out = []
    for line in difflib.unified_diff(old_lines, new_lines, old_header, new_header, n=context):
        out.append(line if line.endswith("\n") else line + "\n\\ No newline at end of file\n")
    return "".join(out)


def normalize_code(text: str) -> str:
    """Whitespace/comment-insensitive form, for 'identical to human fix' checks."""
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    text = re.sub(r"//[^\n]*", "", text)
    return re.sub(r"\s+", "", text)
