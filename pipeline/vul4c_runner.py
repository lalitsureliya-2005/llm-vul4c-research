"""Sandboxed dynamic validation of patches with the Vul4C tool inside Docker.

For each benchmark case one container is started from the Vul4C image. The
project is checked out once (``vul4c checkout``, needs network), a pristine
backup is kept, and the container's network is then cut. Each variant is
validated in a fresh copy restored to the *same absolute path*, because
autotools/libtool record absolute paths at configure time:

    restore checkout -> write patched file(s) into source/ -> vul4c compile
      -> vul4c reproduce (PoC; crash detected from sanitizer output)
      -> vul4c compile --no-flags -> vul4c test (make check summary parsed)

Why patched files are written directly instead of using ``vul4c apply``:
``vul4c apply`` only handles one file per case and uses a simplified hunk
parser (it skips ``@@ -N +N @@`` headers and misplaces later hunks when line
counts change). Instead, each patched file is written byte-exact when the
checked-out file is identical to the benchmark's vulnerable (OLD) file
(sha256 check), and otherwise applied as a unified diff with GNU ``patch``.

Facts about the Vul4C CLI this module relies on (from Vul4C_Src):
  * ``compile`` exits non-zero on build failure.
  * ``reproduce`` and ``test`` always exit 0, so the outcome must be read from
    their output: sanitizer reports for the exploit, the automake
    ``# PASS: / # FAIL:`` summary of ``make check`` for tests.

Calibration: before candidates are judged, every case is run with
  (a) no patch      -> the exploit is expected to CRASH,
  (b) the human fix -> the exploit is expected NOT to crash; its test summary
                       becomes the functional baseline.
Only calibrated cases are used for dynamic repair metrics.

Safety: exploits only run inside the container, with networking disabled
after checkout, CPU/memory limits, and timeouts.
"""

import base64
from dataclasses import asdict, dataclass, field
import logging
import re
import shlex
import subprocess
import time
import uuid
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

DEFAULT_COMMANDS = {
    "checkout": "vul4c checkout -i {cve} -d {dir}",
    # The compile log goes to VUL4C/compile.log; print its tail so failures are visible.
    "compile": "vul4c compile -d {dir}; rc=$?; tail -n 60 {dir}/VUL4C/compile.log 2>/dev/null; exit $rc",
    "compile_no_flags": "vul4c compile -d {dir} --no-flags; rc=$?; tail -n 60 {dir}/VUL4C/compile.log 2>/dev/null; exit $rc",
    "reproduce": "vul4c reproduce -d {dir}",
    "test": "vul4c test -d {dir}",
}

DEFAULT_TIMEOUTS = {
    "setup": 1800, "checkout": 1800, "apply": 120, "compile": 1800,
    "reproduce": 300, "test": 3600, "misc": 600,
}

DEFAULT_CRASH_PATTERNS = [
    r"ERROR: AddressSanitizer",
    r"ERROR: LeakSanitizer",
    r"UndefinedBehaviorSanitizer",
    r"runtime error:",
    r"ERROR: MemorySanitizer",
    r"Segmentation fault",
    r"SEGV on unknown address",
    r"stack smashing detected",
    r"Assertion .* failed",
    r"\(core dumped\)",
]


@dataclass
class SandboxConfig:
    image: str = "vul4c/vul4c:4.0"
    docker_bin: str = "docker"
    work_root: str = "/vul4c_work"
    setup_commands: List[str] = field(default_factory=list)
    mounts: List[str] = field(default_factory=list)  # "host_path:container_path[:ro]"
    disable_network_after_checkout: bool = True
    cpus: Optional[str] = "2"
    memory: Optional[str] = "6g"
    run_tests: bool = True
    shell: str = "bash -lc"
    commands: Dict[str, str] = field(default_factory=lambda: dict(DEFAULT_COMMANDS))
    timeouts: Dict[str, int] = field(default_factory=lambda: dict(DEFAULT_TIMEOUTS))
    crash_patterns: List[str] = field(default_factory=lambda: list(DEFAULT_CRASH_PATTERNS))

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SandboxConfig":
        cfg = cls()
        for key, value in (data or {}).items():
            if key == "commands":
                cfg.commands.update(value)
            elif key == "timeouts":
                cfg.timeouts.update(value)
            elif hasattr(cfg, key):
                setattr(cfg, key, value)
        return cfg


@dataclass
class CommandResult:
    exit_code: int
    output: str
    duration: float
    timed_out: bool = False


@dataclass
class PatchedFile:
    """A file to place into the checkout. ``content`` is the full patched file (bytes)."""
    file_name: str            # benchmark logical name, e.g. "WAVE.cpp"
    repo_path: Optional[str]  # path inside source/, e.g. "libaudiofile/WAVE.cpp"; None -> resolve by name
    old_sha256: str           # sha256 of the benchmark OLD file bytes
    content: bytes
    diff: str                 # unified diff with a/<repo_path> b/<repo_path> headers (fallback)


@dataclass
class VariantResult:
    variant_id: str
    status: str  # "ok", "apply_failed", "compile_failed", "sandbox_error"
    applied: Optional[bool] = None
    apply_mode: Optional[str] = None  # "replaced", "patched", "unpatched"
    compiled: Optional[bool] = None
    exploit_outcome: Optional[str] = None  # "crash", "no_crash", "timeout"
    tests_passed: Optional[bool] = None    # None = no test summary found
    test_summary: Optional[Dict[str, int]] = None
    durations: Dict[str, float] = field(default_factory=dict)
    logs: Dict[str, str] = field(default_factory=dict)
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


Executor = Callable[[List[str], int, Optional[str]], CommandResult]


def subprocess_executor(argv: List[str], timeout: int, input_text: Optional[str] = None) -> CommandResult:
    start = time.perf_counter()
    try:
        proc = subprocess.run(
            argv, input=input_text, capture_output=True, text=True,
            timeout=timeout, errors="replace",
        )
        return CommandResult(proc.returncode, (proc.stdout or "") + (proc.stderr or ""),
                             time.perf_counter() - start)
    except subprocess.TimeoutExpired as err:
        out = ""
        for stream in (err.stdout, err.stderr):
            if stream:
                out += stream if isinstance(stream, str) else stream.decode("utf-8", "replace")
        return CommandResult(124, out, time.perf_counter() - start, timed_out=True)
    except FileNotFoundError as err:
        return CommandResult(127, str(err), time.perf_counter() - start)


def _tail(text: str, n: int = 4000) -> str:
    return text if len(text) <= n else "...[truncated]...\n" + text[-n:]


# Automake test-suite summary as printed by `make check` (what `vul4c test` runs).
_TEST_COUNT_RES = {
    "total": re.compile(r"^#\s*TOTAL:\s+(\d+)", re.M),
    "pass": re.compile(r"^#\s*PASS:\s+(\d+)", re.M),
    "skip": re.compile(r"^#\s*SKIP:\s+(\d+)", re.M),
    "xfail": re.compile(r"^#\s*XFAIL:\s+(\d+)", re.M),
    "fail": re.compile(r"^#\s*FAIL:\s+(\d+)", re.M),
    "xpass": re.compile(r"^#\s*XPASS:\s+(\d+)", re.M),
    "error": re.compile(r"^#\s*ERROR:\s+(\d+)", re.M),
}


def parse_test_summary(output: str) -> Optional[Dict[str, int]]:
    """Sum all automake summaries in the output (one per test directory)."""
    summary: Dict[str, int] = {}
    for key, rx in _TEST_COUNT_RES.items():
        found = rx.findall(output)
        if found:
            summary[key] = sum(int(x) for x in found)
    return summary or None


def tests_preserved(candidate: Optional[Dict[str, int]], reference: Optional[Dict[str, int]]) -> Optional[bool]:
    """True if the candidate passes at least what the human fix passes and fails no more."""
    if not candidate or not reference:
        return None
    bad = lambda s: s.get("fail", 0) + s.get("error", 0) + s.get("xpass", 0)  # noqa: E731
    return candidate.get("pass", 0) >= reference.get("pass", 0) and bad(candidate) <= bad(reference)


class CaseSandbox:
    """One container per case. Use as a context manager."""

    def __init__(self, cfg: SandboxConfig, cve_id: str, executor: Optional[Executor] = None) -> None:
        self.cfg = cfg
        self.cve_id = cve_id
        self.exec = executor or subprocess_executor
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", cve_id)
        self.name = f"vul4c_{safe}_{uuid.uuid4().hex[:8]}"
        self.case_dir = f"{cfg.work_root}/case"
        self.backup_dir = f"{cfg.work_root}/pristine_backup"
        self.upload_dir = f"{cfg.work_root}/uploads"
        self.started = False
        self.setup_log = ""
        self._crash_res = [re.compile(p) for p in cfg.crash_patterns]

    # -- low level ---------------------------------------------------------
    def _docker(self, args: List[str], timeout: int, input_text: Optional[str] = None) -> CommandResult:
        return self.exec([self.cfg.docker_bin] + args, timeout, input_text)

    def _sh(self, command: str, timeout: int, input_text: Optional[str] = None) -> CommandResult:
        argv = ["exec"] + (["-i"] if input_text is not None else []) + [self.name]
        argv += shlex.split(self.cfg.shell) + [command]
        return self._docker(argv, timeout, input_text)

    def _cmd(self, key: str, **fmt: str) -> str:
        return self.cfg.commands[key].format(cve=shlex.quote(self.cve_id),
                                             **{k: shlex.quote(v) for k, v in fmt.items()})

    def _upload(self, path: str, data: bytes) -> CommandResult:
        """Write bytes into the container exactly (base64 keeps non-UTF-8 sources intact)."""
        encoded = base64.b64encode(data).decode("ascii")
        return self._sh(f"base64 -d > {shlex.quote(path)}", self.cfg.timeouts["misc"], input_text=encoded)

    # -- lifecycle -----------------------------------------------------------
    def start(self) -> None:
        args = ["run", "-d", "--name", self.name]
        if self.cfg.cpus:
            args += ["--cpus", str(self.cfg.cpus)]
        if self.cfg.memory:
            args += ["--memory", str(self.cfg.memory)]
        for m in self.cfg.mounts:
            args += ["-v", m]
        args += [self.cfg.image, "sleep", "infinity"]
        res = self._docker(args, self.cfg.timeouts["misc"])
        if res.exit_code != 0:
            raise RuntimeError(f"Could not start container from {self.cfg.image}: {_tail(res.output, 800)}")
        self.started = True

        logs = []
        for command in self.cfg.setup_commands:
            r = self._sh(command, self.cfg.timeouts["setup"])
            logs.append(f"$ {command}\n{_tail(r.output, 1500)}")
            if r.exit_code != 0:
                raise RuntimeError(f"Setup command failed ({command}): {_tail(r.output, 800)}")

        q = shlex.quote
        self._sh(f"mkdir -p {q(self.cfg.work_root)} {q(self.upload_dir)} && rm -rf {q(self.case_dir)}",
                 self.cfg.timeouts["misc"])
        r = self._sh(self._cmd("checkout", dir=self.case_dir), self.cfg.timeouts["checkout"])
        logs.append(f"$ checkout\n{_tail(r.output, 2000)}")
        self.setup_log = "\n".join(logs)
        if r.exit_code != 0:
            raise RuntimeError(f"vul4c checkout failed for {self.cve_id}: {_tail(r.output, 800)}")
        b = self._sh(f"rm -rf {q(self.backup_dir)} && cp -a {q(self.case_dir)} {q(self.backup_dir)}",
                     self.cfg.timeouts["misc"])
        if b.exit_code != 0:
            raise RuntimeError(f"Could not back up checkout: {_tail(b.output, 800)}")

        if self.cfg.disable_network_after_checkout:
            self._docker(["network", "disconnect", "bridge", self.name], self.cfg.timeouts["misc"])

    def stop(self) -> None:
        if self.started:
            self._docker(["rm", "-f", self.name], self.cfg.timeouts["misc"])
            self.started = False

    def __enter__(self) -> "CaseSandbox":
        self.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.stop()

    # -- evaluation ----------------------------------------------------------
    def is_crash(self, output: str) -> bool:
        return any(rx.search(output) for rx in self._crash_res)

    def _place_file(self, idx: int, pf: PatchedFile) -> CommandResult:
        q = shlex.quote
        content_path = f"{self.upload_dir}/f{idx}.bin"
        diff_path = f"{self.upload_dir}/f{idx}.diff"
        for path, data in ((content_path, pf.content), (diff_path, pf.diff.encode("utf-8", "surrogateescape"))):
            up = self._upload(path, data)
            if up.exit_code != 0:
                return up
        if pf.repo_path:
            locate = f"f={q(pf.repo_path)}; "
        else:
            base = pf.file_name.split("/")[-1]
            locate = (
                f"f=$(git ls-files 2>/dev/null | grep -E '(^|/){re.escape(base)}$'); "
                f"n=$(printf '%s\\n' \"$f\" | grep -c .); "
                f"if [ \"$n\" != 1 ]; then echo \"VUL4C_EVAL: cannot uniquely locate {base} ($n matches)\"; exit 3; fi; "
            )
        script = (
            f"cd {q(self.case_dir)}/source && {locate}"
            f"if [ ! -f \"$f\" ]; then echo \"VUL4C_EVAL: file not found: $f\"; exit 3; fi; "
            f"if [ \"$(sha256sum \"$f\" | cut -d' ' -f1)\" = {q(pf.old_sha256)} ]; then "
            f"cp {q(content_path)} \"$f\" && echo \"VUL4C_EVAL: replaced $f\"; "
            f"else sed -i \"s#^--- a/.*#--- a/$f#; s#^+++ b/.*#+++ b/$f#\" {q(diff_path)} && "
            f"patch -p1 --batch --forward -i {q(diff_path)} && echo \"VUL4C_EVAL: patched $f\"; fi"
        )
        return self._sh(script, self.cfg.timeouts["apply"])

    def evaluate(self, variant_id: str, files: Optional[List[PatchedFile]]) -> VariantResult:
        """Validate one variant. ``files=None`` evaluates the unpatched vulnerable version."""
        q = shlex.quote
        result = VariantResult(variant_id=variant_id, status="ok")
        t = self.cfg.timeouts
        try:
            prep = self._sh(f"rm -rf {q(self.case_dir)} && cp -a {q(self.backup_dir)} {q(self.case_dir)}", t["misc"])
            if prep.exit_code != 0:
                result.status, result.error = "sandbox_error", _tail(prep.output, 800)
                return result

            if files:
                modes, logs = [], []
                for i, pf in enumerate(files):
                    a = self._place_file(i, pf)
                    logs.append(_tail(a.output, 800))
                    if a.exit_code != 0:
                        result.applied, result.status = False, "apply_failed"
                        result.logs["apply"] = "\n".join(logs)
                        return result
                    modes.append("patched" if "VUL4C_EVAL: patched" in a.output else "replaced")
                result.applied = True
                result.apply_mode = "patched" if "patched" in modes else "replaced"
                result.logs["apply"] = "\n".join(logs)
            else:
                result.apply_mode = "unpatched"

            c = self._sh(self._cmd("compile", dir=self.case_dir), t["compile"])
            result.durations["compile"] = round(c.duration, 2)
            result.logs["compile"] = _tail(c.output, 3000)
            result.compiled = c.exit_code == 0 and not c.timed_out
            if not result.compiled:
                result.status = "compile_failed"
                return result

            x = self._sh(self._cmd("reproduce", dir=self.case_dir), t["reproduce"])
            result.durations["reproduce"] = round(x.duration, 2)
            result.logs["reproduce"] = _tail(x.output, 3000)
            if x.timed_out:
                result.exploit_outcome = "timeout"
            else:
                result.exploit_outcome = "crash" if self.is_crash(x.output) else "no_crash"

            if self.cfg.run_tests:
                c2 = self._sh(self._cmd("compile_no_flags", dir=self.case_dir), t["compile"])
                result.durations["compile_no_flags"] = round(c2.duration, 2)
                if c2.exit_code != 0:
                    result.tests_passed = False
                    result.logs["test"] = "compile without sanitizer flags failed:\n" + _tail(c2.output, 1500)
                else:
                    tr = self._sh(self._cmd("test", dir=self.case_dir), t["test"])
                    result.durations["test"] = round(tr.duration, 2)
                    result.logs["test"] = _tail(tr.output, 3000)
                    result.test_summary = parse_test_summary(tr.output)
                    if result.test_summary and not tr.timed_out:
                        s = result.test_summary
                        result.tests_passed = (s.get("fail", 0) + s.get("error", 0) + s.get("xpass", 0)) == 0
                    # else: no automake summary -> unknown (vul4c test always exits 0)
            return result
        except Exception as err:  # pragma: no cover - defensive
            result.status, result.error = "sandbox_error", f"{type(err).__name__}: {err}"
            return result


def calibration_from(vulnerable: VariantResult, reference: VariantResult) -> Dict[str, Any]:
    """Decide whether a case can be used for dynamic repair evaluation."""
    reproduces = vulnerable.compiled is True and vulnerable.exploit_outcome == "crash"
    fixed = reference.applied is not False and reference.compiled is True and reference.exploit_outcome == "no_crash"
    reasons = []
    if not reproduces:
        reasons.append(f"vulnerable version: compiled={vulnerable.compiled}, exploit={vulnerable.exploit_outcome}")
    if not fixed:
        reasons.append(f"reference fix: applied={reference.applied}, compiled={reference.compiled}, "
                       f"exploit={reference.exploit_outcome}")
    return {
        "calibrated": reproduces and fixed,
        "vulnerability_reproduces": reproduces,
        "reference_blocks_exploit": fixed,
        "reference_apply_mode": reference.apply_mode,
        "reference_tests_passed": reference.tests_passed,
        "reference_test_summary": reference.test_summary,
        "reasons": reasons,
    }
