# Multi-Model Evaluation Pipeline (Detection + Repair)

This pipeline compares several LLMs on real Vul4C vulnerabilities. It sends the same inputs to every model, collects detection verdicts and repair patches, and checks each patch in four ways: compilation, the proof-of-concept exploit, the project's test suite, and differential static analysis.

```text
Vul4C case ──► region extraction ──► prompts (identical for all models)
                                        │
             ┌──────────────────────────┼───────────────────────────┐
         detection                    repair                      models
  (vulnerable + fixed version)   (vulnerable version)   local HF · Ollama · OpenAI · Anthropic · Gemini
             │                          │                      + oracle / identity sanity models
     JSON parse + validate      splice regions ─► unified diff
             │                          │
             │          ┌───────────────┴──────────────────┐
             │   Docker sandbox (vul4c/vul4c:4.0)    host static analysis
             │   calibrate: unpatched crashes?        cppcheck + flawfinder
             │              human fix blocks it?      (new findings vs original)
             │   apply ─► compile ─► exploit ─► tests
             └──────────────► metrics + report (CSV, Markdown) ◄──────┘
```

## Files

| File | Role |
|---|---|
| `pipeline/run_experiment.py` | Orchestrator CLI (stages: generate, evaluate, report). Resumable. |
| `pipeline/llm_clients.py` | One interface for every model provider, plus the `oracle` and `identity` sanity models. |
| `pipeline/patch_manager.py` | Finds the function(s) changed by the human fix, splices model output back in, and writes diffs. |
| `pipeline/task_prompts.py` | Detection and repair prompts. |
| `pipeline/vul4c_runner.py` | Docker sandbox driving the `vul4c` CLI, with calibration. |
| `pipeline/static_analysis.py` | Differential cppcheck and flawfinder analysis. |
| `pipeline/metrics.py` | Detection and repair metrics. |
| `config/experiment.json` | Models, cases, and settings. |
| `scripts/check_eval_environment.sh` | Pre-flight check, plus an optional one-case sandbox smoke test. |

## Methodological choices (state these in the paper)

1. **Same input for every model.** Each model sees only the function(s) that the developer fix changed. If no enclosing function is found, it sees a window of ±30 lines. This is *perfect fault localization*, as in the Vul4C/SoK evaluation. It removes context-length differences between models, but it tells the model where the bug is.
2. **Balanced detection.** Each case is asked twice: once on the vulnerable version (label: vulnerable) and once on the developer-fixed version (label: not vulnerable). `pair_accuracy` requires both answers to be correct, so a model that always says "vulnerable" scores 0%.
3. **Invalid output is a failure.** A detection answer that isn't a valid JSON assessment counts as "not flagged". A repair answer with missing regions keeps the original code for those regions.
4. **Calibration.** A case counts for dynamic repair metrics only if (a) the exploit crashes the unpatched build in the sandbox, and (b) the human fix applies, compiles, and stops the crash. Excluded cases and the reasons are listed in `report.md`.
5. **Functional check.** "Tests preserved" is judged only when the human fix passes the test suite. Otherwise it is reported as unknown, not counted as a failure.
6. **New security issues.** These are findings that appear in the patched file but not in the vulnerable original. Findings are matched by tool, rule, and source line, so moved code doesn't count. "High" means a cppcheck error or warning, or a flawfinder level of 3 or above.
7. **Headline metric:** `secure_and_functional` means the patch compiles, the exploit is blocked, tests aren't broken, and there are no new high-severity findings.
8. **Sanity models.** On calibrated cases, `oracle` (returns the human fix) must score about 100% and `identity` (returns the unchanged code) about 0%. If not, there is a pipeline or environment problem, not a model result.

Plausible is not the same as correct. A patch that blocks one PoC may still be incomplete. Use `identical_to_reference_rate` and a manual review of a sample of plausible patches, as the SoK paper does, before claiming correctness.

## How patches are applied (and why not `vul4c apply`)

The `vul4c` source (`Vul4C_Src/vul4c_tools.py`) shows three things that matter:

- `vul4c apply` patches only one file per case. Its hunk parser skips `@@ -N +N @@` headers and misplaces later hunks when earlier ones change the line count.
- `vul4c reproduce` and `vul4c test` always exit with code 0. The pipeline reads the exploit outcome from sanitizer output, and test results from the automake `# PASS: / # FAIL:` summary of `make check`.
- `vul4c compile` exits non-zero when the build fails.

The pipeline therefore writes each patched file directly into `source/<path>`, byte for byte, when the checked-out file matches the benchmark's OLD file (checked by sha256). Otherwise it applies the patch as a unified diff with GNU `patch`. Each variant is restored from a pristine backup to the same absolute path, because autotools records absolute paths. Indexed pairs such as `sfconvert.c_OLD-1` / `_OLD-2` are successive patches to one file, so they are merged: first OLD to last NEW.

`tests_preserved` compares the candidate's test summary with the human fix's summary. It is true when the candidate passes at least as many tests and has no more failures or errors. If no summary is printed, the result is unknown.

## Setup (once, on the GPU machine)

```bash
sudo apt install cppcheck
pip install flawfinder
pip install bitsandbytes          # only for 4-bit 7B models
# Docker Desktop with WSL integration, or docker.io inside WSL
bash scripts/check_eval_environment.sh                # pulls vul4c/vul4c:4.0
bash scripts/check_eval_environment.sh CVE-2017-6832  # one-case sandbox smoke test
export ANTHROPIC_API_KEY=...   # only for the API models you enable
```

If the `vul4c` command is missing inside the image, mount the SoK repo and install it through `sandbox.mounts` and `sandbox.setup_commands` (the check script prints the exact lines). The tool also needs `~/vul4c_data/vul4c.ini` with `VUL4C_PATH` pointing at the SoK folder, because it copies each case's exploit from `<VUL4C_PATH>/Vul4C-Benchmark`. For example:

```json
"mounts": ["/path/to/SoK-main:/sok"],
"setup_commands": ["mkdir -p ~/vul4c_data && printf '[VUL4C]\\nVUL4C_PATH = /sok\\n' > ~/vul4c_data/vul4c.ini && cd /sok && pip install ."]
```

## Running

1. Edit `config/experiment.json`: set `benchmark_root`, then choose `cases` (an empty list means all 144) and set `"enabled": true` on the models you want.
2. Pilot on one case, using the sanity models first:
   ```bash
   python3 pipeline/run_experiment.py --config config/experiment.json --stage all --models oracle identity
   ```
   Check `results/experiments/pilot_multi_model/report.md`: oracle should be 100% secure_and_functional and identity 0%.
3. Add real models:
   ```bash
   python3 pipeline/run_experiment.py --config config/experiment.json --stage generate --models qwen2.5-coder-1.5b
   python3 pipeline/run_experiment.py --config config/experiment.json --stage evaluate
   python3 pipeline/run_experiment.py --config config/experiment.json --stage report
   ```
   Local models are loaded one at a time, and each is unloaded before the next starts. Every stage skips work that has already been done, so you can stop a run and restart it.
4. Static analysis only (no Docker): add `--no-docker` to the evaluate stage.

## Outputs (`results/experiments/<experiment_name>/`)

- `generations.jsonl`: every prompt result. Each record has the raw output, parse status, patch, and token counts.
- `calibration.jsonl`: per-case sandbox calibration, with log tails.
- `evaluations.jsonl`: per-candidate results for apply, compile, exploit, tests, and static findings.
- `report.md`, `detection_summary.csv`, `repair_summary.csv`, `repair_by_cwe_family.csv`, `summary.json`.

## Known limitations

- Vul4C sanitizer flags can break some test suites, so tests run after recompiling with `--no-flags`, following the Vul4C README.
- 8 of the 144 cases are skipped because the code the fix changed is over 600 lines (`max_total_region_lines`); they are listed in `cases.json`. 136 cases remain.
- For 60 files the dataset gives no repository path (`Vul4C.json` records one file per case), so the path is looked up inside the container by file name. If a name is ambiguous, the case shows up as an apply failure in calibration.
- The CWE ground truth is the benchmark's label (for example, CWE-20 for a heap overflow). Report the `cwe_family` score alongside `cwe_exact`.
- Static analysis runs on single files without the project's build context, so it is a differential signal, not a full audit.
