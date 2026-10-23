# Re-scoring notes (2026-10-23)

The Qwen2.5-Coder-1.5B outputs in `generations.jsonl` (model `ollama-qwen-1.5b`) are the original run and were **not** regenerated. Everything derived from them was recomputed with the fixed pipeline.

## Why the files were recomputed

1. **Line-ending bug.** The original run used a copy of the benchmark with Windows (CRLF) line endings. When the pipeline put an answer back into the file, it dropped the CRLF and also lost trailing blank lines and spaces. As a result, every candidate counted as "changed", including the `identity` sanity model, which returns the code unchanged (136/136).
2. **CWE labels.** Benchmark labels such as `NVD-CWE-Other` were rejected by the JSON validator. This made 4–8 sanity-model answers "invalid".
3. **Only cppcheck ran.** flawfinder was not installed. The re-score uses cppcheck 2.13 (with `--max-configs=1`) and flawfinder 2.0.20.

## What was regenerated

- `oracle` and `identity` entries in `generations.jsonl`. These are deterministic sanity models; no LLM is involved.
- `evaluations.jsonl`, `report.md`, the CSV files and `summary.json`.

## Not done yet

**The dynamic stage did not run in the original run** (`--no-docker`; 0 calibrated cases). Compile, exploit and test results are therefore still missing, and so is the "security side effects" section. To fill them in, re-run the evaluate stage with Docker:

```bash
python3 pipeline/run_experiment.py --config <config with this experiment_name> --stage evaluate
python3 pipeline/run_experiment.py --config <same config> --stage report
```

The model does not need to be queried again.
