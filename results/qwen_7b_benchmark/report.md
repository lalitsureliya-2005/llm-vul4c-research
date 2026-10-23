# benchmark_qwen1.5b_all: model comparison

Generated 2026-10-23 17:07 UTC.

## Calibration
0 of 0 evaluated cases calibrated (vulnerability reproduces in the sandbox and the human fix blocks it). Dynamic repair metrics use calibrated cases only.

## Detection

Each case is asked twice: vulnerable version (label = vulnerable) and developer-fixed version (label = not vulnerable). Invalid answers count as 'not flagged'. `pair_accuracy` = both versions correct.

| model | samples | valid_output_rate | accuracy | precision | recall | f1 | false_positive_rate | pair_accuracy | cwe_exact | cwe_family |
|---|---|---|---|---|---|---|---|---|---|---|
| identity | 272 | 100.0% | 50.0% | 50.0% | 100.0% | 66.7% | 100.0% | 0.0% | 100.0% | 100.0% |
| ollama-qwen-7b | 272 | 100.0% | 48.5% | 46.4% | 19.1% | 27.1% | 22.1% | 4.4% | 20.8% | 45.8% |
| oracle | 272 | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 0.0% | 100.0% | 100.0% | 100.0% |

## Repair

`secure_and_functional` = compiles, the proof-of-concept exploit no longer crashes, the test suite still passes (when it passes for the human fix), and no new high-severity static analysis findings.

| model | candidates | calibrated_candidates | generated_rate | applied_rate | compiled_rate | exploit_blocked_rate | tests_preserved_rate | new_high_static_issue_rate | secure_and_functional_rate | identical_to_reference_rate | pass@1 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| identity | 136 | 0 | 100.0% | - | - | - | - | 0.0% | - | 0.0% | - |
| ollama-qwen-7b | 136 | 0 | 89.7% | - | - | - | - | 0.0% | - | 0.0% | - |
| oracle | 136 | 0 | 100.0% | - | - | - | - | 0.0% | - | 100.0% | - |

## Security side effects of repairs

How often a patch that works (compiles and blocks the exploit, `plausible`) introduces a new high-severity static-analysis finding that the vulnerable original did not have. Denominators are working patches only. `*_confirmed` columns count only findings a reviewer marked as real (see `scripts/review_findings.py`); `review_precision` is the share of reviewed findings that were real. Limitation: the sandbox runs only each case's own proof-of-concept, so a new memory error elsewhere in a patch is detected only by static analysis, not dynamically.

| model | compiled_patches | plausible_patches | new_findings_in_plausible | reviewed_findings | compiled_with_new_issue_rate | plausible_with_new_issue_rate | plausible_with_confirmed_issue_rate | review_precision | secure_and_functional_confirmed_rate |
|---|---|---|---|---|---|---|---|---|---|
| identity | 0 | 0 | 0 | 0 | - | - | - | - | - |
| ollama-qwen-7b | 0 | 0 | 0 | 0 | - | - | - | - | - |
| oracle | 0 | 0 | 0 | 0 | - | - | - | - | - |

No manual review imported yet; the rates above are tool-reported and include false alarms.

## Repair by CWE family

| model | cwe_family | calibrated_candidates | exploit_blocked_rate | secure_and_functional_rate |
|---|---|---|---|---|
| identity | bounds | 0 | - | - |
| identity | input_validation | 0 | - | - |
| identity | integer | 0 | - | - |
| identity | lifetime | 0 | - | - |
| identity | null | 0 | - | - |
| identity | resource | 0 | - | - |
| identity | unknown | 0 | - | - |
| ollama-qwen-7b | bounds | 0 | - | - |
| ollama-qwen-7b | input_validation | 0 | - | - |
| ollama-qwen-7b | integer | 0 | - | - |
| ollama-qwen-7b | lifetime | 0 | - | - |
| ollama-qwen-7b | null | 0 | - | - |
| ollama-qwen-7b | resource | 0 | - | - |
| ollama-qwen-7b | unknown | 0 | - | - |
| oracle | bounds | 0 | - | - |
| oracle | input_validation | 0 | - | - |
| oracle | integer | 0 | - | - |
| oracle | lifetime | 0 | - | - |
| oracle | null | 0 | - | - |
| oracle | resource | 0 | - | - |
| oracle | unknown | 0 | - | - |

## Sanity models

`oracle` returns the human fix and `identity` returns the unchanged vulnerable code. On calibrated cases, oracle should be ~100% exploit-blocked and identity ~0%. If not, fix the pipeline before trusting other numbers. For detection, `identity` always answers 'vulnerable' and shows the score of a model with no discrimination ability.
