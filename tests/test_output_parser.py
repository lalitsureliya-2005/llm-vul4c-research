"""Unit tests for detection output parsing and validation."""

import json
from pathlib import Path
import sys
import tempfile
import unittest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from pipeline.output_parser import (
    extract_first_json_object,
    parse_detection_output,
    summarize_predictions,
)


class TestParseDetectionOutput(unittest.TestCase):

    def test_valid_object(self):
        text = '{"is_vulnerable": true, "cwe": "cwe-20", "evidence": "len unchecked", "reasoning": "Missing bounds check."}'
        parsed, status, err = parse_detection_output(text)
        self.assertEqual(status, "valid")
        self.assertIsNone(err)
        self.assertTrue(parsed["is_vulnerable"])
        self.assertEqual(parsed["cwe"], "CWE-20")

    def test_valid_benign_with_nulls(self):
        text = '{"is_vulnerable": false, "cwe": null, "evidence": null, "reasoning": "No issue found."}'
        parsed, status, _ = parse_detection_output(text)
        self.assertEqual(status, "valid")
        self.assertFalse(parsed["is_vulnerable"])

    def test_markdown_fence_and_trailing_text(self):
        text = '```json\n{"is_vulnerable": true, "cwe": "CWE-787", "evidence": "if (x) { y; }", "reasoning": "Overflow."}\n```'
        self.assertEqual(parse_detection_output(text)[1], "valid")
        text2 = 'Here you go:\n{"is_vulnerable": true, "cwe": null, "evidence": "a{b}", "reasoning": "r"}\nHope this helps.'
        self.assertEqual(parse_detection_output(text2)[1], "valid")

    def test_schema_echo_bare_types(self):
        text = '{"is_vulnerable": boolean, "cwe": string or null, "evidence": string or null, "reasoning": string}'
        parsed, status, _ = parse_detection_output(text)
        self.assertIsNone(parsed)
        self.assertEqual(status, "schema_echo")

    def test_schema_echo_quoted_descriptions(self):
        text = json.dumps({
            "is_vulnerable": True,
            "cwe": "string or null (the specific CWE identifier)",
            "evidence": "string or null",
            "reasoning": "string",
        })
        self.assertEqual(parse_detection_output(text)[1], "schema_echo")

    def test_truncated_fragment(self):
        text = '{"is_vulnerable": true, "cwe": "CWE-20", "evidence": "WAVE_FORMAT'
        parsed, status, _ = parse_detection_output(text)
        self.assertIsNone(parsed)
        self.assertEqual(status, "truncated_json")

    def test_missing_fields(self):
        self.assertEqual(parse_detection_output('{"is_vulnerable": true}')[1], "missing_fields")

    def test_wrong_types(self):
        text = '{"is_vulnerable": "yes", "cwe": "CWE-20", "evidence": null, "reasoning": "r"}'
        self.assertEqual(parse_detection_output(text)[1], "wrong_types")

    def test_no_json_and_empty(self):
        self.assertEqual(parse_detection_output("WAVE_FORMAT_PCM = 0x0001,")[1], "no_json_object")
        self.assertEqual(parse_detection_output("")[1], "empty")
        self.assertEqual(parse_detection_output(None)[1], "empty")

    def test_brace_scanner_ignores_braces_in_strings(self):
        obj, complete = extract_first_json_object('{"a": "}{", "b": 1} tail')
        self.assertTrue(complete)
        self.assertEqual(json.loads(obj), {"a": "}{", "b": 1})

    def test_summarize_predictions_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "p.jsonl"
            with open(path, "w") as fh:
                fh.write(json.dumps({"sample_id": "a", "task_type": "detection",
                                     "generated_text": '{"is_vulnerable": false, "cwe": null, "evidence": null, "reasoning": "ok"}'}) + "\n")
                fh.write(json.dumps({"sample_id": "b", "task_type": "detection",
                                     "generated_text": '{"is_vulnerable": boolean'}) + "\n")
                fh.write(json.dumps({"sample_id": "c", "task_type": "repair", "generated_text": "int main(){}"}) + "\n")
            summary = summarize_predictions(path)
            self.assertEqual(summary["detection_records"], 2)
            self.assertEqual(summary["status_counts"], {"valid": 1, "truncated_json": 1})


if __name__ == "__main__":
    unittest.main()
