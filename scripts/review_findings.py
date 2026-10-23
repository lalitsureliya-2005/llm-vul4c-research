#!/usr/bin/env python3
"""Export / import the manual review of patch-introduced security findings.

  python3 scripts/review_findings.py export --config config/experiment.json
  python3 scripts/review_findings.py import --config config/experiment.json

See pipeline/review.py for the full workflow.
"""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pipeline.review import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
