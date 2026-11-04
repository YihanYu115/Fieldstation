from __future__ import annotations

import re
import sys
from pathlib import Path

CORE_MODULES = (
    "issue_manager/default_policy.py",
    "issue_manager/errors.py",
    "issue_manager/field_bundle_service.py",
    "issue_manager/import_service.py",
    "issue_manager/record_service.py",
    "issue_manager/registry_service.py",
    "issue_manager/report_service.py",
    "issue_manager/service.py",
    "issue_manager/store.py",
)
DOMAIN_TERMS = ("superconducting", "qubit", "readout", "coherence", "f01")


def main() -> int:
    failures: list[str] = []
    for relative in CORE_MODULES:
        path = Path(relative)
        text = path.read_text(encoding="utf-8")
        for line_number, line in enumerate(text.splitlines(), start=1):
            for term in DOMAIN_TERMS:
                if re.search(rf"\b{re.escape(term)}\b", line, flags=re.IGNORECASE):
                    failures.append(f"{relative}:{line_number}: domain term {term!r}")
    if failures:
        print("generic core check failed:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print("generic core check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
