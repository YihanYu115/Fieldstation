from __future__ import annotations

import json

from .compatibility import COMPAT_POLICY

DEFAULT_POLICY = COMPAT_POLICY


def default_policy_text() -> str:
    # JSON is a strict subset of YAML. Keeping this representation makes the MVP
    # editable as policy.yaml without adding a runtime dependency.
    return json.dumps(DEFAULT_POLICY, ensure_ascii=False, indent=2) + "\n"
