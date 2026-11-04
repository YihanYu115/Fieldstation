"""Execute one explicitly selected trusted UTF-8 Python file, once."""
from __future__ import annotations

import sys
import traceback
from pathlib import Path
from typing import Any


def run_script(path: str | Path, tools: Any) -> int:
    file = Path(path).resolve()
    original_path = list(sys.path)
    try:
        # Ordinary neighboring helpers work, without adding the package source tree.
        sys.path.insert(0, str(file.parent))
        namespace: dict[str, Any] = {'__file__': str(file), '__name__': '__workflow_policy__', '__package__': None}
        code = compile(file.read_text(encoding='utf-8'), str(file), 'exec')
        exec(code, namespace)
        run = namespace.get('run')
        if not callable(run):
            raise ValueError(str(file) + ': expected a callable run(tools)')
        run(tools)
        return 0
    except Exception:
        print('User script failed: ' + str(file), file=sys.stderr)
        traceback.print_exc()
        return 1
    finally:
        sys.path[:] = original_path
        tools.close()
