"""Complete DDL for fresh current-version projects; no historical upgrade chain."""
from pathlib import Path

CURRENT_SCHEMA_SQL = Path(__file__).with_suffix(".sql").read_text(encoding="utf-8")
