"""Atomic durable intents and receipts, never a Queue or a source-state replica."""
from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Any

from .run_lock import exclusive
from .tools_contracts import ToolError, canonical, decode, outside_path


class ActionJournal:
    def __init__(self, path: str | Path):
        self.path = outside_path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def lock(self):
        return exclusive(self.path.with_suffix(self.path.suffix + '.lock'), wait_seconds=5)

    def load(self) -> dict[str, Any]:
        if not self.path.exists():
            return {'format': 'workflow-tools-actions-1', 'binding': None, 'actions': {}}
        try:
            value = decode(self.path.read_bytes())
            if (value['format'] != 'workflow-tools-actions-1'
                    or not isinstance(value['actions'], dict)):
                raise ValueError()
            return dict(value)
        except (KeyError, ValueError, TypeError, ToolError) as exc:
            raise ToolError('journal_invalid', 'original journal is unreadable; never recreate it') from exc

    def save(self, value: dict[str, Any]) -> None:
        # Replace only after the full new intent has reached durable local storage.
        fd, name = tempfile.mkstemp(prefix=self.path.name + '.', suffix='.tmp', dir=self.path.parent)
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(canonical(value).encode('utf-8'))
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(name, self.path)
            if os.name != 'nt':
                directory = os.open(self.path.parent, os.O_RDONLY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
        finally:
            if os.path.exists(name):
                os.unlink(name)

    def bind(self, binding: dict[str, str]) -> None:
        with self.lock():
            value = self.load()
            if value['binding'] is None:
                value['binding'] = binding
                self.save(value)
            elif value['binding'] != binding:
                pending = any(action['state'] == 'pending' for action in value['actions'].values())
                raise ToolError('recovery_binding_changed',
                                'journal belongs to another endpoint, service or principal', status=409,
                                effect='unknown' if pending else 'not_committed')
