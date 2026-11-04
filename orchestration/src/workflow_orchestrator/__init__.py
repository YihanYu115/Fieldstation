"""Independent tools load without importing the retired workflow chain."""
from __future__ import annotations

from typing import Any

__all__ = ['WorkflowAPIError', 'WorkflowClient']


def __getattr__(name: str) -> Any:
    if name in {'WorkflowAPIError', 'WorkflowClient'}:
        from .client import WorkflowAPIError, WorkflowClient
        return {'WorkflowAPIError': WorkflowAPIError, 'WorkflowClient': WorkflowClient}[name]
    raise AttributeError(name)
