"""Deterministic, local-first experimental issue network manager."""

from ._version import __version__
from .service import IssueManager

__all__ = ["IssueManager", "__version__"]
