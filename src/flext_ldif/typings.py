"""Centralized typings facade for flext-ldif.

- Extends flext-core types and re-exports LDIF-specific types
- Keep `types.py` as domain-specific definitions; import here as public API
"""

from __future__ import annotations

from flext_core.typings import FlextTypes as CoreFlextTypes

# Re-export LDIF domain-specific types for a single import point
from flext_ldif.types import *  # noqa: F401,F403


class FlextTypes(CoreFlextTypes):
    """LDIF domain-specific types can extend here."""


__all__ = [
    "FlextTypes",
] + [name for name in dir() if not name.startswith("_")]
