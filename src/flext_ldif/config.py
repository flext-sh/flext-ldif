"""Compatibility shim: re-export config from models.

Historically, tests import flext_ldif.config.FlextLdifConfig. After consolidation,
the canonical definition lives in flext_ldif.models. This module only re-exports it
to preserve backward compatibility.
"""

from __future__ import annotations

from .models import FlextLdifConfig

__all__ = ["FlextLdifConfig"]
