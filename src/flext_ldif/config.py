"""Compatibility shim: re-export config from models.

Historically, tests import flext_ldif.config.FlextLdifConfig. After consolidation,
the canonical definition lives in flext_ldif.models. This module only re-exports it
to preserve backward compatibility.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_ldif.models import FlextLdifConfig

__all__ = ["FlextLdifConfig"]
