"""Flext-LDIF Base Module.

This module provides the foundational base class for flext-ldif services.

Scope:
- FlextLdifServiceBase: Service base class inheriting from FlextService
- Full config access via self.config with namespace support

Usage:
    # Service inheritance:
    class MyService(FlextLdifServiceBase[MyResult]):
        def execute(self) -> FlextResult[MyResult]:
            ldif_config = self.config.get_namespace("ldif", FlextLdifConfig)
            encoding = ldif_config.ldif_encoding

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextService
from flext_core.typings import T


class FlextLdifServiceBase(FlextService[T]):
    """Base class for LDIF services.

    Inherits all functionality from FlextService:
    - self.logger: Configured logger instance
    - self.config: FlextConfig singleton with namespace support
    - execute() pattern: Subclasses implement execute() -> FlextResult[T]
    - with_config(): Dependency injection of config

    Access configuration:
        ldif_config = self.config.get_namespace("ldif", FlextLdifConfig)
        encoding = ldif_config.ldif_encoding
    """
