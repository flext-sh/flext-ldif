"""FLEXT LDIF Exceptions class.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextExceptions, FlextResult


class FlextLdifExceptions(FlextExceptions):
    """LDIF domain exceptions extending flext-core FlextExceptions."""

    # =============================================================================
    # FLEXT RESULT FACTORY METHODS - DIRECT USE OF FLEXT-CORE
    # =============================================================================

    @classmethod
    def validation_error(cls, message: str) -> FlextResult[None]:
        """Create validation error FlextResult."""
        return FlextResult[None].fail(message)

    @classmethod
    def parse_error(cls, message: str) -> FlextResult[None]:
        """Create parse error FlextResult."""
        return FlextResult[None].fail(message)

    @classmethod
    def processing_error(cls, message: str) -> FlextResult[None]:
        """Create processing error FlextResult."""
        return FlextResult[None].fail(message)

    @classmethod
    def file_error(cls, message: str) -> FlextResult[None]:
        """Create file error FlextResult."""
        return FlextResult[None].fail(message)

    @classmethod
    def configuration_error(cls, message: str) -> FlextResult[None]:
        """Create configuration error FlextResult."""
        return FlextResult[None].fail(message)

    @classmethod
    def connection_error(cls, message: str) -> FlextResult[None]:
        """Create connection error FlextResult."""
        return FlextResult[None].fail(message)

    @classmethod
    def timeout_error(cls, message: str) -> FlextResult[None]:
        """Create timeout error FlextResult."""
        return FlextResult[None].fail(message)

    @classmethod
    def authentication_error(cls, message: str) -> FlextResult[None]:
        """Create authentication error FlextResult."""
        return FlextResult[None].fail(message)

    @classmethod
    def error(cls, message: str) -> FlextResult[None]:
        """Create generic error FlextResult."""
        return FlextResult[None].fail(message)

    @classmethod
    def entry_error(cls, message: str) -> FlextResult[None]:
        """Create entry error FlextResult."""
        return FlextResult[None].fail(message)


__all__ = ["FlextLdifExceptions"]
