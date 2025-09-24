"""FLEXT LDIF Exceptions class.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextExceptions, FlextResult
from flext_ldif.mixins import FlextLdifMixins


class FlextLdifExceptions(FlextExceptions, FlextLdifMixins.FactoryMixin):
    """LDIF domain exceptions extending flext-core FlextExceptions.

    Provides LDIF-specific exception handling patterns.
    Uses flext-core SOURCE OF TRUTH for exception patterns.
    """

    # =============================================================================
    # FLEXT RESULT FACTORY METHODS - DIRECT USE OF FLEXT-CORE
    # =============================================================================

    @classmethod
    def validation_error(cls, message: str) -> FlextResult[None]:
        """Create validation error FlextResult."""
        return FlextResult[None].fail(message, error_code="VALIDATION_ERROR")

    @classmethod
    def parse_error(cls, message: str) -> FlextResult[None]:
        """Create parse error FlextResult."""
        return FlextResult[None].fail(message, error_code="PARSE_ERROR")

    @classmethod
    def processing_error(cls, message: str) -> FlextResult[None]:
        """Create processing error FlextResult."""
        return FlextResult[None].fail(message, error_code="PROCESSING_ERROR")

    @classmethod
    def file_error(cls, message: str) -> FlextResult[None]:
        """Create file error FlextResult."""
        return FlextResult[None].fail(message, error_code="FILE_ERROR")

    @classmethod
    def configuration_error(cls, message: str) -> FlextResult[None]:
        """Create configuration error FlextResult."""
        return FlextResult[None].fail(message, error_code="CONFIGURATION_ERROR")

    @classmethod
    def connection_error(cls, message: str) -> FlextResult[None]:
        """Create connection error FlextResult."""
        return FlextResult[None].fail(message, error_code="CONNECTION_ERROR")

    @classmethod
    def timeout_error(cls, message: str) -> FlextResult[None]:
        """Create timeout error FlextResult."""
        return FlextResult[None].fail(message, error_code="TIMEOUT_ERROR")

    @classmethod
    def authentication_error(cls, message: str) -> FlextResult[None]:
        """Create authentication error FlextResult."""
        return FlextResult[None].fail(message, error_code="AUTHENTICATION_ERROR")

    @classmethod
    def error(cls, message: str) -> FlextResult[None]:
        """Create generic error FlextResult."""
        return FlextResult[None].fail(message, error_code="GENERIC_ERROR")

    @classmethod
    def entry_error(cls, message: str) -> FlextResult[None]:
        """Create entry error FlextResult."""
        return FlextResult[None].fail(message, error_code="ENTRY_ERROR")


__all__ = ["FlextLdifExceptions"]
