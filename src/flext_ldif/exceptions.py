"""FLEXT LDIF Exceptions class.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextExceptions
from flext_core import FlextResult


class FlextLdifExceptions(FlextExceptions):
    """LDIF domain exceptions extending flext-core FlextExceptions.

    Provides LDIF-specific exception handling patterns.
    Uses flext-core SOURCE OF TRUTH for exception patterns.
    """

    # =============================================================================
    # FLEXT RESULT FACTORY METHODS - USING CORRECT FLEXT-CORE API
    # =============================================================================

    @classmethod
    def validation_error(
        cls,
        message: str,
        *,
        field: str | None = None,
        value: object = None,
        validation_details: object = None,
    ) -> FlextResult[None]:
        """Create validation error FlextResult using correct flext-core API."""
        _ = field, value, validation_details  # Suppress unused argument warnings
        return FlextResult[None].fail(message, error_code="VALIDATION_ERROR")

    @classmethod
    def parse_error(cls, message: str) -> FlextResult[None]:
        """Create parse error FlextResult."""
        return FlextResult[None].fail(message, error_code="PARSE_ERROR")

    @classmethod
    def processing_error(
        cls,
        message: str,
        *,
        business_rule: str | None = None,
        operation: str | None = None,
    ) -> FlextResult[None]:
        """Create processing error FlextResult using correct flext-core API."""
        _ = business_rule, operation  # Suppress unused argument warnings
        return FlextResult[None].fail(message, error_code="PROCESSING_ERROR")

    @classmethod
    def file_error(cls, message: str) -> FlextResult[None]:
        """Create file error FlextResult."""
        return FlextResult[None].fail(message, error_code="FILE_ERROR")

    @classmethod
    def configuration_error(
        cls,
        message: str,
        *,
        config_key: str | None = None,
        config_file: str | None = None,
    ) -> FlextResult[None]:
        """Create configuration error FlextResult using correct flext-core API."""
        _ = config_key, config_file  # Suppress unused argument warnings
        return FlextResult[None].fail(message, error_code="CONFIGURATION_ERROR")

    @classmethod
    def connection_error(
        cls, message: str, *, service: str | None = None, endpoint: str | None = None
    ) -> FlextResult[None]:
        """Create connection error FlextResult using correct flext-core API."""
        _ = service, endpoint  # Suppress unused argument warnings
        return FlextResult[None].fail(message, error_code="CONNECTION_ERROR")

    @classmethod
    def timeout_error(
        cls, message: str, *, timeout_seconds: float | None = None
    ) -> FlextResult[None]:
        """Create timeout error FlextResult using correct flext-core API."""
        _ = timeout_seconds  # Suppress unused argument warning
        return FlextResult[None].fail(message, error_code="TIMEOUT_ERROR")

    @classmethod
    def authentication_error(
        cls, message: str, *, auth_method: str | None = None
    ) -> FlextResult[None]:
        """Create authentication error FlextResult using correct flext-core API."""
        _ = auth_method  # Suppress unused argument warning
        return FlextResult[None].fail(message, error_code="AUTHENTICATION_ERROR")

    @classmethod
    def error(cls, message: str) -> FlextResult[None]:
        """Create generic error FlextResult."""
        return FlextResult[None].fail(message, error_code="GENERIC_ERROR")

    @classmethod
    def entry_error(cls, message: str) -> FlextResult[None]:
        """Create entry error FlextResult."""
        return FlextResult[None].fail(message, error_code="ENTRY_ERROR")

    # =============================================================================
    # LDIF-SPECIFIC DOMAIN ERRORS
    # =============================================================================

    @classmethod
    def dn_validation_error(
        cls, message: str, *, dn_value: str | None = None
    ) -> FlextResult[None]:
        """Create DN validation error FlextResult."""
        _ = dn_value  # Suppress unused argument warning
        return FlextResult[None].fail(message, error_code="DN_VALIDATION_ERROR")

    @classmethod
    def attribute_validation_error(
        cls,
        message: str,
        *,
        attribute_name: str | None = None,
        attribute_value: object = None,
    ) -> FlextResult[None]:
        """Create attribute validation error FlextResult."""
        _ = attribute_name, attribute_value  # Suppress unused argument warnings
        return FlextResult[None].fail(message, error_code="ATTRIBUTE_VALIDATION_ERROR")

    @classmethod
    def encoding_error(
        cls, message: str, *, encoding: str | None = None
    ) -> FlextResult[None]:
        """Create encoding error FlextResult."""
        _ = encoding  # Suppress unused argument warning
        return FlextResult[None].fail(message, error_code="ENCODING_ERROR")

    @classmethod
    def url_validation_error(
        cls, message: str, *, url: str | None = None
    ) -> FlextResult[None]:
        """Create URL validation error FlextResult."""
        _ = url  # Suppress unused argument warning
        return FlextResult[None].fail(message, error_code="URL_VALIDATION_ERROR")

    @classmethod
    def schema_validation_error(
        cls, message: str, *, schema_name: str | None = None
    ) -> FlextResult[None]:
        """Create schema validation error FlextResult."""
        _ = schema_name  # Suppress unused argument warning
        return FlextResult[None].fail(message, error_code="SCHEMA_VALIDATION_ERROR")

    @classmethod
    def objectclass_error(
        cls, message: str, *, objectclass: str | None = None
    ) -> FlextResult[None]:
        """Create objectclass error FlextResult."""
        _ = objectclass  # Suppress unused argument warning
        return FlextResult[None].fail(message, error_code="OBJECTCLASS_ERROR")

    @classmethod
    def ldif_format_error(
        cls, message: str, *, line_number: int | None = None
    ) -> FlextResult[None]:
        """Create LDIF format error FlextResult."""
        _ = line_number  # Suppress unused argument warning
        return FlextResult[None].fail(message, error_code="LDIF_FORMAT_ERROR")

    @classmethod
    def rfc_compliance_error(
        cls, message: str, *, rfc_section: str | None = None
    ) -> FlextResult[None]:
        """Create RFC compliance error FlextResult."""
        _ = rfc_section  # Suppress unused argument warning
        return FlextResult[None].fail(message, error_code="RFC_COMPLIANCE_ERROR")


__all__ = ["FlextLdifExceptions"]
