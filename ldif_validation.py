"""FLEXT-LDIF Validation - Enterprise LDIF Processing Validation.

CONSOLIDATED PEP8 ARCHITECTURE: This module consolidates LDIF validation
functionality into ONE centralized, PEP8-compliant validation module.

CONSOLIDATION MAPPING:
✅ src/flext_ldif/validation.py → LDIF-specific validation utilities
✅ src/flext_ldif/error_handling.py → Error handling and exception management

✅ CORRECT ARCHITECTURE: This module uses flext-ldap root APIs for all LDAP validation.
   ZERO duplication - leverages existing flext-ldap functionality.

This module provides LDIF-specific validation utilities by delegating to
flext-ldap for all DN and attribute validation operations.

Author: FLEXT Development Team
Version: 0.9.0
License: MIT
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, ClassVar

from flext_core import FlextResult, FlextValidationError

# ✅ CORRECT - Import from flext-ldap root API
from flext_ldap import (
    flext_ldap_validate_attribute_name,
    flext_ldap_validate_dn,
)

if TYPE_CHECKING:
    from .ldif_models import FlextLdifEntry

logger = logging.getLogger(__name__)

# =============================================================================
# ERROR HANDLING UTILITIES
# =============================================================================

# Compatibility aliases that redirect to flext-core
FlextLdifErrorHandler = FlextValidationError


def format_validation_error(error: str) -> str:
    """Format validation error message."""
    return f"LDIF Validation Error: {error}"


def handle_ldif_error(error: Exception) -> FlextResult[None]:
    """Handle LDIF processing error."""
    logger.error("LDIF processing error: %s", error)
    return FlextResult.failure(str(error))

# =============================================================================
# LDIF VALIDATION UTILITIES
# =============================================================================


class LdifValidator:
    """LDIF validation utilities using flext-ldap integration.

    Provides LDIF-specific validation by delegating to flext-ldap services
    for all DN and attribute validation operations. Eliminates code duplication
    while maintaining comprehensive validation capabilities.

    Features:
    - DN validation via flext-ldap integration
    - Attribute name validation via flext-ldap
    - LDIF entry business rule validation
    - Format compliance checking
    """

    # Class constants for validation configuration
    STRICT_VALIDATION: ClassVar[bool] = True
    ALLOW_EMPTY_ATTRIBUTES: ClassVar[bool] = False

    @staticmethod
    def validate_dn(dn: str) -> FlextResult[bool]:
        """Validate DN format using flext-ldap service.

        Args:
            dn: Distinguished name to validate

        Returns:
            FlextResult containing validation result (True/False) or error

        """
        try:
            logger.debug(f"Validating DN format: {dn}")

            if not dn or not dn.strip():
                return FlextResult.failure("Empty DN provided")

            # Use flext-ldap service for validation (eliminates duplication)
            validation_result = flext_ldap_validate_dn(dn.strip())

            if validation_result.success:
                logger.debug(f"DN validation passed: {dn}")
                return FlextResult.success(True)
            error_msg = f"DN validation failed: {validation_result.error}"
            logger.warning(error_msg)
            return FlextResult.failure(error_msg)

        except Exception as e:
            error_msg = f"DN validation error: {e}"
            logger.exception(error_msg)
            return FlextResult.failure(error_msg)

    @staticmethod
    def validate_attribute_name(attribute_name: str) -> FlextResult[bool]:
        """Validate attribute name using flext-ldap service.

        Args:
            attribute_name: Attribute name to validate

        Returns:
            FlextResult containing validation result (True/False) or error

        """
        try:
            logger.debug(f"Validating attribute name: {attribute_name}")

            if not attribute_name or not attribute_name.strip():
                return FlextResult.failure("Empty attribute name provided")

            # Use flext-ldap service for validation (eliminates duplication)
            validation_result = flext_ldap_validate_attribute_name(attribute_name.strip())

            if validation_result.success:
                logger.debug(f"Attribute name validation passed: {attribute_name}")
                return FlextResult.success(True)
            error_msg = f"Attribute name validation failed: {validation_result.error}"
            logger.warning(error_msg)
            return FlextResult.failure(error_msg)

        except Exception as e:
            error_msg = f"Attribute name validation error: {e}"
            logger.exception(error_msg)
            return FlextResult.failure(error_msg)

    @classmethod
    def validate_ldif_entry(cls, entry: FlextLdifEntry) -> FlextResult[bool]:
        """Validate complete LDIF entry using business rules.

        Args:
            entry: FlextLdifEntry object to validate

        Returns:
            FlextResult containing validation result (True/False) or error

        """
        try:
            logger.debug(f"Validating LDIF entry: {entry.dn_string}")

            # Validate DN (already validated in domain object, but double-check)
            dn_validation = cls.validate_dn(entry.dn_string)
            if dn_validation.is_failure:
                return dn_validation

            # Validate attributes exist
            if not entry.attributes.names:
                if not cls.ALLOW_EMPTY_ATTRIBUTES:
                    return FlextResult.failure("Entry has no attributes")

            # Validate required objectClass in strict mode
            if not entry.object_classes and cls.STRICT_VALIDATION:
                return FlextResult.failure("Entry missing objectClass attribute")

            # Validate all attribute names
            for attr_name in entry.attributes.names:
                attr_validation = cls.validate_attribute_name(attr_name)
                if attr_validation.is_failure:
                    return FlextResult.failure(f"Invalid attribute '{attr_name}': {attr_validation.error}")

            logger.debug(f"LDIF entry validation passed: {entry.dn_string}")
            return FlextResult.success(True)

        except Exception as e:
            error_msg = f"LDIF entry validation failed: {e}"
            logger.exception(error_msg)
            return FlextResult.failure(error_msg)

    @classmethod
    def validate_ldif_entries(cls, entries: list[FlextLdifEntry]) -> FlextResult[bool]:
        """Validate multiple LDIF entries.

        Args:
            entries: List of FlextLdifEntry objects to validate

        Returns:
            FlextResult containing validation result (True/False) or error

        """
        try:
            logger.debug(f"Validating {len(entries)} LDIF entries")

            if not entries:
                return FlextResult.success(True)  # Empty list is valid

            # Validate each entry
            for i, entry in enumerate(entries):
                entry_validation = cls.validate_ldif_entry(entry)
                if entry_validation.is_failure:
                    return FlextResult.failure(f"Entry {i}: {entry_validation.error}")

            logger.info(f"Successfully validated {len(entries)} LDIF entries")
            return FlextResult.success(True)

        except Exception as e:
            error_msg = f"LDIF entries validation failed: {e}"
            logger.exception(error_msg)
            return FlextResult.failure(error_msg)

    @classmethod
    def validate_ldif_format(cls, content: str) -> FlextResult[bool]:
        """Validate LDIF format compliance.

        Args:
            content: LDIF content string to validate

        Returns:
            FlextResult containing validation result (True/False) or error

        """
        try:
            logger.debug("Validating LDIF format compliance")

            if not content or not content.strip():
                return FlextResult.failure("Empty LDIF content provided")

            # Basic format validation
            lines = content.splitlines()
            in_entry = False
            dn_found = False

            for line_num, line in enumerate(lines, 1):
                line = line.rstrip()

                # Skip empty lines and comments
                if not line or line.startswith("#"):
                    continue

                # Check for DN line
                if line.lower().startswith("dn:"):
                    if in_entry and not dn_found:
                        return FlextResult.failure(f"Missing DN in entry at line {line_num}")
                    in_entry = True
                    dn_found = True

                    # Validate DN format
                    dn_value = line[3:].strip()
                    if dn_value.startswith(":"):
                        # Base64 encoded DN - skip detailed validation for now
                        dn_value = dn_value[1:].strip()

                    dn_validation = cls.validate_dn(dn_value)
                    if dn_validation.is_failure:
                        return FlextResult.failure(f"Invalid DN at line {line_num}: {dn_validation.error}")

                # Check attribute format
                elif ":" in line and not line.startswith(" "):
                    if not in_entry:
                        return FlextResult.failure(f"Attribute outside entry at line {line_num}")

                    attr_name = line.split(":", 1)[0].strip()
                    attr_validation = cls.validate_attribute_name(attr_name)
                    if attr_validation.is_failure:
                        return FlextResult.failure(f"Invalid attribute name at line {line_num}: {attr_validation.error}")

            logger.info("LDIF format validation passed")
            return FlextResult.success(True)

        except Exception as e:
            error_msg = f"LDIF format validation failed: {e}"
            logger.exception(error_msg)
            return FlextResult.failure(error_msg)

# =============================================================================
# VALIDATION HELPER FUNCTIONS
# =============================================================================


def validate_dn(dn: str) -> FlextResult[bool]:
    """Validate DN format - convenience function."""
    return LdifValidator.validate_dn(dn)


def validate_attribute_name(attribute_name: str) -> FlextResult[bool]:
    """Validate attribute name - convenience function."""
    return LdifValidator.validate_attribute_name(attribute_name)


def validate_ldif_entry(entry: FlextLdifEntry) -> FlextResult[bool]:
    """Validate LDIF entry - convenience function."""
    return LdifValidator.validate_ldif_entry(entry)


def validate_ldif_entries(entries: list[FlextLdifEntry]) -> FlextResult[bool]:
    """Validate LDIF entries - convenience function."""
    return LdifValidator.validate_ldif_entries(entries)


def validate_ldif_format(content: str) -> FlextResult[bool]:
    """Validate LDIF format - convenience function."""
    return LdifValidator.validate_ldif_format(content)


# =============================================================================
# LEGACY COMPATIBILITY
# =============================================================================

# Backward compatibility aliases
class FlextLdifValidator:
    """Legacy validator class for backward compatibility."""

    @staticmethod
    def validate_dn(dn: str) -> FlextResult[bool]:
        """Validate DN - legacy compatibility."""
        return LdifValidator.validate_dn(dn)

    @staticmethod
    def validate_attribute_name(attr_name: str) -> FlextResult[bool]:
        """Validate attribute name - legacy compatibility."""
        return LdifValidator.validate_attribute_name(attr_name)

    @staticmethod
    def validate_entry(entry: FlextLdifEntry) -> FlextResult[bool]:
        """Validate entry - legacy compatibility."""
        return LdifValidator.validate_ldif_entry(entry)

# =============================================================================
# PUBLIC API
# =============================================================================


__all__ = [
    # Error handling
    "FlextLdifErrorHandler",
    # Legacy compatibility
    "FlextLdifValidator",
    # Main validator class
    "LdifValidator",
    "format_validation_error",
    "handle_ldif_error",
    "validate_attribute_name",
    # Convenience functions
    "validate_dn",
    "validate_ldif_entries",
    "validate_ldif_entry",
    "validate_ldif_format",
]
