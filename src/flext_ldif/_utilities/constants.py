"""Utilities for accessing and validating standardized constants.

This module provides helper functions for working with FlextLdifConstants and
server-specific Constants classes defined in server quirks modules.

Provides:
- Parameterized validation for any category of values
- Get valid values by category
- Bulk validation with detailed error reporting

DRY Refactoring: All validation methods consolidated into parameterized functions.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from enum import StrEnum
from typing import ClassVar

from flext_ldif.constants import FlextLdifConstants


class FlextLdifUtilitiesConstants:
    """Utilities for accessing and validating standardized constants.

    All validation is done via parameterized methods that accept a category.
    This eliminates duplication across is_valid_*, get_*, and validate_* methods.
    """

    # SECTION 1: VALIDATION CATEGORIES (RFC BASELINE VALUES)
    # =========================================================================

    class Category(StrEnum):
        """Categories of values that can be validated."""

        SERVER_TYPE = "server_type"
        PERMISSION = "permission"
        ACL_ACTION = "acl_action"
        ENCODING = "encoding"

    # Registry of valid values per category
    _VALID_VALUES: ClassVar[dict[str, set[str]]] = {
        "server_type": {
            "rfc",
            "oid",
            "oud",
            "openldap",
            "openldap1",
            "ad",
            "apache",
            "389ds",
            "novell",
            "tivoli",
            "relaxed",
        },
        "permission": {
            "read",
            "write",
            "add",
            "delete",
            "search",
            "compare",
            "auth",
            "all",
            "none",
        },
        "acl_action": {"allow", "deny"},
        "encoding": {
            "utf-8",
            "utf-16",
            "utf-16-le",
            "utf-32",
            "ascii",
            "latin-1",
            "cp1252",
            "iso-8859-1",
        },
    }

    # SECTION 2: UNIFIED PARAMETERIZED VALIDATION
    # =========================================================================

    @staticmethod
    def get_valid_values(category: str | Category) -> set[str]:
        """Get all valid values for a category.

        Args:
            category: Category name or Category enum value

        Returns:
            Set of valid values for the category

        Raises:
            KeyError: If category is not recognized

        Example:
            >>> FlextLdifUtilitiesConstants.get_valid_values("server_type")
            {'rfc', 'oid', 'oud', ...}
            >>> FlextLdifUtilitiesConstants.get_valid_values(Category.PERMISSION)
            {'read', 'write', 'add', ...}

        """
        key = str(category).lower()
        if key not in FlextLdifUtilitiesConstants._VALID_VALUES:
            msg = f"Unknown category: {category}"
            raise KeyError(msg)
        return FlextLdifUtilitiesConstants._VALID_VALUES[key].copy()

    @staticmethod
    def is_valid(value: str, category: str | Category) -> bool:
        """Check if a value is valid for the given category.

        Args:
            value: Value to validate
            category: Category to validate against

        Returns:
            True if value is valid, False otherwise

        Example:
            >>> FlextLdifUtilitiesConstants.is_valid("oid", "server_type")
            True
            >>> FlextLdifUtilitiesConstants.is_valid("read", Category.PERMISSION)
            True
            >>> FlextLdifUtilitiesConstants.is_valid("invalid", "encoding")
            False

        """
        try:
            valid_values = FlextLdifUtilitiesConstants.get_valid_values(category)
            return value.lower() in valid_values
        except KeyError:
            return False

    @staticmethod
    def validate_many(
        values: set[str],
        category: str | Category,
    ) -> tuple[bool, list[str]]:
        """Validate multiple values against a category.

        Args:
            values: Set of values to validate
            category: Category to validate against

        Returns:
            Tuple of (all_valid, list_of_invalid_values)

        Example:
            >>> is_valid, invalid = FlextLdifUtilitiesConstants.validate_many(
            ...     {"read", "write", "invalid"}, "permission"
            ... )
            >>> is_valid
            False
            >>> invalid
            ['invalid']

        """
        valid_values = FlextLdifUtilitiesConstants.get_valid_values(category)
        invalid = [v for v in values if v.lower() not in valid_values]
        return len(invalid) == 0, invalid

    # SECTION 3: CONVENIENCE METHODS (Delegate to parameterized)
    # =========================================================================
    # These provide backward compatibility and clearer API for common cases

    @staticmethod
    def is_valid_server_type(server_type: str) -> bool:
        """Check if server type is recognized."""
        return FlextLdifUtilitiesConstants.is_valid(server_type, "server_type")

    @staticmethod
    def get_all_server_types() -> set[str]:
        """Get all recognized server types."""
        return FlextLdifUtilitiesConstants.get_valid_values("server_type")

    @staticmethod
    def get_server_permissions() -> set[str]:
        """Get all valid ACL permissions (RFC baseline)."""
        return FlextLdifUtilitiesConstants.get_valid_values("permission")

    @staticmethod
    def is_valid_permission(permission: str) -> bool:
        """Check if a permission is valid (RFC baseline)."""
        return FlextLdifUtilitiesConstants.is_valid(permission, "permission")

    @staticmethod
    def get_server_acl_actions() -> set[str]:
        """Get valid ACL actions (RFC baseline)."""
        return FlextLdifUtilitiesConstants.get_valid_values("acl_action")

    @staticmethod
    def is_valid_acl_action(action: str) -> bool:
        """Check if an ACL action is valid (RFC baseline)."""
        return FlextLdifUtilitiesConstants.is_valid(action, "acl_action")

    @staticmethod
    def get_server_encodings() -> set[str]:
        """Get supported encodings (RFC baseline)."""
        return FlextLdifUtilitiesConstants.get_valid_values("encoding")

    @staticmethod
    def is_valid_encoding(encoding: str) -> bool:
        """Check if an encoding is valid (RFC baseline)."""
        return FlextLdifUtilitiesConstants.is_valid(encoding, "encoding")

    @staticmethod
    def validate_permissions(permissions: set[str]) -> tuple[bool, list[str]]:
        """Validate a set of permissions (RFC baseline)."""
        return FlextLdifUtilitiesConstants.validate_many(permissions, "permission")

    @staticmethod
    def validate_acl_actions(actions: set[str]) -> tuple[bool, list[str]]:
        """Validate a set of ACL actions (RFC baseline)."""
        return FlextLdifUtilitiesConstants.validate_many(actions, "acl_action")

    @staticmethod
    def get_permission_mapping() -> Mapping[str, str]:
        """Get permission mapping (RFC baseline identity)."""
        rfc_perms = FlextLdifUtilitiesConstants.get_valid_values("permission")
        return {perm: perm for perm in rfc_perms}

    @staticmethod
    def validate_attribute_name(name: str) -> bool:
        """Validate LDAP attribute name against RFC 4512 rules.

        RFC 4512 Section 2.5: Attribute Type Definitions
        - AttributeType names must start with a letter
        - Can contain letters, digits, and hyphens
        - Case-insensitive comparison
        - Limited to reasonable length (1-255 chars)

        Args:
            name: Attribute name to validate

        Returns:
            True if valid, False otherwise

        Example:
            >>> FlextLdifUtilitiesConstants.validate_attribute_name("cn")
            True
            >>> FlextLdifUtilitiesConstants.validate_attribute_name("2invalid")
            False

        """
        # Import moved to module level

        # Check empty or too long
        if (
            not name
            or len(name) > FlextLdifConstants.LdifValidation.MAX_ATTRIBUTE_NAME_LENGTH
        ):
            return False

        # Check pattern
        return bool(re.match(FlextLdifConstants.LdifPatterns.ATTRIBUTE_NAME, name))


# NOTE: Server-specific constants access removed due to architectural constraints.
# Core modules (_utilities/*) cannot import from services/* or servers/*.
# For server-specific constants, use services layer (e.g., FlextLdifServer registry).
