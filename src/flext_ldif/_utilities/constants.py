"""Utilities for accessing and validating standardized constants.

This module provides helper functions for working with FlextLdifConstants and
server-specific Constants classes defined in server quirks modules.

Provides:
- Get server constants by server type
- Validate permission values against server capabilities
- Look up ACL configurations and metadata
- Helper methods for permission and action validation

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Callable, Mapping


class FlextLdifUtilitiesConstants:
    """Utilities for accessing and validating standardized constants."""

    # SECTION 1: SERVER TYPE VALIDATION
    # =========================================================================
    #
    # NOTE: Server-specific constants access removed due to architectural constraints.
    # Core modules (_utilities/*) cannot import from services/* or servers/*.
    # Methods below provide RFC baseline only. For server-specific constants,
    # use services layer (e.g., FlextLdifServer registry).

    @staticmethod
    def is_valid_server_type(server_type: str) -> bool:
        """Check if server type is recognized.

        Args:
            server_type: Server type to validate

        Returns:
            True if server type is valid, False otherwise

        Example:
            >>> FlextLdifUtilitiesConstants.is_valid_server_type("oid")
            True
            >>> FlextLdifUtilitiesConstants.is_valid_server_type("unknown")
            False

        """
        valid_types = {
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
        }
        return server_type.lower() in valid_types

    @staticmethod
    def get_all_server_types() -> set[str]:
        """Get all recognized server types.

        Returns:
            Set of all valid server type strings

        Example:
            >>> types = FlextLdifUtilitiesConstants.get_all_server_types()
            >>> "oid" in types
            True

        """
        return {
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
        }

    # SECTION 2: PERMISSION VALIDATION
    # =========================================================================

    @staticmethod
    def get_server_permissions() -> set[str]:
        """Get all valid ACL permissions (RFC baseline).

        Returns RFC baseline permissions only. Core modules cannot access server-specific constants.

        Returns:
            Set of RFC baseline permission strings

        Note:
            This method returns RFC baseline only due to architectural constraints.
            For server-specific permissions, use services layer (FlextLdifServer registry).

        """
        # Return RFC baseline permissions
        return {
            "read",
            "write",
            "add",
            "delete",
            "search",
            "compare",
            "auth",
            "all",
            "none",
        }

    @staticmethod
    def is_valid_permission(permission: str) -> bool:
        """Check if a permission is valid (RFC baseline).

        Args:
            permission: Permission string to validate

        Returns:
            True if permission is valid, False otherwise

        Example:
            >>> FlextLdifUtilitiesConstants.is_valid_permission("read")
            True
            >>> FlextLdifUtilitiesConstants.is_valid_permission("invalid")
            False

        """
        valid_perms = FlextLdifUtilitiesConstants.get_server_permissions()
        return permission.lower() in valid_perms

    # SECTION 3: ACL ACTION VALIDATION
    # =========================================================================

    @staticmethod
    def get_server_acl_actions() -> set[str]:
        """Get valid ACL actions (RFC baseline).

        Returns RFC baseline ACL actions only. Core modules cannot access server-specific constants.

        Returns:
            Set of RFC baseline ACL action strings

        Note:
            This method returns RFC baseline only due to architectural constraints.
            For server-specific actions, use services layer (FlextLdifServer registry).

        """
        # Return RFC baseline ACL actions
        return {"allow", "deny"}

    @staticmethod
    def is_valid_acl_action(action: str) -> bool:
        """Check if an ACL action is valid (RFC baseline).

        Args:
            action: ACL action string to validate

        Returns:
            True if action is valid, False otherwise

        Example:
            >>> FlextLdifUtilitiesConstants.is_valid_acl_action("allow")
            True

        """
        valid_actions = FlextLdifUtilitiesConstants.get_server_acl_actions()
        return action.lower() in valid_actions

    # SECTION 4: ENCODING UTILITIES
    # =========================================================================

    @staticmethod
    def get_server_encodings() -> set[str]:
        """Get supported encodings (RFC baseline).

        Returns RFC baseline encodings only. Core modules cannot access server-specific constants.

        Returns:
            Set of RFC baseline encoding strings

        Note:
            This method returns RFC baseline only due to architectural constraints.
            For server-specific encodings, use services layer (FlextLdifServer registry).

        """
        # Return RFC baseline encodings
        return {
            "utf-8",
            "utf-16",
            "utf-16-le",
            "utf-32",
            "ascii",
            "latin-1",
            "cp1252",
            "iso-8859-1",
        }

    @staticmethod
    def is_valid_encoding(encoding: str) -> bool:
        """Check if an encoding is valid (RFC baseline).

        Args:
            encoding: Encoding string to validate

        Returns:
            True if encoding is valid, False otherwise

        Example:
            >>> FlextLdifUtilitiesConstants.is_valid_encoding("utf-8")
            True

        """
        valid_encodings = FlextLdifUtilitiesConstants.get_server_encodings()
        return encoding.lower() in valid_encodings

    # SECTION 5: BULK VALIDATION
    # =========================================================================

    @staticmethod
    def _validate_items(
        items: set[str],
        get_valid_items: Callable[[], set[str]],
    ) -> tuple[bool, list[str]]:
        """Generic validation helper for permissions, actions, etc.

        Internal helper to reduce duplication between validate_permissions
        and validate_acl_actions methods (eliminates 44 lines of duplication).

        Args:
            items: Set of items to validate
            get_valid_items: Callable that returns set of valid items

        Returns:
            Tuple of (is_valid, invalid_items)

        """
        valid_items = get_valid_items()
        invalid = [item for item in items if item.lower() not in valid_items]
        return len(invalid) == 0, invalid

    @staticmethod
    def validate_permissions(permissions: set[str]) -> tuple[bool, list[str]]:
        """Validate a set of permissions (RFC baseline).

        Args:
            permissions: Set of permission strings to validate

        Returns:
            Tuple of (is_valid, invalid_permissions)

        Example:
            >>> is_valid, invalid = FlextLdifUtilitiesConstants.validate_permissions({
            ...     "read",
            ...     "write",
            ...     "invalid",
            ... })
            >>> is_valid
            False
            >>> invalid
            ['invalid']

        """
        return FlextLdifUtilitiesConstants._validate_items(
            permissions,
            FlextLdifUtilitiesConstants.get_server_permissions,
        )

    @staticmethod
    def validate_acl_actions(actions: set[str]) -> tuple[bool, list[str]]:
        """Validate a set of ACL actions (RFC baseline).

        Args:
            actions: Set of action strings to validate

        Returns:
            Tuple of (is_valid, invalid_actions)

        Example:
            >>> is_valid, invalid = FlextLdifUtilitiesConstants.validate_acl_actions({
            ...     "allow",
            ...     "deny",
            ...     "invalid",
            ... })
            >>> is_valid
            False

        """
        return FlextLdifUtilitiesConstants._validate_items(
            actions,
            FlextLdifUtilitiesConstants.get_server_acl_actions,
        )

    @staticmethod
    def get_permission_mapping() -> Mapping[str, str]:
        """Get permission mapping (RFC baseline identity).

        All servers share the same permission names (RFC baseline),
        so returns identity mapping for all permissions.

        Returns:
            Identity mapping of RFC baseline permissions

        Example:
            >>> mapping = FlextLdifUtilitiesConstants.get_permission_mapping()
            >>> mapping.get("read")
            'read'

        """
        # All servers share the same permission names (RFC baseline)
        # Returns identity mapping for RFC baseline permissions
        rfc_perms = FlextLdifUtilitiesConstants.get_server_permissions()
        return {perm: perm for perm in rfc_perms}


# NOTE: Server-specific constants access removed due to architectural constraints.
# Core modules (_utilities/*) cannot import from services/* or servers/*.
# For server-specific constants, use services layer (e.g., FlextLdifServer registry).
