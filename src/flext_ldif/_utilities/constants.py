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

from collections.abc import Mapping


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
    def get_server_permissions(server_type: str) -> set[str]:  # noqa: ARG004
        """Get all valid ACL permissions for a server type.

        Returns RFC baseline permissions only. Core modules cannot access server-specific constants.

        Args:
            server_type: Server type identifier (unused, kept for API compatibility)

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
    def is_valid_permission(permission: str, server_type: str = "rfc") -> bool:
        """Check if a permission is valid for a server type.

        Args:
            permission: Permission string to validate
            server_type: Server type (defaults to RFC)

        Returns:
            True if permission is valid for the server, False otherwise

        Example:
            >>> FlextLdifUtilitiesConstants.is_valid_permission("read", "oid")
            True
            >>> FlextLdifUtilitiesConstants.is_valid_permission("invalid", "oid")
            False

        """
        valid_perms = FlextLdifUtilitiesConstants.get_server_permissions(server_type)
        return permission.lower() in valid_perms

    # SECTION 3: ACL ACTION VALIDATION
    # =========================================================================

    @staticmethod
    def get_server_acl_actions(server_type: str) -> set[str]:  # noqa: ARG004
        """Get valid ACL actions for a server type.

        Returns RFC baseline ACL actions only. Core modules cannot access server-specific constants.

        Args:
            server_type: Server type identifier (unused, kept for API compatibility)

        Returns:
            Set of RFC baseline ACL action strings

        Note:
            This method returns RFC baseline only due to architectural constraints.
            For server-specific actions, use services layer (FlextLdifServer registry).

        """
        # Return RFC baseline ACL actions
        return {"allow", "deny"}

    @staticmethod
    def is_valid_acl_action(action: str, server_type: str = "rfc") -> bool:
        """Check if an ACL action is valid for a server type.

        Args:
            action: ACL action string to validate
            server_type: Server type (defaults to RFC)

        Returns:
            True if action is valid for the server, False otherwise

        Example:
            >>> FlextLdifUtilitiesConstants.is_valid_acl_action("allow")
            True

        """
        valid_actions = FlextLdifUtilitiesConstants.get_server_acl_actions(server_type)
        return action.lower() in valid_actions

    # SECTION 4: ENCODING UTILITIES
    # =========================================================================

    @staticmethod
    def get_server_encodings(server_type: str) -> set[str]:  # noqa: ARG004
        """Get supported encodings for a server type.

        Returns RFC baseline encodings only. Core modules cannot access server-specific constants.

        Args:
            server_type: Server type identifier (unused, kept for API compatibility)

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
    def is_valid_encoding(encoding: str, server_type: str = "rfc") -> bool:
        """Check if an encoding is valid for a server type.

        Args:
            encoding: Encoding string to validate
            server_type: Server type (defaults to RFC)

        Returns:
            True if encoding is valid for the server, False otherwise

        Example:
            >>> FlextLdifUtilitiesConstants.is_valid_encoding("utf-8", "oid")
            True

        """
        valid_encodings = FlextLdifUtilitiesConstants.get_server_encodings(server_type)
        return encoding.lower() in valid_encodings

    # SECTION 5: BULK VALIDATION
    # =========================================================================

    @staticmethod
    def validate_permissions(
        permissions: set[str],
        server_type: str = "rfc",
    ) -> tuple[bool, list[str]]:
        """Validate a set of permissions for a server type.

        Args:
            permissions: Set of permission strings to validate
            server_type: Server type to validate against

        Returns:
            Tuple of (is_valid, invalid_permissions)

        Example:
            >>> is_valid, invalid = FlextLdifUtilitiesConstants.validate_permissions(
            ...     {"read", "write", "invalid"}, "oid"
            ... )
            >>> is_valid
            False
            >>> invalid
            ['invalid']

        """
        valid_perms = FlextLdifUtilitiesConstants.get_server_permissions(server_type)
        invalid = [p for p in permissions if p.lower() not in valid_perms]
        return len(invalid) == 0, invalid

    @staticmethod
    def validate_acl_actions(
        actions: set[str],
        server_type: str = "rfc",
    ) -> tuple[bool, list[str]]:
        """Validate a set of ACL actions for a server type.

        Args:
            actions: Set of action strings to validate
            server_type: Server type to validate against

        Returns:
            Tuple of (is_valid, invalid_actions)

        Example:
            >>> is_valid, invalid = FlextLdifUtilitiesConstants.validate_acl_actions(
            ...     {"allow", "deny", "invalid"}, "oid"
            ... )
            >>> is_valid
            False

        """
        valid_actions = FlextLdifUtilitiesConstants.get_server_acl_actions(server_type)
        invalid = [a for a in actions if a.lower() not in valid_actions]
        return len(invalid) == 0, invalid

    @staticmethod
    def get_permission_mapping(
        from_server: str,
        to_server: str,
    ) -> Mapping[str, str]:
        """Get permission mapping between two server types.

        Maps permissions from source server format to target server format.
        For servers with identical permission names, returns identity mapping.

        Args:
            from_server: Source server type
            to_server: Target server type

        Returns:
            Mapping of source permission -> target permission

        Example:
            >>> mapping = FlextLdifUtilitiesConstants.get_permission_mapping(
            ...     "oid", "oud"
            ... )
            >>> mapping.get("read")
            'read'

        """
        # For now, all servers share the same permission names (RFC baseline)
        # This method is extensible for future server-specific mappings
        source_perms = FlextLdifUtilitiesConstants.get_server_permissions(from_server)
        target_perms = FlextLdifUtilitiesConstants.get_server_permissions(to_server)

        # Return identity mapping for common permissions
        common_perms = source_perms & target_perms
        return {perm: perm for perm in common_perms}


# NOTE: Server-specific constants access removed due to architectural constraints.
# Core modules (_utilities/*) cannot import from services/* or servers/*.
# For server-specific constants, use services layer (e.g., FlextLdifServer registry).
