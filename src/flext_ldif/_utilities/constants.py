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

    # SECTION 1: SERVER CONSTANTS LOOKUP
    # =========================================================================

    @staticmethod
    def get_server_constants(server_type: str) -> type[object] | None:
        """Get server-specific Constants class by server type.

        Args:
            server_type: Server type identifier (e.g., "oid", "oud", "openldap")

        Returns:
            Constants class for the server, or None if not found

        Example:
            >>> constants = FlextLdifUtilitiesConstants.get_server_constants("oid")
            >>> if constants:
            ...     perms = constants.AclPermission

        """
        server_map = {
            "rfc": None,  # RFC has no server-specific constants
            "oid": _get_oid_constants,
            "oud": _get_oud_constants,
            "openldap": _get_openldap_constants,
            "openldap1": _get_openldap1_constants,
            "ad": _get_ad_constants,
            "apache": _get_apache_constants,
            "389ds": _get_ds389_constants,
            "novell": _get_novell_constants,
            "tivoli": _get_tivoli_constants,
            "relaxed": _get_relaxed_constants,
        }

        loader = server_map.get(server_type.lower())
        if loader is None:
            return None
        return loader() if callable(loader) else loader

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
    def get_server_permissions(server_type: str) -> set[str]:
        """Get all valid ACL permissions for a server type.

        Args:
            server_type: Server type identifier

        Returns:
            Set of valid permission strings for the server

        Example:
            >>> perms = FlextLdifUtilitiesConstants.get_server_permissions("oid")
            >>> "read" in perms
            True

        """
        constants = FlextLdifUtilitiesConstants.get_server_constants(server_type)
        if not constants or not hasattr(constants, "AclPermission"):
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

        try:
            perm_enum = constants.AclPermission
            return {item.value for item in perm_enum}
        except (AttributeError, TypeError):
            # Fallback to RFC baseline
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
    def get_server_acl_actions(server_type: str) -> set[str]:
        """Get valid ACL actions for a server type.

        Args:
            server_type: Server type identifier

        Returns:
            Set of valid ACL action strings (typically "allow", "deny")

        Example:
            >>> actions = FlextLdifUtilitiesConstants.get_server_acl_actions("oid")
            >>> "allow" in actions
            True

        """
        constants = FlextLdifUtilitiesConstants.get_server_constants(server_type)
        if not constants or not hasattr(constants, "AclAction"):
            # Return default ACL actions
            return {"allow", "deny"}

        try:
            action_enum = constants.AclAction
            return {item.value for item in action_enum}
        except (AttributeError, TypeError):
            # Fallback to defaults
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
    def get_server_encodings(server_type: str) -> set[str]:
        """Get supported encodings for a server type.

        Args:
            server_type: Server type identifier

        Returns:
            Set of valid encoding strings for the server

        Example:
            >>> encodings = FlextLdifUtilitiesConstants.get_server_encodings("oid")
            >>> "utf-8" in encodings
            True

        """
        constants = FlextLdifUtilitiesConstants.get_server_constants(server_type)
        if not constants or not hasattr(constants, "Encoding"):
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

        try:
            encoding_enum = constants.Encoding
            return {item.value for item in encoding_enum}
        except (AttributeError, TypeError):
            # Fallback to RFC baseline
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


# SECTION 6: LAZY LOADERS FOR SERVER CONSTANTS
# =============================================================================


def _get_oid_constants() -> type[object]:
    """Lazy load OID server constants."""
    from flext_ldif.servers.oid import FlextLdifServersOid  # noqa: PLC0415

    return FlextLdifServersOid.Constants


def _get_oud_constants() -> type[object]:
    """Lazy load OUD server constants."""
    from flext_ldif.servers.oud import FlextLdifServersOud  # noqa: PLC0415

    return FlextLdifServersOud.Constants


def _get_openldap_constants() -> type[object]:
    """Lazy load OpenLDAP 2.x server constants."""
    from flext_ldif.servers.openldap import FlextLdifServersOpenldap  # noqa: PLC0415

    return FlextLdifServersOpenldap.Constants


def _get_openldap1_constants() -> type[object]:
    """Lazy load OpenLDAP 1.x server constants."""
    from flext_ldif.servers.openldap1 import FlextLdifServersOpenldap1  # noqa: PLC0415

    return FlextLdifServersOpenldap1.Constants


def _get_ad_constants() -> type[object]:
    """Lazy load Active Directory server constants."""
    from flext_ldif.servers.ad import FlextLdifServersAd  # noqa: PLC0415

    return FlextLdifServersAd.Constants


def _get_apache_constants() -> type[object]:
    """Lazy load Apache Directory Server constants."""
    from flext_ldif.servers.apache import FlextLdifServersApache  # noqa: PLC0415

    return FlextLdifServersApache.Constants


def _get_ds389_constants() -> type[object]:
    """Lazy load 389 Directory Server constants."""
    from flext_ldif.servers.ds389 import FlextLdifServersDs389  # noqa: PLC0415

    return FlextLdifServersDs389.Constants


def _get_novell_constants() -> type[object]:
    """Lazy load Novell eDirectory constants."""
    from flext_ldif.servers.novell import FlextLdifServersNovell  # noqa: PLC0415

    return FlextLdifServersNovell.Constants


def _get_tivoli_constants() -> type[object]:
    """Lazy load IBM Tivoli Directory Server constants."""
    from flext_ldif.servers.tivoli import FlextLdifServersTivoli  # noqa: PLC0415

    return FlextLdifServersTivoli.Constants


def _get_relaxed_constants() -> type[object]:
    """Lazy load Relaxed mode constants."""
    from flext_ldif.servers.relaxed import FlextLdifServersRelaxed  # noqa: PLC0415

    return FlextLdifServersRelaxed.Constants
