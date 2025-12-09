"""LDIF Server Utilities - Helpers for Server Type Resolution and Detection.

Provides helper methods for resolving server type from nested classes,
reducing code duplication in server quirk implementations.

PHASE 1: DRY Refactoring (2025-11-19)
- get_parent_server_type(): Extract SERVER_TYPE from parent class Constants

PHASE 2: Detection Pattern Consolidation (2025-11-19)
- matches_server_patterns(): Universal detection for can_handle_attribute/objectclass

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import re
from typing import cast

from flext_core import FlextUtilities

from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif.constants import c

# Import FlextLdifModelsDomains for type annotations
# Models import moved to runtime to avoid circular import

# Aliases for simplified usage - after all imports
# Use flext-core utilities directly (FlextLdifUtilities extends FlextUtilities)
u = FlextUtilities  # Use base class to avoid circular dependency


# Valid server types for validation
_VALID_SERVER_TYPES: frozenset[str] = frozenset(
    {
        "oid",
        "oud",
        "rfc",
        "openldap",
        "ad",
        "apache",
        "ds389",
        "novell",
        "tivoli",
        "relaxed",
    },
)
_CLASS_SUFFIXES: tuple[str, ...] = ("Acl", "Schema", "Entry", "Constants")


class FlextLdifUtilitiesServer:
    """Server utilities for LDIF server type resolution.

    Provides helper methods for:
    - Extracting server type from nested class parent via __qualname__
    - Centralizing server-related utility functions
    """

    @staticmethod
    def _get_type_from_nested_class(
        target_cls: type[object],
    ) -> c.Ldif.LiteralTypes.ServerTypeLiteral | None:
        """Extract server type from nested class via parent's Constants."""
        if not (hasattr(target_cls, "__qualname__") and "." in target_cls.__qualname__):
            return None
        parent_class_name = target_cls.__qualname__.split(".")[0]
        try:
            parent_module = __import__(
                target_cls.__module__,
                fromlist=[parent_class_name],
            )
            parent_server_cls = getattr(parent_module, parent_class_name, None)
            if parent_server_cls is None:
                return None
            constants = getattr(parent_server_cls, "Constants", None)
            if constants is None:
                return None
            server_type = getattr(constants, "SERVER_TYPE", None)
            if server_type is not None:
                # Type narrowing: server_type is from ClassVar[ServerTypeLiteral]
                return cast(
                    "c.Ldif.LiteralTypes.ServerTypeLiteral",
                    server_type,
                )
        except (AttributeError, ImportError):
            pass
        return None

    @staticmethod
    def _get_type_from_independent_class(
        target_cls: type[object],
    ) -> c.Ldif.LiteralTypes.ServerTypeLiteral | None:
        """Extract server type from independent class naming pattern."""
        class_name = target_cls.__name__
        if not class_name.startswith("FlextLdifServers"):
            return None
        name_without_prefix = class_name[len("FlextLdifServers") :]
        server_name = FlextLdifUtilitiesServer._extract_server_name(name_without_prefix)
        if not server_name:
            return None
        server_type_lower = server_name.lower()
        # Try import from constants module
        imported_type = FlextLdifUtilitiesServer._import_server_type(
            server_name,
            server_type_lower,
        )
        if imported_type:
            return imported_type
        # Fallback: validate and return derived type
        if server_type_lower in _VALID_SERVER_TYPES:
            # Type narrowing: server_type_lower is in valid server types
            # Cast to ServerTypeLiteral for type compatibility
            return cast(
                "c.Ldif.LiteralTypes.ServerTypeLiteral",
                server_type_lower,
            )
        return None

    @staticmethod
    def _extract_server_name(name_without_prefix: str) -> str | None:
        """Extract server name from class name suffix."""
        for suffix in _CLASS_SUFFIXES:
            if name_without_prefix.endswith(suffix):
                return name_without_prefix[: -len(suffix)] or None
        return None

    @staticmethod
    def _import_server_type(
        server_name: str,
        server_type_lower: str,
    ) -> c.Ldif.LiteralTypes.ServerTypeLiteral | None:
        """Import and return SERVER_TYPE from server constants module."""
        try:
            constants_module = __import__(
                f"flext_ldif.servers._{server_type_lower}.constants",
                fromlist=[f"FlextLdifServers{server_name}Constants"],
            )
            constants_cls = getattr(
                constants_module,
                f"FlextLdifServers{server_name}Constants",
                None,
            )
            if constants_cls is not None:
                return getattr(constants_cls, "SERVER_TYPE", None)
        except ImportError:
            pass
        return None

    @staticmethod
    def get_parent_server_type(
        nested_class_instance_or_type: type[object] | object,
    ) -> c.Ldif.LiteralTypes.ServerTypeLiteral:
        """Get server_type from parent server class via __qualname__.

        For nested classes like FlextLdifServersAd.Schema, extracts parent
        class name from __qualname__ and gets SERVER_TYPE from parent.Constants.

        This is a DRY refactoring to eliminate duplicate code across Schema,
        Acl, and Entry nested classes in base.py.

        Args:
            nested_class_instance_or_type: Instance or type of a nested class (Schema, Acl, Entry)

        Returns:
            Server type literal from parent Constants.SERVER_TYPE

        Raises:
            AttributeError: If parent server class or SERVER_TYPE not found

        Example:
            >>> class MyServer:
            ...     class Constants:
            ...         SERVER_TYPE: ClassVar[c.Ldif.LiteralTypes.ServerTypeLiteral] = (
            ...             "oid"
            ...         )
            ...
            ...     class Schema:
            ...         def get_type(
            ...             self,
            ...         ) -> c.Ldif.LiteralTypes.ServerTypeLiteral:
            ...             return FlextLdifUtilitiesServer.get_parent_server_type(self)
            >>> schema = MyServer.Schema()
            >>> schema.get_type()
            'oid'

        """
        cls = (
            nested_class_instance_or_type
            if isinstance(nested_class_instance_or_type, type)
            else type(nested_class_instance_or_type)
        )
        # Try nested class pattern first
        server_type = FlextLdifUtilitiesServer._get_type_from_nested_class(cls)
        if server_type:
            return server_type
        # Try independent class pattern
        server_type = FlextLdifUtilitiesServer._get_type_from_independent_class(cls)
        if server_type:
            return server_type
        # No parent found - error
        msg = f"{cls.__name__} nested class must have parent with Constants.SERVER_TYPE"
        raise AttributeError(msg)

    @staticmethod
    def _check_name_patterns(
        name_lower: str,
        detection_names: frozenset[str],
        detection_string: str | None,
        *,
        use_prefix_match: bool = False,
    ) -> bool:
        """Check if name matches detection patterns (helper to reduce complexity).

        Args:
            name_lower: Lowercase name to check
            detection_names: Set of names/prefixes to match against
            detection_string: Optional string that must be contained
            use_prefix_match: If True, check startswith; if False, check contains

        """
        if detection_string and detection_string in name_lower:
            return True
        if name_lower in detection_names:
            return True
        if use_prefix_match:
            return any(name_lower.startswith(prefix) for prefix in detection_names)
        return any(marker in name_lower for marker in detection_names)

    @staticmethod
    def matches_server_patterns(
        value: (
            str
            | FlextLdifModelsDomains.SchemaAttribute
            | FlextLdifModelsDomains.SchemaObjectClass
        ),
        oid_pattern: str,
        detection_names: frozenset[str],
        detection_string: str | None = None,
        *,
        use_prefix_match: bool = False,
    ) -> bool:
        r"""Check if value matches server-specific detection patterns.

        Universal detection logic for can_handle_attribute and can_handle_objectclass
        methods across all server quirks. Reduces code duplication by centralizing
        the OID pattern, detection string, and attribute name checking.

        Args:
            value: The definition string or parsed model to check
            oid_pattern: Regex pattern for server-specific OIDs (e.g., r"2\.16\.840\.1\.113894")
            detection_names: Set of attribute/objectclass names that indicate this server
            detection_string: Optional string to check for in the definition (e.g., "microsoft")
            use_prefix_match: If True, use startswith for prefixes; if False, use contains

        Returns:
            True if value matches any server detection pattern, False otherwise

        Example:
            >>> # In a server's can_handle_attribute method:
            >>> return FlextLdifUtilitiesServer.matches_server_patterns(
            ...     value=attr_definition,
            ...     oid_pattern=MyServer.Constants.DETECTION_OID_PATTERN,
            ...     detection_names=MyServer.Constants.DETECTION_ATTRIBUTE_NAMES,
            ...     detection_string="myserver",
            ... )

        """

        def check_oid_pattern(check_value: str | None) -> bool:
            """Check OID pattern match."""
            return bool(check_value and re.search(oid_pattern, check_value))

        def check_name_in_set(name: str | None) -> bool:
            """Check if name is in detection set."""
            return bool(name and name.lower() in detection_names)

        def check_model_patterns(
            model: (
                FlextLdifModelsDomains.SchemaAttribute
                | FlextLdifModelsDomains.SchemaObjectClass
            ),
        ) -> bool:
            """Check patterns for model types."""
            if check_oid_pattern(model.oid) or check_name_in_set(model.name):
                return True
            name_lower = model.name.lower() if model.name else ""
            return FlextLdifUtilitiesServer._check_name_patterns(
                name_lower,
                detection_names,
                detection_string,
                use_prefix_match=use_prefix_match,
            )

        if isinstance(value, str):
            return check_oid_pattern(
                value,
            ) or FlextLdifUtilitiesServer._check_name_patterns(
                value.lower(),
                detection_names,
                detection_string,
                use_prefix_match=use_prefix_match,
            )

        # Import here to avoid circular import - only needed at runtime for isinstance checks
        from flext_ldif.models import m  # noqa: PLC0415

        if isinstance(value, m.Ldif.SchemaAttribute):
            return check_model_patterns(value)

        if isinstance(value, m.Ldif.SchemaObjectClass):
            return check_model_patterns(value)

        return False

    @staticmethod
    def normalize_server_type(
        server_type: str,
    ) -> str:
        """Normalize server type string to canonical ServerTypes enum value.

        Converts aliases and variations to canonical short form:
        - "active_directory", "ad", "ActiveDirectory" → "ad"
        - "oracle_oid", "oid", "OID" → "oid"
        - etc.

        Returns canonical ServerTypes enum value (short identifier).
        Raises ValueError if server_type is not recognized.

        Note: Return value is guaranteed to be a valid ServerTypeLiteral string,
        but returned as `str` for type compatibility. All returned values are
        validated against ServerTypes enum members.
        """
        server_type_lower = server_type.lower().strip()
        # Map aliases to canonical forms
        # Use full path to ServerTypes to avoid name resolution issues
        alias_map: dict[str, str] = {
            "active_directory": c.Ldif.ServerTypes.AD.value,
            "activedirectory": c.Ldif.ServerTypes.AD.value,
            "oracle_oid": c.Ldif.ServerTypes.OID.value,
            "oracleoid": c.Ldif.ServerTypes.OID.value,
            "oracle_oud": c.Ldif.ServerTypes.OUD.value,
            "oracleoud": c.Ldif.ServerTypes.OUD.value,
            "openldap1": c.Ldif.ServerTypes.OPENLDAP1.value,
            "openldap2": c.Ldif.ServerTypes.OPENLDAP2.value,
            "ibm_tivoli": c.Ldif.ServerTypes.IBM_TIVOLI.value,
            "ibmtivoli": c.Ldif.ServerTypes.IBM_TIVOLI.value,
            "tivoli": c.Ldif.ServerTypes.IBM_TIVOLI.value,
        }
        # Check alias map first
        if server_type_lower in alias_map:
            # alias_map values are guaranteed valid ServerTypeLiterals
            return alias_map[server_type_lower]  # Returns str value from enum
        # Check if it's already a canonical value
        # ServerTypes is a StrEnum, iterate over enum members
        for server_enum in c.Ldif.ServerTypes.__members__.values():
            if server_enum.value == server_type_lower:
                return server_enum.value  # StrEnum.value is a valid ServerTypeLiteral
        # Not found
        # ServerTypes is a StrEnum, iterate over enum members
        valid_types = [s.value for s in c.Ldif.ServerTypes.__members__.values()]
        msg = f"Invalid server type: {server_type}. Valid types: {valid_types}"
        raise ValueError(msg)

    @staticmethod
    def get_all_server_types() -> list[str]:
        """Get all supported server type values.

        Returns:
            List of all server type string values (e.g., ["oid", "oud", "rfc", ...])

        """
        return [s.value for s in c.Ldif.ServerTypes.__members__.values()]

    @staticmethod
    def get_server_type_value(server_type: str) -> str:
        """Get server type enum value by name.

        Args:
            server_type: Server type name (e.g., "OID", "OUD", "RFC")

        Returns:
            Server type value string

        Raises:
            AttributeError: If server type not found

        """
        server_enum = getattr(c.Ldif.ServerTypes, server_type.upper(), None)
        if server_enum is None:
            error_msg = f"Server type {server_type} not found"
            raise AttributeError(error_msg)
        return server_enum.value

    @staticmethod
    def get_server_detection_default_max_lines() -> int:
        """Get default max lines for server detection.

        Returns:
            Default max lines constant value

        """
        return c.Ldif.ServerDetection.DEFAULT_MAX_LINES

    @staticmethod
    def get_server_detection_confidence_threshold() -> float:
        """Get confidence threshold for server detection.

        Returns:
            Confidence threshold constant value

        """
        return c.Ldif.ServerDetection.CONFIDENCE_THRESHOLD

    @staticmethod
    def get_server_detection_attribute_match_score() -> int:
        """Get attribute match score for server detection.

        Returns:
            Attribute match score constant value

        """
        return c.Ldif.ServerDetection.ATTRIBUTE_MATCH_SCORE

    @staticmethod
    def get_default_acl_attributes() -> list[str]:
        """Get default ACL attributes list.

        Returns:
            Default ACL attributes constant value

        """
        return list(c.Ldif.AclAttributes.DEFAULT_ACL_ATTRIBUTES)

    @staticmethod
    def get_sort_target_values() -> list[str]:
        """Get all valid sort target values.

        Returns:
            List of all sort target string values

        """
        return [t.value for t in c.Ldif.SortTarget.__members__.values()]

    @staticmethod
    def get_sort_strategy_values() -> list[str]:
        """Get all valid sort strategy values.

        Returns:
            List of all sort strategy string values

        """
        return [s.value for s in c.Ldif.SortStrategy.__members__.values()]

    @staticmethod
    def get_sort_target_value(name: str) -> str:
        """Get sort target enum value by name.

        Args:
            name: Sort target name (e.g., "ENTRIES", "ATTRIBUTES")

        Returns:
            Sort target value string

        Raises:
            AttributeError: If sort target not found

        """
        sort_target_enum = getattr(c.Ldif.SortTarget, name.upper(), None)
        if sort_target_enum is None:
            error_msg = f"Sort target {name} not found"
            raise AttributeError(error_msg)
        return sort_target_enum.value

    @staticmethod
    def get_sort_strategy_value(name: str) -> str:
        """Get sort strategy enum value by name.

        Args:
            name: Sort strategy name (e.g., "HIERARCHY", "DN")

        Returns:
            Sort strategy value string

        Raises:
            AttributeError: If sort strategy not found

        """
        sort_strategy_enum = getattr(c.Ldif.SortStrategy, name.upper(), None)
        if sort_strategy_enum is None:
            error_msg = f"Sort strategy {name} not found"
            raise AttributeError(error_msg)
        return sort_strategy_enum.value

    @staticmethod
    def matches(server_type: str, *allowed_types: str) -> bool:
        """Check if a server type matches any of the allowed types.

        Args:
            server_type: Server type to check (e.g., "oid", "oud")
            *allowed_types: Allowed server types to match against

        Returns:
            True if server_type matches any allowed type, False otherwise

        Example:
            >>> FlextLdifUtilitiesServer.matches("oid", "oid", "oud")
            True
            >>> FlextLdifUtilitiesServer.matches("ad", "oid", "oud")
            False

        """
        normalized = server_type.lower().strip()
        return normalized in [t.lower().strip() for t in allowed_types]
