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

from flext_ldif.models import FlextLdifModels


class FlextLdifUtilitiesServer:
    """Server utilities for LDIF server type resolution.

    Provides helper methods for:
    - Extracting server type from nested class parent via __qualname__
    - Centralizing server-related utility functions
    """

    @staticmethod
    def get_parent_server_type(nested_class_instance: object) -> str:
        """Get server_type from parent server class via __qualname__.

        For nested classes like FlextLdifServersAd.Schema, extracts parent
        class name from __qualname__ and gets SERVER_TYPE from parent.Constants.

        This is a DRY refactoring to eliminate duplicate code across Schema,
        Acl, and Entry nested classes in base.py.

        Args:
            nested_class_instance: Instance of a nested class (Schema, Acl, Entry)

        Returns:
            Server type string from parent Constants.SERVER_TYPE

        Raises:
            AttributeError: If parent server class or SERVER_TYPE not found

        Example:
            >>> class MyServer:
            ...     class Constants:
            ...         SERVER_TYPE = "myserver"
            ...
            ...     class Schema:
            ...         def get_type(self) -> str:
            ...             return FlextLdifUtilitiesServer.get_parent_server_type(self)
            >>> schema = MyServer.Schema()
            >>> schema.get_type()
            'myserver'

        """
        cls = type(nested_class_instance)

        # For nested classes, extract parent server class from __qualname__
        # Example: "FlextLdifServersAd.Schema" -> "FlextLdifServersAd"
        if hasattr(cls, "__qualname__") and "." in cls.__qualname__:
            parent_class_name = cls.__qualname__.split(".")[0]
            try:
                # Import parent class from module
                parent_module = __import__(
                    cls.__module__,
                    fromlist=[parent_class_name],
                )
                if hasattr(parent_module, parent_class_name):
                    parent_server_cls = getattr(parent_module, parent_class_name)
                    # Get SERVER_TYPE from parent.Constants
                    if hasattr(parent_server_cls, "Constants") and hasattr(
                        parent_server_cls.Constants,
                        "SERVER_TYPE",
                    ):
                        server_type_value = parent_server_cls.Constants.SERVER_TYPE
                        if not isinstance(server_type_value, str):
                            msg = f"Expected str, got {type(server_type_value)}"
                            raise TypeError(msg)
                        return server_type_value
            except AttributeError:
                pass

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
        value: str
        | FlextLdifModels.SchemaAttribute
        | FlextLdifModels.SchemaObjectClass,
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
        if isinstance(value, str):
            if re.search(oid_pattern, value):
                return True
            return FlextLdifUtilitiesServer._check_name_patterns(
                value.lower(),
                detection_names,
                detection_string,
                use_prefix_match=use_prefix_match,
            )

        if isinstance(value, FlextLdifModels.SchemaAttribute):
            if re.search(oid_pattern, value.oid):
                return True
            return FlextLdifUtilitiesServer._check_name_patterns(
                value.name.lower(),
                detection_names,
                detection_string,
                use_prefix_match=use_prefix_match,
            )

        if isinstance(value, FlextLdifModels.SchemaObjectClass):
            if re.search(oid_pattern, value.oid):
                return True
            return FlextLdifUtilitiesServer._check_name_patterns(
                value.name.lower(),
                detection_names,
                detection_string,
                use_prefix_match=use_prefix_match,
            )

        return False
