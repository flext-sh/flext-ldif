"""LDIF Server Utilities - Helpers for Server Type Resolution and Detection."""

from __future__ import annotations

import re
import sys
from collections.abc import MutableSequence
from typing import TypeIs

from flext_core import r
from flext_ldif import FlextLdifModelsDomains, FlextLdifShared, c, t

_VALID_SERVER_TYPES: frozenset[str] = frozenset({
    "oid",
    "oud",
    "rfc",
    "openldap",
    "openldap1",
    "openldap2",
    "ad",
    "apache",
    "ds389",
    "novell",
    "ibm_tivoli",
    "relaxed",
    "generic",
})
_CLASS_SUFFIXES: tuple[str, ...] = ("Acl", "Schema", "Entry", "Constants")


class FlextLdifUtilitiesServer:
    """Server utilities for LDIF server type resolution."""

    @staticmethod
    def _check_name_patterns(
        name_lower: str,
        detection_names: frozenset[str],
        detection_string: str | None,
        *,
        use_prefix_match: bool = False,
    ) -> bool:
        """Check if name matches detection patterns (helper to reduce complexity)."""
        if detection_string and detection_string in name_lower:
            return True
        if name_lower in detection_names:
            return True
        if use_prefix_match:
            return any(name_lower.startswith(prefix) for prefix in detection_names)
        return any(marker in name_lower for marker in detection_names)

    @staticmethod
    def _extract_server_name(name_without_prefix: str) -> r[str]:
        """Extract server name from class name suffix."""
        for suffix in _CLASS_SUFFIXES:
            if name_without_prefix.endswith(suffix):
                server_name = name_without_prefix[: -len(suffix)]
                if server_name:
                    return r[str].ok(server_name)
                return r[str].fail("Server name is empty after suffix extraction")
        return r[str].fail("Class name does not contain a supported server suffix")

    @staticmethod
    def _get_type_from_independent_class(
        target_cls: type,
    ) -> c.Ldif.ServerTypeLiteral | None:
        """Extract server type from independent class naming pattern."""
        class_name = target_cls.__name__
        if not class_name.startswith("FlextLdifServers"):
            return None
        name_without_prefix = class_name[len("FlextLdifServers") :]
        server_name_result = FlextLdifUtilitiesServer._extract_server_name(
            name_without_prefix,
        )
        if server_name_result.is_failure:
            return None
        server_type_lower = server_name_result.value.lower()
        if FlextLdifUtilitiesServer._is_valid_server_type_literal(server_type_lower):
            return server_type_lower
        return None

    @staticmethod
    def _get_type_from_nested_class(
        target_cls: type,
    ) -> c.Ldif.ServerTypeLiteral | None:
        """Extract server type from nested class via parent's Constants."""
        if "." in target_cls.__qualname__:
            parent_class_name = target_cls.__qualname__.split(".")[0]
            parent_module = sys.modules.get(target_cls.__module__)
            if parent_module:
                parent_server_cls_obj: type | None = vars(parent_module).get(
                    parent_class_name,
                )
                if isinstance(parent_server_cls_obj, type):
                    srv = FlextLdifUtilitiesServer
                    result = srv.extract_server_type_from_constants(
                        parent_server_cls_obj,
                    )
                    if result is not None:
                        return result
        for mro_cls in target_cls.__mro__:
            result = FlextLdifUtilitiesServer.extract_server_type_from_constants(
                mro_cls,
            )
            if result is not None:
                return result
        return None

    @staticmethod
    def _is_valid_server_type_literal(
        value: str,
    ) -> TypeIs[c.Ldif.ServerTypeLiteral]:
        return value in _VALID_SERVER_TYPES

    @staticmethod
    def extract_server_type_from_constants(
        cls_with_constants: type | None,
    ) -> c.Ldif.ServerTypeLiteral | None:
        """Extract server type from a class's Constants.SERVER_TYPE."""
        if cls_with_constants is None:
            return None
        constants_obj: type | None = vars(cls_with_constants).get("Constants")
        if not isinstance(constants_obj, type):
            return None
        server_type_raw = getattr(constants_obj, "SERVER_TYPE", None)
        if (
            server_type_raw is not None
            and FlextLdifUtilitiesServer._is_valid_server_type_literal(server_type_raw)
        ):
            return server_type_raw
        return None

    @staticmethod
    def get_all_server_types() -> MutableSequence[str]:
        """Get all supported server type values."""
        return [s.value for s in c.Ldif.ServerTypes.__members__.values()]

    @staticmethod
    def get_server_type_value(name: str) -> str:
        """Get the enum value for a server type by its member name.

        Args:
            name: The ServerTypes enum member name (e.g., "RFC", "OID", "AD").

        Returns:
            The string value of the corresponding ServerTypes enum member.

        """
        return c.Ldif.ServerTypes[name].value

    @staticmethod
    def get_parent_server_type(
        nested_class_instance_or_type: type | t.Container,
    ) -> c.Ldif.ServerTypeLiteral:
        """Get server_type from parent server class via __qualname__."""
        cls = (
            nested_class_instance_or_type
            if isinstance(nested_class_instance_or_type, type)
            else nested_class_instance_or_type.__class__
        )
        server_type = FlextLdifUtilitiesServer._get_type_from_nested_class(cls)
        if server_type:
            return server_type
        server_type = FlextLdifUtilitiesServer._get_type_from_independent_class(cls)
        if server_type:
            return server_type
        msg = f"{cls.__name__} nested class must have parent with Constants.SERVER_TYPE"
        raise AttributeError(msg)

    @staticmethod
    def get_attribute_match_score() -> int:
        """Get attribute match score for server detection."""
        return c.Ldif.ATTRIBUTE_MATCH_SCORE

    @staticmethod
    def get_confidence_threshold() -> float:
        """Get confidence threshold for server detection."""
        return c.Ldif.CONFIDENCE_THRESHOLD

    @staticmethod
    def get_server_detection_default_max_lines() -> int:
        """Get default max lines for server detection."""
        return c.Ldif.DEFAULT_MAX_LINES

    @staticmethod
    def matches(server_type: str, *allowed_types: str) -> bool:
        """Check if a server type matches any of the allowed types."""
        normalized = server_type.lower().strip()
        return normalized in [t.lower().strip() for t in allowed_types]

    @staticmethod
    def matches_server_patterns(
        value: str
        | FlextLdifModelsDomains.SchemaAttribute
        | FlextLdifModelsDomains.SchemaObjectClass,
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
            oid_pattern: Regex pattern for server-specific OIDs (e.g., r"2\\.16\\.840\\.1\\.113894")
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
            model: FlextLdifModelsDomains.SchemaAttribute
            | FlextLdifModelsDomains.SchemaObjectClass,
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
        if isinstance(value, FlextLdifModelsDomains.SchemaAttribute):
            return check_model_patterns(value)
        return check_model_patterns(value)

    @staticmethod
    def normalize_server_type(
        server_type: str,
    ) -> c.Ldif.ServerTypes:
        """Normalize server type string to canonical ServerTypes enum member."""
        return FlextLdifShared.normalize_server_type(server_type)
