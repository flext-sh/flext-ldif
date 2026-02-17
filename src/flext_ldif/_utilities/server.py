"""LDIF Server Utilities - Helpers for Server Type Resolution and Detection."""
# ruff: noqa: SLF001  # Accessing own private methods within the same class

from __future__ import annotations

import importlib
import importlib.util
import re
from typing import Literal, TypeGuard

from flext_core.utilities import FlextUtilities

from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif._shared import normalize_server_type as normalize_server_type_shared
from flext_ldif.constants import c

# Import FlextLdifModelsDomains for type annotations
# Models import moved to runtime to avoid circular import

# Aliases for simplified usage - after all imports
# Use flext-core utilities directly (FlextLdifUtilities extends FlextUtilities)
u = FlextUtilities  # Use base class to avoid circular dependency


# Valid server types for validation - must match c.Ldif.ServerTypes enum values
_VALID_SERVER_TYPES: frozenset[str] = frozenset(
    {
        "oid",
        "oud",
        "rfc",
        "openldap",
        "openldap1",
        "openldap2",  # Added - canonical OpenLDAP 2.x type
        "ad",
        "apache",
        "ds389",
        "novell",
        "ibm_tivoli",  # Fixed - was "tivoli", should match ServerTypes.IBM_TIVOLI
        "relaxed",
        "generic",  # Added - matches ServerTypes.GENERIC
    },
)
_CLASS_SUFFIXES: tuple[str, ...] = ("Acl", "Schema", "Entry", "Constants")


def _is_valid_server_type_literal(
    value: str,
) -> TypeGuard[c.Ldif.LiteralTypes.ServerTypeLiteral]:
    """TypeGuard to narrow str to ServerTypeLiteral."""
    return value in _VALID_SERVER_TYPES


class FlextLdifUtilitiesServer:
    """Server utilities for LDIF server type resolution."""

    @staticmethod
    def _extract_server_type_from_constants(
        cls_with_constants: type[object] | None,
    ) -> c.Ldif.LiteralTypes.ServerTypeLiteral | None:
        """Extract server type from a class's Constants.SERVER_TYPE."""
        if cls_with_constants is None:
            return None
        constants_obj: object = getattr(cls_with_constants, "Constants", None)
        if not isinstance(constants_obj, type):
            return None
        server_type_raw: object = getattr(constants_obj, "SERVER_TYPE", None)
        if (
            server_type_raw is not None
            and isinstance(server_type_raw, str)
            and _is_valid_server_type_literal(server_type_raw)
        ):
            return server_type_raw
        return None

    @staticmethod
    def _get_type_from_nested_class(
        target_cls: type[object],
    ) -> c.Ldif.LiteralTypes.ServerTypeLiteral | None:
        """Extract server type from nested class via parent's Constants."""
        # First try the nested class pattern with __qualname__
        if hasattr(target_cls, "__qualname__") and "." in target_cls.__qualname__:
            parent_class_name = target_cls.__qualname__.split(".")[0]
            # Check if module exists before importing
            module_spec = importlib.util.find_spec(target_cls.__module__)
            if module_spec is not None:
                parent_module = importlib.import_module(target_cls.__module__)
                parent_server_cls_obj: object = getattr(
                    parent_module,
                    parent_class_name,
                    None,
                )
                if isinstance(parent_server_cls_obj, type):
                    # Extract server type from parent class constants
                    srv = FlextLdifUtilitiesServer
                    result = srv._extract_server_type_from_constants(
                        parent_server_cls_obj,
                    )
                    if result is not None:
                        return result

        # Fallback: search through MRO for a class with Constants.SERVER_TYPE
        for mro_cls in target_cls.__mro__:
            result = FlextLdifUtilitiesServer._extract_server_type_from_constants(
                mro_cls,
            )
            if result is not None:
                return result
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
        # Use TypeGuard to narrow to ServerTypeLiteral
        if _is_valid_server_type_literal(server_type_lower):
            return server_type_lower
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
        module_name = f"flext_ldif.servers._{server_type_lower}.constants"
        # Check if module exists before importing - avoids try/except ImportError
        module_spec = importlib.util.find_spec(module_name)
        if module_spec is None:
            return None
        constants_module = importlib.import_module(module_name)
        constants_cls_obj: object = getattr(
            constants_module,
            f"FlextLdifServers{server_name}Constants",
            None,
        )
        if isinstance(constants_cls_obj, type):
            server_type_value: object = getattr(constants_cls_obj, "SERVER_TYPE", None)
            if isinstance(server_type_value, str) and _is_valid_server_type_literal(
                server_type_value,
            ):
                return server_type_value
        return None

    @staticmethod
    def get_parent_server_type(
        nested_class_instance_or_type: type[object] | object,
    ) -> c.Ldif.LiteralTypes.ServerTypeLiteral:
        """Get server_type from parent server class via __qualname__."""
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
        """Check if name matches detection patterns (helper to reduce complexity)."""
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

        if isinstance(value, FlextLdifModelsDomains.SchemaAttribute):
            return check_model_patterns(value)

        # value must be SchemaObjectClass since type is union of 3 types
        # and str and SchemaAttribute were already handled
        return check_model_patterns(value)

    @staticmethod
    def normalize_server_type(
        server_type: str,
    ) -> Literal[
        "oid",
        "oud",
        "openldap",
        "openldap1",
        "openldap2",
        "ad",
        "apache",
        "ds389",
        "rfc",
        "relaxed",
        "novell",
        "ibm_tivoli",
        "generic",
    ]:
        """Normalize server type string to canonical ServerTypes enum value."""
        normalized = normalize_server_type_shared(server_type).value
        if _is_valid_server_type_literal(normalized):
            return normalized
        valid_types = [s.value for s in c.Ldif.ServerTypes.__members__.values()]
        msg = f"Invalid server type: {server_type}. Valid types: {valid_types}"
        raise ValueError(msg)

    @staticmethod
    def get_all_server_types() -> list[str]:
        """Get all supported server type values."""
        return [s.value for s in c.Ldif.ServerTypes.__members__.values()]

    @staticmethod
    def get_server_type_value(server_type: str) -> str:
        """Get server type enum value by name."""
        server_enum = c.Ldif.ServerTypes.__members__.get(server_type.upper())
        if server_enum is None:
            error_msg = f"Server type {server_type} not found"
            raise AttributeError(error_msg)
        return server_enum.value

    @staticmethod
    def get_server_detection_default_max_lines() -> int:
        """Get default max lines for server detection."""
        return c.Ldif.ServerDetection.DEFAULT_MAX_LINES

    @staticmethod
    def get_server_detection_confidence_threshold() -> float:
        """Get confidence threshold for server detection."""
        return c.Ldif.ServerDetection.CONFIDENCE_THRESHOLD

    @staticmethod
    def get_server_detection_attribute_match_score() -> int:
        """Get attribute match score for server detection."""
        return c.Ldif.ServerDetection.ATTRIBUTE_MATCH_SCORE

    @staticmethod
    def get_sort_target_value(name: str) -> str:
        """Get sort target enum value by name."""
        sort_target_enum = c.Ldif.SortTarget.__members__.get(name.upper())
        if sort_target_enum is None:
            error_msg = f"Sort target {name} not found"
            raise AttributeError(error_msg)
        return sort_target_enum.value

    @staticmethod
    def get_sort_strategy_value(name: str) -> str:
        """Get sort strategy enum value by name."""
        sort_strategy_enum = c.Ldif.SortStrategy.__members__.get(name.upper())
        if sort_strategy_enum is None:
            error_msg = f"Sort strategy {name} not found"
            raise AttributeError(error_msg)
        return sort_strategy_enum.value

    @staticmethod
    def matches(server_type: str, *allowed_types: str) -> bool:
        """Check if a server type matches any of the allowed types."""
        normalized = server_type.lower().strip()
        return normalized in [t.lower().strip() for t in allowed_types]
