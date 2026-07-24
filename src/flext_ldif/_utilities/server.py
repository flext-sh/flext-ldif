"""LDIF Server Utilities - Helpers for Server Type Resolution and Detection."""

from __future__ import annotations

import sys
from typing import TypeIs

from flext_ldif import FlextLdifShared, c, p, r, t


class FlextLdifUtilitiesServer:
    """Server utilities for LDIF server type resolution."""

    VALID_SERVER_TYPES: frozenset[str] = c.Ldif.VALID_SERVER_TYPES
    CLASS_SUFFIXES: t.StrSequence = c.Ldif.CLASS_SUFFIXES

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
    def _extract_pattern_name_candidates(
        value: str | p.Ldif.SchemaAttribute | p.Ldif.SchemaObjectClass,
        settings: p.Ldif.ServerPatternsConfig,
    ) -> list[str]:
        """Extract comparable schema names from a raw definition or parsed model."""
        if not isinstance(value, str):
            return [value.name] if value.name else []
        if not settings.name_regex:
            return []
        name_candidates: list[str] = []
        name_matches = c.Ldif.compile_pattern(
            settings.name_regex, ignorecase=True
        ).findall(value)
        for match in name_matches:
            if isinstance(match, tuple):
                name_candidates.extend(part for part in match if part)
            elif match:
                name_candidates.append(match)
        return name_candidates

    @staticmethod
    def _matches_definition_text(
        definition_text: str | None,
        detection_names: frozenset[str],
        settings: p.Ldif.ServerPatternsConfig,
    ) -> bool:
        """Check raw definition text when settings require substring-based detection."""
        if not definition_text or not settings.match_definition_text:
            return False
        definition_lower = definition_text.lower()
        if settings.detection_string and settings.detection_string in definition_lower:
            return True
        return any(marker in definition_lower for marker in detection_names)

    @staticmethod
    def _extract_server_name(name_without_prefix: str) -> p.Result[str]:
        """Extract server name from class name suffix."""
        for suffix in FlextLdifUtilitiesServer.CLASS_SUFFIXES:
            if name_without_prefix.endswith(suffix):
                server_name = name_without_prefix[: -len(suffix)]
                if server_name:
                    return r[str].ok(server_name)
                return r[str].fail("Server name is empty after suffix extraction")
        return r[str].fail("Class name does not contain a supported server suffix")

    @staticmethod
    def _get_type_from_independent_class(target_cls: type) -> c.Ldif.ServerTypes | None:
        """Extract server type from independent class naming pattern."""
        class_name = target_cls.__name__
        if not class_name.startswith("FlextLdifServers"):
            return None
        name_without_prefix = class_name[len("FlextLdifServers") :]
        server_name = FlextLdifUtilitiesServer._extract_server_name(
            name_without_prefix
        ).unwrap_or(None)
        if server_name is None:
            return None
        server_type_lower = server_name.lower()
        if FlextLdifUtilitiesServer._is_valid_server_type(server_type_lower):
            return c.Ldif.ServerTypes(server_type_lower)
        return None

    @staticmethod
    def _get_type_from_nested_class(target_cls: type) -> c.Ldif.ServerTypes | None:
        """Extract server type from nested class via parent's Constants."""
        qualname_parts = target_cls.__qualname__.split(".")
        if len(qualname_parts) > 1:
            parent_module = sys.modules.get(target_cls.__module__)
            if parent_module:
                parent_obj: type | None = vars(parent_module).get(qualname_parts[0])
                for part in qualname_parts[1:-1]:
                    if isinstance(parent_obj, type):
                        parent_obj = vars(parent_obj).get(part)
                if isinstance(parent_obj, type):
                    srv = FlextLdifUtilitiesServer
                    result = srv.extract_server_type_from_constants(parent_obj)
                    if result is not None:
                        return result
        for mro_cls in target_cls.__mro__:
            result = FlextLdifUtilitiesServer.extract_server_type_from_constants(
                mro_cls
            )
            if result is not None:
                return result
        return None

    @staticmethod
    def _is_valid_server_type(value: str) -> TypeIs[c.Ldif.ServerTypes]:
        return value in FlextLdifUtilitiesServer.VALID_SERVER_TYPES

    @staticmethod
    def extract_server_type_from_constants(
        cls_with_constants: type | None,
    ) -> c.Ldif.ServerTypes | None:
        """Extract server type from a class's Constants.SERVER_TYPE."""
        if cls_with_constants is None:
            return None
        constants_obj: type | None = vars(cls_with_constants).get("Constants")
        if not isinstance(constants_obj, type):
            return None
        server_type_raw = getattr(constants_obj, "SERVER_TYPE", None)
        if (
            server_type_raw is not None
            and FlextLdifUtilitiesServer._is_valid_server_type(server_type_raw)
        ):
            return c.Ldif.ServerTypes(server_type_raw)
        return None

    @staticmethod
    def get_all_server_types() -> t.MutableSequenceOf[str]:
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
        server_type_value: str = c.Ldif.ServerTypes[name].value
        return server_type_value

    @staticmethod
    def get_parent_server_type(
        nested_class_instance_or_type: type | t.JsonValue,
    ) -> c.Ldif.ServerTypes:
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
        score: int = c.Ldif.ATTRIBUTE_MATCH_SCORE
        return score

    @staticmethod
    def get_confidence_threshold() -> float:
        """Get confidence threshold for server detection."""
        threshold: float = c.Ldif.CONFIDENCE_THRESHOLD
        return threshold

    @staticmethod
    def get_server_detection_default_max_lines() -> int:
        """Get default max lines for server detection."""
        max_lines: int = c.Ldif.DEFAULT_MAX_LINES
        return max_lines

    @staticmethod
    def matches(server_type: str, *allowed_types: str) -> bool:
        """Check if a server type matches any of the allowed types."""
        normalized = server_type.lower().strip()
        return normalized in [t.lower().strip() for t in allowed_types]

    @staticmethod
    def matches_server_patterns(
        # NOTE (multi-agent, mro-0ftd.3.7.2): behavior layer accepts the protocol
        # payload (§3.2) so p.X-annotated can_handle_* overrides pass it through.
        value: str | p.Ldif.SchemaAttribute | p.Ldif.SchemaObjectClass,
        settings: p.Ldif.ServerPatternsConfig,
    ) -> bool:
        r"""Check if value matches server-specific detection patterns.

        Universal detection logic for can_handle_attribute and can_handle_objectclass
        methods across all server servers. Reduces code duplication by centralizing
        the OID pattern, detection string, and attribute name checking.

        Args:
            value: The definition string or parsed model to check
            settings: Centralized server pattern settings

        Returns:
            True if value matches any server detection pattern, False otherwise

        Example:
            >>> # In a server's can_handle_attribute method:
            >>> return FlextLdifUtilitiesServer.matches_server_patterns(
            ...     value=attr_definition,
            ...     settings=MyServer.Constants.ATTRIBUTE_PATTERN_SETTINGS,
            ... )

        """
        detection_names = frozenset(
            marker.lower() for marker in (*settings.attr_names, *settings.attr_prefixes)
        )

        def check_oid_pattern(check_value: str | None) -> bool:
            """Check OID pattern match."""
            return bool(
                check_value
                and settings.oid_pattern
                and c.Ldif.compile_pattern(settings.oid_pattern).search(check_value)
            )

        oid_value = value if isinstance(value, str) else value.oid
        definition_text = value if isinstance(value, str) else None
        name_candidates = FlextLdifUtilitiesServer._extract_pattern_name_candidates(
            value, settings
        )
        result = check_oid_pattern(oid_value) or any(
            FlextLdifUtilitiesServer._check_name_patterns(
                name.lower(),
                detection_names,
                settings.detection_string,
                use_prefix_match=settings.use_prefix_match,
            )
            for name in name_candidates
        )
        if not result:
            return FlextLdifUtilitiesServer._matches_definition_text(
                definition_text, detection_names, settings
            )
        return result

    @staticmethod
    def normalize_server_type(server_type: str) -> c.Ldif.ServerTypes:
        """Normalize server type string to canonical ServerTypes enum member."""
        return FlextLdifShared.normalize_server_type(server_type)

    @staticmethod
    def validation_rule_flags(server_type: str | c.Ldif.ServerTypes) -> dict[str, bool]:
        """Resolve validation-rule booleans from the canonical server capability map."""
        normalized_server_type = FlextLdifUtilitiesServer.normalize_server_type(
            str(server_type)
        )
        validation_capabilities = c.Ldif.SERVER_VALIDATION_CAPABILITIES.get(
            normalized_server_type, frozenset()
        )
        return {
            "requires_objectclass": "requires_objectclass" in validation_capabilities,
            "requires_naming_attr": "requires_naming_attr" in validation_capabilities,
            "requires_binary_option": "requires_binary_option"
            in validation_capabilities,
        }
