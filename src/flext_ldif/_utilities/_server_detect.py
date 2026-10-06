"""LDIF server detection pattern utilities.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_ldif import c

if TYPE_CHECKING:
    from flext_ldif import FlextLdifModels


class FlextLdifServerDetection:
    """Universal server detection logic shared by dialect handlers."""

    @staticmethod
    def _check_name_patterns(
        name_lower: str,
        detection_names: frozenset[str],
        detection_string: str | None,
        *,
        use_prefix_match: bool = False,
    ) -> bool:
        """Check if name matches detection patterns (helper to reduce complexity).

        Returns:
            The resulting ``bool``.
        """
        if detection_string and detection_string in name_lower:
            return True
        if name_lower in detection_names:
            return True
        if use_prefix_match:
            return any(name_lower.startswith(prefix) for prefix in detection_names)
        return any(marker in name_lower for marker in detection_names)

    @staticmethod
    def _extract_pattern_name_candidates(
        value: str
        | FlextLdifModels.Ldif.SchemaAttribute
        | FlextLdifModels.Ldif.SchemaObjectClass,
        settings: FlextLdifModels.Ldif.ServerPatternsConfig,
    ) -> list[str]:
        """Extract comparable schema names from a raw definition or parsed model.

        Returns:
            The resulting ``list[str]``.
        """
        if not isinstance(value, str):
            return [value.name] if value.name else []
        if not settings.name_regex:
            return []
        name_candidates: list[str] = []
        name_matches = c.Ldif.compile_pattern(
            settings.name_regex,
            ignorecase=True,
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
        settings: FlextLdifModels.Ldif.ServerPatternsConfig,
    ) -> bool:
        """Check raw definition text when settings require substring-based detection.

        Returns:
            The resulting ``bool``.
        """
        if not definition_text or not settings.match_definition_text:
            return False
        definition_lower = definition_text.lower()
        if settings.detection_string and settings.detection_string in definition_lower:
            return True
        return any(marker in definition_lower for marker in detection_names)

    @staticmethod
    def matches_server_patterns(
        value: str
        | FlextLdifModels.Ldif.SchemaAttribute
        | FlextLdifModels.Ldif.SchemaObjectClass,
        settings: FlextLdifModels.Ldif.ServerPatternsConfig,
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
            >>> result = FlextLdifUtilitiesServer.matches_server_patterns(
            ...     value=attr_definition,
            ...     settings=MyServer.Constants.ATTRIBUTE_PATTERN_SETTINGS,
            ... )

        """
        detection_names = frozenset(
            marker.lower() for marker in (*settings.attr_names, *settings.attr_prefixes)
        )

        def check_oid_pattern(check_value: str | None) -> bool:
            """Check OID pattern match.

            Returns:
                The resulting ``bool``.
            """
            return bool(
                check_value
                and settings.oid_pattern
                and c.Ldif.compile_pattern(settings.oid_pattern).search(check_value),
            )

        oid_value = value if isinstance(value, str) else value.oid
        definition_text = value if isinstance(value, str) else None
        name_candidates = FlextLdifServerDetection._extract_pattern_name_candidates(
            value,
            settings,
        )
        result = check_oid_pattern(oid_value) or any(
            FlextLdifServerDetection._check_name_patterns(
                name.lower(),
                detection_names,
                settings.detection_string,
                use_prefix_match=settings.use_prefix_match,
            )
            for name in name_candidates
        )
        if not result:
            return FlextLdifServerDetection._matches_definition_text(
                definition_text,
                detection_names,
                settings,
            )
        return result


__all__: list[str] = ["FlextLdifServerDetection"]
