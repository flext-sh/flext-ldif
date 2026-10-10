"""LDIF server configuration value helpers.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif import FlextLdifShared, c, m, t


class FlextLdifServerConfig:
    """Expose canonical server configuration values and normalization."""

    @staticmethod
    def normalize_server_type(server_type: str) -> c.Ldif.ServerTypes:
        """Normalize server type string to canonical ServerTypes enum member.

        Returns:
            The resulting ``c.Ldif.ServerTypes``.
        """
        return FlextLdifShared.normalize_server_type(server_type)

    @staticmethod
    def resolve_all_server_types() -> t.MutableSequenceOf[str]:
        """Get all supported server type values.

        Returns:
            The resulting ``t.MutableSequenceOf[str]``.
        """
        return [s.value for s in c.Ldif.ServerTypes.__members__.values()]

    @staticmethod
    def resolve_server_type_value(name: str) -> str:
        """Get the enum value for a server type by its member name.

        Args:
            name: The ServerTypes enum member name (e.g., "RFC", "OID", "AD").

        Returns:
            The string value of the corresponding ServerTypes enum member.

        """
        server_type_value: str = c.Ldif.ServerTypes[name].value
        return server_type_value

    @staticmethod
    def matches(server_type: str, *allowed_types: str) -> bool:
        """Check if a server type matches any of the allowed types.

        Returns:
            The resulting ``bool``.
        """
        normalized = server_type.lower().strip()
        return normalized in [allowed.lower().strip() for allowed in allowed_types]

    @staticmethod
    def resolve_attribute_match_score() -> int:
        """Get attribute match score for server detection.

        Returns:
            The resulting ``int``.
        """
        score: int = c.Ldif.ATTRIBUTE_MATCH_SCORE
        return score

    @staticmethod
    def resolve_confidence_threshold() -> float:
        """Get confidence threshold for server detection.

        Returns:
            The resulting ``float``.
        """
        threshold: float = c.Ldif.CONFIDENCE_THRESHOLD
        return threshold

    @staticmethod
    def resolve_server_detection_default_max_lines() -> int:
        """Get default max lines for server detection.

        Returns:
            The resulting ``int``.
        """
        max_lines: int = c.Ldif.DEFAULT_MAX_LINES
        return max_lines

    @staticmethod
    def validation_rule_flags(
        server_type: str | c.Ldif.ServerTypes,
    ) -> m.Ldif.ServerValidationRules:
        """Resolve validation-rule booleans from the canonical server capability map.

        Returns:
            The resulting ``m.Ldif.ServerValidationRules``.
        """
        normalized_server_type = FlextLdifServerConfig.normalize_server_type(
            str(server_type),
        )
        validation_capabilities = c.Ldif.SERVER_VALIDATION_CAPABILITIES.get(
            normalized_server_type,
            frozenset(),
        )
        return m.Ldif.ServerValidationRules(
            requires_objectclass="requires_objectclass" in validation_capabilities,
            requires_naming_attr="requires_naming_attr" in validation_capabilities,
            requires_binary_option="requires_binary_option" in validation_capabilities,
        )


__all__: list[str] = ["FlextLdifServerConfig"]
