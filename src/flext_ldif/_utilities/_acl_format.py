"""LDIF ACI line formatting utilities.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif import c, m, t


class FlextLdifACLFormatting:
    """Format ACI lines, subjects, targets, and ACL names."""

    @staticmethod
    def build_aci_target_clause(
        target_attributes: t.MutableSequenceOf[str] | None,
        target_dn: str | None = None,
        separator: str = " || ",
    ) -> str:
        """Build ACI targetattr clause.

        Returns:
            The resulting ``str``.
        """
        if target_attributes:
            return f'(targetattr="{separator.join(target_attributes)}")'
        if target_dn and target_dn != "*":
            return f'(targetattr="{target_dn}")'
        return '(targetattr="*")'

    @staticmethod
    def format_aci_subject(
        _subject_type: str,
        subject_value: str,
        bind_operator: str = "userdn",
    ) -> str:
        """Format ACL subject into ACI bind rule format.

        Returns:
            The resulting ``str``.
        """
        cleaned_value = subject_value.replace(", ", ",")
        default_value = f'by dn="{cleaned_value}"'
        bind_rules: t.MutableStrMapping = {
            "userdn": f'userdn="ldap:///{cleaned_value}"',
            "groupdn": f'groupdn="ldap:///{cleaned_value}"',
            "roledn": f'roledn="ldap:///{cleaned_value}"',
        }
        result: str = bind_rules.get(bind_operator, default_value)
        return result

    @staticmethod
    def sanitize_acl_name(raw_name: str, max_length: int = 128) -> tuple[str, bool]:
        """Sanitize ACL name for ACI format.

        Returns:
            The resulting ``tuple[str, bool]``.
        """
        if not raw_name or not raw_name.strip():
            return ("", False)

        def sanitize_char(char: str) -> str:
            """Sanitize single character.

            Returns:
                The resulting ``str``.
            """
            char_ord = ord(char)
            rfc_format = c.Ldif
            ascii_min = rfc_format.ASCII_PRINTABLE_MIN
            ascii_max = rfc_format.ASCII_PRINTABLE_MAX
            if char_ord < ascii_min or char_ord > ascii_max or char == '"':
                return " "
            return char

        sanitized_chars: t.MutableSequenceOf[str] = [sanitize_char(ch) for ch in raw_name]
        sanitized_chars_list: t.MutableSequenceOf[str] = sanitized_chars
        was_sanitized = sanitized_chars_list != list(raw_name)
        result_chars: t.MutableSequenceOf[str] = []
        prev_char = ""
        for char in sanitized_chars_list:
            if not (char == " " and prev_char == " "):
                result_chars.append(char)
            else:
                was_sanitized = True
            prev_char = char
        sanitized = " ".join("".join(result_chars).split())
        if len(sanitized) > max_length:
            sanitized = sanitized[: max_length - 3] + "..."
            was_sanitized = True
        return (sanitized, was_sanitized)

    @staticmethod
    def format_aci_line(settings: m.Ldif.AciLineFormatConfig) -> str:
        r"""Format complete ACI line from components.

        Args:
            settings: AciLineFormatConfig with all formatting parameters

        Returns:
            Formatted ACI line string

        Example:
            settings = m.Ldif.AciLineFormatConfig(
                name="test-acl",
                target_clause="(targetattr=\\"cn\\")",
                permissions_clause="allow (read,write)",
                bind_rule="userdn=\\"ldap:///self\\"",
            )
            aci_line = FlextLdifUtilitiesACL.format_aci_line(settings)

        """
        sanitized_name, _ = FlextLdifACLFormatting.sanitize_acl_name(settings.name)
        return (
            f"{settings.aci_prefix}{settings.target_clause}"
            f'(version {settings.version}; acl "{sanitized_name}"; '
            f"{settings.permissions_clause} {settings.bind_rule};)"
        )

    @staticmethod
    def build_metadata_extensions(
        settings: m.Ldif.AclMetadataConfig,
    ) -> t.Ldif.MutableMetadataMapping:
        """Build ServerMetadata extensions for ACL.

        Returns:
            The resulting ``t.Ldif.MutableMetadataMapping``.
        """
        result: t.Ldif.MutableMetadataMapping = {}
        if settings.line_breaks is not None:
            result["line_breaks"] = settings.line_breaks
        if settings.dn_spaces is not None:
            result["dn_spaces"] = settings.dn_spaces
        if settings.targetscope is not None:
            result["targetscope"] = settings.targetscope
        if settings.version is not None:
            result["version"] = settings.version
        if settings.action_type is not None:
            result["action_type"] = settings.action_type
        return result

    @staticmethod
    def split_acl_line(acl_line: str) -> t.StrPair:
        r"""Split an ACL line into attribute name and payload.

        Generic utility for splitting ACL lines at the colon separator,
        used by multiple server implementations (RFC, OUD, OID, etc.).

        Args:
            acl_line: The raw ACL line string.

        Returns:
            Tuple of (attribute_name, payload).

        Example:
            >>> split_acl_line('aci: (version 3.0; acl "test"; ...)')
            ("aci", "(version 3.0; acl \\"test\\"; ...)")

        """
        attr_name, _, remainder = acl_line.partition(":")
        return (attr_name.strip(), remainder.strip())

    @staticmethod
    def validate_aci_format(
        acl_line: str,
        aci_prefix: str = "aci:",
    ) -> tuple[bool, str]:
        """Validate and extract ACI content from line.

        Returns:
            The resulting ``tuple[bool, str]``.
        """
        if not acl_line or not acl_line.strip():
            return (False, "")
        first_line = acl_line.split("\n", maxsplit=1)[0].strip()
        if not first_line.startswith(aci_prefix):
            return (False, "")
        if "\n" in acl_line:
            lines = acl_line.split("\n")
            aci_content: str = (
                lines[0].split(":", 1)[1].strip() + "\n" + "\n".join(lines[1:])
            )
        else:
            aci_content = acl_line.split(":", 1)[1].strip()
        return (True, aci_content)


__all__: list[str] = ["FlextLdifACLFormatting"]
