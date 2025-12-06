"""Extracted nested class from FlextLdifUtilities.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Literal, cast

from flext_core import (
    FlextLogger,
    r,
)
from flext_core.typings import t
from flext_core.utilities import FlextUtilities

from flext_ldif._models.config import FlextLdifModelsConfig
from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif._models.metadata import FlextLdifModelsMetadata
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels

# Aliases for simplified usage - after all imports
u = FlextUtilities  # Utilities (from flext-core)
# t is already imported from flext_core.typings
# r is already imported from flext_core


# Lazy-loading proxy for FlextLdifUtilities to avoid circular import
# utilities.py imports this module, so we can't import at module level
class _LazyLdifUtilities:
    """Lazy proxy for FlextLdifUtilities to avoid circular imports."""

    _cached: type | None = None

    def __getattr__(self, name: str) -> object:
        """Lazy-load FlextLdifUtilities on first attribute access."""
        if self._cached is None:
            # Import inside method to break circular dependency
            from flext_ldif.utilities import FlextLdifUtilities  # noqa: PLC0415

            object.__setattr__(self, "_cached", FlextLdifUtilities)
        cached = object.__getattribute__(self, "_cached")
        return getattr(cached, name)


u_ldif = _LazyLdifUtilities()


def _get_u_ldif() -> _LazyLdifUtilities:
    """Get u_ldif utilities lazily to avoid circular imports.

    Returns:
        Lazy proxy for FlextLdifUtilities

    """
    return u_ldif


logger = FlextLogger(__name__)

# Constants for tuple length validation
TUPLE_LENGTH_PAIR = 2

# Type for parsed ACL components (using MetadataValue for nested structures)
AclComponent = dict[str, str | t.MetadataAttributeValue]


class FlextLdifUtilitiesACL:
    """Generic ACL parsing and writing utilities."""

    # ASCII control character boundaries for sanitization
    # (use constants from FlextLdifConstants.Rfc)
    # Note: Cannot use class attribute assignment with constants due to import order
    # Use constants directly in methods instead

    @staticmethod
    def split_acl_line(acl_line: str) -> tuple[str, str]:
        r"""Split an ACL line into attribute name and payload.

        Generic utility for splitting ACL lines at the colon separator,
        used by multiple server implementations (RFC, OUD, OID, etc.).

        Args:
            acl_line: The raw ACL line string.

        Returns:
            Tuple of (attribute_name, payload).

        Example:
            >>> split_acl_line('aci: (version 3.0; acl "test"; ...)')
            ("aci", "(version 3.0; acl \"test\"; ...)")

        """
        attr_name, _, remainder = acl_line.partition(":")
        return attr_name.strip(), remainder.strip()

    @staticmethod
    def _extract_from_match(match: re.Match[str], group: int) -> str | None:
        """Extract group from regex match."""
        if match.lastindex is None:
            return match.group(0)
        if group > match.lastindex:
            return None
        try:
            return match.group(group)
        except IndexError:
            return None

    @staticmethod
    def extract_component(content: str, pattern: str, group: int = 1) -> str | None:
        r"""Extract single ACL component using regex pattern.

        Args:
            content: ACL content string to parse
            pattern: Regex pattern to match
            group: Regex group number to extract (default: 1)

        Returns:
            Extracted component value or None if not found

        Example:
            >>> pattern = r"targetattr\\s*=\\s*\"([^\"]+)\""
            >>> extract_component(aci_content, pattern, group=1)
            "cn,mail,telephoneNumber"

        """
        if not content or not pattern:
            return None
        match = re.search(pattern, content)
        return (
            FlextLdifUtilitiesACL._extract_from_match(match, group) if match else None
        )

    @staticmethod
    def extract_permissions(
        content: str,
        allow_deny_pattern: str,
        ops_separator: str = ",",
        action_filter: str | None = None,
    ) -> list[str]:
        r"""Extract permissions from ACL content using configurable patterns.

        Args:
            content: ACL content string
            allow_deny_pattern: Regex pattern to match allow/deny rules
            ops_separator: Separator for operations list (default: ",")
            action_filter: Only include permissions for this action (e.g., "allow")

        Returns:
            List of permission strings

        """
        if not content or not allow_deny_pattern:
            return []

        permissions: list[str] = []
        matches = re.finditer(allow_deny_pattern, content, re.IGNORECASE)

        min_groups_for_action = 1
        min_groups_for_ops = 2
        for match in matches:
            action = (
                match.group(1)
                if match.lastindex and match.lastindex >= min_groups_for_action
                else ""
            )
            ops = (
                match.group(2)
                if match.lastindex and match.lastindex >= min_groups_for_ops
                else ""
            )

            # Filter by action if specified
            if action_filter and action.lower() != action_filter.lower():
                continue

            if ops:
                split_ops = ops.split(ops_separator)
                u_ldif_instance = _get_u_ldif()
                filtered_perms_list = u_ldif_instance.map_filter(
                    split_ops,
                    mapper=str.strip,
                    predicate=bool,
                )
                permissions.extend(filtered_perms_list)

        return permissions

    @staticmethod
    def extract_bind_rules(
        content: str,
        bind_patterns: dict[str, str] | None = None,
    ) -> list[dict[str, str]]:
        r"""Extract bind rules from ACL content.

        Finds userdn, groupdn, or other bind rule specifications.

        Args:
            content: ACL content string
            bind_patterns: Optional dict mapping bind type names to regex patterns.
                          Each pattern MUST have a capturing group for the value.
                          If None, uses default RFC patterns.

        Returns:
            List of dicts with 'type' and 'value' keys.

        """
        if not content:
            return []

        # Default patterns with capturing groups for values
        default_patterns: dict[str, str] = {
            "userdn": r'userdn\s*=\s*"([^"]*)"',
            "groupdn": r'groupdn\s*=\s*"([^"]*)"',
            "roledn": r'roledn\s*=\s*"([^"]*)"',
        }

        patterns = bind_patterns or default_patterns

        def extract_bind_rule(bind_type: str, pattern: str) -> list[dict[str, str]]:
            """Extract bind rules for single bind type."""
            matches = re.findall(pattern, content, re.IGNORECASE)

            def build_rule(match: str) -> dict[str, str]:
                """Build rule dict from match."""
                return {"type": bind_type, "value": match}

            u_ldif_instance = _get_u_ldif()
            mapped_rules = u_ldif_instance.map_filter(
                matches,
                mapper=build_rule,
                predicate=lambda r: u_ldif_instance.is_type(r, dict),
            )
            return cast("list[dict[str, str]]", mapped_rules)

        u_ldif_instance = _get_u_ldif()
        bind_rules_result = u.Collection.process(
            u_ldif_instance.pairs(patterns),
            processor=lambda item: extract_bind_rule(item[0], item[1]),
            on_error="skip",
        )
        bind_rules = u_ldif_instance.process_flatten(
            bind_rules_result.value if bind_rules_result.is_success else [],
            processor=lambda rule_list: u_ldif_instance.as_type(
                rule_list,
                target="list",
                default=[],
            ),
            on_error="skip",
        )
        return cast("list[dict[str, str]]", bind_rules)

    @staticmethod
    def _normalize_permission(
        perm: str,
        permission_map: dict[str, str] | None,
    ) -> str:
        """Normalize permission name using map if available."""
        if not permission_map:
            return perm
        u_ldif_instance = _get_u_ldif()
        return u_ldif_instance.maybe(
            u_ldif_instance.get(permission_map, perm),
            default=perm,
        )

    @staticmethod
    def _process_permission_list(
        perm_list: list[str],
        permission_map: dict[str, str] | None,
        *,
        is_allow: bool,
    ) -> dict[str, bool]:
        """Process permission list into dictionary."""

        def process_perm(p: str) -> tuple[str, bool] | None:
            """Process single permission."""
            normalized = FlextLdifUtilitiesACL._normalize_permission(p, permission_map)
            return (normalized, is_allow) if p else None

        def is_valid_perm(p: str) -> bool:
            """Check if permission is valid."""
            return bool(p)

        u_ldif_instance = _get_u_ldif()
        process_result = u.Collection.process(
            perm_list,
            processor=process_perm,
            predicate=is_valid_perm,
            on_error="skip",
        )
        if not process_result.is_success:
            return {}
        filtered_tuples = u_ldif_instance.map_filter(
            process_result.value,
            predicate=lambda t: (
                u_ldif_instance.is_type(t, tuple) and len(t) == TUPLE_LENGTH_PAIR
            ),
        )

        def map_tuple_to_dict(t: object) -> dict[str, bool] | None:
            """Map tuple to dict."""
            u_ldif_instance_inner = _get_u_ldif()
            if u_ldif_instance_inner.is_type(t, tuple) and len(t) == TUPLE_LENGTH_PAIR:
                t_tuple = t
                return {t_tuple[0]: t_tuple[1]}
            return None

        mapped_dicts = u_ldif_instance.map_filter(
            filtered_tuples,
            mapper=map_tuple_to_dict,
            predicate=lambda d: d is not None,
        )
        return u_ldif_instance.reduce_dict(
            mapped_dicts,
            predicate=lambda _k, v: u_ldif_instance.is_type(v, bool),
        )

    @staticmethod
    def build_permissions_dict(
        allow_permissions: list[str],
        permission_map: dict[str, str] | None = None,
        deny_permissions: list[str] | None = None,
    ) -> dict[str, bool]:
        """Build permissions dictionary from allow/deny lists.

        Args:
            allow_permissions: List of allowed permission names
            permission_map: Optional dict to normalize permission names.
                           Maps server-specific names to canonical names.
            deny_permissions: Optional list of denied permission names

        Returns:
            Dictionary mapping permission names to True (allow) or False (deny)

        """
        u_ldif_instance = _get_u_ldif()
        allow_dict = u_ldif_instance.when(
            condition=bool(allow_permissions),
            then=lambda: FlextLdifUtilitiesACL._process_permission_list(
                allow_permissions,
                permission_map,
                is_allow=True,
            ),
            else_={},
        )
        deny_dict = u_ldif_instance.when(
            condition=bool(deny_permissions),
            then=lambda: FlextLdifUtilitiesACL._process_permission_list(
                deny_permissions or [],
                permission_map,
                is_allow=False,
            ),
            else_={},
        )
        return u_ldif_instance.merge(allow_dict, deny_dict)

    # NOTE: OID-specific methods (extract_oid_target, detect_oid_subject,
    # parse_oid_permissions, format_oid_target, format_oid_subject,
    # format_oid_permissions) were REMOVED from here.
    # They are now in FlextLdifServersOid.Acl class where OID knowledge belongs.
    # Servers must encapsulate their own knowledge -
    # utilities should be generic/parametrized.

    @staticmethod
    def format_aci_subject(
        _subject_type: str,
        subject_value: str,
        bind_operator: str = "userdn",
    ) -> str:
        """Format ACL subject into ACI bind rule format.

        Supports both RFC (userdn/groupdn with ldap:///) and OID (by DN=) formats.

        Args:
            _subject_type: "user", "group", "role" (reserved for future use)
            subject_value: Subject DN or value
            bind_operator: "userdn", "groupdn", "roledn"

        Returns:
            Formatted ACI bind rule

        """
        u_ldif_instance = _get_u_ldif()
        cleaned_value = subject_value.replace(", ", ",")
        return u_ldif_instance.switch(
            bind_operator,
            {
                "userdn": f'userdn="ldap:///{cleaned_value}"',
                "groupdn": f'groupdn="ldap:///{cleaned_value}"',
                "roledn": f'roledn="ldap:///{cleaned_value}"',
            },
            default=f'by dn="{cleaned_value}"',
        )

    @staticmethod
    def build_acl_subject(
        bind_rules_data: list[dict[str, str]],
        subject_type_map: dict[str, str],
        special_values: dict[str, tuple[str, str]],
    ) -> tuple[str, str]:
        """Build ACL subject from bind rules - generic implementation.

        Args:
            bind_rules_data: List of dicts with 'type' and 'value' keys
            subject_type_map: Maps bind rule types to subject types
            special_values: Maps special values to (type, value) tuples

        Returns:
            Tuple of (subject_type, subject_value)

        """
        u_ldif_instance = _get_u_ldif()
        if not bind_rules_data:
            return ("", "")

        first_rule = bind_rules_data[0]
        get_type = u_ldif_instance.prop("type")
        get_value = u_ldif_instance.prop("value")
        rule_type = u_ldif_instance.maybe(get_type(first_rule), default="")
        rule_value = u_ldif_instance.maybe(get_value(first_rule), default="")

        # Check for special values first
        special_match = u_ldif_instance.maybe(
            u_ldif_instance.get(special_values, rule_value),
        )
        if special_match:
            return cast("tuple[str, str]", special_match)

        # Map the type
        subject_type = u_ldif_instance.maybe(
            u_ldif_instance.get(subject_type_map, rule_type),
            default=rule_type,
        )

        return (subject_type, rule_value)

    @staticmethod
    def build_metadata_extensions(
        config: FlextLdifModelsConfig.AclMetadataConfig,
    ) -> dict[str, t.MetadataAttributeValue]:
        """Build QuirkMetadata extensions for ACL.

        Args:
            config: ACL metadata configuration

        Returns:
            Metadata extensions dictionary

        """

        def build_extension_entry(
            key: str,
            value: object,
        ) -> dict[str, t.MetadataAttributeValue] | None:
            """Build extension entry if value exists."""
            if value:
                return {key: value}
                return None
            return None

        extension_items = [
            ("line_breaks", config.line_breaks),
            ("dn_spaces", config.dn_spaces),
            ("targetscope", config.targetscope),
            ("version", config.version),
            ("action_type", config.action_type),
        ]

        extension_dicts = u_ldif.process_flatten(
            extension_items,
            processor=lambda item: build_extension_entry(item[0], item[1]),
            on_error="skip",
        )

        return u_ldif.reduce_dict(
            extension_dicts,
            predicate=lambda _k, v: v is not None,
        )

    @staticmethod
    def sanitize_acl_name(raw_name: str, max_length: int = 128) -> tuple[str, bool]:
        """Sanitize ACL name for ACI format."""
        if not raw_name or not raw_name.strip():
            return "", False

        def sanitize_char(char: str) -> str:
            """Sanitize single character."""
            char_ord = ord(char)
            if (
                char_ord < FlextLdifConstants.Rfc.ASCII_PRINTABLE_MIN
                or char_ord > FlextLdifConstants.Rfc.ASCII_PRINTABLE_MAX
                or char == '"'
            ):
                return " "
            return char

        u_ldif_instance = _get_u_ldif()
        sanitized_chars = u_ldif_instance.normalize_list(
            list(raw_name),
            mapper=sanitize_char,
        )

        # Check if any characters were modified during sanitization
        sanitized_chars_list: list[str] = (
            sanitized_chars
            if isinstance(sanitized_chars, list)
            else list(sanitized_chars)
        )
        was_sanitized = sanitized_chars_list != list(raw_name)

        # Remove consecutive spaces
        result_chars: list[str] = []
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

        return sanitized, was_sanitized

    # =========================================================================
    # GENERIC ACI PARSING - Parametrized for OUD/RFC/OID
    # =========================================================================

    @staticmethod
    def validate_aci_format(
        acl_line: str,
        aci_prefix: str = "aci:",
    ) -> tuple[bool, str]:
        """Validate and extract ACI content from line.

        Args:
            acl_line: Raw ACL line
            aci_prefix: Expected prefix (default: "aci:")

        Returns:
            Tuple of (is_valid, aci_content)

        """
        u_ldif_instance = _get_u_ldif()
        if not acl_line or not acl_line.strip():
            return False, ""
        first_line = acl_line.split("\n", maxsplit=1)[0].strip()
        if not first_line.startswith(aci_prefix):
            return False, ""
        aci_content = u_ldif_instance.cond(
            (
                lambda: "\n" in acl_line,
                lambda: u_ldif_instance.pipe(
                    acl_line,
                    lambda line: line.split("\n"),
                    lambda lines: (
                        lines[0].split(":", 1)[1].strip() + "\n" + "\n".join(lines[1:])
                    ),
                ),
            ),
            default=acl_line.split(":", 1)[1].strip,
        )()
        return True, aci_content

    @staticmethod
    def extract_aci_components(
        aci_content: str,
        patterns: dict[str, tuple[str, int]],
        defaults: dict[str, str | None] | None = None,
    ) -> dict[str, str | None]:
        """Extract all ACI components using configurable patterns.

        Args:
            aci_content: ACI content string (without prefix)
            patterns: Dict mapping component name to (pattern, group) tuple
            defaults: Default values for components

        Returns:
            Context dict with extracted components

        """
        context: dict[str, str | None] = dict(defaults or {})
        context["aci_content"] = aci_content

        def extract_pattern(
            name: str,
            pattern_spec: str | tuple[str, int],
        ) -> tuple[str, str | None]:
            """Extract component from pattern spec."""
            u_ldif_instance = _get_u_ldif()
            if u_ldif_instance.is_type(pattern_spec, tuple):
                pattern_spec_tuple = pattern_spec
                pattern, group = pattern_spec_tuple
            else:
                pattern = pattern_spec
                group = 1
            if not pattern:
                return name, None
            value = FlextLdifUtilitiesACL.extract_component(aci_content, pattern, group)
            return name, value

        def has_pattern(pattern_spec: str | tuple[str, int]) -> bool:
            """Check if pattern spec is valid."""
            u_ldif_instance = _get_u_ldif()
            if u_ldif_instance.is_type(pattern_spec, tuple):
                return bool(pattern_spec[0])
            return bool(pattern_spec)

        process_result = u.Collection.process(
            patterns,
            processor=extract_pattern,
            predicate=lambda _k, v: has_pattern(v),
            on_error="skip",
        )
        u_ldif_instance = _get_u_ldif()
        if process_result.is_success:
            filtered_dict = u_ldif_instance.as_type(
                u.Collection.filter(
                    process_result.value,
                    predicate=lambda _k, v: u_ldif_instance.is_type(v, str),
                ),
                target="dict",
                default={},
            )
            if filtered_dict:
                context.update(filtered_dict)

        return context

    @staticmethod
    def parse_targetattr(
        targetattr_str: str | None,
        separator: str = "||",
    ) -> tuple[list[str], str]:
        """Parse targetattr string to attributes list and target DN.

        Args:
            targetattr_str: Target attribute string
            separator: Separator for multiple attributes (default: "||")

        Returns:
            Tuple of (target_attributes, target_dn)

        """
        u_ldif_instance = _get_u_ldif()
        if not targetattr_str:
            return [], "*"

        return u_ldif_instance.cond(
            (
                lambda s: separator in s,
                lambda s: (
                    u_ldif_instance.as_type(
                        u_ldif_instance.map_filter(
                            s.split(separator),
                            mapper=lambda a: a.strip(),
                            predicate=lambda a: bool(a.strip()),
                        ),
                        target="list",
                        default=[],
                    ),
                    "*",
                ),
            ),
            (lambda s: s != "*", lambda s: ([s.strip()], "*")),
            default=([], "*"),
        )(targetattr_str)

    @staticmethod
    def _check_special_value(
        rule_value: str,
        special_values: dict[str, tuple[str, str]],
    ) -> tuple[str, str] | None:
        """Check if rule value matches any special value."""

        def matches_special(_k: str, _unused_value_tuple: tuple[str, str]) -> bool:
            """Check if rule value matches special key."""
            return bool(u.normalize(rule_value, _k))

        found = u.Collection.find(
            special_values,
            predicate=matches_special,
            return_key=True,
        )

        def is_valid_special_match(found_item: object) -> bool:
            """Check if found item is valid special match tuple."""
            u_ldif_instance = _get_u_ldif()
            if (
                not u_ldif_instance.is_type(found_item, tuple)
                or len(found_item) != TUPLE_LENGTH_PAIR
            ):
                return False
            found_item_tuple = found_item
            value_tuple = found_item_tuple[1]
            if (
                not u_ldif_instance.is_type(value_tuple, tuple)
                or len(value_tuple) != TUPLE_LENGTH_PAIR
            ):
                return False
            value_tuple_typed = value_tuple
            return isinstance(value_tuple_typed[0], str) and isinstance(
                value_tuple_typed[1],
                str,
            )

        if found and is_valid_special_match(found):
            key, value_tuple = cast("tuple[str, tuple[str, str]]", found)
            if u.normalize(rule_value, key):
                return cast("tuple[str, str]", value_tuple)
        return None

    @staticmethod
    def build_aci_subject(
        bind_rules_data: list[dict[str, str]],
        subject_type_map: dict[str, str],
        special_values: dict[str, tuple[str, str]],
    ) -> tuple[str, str]:
        """Build ACL subject from bind rules using configurable maps.

        Args:
            bind_rules_data: List of bind rule dicts with 'type' and 'value'
            subject_type_map: Mapping of bind type to subject type
            special_values: Special subject values (self, anonymous, etc.)

        Returns:
            Tuple of (subject_type, subject_value)

        """
        if not bind_rules_data:
            return "self", "ldap:///self"

        def process_rule(rule: dict[str, str]) -> tuple[str, str] | None:
            """Process single bind rule."""
            u_ldif_instance = _get_u_ldif()
            get_type = u_ldif_instance.prop("type")
            get_value = u_ldif_instance.prop("value")
            rule_type = u_ldif_instance.maybe(
                get_type(rule),
                default="",
                mapper=str.lower,
            )
            rule_value = u_ldif_instance.maybe(get_value(rule), default="")
            special_match = FlextLdifUtilitiesACL._check_special_value(
                rule_value,
                special_values,
            )
            if special_match:
                return special_match
            mapped_type = u_ldif_instance.maybe(
                u_ldif_instance.get(subject_type_map, rule_type),
            )
            if mapped_type:
                return mapped_type, rule_value
            return None

        process_result = u.Collection.process(
            bind_rules_data,
            processor=process_rule,
            on_error="skip",
        )
        tuple_length_expected = 2
        u_ldif_instance = _get_u_ldif()
        if process_result.is_success and u_ldif_instance.is_type(
            process_result.value,
            "list",
        ):
            process_value = process_result.value
            if isinstance(process_value, dict):
                process_value = list(process_value.values())
            found = u.Collection.find(process_value, predicate=lambda r: r is not None)
            u_ldif_instance = _get_u_ldif()
            if (
                found is not None
                and u_ldif_instance.is_type(found, tuple)
                and len(found) == tuple_length_expected
                and u_ldif_instance.is_type(found[0], str)
                and u_ldif_instance.is_type(found[1], str)
            ):
                return cast("tuple[str, str]", found)

        u_ldif_instance = _get_u_ldif()
        get_value = u_ldif_instance.prop("value")
        default_value = u_ldif_instance.maybe(
            get_value(bind_rules_data[0]) if bind_rules_data else None,
            default="",
        )
        return "user", default_value

    @staticmethod
    def filter_supported_permissions(
        permissions: list[str],
        supported: set[str] | frozenset[str],
    ) -> list[str]:
        """Filter permissions to only include supported ones.

        Args:
            permissions: List of permission names
            supported: Set of supported permission names

        Returns:
            Filtered list of supported permissions

        """
        u_ldif_instance = _get_u_ldif()
        supported_lower = {s.lower() for s in supported}
        return u_ldif_instance.map_filter(
            permissions,
            mapper=lambda p: p.lower(),
            predicate=lambda p: p in supported_lower,
        )

    @staticmethod
    def build_aci_target_clause(
        target_attributes: list[str] | None,
        target_dn: str | None = None,
        separator: str = " || ",
    ) -> str:
        """Build ACI targetattr clause.

        Args:
            target_attributes: List of target attributes
            target_dn: Target DN (used if no attributes)
            separator: Separator for multiple attributes

        Returns:
            Formatted targetattr clause

        """
        u_ldif_instance = _get_u_ldif()
        return u_ldif_instance.cond(
            (
                lambda: bool(target_attributes),
                lambda: f'(targetattr="{separator.join(target_attributes)}")',
            ),
            (
                lambda: bool(target_dn) and target_dn != "*",
                lambda: f'(targetattr="{target_dn}")',
            ),
            default='(targetattr="*")',
        )()

    @staticmethod
    def build_aci_permissions_clause(
        permissions: list[str],
        allow_prefix: str = "(allow (",
        supported_permissions: set[str] | frozenset[str] | None = None,
    ) -> str | None:
        """Build ACI permissions clause.

        Args:
            permissions: List of permission names
            allow_prefix: Prefix for allow clause
            supported_permissions: Optional set of supported permissions to filter

        Returns:
            Formatted permissions clause or None if empty

        """
        u_ldif_instance = _get_u_ldif()
        filtered = u_ldif_instance.when(
            condition=bool(supported_permissions),
            then=lambda: FlextLdifUtilitiesACL.filter_supported_permissions(
                permissions,
                supported_permissions or frozenset(),
            ),
            else_=permissions,
        )
        return u_ldif_instance.when(
            condition=bool(filtered),
            then=lambda: f"{allow_prefix}{','.join(filtered)})",
            else_=None,
        )

    @staticmethod
    def build_aci_bind_rule(
        subject_type: str,
        subject_value: str,
        bind_operators: dict[str, str] | None = None,
        self_value: str = "ldap:///self",
        anonymous_value: str = "ldap:///anyone",
    ) -> str:
        """Build ACI bind rule (subject) clause.

        Args:
            subject_type: Subject type (user, group, self, anonymous, etc.)
            subject_value: Subject value (DN or special value)
            bind_operators: Mapping of subject type to bind operator
            self_value: Value for self subject
            anonymous_value: Value for anonymous subject

        Returns:
            Formatted bind rule string

        """
        default_operators = {
            "user": "userdn",
            "group": "groupdn",
            "role": "roledn",
            "self": "userdn",
            "anonymous": "userdn",
        }
        u_ldif_instance = _get_u_ldif()
        operators = bind_operators or default_operators
        get_self = u_ldif_instance.prop("self")
        get_anonymous = u_ldif_instance.prop("anonymous")
        get_subject = u_ldif_instance.prop(subject_type)

        return u_ldif_instance.switch(
            subject_type,
            {
                "self": (
                    f"{u_ldif_instance.maybe(get_self(operators), default='userdn')}="
                    f'"{self_value}"'
                ),
                "anonymous": (
                    f"{u_ldif_instance.maybe(get_anonymous(operators), default='userdn')}="
                    f'"{anonymous_value}"'
                ),
            },
            default=u_ldif_instance.pipe(
                subject_value,
                lambda v: v.replace(", ", ","),
                lambda v: v if v.startswith("ldap:///") else f"ldap:///{v}",
                lambda v: (
                    f"{u_ldif_instance.maybe(get_subject(operators), default='userdn')}="
                    f'"{v}"'
                ),
            ),
        )

    @staticmethod
    def format_aci_line(
        config: FlextLdifModelsConfig.AciLineFormatConfig,
    ) -> str:
        r"""Format complete ACI line from components.

        Args:
            config: AciLineFormatConfig with all formatting parameters

        Returns:
            Formatted ACI line string

        Example:
            config = FlextLdifModelsConfig.AciLineFormatConfig(
                name="test-acl",
                target_clause="(targetattr=\"cn\")",
                permissions_clause="allow (read,write)",
                bind_rule="userdn=\"ldap:///self\"",
            )
            aci_line = FlextLdifUtilities.ACL.format_aci_line(config)

        """
        sanitized_name, _ = FlextLdifUtilitiesACL.sanitize_acl_name(config.name)
        return (
            f"{config.aci_prefix}{config.target_clause}"
            f'(version {config.version}; acl "{sanitized_name}"; '
            f"{config.permissions_clause} {config.bind_rule};)"
        )

    # =========================================================================
    # HIGH-LEVEL PARSE/WRITE - Uses Models for server-specific config
    # =========================================================================

    @staticmethod
    def _extract_version_and_name(
        aci_content: str,
        version_pattern: str,
        default_name: str,
    ) -> tuple[str, str]:
        """Extract version and ACL name from content."""
        u_ldif_instance = _get_u_ldif()
        version_match = re.search(version_pattern, aci_content)
        version = u_ldif_instance.or_(
            (
                version_match.group(1)
                if version_match
                and version_match.lastindex
                and version_match.lastindex >= 1
                else None
            ),
            default="3.0",
        )
        acl_name = u_ldif_instance.or_(
            (
                version_match.group(TUPLE_LENGTH_PAIR)
                if version_match
                and version_match.lastindex
                and version_match.lastindex >= TUPLE_LENGTH_PAIR
                else None
            ),
            default=default_name,
        )
        return version, acl_name

    @staticmethod
    def _extract_target_info(
        aci_content: str,
        config: FlextLdifModelsConfig.AciParserConfig,
    ) -> tuple[list[str], str]:
        """Extract target attributes and DN from ACI content.

        Args:
            aci_content: ACI content string
            config: AciParserConfig with targetattr_pattern and default_targetattr

        Returns:
            Tuple of (target_attributes, target_dn)

        """
        # Extract targetattr
        u_ldif_instance = _get_u_ldif()
        targetattr_extracted = FlextLdifUtilitiesACL.extract_component(
            aci_content,
            config.targetattr_pattern,
            group=2,
        )
        targetattr = u_ldif_instance.or_(
            targetattr_extracted,
            default=config.default_targetattr,
        )
        target_attributes, target_dn = FlextLdifUtilitiesACL.parse_targetattr(
            targetattr,
        )
        return target_attributes, target_dn

    @staticmethod
    def _build_subject_and_permissions(
        aci_content: str,
        config: FlextLdifModelsConfig.AciParserConfig,
    ) -> tuple[str, str, dict[str, bool]]:
        """Build subject and permissions from ACI content.

        Args:
            aci_content: ACI content string
            config: AciParserConfig with patterns and maps

        Returns:
            Tuple of (subject_type, subject_value, permissions_dict)

        """
        # Extract permissions and bind rules
        permissions_list = FlextLdifUtilitiesACL.extract_permissions(
            aci_content,
            config.allow_deny_pattern,
            config.ops_separator,
            config.action_filter,
        )
        bind_rules_data = FlextLdifUtilitiesACL.extract_bind_rules(
            aci_content,
            config.bind_patterns,
        )

        # Build subject and permissions
        subject_type_map = {"userdn": "user", "groupdn": "group", "roledn": "role"}
        subject_type, subject_value = FlextLdifUtilitiesACL.build_aci_subject(
            bind_rules_data,
            subject_type_map,
            config.special_subjects,
        )
        permissions_dict_raw = FlextLdifUtilitiesACL.build_permissions_dict(
            permissions_list,
            config.permission_map,
        )
        u_ldif_instance = _get_u_ldif()
        permissions_dict = u_ldif_instance.map_dict(
            permissions_dict_raw,
            mapper=lambda _k, v: (
                bool(v) if u_ldif_instance.is_type(v, bool, int, str) else False
            ),
        )
        return subject_type, subject_value, permissions_dict

    @staticmethod
    def _build_extensions(
        aci_content: str,
        version: str,
        acl_line: str,
        extra_patterns: dict[str, str],
    ) -> dict[str, t.MetadataAttributeValue]:
        """Build metadata extensions dict."""
        extensions: dict[str, t.MetadataAttributeValue] = {
            "version": version,
            "original_format": acl_line,
        }

        def extract_extra(_pattern_name: str, pattern: str) -> str | None:
            """Extract extra field from pattern."""
            return FlextLdifUtilitiesACL.extract_component(
                aci_content,
                pattern,
                group=1,
            )

        extra_result = u.Collection.process(
            extra_patterns,
            processor=extract_extra,
            predicate=lambda _k, v: bool(v),
            on_error="skip",
        )
        u_ldif_instance = _get_u_ldif()
        if extra_result.is_success:
            filtered_extensions = u_ldif_instance.as_type(
                u.Collection.filter(
                    extra_result.value,
                    predicate=lambda _k, v: u_ldif_instance.is_type(v, str),
                ),
                target="dict",
                default={},
            )
            if filtered_extensions:
                extensions = u_ldif_instance.evolve(extensions, filtered_extensions)
        return extensions

    @staticmethod
    def parse_aci(
        acl_line: str,
        config: FlextLdifModelsConfig.AciParserConfig,
    ) -> r[FlextLdifModelsDomains.Acl]:
        """Parse ACI line using server-specific config Model.

        Args:
            acl_line: Raw ACL line string
            config: AciParserConfig with server-specific patterns

        Returns:
            r with parsed Acl model

        Example:
            config = FlextLdifModelsConfig.AciParserConfig(
                server_type=FlextLdifConstants.ServerTypes.OUD,
                version_acl_pattern=OudConstants.ACL_VERSION_ACL_PATTERN,
                targetattr_pattern=OudConstants.ACL_TARGETATTR_PATTERN,
                allow_deny_pattern=OudConstants.ACL_ALLOW_DENY_PATTERN,
                bind_patterns=dict(OudConstants.ACL_BIND_PATTERNS),
            )
            result = FlextLdifUtilities.ACL.parse_aci(acl_line, config)

        """
        # Validate and extract ACI content
        is_valid, aci_content = FlextLdifUtilitiesACL.validate_aci_format(
            acl_line,
            config.aci_prefix,
        )
        if not is_valid:
            return r.fail(
                f"Not a valid ACI format: {config.aci_prefix}",
            )

        # Extract version and name
        version, acl_name = FlextLdifUtilitiesACL._extract_version_and_name(
            aci_content,
            config.version_acl_pattern,
            config.default_name,
        )

        # Extract target info
        target_attributes, target_dn = FlextLdifUtilitiesACL._extract_target_info(
            aci_content,
            config,
        )

        # Build subject and permissions
        subject_type, subject_value, permissions_dict = (
            FlextLdifUtilitiesACL._build_subject_and_permissions(
                aci_content,
                config,
            )
        )

        # Build extensions
        extensions = FlextLdifUtilitiesACL._build_extensions(
            aci_content,
            version,
            acl_line,
            config.extra_patterns,
        )

        # Create Acl model
        acl_model = FlextLdifModelsDomains.Acl(
            name=acl_name,
            target=FlextLdifModelsDomains.AclTarget(
                target_dn=target_dn,
                attributes=target_attributes,
            ),
            subject=FlextLdifModelsDomains.AclSubject.model_validate({
                "subject_type": subject_type,
                "subject_value": subject_value,
            }),
            permissions=FlextLdifModelsDomains.AclPermissions(**permissions_dict),
            server_type=config.server_type,
            raw_acl=acl_line,
            metadata=FlextLdifModels.QuirkMetadata.create_for(
                config.server_type,
                extensions=(
                    FlextLdifModelsMetadata.DynamicMetadata(**extensions)
                    if extensions
                    else None
                ),
            ),
        )
        return r.ok(acl_model)

    @staticmethod
    def write_aci(
        acl_data: FlextLdifModelsDomains.Acl,
        config: FlextLdifModelsConfig.AciWriterConfig,
    ) -> r[str]:
        """Write Acl model to ACI string using server-specific config Model.

        Args:
            acl_data: Acl model to write
            config: AciWriterConfig with server-specific settings

        Returns:
            r with formatted ACI string

        Example:
            config = FlextLdifModelsConfig.AciWriterConfig(
                aci_prefix="aci: ",
                version="3.0",
                supported_permissions=OudConstants.SUPPORTED_PERMISSIONS,
            )
            result = FlextLdifUtilities.ACL.write_aci(acl, config)

        """
        # Build target clause
        # Type narrowed: acl_data is concrete Acl model with target object
        target_attributes = acl_data.target.attributes if acl_data.target else None
        target_dn = acl_data.target.target_dn if acl_data.target else None
        target_clause = FlextLdifUtilitiesACL.build_aci_target_clause(
            target_attributes,
            target_dn,
            config.attr_separator,
        )

        # Build permissions clause
        # Type narrowed: acl_data is concrete Acl model with permissions object
        if not acl_data.permissions:
            return r.fail("ACL has no permissions")
        u_ldif_instance = _get_u_ldif()
        perm_candidates = [
            "read",
            "write",
            "add",
            "delete",
            "search",
            "compare",
            "self_write",
            "proxy",
        ]
        perm_names = u_ldif_instance.map_filter(
            perm_candidates,
            predicate=lambda name: bool(getattr(acl_data.permissions, name, False)),
        )
        permissions_clause = FlextLdifUtilitiesACL.build_aci_permissions_clause(
            perm_names,
            f"({config.allow_prefix}",
            config.supported_permissions,
        )
        if not permissions_clause:
            return r.fail("No supported permissions")

        # Build bind rule
        # Type narrowed: acl_data is concrete Acl model with subject object
        subject_type = acl_data.subject.subject_type if acl_data.subject else "self"
        subject_value = (
            acl_data.subject.subject_value if acl_data.subject else config.self_subject
        )
        bind_rule = FlextLdifUtilitiesACL.build_aci_bind_rule(
            subject_type,
            subject_value,
            bind_operators=config.bind_operators,
            self_value=config.self_subject,
            anonymous_value=config.anonymous_subject,
        )

        # Format complete ACI
        acl_name = acl_data.name or "ACL"
        format_config = FlextLdifModelsConfig.AciLineFormatConfig(
            name=acl_name,
            target_clause=target_clause,
            permissions_clause=permissions_clause,
            bind_rule=bind_rule,
            version=config.version,
            aci_prefix=config.aci_prefix,
        )
        aci_line = FlextLdifUtilitiesACL.format_aci_line(format_config)
        return r.ok(aci_line)

    @staticmethod
    def extract_bind_rules_from_extensions(
        extensions: dict[str, t.MetadataAttributeValue] | None,
        rule_config: list[tuple[str, str, str | None]],
        *,
        tuple_length: int = 2,
    ) -> list[str]:
        """Extract and format bind rules from metadata extensions.

        Generic utility for extracting bind rules like ip, dns, dayofweek, etc.
        from ACL metadata extensions with consistent formatting.

        Args:
            extensions: Metadata extensions dict (may be None)
            rule_config: List of (extension_key, format_template, operator_default)
                        tuples. format_template can use {value} or {operator}/{value}
                        placeholders. operator_default is used for tuple values that
                        need operator.
            tuple_length: Expected length for tuple values
                         (default: 2 for (operator, value))

        Returns:
            List of formatted bind rule strings

        Example:
            >>> rule_config = [
            ...     ("ACL_BIND_IP", 'ip="{value}"', None),
            ...     ("ACL_BIND_DNS", 'dns="{value}"', None),
            ...     ("ACL_BIND_TIMEOFDAY", 'timeofday {operator} "{value}"', "="),
            ... ]
            >>> extract_bind_rules_from_extensions(extensions, rule_config)
            ['ip="192.168.1.0/24"', 'timeofday >= "0800"']

        """
        if not extensions:
            return []

        def process_rule_config(rule_item: tuple[str, str, str | None]) -> str | None:
            """Process single rule config item."""
            ext_key, format_template, operator_default = rule_item
            u_ldif_instance = _get_u_ldif()
            value_raw = u_ldif_instance.maybe(
                (u_ldif_instance.get(extensions, ext_key) if extensions else None),
            )
            if not value_raw:
                return None

            operator_placeholder = "{" + "operator" + "}"
            expected_tuple_length = tuple_length
            u_ldif_instance = _get_u_ldif()
            return u_ldif_instance.match(
                value_raw,
                (
                    lambda v: (
                        u_ldif_instance.is_type(v, tuple)
                        and len(v) == expected_tuple_length
                    ),
                    lambda v: (
                        format_template.format(
                            operator=str(v[0]),
                            value=str(v[1]),
                        )
                        if operator_placeholder in format_template
                        else format_template.format(value=str(v[1]))
                    ),
                ),
                (
                    lambda _v: (
                        operator_placeholder in format_template
                        and operator_default is not None
                    ),
                    lambda v: format_template.format(
                        operator=operator_default,
                        value=str(v),
                    ),
                ),
                default=lambda v: format_template.format(value=str(v)),
            )

        process_result = u.Collection.process(
            rule_config,
            processor=process_rule_config,
            predicate=lambda item: bool(
                u_ldif_instance.maybe(
                    u_ldif_instance.get(extensions, item[0]) if extensions else None,
                ),
            ),
            on_error="skip",
        )
        u_ldif_instance = _get_u_ldif()
        return u_ldif_instance.maybe(
            process_result.value if process_result.is_success else None,
            default=[],
            mapper=lambda v: (
                u_ldif_instance.map_filter(
                    v,
                    predicate=lambda rule: rule is not None,
                )
                if u_ldif_instance.is_type(v, "list")
                else []
            ),
        )

    @staticmethod
    def extract_target_extensions(
        extensions: FlextLdifModelsMetadata.DynamicMetadata
        | dict[str, t.MetadataAttributeValue]
        | None,
        target_config: list[tuple[str, str]],
    ) -> list[str]:
        """Extract and format target extensions from metadata extensions.

        Generic utility for extracting target extensions like targattrfilters,
        targetcontrol, extop, etc. from ACL metadata extensions.

        Args:
            extensions: Metadata extensions dict (may be None)
            target_config: List of (extension_key, format_template) tuples.
                          format_template uses {value} placeholder.

        Returns:
            List of formatted target extension strings

        Example:
            >>> target_config = [
            ...     ("ACL_TARGETATTR_FILTERS", '(targattrfilters="{value}")'),
            ...     ("ACL_TARGET_CONTROL", '(targetcontrol="{value}")'),
            ...     ("ACL_EXTOP", '(extop="{value}")'),
            ... ]
            >>> extract_target_extensions(extensions, target_config)
            ['(targetcontrol="1.2.840.113556.1.4.805")']

        """
        if not extensions:
            return []

        def process_target_config(target_item: tuple[str, str]) -> str | None:
            """Process single target config item."""
            ext_key, format_template = target_item
            u_ldif_instance = _get_u_ldif()
            value = u_ldif_instance.maybe(
                u_ldif_instance.get(extensions, ext_key),
            )
            return u_ldif_instance.maybe(
                value,
                mapper=lambda v: format_template.format(value=v),
            )

        process_result = u.Collection.process(
            target_config,
            processor=process_target_config,
            predicate=lambda item: bool(
                u_ldif_instance.maybe(
                    u_ldif_instance.get(extensions, item[0]) if extensions else None,
                ),
            ),
            on_error="skip",
        )
        u_ldif_instance = _get_u_ldif()
        return u_ldif_instance.maybe(
            process_result.value if process_result.is_success else None,
            default=[],
            mapper=lambda v: u_ldif_instance.map_filter(
                v,
                predicate=lambda part: part is not None,
            )
            if u_ldif_instance.is_type(v, "list")
            else [],
        )

    @staticmethod
    def format_conversion_comments(
        extensions: FlextLdifModelsMetadata.DynamicMetadata
        | dict[str, t.MetadataAttributeValue]
        | None,
        converted_from_key: str,
        comments_key: str,
    ) -> list[str]:
        """Extract conversion comments from metadata extensions.

        Args:
            extensions: Metadata extensions dict (may be None)
            converted_from_key: Key for checking if conversion occurred
            comments_key: Key for the list of comment strings

        Returns:
            List of comment strings (with empty string at end if comments exist)

        """
        if not extensions:
            return []

        u_ldif_instance = _get_u_ldif()
        if not u_ldif_instance.maybe(
            u_ldif_instance.get(extensions, converted_from_key),
        ):
            return []

        return u_ldif_instance.pipe(
            u_ldif_instance.maybe(
                u_ldif_instance.get(extensions, comments_key),
                default=[],
            ),
            lambda c: u_ldif_instance.normalize_list(c, mapper=str),
            lambda m: u_ldif_instance.as_type(m, target="list", default=[]),
            lambda r: r + [""],  # Empty line after comments
        )

    @staticmethod
    def parser(acl_string: str) -> dict[str, str] | None:
        """Detect ACL format and return format information.

        Generic utility for detecting ACL format from raw string,
        used to determine which server-specific quirk to apply.

        Args:
            acl_string: Raw ACL string to analyze

        Returns:
            Dict with "format" key ("oid", "oud", "rfc") or None if unrecognized

        Example:
            >>> parser("orclaci: access to entry by * (browse)")
            {"format": "oid"}
            >>> parser('aci: (version 3.0; acl "test"; ...)')
            {"format": "oud"}

        """
        u_ldif_instance = _get_u_ldif()
        if not acl_string or not acl_string.strip():
            return None

        first_line = acl_string.split("\n", maxsplit=1)[0].strip()

        return u_ldif_instance.cond(
            (
                lambda: first_line.startswith(("orclaci:", "orclentrylevelaci:")),
                lambda: {"format": "oid"},
            ),
            (
                lambda: first_line.startswith("aci:"),
                lambda: {"format": "oud"},
            ),
            default=None,
        )()

    @staticmethod
    def map_oid_to_oud_permissions(
        oid_permissions: dict[str, bool],
    ) -> dict[str, bool]:
        """Map OID-specific permissions to OUD-equivalent permissions.

        Handles OID → OUD permission conversion:
        - browse → read + search (OID browse allows listing, OUD requires
          read+search)
        - selfwrite → write (OID-specific self-write becomes OUD write)
        - Other permissions (read, write, add, delete, search, compare, all)
          pass through

        Args:
            oid_permissions: Dict with OID permission names as keys
                           (e.g., browse, selfwrite)

        Returns:
            Dict with OUD-compatible permission names mapped correctly

        Example:
            >>> oid_perms = {"browse": True, "write": False}
            >>> oud_perms = FlextLdifUtilitiesACL.map_oid_to_oud_permissions(oid_perms)
            >>> print(oud_perms)  # {"read": True, "search": True, "write": False}

        """
        u_ldif_instance = _get_u_ldif()
        pass_through_perms = {
            "read",
            "write",
            "add",
            "delete",
            "search",
            "compare",
            "all",
        }

        def map_perm(perm_name: str, *, perm_value: bool) -> dict[str, bool]:
            """Map single permission."""
            u_ldif_instance = _get_u_ldif()
            return u_ldif_instance.switch(
                perm_name,
                {
                    "browse": {
                        "read": perm_value,
                        "search": perm_value,
                    },
                    "selfwrite": {"write": perm_value},
                },
                default=(
                    {perm_name: perm_value} if perm_name in pass_through_perms else {}
                ),
            )

        u_ldif_instance = _get_u_ldif()
        pairs = u_ldif_instance.pairs(oid_permissions)
        mapped_dicts = u_ldif_instance.process_flatten(
            pairs,
            processor=lambda item: map_perm(
                item[0],
                perm_value=item[1],
            ),
            on_error="skip",
        )

        # Merge with OR combiner for boolean values
        filtered_dicts = u_ldif_instance.map_filter(
            mapped_dicts,
            predicate=lambda d: u_ldif_instance.is_type(d, dict),
        )
        return u_ldif_instance.merge(
            *filtered_dicts,
            combiner=lambda _k, v1, v2: v1 or v2,
        )

    @staticmethod
    def map_oud_to_oid_permissions(
        oud_permissions: dict[str, bool],
    ) -> dict[str, bool]:
        """Map OUD-specific permissions to OID-equivalent permissions.

        Handles OUD → OID permission conversion (reverse mapping):
        - read + search → browse (OUD read+search becomes OID browse)
        - write → write (standard mapping, no special handling needed)
        - Other permissions (add, delete, compare, all) pass through

        Args:
            oud_permissions: Dict with OUD permission names as keys

        Returns:
            Dict with OID-compatible permission names mapped correctly

        Example:
            >>> oud_perms = {"read": True, "search": True, "write": False}
            >>> oid_perms = FlextLdifUtilitiesACL.map_oud_to_oid_permissions(oud_perms)
            >>> print(oid_perms)  # {"browse": True, "write": False}

        """
        u_ldif_instance = _get_u_ldif()
        pass_through_perms = {
            "read",
            "write",
            "add",
            "delete",
            "search",
            "compare",
            "all",
        }

        # Handle read + search → browse conversion
        get_read = u_ldif_instance.prop("read")
        get_search = u_ldif_instance.prop("search")
        has_read = u_ldif_instance.maybe(
            get_read(oud_permissions),
            default=False,
        )
        has_search = u_ldif_instance.maybe(
            get_search(oud_permissions),
            default=False,
        )
        browse_dict = (
            {"browse": has_read and has_search} if (has_read or has_search) else {}
        )

        # Pass through standard permissions (except read/search)
        pass_through = u_ldif_instance.where(
            oud_permissions,
            predicate=lambda k, _v: (
                k in pass_through_perms and k not in {"read", "search"}
            ),
        )

        return u_ldif_instance.merge(browse_dict, pass_through)

    # =========================================================================
    # BATCH METHODS - Power Method Support
    # =========================================================================

    @staticmethod
    def extract_components_batch(
        content: str,
        patterns: Mapping[str, str | tuple[str, int]],
        *,
        defaults: Mapping[str, object] | None = None,
    ) -> dict[str, object]:
        r"""Extract multiple ACL components in one call.

        Replaces repetitive extract_component() calls with a single batch call.

        Example - BEFORE (9 calls in oid.py):
            bindmode = extract_component(acl, r'bindmode=([^,;]+)', None)
            filter = extract_component(acl, r'filter="([^"]*)"', None)
            constraint = extract_component(acl, r'constraint="([^"]*)"', None)
            # ... 6 more calls

        AFTER (1 call):
            components = extract_components_batch(
                acl_string,
                {
                    'bindmode': r'bindmode=([^,;]+)',
                    'filter': r'filter="([^"]*)"',
                    'constraint': r'constraint="([^"]*)"',
                },
                defaults={'bindmode': None, 'filter': None, 'constraint': None}
            )

        Args:
            content: ACL content string to extract from
            patterns: Mapping of component names to regex patterns.
                      Pattern can be str or (pattern, group_index) tuple.
            defaults: Default values for components not found

        Returns:
            Dictionary of extracted component values

        Examples:
            >>> components = FlextLdifUtilitiesACL.extract_components_batch(
            ...     "target=ldap:///dc=example;bindmode=all;filter=(*)",
            ...     {
            ...         "target": r"target=([^;]+)",
            ...         "bindmode": r"bindmode=([^;]+)",
            ...         "filter": r"filter=\\(([^)]*)\\)",
            ...     },
            ...     defaults={"filter": "*"},
            ... )
            >>> components["target"]
            'ldap:///dc=example'

        """
        effective_defaults = defaults or {}

        def extract_component_batch(
            name: str,
            pattern_spec: str | tuple[str, int],
        ) -> tuple[str, object]:
            """Extract component from pattern spec."""
            u_ldif_instance = _get_u_ldif()
            if u_ldif_instance.is_type(pattern_spec, tuple):
                pattern_spec_tuple = pattern_spec
                pattern, group_idx = pattern_spec_tuple
            else:
                pattern = pattern_spec
                group_idx = 1
            value = FlextLdifUtilitiesACL.extract_component(content, pattern, group_idx)
            u_ldif_instance = _get_u_ldif()
            default_value = u_ldif_instance.maybe(
                u_ldif_instance.get(effective_defaults, name),
            )
            return name, u_ldif_instance.maybe(value, default=default_value)

        u_ldif_instance = _get_u_ldif()
        process_result = u.Collection.process(
            patterns,
            processor=extract_component_batch,
            on_error="skip",
        )
        u_ldif_instance = _get_u_ldif()
        if not process_result.is_success or not u_ldif_instance.is_type(
            process_result.value,
            "dict",
        ):
            return {}

        def extract_value(name: str, value_tuple: object) -> dict[str, object] | None:
            """Extract value from tuple."""
            u_ldif_instance = _get_u_ldif()
            if (
                u_ldif_instance.is_type(value_tuple, tuple)
                and len(value_tuple) == TUPLE_LENGTH_PAIR
            ):
                value_tuple_typed = value_tuple
                return {name: value_tuple_typed[1]}
            return None

        u_ldif_instance = _get_u_ldif()
        pairs = (
            u_ldif_instance.pipe(
                process_result.value if process_result.is_success else {},
                lambda v: u_ldif_instance.as_type(v, target="dict"),
                u_ldif_instance.pairs,
            )
            if process_result.is_success
            else []
        )
        mapped_dicts = u_ldif_instance.process_flatten(
            pairs,
            processor=extract_value,
            on_error="skip",
        )

        return u_ldif_instance.reduce_dict(mapped_dicts)

    @staticmethod
    def _parse_single_acl_with_config(
        acl_line: str,
        config: FlextLdifModelsConfig.AciParserConfig,
        *,
        fail_fast: bool = False,
    ) -> FlextLdifModelsDomains.Acl | None:
        """Parse single ACL line, return None on error."""
        u_ldif_instance = _get_u_ldif()
        result = u_ldif_instance.try_(
            lambda: FlextLdifUtilitiesACL.parse_aci(acl_line, config),
            default=None,
        )
        if not result or not result.is_success:
            if fail_fast and result:
                error_msg = f"ACL parse failed: {result.error}"
                raise ValueError(error_msg)
            return None
        return result.unwrap()

    @staticmethod
    def _format_batch_errors(errors: list[tuple[int, str]]) -> list[str]:
        """Format batch error tuples to strings."""
        u_ldif_instance = _get_u_ldif()
        return u_ldif_instance.pipe(
            errors,
            lambda errs: u_ldif_instance.map_filter(
                errs,
                mapper=lambda t: f"ACL {t[0]}: {t[1]}",
            ),
        )

    @staticmethod
    def _process_batch_results(
        batch_data: dict[str, object],
        *,
        skip_invalid: bool = True,
    ) -> r[list[FlextLdifModelsDomains.Acl]]:
        """Process batch results and return r."""
        u_ldif_instance = _get_u_ldif()
        results = u_ldif_instance.smart_convert(
            u_ldif_instance.maybe(
                u_ldif_instance.get(batch_data, "results"),
                default=[],
            ),
            target_type="list",
            predicate=lambda r: (
                u_ldif_instance.is_type(r, FlextLdifModelsDomains.Acl)
            ),
            default=[],
        )
        results_typed = cast("list[FlextLdifModelsDomains.Acl]", results)

        error_count = u_ldif_instance.pipe(
            u_ldif_instance.maybe(
                u_ldif_instance.get(batch_data, "error_count"),
                default=0,
            ),
            lambda v: u_ldif_instance.as_type(v, target=int, default=0),
        )
        if error_count > 0 and not skip_invalid:
            errors_raw = u_ldif_instance.as_type(
                u_ldif_instance.maybe(
                    u_ldif_instance.get(batch_data, "errors"),
                    default=[],
                ),
                target="list",
                default=[],
            )
            errors_typed = u_ldif_instance.map_filter(
                errors_raw,
                predicate=lambda e: (
                    u_ldif_instance.is_type(e, tuple) and len(e) == TUPLE_LENGTH_PAIR
                ),
            )
            if errors_typed:
                error_msgs = FlextLdifUtilitiesACL._format_batch_errors(
                    cast("list[tuple[int, str]]", errors_typed),
                )
                return r.fail(f"Parse errors: {'; '.join(error_msgs)}")
        return r.ok(results_typed)

    @staticmethod
    def parse_batch(
        acl_lines: Sequence[str],
        config: FlextLdifModelsConfig.AciParserConfig,
        *,
        fail_fast: bool = False,
        skip_invalid: bool = True,
    ) -> r[list[FlextLdifModelsDomains.Acl]]:
        """Parse multiple ACL lines in one call.

        Args:
            acl_lines: Sequence of ACL line strings to parse
            config: Parser configuration
            fail_fast: If True, return error on first parse failure
            skip_invalid: If True, skip invalid ACLs (when fail_fast=False)

        Returns:
            r containing list of parsed ACL objects

        Examples:
            >>> config = FlextLdifModelsConfig.AciParserConfig(
            ...     strict_mode=False,
            ...     preserve_comments=True,
            ... )
            >>> result = FlextLdifUtilitiesACL.parse_batch(
            ...     acl_lines,
            ...     config,
            ...     fail_fast=False,
            ... )
            >>> if result.is_success:
            ...     acls = result.unwrap()

        """

        def parse_single_acl(acl_line: str) -> FlextLdifModelsDomains.Acl | None:
            """Parse single ACL line wrapper."""
            return FlextLdifUtilitiesACL._parse_single_acl_with_config(
                acl_line,
                config,
                fail_fast=fail_fast,
            )

        u_ldif_instance = _get_u_ldif()
        batch_result: r[t.Types.BatchResultDict] = u.batch(
            list(acl_lines),
            operation=parse_single_acl,
            on_error="collect" if not fail_fast else "fail",
            pre_validate=lambda r: r
            is not None,  # Changed from post_validate to pre_validate
        )
        if batch_result.is_failure:
            return cast("r[list[FlextLdifModelsDomains.Acl]]", batch_result)

        batch_data_dict = u_ldif_instance.pick(
            batch_result.value,
            "results",
            "errors",
            "error_count",
        )
        return FlextLdifUtilitiesACL._process_batch_results(
            batch_data_dict,
            skip_invalid=skip_invalid,
        )

    @staticmethod
    def convert_permissions_batch(
        permissions_list: Sequence[dict[str, bool]],
        direction: Literal["oid_to_oud", "oud_to_oid"],
    ) -> r[list[dict[str, bool]]]:
        """Convert multiple permission sets between OID and OUD formats.

        Args:
            permissions_list: Sequence of permission dictionaries
            direction: Conversion direction ("oid_to_oud" or "oud_to_oid")

        Returns:
            r containing list of converted permission dictionaries

        Examples:
            >>> oid_perms = [{"read": True, "search": True}, {"write": True}]
            >>> result = FlextLdifUtilitiesACL.convert_permissions_batch(
            ...     oid_perms,
            ...     direction="oid_to_oud",
            ... )

        """

        def convert_single_permissions(permissions: dict[str, bool]) -> dict[str, bool]:
            """Convert single permission set."""
            u_ldif_instance = _get_u_ldif()
            return u_ldif_instance.switch(
                direction,
                {
                    "oid_to_oud": (
                        lambda: (
                            FlextLdifUtilitiesACL.map_oid_to_oud_permissions(
                                permissions,
                            )
                        )
                    ),
                    "oud_to_oid": (
                        lambda: (
                            FlextLdifUtilitiesACL.map_oud_to_oid_permissions(
                                permissions,
                            )
                        )
                    ),
                },
                default=lambda: permissions,
            )()

        batch_result: r[t.Types.BatchResultDict] = u.batch(
            list(permissions_list),
            operation=convert_single_permissions,
            on_error="fail",
        )
        if batch_result.is_failure:
            return cast("r[list[dict[str, bool]]]", batch_result)
        u_ldif_instance = _get_u_ldif()
        results = u_ldif_instance.pipe(
            batch_result.value,
            lambda b: u_ldif_instance.maybe(
                u_ldif_instance.get(b, "results"),
                default=[],
            ),
            lambda r: u_ldif_instance.smart_convert(
                r,
                target_type="list",
                predicate=lambda x: (u_ldif_instance.is_type(x, dict)),
                default=[],
            ),
        )
        return r.ok(cast("list[dict[str, bool]]", results))

    @staticmethod
    def validate_batch(
        acl_lines: Sequence[str],
        *,
        collect_errors: bool = True,
    ) -> r[list[tuple[str, bool, str | None]]]:
        """Validate multiple ACL lines.

        Business Rule:
        - Validates ACI format for each ACL line using RFC 2849/4512 standards
        - Returns tuple (is_valid, aci_content) where is_valid indicates
          format correctness
        - When collect_errors=False, stops at first invalid ACL
          (fail-fast pattern)
        - Error messages are extracted from validation tuple for audit trail

        Args:
            acl_lines: Sequence of ACL line strings to validate
            collect_errors: If True, continue after failures (default: True)

        Returns:
            r containing list of (acl_line, is_valid, error_message) tuples
            - is_valid: True if ACL format is valid, False otherwise
            - error_message: None if valid, error description if invalid

        Examples:
            >>> result = FlextLdifUtilitiesACL.validate_batch([
            ...     "(target=ldap:///...)(version 3.0;acl...)",
            ...     "invalid-acl",
            ... ])
            >>> if result.is_success:
            ...     for line, is_valid, error in result.unwrap():
            ...         print(f"Valid: {is_valid}")

        """

        def validate_single_acl(acl_line: str) -> tuple[str, bool, str | None]:
            """Validate single ACL line."""
            is_valid, aci_content = FlextLdifUtilitiesACL.validate_aci_format(acl_line)
            if is_valid:
                return (acl_line, True, None)
            error_msg = aci_content or "Invalid ACI format"
            return (acl_line, False, error_msg)

        u_ldif_instance = _get_u_ldif()
        if collect_errors:
            validated_result = u.Collection.process(
                list(acl_lines),
                processor=validate_single_acl,
                on_error="skip",
            )
            results = u_ldif_instance.maybe(
                validated_result.value if validated_result.is_success else None,
                default=[],
                mapper=lambda v: (
                    u_ldif_instance.as_type(v, target="list", default=[])
                ),
            )
        else:
            # Fail-fast: stop at first invalid using fold
            def fold_validate(
                acc: tuple[list[tuple[str, bool, str | None]], bool],
                line: str,
            ) -> tuple[list[tuple[str, bool, str | None]], bool]:
                """Fold with early termination."""
                results_list, should_stop = acc
                if should_stop:
                    return acc
                result_tuple = validate_single_acl(line)
                results_list.append(result_tuple)
                return results_list, not result_tuple[1]

            results, _ = u_ldif_instance.fold(
                list(acl_lines),
                initial=([], False),
                folder=fold_validate,
            )

        return r.ok(results)


__all__ = [
    "FlextLdifUtilitiesACL",
]
