"""Extracted nested class from FlextLdifUtilities.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import logging
import re
from typing import Any

from flext_core import FlextUtilities

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels

logger = logging.getLogger(__name__)


class FlextLdifUtilitiesACL:
    """Generic ACL parsing and writing utilities."""

    @staticmethod
    def parser(acl_line: str) -> dict[str, Any] | None:
        """Parse ACL line into components."""
        if not acl_line or not acl_line.strip():
            return None

        result: dict[str, Any] = {}
        line = acl_line.strip()

        if line.startswith("("):
            result["format"] = "oid"
            result["content"] = line
        elif ":" in line:
            parts = line.split(":", 1)
            result["format"] = "oud"
            result["key"] = parts[0]
            result["value"] = parts[1] if len(parts) > 1 else ""
        else:
            result["format"] = "unknown"
            result["content"] = line

        return result or None

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
        return match.group(group) if match else None

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

        Example:
            >>> pattern = r"(allow|deny)\\s*\\(([^)]+)\\)"
            >>> extract_permissions(aci, pattern, action_filter="allow")
            ["read", "write", "search"]

        """
        if not content or not allow_deny_pattern:
            return []

        permissions: list[str] = []
        matches = re.findall(allow_deny_pattern, content)

        for action, ops in matches:
            if action_filter and action != action_filter:
                continue

            ops_list = [op.strip() for op in ops.split(ops_separator) if op.strip()]
            permissions.extend(ops_list)

        return permissions

    @staticmethod
    def extract_bind_rules(
        content: str,
        patterns: dict[str, str],
    ) -> list[dict[str, str]]:
        r"""Extract bind rules from ACL content using configurable patterns.

        Args:
            content: ACL content string
            patterns: Dict mapping rule types to regex patterns
                Example: {"userdn": r'userdn\\s*=\\s*"ldap:///([^"]+)"'}

        Returns:
            List of bind rule dicts with 'type' and 'value' keys

        Example:
            >>> patterns = {
            ...     "userdn": r'userdn="ldap:///([^"]+)"',
            ...     "groupdn": r'groupdn="ldap:///([^"]+)"',
            ... }
            >>> extract_bind_rules(aci, patterns)
            [
                {"type": "userdn", "value": "cn=admin,dc=example,dc=com"},
                {"type": "groupdn", "value": "cn=admins,ou=groups,dc=example,dc=com"}
            ]

        """
        if not content or not patterns:
            return []

        bind_rules: list[dict[str, str]] = []

        for rule_type, pattern in patterns.items():
            matches = re.findall(pattern, content)
            bind_rules.extend(
                {
                    "type": rule_type,
                    "value": match if isinstance(match, str) else match[0],
                }
                for match in matches
            )

        return bind_rules

    @staticmethod
    def build_permissions_dict(
        permission_list: list[str],
        permission_mapping: dict[str, str],
    ) -> dict[str, bool]:
        """Build permissions dictionary from permission list.

        Args:
            permission_list: List of permission strings (e.g., ["read", "write"])
            permission_mapping: Map from permission names to dict keys
                Example: {"read": "can_read", "write": "can_write"}

        Returns:
            Dict with all permissions as keys, True for present permissions

        Example:
            >>> mapping = {
            ...     "read": "can_read",
            ...     "write": "can_write",
            ...     "add": "can_add",
            ... }
            >>> build_permissions_dict(["read", "write"], mapping)
            {"can_read": True, "can_write": True, "can_add": False}

        """
        # Initialize all permissions to False
        result: dict[str, bool] = dict.fromkeys(permission_mapping.values(), False)

        # Set True for permissions in list
        for perm in permission_list:
            perm_lower = perm.lower()
            if perm_lower in permission_mapping:
                dict_key = permission_mapping[perm_lower]
                result[dict_key] = True

        return result

    @staticmethod
    def detect_line_breaks(
        content: str,
        newline_separator: str = "\n",
    ) -> list[int]:
        r"""Detect line break positions in multi-line ACL content.

        Args:
            content: ACL content string
            newline_separator: Separator character for lines

        Returns:
            List of byte positions where line breaks occur

        Example:
            >>> detect_line_breaks("line1\\nline2\\nline3")
            [5, 11]  # Positions after "line1" and "line2"

        """
        if not content or newline_separator not in content:
            return []

        line_breaks: list[int] = []
        current_pos = 0

        for line_num, line in enumerate(content.split(newline_separator)):
            if line_num > 0:  # Skip first line
                line_breaks.append(current_pos)
            current_pos += len(line) + len(newline_separator)

        return line_breaks

    @staticmethod
    def build_acl_subject(
        bind_rules: list[dict[str, str]],
        subject_type_map: dict[str, str],
        special_values: dict[str, tuple[str, str]] | None = None,
    ) -> tuple[str, str]:
        """Build ACL subject from bind rules using configuration.

        Args:
            bind_rules: List of bind rule dicts with 'type' and 'value' keys
            subject_type_map: Map from bind rule type to subject type
                Example: {"userdn": "bind_rules", "groupdn": "group"}
            special_values: Map from rule values to (subject_type, subject_value)
                Example: {"self": ("self", "ldap:///self")}

        Returns:
            Tuple of (subject_type, subject_value)

        Example:
            >>> rules = [{"type": "userdn", "value": "cn=admin,dc=example,dc=com"}]
            >>> type_map = {"userdn": "bind_rules", "groupdn": "group"}
            >>> build_acl_subject(rules, type_map)
            ("bind_rules", 'userdn="cn=admin,dc=example,dc=com"')

        """
        # Default anonymous
        if not bind_rules:
            return ("anonymous", "*")

        first_rule = bind_rules[0]
        rule_type = first_rule["type"]
        rule_value = first_rule["value"]

        # Check special values first
        if special_values and rule_value in special_values:
            return special_values[rule_value]

        # Map rule type to subject type
        if rule_type in subject_type_map:
            subject_type = subject_type_map[rule_type]

            # Format based on rule type
            if rule_type == "groupdn":
                return (subject_type, rule_value)
            # Default format for userdn and others
            return (subject_type, f'{rule_type}="{rule_value}"')

        # Fallback
        return ("anonymous", "*")

    @staticmethod
    def build_metadata_extensions(
        line_breaks: list[int] | None = None,
        *,
        dn_spaces: bool = False,
        targetscope: str | None = None,
        version: str | None = None,
        default_version: str = "3.0",
    ) -> dict[str, object]:
        """Build QuirkMetadata extensions dict from parsed ACL components.

        Args:
            line_breaks: List of line break positions
            dn_spaces: Whether DN contains spaces after commas
            targetscope: Target scope value
            version: ACL version string
            default_version: Default version to compare against

        Returns:
            Dict of metadata extensions

        Example:
            >>> build_metadata_extensions(
            ...     line_breaks=[10, 20],
            ...     dn_spaces=True,
            ...     targetscope="subtree",
            ...     version="3.0",
            ... )
            {
                "line_breaks": [10, 20],
                "is_multiline": True,
                "dn_spaces": True,
                "targetscope": "subtree"
            }

        """
        extensions: dict[str, object] = {}

        if line_breaks:
            extensions["line_breaks"] = line_breaks
            extensions["is_multiline"] = True

        if dn_spaces:
            extensions["dn_spaces"] = True

        if targetscope:
            extensions["targetscope"] = targetscope

        if version and version != default_version:
            extensions["version"] = version

        return extensions

    @staticmethod
    def extract_oid_target(
        acl_line: str,
    ) -> tuple[str, list[str]]:
        """Extract target DN and attributes from OID ACL line.

        OID ACL format: orclaci: access to [entry|attr=(...)] by subject (permissions)

        Args:
            acl_line: OID ACL definition line

        Returns:
            Tuple of (target_dn, target_attributes)

        Example:
            >>> extract_oid_target(
            ...     "orclaci: access to attr=(cn,mail) by self (read,write)"
            ... )
            ("cn", ["cn", "mail"])

        """
        target_dn = "*"
        target_attrs: list[str] = []

        acl_line_lower = acl_line.strip().lower()
        if "attr=" in acl_line_lower:
            match = re.search(r"attr\s*=\s*\(([^)]+)\)", acl_line)
            if match:
                attrs_str = match.group(1)
                target_attrs = [a.strip() for a in attrs_str.split(",")]
                target_dn = attrs_str.split(",")[0].strip() if attrs_str else "*"

        return (target_dn, target_attrs)

    @staticmethod
    def detect_oid_subject(
        acl_line: str,
        subject_patterns: dict[str, tuple[str | None, str, str]],
    ) -> tuple[str, str]:
        r"""Detect OID ACL subject type and value using pattern matching.

        Args:
            acl_line: OID ACL definition line
            subject_patterns: Dict mapping check strings to (regex, type, value_format)
                Example: {
                    " by self ": (None, "self", "ldap:///self"),
                    ' by "': (r'by\\s+"([^"]+)"', "user_dn", "ldap:///{0}")
                }

        Returns:
            Tuple of (subject_type, subject_value)

        Example:
            >>> patterns = {
            ...     " by self ": (None, "self", "ldap:///self"),
            ...     ' by "': (r'by\\s+"([^"]+)"', "user_dn", "ldap:///{0}"),
            ... }
            >>> detect_oid_subject(
            ...     'orclaci: ... by "cn=admin,dc=example" (read)', patterns
            ... )
            ("user_dn", "ldap:///cn=admin,dc=example")

        """
        acl_line_lower = acl_line.strip().lower()

        for check_str, (
            pattern,
            subj_type,
            value_format,
        ) in subject_patterns.items():
            if check_str in acl_line_lower:
                if pattern is None:
                    # No regex needed, use format directly
                    return (subj_type, value_format)
                # Extract using regex
                match = re.search(pattern, acl_line)
                if match:
                    # Format value with match groups
                    value = value_format.format(*match.groups())
                    return (subj_type, value)

        # Default: anonymous
        return ("*", "*")

    @staticmethod
    def parse_oid_permissions(
        acl_line: str,
        permission_mapping: dict[str, list[str]],
    ) -> dict[str, bool]:
        """Parse OID ACL permissions from line.

        OID permissions are at the end in parentheses: (read,write,add)
        Special handling for "all" and "browse" permissions.

        Args:
            acl_line: OID ACL definition line
            permission_mapping: Map from permission names to result keys
                Example: {
                    "all": ["read", "write", "add", "delete", "search", "compare", "proxy"],
                    "browse": ["read", "search"],
                    "read": ["read"],
                    "write": ["write"]
                }

        Returns:
            Dict with all permission keys, True for granted permissions

        Example:
            >>> mapping = {
            ...     "all": ["read", "write", "add"],
            ...     "read": ["read"],
            ...     "write": ["write"],
            ... }
            >>> parse_oid_permissions("orclaci: ... (read,write)", mapping)
            {"read": True, "write": True, "add": False}

        """
        # Initialize all permissions to False
        all_keys = set()
        for keys_list in permission_mapping.values():
            all_keys.update(keys_list)
        perms_dict = dict.fromkeys(all_keys, False)

        # Find permission list at end of line
        perm_match = re.search(r"\(([^)]+)\)\s*$", acl_line)
        if not perm_match:
            return perms_dict

        perms_str = perm_match.group(1).lower()

        # Check each permission in the string
        for perm_name, keys_to_set in permission_mapping.items():
            if perm_name in perms_str:
                for key in keys_to_set:
                    perms_dict[key] = True

        return perms_dict

    @staticmethod
    def format_oid_target(
        target: FlextLdifModels.AclTarget | None,
    ) -> str:
        """Format OID ACL target clause.

        Args:
            target: AclTarget model with target_dn and attributes

        Returns:
            Formatted target string ("entry" or "attr=(...)")

        Example:
            >>> format_oid_target(AclTarget(attributes=["cn", "mail"]))
            "attr=(cn,mail)"

        """
        if not target:
            return "entry"

        if hasattr(target, "attributes") and target.attributes:
            attrs = ",".join(target.attributes)
            return f"attr=({attrs})"
        if (
            hasattr(target, "target_dn")
            and target.target_dn
            and target.target_dn != "*"
        ):
            return f"attr=({target.target_dn})"
        return "entry"

    @staticmethod
    def format_oid_subject(
        subject: FlextLdifModels.AclSubject | None,
        subject_formatters: dict[str, tuple[str, bool]],
    ) -> str:
        """Format OID ACL subject clause.

        Args:
            subject: AclSubject model with subject_type and subject_value
            subject_formatters: Dict mapping subject_type to (format_str, needs_dn_extraction)
                Example: {
                    "self": ("self", False),
                    "user_dn": ('"{0}"', True),
                    "group_dn": ('group="{0}"', True),
                    "dn_attr": ("dnattr=({0})", False)
                }

        Returns:
            Formatted subject string

        Example:
            >>> formatters = {"self": ("self", False), "user_dn": ('"{0}"', True)}
            >>> format_oid_subject(AclSubject(subject_type="self"), formatters)
            "self"

        """
        if not subject:
            return "*"

        subject_type = getattr(subject, "subject_type", "*")
        subject_value = getattr(subject, "subject_value", "*")

        if subject_type not in subject_formatters:
            return "*"

        format_str, needs_dn_extraction = subject_formatters[subject_type]

        # Extract DN from LDAP URL if needed
        if needs_dn_extraction and "ldap:///" in subject_value:
            dn = subject_value.split("ldap:///", 1)[1].split("?", 1)[0]
            if not dn or dn == "*":
                return "*"
            return format_str.format(dn)
        if needs_dn_extraction:
            return format_str.format(subject_value)
        # Extract attribute name from value (before #)
        attr_name = (
            subject_value.split("#", 1)[0] if "#" in subject_value else subject_value
        )
        return format_str.format(attr_name)

    @staticmethod
    def format_oid_permissions(
        permissions: FlextLdifModels.AclPermissions | None,
        permission_names: dict[str, str],
    ) -> str:
        """Format OID ACL permissions clause.

        Args:
            permissions: AclPermissions model
            permission_names: Dict mapping permission attribute to OID name
                Example: {"read": "read", "write": "write", "self_write": "selfwrite"}

        Returns:
            Formatted permissions string in parentheses: "(read,write)"

        Example:
            >>> names = {"read": "read", "write": "write"}
            >>> format_oid_permissions(AclPermissions(read=True, write=True), names)
            "(read,write)"

        """
        if not permissions:
            return "(all)"

        perms = []
        for attr_name, oid_name in permission_names.items():
            if hasattr(permissions, attr_name) and getattr(permissions, attr_name):
                perms.append(oid_name)

        return f"({','.join(perms)})" if perms else "(all)"

    @staticmethod
    def filter_supported_permissions(
        permissions: list[str],
        supported_set: set[str] | frozenset[str],
    ) -> list[str]:
        """Filter permissions to only supported ones.

        Args:
            permissions: List of permission names
            supported_set: Set or frozenset of supported permission names

        Returns:
            Filtered list of permissions

        """
        return [perm for perm in permissions if perm in supported_set]

    @staticmethod
    def format_aci_subject(
        subject_type: str,
        subject_value: str,
        constants: type,  # Server-specific Constants class with ACL attributes
    ) -> str:
        """Format ACL subject into ACI bind rule format.

        Args:
            subject_type: Type of subject (self, anonymous, group, etc.)
            subject_value: Subject value
            constants: Constants class with ACL format definitions

        Returns:
            Formatted bind rule string

        """
        # Map subject type to ACI format
        if subject_type == FlextLdifConstants.AclSubjectTypes.SELF:
            return f'userdn="{constants.ACL_SELF_SUBJECT}";)'

        if subject_type == FlextLdifConstants.AclSubjectTypes.ANONYMOUS:
            return f'userdn="{constants.ACL_ANONYMOUS_SUBJECT_ALT}";)'

        # Handle both "group" and "group_dn" subject types
        if subject_type in {FlextLdifConstants.AclSubjectTypes.GROUP, "group_dn"}:
            # Ensure LDAP URL format
            if not subject_value.startswith(constants.ACL_LDAP_URL_PREFIX):
                subject_value = f"{constants.ACL_LDAP_URL_PREFIX}{subject_value}"
            return f'groupdn="{subject_value}";)'

        if subject_type == constants.ACL_SUBJECT_TYPE_BIND_RULES:
            return f"{subject_value};)"

        if subject_type == "dn_attr":
            return f'userattr="{subject_value}";)'

        if subject_type == "guid_attr":
            return f'userattr="{subject_value}";)'

        if subject_type == "group_attr":
            return f'userattr="{subject_value}";)'

        # Default: treat as userdn
        if not subject_value.startswith(constants.ACL_LDAP_URL_PREFIX):
            subject_value = f"{constants.ACL_LDAP_URL_PREFIX}{subject_value}"
        return f'userdn="{subject_value}";)'

    @staticmethod
    def parse_novell_rights(
        rights_str: str,
        char_mapping: dict[str, list[str]],
    ) -> list[str]:
        """Parse Novell eDirectory rights string into permission list.

        Novell format: [BCDRWASE] where each letter represents a permission.

        Args:
            rights_str: Rights string like "[BCDRSE]" or "BCDR"
            char_mapping: Dict mapping chars to permission names
                Example: {"B": ["search"], "C": ["compare"], "R": ["read"]}

        Returns:
            List of permission names

        Example:
            >>> mapping = {"B": ["search"], "C": ["compare"], "R": ["read"]}
            >>> parse_novell_rights("[BCR]", mapping)
            ["search", "compare", "read"]

        """
        rights: list[str] = []

        if not rights_str:
            return rights

        # Remove brackets if present
        rights_clean = rights_str.strip("[]")

        # Parse individual permission letters
        for char in rights_clean:
            char_upper = char.upper()
            if char_upper in char_mapping:
                rights.extend(char_mapping[char_upper])

        return rights

    @staticmethod
    def build_novell_permissions(
        rights_list: list[str],
        permission_checks: dict[str, str],
    ) -> dict[str, bool]:
        """Build Novell permissions dict from rights list.

        **DRY Optimization**: Uses FlextUtilities.DataMapper.build_flags_dict()
        to eliminate duplicated permission-building logic.

        Args:
            rights_list: List of permission names
            permission_checks: Dict mapping permission names to check
                Example: {"read": "read", "write": "write"}

        Returns:
            Dict with permission keys set to True/False

        Example:
            >>> checks = {"read": "read", "write": "write", "add": "add"}
            >>> build_novell_permissions(["read", "write"], checks)
            {"read": True, "write": True, "add": False}

        """
        if not isinstance(rights_list, list):
            # Return all False if invalid input
            return dict.fromkeys(permission_checks, False)

        # Use generic DataMapper to build flags dict
        result = FlextUtilities.DataMapper.build_flags_dict(
            rights_list,
            permission_checks,
            default_value=False,
        )
        return (
            result.unwrap()
            if result.is_success
            else dict.fromkeys(permission_checks, False)
        )

    @staticmethod
    def collect_active_permissions(
        permissions: FlextLdifModels.AclPermissions | None,
        permission_attrs: list[tuple[str, str]],
    ) -> list[str]:
        """Collect list of active permission names from permissions model.

        Args:
            permissions: AclPermissions model
            permission_attrs: List of (attribute_name, output_name) tuples
                Example: [("read", "read"), ("write", "write")]

        Returns:
            List of active permission names

        Example:
            >>> attrs = [("read", "read"), ("write", "write"), ("add", "add")]
            >>> collect_active_permissions(AclPermissions(read=True, write=True), attrs)
            ["read", "write"]

        """
        active_perms: list[str] = []

        if not permissions:
            return active_perms

        for attr_name, output_name in permission_attrs:
            if hasattr(permissions, attr_name) and getattr(permissions, attr_name):
                active_perms.append(output_name)

        return active_perms


__all__ = [
    "FlextLdifUtilitiesACL",
]
