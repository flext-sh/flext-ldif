"""Extracted nested class from FlextLdifUtilities.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import re

from flext_core import FlextLogger, FlextResult, FlextTypes

from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif.models import FlextLdifModels

# Lazy import to avoid circular dependency
# FlextLdifConstants imported when needed in methods

logger = FlextLogger(__name__)

# Type for parsed ACL components (using MetadataValue for nested structures)
AclComponent = dict[str, str | FlextTypes.MetadataAttributeValue]


class FlextLdifUtilitiesACL:
    """Generic ACL parsing and writing utilities."""

    # ASCII control character boundaries for sanitization (use constants from FlextLdifConstants.Rfc)
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
                perms = [op.strip() for op in ops.split(ops_separator)]
                permissions.extend([p for p in perms if p])

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

        bind_rules: list[dict[str, str]] = []
        for bind_type, pattern in patterns.items():
            matches = re.findall(pattern, content, re.IGNORECASE)
            bind_rules.extend({"type": bind_type, "value": m} for m in matches)

        return bind_rules

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
        permissions: dict[str, bool] = {}

        def normalize(perm: str) -> str:
            """Normalize permission name using map if available."""
            if permission_map and perm in permission_map:
                return permission_map[perm]
            return perm

        if allow_permissions:
            for perm in allow_permissions:
                if perm:
                    permissions[normalize(perm)] = True

        if deny_permissions:
            for perm in deny_permissions:
                if perm:
                    permissions[normalize(perm)] = False

        return permissions

    # NOTE: OID-specific methods (extract_oid_target, detect_oid_subject, parse_oid_permissions,
    # format_oid_target, format_oid_subject, format_oid_permissions) were REMOVED from here.
    # They are now in FlextLdifServersOid.Acl class where OID knowledge belongs.
    # Servers must encapsulate their own knowledge - utilities should be generic/parametrized.

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
        # Clean up subject value if it contains spaces
        cleaned_value = subject_value.replace(", ", ",")

        # OUD ACI format: userdn="ldap:///..." or groupdn="ldap:///..."
        if bind_operator in {"userdn", "groupdn", "roledn"}:
            return f'{bind_operator}="ldap:///{cleaned_value}"'

        # OID format: by dn="..."
        return f'by dn="{cleaned_value}"'

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
        if not bind_rules_data:
            return ("", "")

        first_rule = bind_rules_data[0]
        rule_type = first_rule.get("type", "")
        rule_value = first_rule.get("value", "")

        # Check for special values first
        if rule_value in special_values:
            return special_values[rule_value]

        # Map the type
        subject_type = subject_type_map.get(rule_type, rule_type)

        return (subject_type, rule_value)

    @staticmethod
    def build_metadata_extensions(
        config: FlextLdifModels.Config.AclMetadataConfig,
    ) -> dict[str, FlextTypes.MetadataAttributeValue]:
        """Build QuirkMetadata extensions for ACL.

        Args:
            config: ACL metadata configuration

        Returns:
            Metadata extensions dictionary

        """
        extensions: dict[str, FlextTypes.MetadataAttributeValue] = {}

        if config.line_breaks:
            # config.line_breaks is list[int] | None, compatible with MetadataAttributeValue
            extensions["line_breaks"] = config.line_breaks
        if config.dn_spaces:
            # config.dn_spaces is bool, compatible with MetadataAttributeValue
            extensions["dn_spaces"] = config.dn_spaces
        if config.targetscope:
            extensions["targetscope"] = config.targetscope
        if config.version:
            extensions["version"] = config.version
        if config.action_type:
            extensions["action_type"] = config.action_type

        return extensions

    @staticmethod
    def sanitize_acl_name(raw_name: str, max_length: int = 128) -> tuple[str, bool]:
        """Sanitize ACL name for ACI format."""
        if not raw_name or not raw_name.strip():
            return "", False

        result: list[str] = []
        was_sanitized = False

        for char in raw_name:
            char_ord = ord(char)
            if (
                char_ord < FlextLdifConstants.Rfc.ASCII_PRINTABLE_MIN
                or char_ord > FlextLdifConstants.Rfc.ASCII_PRINTABLE_MAX
                or char == '"'
            ):
                was_sanitized = True
                if result and result[-1] != " ":
                    result.append(" ")
            else:
                result.append(char)

        sanitized = " ".join("".join(result).split())

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
        if not acl_line or not acl_line.strip():
            return False, ""
        first_line = acl_line.split("\n", maxsplit=1)[0].strip()
        if not first_line.startswith(aci_prefix):
            return False, ""
        if "\n" in acl_line:
            lines = acl_line.split("\n")
            first_line_content = lines[0].split(":", 1)[1].strip()
            aci_content = first_line_content + "\n" + "\n".join(lines[1:])
        else:
            aci_content = acl_line.split(":", 1)[1].strip()
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

        for name, (pattern, group) in patterns.items():
            if not pattern:
                continue
            value = FlextLdifUtilitiesACL.extract_component(aci_content, pattern, group)
            if value is not None:
                context[name] = value

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
        if not targetattr_str:
            return [], "*"
        if separator in targetattr_str:
            return [
                a.strip() for a in targetattr_str.split(separator) if a.strip()
            ], "*"
        if targetattr_str != "*":
            return [targetattr_str.strip()], "*"
        return [], "*"

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

        for rule in bind_rules_data:
            rule_type = rule.get("type", "").lower()
            rule_value = rule.get("value", "")

            # Check special values first
            for special_key, (stype, svalue) in special_values.items():
                if rule_value.lower() == special_key.lower():
                    return stype, svalue

            # Map bind type to subject type
            if rule_type in subject_type_map:
                return subject_type_map[rule_type], rule_value

        return "user", bind_rules_data[0].get("value", "")

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
        supported_lower = {s.lower() for s in supported}
        return [p for p in permissions if p.lower() in supported_lower]

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
        if target_attributes:
            return f'(targetattr="{separator.join(target_attributes)}")'
        if target_dn and target_dn != "*":
            return f'(targetattr="{target_dn}")'
        return '(targetattr="*")'

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
        filtered = permissions
        if supported_permissions:
            filtered = FlextLdifUtilitiesACL.filter_supported_permissions(
                permissions,
                supported_permissions,
            )
        if not filtered:
            return None
        return f"{allow_prefix}{','.join(filtered)})"

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
        operators = bind_operators or default_operators

        if subject_type == "self":
            return f'{operators.get("self", "userdn")}="{self_value}"'
        if subject_type == "anonymous":
            return f'{operators.get("anonymous", "userdn")}="{anonymous_value}"'

        operator = operators.get(subject_type, "userdn")
        clean_value = subject_value.replace(", ", ",")
        if not clean_value.startswith("ldap:///"):
            clean_value = f"ldap:///{clean_value}"
        return f'{operator}="{clean_value}"'

    @staticmethod
    def format_aci_line(
        name: str,
        target_clause: str,
        permissions_clause: str,
        bind_rule: str,
        version: str = "3.0",
        aci_prefix: str = "aci: ",
    ) -> str:
        """Format complete ACI line from components."""
        sanitized_name, _ = FlextLdifUtilitiesACL.sanitize_acl_name(name)
        return (
            f"{aci_prefix}{target_clause}"
            f'(version {version}; acl "{sanitized_name}"; '
            f"{permissions_clause} {bind_rule};)"
        )

    # =========================================================================
    # HIGH-LEVEL PARSE/WRITE - Uses Models for server-specific config
    # =========================================================================

    @staticmethod
    def parse_aci(
        acl_line: str,
        config: FlextLdifModels.Config.AciParserConfig,  # type: ignore[name-defined]
    ) -> FlextResult[FlextLdifModelsDomains.Acl]:
        """Parse ACI line using server-specific config Model.

        Args:
            acl_line: Raw ACL line string
            config: AciParserConfig with server-specific patterns

        Returns:
            FlextResult with parsed Acl model

        Example:
            config = FlextLdifModels.Config.AciParserConfig(
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
            return FlextResult[FlextLdifModels.Acl].fail(
                f"Not a valid ACI format: {config.aci_prefix}",
            )

        # Extract version and name
        acl_name = config.default_name
        version = "3.0"
        version_match = re.search(config.version_acl_pattern, aci_content)
        if version_match:
            version = version_match.group(1)
            acl_name = version_match.group(2)

        # Extract targetattr
        targetattr = config.default_targetattr
        targetattr_extracted = FlextLdifUtilitiesACL.extract_component(
            aci_content,
            config.targetattr_pattern,
            group=2,
        )
        if targetattr_extracted:
            targetattr = targetattr_extracted
        target_attributes, target_dn = FlextLdifUtilitiesACL.parse_targetattr(
            targetattr,
        )

        # Extract permissions
        permissions_list = FlextLdifUtilitiesACL.extract_permissions(
            aci_content,
            config.allow_deny_pattern,
            config.ops_separator,
            config.action_filter,
        )

        # Extract bind rules
        bind_rules_data = FlextLdifUtilitiesACL.extract_bind_rules(
            aci_content,
            config.bind_patterns,
        )

        # Build subject using config's special_subjects
        subject_type_map = {"userdn": "user", "groupdn": "group", "roledn": "role"}
        subject_type, subject_value = FlextLdifUtilitiesACL.build_aci_subject(
            bind_rules_data,
            subject_type_map,
            config.special_subjects,
        )

        # Build permissions dict using config's permission_map
        permissions_dict_raw = FlextLdifUtilitiesACL.build_permissions_dict(
            permissions_list,
            config.permission_map,
        )

        # Convert to typed permissions dict for AclPermissions model
        # AclPermissions expects bool fields, so ensure all values are bool
        permissions_dict: dict[str, bool] = {
            k: bool(v) if isinstance(v, (bool, int, str)) else False
            for k, v in permissions_dict_raw.items()
        }

        # Extract extra fields via extra_patterns and build extensions
        extensions: dict[str, FlextTypes.MetadataAttributeValue] = {
            "version": version,
            "original_format": acl_line,
        }
        for pattern_name, pattern in config.extra_patterns.items():
            extracted = FlextLdifUtilitiesACL.extract_component(
                aci_content,
                pattern,
                group=1,
            )
            if extracted:
                extensions[pattern_name] = extracted

        # Create Acl model
        acl = FlextLdifModels.Acl(
            name=acl_name,
            target=FlextLdifModels.AclTarget(
                target_dn=target_dn,
                attributes=target_attributes,
            ),
            subject=FlextLdifModels.AclSubject.model_validate({
                "subject_type": subject_type,  # Pydantic validates against AclSubjectTypeLiteral
                "subject_value": subject_value,
            }),
            permissions=FlextLdifModels.AclPermissions(**permissions_dict),
            server_type=config.server_type,
            raw_acl=acl_line,
            metadata=FlextLdifModels.QuirkMetadata.create_for(
                config.server_type,
                extensions=FlextLdifModels.DynamicMetadata(**extensions)
                if extensions
                else None,
            ),
        )
        return FlextResult[FlextLdifModelsDomains.Acl].ok(acl)

    @staticmethod
    def write_aci(
        acl_data: FlextLdifModelsDomains.Acl,
        config: FlextLdifModels.Config.AciWriterConfig,  # type: ignore[name-defined]
    ) -> FlextResult[str]:
        """Write Acl model to ACI string using server-specific config Model.

        Args:
            acl_data: Acl model to write
            config: AciWriterConfig with server-specific settings

        Returns:
            FlextResult with formatted ACI string

        Example:
            from flext_ldif.models import FlextLdifModels

            config = FlextLdifModels.Config.AciWriterConfig(
                aci_prefix="aci: ",
                version="3.0",
                supported_permissions=OudConstants.SUPPORTED_PERMISSIONS,
            )
            result = FlextLdifUtilities.ACL.write_aci(acl, config)

        """
        # Build target clause
        target_attributes = acl_data.target.attributes if acl_data.target else None
        target_dn = acl_data.target.target_dn if acl_data.target else None
        target_clause = FlextLdifUtilitiesACL.build_aci_target_clause(
            target_attributes,
            target_dn,
            config.attr_separator,
        )

        # Build permissions clause
        if not acl_data.permissions:
            return FlextResult[str].fail("ACL has no permissions")

        perm_names = [
            name
            for name in [
                "read",
                "write",
                "add",
                "delete",
                "search",
                "compare",
                "self_write",
                "proxy",
            ]
            if getattr(acl_data.permissions, name, False)
        ]
        permissions_clause = FlextLdifUtilitiesACL.build_aci_permissions_clause(
            perm_names,
            f"({config.allow_prefix}",
            config.supported_permissions,
        )
        if not permissions_clause:
            return FlextResult[str].fail("No supported permissions")

        # Build bind rule
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
        aci_line = FlextLdifUtilitiesACL.format_aci_line(
            acl_name,
            target_clause,
            permissions_clause,
            bind_rule,
            config.version,
            config.aci_prefix,
        )
        return FlextResult[str].ok(aci_line)

    @staticmethod
    def extract_bind_rules_from_extensions(
        extensions: dict[str, FlextTypes.MetadataAttributeValue] | None,
        rule_config: list[tuple[str, str, str | None]],
        *,
        tuple_length: int = 2,
    ) -> list[str]:
        """Extract and format bind rules from metadata extensions.

        Generic utility for extracting bind rules like ip, dns, dayofweek, etc.
        from ACL metadata extensions with consistent formatting.

        Args:
            extensions: Metadata extensions dict (may be None)
            rule_config: List of (extension_key, format_template, operator_default) tuples.
                        format_template can use {value} or {operator}/{value} placeholders.
                        operator_default is used for tuple values that need operator.
            tuple_length: Expected length for tuple values (default: 2 for (operator, value))

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

        bind_rules: list[str] = []

        for ext_key, format_template, operator_default in rule_config:
            # Get value - can be ScalarValue or tuple (operator, value)
            # Use FlextTypes.MetadataAttributeValue to include tuples
            value_raw: FlextTypes.MetadataAttributeValue | None = (
                extensions.get(ext_key) if extensions else None
            )
            if not value_raw:
                continue

            # Handle tuple values (operator, value)
            # Type narrowing: check if value is tuple before accessing
            operator_placeholder = "{" + "operator" + "}"
            if isinstance(value_raw, tuple) and len(value_raw) == tuple_length:
                operator, val = value_raw
                if operator_placeholder in format_template:
                    bind_rules.append(
                        format_template.format(operator=str(operator), value=str(val)),
                    )
                else:
                    bind_rules.append(format_template.format(value=str(val)))
            # Handle simple string values
            elif operator_placeholder in format_template and operator_default:
                # Type narrowing: value is not tuple here, safe to use as string
                value_str = str(value_raw)
                bind_rules.append(
                    format_template.format(operator=operator_default, value=value_str),
                )
            else:
                # Type narrowing: value is not tuple here, safe to use as string
                value_str = str(value_raw)
                bind_rules.append(format_template.format(value=value_str))

        return bind_rules

    @staticmethod
    def extract_target_extensions(
        extensions: FlextLdifModelsMetadata.DynamicMetadata
        | dict[str, FlextTypes.MetadataAttributeValue]
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

        target_parts: list[str] = []

        for ext_key, format_template in target_config:
            value = extensions.get(ext_key)
            if value:
                target_parts.append(format_template.format(value=value))

        return target_parts

    @staticmethod
    def format_conversion_comments(
        extensions: FlextLdifModelsMetadata.DynamicMetadata
        | dict[str, FlextTypes.MetadataAttributeValue]
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

        if not extensions.get(converted_from_key):
            return []

        comments = extensions.get(comments_key, [])
        if not comments or not isinstance(comments, list):
            return []

        result = [str(comment) for comment in comments]
        result.append("")  # Empty line after comments
        return result

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
        if not acl_string or not acl_string.strip():
            return None

        first_line = acl_string.split("\n", maxsplit=1)[0].strip()

        # Check OID format (orclaci: or orclentrylevelaci:)
        if first_line.startswith(("orclaci:", "orclentrylevelaci:")):
            return {"format": "oid"}

        # Check OUD/RFC ACI format (aci:)
        if first_line.startswith("aci:"):
            return {"format": "oud"}  # OUD uses RFC ACI format

        return None

    @staticmethod
    def map_oid_to_oud_permissions(
        oid_permissions: dict[str, bool],
    ) -> dict[str, bool]:
        """Map OID-specific permissions to OUD-equivalent permissions.

        Handles OID → OUD permission conversion:
        - browse → read + search (OID browse allows listing, OUD requires read+search)
        - selfwrite → write (OID-specific self-write becomes OUD write)
        - Other permissions (read, write, add, delete, search, compare, all) pass through

        Args:
            oid_permissions: Dict with OID permission names as keys (e.g., browse, selfwrite)

        Returns:
            Dict with OUD-compatible permission names mapped correctly

        Example:
            >>> oid_perms = {"browse": True, "write": False}
            >>> oud_perms = FlextLdifUtilitiesACL.map_oid_to_oud_permissions(oid_perms)
            >>> print(oud_perms)  # {"read": True, "search": True, "write": False}

        """
        oud_permissions: dict[str, bool] = {}

        # Direct pass-through permissions (exist in both OID and OUD)
        pass_through_perms = {
            "read",
            "write",
            "add",
            "delete",
            "search",
            "compare",
            "all",
        }

        # Process each OID permission
        for perm_name, perm_value in oid_permissions.items():
            if perm_name in pass_through_perms:
                # Standard permission - use as-is
                oud_permissions[perm_name] = perm_value
            elif perm_name == "browse":
                # OID browse → OUD read + search
                oud_permissions["read"] = (
                    oud_permissions.get("read", False) or perm_value
                )
                oud_permissions["search"] = (
                    oud_permissions.get("search", False) or perm_value
                )
            elif perm_name == "selfwrite":
                # OID selfwrite → OUD write
                oud_permissions["write"] = (
                    oud_permissions.get("write", False) or perm_value
                )
            elif perm_name == "proxy":
                # OID proxy has no direct OUD equivalent - skip for now
                # Could be preserved in metadata for potential future OUD extensions
                pass
            # Skip unknown OID-specific permissions

        return oud_permissions

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
        oid_permissions: dict[str, bool] = {}

        # Direct pass-through permissions (exist in both OUD and OID)
        pass_through_perms = {
            "read",
            "write",
            "add",
            "delete",
            "search",
            "compare",
            "all",
        }

        # Track which permissions we've processed
        processed = set()

        # Handle read + search → browse conversion
        has_read = oud_permissions.get("read", False)
        has_search = oud_permissions.get("search", False)
        if has_read or has_search:
            # Set browse if both read and search are present
            oid_permissions["browse"] = has_read and has_search
            processed.add("read")
            processed.add("search")

        # Pass through standard permissions (except read/search already processed)
        for perm_name in pass_through_perms:
            if (
                perm_name not in processed
                and perm_name not in {"read", "search"}
                and perm_name in oud_permissions
            ):
                oid_permissions[perm_name] = oud_permissions[perm_name]

        return oid_permissions


__all__ = [
    "FlextLdifUtilitiesACL",
]
