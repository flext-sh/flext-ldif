"""LDIF ACL content extraction utilities.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import r

from flext_ldif import c, p, t


class FlextLdifACLExtraction:
    """Extract components, permissions, and bind rules from ACL content."""

    @staticmethod
    def _extract_from_match(match: t.Ldif.RegexMatch, group: int) -> p.Result[str]:
        """Extract group from regex match, propagating the group-index failure.

        Returns:
            The resulting ``p.Result[str]``.
        """
        if match.lastindex is None:
            full_match: str = match.group(0)
            return r[str].ok(full_match)
        if group > match.lastindex:
            return r[str].fail(f"Regex group {group} exceeds last index")
        try:
            extracted: str = match.group(group)
        except IndexError as exc:
            return r[str].fail(str(exc), exception=exc)
        return r[str].ok(extracted)

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
            >>> pattern = r"targetattr\s*=\s*\"([^\"]+)\""
            >>> extract_component(aci_content, pattern, group=1)
            "cn,mail,telephoneNumber"

        """
        if not content or not pattern:
            return None
        match = c.Ldif.compile_pattern(pattern).search(content)
        if not match:
            return None
        extraction = FlextLdifACLExtraction._extract_from_match(match, group)
        if extraction.success:
            extracted_value: str = extraction.value
            return extracted_value
        return None

    @staticmethod
    def extract_permissions(
        content: str,
        allow_deny_pattern: str,
        ops_separator: str = ",",
        action_filter: str | None = None,
    ) -> t.MutableSequenceOf[str]:
        """Extract permissions from ACL content using configurable patterns.

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
        permissions: t.MutableSequenceOf[str] = []
        matches = c.Ldif.compile_pattern(allow_deny_pattern, ignorecase=True).finditer(
            content,
        )
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
            if action_filter and action.lower() != action_filter.lower():
                continue
            if ops:
                split_ops = ops.split(ops_separator)
                permissions.extend(s for op in split_ops if (s := op.strip()))
        return permissions

    @staticmethod
    def extract_bind_rules(
        content: str,
        bind_patterns: t.MutableStrMapping | None = None,
    ) -> t.MutableSequenceOf[t.MutableStrMapping]:
        """Extract bind rules from ACL content.

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
        default_patterns: t.MutableStrMapping = {
            "userdn": 'userdn\\s*=\\s*"([^"]*)"',
            "groupdn": 'groupdn\\s*=\\s*"([^"]*)"',
            "roledn": 'roledn\\s*=\\s*"([^"]*)"',
        }
        patterns = bind_patterns or default_patterns
        all_bind_rules: t.MutableSequenceOf[t.MutableStrMapping] = []
        for bind_type, pattern in dict(patterns).items():
            matches = c.Ldif.compile_pattern(pattern, ignorecase=True).findall(content)
            all_bind_rules.extend([
                {"type": bind_type, "value": match} for match in matches
            ])
        return all_bind_rules


__all__: list[str] = ["FlextLdifACLExtraction"]
