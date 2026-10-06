"""LDIF ACL metadata extension formatting utilities.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import ClassVar

from flext_cli import u

from flext_ldif import c, p, t


class FlextLdifACLExtensionFormatting:
    """Format ACL bind rules and targets from metadata extensions."""

    _module_logger: ClassVar[p.Logger] = u.fetch_logger(__name__)
    _OPERATOR_PLACEHOLDER: str = "{operator}"

    @staticmethod
    def _format_bind_rule_from_extension(
        value_raw: t.JsonValue | t.StrPair,
        format_template: str,
        operator_default: str | None,
        tuple_length: int,
    ) -> str:
        """Format one ACL bind rule from metadata extension payload.

        Returns:
            The resulting ``str``.
        """
        has_operator_placeholder = (
            FlextLdifACLExtensionFormatting._OPERATOR_PLACEHOLDER in format_template
        )
        match value_raw:
            case tuple() as tuple_items if (
                len(tuple_items) == tuple_length
                and len(tuple_items) >= c.Ldif.TUPLE_LENGTH_PAIR
            ):
                operator_val = tuple_items[0]
                value_val = tuple_items[1]
                if has_operator_placeholder:
                    return format_template.format(
                        operator=operator_val,
                        value=value_val,
                    )
                return format_template.format(value=value_val)
            case _ if has_operator_placeholder and operator_default is not None:
                return format_template.format(
                    operator=operator_default,
                    value=str(value_raw),
                )
            case _:
                return format_template.format(value=str(value_raw))

    @staticmethod
    def extract_bind_rules_from_extensions(
        extensions: t.Ldif.MutableMetadataMapping | None,
        rule_config: t.SequenceOf[tuple[str, str, str | None]],
        *,
        tuple_length: int = 2,
    ) -> t.MutableSequenceOf[str]:
        """Extract and format bind rules from metadata extensions.

        Returns:
            The resulting ``t.MutableSequenceOf[str]``.
        """
        if not extensions:
            return []

        result: t.MutableSequenceOf[str] = []
        for ext_key, format_template, operator_default in rule_config:
            try:
                value_raw = extensions.get(ext_key)
                if value_raw is None:
                    continue
                formatted_rule = (
                    FlextLdifACLExtensionFormatting._format_bind_rule_from_extension(
                        value_raw,
                        format_template,
                        operator_default,
                        tuple_length,
                    )
                )
                result.append(formatted_rule)
            except c.Ldif.EXC_LDIF_PARSE as e:
                FlextLdifACLExtensionFormatting._module_logger.debug(
                    "Skipping ACL rule processing due to error",
                    error=str(e),
                )
                continue
        return result

    @staticmethod
    def extract_target_extensions(
        extensions: t.Ldif.MetadataInputMapping | None,
        target_config: t.StrPairSequence,
    ) -> t.MutableSequenceOf[str]:
        """Extract and format target extensions from metadata extensions.

        Returns:
            The resulting ``t.MutableSequenceOf[str]``.
        """
        if not extensions:
            return []

        result: t.MutableSequenceOf[str] = []
        for ext_key, format_template in target_config:
            try:
                value_raw = extensions.get(ext_key)
                if not value_raw:
                    continue
                result.append(format_template.format(value=str(value_raw)))
            except c.Ldif.EXC_LDIF_PARSE as e:
                FlextLdifACLExtensionFormatting._module_logger.debug(
                    "Skipping ACL rule processing due to error",
                    error=str(e),
                )
        return result

    @staticmethod
    def format_conversion_comments(
        extensions: t.Ldif.MetadataInputMapping | None,
        converted_from_key: str,
        comments_key: str,
    ) -> t.MutableSequenceOf[str]:
        """Extract conversion comments from metadata extensions.

        Returns:
            The resulting ``t.MutableSequenceOf[str]``.
        """
        if not extensions:
            return []
        converted_from_value = (
            extensions.get(converted_from_key) if extensions else None
        )
        if not converted_from_value:
            return []
        comments_value: t.Ldif.MetadataCarrierValue | None = (
            extensions.get(comments_key) if extensions else None
        )
        if comments_value is None:
            return []
        normalized: t.MutableSequenceOf[str]
        if isinstance(comments_value, str):
            normalized = [comments_value]
        elif isinstance(comments_value, list):
            normalized = [str(item) for item in comments_value]
        else:
            normalized = [str(comments_value)]
        return [*normalized, ""]


__all__: list[str] = ["FlextLdifACLExtensionFormatting"]
