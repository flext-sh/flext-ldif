"""OID schema server — OID-specific field normalization helpers.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import MutableMapping
from typing import ClassVar

from flext_ldif import c, m, p, t, u
from flext_ldif.servers._oid.server_constants import FlextLdifServersOidConstants
from flext_ldif.servers.rfc import FlextLdifServersRfc


class FlextLdifServersOidSchemaNormalizeMixin(FlextLdifServersRfc.Schema):
    """Normalize parsed OID schema fields toward RFC-canonical values."""

    _module_logger: ClassVar[p.Logger] = u.fetch_logger(__name__)

    def _normalize_oid_attribute(
        self,
        attr: m.Ldif.SchemaAttribute,
    ) -> m.Ldif.SchemaAttribute:
        """Normalize OID-specific schema attribute fields.

        Returns:
            The resulting ``m.Ldif.SchemaAttribute``.
        """
        if attr.syntax:
            attr.syntax = u.Ldif.normalize_syntax_oid(attr.syntax)
        normalized_equality, normalized_substr = u.Ldif.normalize_matching_rules(
            attr.equality,
            attr.substr,
            replacements=FlextLdifServersOidConstants.MATCHING_RULE_TO_RFC,
            normalized_substr_values=FlextLdifServersOidConstants.MATCHING_RULE_TO_RFC,
        )
        if normalized_equality != attr.equality:
            attr.equality = normalized_equality
        if normalized_substr != attr.substr:
            attr.substr = normalized_substr
        if attr.ordering:
            normalized_ordering = FlextLdifServersOidConstants.MATCHING_RULE_TO_RFC.get(
                attr.ordering,
            )
            if normalized_ordering:
                attr.ordering = normalized_ordering
        if attr.syntax:
            attr.syntax = u.Ldif.normalize_syntax_oid(
                attr.syntax,
                replacements=FlextLdifServersOidConstants.SYNTAX_OID_TO_RFC,
            )
        return self._transform_case_ignore_substrings(attr)

    def _normalize_oid_objectclass(
        self,
        oc: m.Ldif.SchemaObjectClass,
    ) -> m.Ldif.SchemaObjectClass:
        """Normalize OID-specific objectClass fields.

        Returns:
            The resulting ``m.Ldif.SchemaObjectClass``.
        """
        original_format_str = (
            str(
                oc.metadata.extensions.get(
                    c.Ldif.SCHEMA_ORIGINAL_FORMAT,
                    oc.metadata.extensions.get(c.Ldif.ORIGINAL_FORMAT, ""),
                ),
            )
            if oc.metadata and oc.metadata.extensions
            else ""
        )
        updated_sup = self._normalize_sup_from_model(oc)
        if updated_sup is None and original_format_str:
            updated_sup = self._normalize_sup_from_original_format(original_format_str)
        updated_kind = self._normalize_auxiliary_typo(oc, original_format_str)
        normalized_must = self._normalize_attribute_names(oc.must)
        normalized_may = self._normalize_attribute_names(oc.may)
        update_dict: MutableMapping[str, str | t.MutableSequenceOf[str] | None] = {
            k: v
            for k, v in {
                "sup": updated_sup,
                "kind": updated_kind,
                "must": normalized_must if normalized_must != oc.must else None,
                "may": normalized_may if normalized_may != oc.may else None,
            }.items()
            if v
        }
        if update_dict:
            updated_oc: m.Ldif.SchemaObjectClass = oc.model_copy(update=update_dict)
            return updated_oc
        return oc

    @staticmethod
    def _normalize_attribute_names(
        attr_list: t.MutableSequenceOf[str] | None,
    ) -> t.MutableSequenceOf[str] | None:
        """Normalize attribute names using OID case mappings.

        Returns:
            The resulting ``t.MutableSequenceOf[str] | None``.
        """
        if not attr_list:
            return attr_list
        case_map = FlextLdifServersOidConstants.ATTR_NAME_CASE_MAP
        return [case_map.get(attr_name.lower(), attr_name) for attr_name in attr_list]

    @staticmethod
    def _normalize_auxiliary_typo(
        oc_data: m.Ldif.SchemaObjectClass,
        original_format_str: str,
    ) -> str | None:
        """Normalize AUXILLARY typo to AUXILIARY.

        Returns:
            The resulting ``str | None``.
        """
        kind = getattr(oc_data, "kind", None)
        match (kind, original_format_str):
            case [k, _] if k and k.upper() == "AUXILLARY":
                FlextLdifServersOidSchemaNormalizeMixin._module_logger.debug(
                    "OID→RFC transform: AUXILLARY → AUXILIARY",
                    objectclass_name=oc_data.name,
                    objectclass_oid=oc_data.oid,
                    original_kind=k,
                    normalized_kind="AUXILIARY",
                )
                return "AUXILIARY"
            case [_, fmt] if fmt and "AUXILLARY" in fmt:
                FlextLdifServersOidSchemaNormalizeMixin._module_logger.debug(
                    "OID→RFC: AUXILLARY → AUXILIARY (original_format)",
                    objectclass_name=oc_data.name,
                    objectclass_oid=oc_data.oid,
                    original_format_preview=fmt[
                        : FlextLdifServersOidConstants.MAX_LOG_LINE_LENGTH
                    ],
                )
                return "AUXILIARY"
            case _:
                return None

    @staticmethod
    def _normalize_sup_from_model(oc_data: m.Ldif.SchemaObjectClass) -> str | (
        t.MutableSequenceOf[str] | None
    ):
        """Normalize SUP from objectClass model.

        Returns:
            The resulting ``str | (t.MutableSequenceOf[str] | None)``.
        """
        if not oc_data.sup:
            return None
        sup_normalize_set = {"( top )", "(top)", "'top'", '"top"'}
        match oc_data.sup:
            case sup_str if (sup_clean := str(sup_str).strip()) in sup_normalize_set:
                FlextLdifServersOidSchemaNormalizeMixin._module_logger.debug(
                    "OID→RFC transform: SUP normalization",
                    objectclass_name=oc_data.name,
                    objectclass_oid=oc_data.oid,
                    original_sup=sup_clean,
                    normalized_sup="top",
                )
                return "top"
            case [sup_item] if (sup_clean := sup_item.strip()) in sup_normalize_set:
                FlextLdifServersOidSchemaNormalizeMixin._module_logger.debug(
                    "OID→RFC transform: SUP normalization (list)",
                    objectclass_name=oc_data.name,
                    objectclass_oid=oc_data.oid,
                    original_sup=sup_clean,
                    normalized_sup="top",
                )
                return "top"
            case _:
                return None

    @staticmethod
    def _normalize_sup_from_original_format(
        original_format_str: str,
    ) -> str | None:
        """Normalize SUP from original_format string.

        Returns:
            The resulting ``str | None``.
        """
        sup_patterns = ("SUP 'top'", "SUP ( top )", "SUP (top)")
        match original_format_str:
            case s if any(pattern in s for pattern in sup_patterns):
                FlextLdifServersOidSchemaNormalizeMixin._module_logger.debug(
                    "OID→RFC transform: SUP normalization (from original_format)",
                    original_format_preview=s[
                        : FlextLdifServersOidConstants.MAX_LOG_LINE_LENGTH
                    ],
                )
                return "top"
            case _:
                return None

    @staticmethod
    def _transform_case_ignore_substrings(
        attr_data: m.Ldif.SchemaAttribute,
    ) -> m.Ldif.SchemaAttribute:
        """Transform caseIgnoreSubstringsMatch from EQUALITY to SUBSTR.

        Returns:
            The resulting ``m.Ldif.SchemaAttribute``.
        """
        normalized_equality, normalized_substr = u.Ldif.normalize_matching_rules(
            attr_data.equality,
            attr_data.substr,
            substr_rules_in_equality={
                "caseIgnoreSubstringsMatch": "caseIgnoreMatch",
                "caseIgnoreSubStringsMatch": "caseIgnoreMatch",
            },
        )
        if (
            normalized_equality != attr_data.equality
            or normalized_substr != attr_data.substr
        ):
            FlextLdifServersOidSchemaNormalizeMixin._module_logger.debug(
                "Moved caseIgnoreSubstringsMatch from EQUALITY to SUBSTR",
                attribute_name=attr_data.name,
                original_equality=attr_data.equality or "",
                normalized_substr=normalized_substr or "",
            )
            original_format = (
                attr_data.metadata.extensions.get("original_format")
                if attr_data.metadata and attr_data.metadata.extensions
                else None
            )
            transformed = attr_data.model_copy(
                update={"equality": normalized_equality, "substr": normalized_substr},
            )
            if original_format and transformed.metadata:
                transformed.metadata.extensions[c.Ldif.SCHEMA_ORIGINAL_FORMAT] = (
                    original_format
                )
            transformed_attr: m.Ldif.SchemaAttribute = transformed
            return transformed_attr
        return attr_data


__all__: list[str] = ["FlextLdifServersOidSchemaNormalizeMixin"]
