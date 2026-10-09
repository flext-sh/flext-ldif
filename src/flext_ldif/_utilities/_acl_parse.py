"""LDIF ACL subject, target, and permissions assembly utilities.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif import c, m, p, r, t
from flext_ldif._utilities import (
    FlextLdifACLExtraction,
    FlextLdifACLFormatting,
    FlextLdifACLPermissions,
    FlextLdifUtilitiesMetadata as um,
)


class FlextLdifACLParsing:
    """Parse ACI lines into structured Acl models."""

    @staticmethod
    def _check_special_value(
        rule_value: str,
        special_values: t.MutableStrPairMapping,
    ) -> t.StrPair | None:
        """Check if rule value matches any special value.

        Returns:
            The resulting ``t.StrPair | None``.
        """
        for key, value_tuple in dict(special_values).items():
            if (
                rule_value.lower() == key.lower()
                and len(value_tuple) == c.Ldif.TUPLE_LENGTH_PAIR
            ):
                return value_tuple
        return None

    @staticmethod
    def build_aci_subject(
        bind_rules_data: t.MutableSequenceOf[t.MutableStrMapping],
        subject_type_map: t.MutableStrMapping,
        special_values: t.MutableStrPairMapping,
    ) -> t.StrPair:
        """Build ACL subject from bind rules using configurable maps.

        Returns:
            The resulting ``t.StrPair``.
        """
        if not bind_rules_data:
            return ("self", "ldap:///self")
        for rule in bind_rules_data:
            rule_type_raw = rule.get("type", "")
            rule_type = rule_type_raw.lower()
            rule_value_raw = rule.get("value", "")
            rule_value = rule_value_raw
            special_match = FlextLdifACLParsing._check_special_value(
                rule_value,
                special_values,
            )
            if special_match:
                return special_match
            mapped_type_raw = subject_type_map.get(rule_type)
            mapped_type: str | None = (
                mapped_type_raw if isinstance(mapped_type_raw, str) else None
            )
            if mapped_type:
                return (mapped_type, rule_value)
        if bind_rules_data:
            default_value_raw = bind_rules_data[0].get("value", "")
            default_value = default_value_raw
        else:
            default_value = ""
        return ("user", default_value)

    @staticmethod
    def parse_targetattr(
        targetattr_str: str | None,
        separator: str = "||",
    ) -> tuple[t.MutableSequenceOf[str], str]:
        """Parse targetattr string to attributes list and target DN.

        Returns:
            The resulting ``tuple[t.MutableSequenceOf[str], str]``.
        """
        if not targetattr_str:
            return ([], "*")
        if separator in targetattr_str:
            attrs = [a.strip() for a in targetattr_str.split(separator) if a.strip()]
            return (attrs, "*")
        if targetattr_str != "*":
            return ([targetattr_str.strip()], "*")
        return ([], "*")

    @staticmethod
    def _extract_target_info(
        aci_content: str,
        settings: m.Ldif.AciParserConfig,
    ) -> tuple[t.MutableSequenceOf[str], str]:
        """Extract target attributes and DN from ACI content.

        Returns:
            The resulting ``tuple[t.MutableSequenceOf[str], str]``.
        """
        targetattr_extracted = FlextLdifACLExtraction.extract_component(
            aci_content,
            settings.targetattr_pattern,
            group=2,
        )
        targetattr: str = targetattr_extracted or settings.default_targetattr
        target_attributes, target_dn = FlextLdifACLParsing.parse_targetattr(targetattr)
        return (target_attributes, target_dn)

    @staticmethod
    def _extract_version_and_name(
        aci_content: str,
        version_pattern: str,
        default_name: str,
    ) -> t.StrPair:
        """Extract version and ACL name from content.

        Returns:
            The resulting ``t.StrPair``.
        """
        version_match = c.Ldif.compile_pattern(version_pattern).search(aci_content)
        version: str = (
            version_match.group(1)
            if version_match
            and version_match.lastindex
            and (version_match.lastindex >= 1)
            else None
        ) or "3.0"
        acl_name: str = (
            version_match.group(c.Ldif.TUPLE_LENGTH_PAIR)
            if version_match
            and version_match.lastindex
            and (version_match.lastindex >= c.Ldif.TUPLE_LENGTH_PAIR)
            else None
        ) or default_name
        return (version, acl_name)

    @staticmethod
    def _build_extensions(
        aci_content: str,
        version: str,
        acl_line: str,
        extra_patterns: t.MutableStrMapping,
    ) -> t.Ldif.MutableMetadataInputMapping:
        """Build metadata extensions dict.

        Returns:
            The resulting ``t.Ldif.MutableMetadataInputMapping``.
        """
        extensions: t.Ldif.MutableMetadataInputMapping = {
            "version": version,
            "original_format": acl_line,
        }

        def extract_extra(_pattern_name: str, pattern: str) -> str | None:
            """Extract extra field from pattern.

            Returns:
                The resulting ``str | None``.
            """
            return FlextLdifACLExtraction.extract_component(
                aci_content,
                pattern,
                group=1,
            )

        extra_dict: t.MutableOptionalStrMapping = {}
        for k, v in extra_patterns.items():
            if bool(v):
                result = extract_extra(k, v)
                if result is not None:
                    extra_dict[k] = result
        if extra_dict:
            filtered_extensions: t.MutableStrMapping = {
                k: v for k, v in extra_dict.items() if isinstance(v, str)
            }
            if filtered_extensions:
                extensions = dict(extensions, **filtered_extensions)
        return extensions

    @staticmethod
    def _build_subject_and_permissions(
        aci_content: str,
        settings: m.Ldif.AciParserConfig,
    ) -> tuple[str, str, t.MutableBoolMapping]:
        """Build subject and permissions from ACI content.

        Returns:
            The resulting ``tuple[str, str, t.MutableBoolMapping]``.
        """
        permissions_list = FlextLdifACLExtraction.extract_permissions(
            aci_content,
            settings.allow_deny_pattern,
            settings.ops_separator,
            settings.action_filter,
        )
        bind_rules_data = FlextLdifACLExtraction.extract_bind_rules(
            aci_content,
            settings.bind_patterns,
        )
        subject_type_map = {"userdn": "user", "groupdn": "group", "roledn": "role"}
        subject_type, subject_value = FlextLdifACLParsing.build_aci_subject(
            bind_rules_data,
            subject_type_map,
            settings.special_subjects,
        )
        permissions_dict_raw = FlextLdifACLPermissions.build_permissions_dict(
            permissions_list,
            settings.permission_map,
        )
        permissions_dict: t.MutableBoolMapping = dict(
            dict(permissions_dict_raw).items(),
        )
        return (subject_type, subject_value, permissions_dict)

    @staticmethod
    def parse_aci(
        acl_line: str,
        settings: m.Ldif.AciParserConfig,
    ) -> p.Result[m.Ldif.Acl]:
        """Parse ACI line using server-specific settings Model.

        Returns:
            The resulting ``p.Result[m.Ldif.Acl]``.
        """
        valid, aci_content = FlextLdifACLFormatting.validate_aci_format(
            acl_line,
            settings.aci_prefix,
        )
        if not valid:
            return r[m.Ldif.Acl].fail(f"Not a valid ACI format: {settings.aci_prefix}")
        version, acl_name = FlextLdifACLParsing._extract_version_and_name(
            aci_content,
            settings.version_acl_pattern,
            settings.default_name,
        )
        target_attributes, target_dn = FlextLdifACLParsing._extract_target_info(
            aci_content,
            settings,
        )
        subject_type, subject_value, permissions_dict = (
            FlextLdifACLParsing._build_subject_and_permissions(aci_content, settings)
        )
        extensions = FlextLdifACLParsing._build_extensions(
            aci_content,
            version,
            acl_line,
            settings.extra_patterns,
        )
        acl_model = m.Ldif.Acl(
            name=acl_name,
            target=m.Ldif.AclTarget.model_validate({
                "target_dn": target_dn,
                "attributes": target_attributes,
            }),
            subject=m.Ldif.AclSubject(
                subject_type=subject_type
                if FlextLdifACLPermissions.valid_acl_subject_type(subject_type)
                else c.Ldif.AclSubjectType.USER,
                subject_value=subject_value,
            ),
            permissions=m.Ldif.AclPermissions(**permissions_dict),
            server_type=settings.server_type,
            raw_acl=acl_line,
            metadata=um.server_metadata_for(
                settings.server_type,
                extensions=extensions or None,
            ),
        )
        return r[m.Ldif.Acl].ok(acl_model)


__all__: list[str] = ["FlextLdifACLParsing"]
