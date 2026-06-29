"""Oracle Internet Directory (OID) Servers."""

from __future__ import annotations

from collections.abc import (
    Mapping,
    MutableMapping,
)
from typing import override

from flext_ldif import c, m, p, r, t, u
from flext_ldif.servers._base.schema import FlextLdifServersBaseSchema
from flext_ldif.servers._oid.constants import FlextLdifServersOidConstants
from flext_ldif.servers.rfc import FlextLdifServersRfc

logger = u.fetch_logger(__name__)


class FlextLdifServersOidSchema(FlextLdifServersRfc.Schema):
    """Oracle Internet Directory (OID) schema servers implementation."""

    def __init__(
        self,
        schema_service: p.Ldif.SchemaServer | None = None,
        parent_server: p.Ldif.SchemaServer | None = None,
        **kwargs: t.Ldif.Scalar | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass,
    ) -> None:
        """Initialize OID schema server."""
        filtered_kwargs: t.MutableConfigValueMapping = {
            k: v
            for k, v in kwargs.items()
            if k not in {"_parent_server", "_schema_service"}
            and isinstance(v, (str, float, bool))
        }
        schema_service_typed: p.Ldif.SchemaServer | None = (
            schema_service if schema_service is not None else None
        )
        FlextLdifServersBaseSchema.__init__(
            self,
            _schema_service=schema_service_typed,
            _parent_server=None,
            **filtered_kwargs,
        )
        if parent_server is not None:
            object.__setattr__(self, "_parent_server", parent_server)

    @override
    def extract_schemas_from_ldif(
        self,
        ldif_content: str,
        *,
        validate_dependencies: bool = False,
    ) -> p.Result[
        MutableMapping[
            str,
            t.MutableSequenceOf[m.Ldif.SchemaAttribute]
            | t.MutableSequenceOf[m.Ldif.SchemaObjectClass],
        ]
    ]:
        """Extract and parse all schema definitions from LDIF content."""
        return super().extract_schemas_from_ldif(
            ldif_content,
            validate_dependencies=validate_dependencies,
        )

    def _add_target_metadata(
        self,
        attr_data: m.Ldif.SchemaAttribute,
        target_values: t.MutableOptionalStrMapping,
    ) -> None:
        """Add target metadata to attribute."""
        if not attr_data.metadata:
            return
        if target_values["syntax_oid"]:
            attr_data.metadata.extensions[c.Ldif.SCHEMA_TARGET_SYNTAX_OID] = (
                target_values["syntax_oid"]
            )
        if target_values["name"]:
            attr_data.metadata.extensions[c.Ldif.SCHEMA_TARGET_ATTRIBUTE_NAME] = (
                target_values["name"]
            )
        target_rules: t.MutableStrMapping = {}
        if target_values["equality"]:
            target_rules["equality"] = target_values["equality"]
        if target_values["substr"]:
            target_rules["substr"] = target_values["substr"]
        if target_values["ordering"]:
            target_rules["ordering"] = target_values["ordering"]
        if target_rules:
            setattr(
                attr_data.metadata.extensions,
                c.Ldif.SCHEMA_TARGET_MATCHING_RULES,
                target_rules,
            )
        attr_data.metadata.extensions[c.Ldif.META_TRANSFORMATION_TIMESTAMP] = (
            u.generate_iso_timestamp()
        )

    def _capture_attribute_values(
        self,
        attr_data: m.Ldif.SchemaAttribute,
    ) -> t.MutableOptionalStrMapping:
        """Capture attribute values for metadata tracking."""
        return {
            "syntax_oid": attr_data.syntax or None,
            "equality": attr_data.equality,
            "substr": attr_data.substr,
            "ordering": attr_data.ordering,
            "name": attr_data.name,
        }

    @override
    def _hook_post_parse_attribute(
        self,
        attr: m.Ldif.SchemaAttribute,
    ) -> p.Result[m.Ldif.SchemaAttribute]:
        """Hook: Transform parsed attribute using OID-specific normalizations."""
        try:
            return r[m.Ldif.SchemaAttribute].ok(
                self._normalize_oid_attribute(attr),
            )
        except c.Ldif.EXC_LDIF_PARSE as e:
            logger.exception("OID post-parse attribute hook failed")
            return r[m.Ldif.SchemaAttribute].fail_op("OID post-parse attribute hook", e)

    def _normalize_oid_attribute(
        self,
        attr: m.Ldif.SchemaAttribute,
    ) -> m.Ldif.SchemaAttribute:
        """Normalize OID-specific schema attribute fields."""
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

    @override
    def _hook_post_parse_objectclass(
        self,
        oc: m.Ldif.SchemaObjectClass,
    ) -> p.Result[m.Ldif.SchemaObjectClass]:
        """Hook: Transform parsed objectClass using OID-specific normalizations."""
        try:
            return r[m.Ldif.SchemaObjectClass].ok(
                self._normalize_oid_objectclass(oc),
            )
        except c.Ldif.EXC_LDIF_PARSE as e:
            logger.exception("OID post-parse objectclass hook failed")
            return r[m.Ldif.SchemaObjectClass].fail_op(
                "OID post-parse objectclass hook", e
            )

    def _normalize_oid_objectclass(
        self,
        oc: m.Ldif.SchemaObjectClass,
    ) -> m.Ldif.SchemaObjectClass:
        """Normalize OID-specific objectClass fields."""
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
            updated_sup = self._normalize_sup_from_original_format(
                original_format_str,
            )
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

    def _normalize_attribute_names(
        self,
        attr_list: t.MutableSequenceOf[str] | None,
    ) -> t.MutableSequenceOf[str] | None:
        """Normalize attribute names using OID case mappings."""
        if not attr_list:
            return attr_list
        case_map = FlextLdifServersOidConstants.ATTR_NAME_CASE_MAP
        return [case_map.get(attr_name.lower(), attr_name) for attr_name in attr_list]

    def _normalize_auxiliary_typo(
        self,
        oc_data: m.Ldif.SchemaObjectClass,
        original_format_str: str,
    ) -> str | None:
        """Normalize AUXILLARY typo to AUXILIARY."""
        kind = getattr(oc_data, "kind", None)
        match (kind, original_format_str):
            case [k, _] if k and k.upper() == "AUXILLARY":
                logger.debug(
                    "OID→RFC transform: AUXILLARY → AUXILIARY",
                    objectclass_name=oc_data.name,
                    objectclass_oid=oc_data.oid,
                    original_kind=k,
                    normalized_kind="AUXILIARY",
                )
                return "AUXILIARY"
            case [_, fmt] if fmt and "AUXILLARY" in fmt:
                logger.debug(
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

    def _normalize_sup_from_model(self, oc_data: m.Ldif.SchemaObjectClass) -> str | (
        t.MutableSequenceOf[str] | None
    ):
        """Normalize SUP from objectClass model."""
        if not oc_data.sup:
            return None
        sup_normalize_set = {"( top )", "(top)", "'top'", '"top"'}
        match oc_data.sup:
            case sup_str if (sup_clean := str(sup_str).strip()) in sup_normalize_set:
                logger.debug(
                    "OID→RFC transform: SUP normalization",
                    objectclass_name=oc_data.name,
                    objectclass_oid=oc_data.oid,
                    original_sup=sup_clean,
                    normalized_sup="top",
                )
                return "top"
            case [sup_item] if (sup_clean := sup_item.strip()) in sup_normalize_set:
                logger.debug(
                    "OID→RFC transform: SUP normalization (list)",
                    objectclass_name=oc_data.name,
                    objectclass_oid=oc_data.oid,
                    original_sup=sup_clean,
                    normalized_sup="top",
                )
                return "top"
            case _:
                return None

    def _normalize_sup_from_original_format(
        self,
        original_format_str: str,
    ) -> str | None:
        """Normalize SUP from original_format string."""
        sup_patterns = ("SUP 'top'", "SUP ( top )", "SUP (top)")
        match original_format_str:
            case s if any(pattern in s for pattern in sup_patterns):
                logger.debug(
                    "OID→RFC transform: SUP normalization (from original_format)",
                    original_format_preview=s[
                        : FlextLdifServersOidConstants.MAX_LOG_LINE_LENGTH
                    ],
                )
                return "top"
            case _:
                return None

    @override
    def _parse_attribute(
        self, attr_definition: str
    ) -> p.Result[m.Ldif.SchemaAttribute]:
        """Parse Oracle OID attribute definition (Phase 1: Normalization)."""
        try:
            return self._parse_oid_attribute(attr_definition)
        except c.Ldif.EXC_LDIF_PARSE as e:
            logger.exception("OID attribute parsing failed")
            return r[m.Ldif.SchemaAttribute].fail_op("OID attribute parsing", e)

    def _parse_oid_attribute(
        self,
        attr_definition: str,
    ) -> p.Result[m.Ldif.SchemaAttribute]:
        """Parse OID attribute and attach OID metadata."""
        result = super()._parse_attribute(attr_definition)
        if not result.success:
            return result
        attr_data = result.value
        target_values = self._capture_attribute_values(attr_data)
        if not attr_data.metadata:
            attr_data.metadata = self.create_metadata(attr_definition.strip())
        if attr_data.metadata:
            attr_data.metadata.extensions[c.Ldif.SCHEMA_ORIGINAL_FORMAT] = (
                attr_definition.strip()
            )
            attr_data.metadata.extensions[c.Ldif.SCHEMA_ORIGINAL_STRING_COMPLETE] = (
                attr_definition
            )
            attr_data.metadata.extensions[c.Ldif.SCHEMA_SOURCE_SERVER] = "oid"
            u.Ldif.preserve_schema_formatting(attr_data.metadata, attr_definition)
            self._add_target_metadata(attr_data, target_values)
        return r[m.Ldif.SchemaAttribute].ok(attr_data)

    @override
    def _parse_objectclass(
        self, oc_definition: str
    ) -> p.Result[m.Ldif.SchemaObjectClass]:
        """Parse Oracle OID objectClass definition."""
        try:
            return self._parse_oid_objectclass(oc_definition)
        except c.Ldif.EXC_LDIF_PARSE as e:
            logger.exception("OID objectClass parsing failed")
            return r[m.Ldif.SchemaObjectClass].fail_op("OID objectClass parsing", e)

    def _parse_oid_objectclass(
        self,
        oc_definition: str,
    ) -> p.Result[m.Ldif.SchemaObjectClass]:
        """Parse OID objectClass and attach OID metadata."""
        result = super()._parse_objectclass(oc_definition)
        if not result.success:
            return result
        oc_data = result.value
        key = c.Ldif.SCHEMA_ORIGINAL_FORMAT
        if not oc_data.metadata:
            oc_data.metadata = self.create_metadata(oc_definition.strip())
        elif not oc_data.metadata.extensions.get(key):
            oc_data.metadata.extensions[key] = oc_definition.strip()
        if oc_data.metadata:
            oc_data.metadata.extensions[c.Ldif.META_TRANSFORMATION_TIMESTAMP] = (
                u.generate_iso_timestamp()
            )
        return r[m.Ldif.SchemaObjectClass].ok(oc_data)

    @override
    def _transform_attribute_for_write(
        self,
        attr_data: m.Ldif.SchemaAttribute,
    ) -> m.Ldif.SchemaAttribute:
        """Apply OID-specific attribute transformations before writing."""
        fixed_name = u.Ldif.normalize_name(attr_data.name) or attr_data.name
        fixed_equality = attr_data.equality
        fixed_substr = attr_data.substr
        original_substr = fixed_substr
        fixed_substr = u.Ldif.replace_invalid_substr_rule(
            fixed_substr,
            FlextLdifServersOidConstants.INVALID_SUBSTR_RULES,
        )
        if fixed_substr != original_substr:
            logger.debug(
                "Replaced invalid SUBSTR rule",
                attribute_name=attr_data.name,
                attribute_oid=attr_data.oid,
                original_substr=original_substr or "",
                replacement_substr=fixed_substr or "",
            )
        is_boolean = u.Ldif.is_boolean_attribute(
            fixed_name,
            set(FlextLdifServersOidConstants.BOOLEAN_ATTRIBUTES),
        )
        if is_boolean:
            logger.debug(
                "Identified boolean attribute",
                attribute_name=fixed_name,
                attribute_oid=attr_data.oid,
            )
        x_origin_value = attr_data.x_origin
        return m.Ldif.SchemaAttribute(
            oid=attr_data.oid,
            name=fixed_name,
            desc=attr_data.desc,
            sup=attr_data.sup,
            equality=fixed_equality,
            ordering=attr_data.ordering,
            substr=fixed_substr,
            syntax=attr_data.syntax,
            length=attr_data.length,
            usage=attr_data.usage,
            single_value=attr_data.single_value,
            no_user_modification=attr_data.no_user_modification,
            metadata=attr_data.metadata,
            x_origin=x_origin_value,
            x_file_ref=attr_data.x_file_ref,
            x_name=attr_data.x_name,
            x_alias=attr_data.x_alias,
            x_oid=attr_data.x_oid,
        )

    def _transform_case_ignore_substrings(
        self,
        attr_data: m.Ldif.SchemaAttribute,
    ) -> m.Ldif.SchemaAttribute:
        """Transform caseIgnoreSubstringsMatch from EQUALITY to SUBSTR."""
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
            logger.debug(
                "Moved caseIgnoreSubstringsMatch from EQUALITY to SUBSTR",
                attribute_name=attr_data.name,
                original_equality=attr_data.equality or "",
                normalized_substr=normalized_substr or "",
            )
            original_format = (
                attr_data.metadata.extensions.original_format
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

    @override
    def _write_attribute(self, attr_data: m.Ldif.SchemaAttribute) -> p.Result[str]:
        """Write Oracle OID attribute definition (Phase 2: Denormalization)."""
        attr_copy = attr_data.model_copy(deep=True)
        source_rules: t.JsonPayload | None = None
        source_syntax: t.JsonPayload | None = None
        if attr_copy.metadata and attr_copy.metadata.extensions:
            source_rules = attr_copy.metadata.extensions.get(
                c.Ldif.SCHEMA_SOURCE_MATCHING_RULES,
            )
            source_syntax = attr_copy.metadata.extensions.get(
                c.Ldif.SCHEMA_SOURCE_SYNTAX_OID,
            )
        if isinstance(source_rules, Mapping):
            equality_raw = source_rules.get("equality", attr_copy.equality)
            substr_raw = source_rules.get("substr", attr_copy.substr)
            ordering_raw = source_rules.get("ordering", attr_copy.ordering)
            oid_equality = (
                equality_raw if isinstance(equality_raw, str) else attr_copy.equality
            )
            oid_substr = substr_raw if isinstance(substr_raw, str) else attr_copy.substr
            oid_ordering = (
                ordering_raw if isinstance(ordering_raw, str) else attr_copy.ordering
            )
        else:
            oid_equality, oid_substr = u.Ldif.normalize_matching_rules(
                attr_copy.equality,
                attr_copy.substr,
                replacements=FlextLdifServersOidConstants.MATCHING_RULE_RFC_TO_OID,
                normalized_substr_values=FlextLdifServersOidConstants.MATCHING_RULE_RFC_TO_OID,
            )
            oid_ordering = attr_copy.ordering
            if attr_copy.ordering:
                mapped = FlextLdifServersOidConstants.MATCHING_RULE_RFC_TO_OID.get(
                    attr_copy.ordering,
                )
                if mapped:
                    oid_ordering = mapped
        oid_syntax = (
            source_syntax
            if isinstance(source_syntax, str)
            else (attr_copy.syntax or None)
        )
        oid_metadata = attr_copy.metadata
        if attr_copy.metadata and attr_copy.metadata.extensions:
            keys_to_remove = {c.Ldif.SCHEMA_ORIGINAL_FORMAT}
            new_extensions = {
                k: v
                for k, v in attr_copy.metadata.extensions.items()
                if k not in keys_to_remove
            }
            oid_metadata = attr_copy.metadata.model_copy(
                update={
                    "extensions": m.Ldif.DynamicMetadata.from_dict(
                        new_extensions,
                    ),
                },
            )
        attr_copy = attr_copy.model_copy(
            update={
                "equality": oid_equality,
                "substr": oid_substr,
                "ordering": oid_ordering,
                "syntax": oid_syntax,
                "metadata": oid_metadata,
            },
        )
        return super()._write_attribute(attr_copy)


"Oracle Internet Directory (OID) Servers.\n\nCopyright (c) 2025 FLEXT Team. All rights reserved.\nSPDX-License-Identifier: MIT\n\nImplements Oracle OID-specific extensions as servers on top of RFC-compliant\nbase parsers. This wraps existing OID parser logic as composable servers.\n\nOID-specific features:\n- Oracle OID attribute types (2.16.840.1.113894.* namespace)\n- Oracle orclaci and orclentrylevelaci ACLs\n- Oracle-specific schema attributes\n- Oracle operational attributes\n"
