"""Oracle Internet Directory (OID) Servers.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping, MutableMapping
from typing import ClassVar, override

from flext_ldif import c, m, p, r, t, u
from flext_ldif.servers._oid.schema_normalize import (
    FlextLdifServersOidSchemaNormalizeMixin,
)
from flext_ldif.servers._oid.server_constants import FlextLdifServersOidConstants
from flext_ldif.servers.rfc import FlextLdifServersRfc


class FlextLdifServersOidSchema(
    FlextLdifServersOidSchemaNormalizeMixin,
    FlextLdifServersRfc.Schema,
):
    """Oracle Internet Directory (OID) schema servers implementation."""

    _module_logger: ClassVar[p.Logger] = u.fetch_logger(__name__)

    def __init__(
        self,
        schema_service: p.Ldif.SchemaServer | None = None,
        parent_server: p.Ldif.SchemaServer | None = None,
        **kwargs: t.Ldif.Scalar | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass,
    ) -> None:
        """Initialize OID schema server."""
        self._init_base_schema(
            schema_service,
            parent_server,
            frozenset({"_parent_server", "_schema_service"}),
            **kwargs,
        )

    @staticmethod
    def _add_target_metadata(
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
        target_rules: t.JsonDict = {}
        if target_values["equality"]:
            target_rules["equality"] = target_values["equality"]
        if target_values["substr"]:
            target_rules["substr"] = target_values["substr"]
        if target_values["ordering"]:
            target_rules["ordering"] = target_values["ordering"]
        if target_rules:
            # mro-wgwh.5 (agent: kimi-coder) — extensions is a plain mapping now:
            # subscript assignment instead of DynamicMetadata setattr.
            attr_data.metadata.extensions[c.Ldif.SCHEMA_TARGET_MATCHING_RULES] = (
                target_rules
            )
        attr_data.metadata.extensions[c.Ldif.META_TRANSFORMATION_TIMESTAMP] = (
            u.generate_iso_timestamp()
        )

    @staticmethod
    def _capture_attribute_values(
        attr_data: m.Ldif.SchemaAttribute,
    ) -> t.MutableOptionalStrMapping:
        """Capture attribute values for metadata tracking.

        Returns:
            The resulting ``t.MutableOptionalStrMapping``.
        """
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
        """Transform parsed attribute using OID-specific normalizations.

        Returns:
            The resulting ``p.Result[m.Ldif.SchemaAttribute]``.
        """
        try:
            return r[m.Ldif.SchemaAttribute].ok(self._normalize_oid_attribute(attr))
        except c.Ldif.EXC_LDIF_PARSE as e:
            FlextLdifServersOidSchema._module_logger.exception(
                "OID post-parse attribute hook failed",
            )
            return r[m.Ldif.SchemaAttribute].fail_op("OID post-parse attribute hook", e)


    @override
    def _hook_post_parse_objectclass(
        self,
        oc: m.Ldif.SchemaObjectClass,
    ) -> p.Result[m.Ldif.SchemaObjectClass]:
        """Transform parsed objectClass using OID-specific normalizations.

        Returns:
            The resulting ``p.Result[m.Ldif.SchemaObjectClass]``.
        """
        try:
            return r[m.Ldif.SchemaObjectClass].ok(self._normalize_oid_objectclass(oc))
        except c.Ldif.EXC_LDIF_PARSE as e:
            FlextLdifServersOidSchema._module_logger.exception(
                "OID post-parse objectclass hook failed",
            )
            return r[m.Ldif.SchemaObjectClass].fail_op(
                "OID post-parse objectclass hook",
                e,
            )






    @override
    def _parse_attribute(
        self,
        attr_definition: str,
    ) -> p.Result[m.Ldif.SchemaAttribute]:
        """Parse Oracle OID attribute definition (Phase 1: Normalization).

        Returns:
            The resulting ``p.Result[m.Ldif.SchemaAttribute]``.
        """
        try:
            return self._parse_oid_attribute(attr_definition)
        except c.Ldif.EXC_LDIF_PARSE as e:
            FlextLdifServersOidSchema._module_logger.exception(
                "OID attribute parsing failed",
            )
            return r[m.Ldif.SchemaAttribute].fail_op("OID attribute parsing", e)

    def _parse_oid_attribute(
        self,
        attr_definition: str,
    ) -> p.Result[m.Ldif.SchemaAttribute]:
        """Parse OID attribute and attach OID metadata.

        Returns:
            The resulting ``p.Result[m.Ldif.SchemaAttribute]``.
        """
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
        self,
        oc_definition: str,
    ) -> p.Result[m.Ldif.SchemaObjectClass]:
        """Parse Oracle OID objectClass definition.

        Returns:
            The resulting ``p.Result[m.Ldif.SchemaObjectClass]``.
        """
        try:
            return self._parse_oid_objectclass(oc_definition)
        except c.Ldif.EXC_LDIF_PARSE as e:
            FlextLdifServersOidSchema._module_logger.exception(
                "OID objectClass parsing failed",
            )
            return r[m.Ldif.SchemaObjectClass].fail_op("OID objectClass parsing", e)

    def _parse_oid_objectclass(
        self,
        oc_definition: str,
    ) -> p.Result[m.Ldif.SchemaObjectClass]:
        """Parse OID objectClass and attach OID metadata.

        Returns:
            The resulting ``p.Result[m.Ldif.SchemaObjectClass]``.
        """
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
        """Apply OID-specific attribute transformations before writing.

        Returns:
            The resulting ``m.Ldif.SchemaAttribute``.
        """
        fixed_name = u.Ldif.normalize_name(attr_data.name) or attr_data.name
        fixed_equality = attr_data.equality
        fixed_substr = attr_data.substr
        original_substr = fixed_substr
        fixed_substr = u.Ldif.replace_invalid_substr_rule(
            fixed_substr,
            FlextLdifServersOidConstants.INVALID_SUBSTR_RULES,
        )
        if fixed_substr != original_substr:
            FlextLdifServersOidSchema._module_logger.debug(
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
            FlextLdifServersOidSchema._module_logger.debug(
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


    @override
    def _write_attribute(self, attr_data: m.Ldif.SchemaAttribute) -> p.Result[str]:
        """Write Oracle OID attribute definition (Phase 2: Denormalization).

        Returns:
            The resulting ``p.Result[str]``.
        """
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
            new_extensions: t.MutableJsonMapping = {
                k: v
                for k, v in attr_copy.metadata.extensions.items()
                if k not in keys_to_remove
            }
            oid_metadata = attr_copy.metadata.model_copy(
                update={"extensions": new_extensions},
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
