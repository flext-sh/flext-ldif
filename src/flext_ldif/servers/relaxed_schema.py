"""Relaxed schema server for lenient LDIF processing.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import re
from typing import override

from flext_ldif import c, m, p, r, t, u
from flext_ldif.servers.relaxed_constants import FlextLdifServersRelaxedConstants
from flext_ldif.servers.rfc import FlextLdifServersRfc


class FlextLdifServersRelaxedSchema(FlextLdifServersRfc.Schema):
    """Relaxed schema server - main class for lenient LDIF processing."""

    def _enhance_schema_item_metadata(
        self,
        schema_item: m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass,
        original_definition: str,
    ) -> m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass:
        if not schema_item.metadata:
            schema_item.metadata = m.Ldif.ServerMetadata.model_validate({
                "server_type": self._get_server_type(),
                "extensions": {
                    "original_format": original_definition.strip(),
                    "schema_source_server": "relaxed",
                },
            })
            return schema_item
        if not schema_item.metadata.extensions:
            schema_item.metadata.extensions = {}
        schema_item.metadata.server_type = self._get_server_type()
        if not schema_item.metadata.extensions.get("original_format"):
            schema_item.metadata.extensions["original_format"] = (
                original_definition.strip()
            )
        schema_item.metadata.extensions["schema_source_server"] = "relaxed"
        return schema_item

    def _enhance_objectclass_metadata(
        self,
        objectclass: m.Ldif.SchemaObjectClass,
        original_definition: str,
    ) -> m.Ldif.SchemaObjectClass:
        """Enhance objectClass metadata to indicate relaxed mode parsing.

        Returns:
            The resulting ``m.Ldif.SchemaObjectClass``.
        """
        result = self._enhance_schema_item_metadata(
            schema_item=objectclass,
            original_definition=original_definition,
        )
        # _enhance_schema_item_metadata preserves the concrete type at runtime
        if isinstance(result, m.Ldif.SchemaObjectClass):
            return result
        return objectclass

    @staticmethod
    def _extract_must_may_from_objectclass(
        oc_definition: str,
    ) -> tuple[t.MutableSequenceOf[str] | None, t.MutableSequenceOf[str] | None]:
        """Extract MUST and MAY fields from objectClass definition.

        Returns:
            The resulting ``tuple[t.MutableSequenceOf[str] | None,
                t.MutableSequenceOf[str] | None]``.
        """
        must = None
        must_match = c.Ldif.SCHEMA_OBJECTCLASS_MUST_RE.search(oc_definition)
        if must_match:
            must = FlextLdifServersRelaxedSchema._split_grouped_field(
                must_match,
                FlextLdifServersRelaxedConstants.SCHEMA_MUST_SEPARATOR,
            )
        may = None
        may_match = c.Ldif.SCHEMA_OBJECTCLASS_MAY_RE.search(oc_definition)
        if may_match:
            may = FlextLdifServersRelaxedSchema._split_grouped_field(
                may_match,
                FlextLdifServersRelaxedConstants.SCHEMA_MAY_SEPARATOR,
            )
        return (must, may)

    @staticmethod
    def _split_grouped_field(
        field_match: re.Match[str],
        separator: str,
    ) -> t.MutableSequenceOf[str] | None:
        """Split a regex-matched schema field into its separator-delimited values.

        Returns:
            The resulting ``t.MutableSequenceOf[str] | None``.
        """
        if field_match.group(1):
            field_value = field_match.group(1).strip()
        elif field_match.group(2):
            field_value = field_match.group(2).strip()
        else:
            field_value = ""
        return [value.strip() for value in field_value.split(separator)]

    def _extract_oid_with_fallback_patterns(self, definition: str) -> str | None:
        """Extract OID using multiple fallback patterns for relaxed mode.

        Returns:
            The resulting ``str | None``.
        """
        oid_result = u.Ldif.extract_oid(definition)
        if oid_result.success:
            oid_val: str = oid_result.value
            return oid_val
        fallback_patterns = (
            FlextLdifServersRelaxedConstants.OID_NUMERIC_WITH_PAREN_RE,
            FlextLdifServersRelaxedConstants.OID_NUMERIC_ANYWHERE_RE,
            FlextLdifServersRelaxedConstants.OID_ALPHANUMERIC_RELAXED_RE,
        )
        for pattern in fallback_patterns:
            oid_match = pattern.search(definition)
            if oid_match:
                return str(oid_match.group(1))
        return None

    def _extract_sup_from_objectclass(self, oc_definition: str) -> str | None:
        """Extract SUP (superior) field from objectClass definition.

        Returns:
            The resulting ``str | None``.
        """
        sup_match = c.Ldif.SCHEMA_OBJECTCLASS_SUP_RE.search(oc_definition)
        if not sup_match:
            return None
        if sup_match.group(1):
            sup_value = sup_match.group(1).strip()
        elif sup_match.group(2):
            sup_value = sup_match.group(2).strip()
        else:
            sup_value = ""
        if FlextLdifServersRelaxedConstants.SCHEMA_MUST_SEPARATOR in sup_value:
            first_part: str = next(
                s.strip()
                for s in sup_value.split(
                    FlextLdifServersRelaxedConstants.SCHEMA_MUST_SEPARATOR,
                )
            )
            return first_part
        sup_value_str: str = sup_value
        return sup_value_str

    @override
    def can_handle_attribute(
        self,
        attr_definition: str | m.Ldif.SchemaAttribute,
    ) -> bool:
        """Accept any attribute definition in relaxed mode.

        Returns:
            The resulting ``bool``.
        """
        if not isinstance(attr_definition, str):
            return True
        return bool(attr_definition.strip())

    @override
    def can_handle_objectclass(
        self,
        oc_definition: str | m.Ldif.SchemaObjectClass,
    ) -> bool:
        """Accept any objectClass definition in relaxed mode.

        Returns:
            The resulting ``bool``.
        """
        if not isinstance(oc_definition, str):
            return True
        return bool(oc_definition.strip())

    @override
    def _parse_attribute(
        self,
        attr_definition: str,
    ) -> p.Result[m.Ldif.SchemaAttribute]:
        """Parse attribute with best-effort approach using RFC baseline.

        Returns:
            The resulting ``p.Result[m.Ldif.SchemaAttribute]``.
        """
        if not attr_definition or not attr_definition.strip():
            return r[m.Ldif.SchemaAttribute].fail(
                "Attribute definition cannot be empty",
            )
        parent_result = super()._parse_attribute(attr_definition)
        if parent_result.success:
            attribute = parent_result.value
            self._enhance_schema_item_metadata(
                schema_item=attribute,
                original_definition=attr_definition,
            )
            return r[m.Ldif.SchemaAttribute].ok(attribute)
        self.logger.debug(
            f"RFC parser failed, using best-effort parsing: {parent_result.error}",
        )
        try:
            return self._parse_relaxed_attribute(attr_definition)
        except c.Ldif.EXC_LDIF_PARSE as e:
            self.logger.debug("Relaxed attribute parse exception: %s", e)
            return r[m.Ldif.SchemaAttribute].fail(
                f"Failed to parse attribute definition: {e}",
                exception=e,
            )

    def _parse_relaxed_attribute(
        self,
        attr_definition: str,
    ) -> p.Result[m.Ldif.SchemaAttribute]:
        """Parse an attribute definition using relaxed fallback rules.

        Returns:
            The resulting ``p.Result[m.Ldif.SchemaAttribute]``.
        """
        oid = self._extract_oid_with_fallback_patterns(attr_definition)
        if not oid:
            return r[m.Ldif.SchemaAttribute].fail(
                "Cannot extract OID from attribute definition",
            )
        name_match = FlextLdifServersRelaxedConstants.SCHEMA_NAME_RE.search(
            attr_definition,
        )
        name = name_match.group(1) if name_match else oid
        metadata = m.Ldif.ServerMetadata.model_validate({
            "server_type": self._get_server_type(),
            "extensions": {
                "original_format": attr_definition.strip(),
                "schema_source_server": "relaxed",
            },
        })
        attr_domain = m.Ldif.SchemaAttribute(
            name=name,
            oid=oid,
            desc=None,
            sup=None,
            equality=None,
            ordering=None,
            substr=None,
            syntax=None,
            length=None,
            usage=None,
            single_value=False,
            collective=False,
            no_user_modification=False,
            immutable=False,
            user_modification=True,
            obsolete=False,
            metadata=metadata,
            x_origin=None,
            x_file_ref=None,
            x_name=None,
            x_alias=None,
            x_oid=None,
        )
        return r[m.Ldif.SchemaAttribute].ok(attr_domain)

    @override
    def _parse_objectclass(
        self,
        oc_definition: str,
    ) -> p.Result[m.Ldif.SchemaObjectClass]:
        """Parse objectClass with best-effort approach using RFC baseline.

        Returns:
            The resulting ``p.Result[m.Ldif.SchemaObjectClass]``.
        """
        if not oc_definition or not oc_definition.strip():
            return r[m.Ldif.SchemaObjectClass].fail(
                "ObjectClass definition cannot be empty",
            )
        parent_result = super()._parse_objectclass(oc_definition)
        if parent_result.success:
            objectclass = parent_result.value
            return r[m.Ldif.SchemaObjectClass].ok(
                self._enhance_objectclass_metadata(objectclass, oc_definition),
            )
        self.logger.debug(
            f"RFC parser failed, using best-effort parsing: {parent_result.error}",
        )
        return self._parse_objectclass_relaxed(oc_definition)

    def _parse_objectclass_relaxed(
        self,
        oc_definition: str,
    ) -> p.Result[m.Ldif.SchemaObjectClass]:
        """Parse objectClass with relaxed/best-effort parsing using utilities.

        Returns:
            The resulting ``p.Result[m.Ldif.SchemaObjectClass]``.
        """
        oid = self._extract_oid_with_fallback_patterns(oc_definition)
        if not oid:
            return r[m.Ldif.SchemaObjectClass].fail(
                "Failed to extract OID from objectClass definition",
            )
        name = u.Ldif.extract_optional_field(
            oc_definition,
            "\\bNAME\\s+(?:'([^']+)'|\\(([^)]+)\\))\\b",
            default=oid,
        )
        desc = u.Ldif.extract_optional_field(
            oc_definition,
            "\\bDESC\\s+'([^']+)'\\b",
        )
        sup = self._extract_sup_from_objectclass(oc_definition)
        kind_match = c.Ldif.SCHEMA_OBJECTCLASS_KIND_RE.search(oc_definition)
        kind = (
            kind_match.group(1).upper()
            if kind_match
            else c.Ldif.SchemaKind.STRUCTURAL.value
        )
        must, may = self._extract_must_may_from_objectclass(oc_definition)
        metadata = m.Ldif.ServerMetadata.model_validate({
            "server_type": self._get_server_type(),
            "extensions": {
                "original_format": oc_definition.strip(),
                "schema_source_server": "relaxed",
            },
        })
        objectclass_name = name or oid
        return r[m.Ldif.SchemaObjectClass].ok(
            m.Ldif.SchemaObjectClass.model_validate({
                "name": objectclass_name,
                "oid": oid,
                "desc": desc,
                "sup": sup,
                "kind": kind,
                "must": must,
                "may": may,
                "metadata": metadata,
            }),
        )

    def _relaxed_original_output(
        self,
        schema_data: m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass,
    ) -> str | None:
        """Return the preserved original-format text for a relaxed schema item.

        Returns:
            The resulting ``str | None``.
        """
        extensions = schema_data.metadata.extensions if schema_data.metadata else None
        source_server = (
            extensions.get("schema_source_server") if extensions is not None else None
        )
        original_format = (
            u.to_str(extensions.get("original_format"))
            if extensions is not None
            else ""
        )
        if source_server == "relaxed" and original_format:
            return original_format
        return None

    @override
    def _write_attribute(self, attr_data: m.Ldif.SchemaAttribute) -> p.Result[str]:
        """Write attribute to RFC format - stringify in relaxed mode.

        Returns:
            The resulting ``p.Result[str]``.
        """
        parent_result = super()._write_attribute(attr_data)
        if parent_result.success:
            return parent_result
        original_output = self._relaxed_original_output(attr_data)
        if original_output is not None:
            return r[str].ok(original_output)
        if not attr_data.oid:
            return r[str].fail("Attribute OID is required for writing")
        attr_name: str
        attr_name = attr_data.name or attr_data.oid
        return r[str].ok(f"( {attr_data.oid} NAME '{attr_name}' )")

    @override
    def _write_objectclass(
        self,
        oc_data: m.Ldif.SchemaObjectClass,
    ) -> p.Result[str]:
        """Write objectClass to RFC format - stringify in relaxed mode.

        Returns:
            The resulting ``p.Result[str]``.
        """
        parent_result = super()._write_objectclass(oc_data)
        if parent_result.success:
            return parent_result
        original_output = self._relaxed_original_output(oc_data)
        if original_output is not None:
            return r[str].ok(original_output)
        if not oc_data.oid:
            return r[str].fail("ObjectClass OID is required for writing")
        oc_name: str
        oc_name = oc_data.name or oc_data.oid
        oc_kind: str
        oc_kind = oc_data.kind or c.Ldif.SchemaKind.STRUCTURAL.value
        return r[str].ok(f"( {oc_data.oid} NAME '{oc_name}' {oc_kind} )")


__all__: list[str] = ["FlextLdifServersRelaxedSchema"]
