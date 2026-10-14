"""Relaxed schema server for lenient LDIF processing.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import re
from typing import override

from flext_ldif import c, m, p, r, t, u
from flext_ldif.servers._relaxed import FlextLdifServersRelaxedConstants
from flext_ldif.servers._rfc.schema import FlextLdifServersRfcSchema


class FlextLdifServersRelaxedSchema(FlextLdifServersRfcSchema):
    """Relaxed schema server - main class for lenient LDIF processing."""

    def _enhance_schema_item_metadata(
        self,
        schema_item: m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass,
        original_definition: str,
    ) -> m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass:
        """Attach relaxed-mode metadata to a parsed schema item.

        Args:
            schema_item: Attribute or objectClass that was parsed.
            original_definition: Raw definition text to preserve.

        Returns:
            The schema item carrying relaxed-source metadata.

        """
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
        """Attach relaxed-mode metadata to a parsed objectClass.

        Args:
            objectclass: ObjectClass parsed from the definition.
            original_definition: Raw definition text to preserve.

        Returns:
            The objectClass carrying relaxed-source metadata.

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
        """Extract the MUST and MAY field lists from an objectClass definition.

        Args:
            oc_definition: Raw objectClass definition text.

        Returns:
            Pair of field-name lists for MUST and MAY; either element is None
            when the corresponding clause is absent.

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
        """Split a regex-matched schema field into separator-delimited values.

        Args:
            field_match: Match whose first or second group holds the value.
            separator: Delimiter between individual values.

        Returns:
            Stripped, trimmed field values, or None when no group captured.

        """
        if field_match.group(1):
            field_value = field_match.group(1).strip()
        elif field_match.group(2):
            field_value = field_match.group(2).strip()
        else:
            field_value = ""
        return [value.strip() for value in field_value.split(separator)]

    @staticmethod
    def _extract_oid_with_fallback_patterns(definition: str) -> str | None:
        """Extract the OID from a definition using relaxed fallback patterns.

        Tries the standard OID extraction first, then progressively lenient
        numeric and alphanumeric patterns.

        Args:
            definition: Raw schema definition text.

        Returns:
            The extracted OID, or None when no pattern matches.

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

    @staticmethod
    def _extract_sup_from_objectclass(oc_definition: str) -> str | None:
        """Extract the SUP (superior) class name from an objectClass definition.

        Args:
            oc_definition: Raw objectClass definition text.

        Returns:
            The superior class name, or None when the clause is absent.

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
        """Accept any non-empty attribute definition in relaxed mode.

        Args:
            attr_definition: Raw definition text or a parsed attribute.

        Returns:
            True when the definition can be handled by this parser.

        """
        if not isinstance(attr_definition, str):
            return True
        return bool(attr_definition.strip())

    @override
    def can_handle_objectclass(
        self,
        oc_definition: str | m.Ldif.SchemaObjectClass,
    ) -> bool:
        """Accept any non-empty objectClass definition in relaxed mode.

        Args:
            oc_definition: Raw definition text or a parsed objectClass.

        Returns:
            True when the definition can be handled by this parser.

        """
        if not isinstance(oc_definition, str):
            return True
        return bool(oc_definition.strip())

    @override
    def _parse_attribute(
        self,
        attr_definition: str,
    ) -> p.Result[m.Ldif.SchemaAttribute]:
        """Parse an attribute definition with best-effort relaxed handling.

        Delegates to the RFC baseline first; on failure, falls back to lenient
        extraction of OID and name.

        Args:
            attr_definition: Raw attribute definition text.

        Returns:
            Result carrying the parsed attribute, or a failure.

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
            "RFC parser failed, using best-effort parsing: %s",
            parent_result.error,
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

        Builds a minimal attribute from the extracted OID and NAME clause when
        strict parsing is not possible.

        Args:
            attr_definition: Raw attribute definition text.

        Returns:
            Result carrying the minimally parsed attribute, or a failure.

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
        """Parse an objectClass definition with best-effort relaxed handling.

        Delegates to the RFC baseline first; on failure, falls back to lenient
        extraction of the objectClass clauses.

        Args:
            oc_definition: Raw objectClass definition text.

        Returns:
            Result carrying the parsed objectClass, or a failure.

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
            "RFC parser failed, using best-effort parsing: %s",
            parent_result.error,
        )
        return self._parse_objectclass_relaxed(oc_definition)

    def _parse_objectclass_relaxed(
        self,
        oc_definition: str,
    ) -> p.Result[m.Ldif.SchemaObjectClass]:
        """Parse an objectClass definition using relaxed fallback rules.

        Builds a minimal objectClass from the extracted OID, NAME, DESC, SUP,
        kind, MUST, and MAY clauses.

        Args:
            oc_definition: Raw objectClass definition text.

        Returns:
            Result carrying the minimally parsed objectClass, or a failure.

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

    @staticmethod
    def _relaxed_original_output(
        schema_data: m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass,
    ) -> str | None:
        """Return the preserved original-format text for a relaxed schema item.

        Args:
            schema_data: Attribute or objectClass with relaxed metadata.

        Returns:
            The preserved original definition text, or None when the item was
            not parsed in relaxed mode.

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
        """Write an attribute definition, preserving its original text.

        Delegates to the RFC baseline first; on failure, emits the preserved
        original-format text or a minimal synthetic definition.

        Args:
            attr_data: Parsed attribute to serialize.

        Returns:
            Result carrying the attribute definition string, or a failure.

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
        """Write an objectClass definition, preserving its original text.

        Delegates to the RFC baseline first; on failure, emits the preserved
        original-format text or a minimal synthetic definition.

        Args:
            oc_data: Parsed objectClass to serialize.

        Returns:
            Result carrying the objectClass definition string, or a failure.

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
