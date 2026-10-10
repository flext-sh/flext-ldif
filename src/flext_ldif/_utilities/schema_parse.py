"""Schema parsing helpers for FLEXT-LDIF.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from flext_cli import u

from flext_core import r
from flext_ldif import FlextLdifModels, c, p, t
from flext_ldif._utilities import (
    FlextLdifUtilitiesOID as uo,
    FlextLdifUtilitiesParser as up,
    FlextLdifUtilitiesSchemaExtract as se,
)

if TYPE_CHECKING:
    from collections.abc import Callable, MutableMapping


class FlextLdifUtilitiesSchemaParse:
    """Parse RFC 4512 schema definitions from strings and LDIF content."""

    _module_logger: ClassVar[p.Logger] = u.fetch_logger(__name__)

    @staticmethod
    def _convert_metadata_extensions(
        extensions_raw: t.Ldif.MutableMetadataMapping,
    ) -> t.Ldif.MutableMetadataMapping:
        converted: t.Ldif.MutableMetadataMapping = {}
        for key, raw_value in extensions_raw.items():
            converted[key] = u.normalize_to_metadata(raw_value)
        return converted

    @staticmethod
    def _validate_attribute_syntax(
        syntax: str | None,
    ) -> t.Ldif.MutableMetadataMapping | None:
        """Validate syntax OID and return validation result.

        Returns:
            The resulting ``t.Ldif.MutableMetadataMapping | None``.
        """
        if not syntax or not syntax.strip():
            return None
        syntax_extensions: MutableMapping[
            str,
            bool | t.MutableSequenceOf[str] | str | None,
        ] = {}
        validate_result = uo.validate_format(syntax)
        if validate_result.failure:
            syntax_extensions[c.Ldif.SYNTAX_VALIDATION_ERROR] = (
                f"Syntax OID validation failed: {validate_result.error}"
            )
        elif not validate_result.value:
            syntax_extensions[c.Ldif.SYNTAX_VALIDATION_ERROR] = (
                f"Invalid syntax OID format: {syntax} "
                f"(must be numeric dot-separated format)"
            )
        syntax_extensions[c.Ldif.SYNTAX_OID_VALID] = (
            c.Ldif.SYNTAX_VALIDATION_ERROR not in syntax_extensions
        )
        result_dict: t.Ldif.MutableMetadataMapping = {}
        for key, val in syntax_extensions.items():
            if val is not None:
                result_dict[key] = t.Cli.JSON_VALUE_ADAPTER.validate_python(val)
        return result_dict

    @staticmethod
    def build_metadata(
        definition: str,
        additional_extensions: t.Ldif.MutableMetadataMapping | None = None,
    ) -> t.Ldif.MutableMetadataMapping:
        """Build metadata extensions dictionary for schema definitions.

        Returns:
            The resulting ``t.Ldif.MutableMetadataMapping``.
        """
        extensions_raw = up.extract_extensions(definition)
        extensions: t.Ldif.MutableMetadataMapping = {}
        for key, val in extensions_raw.items():
            val_payload: t.JsonValueList = list(val)
            extensions[key] = val_payload
        extensions[c.Ldif.ORIGINAL_FORMAT] = definition.strip()
        if additional_extensions:
            extensions.update(additional_extensions)
        return extensions

    @staticmethod
    def _detect_schema_kind_from_text(definition_lower: str) -> c.Ldif.SchemaItemKind:
        """Classify a string definition via RFC 4512 keyword patterns.

        Returns:
            "attribute" or "objectclass".

        """
        objectclass_only_keywords = [
            " structural",
            " auxiliary",
            " abstract",
            " must (",
            " may (",
        ]
        attribute_only_keywords = [
            " equality ",
            " substr ",
            " ordering ",
            " syntax ",
            " usage ",
            " single-value",
            " no-user-modification",
        ]
        if any(keyword in definition_lower for keyword in objectclass_only_keywords):
            return c.Ldif.SchemaItemKind.OBJECTCLASS
        if any(keyword in definition_lower for keyword in attribute_only_keywords):
            return c.Ldif.SchemaItemKind.ATTRIBUTE
        if "objectclass" in definition_lower or "oclass" in definition_lower:
            return c.Ldif.SchemaItemKind.OBJECTCLASS
        return c.Ldif.SchemaItemKind.ATTRIBUTE

    @staticmethod
    def detect_schema_type(
        definition: str
        | FlextLdifModels.Ldif.SchemaAttribute
        | FlextLdifModels.Ldif.SchemaObjectClass,
    ) -> c.Ldif.SchemaItemKind:
        """Detect schema type (attribute or objectclass) for automatic routing.

        Generic utility used by multiple server implementations to automatically
        classify schema definitions. Detects based on model type first, then
        uses RFC 4512 keyword patterns for string detection.

        Args:
            definition: Schema definition string or model.

        Returns:
            "attribute" or "objectclass".

        """
        if isinstance(definition, FlextLdifModels.Ldif.SchemaAttribute):
            return c.Ldif.SchemaItemKind.ATTRIBUTE
        if isinstance(definition, FlextLdifModels.Ldif.SchemaObjectClass):
            return c.Ldif.SchemaItemKind.OBJECTCLASS
        return FlextLdifUtilitiesSchemaParse._detect_schema_kind_from_text(
            definition.lower(),
        )

    @staticmethod
    def extract_attributes_from_lines(
        ldif_content: str,
        parse_callback: Callable[[str], p.Result[FlextLdifModels.Ldif.SchemaAttribute]],
    ) -> t.MutableSequenceOf[FlextLdifModels.Ldif.SchemaAttribute]:
        """Extract and parse all attributeTypes from LDIF content lines.

        Returns:
            The resulting ``t.MutableSequenceOf[FlextLdifModels.Ldif.SchemaAttribute]``.
        """
        return se.extract_schema_items_from_lines(
            ldif_content,
            parse_callback,
            "attributetypes:",
            FlextLdifModels.Ldif.SchemaAttribute,
        )

    @staticmethod
    def extract_objectclasses_from_lines(
        ldif_content: str,
        parse_callback: Callable[
            [str],
            p.Result[FlextLdifModels.Ldif.SchemaObjectClass],
        ],
    ) -> t.MutableSequenceOf[FlextLdifModels.Ldif.SchemaObjectClass]:
        """Extract and parse all objectClasses from LDIF content lines.

        Returns:
            The resulting
                ``t.MutableSequenceOf[FlextLdifModels.Ldif.SchemaObjectClass]``.
        """
        return se.extract_schema_items_from_lines(
            ldif_content,
            parse_callback,
            "objectclasses:",
            FlextLdifModels.Ldif.SchemaObjectClass,
        )

    @staticmethod
    def parse_attribute(
        attr_definition: str,
        *,
        validate_syntax: bool = True,
    ) -> p.Result[t.Ldif.MutableMetadataMapping]:
        """Parse RFC 4512 attribute definition into structured data.

        Returns:
            The resulting ``p.Result[t.Ldif.MutableMetadataMapping]``.
        """
        basic_fields = se.extract_schema_basic_fields(
            definition=attr_definition,
            definition_label=c.Ldif.SchemaItemKind.ATTRIBUTE.value,
        )
        if basic_fields.failure:
            return r[t.Ldif.MutableMetadataMapping].fail(basic_fields.error)
        oid, name, desc = basic_fields.value
        syntax, fields = FlextLdifUtilitiesSchemaParse._attribute_syntax_fields(
            attr_definition,
        )
        syntax_validation, syntax_validation_converted = (
            FlextLdifUtilitiesSchemaParse._validated_syntax_extensions(
                syntax,
                validate=validate_syntax,
            )
        )
        extensions_raw = FlextLdifUtilitiesSchemaParse.build_metadata(
            attr_definition,
            additional_extensions=syntax_validation,
        )
        extensions_converted = (
            FlextLdifUtilitiesSchemaParse._convert_metadata_extensions(extensions_raw)
        )
        payload = {
            "oid": oid,
            "name": name,
            "desc": desc,
            **fields,
            "metadata_extensions": extensions_converted,
            "syntax_validation": syntax_validation_converted,
        }
        parsed_dict = dict(t.Cli.JSON_MAPPING_ADAPTER.validate_python(payload))
        return r[t.Ldif.MutableMetadataMapping].ok(parsed_dict)

    @staticmethod
    def _attribute_syntax_fields(
        attr_definition: str,
    ) -> tuple[str | None, t.Ldif.MutableMetadataMapping]:
        """Extract the syntax, matching-rule, and flag fields of one attribute.

        Returns:
            The resulting ``tuple[str, t.Ldif.MutableMetadataMapping]``.
        """
        syntax, length = se.extract_attribute_syntax(attr_definition)
        equality, substr, ordering = se.extract_attribute_matching_rules(
            attr_definition,
        )
        single_value, no_user_modification = se.extract_attribute_flags(attr_definition)
        sup, usage = se.extract_attribute_sup_usage(attr_definition)
        return syntax, {
            "syntax": syntax,
            "length": length,
            "equality": equality,
            "ordering": ordering,
            "substr": substr,
            "single_value": single_value,
            "no_user_modification": no_user_modification,
            "sup": sup,
            "usage": usage,
        }

    @staticmethod
    def _validated_syntax_extensions(
        syntax: str | None,
        *,
        validate: bool,
    ) -> tuple[
        t.Ldif.MutableMetadataMapping | None,
        t.Ldif.MutableMetadataMapping | None,
    ]:
        """Validate one attribute syntax and convert its metadata extensions.

        Returns:
            The resulting ``tuple[t.Ldif.MutableMetadataMapping | None,
            t.Ldif.MutableMetadataMapping | None]``.
        """
        if not validate:
            return None, None
        validation = FlextLdifUtilitiesSchemaParse._validate_attribute_syntax(syntax)
        return validation, (
            FlextLdifUtilitiesSchemaParse._convert_metadata_extensions(validation)
            if validation
            else None
        )

    @staticmethod
    def parse_objectclass(oc_definition: str) -> t.Ldif.MutableMetadataMapping:
        """Parse RFC 4512 objectClass definition into structured data.

        Returns:
            The resulting ``t.Ldif.MutableMetadataMapping``.

        Raises:
            ValueError: If ``basic_fields_result.failure``.
        """
        basic_fields_result = se.extract_schema_basic_fields(
            definition=oc_definition,
            definition_label=c.Ldif.SchemaItemKind.OBJECTCLASS.value,
        )
        if basic_fields_result.failure:
            msg = basic_fields_result.error or "RFC objectClass parsing failed"
            raise ValueError(msg)
        basic_fields_value = basic_fields_result.value
        oid = basic_fields_value[0]
        name = basic_fields_value[1]
        desc = basic_fields_value[2]
        sup = se.extract_objectclass_sup(oc_definition)
        kind = se.extract_objectclass_kind(oc_definition)
        must, may = se.extract_objectclass_must_may(oc_definition)
        extensions_raw = FlextLdifUtilitiesSchemaParse.build_metadata(oc_definition)
        extensions_converted = (
            FlextLdifUtilitiesSchemaParse._convert_metadata_extensions(extensions_raw)
        )
        return dict(
            t.Cli.JSON_MAPPING_ADAPTER.validate_python({
                "oid": oid,
                "name": name,
                "desc": desc,
                "sup": sup,
                "kind": kind,
                "must": must,
                "may": may,
                "metadata_extensions": extensions_converted,
            }),
        )


__all__: list[str] = ["FlextLdifUtilitiesSchemaParse"]
