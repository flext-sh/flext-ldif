"""Schema parsing helpers for FLEXT-LDIF."""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from flext_cli import u as core_u
from flext_ldif import FlextLdifModels as m, c, p, r, t
from flext_ldif._utilities.oid import FlextLdifUtilitiesOID as uo
from flext_ldif._utilities.parser import FlextLdifUtilitiesParser as up
from flext_ldif._utilities.schema_extract import FlextLdifUtilitiesSchemaExtract as se

if TYPE_CHECKING:
    from collections.abc import Callable, MutableMapping


class FlextLdifUtilitiesSchemaParse:
    """Parse RFC 4512 schema definitions from strings and LDIF content."""

    _module_logger: ClassVar[p.Logger] = core_u.fetch_logger(__name__)

    @staticmethod
    def _convert_metadata_extensions(
        extensions_raw: t.Ldif.MutableMetadataMapping,
    ) -> t.Ldif.MutableMetadataMapping:
        converted: t.Ldif.MutableMetadataMapping = {}
        for key, raw_value in extensions_raw.items():
            converted[key] = core_u.normalize_to_metadata(raw_value)
        return converted

    @staticmethod
    def _validate_attribute_syntax(
        syntax: str | None,
    ) -> t.Ldif.MutableMetadataMapping | None:
        """Validate syntax OID and return validation result."""
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
                f"Invalid syntax OID format: {syntax} (must be numeric dot-separated format)"
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
        """Build metadata extensions dictionary for schema definitions."""
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
    def detect_schema_type(
        definition: str | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass,
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
        try:
            _ = m.Ldif.SchemaAttribute.model_validate(definition)
            return c.Ldif.SchemaItemKind.ATTRIBUTE
        except c.Ldif.EXC_LDIF_PARSE as exc:
            FlextLdifUtilitiesSchemaParse._module_logger.debug(
                "SchemaAttribute model validation did not match: %s",
                exc,
            )
        try:
            _ = m.Ldif.SchemaObjectClass.model_validate(definition)
            return c.Ldif.SchemaItemKind.OBJECTCLASS
        except c.Ldif.EXC_LDIF_PARSE as exc:
            FlextLdifUtilitiesSchemaParse._module_logger.debug(
                "SchemaObjectClass model validation did not match: %s",
                exc,
            )
        definition_str = str(definition)
        definition_lower = definition_str.lower()
        objectclass_only_keywords = [
            " structural",
            " auxiliary",
            " abstract",
            " must (",
            " may (",
        ]
        for keyword in objectclass_only_keywords:
            if keyword in definition_lower:
                return c.Ldif.SchemaItemKind.OBJECTCLASS
        attribute_only_keywords = [
            " equality ",
            " substr ",
            " ordering ",
            " syntax ",
            " usage ",
            " single-value",
            " no-user-modification",
        ]
        for keyword in attribute_only_keywords:
            if keyword in definition_lower:
                return c.Ldif.SchemaItemKind.ATTRIBUTE
        if "objectclass" in definition_lower or "oclass" in definition_lower:
            return c.Ldif.SchemaItemKind.OBJECTCLASS
        return c.Ldif.SchemaItemKind.ATTRIBUTE

    @staticmethod
    def extract_attributes_from_lines(
        ldif_content: str,
        parse_callback: Callable[[str], p.Result[m.Ldif.SchemaAttribute]],
    ) -> t.MutableSequenceOf[m.Ldif.SchemaAttribute]:
        """Extract and parse all attributeTypes from LDIF content lines."""
        return se.extract_schema_items_from_lines(
            ldif_content,
            parse_callback,
            "attributetypes:",
            m.Ldif.SchemaAttribute,
        )

    @staticmethod
    def extract_objectclasses_from_lines(
        ldif_content: str,
        parse_callback: Callable[[str], p.Result[m.Ldif.SchemaObjectClass]],
    ) -> t.MutableSequenceOf[m.Ldif.SchemaObjectClass]:
        """Extract and parse all objectClasses from LDIF content lines."""
        return se.extract_schema_items_from_lines(
            ldif_content,
            parse_callback,
            "objectclasses:",
            m.Ldif.SchemaObjectClass,
        )

    @staticmethod
    def parse_attribute(
        attr_definition: str,
        *,
        validate_syntax: bool = True,
    ) -> p.Result[t.Ldif.MutableMetadataMapping]:
        """Parse RFC 4512 attribute definition into structured data."""
        basic_fields_result = se.extract_schema_basic_fields(
            definition=attr_definition,
            definition_label=c.Ldif.SchemaItemKind.ATTRIBUTE.value,
        )
        if basic_fields_result.failure:
            return r[t.Ldif.MutableMetadataMapping].fail(basic_fields_result.error)
        basic_fields_value = basic_fields_result.value
        oid = basic_fields_value[0]
        name = basic_fields_value[1]
        desc = basic_fields_value[2]
        syntax, length = se.extract_attribute_syntax(attr_definition)
        syntax_validation_result: t.Ldif.MutableMetadataMapping | None = None
        if validate_syntax:
            syntax_validation_result = (
                FlextLdifUtilitiesSchemaParse._validate_attribute_syntax(syntax)
            )
        equality, substr, ordering = se.extract_attribute_matching_rules(
            attr_definition,
        )
        single_value, no_user_modification = se.extract_attribute_flags(
            attr_definition,
        )
        sup, usage = se.extract_attribute_sup_usage(attr_definition)
        additional_extensions_converted: t.Ldif.MutableMetadataMapping | None = (
            syntax_validation_result
        )
        extensions_raw = FlextLdifUtilitiesSchemaParse.build_metadata(
            attr_definition,
            additional_extensions=additional_extensions_converted,
        )
        extensions_converted = (
            FlextLdifUtilitiesSchemaParse._convert_metadata_extensions(extensions_raw)
        )
        syntax_validation_converted: t.Ldif.MutableMetadataMapping | None = None
        if syntax_validation_result is not None:
            syntax_validation_converted = (
                FlextLdifUtilitiesSchemaParse._convert_metadata_extensions(
                    syntax_validation_result,
                )
            )
        parsed_dict = dict(
            t.Cli.JSON_MAPPING_ADAPTER.validate_python({
                "oid": oid,
                "name": name,
                "desc": desc,
                "syntax": syntax,
                "length": length,
                "equality": equality,
                "ordering": ordering,
                "substr": substr,
                "single_value": single_value,
                "no_user_modification": no_user_modification,
                "sup": sup,
                "usage": usage,
                "metadata_extensions": extensions_converted,
                "syntax_validation": syntax_validation_converted,
            }),
        )
        return r[t.Ldif.MutableMetadataMapping].ok(parsed_dict)

    @staticmethod
    def parse_objectclass(
        oc_definition: str,
    ) -> t.Ldif.MutableMetadataMapping:
        """Parse RFC 4512 objectClass definition into structured data."""
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
