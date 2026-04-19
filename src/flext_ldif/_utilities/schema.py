"""Extracted nested class from FlextLdifUtilities."""

from __future__ import annotations

import re
import struct
from collections.abc import Callable, Mapping, MutableMapping, MutableSequence, Sequence
from datetime import datetime
from typing import TypeIs

from flext_core import u
from flext_ldif import (
    FlextLdifUtilitiesOID,
    FlextLdifUtilitiesParser,
    FlextLdifUtilitiesServer,
    FlextLdifUtilitiesWriter,
    c,
    m,
    p,
    r,
    t,
)

logger = u.fetch_logger(__name__)


class FlextLdifUtilitiesSchema:
    """Generic attribute definition normalization utilities."""

    @staticmethod
    def _add_objectclass_must_may(
        oc_data: m.Ldif.SchemaObjectClass,
        parts: MutableSequence[str],
    ) -> None:
        """Add MUST and MAY to objectclass parts list."""
        if oc_data.must:
            if u.list_like(oc_data.must):
                must_list_str: MutableSequence[str] = [
                    str(item) for item in oc_data.must
                ]
                if len(must_list_str) == 1:
                    parts.append(f"MUST {must_list_str[0]}")
                else:
                    must_str = " $ ".join(must_list_str)
                    parts.append(f"MUST ( {must_str} )")
            else:
                parts.append(f"MUST {oc_data.must}")
        if oc_data.may:
            if u.list_like(oc_data.may):
                may_list_str: MutableSequence[str] = [str(item) for item in oc_data.may]
                if len(may_list_str) == 1:
                    parts.append(f"MAY {may_list_str[0]}")
                else:
                    may_str = " $ ".join(may_list_str)
                    parts.append(f"MAY ( {may_str} )")
            else:
                parts.append(f"MAY {oc_data.may}")

    @staticmethod
    def _add_objectclass_sup(
        oc_data: m.Ldif.SchemaObjectClass,
        parts: MutableSequence[str],
    ) -> None:
        """Add SUP to objectclass parts list."""
        if oc_data.sup:
            if u.list_like(oc_data.sup):
                sup_list_str: MutableSequence[str] = [str(item) for item in oc_data.sup]
                if len(sup_list_str) == 1:
                    parts.append(f"SUP {sup_list_str[0]}")
                else:
                    sup_str = " $ ".join(sup_list_str)
                    parts.append(f"SUP ( {sup_str} )")
            else:
                parts.append(f"SUP {oc_data.sup}")

    @staticmethod
    def _apply_trailing_spaces(
        attr_data: m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass,
        parts: MutableSequence[str],
    ) -> None:
        """Apply trailing spaces from metadata if available."""
        if not attr_data.metadata or not attr_data.metadata.schema_format_details:
            return
        trailing = getattr(
            attr_data.metadata.schema_format_details,
            "trailing_spaces",
            "",
        )
        if trailing and parts:
            parts[-1] += str(trailing)

    @staticmethod
    def _build_attribute_parts_from_model(
        attr_data: m.Ldif.SchemaAttribute,
    ) -> MutableSequence[str]:
        """Build RFC 4512 attribute definition parts (simple version)."""
        parts: MutableSequence[str] = [f"( {attr_data.oid}"]
        if attr_data.name:
            parts.append(f"NAME '{attr_data.name}'")
        if attr_data.desc:
            parts.append(f"DESC '{attr_data.desc}'")
        if attr_data.metadata and attr_data.metadata.extensions.get(
            c.Ldif.ObsoleteField.OBSOLETE,
        ):
            parts.append("OBSOLETE")
        if attr_data.sup:
            parts.append(f"SUP {attr_data.sup}")
        FlextLdifUtilitiesWriter.add_attribute_matching_rules(attr_data, parts)
        FlextLdifUtilitiesWriter.add_attribute_syntax(attr_data, parts)
        FlextLdifUtilitiesWriter.add_attribute_flags(attr_data, parts)
        if attr_data.usage:
            parts.append(f"USAGE {attr_data.usage}")
        if attr_data.metadata and attr_data.metadata.extensions.get("x_origin"):
            parts.append(f"X-ORIGIN '{attr_data.metadata.extensions.get('x_origin')}'")
        parts.append(")")
        return parts

    @staticmethod
    def _build_name_part(
        attr_data: m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass,
        *,
        restore_format: bool = False,
    ) -> str | None:
        """Build NAME part with optional format restoration."""
        if not attr_data.name:
            return None
        if not restore_format or not attr_data.metadata:
            return f"NAME '{attr_data.name}'"
        schema_details = attr_data.metadata.schema_format_details
        if not schema_details:
            return f"NAME '{attr_data.name}'"
        name_format = getattr(schema_details, "name_format", "single")
        name_values_ = getattr(schema_details, "name_values", [])
        name_values: MutableSequence[str] = (
            [str(v) for v in name_values_] if u.list_like(name_values_) else []
        )
        if name_format == "multiple" and name_values:
            names_str = " ".join(f"'{n}'" for n in name_values)
            return f"NAME ( {names_str} )"
        return f"NAME '{attr_data.name}'"

    @staticmethod
    def _build_objectclass_parts_from_model(
        oc_data: m.Ldif.SchemaObjectClass,
    ) -> MutableSequence[str]:
        """Build RFC 4512 objectClass definition parts (extracted to reduce complexity)."""
        parts: MutableSequence[str] = [f"( {oc_data.oid}"]
        if oc_data.name:
            parts.append(f"NAME '{oc_data.name}'")
        if oc_data.desc:
            parts.append(f"DESC '{oc_data.desc}'")
        if oc_data.metadata and oc_data.metadata.extensions.get(
            c.Ldif.ObsoleteField.OBSOLETE,
        ):
            parts.append("OBSOLETE")
        FlextLdifUtilitiesSchema._add_objectclass_sup(oc_data, parts)
        kind = oc_data.kind or c.Ldif.SchemaKind.STRUCTURAL.value
        parts.append(str(kind))
        FlextLdifUtilitiesSchema._add_objectclass_must_may(oc_data, parts)
        if oc_data.metadata and oc_data.metadata.extensions.get("x_origin"):
            parts.append(f"X-ORIGIN '{oc_data.metadata.extensions.get('x_origin')}'")
        parts.append(")")
        return parts

    @staticmethod
    def _build_obsolete_part(
        attr_data: m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass,
        parts: MutableSequence[str],
        field_order: MutableSequence[str] | None,
        *,
        restore_position: bool = False,
    ) -> None:
        """Build OBSOLETE part with optional position restoration."""
        has_obsolete = False
        if attr_data.metadata:
            schema_details = attr_data.metadata.schema_format_details
            has_obsolete = bool(
                getattr(schema_details, "obsolete_presence", False)
                if schema_details
                else False,
            )
            if not has_obsolete:
                has_obsolete = bool(
                    attr_data.metadata.extensions.get(c.Ldif.ObsoleteField.OBSOLETE),
                )
        if not has_obsolete:
            return
        if restore_position and field_order and ("OBSOLETE" in field_order):
            obs_pos = field_order.index("OBSOLETE")
            parts.insert(min(obs_pos, len(parts)), "OBSOLETE")
        else:
            parts.append("OBSOLETE")

    @staticmethod
    def _build_x_origin_part(
        attr_data: m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass,
        *,
        restore_format: bool = False,
    ) -> str | None:
        """Build X-ORIGIN part with optional format restoration."""
        if not attr_data.metadata:
            return None
        schema_details = attr_data.metadata.schema_format_details
        x_origin_value = None
        if (
            restore_format
            and schema_details
            and getattr(schema_details, "x_origin_presence", None)
            and getattr(schema_details, "x_origin_value", None)
        ):
            x_origin_value = getattr(schema_details, "x_origin_value", None)
        if not x_origin_value:
            x_origin_value = attr_data.metadata.extensions.get("x_origin")
        return f"X-ORIGIN '{x_origin_value}'" if x_origin_value else None

    @staticmethod
    def _convert_metadata_extensions(
        extensions_raw: t.MutableRecursiveContainerMapping,
    ) -> MutableMapping[
        str,
        t.Scalar
        | MutableSequence[str]
        | MutableMapping[str, t.Scalar | MutableSequence[str]],
    ]:
        converted: MutableMapping[
            str,
            t.Scalar
            | MutableSequence[str]
            | MutableMapping[str, t.Scalar | MutableSequence[str]],
        ] = {}
        for key, raw_value in extensions_raw.items():
            if u.primitive(raw_value) or isinstance(raw_value, datetime):
                converted[key] = FlextLdifUtilitiesSchema._convert_metadata_value(
                    raw_value,
                )
                continue
            if FlextLdifUtilitiesSchema._is_object_list(raw_value):
                converted[key] = FlextLdifUtilitiesSchema._convert_metadata_value(
                    raw_value,
                )
                continue
            if FlextLdifUtilitiesSchema._is_object_mapping(raw_value):
                converted[key] = FlextLdifUtilitiesSchema._convert_metadata_value(
                    dict(raw_value),
                )
                continue
            converted[key] = FlextLdifUtilitiesSchema._convert_metadata_value(
                str(raw_value),
            )
        return converted

    @staticmethod
    def _convert_metadata_value(
        value: t.Scalar
        | datetime
        | t.MutableRecursiveContainerList
        | MutableMapping[t.RecursiveContainer, t.RecursiveContainer]
        | t.RecursiveContainerMapping,
    ) -> (
        t.Scalar
        | MutableSequence[str]
        | MutableMapping[str, t.Scalar | MutableSequence[str]]
    ):
        if isinstance(value, t.SCALAR_TYPES):
            return value
        if isinstance(value, datetime):
            return value.isoformat()
        if isinstance(value, list):
            converted_list: MutableSequence[str] = []
            for index in range(len(value)):
                item_value: t.RecursiveContainer = value[index]
                converted_list.append(str(item_value))
            return converted_list
        if isinstance(value, Mapping):
            converted_mapping: MutableMapping[str, t.Scalar | MutableSequence[str]] = {}
            for key_obj, nested_value_raw in value.items():
                nested_value = FlextLdifUtilitiesSchema._convert_nested_metadata_value(
                    nested_value_raw,
                )
                converted_mapping[str(key_obj)] = nested_value
            return converted_mapping
        return {
            "value": FlextLdifUtilitiesSchema._convert_nested_metadata_value(
                str(value),
            ),
        }

    @staticmethod
    def _convert_nested_metadata_value(
        value: t.Scalar
        | datetime
        | t.MutableRecursiveContainerList
        | t.RecursiveContainer,
    ) -> t.Scalar | MutableSequence[str]:
        if u.primitive(value):
            return value
        if isinstance(value, datetime):
            return value.isoformat()
        if FlextLdifUtilitiesSchema._is_object_sequence(value):
            converted_nested_list: MutableSequence[str] = []
            for index in range(len(value)):
                nested_item_value: t.RecursiveContainer = value[index]
                converted_nested_list.append(str(nested_item_value))
            return converted_nested_list
        return str(value)

    @staticmethod
    def _is_object_list(
        value: t.RecursiveContainer,
    ) -> TypeIs[t.MutableRecursiveContainerList]:
        return isinstance(value, list)

    @staticmethod
    def _is_object_mapping(
        value: t.RecursiveContainer,
    ) -> TypeIs[t.RecursiveContainerMapping]:
        return isinstance(value, Mapping)

    @staticmethod
    def _is_object_sequence(
        value: t.RecursiveContainer,
    ) -> TypeIs[t.MutableRecursiveContainerList]:
        return isinstance(value, Sequence) and not isinstance(value, str | bytes)

    @staticmethod
    def _convert_sequence_to_str_list(
        seq: MutableSequence[t.Scalar],
    ) -> MutableSequence[str]:
        """Convert Sequence to MutableSequence[str] (internal helper, no loose functions)."""
        return [str(item) for item in seq]

    @staticmethod
    def _extract_attribute_basic_fields(
        attr_definition: str,
    ) -> r[tuple[str, str, str | None]]:
        """Extract OID, NAME, and DESC from attribute definition."""
        return FlextLdifUtilitiesSchema._extract_schema_basic_fields(
            definition=attr_definition,
            definition_label="attribute",
        )

    @staticmethod
    def _extract_attribute_flags(attr_definition: str) -> tuple[bool, bool]:
        """Extract boolean flags (single_value, no_user_modification) from attribute definition."""
        single_value = FlextLdifUtilitiesParser.extract_boolean_flag(
            attr_definition,
            c.Ldif.SCHEMA_SINGLE_VALUE,
        )
        no_user_modification = FlextLdifUtilitiesParser.extract_boolean_flag(
            attr_definition,
            c.Ldif.SCHEMA_NO_USER_MODIFICATION,
        )
        return (single_value, no_user_modification)

    @staticmethod
    def _extract_attribute_matching_rules(
        attr_definition: str,
    ) -> tuple[str | None, str | None, str | None]:
        """Extract matching rules (equality, substr, ordering) from attribute definition."""
        equality = FlextLdifUtilitiesParser.extract_optional_field(
            attr_definition,
            c.Ldif.SCHEMA_EQUALITY,
        )
        substr = FlextLdifUtilitiesParser.extract_optional_field(
            attr_definition,
            c.Ldif.SCHEMA_SUBSTR,
        )
        ordering = FlextLdifUtilitiesParser.extract_optional_field(
            attr_definition,
            c.Ldif.SCHEMA_ORDERING,
        )
        return (equality, substr, ordering)

    @staticmethod
    def _extract_attribute_sup_usage(
        attr_definition: str,
    ) -> tuple[str | None, str | None]:
        """Extract SUP and USAGE from attribute definition."""
        sup = FlextLdifUtilitiesParser.extract_optional_field(
            attr_definition,
            c.Ldif.SCHEMA_SUP,
        )
        usage = FlextLdifUtilitiesParser.extract_optional_field(
            attr_definition,
            c.Ldif.SCHEMA_USAGE,
        )
        return (sup, usage)

    @staticmethod
    def _extract_attribute_syntax(
        attr_definition: str,
    ) -> tuple[str | None, int | None]:
        """Extract SYNTAX and length from attribute definition."""
        syntax_match = re.search(
            c.Ldif.SCHEMA_SYNTAX_LENGTH,
            attr_definition,
        )
        syntax = syntax_match.group(1) if syntax_match else None
        length = (
            int(syntax_match.group(2))
            if syntax_match and syntax_match.group(2)
            else None
        )
        return (syntax, length)

    @staticmethod
    def _extract_objectclass_basic_fields(
        oc_definition: str,
    ) -> r[tuple[str, str, str | None]]:
        """Extract OID, NAME, and DESC from objectClass definition."""
        return FlextLdifUtilitiesSchema._extract_schema_basic_fields(
            definition=oc_definition,
            definition_label="objectClass",
        )

    @staticmethod
    def _extract_schema_basic_fields(
        definition: str,
        definition_label: str,
    ) -> r[tuple[str, str, str | None]]:
        oid_result = FlextLdifUtilitiesParser.extract_oid(definition)
        if oid_result.failure:
            error = oid_result.error or "unknown OID extraction error"
            return r[tuple[str, str, str | None]].fail(
                f"RFC {definition_label} parsing failed: {error}",
            )
        if not oid_result.success:
            return r[tuple[str, str, str | None]].fail(
                f"RFC {definition_label} parsing failed: unknown result state",
            )
        oid = oid_result.value
        name_raw = FlextLdifUtilitiesParser.extract_optional_field(
            definition,
            c.Ldif.SCHEMA_NAME,
            default=oid,
        )
        name: str = name_raw if name_raw is not None else oid
        desc = FlextLdifUtilitiesParser.extract_optional_field(
            definition,
            c.Ldif.SCHEMA_DESC,
        )
        return r[tuple[str, str, str | None]].ok((oid, name, desc))

    @staticmethod
    def _extract_objectclass_kind(oc_definition: str) -> str:
        """Extract KIND from objectClass definition."""
        kind_match = re.search(
            c.Ldif.SCHEMA_OBJECTCLASS_KIND,
            oc_definition,
            re.IGNORECASE,
        )
        return (
            kind_match.group(1).upper()
            if kind_match
            else c.Ldif.SchemaKind.STRUCTURAL.value
        )

    @staticmethod
    def _extract_objectclass_must_may(
        oc_definition: str,
    ) -> tuple[MutableSequence[str] | None, MutableSequence[str] | None]:
        """Extract MUST and MAY attributes from objectClass definition."""
        must = None
        must_match = re.search(
            c.Ldif.SCHEMA_OBJECTCLASS_MUST,
            oc_definition,
        )
        if must_match:
            must_value = (must_match.group(1) or must_match.group(2)).strip()
            must = FlextLdifUtilitiesSchema._split_schema_values(must_value)
        may = None
        may_match = re.search(c.Ldif.SCHEMA_OBJECTCLASS_MAY, oc_definition)
        if may_match:
            may_value = (may_match.group(1) or may_match.group(2)).strip()
            may = FlextLdifUtilitiesSchema._split_schema_values(may_value)
        return (must, may)

    @staticmethod
    def _extract_objectclass_sup(oc_definition: str) -> str | None:
        """Extract SUP from objectClass definition."""
        sup_match = re.search(c.Ldif.SCHEMA_OBJECTCLASS_SUP, oc_definition)
        if not sup_match:
            return None
        sup_value = sup_match.group(1) or sup_match.group(2) or sup_match.group(3)
        return FlextLdifUtilitiesSchema._split_schema_values(sup_value)[0]

    @staticmethod
    def _extract_schema_items_from_lines[SchemaModelT: m.Ldif.SchemaElement](
        ldif_content: str,
        parse_callback: Callable[[str], r[SchemaModelT]],
        line_prefix: str,
        model_type: type[SchemaModelT],
    ) -> MutableSequence[SchemaModelT]:
        """Generic extraction of schema items from LDIF content lines."""
        items: MutableSequence[SchemaModelT] = []
        for raw_line in ldif_content.split("\n"):
            line = raw_line.strip()
            if line.lower().startswith(line_prefix.lower()):
                item_def = line.split(":", 1)[1].strip()
                result = parse_callback(item_def)
                if result.success:
                    try:
                        items.append(model_type.model_validate(result.value))
                    except (
                        ValueError,
                        KeyError,
                        AttributeError,
                        UnicodeDecodeError,
                        struct.error,
                    ) as exc:
                        logger.debug(f"Schema line item validation failed: : {exc}")
                        continue
        return items

    @staticmethod
    def _format_attribute_list(
        attr_list: str | MutableSequence[str] | None,
        prefix: str,
    ) -> str | None:
        """Format attribute list (MUST/MAY) for objectClass definition."""
        if not attr_list:
            return None
        if u.list_like(attr_list):
            attr_strs = [str(item) for item in attr_list]
            if len(attr_strs) == 1:
                return f"{prefix} {attr_strs[0]}"
            return f"{prefix} ( {' $ '.join(attr_strs)} )"
        return f"{prefix} {attr_list}"

    @staticmethod
    def _format_sup_list(sup_value: str | MutableSequence[str] | None) -> str | None:
        """Format SUP (superior) list for objectClass definition."""
        if not sup_value:
            return None
        if u.list_like(sup_value):
            sup_strs = [str(item) for item in sup_value]
            return f"SUP ( {' $ '.join(sup_strs)} )"
        return f"SUP {sup_value}"

    @staticmethod
    def _get_field_order(
        attr_data: m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass,
    ) -> MutableSequence[str] | None:
        """Extract field order from metadata if available."""
        if not attr_data.metadata or not attr_data.metadata.schema_format_details:
            return None
        field_order_ = getattr(
            attr_data.metadata.schema_format_details,
            "field_order",
            None,
        )
        if field_order_ and u.list_like(field_order_):
            return [str(item) for item in field_order_]
        return None

    @staticmethod
    def _split_schema_values(value: str) -> MutableSequence[str]:
        return [item.strip() for item in value.strip().split("$")]

    @staticmethod
    def _try_restore_objectclass_original_format(
        oc_data: m.Ldif.SchemaObjectClass,
        *,
        restore_original: bool = True,
    ) -> MutableSequence[str] | None:
        """Try to restore original format from metadata for objectClass."""
        if not restore_original or not oc_data.metadata:
            return None
        schema_details = oc_data.metadata.schema_format_details
        if not schema_details:
            return None
        original = str(getattr(schema_details, "original_string_complete", ""))
        if not original:
            return None
        definition_match = re.search(r"\(.*\)", original, re.DOTALL)
        if definition_match:
            return [definition_match.group(0)]
        return None

    @staticmethod
    def _try_restore_original_format(
        attr_data: m.Ldif.SchemaAttribute,
    ) -> MutableSequence[str] | None:
        """Try to restore original format from metadata for perfect round-trip."""
        if not (
            attr_data.metadata
            and attr_data.metadata.schema_format_details
            and getattr(
                attr_data.metadata.schema_format_details,
                "original_string_complete",
                None,
            )
        ):
            return None
        original = str(
            getattr(
                attr_data.metadata.schema_format_details,
                "original_string_complete",
                "",
            ),
        )
        if not original:
            return None
        definition_match = re.search(r"\(.*\)", original, re.DOTALL)
        return [definition_match.group(0)] if definition_match else None

    @staticmethod
    def should_restore_schema_original_format(
        metadata: m.Ldif.QuirkMetadata | None,
        target_server_type: str | None,
    ) -> bool:
        """Restore original schema text only for same-server round-trips."""
        if metadata is None:
            return False
        source_server_type = metadata.original_server_type
        if source_server_type is None and metadata.extensions:
            source_server_raw = metadata.extensions.get(c.Ldif.SCHEMA_SOURCE_SERVER)
            if isinstance(source_server_raw, str):
                source_server_type = source_server_raw
        if source_server_type is None:
            source_server_type = str(metadata.quirk_type)
        if not source_server_type or not target_server_type:
            return True
        try:
            normalized_source = FlextLdifUtilitiesServer.normalize_server_type(
                str(source_server_type),
            )
            normalized_target = FlextLdifUtilitiesServer.normalize_server_type(
                target_server_type,
            )
        except (TypeError, ValueError):
            return str(source_server_type).lower() == target_server_type.lower()
        return normalized_source == normalized_target

    @staticmethod
    def _validate_attribute_syntax(
        syntax: str | None,
    ) -> t.MutableRecursiveContainerMapping | None:
        """Validate syntax OID and return validation result."""
        if not syntax or not syntax.strip():
            return None
        syntax_extensions: MutableMapping[
            str,
            bool | MutableSequence[str] | str | None,
        ] = {}
        validate_result = FlextLdifUtilitiesOID.validate_format(syntax)
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
        result_dict: t.MutableRecursiveContainerMapping = {}
        for key, val in syntax_extensions.items():
            if isinstance(val, list):
                list_typed: t.RecursiveContainer = list(val)
                result_dict[key] = list_typed
            elif val is not None:
                result_dict[key] = val
        return result_dict

    @staticmethod
    def _write_schema_element(
        data: p.Ldif.SchemaAttribute | p.Ldif.SchemaObjectClass,
        expected_type: (type[m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass]),
        type_name: str,
        parts_builder: Callable[..., MutableSequence[str]],
    ) -> str:
        """Generic helper for writing schema elements (DRY pattern)."""
        if not isinstance(data, expected_type):
            msg = f"{type_name} must implement {expected_type.__name__}"
            raise TypeError(msg)
        validated_data = data
        if not validated_data.oid:
            msg = f"RFC {type_name} writing failed: missing OID"
            raise ValueError(msg)
        parts = parts_builder(validated_data)
        return " ".join(parts)

    @staticmethod
    def build_attribute_parts_with_metadata(
        attr_data: m.Ldif.SchemaAttribute,
        *,
        restore_original: bool = True,
    ) -> MutableSequence[str]:
        """Build RFC 4512 attribute parts with full metadata restoration."""
        if restore_original:
            original_parts = FlextLdifUtilitiesSchema._try_restore_original_format(
                attr_data,
            )
            if original_parts:
                return original_parts
        parts: MutableSequence[str] = [f"( {attr_data.oid}"]
        field_order = FlextLdifUtilitiesSchema._get_field_order(attr_data)
        name_part = FlextLdifUtilitiesSchema._build_name_part(
            attr_data,
            restore_format=True,
        )
        if name_part:
            parts.append(name_part)
        if attr_data.desc:
            parts.append(f"DESC '{attr_data.desc}'")
        if attr_data.sup:
            parts.append(f"SUP {attr_data.sup}")
        if attr_data.usage:
            parts.append(f"USAGE {attr_data.usage}")
        FlextLdifUtilitiesSchema._build_obsolete_part(
            attr_data,
            parts,
            field_order,
            restore_position=True,
        )
        FlextLdifUtilitiesWriter.add_attribute_matching_rules(attr_data, parts)
        FlextLdifUtilitiesWriter.add_attribute_syntax(attr_data, parts)
        FlextLdifUtilitiesWriter.add_attribute_flags(attr_data, parts)
        x_origin_part = FlextLdifUtilitiesSchema._build_x_origin_part(
            attr_data,
            restore_format=True,
        )
        if x_origin_part:
            parts.append(x_origin_part)
        parts.append(")")
        FlextLdifUtilitiesSchema._apply_trailing_spaces(attr_data, parts)
        return parts

    @staticmethod
    def build_available_attributes_set(
        attributes: MutableSequence[m.Ldif.SchemaAttribute],
    ) -> set[str]:
        """Build set of available attribute names (lowercase) for dependency validation."""
        available: set[str] = set()
        for attr_data in attributes:
            attr_name = str(attr_data.name).lower()
            available.add(attr_name)
        return available

    @staticmethod
    def build_metadata(
        definition: str,
        additional_extensions: t.MutableRecursiveContainerMapping | None = None,
    ) -> t.MutableRecursiveContainerMapping:
        """Build metadata extensions dictionary for schema definitions."""
        extensions_raw = FlextLdifUtilitiesParser.extract_extensions(definition)
        extensions: t.MutableRecursiveContainerMapping = {}
        for key, val in extensions_raw.items():
            typed_val: t.RecursiveContainer = list(val)
            extensions[key] = typed_val
        extensions[c.Ldif.ORIGINAL_FORMAT] = definition.strip()
        if additional_extensions:
            extensions.update(additional_extensions)
        return extensions

    @staticmethod
    def build_objectclass_parts_with_metadata(
        oc_data: m.Ldif.SchemaObjectClass,
        *,
        restore_original: bool = True,
    ) -> MutableSequence[str]:
        """Build RFC 4512 objectClass parts with full metadata restoration."""
        original_parts = (
            FlextLdifUtilitiesSchema._try_restore_objectclass_original_format(
                oc_data,
                restore_original=restore_original,
            )
        )
        if original_parts:
            return original_parts
        parts: MutableSequence[str] = [f"( {oc_data.oid}"]
        name_part = FlextLdifUtilitiesSchema._build_name_part(
            oc_data,
            restore_format=True,
        )
        if name_part:
            parts.append(name_part)
        if oc_data.desc:
            parts.append(f"DESC '{oc_data.desc}'")
        field_order = None
        if oc_data.metadata and oc_data.metadata.schema_format_details:
            field_order_ = getattr(
                oc_data.metadata.schema_format_details,
                "field_order",
                None,
            )
            if field_order_ and u.list_like(field_order_):
                field_order = [str(item) for item in field_order_]
        FlextLdifUtilitiesSchema._build_obsolete_part(
            oc_data,
            parts,
            field_order,
            restore_position=True,
        )
        sup_part = FlextLdifUtilitiesSchema._format_sup_list(oc_data.sup)
        if sup_part:
            parts.append(sup_part)
        kind = oc_data.kind or c.Ldif.SchemaKind.STRUCTURAL.value
        parts.append(str(kind))
        must_part = FlextLdifUtilitiesSchema._format_attribute_list(
            oc_data.must,
            "MUST",
        )
        if must_part:
            parts.append(must_part)
        may_part = FlextLdifUtilitiesSchema._format_attribute_list(oc_data.may, "MAY")
        if may_part:
            parts.append(may_part)
        x_origin_part = FlextLdifUtilitiesSchema._build_x_origin_part(
            oc_data,
            restore_format=True,
        )
        if x_origin_part:
            parts.append(x_origin_part)
        parts.append(")")
        FlextLdifUtilitiesSchema._apply_trailing_spaces(oc_data, parts)
        return parts

    @staticmethod
    def detect_schema_type(
        definition: str | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass,
    ) -> str:
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
            return "attribute"
        except (
            ValueError,
            KeyError,
            AttributeError,
            UnicodeDecodeError,
            struct.error,
        ) as exc:
            logger.debug(f"SchemaAttribute model validation did not match: {exc}")
        try:
            _ = m.Ldif.SchemaObjectClass.model_validate(definition)
            return "objectclass"
        except (
            ValueError,
            KeyError,
            AttributeError,
            UnicodeDecodeError,
            struct.error,
        ):
            logger.debug("SchemaObjectClass model validation did not match: {exc}")
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
                return "objectclass"
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
                return "attribute"
        if "objectclass" in definition_lower or "oclass" in definition_lower:
            return "objectclass"
        return "attribute"

    @staticmethod
    def extract_attributes_from_lines(
        ldif_content: str,
        parse_callback: Callable[[str], r[m.Ldif.SchemaAttribute]],
    ) -> MutableSequence[m.Ldif.SchemaAttribute]:
        """Extract and parse all attributeTypes from LDIF content lines."""
        return FlextLdifUtilitiesSchema._extract_schema_items_from_lines(
            ldif_content,
            parse_callback,
            "attributetypes:",
            m.Ldif.SchemaAttribute,
        )

    @staticmethod
    def extract_objectclasses_from_lines(
        ldif_content: str,
        parse_callback: Callable[[str], r[m.Ldif.SchemaObjectClass]],
    ) -> MutableSequence[m.Ldif.SchemaObjectClass]:
        """Extract and parse all objectClasses from LDIF content lines."""
        return FlextLdifUtilitiesSchema._extract_schema_items_from_lines(
            ldif_content,
            parse_callback,
            "objectclasses:",
            m.Ldif.SchemaObjectClass,
        )

    @staticmethod
    def is_attribute_in_list(
        attribute_name: str | None,
        attribute_list: MutableSequence[str] | set[str] | None,
    ) -> bool:
        """Check if attribute exists in list or set (case-insensitive)."""
        if not attribute_name or not attribute_list:
            return False
        normalized_input = FlextLdifUtilitiesSchema.normalize_attribute_name(
            attribute_name,
        )
        return any(
            FlextLdifUtilitiesSchema.normalize_attribute_name(attr) == normalized_input
            for attr in attribute_list
        )

    @staticmethod
    def is_boolean_attribute(
        attribute_name: str | None,
        boolean_attributes: set[str],
    ) -> bool:
        """Check if attribute is in boolean attributes set (case-insensitive)."""
        if not attribute_name or not boolean_attributes:
            return False
        normalized_input = FlextLdifUtilitiesSchema.normalize_attribute_name(
            attribute_name,
        )
        normalized_set = {
            FlextLdifUtilitiesSchema.normalize_attribute_name(attr)
            for attr in boolean_attributes
        }
        return normalized_input in normalized_set

    @staticmethod
    def normalize_attribute_name(
        attribute_name: str | None,
        *,
        case_sensitive: bool = False,
    ) -> str | None:
        """Normalize attribute name for case-insensitive comparisons."""
        if not attribute_name:
            return attribute_name
        return attribute_name if case_sensitive else attribute_name.lower()

    @staticmethod
    def normalize_matching_rules(
        equality: str | None,
        substr: str | None = None,
        *,
        replacements: t.MutableStrMapping | None = None,
        substr_rules_in_equality: t.MutableStrMapping | None = None,
        normalized_substr_values: t.MutableStrMapping | None = None,
    ) -> tuple[str | None, str | None]:
        """Normalize EQUALITY and SUBSTR matching rules."""
        result_equality = equality
        result_substr = substr
        if (
            substr_rules_in_equality
            and equality
            and (equality in substr_rules_in_equality)
        ):
            result_substr = equality
            result_equality = substr_rules_in_equality[equality]
        if (
            result_substr
            and normalized_substr_values
            and (result_substr in normalized_substr_values)
        ):
            result_substr = normalized_substr_values[result_substr]
        if replacements and result_equality and (result_equality in replacements):
            result_equality = replacements[result_equality]
        return (result_equality, result_substr)

    @staticmethod
    def normalize_name(
        name_value: str | None,
        suffixes_to_remove: MutableSequence[str] | None = None,
        char_replacements: t.MutableStrMapping | None = None,
    ) -> str | None:
        """Normalize attribute NAME field."""
        if not name_value:
            return name_value
        result = name_value
        normalized_suffixes = (
            suffixes_to_remove if suffixes_to_remove is not None else [";binary"]
        )
        normalized_replacements = (
            char_replacements if char_replacements is not None else {"_": "-"}
        )
        for suffix in normalized_suffixes:
            if suffix in result:
                result = result.replace(suffix, "")
        for old, new in normalized_replacements.items():
            if old in result:
                result = result.replace(old, new)
        return result if result != name_value else name_value

    @staticmethod
    def normalize_syntax_oid(
        syntax: str | None,
        *,
        replacements: t.MutableStrMapping | None = None,
    ) -> str | None:
        """Normalize SYNTAX OID field."""
        if not syntax:
            return syntax
        result = syntax
        if result.startswith("'") and result.endswith("'"):
            result = result[1:-1]
        if replacements and result in replacements:
            result = replacements[result]
        return result

    @staticmethod
    def parse_attribute(
        attr_definition: str,
        *,
        validate_syntax: bool = True,
    ) -> r[t.MutableRecursiveContainerMapping]:
        """Parse RFC 4512 attribute definition into structured data."""
        basic_fields_result = FlextLdifUtilitiesSchema._extract_attribute_basic_fields(
            attr_definition,
        )
        if basic_fields_result.failure:
            return r[t.MutableRecursiveContainerMapping].fail(basic_fields_result.error)
        oid, name, desc = basic_fields_result.value
        syntax, length = FlextLdifUtilitiesSchema._extract_attribute_syntax(
            attr_definition,
        )
        syntax_validation_result: t.MutableRecursiveContainerMapping | None = None
        if validate_syntax:
            syntax_validation_result = (
                FlextLdifUtilitiesSchema._validate_attribute_syntax(syntax)
            )
        equality, substr, ordering = (
            FlextLdifUtilitiesSchema._extract_attribute_matching_rules(attr_definition)
        )
        single_value, no_user_modification = (
            FlextLdifUtilitiesSchema._extract_attribute_flags(attr_definition)
        )
        sup, usage = FlextLdifUtilitiesSchema._extract_attribute_sup_usage(
            attr_definition,
        )
        additional_extensions_converted: t.MutableRecursiveContainerMapping | None = (
            syntax_validation_result
        )
        extensions_raw = FlextLdifUtilitiesSchema.build_metadata(
            attr_definition,
            additional_extensions=additional_extensions_converted,
        )
        extensions_converted = FlextLdifUtilitiesSchema._convert_metadata_extensions(
            extensions_raw,
        )
        syntax_validation_converted: (
            MutableMapping[
                str,
                t.Scalar
                | MutableSequence[str]
                | MutableMapping[str, t.Scalar | MutableSequence[str]],
            ]
            | None
        ) = None
        if syntax_validation_result is not None:
            syntax_validation_converted = (
                FlextLdifUtilitiesSchema._convert_metadata_extensions(
                    syntax_validation_result,
                )
            )
        parsed_dict: t.MutableRecursiveContainerMapping = {
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
        }
        return r[t.MutableRecursiveContainerMapping].ok(parsed_dict)

    @staticmethod
    def parse_objectclass(
        oc_definition: str,
    ) -> t.MutableRecursiveContainerMapping:
        """Parse RFC 4512 objectClass definition into structured data."""
        basic_fields_result = (
            FlextLdifUtilitiesSchema._extract_objectclass_basic_fields(oc_definition)
        )
        if basic_fields_result.failure:
            msg = basic_fields_result.error or "RFC objectClass parsing failed"
            raise ValueError(msg)
        oid, name, desc = basic_fields_result.value
        sup = FlextLdifUtilitiesSchema._extract_objectclass_sup(oc_definition)
        kind = FlextLdifUtilitiesSchema._extract_objectclass_kind(oc_definition)
        must, may = FlextLdifUtilitiesSchema._extract_objectclass_must_may(
            oc_definition,
        )
        extensions_raw = FlextLdifUtilitiesSchema.build_metadata(oc_definition)
        extensions_converted = FlextLdifUtilitiesSchema._convert_metadata_extensions(
            extensions_raw,
        )
        parsed_dict: t.MutableRecursiveContainerMapping = {
            "oid": oid,
            "name": name,
            "desc": desc,
            "sup": sup,
            "kind": kind,
            "must": must,
            "may": may,
            "metadata_extensions": extensions_converted,
        }
        return parsed_dict

    @staticmethod
    def replace_invalid_substr_rule(
        substr: str | None,
        invalid_rules: t.MutableOptionalStrMapping,
    ) -> str | None:
        """Replace invalid SUBSTR rule with valid replacement."""
        if not substr or not invalid_rules:
            return substr
        if substr in invalid_rules:
            return invalid_rules[substr]
        return substr

    @staticmethod
    def validate_syntax_oid(syntax: str | None) -> str | None:
        """Validate syntax OID format.

        Generic validation for syntax OID fields used across server implementations.
        Checks that OID syntax conforms to standard OID format (numeric dot notation).

        Args:
            syntax: Syntax OID to validate

        Returns:
            Error message if validation fails, None otherwise

        """
        if syntax is None or not syntax.strip():
            return None
        validate_result = FlextLdifUtilitiesOID.validate_format(syntax)
        if validate_result.failure:
            return f"Syntax OID validation failed: {validate_result.error}"
        if not validate_result.value:
            return f"Invalid syntax OID format: {syntax}"
        return None

    @staticmethod
    def write_attribute(attr_data: p.Ldif.SchemaAttribute) -> str:
        """Write RFC 4512 attribute definition string from SchemaAttribute protocol."""
        return FlextLdifUtilitiesSchema._write_schema_element(
            attr_data,
            m.Ldif.SchemaAttribute,
            "attr_data",
            FlextLdifUtilitiesSchema._build_attribute_parts_from_model,
        )

    @staticmethod
    def write_objectclass(oc_data: p.Ldif.SchemaObjectClass) -> str:
        """Write RFC 4512 objectClass definition string from SchemaObjectClass protocol."""
        return FlextLdifUtilitiesSchema._write_schema_element(
            oc_data,
            m.Ldif.SchemaObjectClass,
            "oc_data",
            FlextLdifUtilitiesSchema._build_objectclass_parts_from_model,
        )


__all__: list[str] = ["FlextLdifUtilitiesSchema"]
