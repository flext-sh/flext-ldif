"""Extracted nested class from FlextLdifUtilities."""

from __future__ import annotations

import base64
import contextlib
import re
from collections.abc import Mapping, MutableMapping, MutableSequence
from typing import TypeIs

from flext_core import r, u
from flext_ldif import (
    FlextLdifModelsMetadata,
    FlextLdifUtilitiesOID,
    FlextLdifUtilitiesServer,
    c,
    m,
    t,
)

logger = u.fetch_logger(__name__)


class FlextLdifUtilitiesParser:
    """Generic LDIF parsing utilities - simple helper functions."""

    @staticmethod
    def _build_attribute_metadata(
        attr_definition: str,
        syntax: str | None,
        syntax_validation_error: str | None,
        server_type: str | None = None,
    ) -> m.Ldif.QuirkMetadata | None:
        """Build metadata for attribute including extensions."""
        metadata_extensions = FlextLdifUtilitiesParser.extract_extensions(
            attr_definition,
        )
        if syntax:
            metadata_extensions["syntax_oid_valid"] = [
                str(syntax_validation_error is None),
            ]
            if syntax_validation_error:
                metadata_extensions["syntax_validation_error"] = [
                    syntax_validation_error,
                ]
        metadata_extensions["original_format"] = [attr_definition.strip()]
        metadata_extensions["schema_original_string_complete"] = [attr_definition]
        quirk_type = (
            FlextLdifUtilitiesServer.normalize_server_type(server_type)
            if server_type
            else FlextLdifUtilitiesServer.normalize_server_type("rfc")
        )
        if metadata_extensions:
            extensions_typed: t.MutableStrSequenceMapping = {}
            for key, val in metadata_extensions.items():
                extensions_typed[key] = list(val)
            return m.Ldif.QuirkMetadata(
                quirk_type=quirk_type,
                extensions=FlextLdifModelsMetadata.DynamicMetadata.from_dict(
                    extensions_typed,
                ),
            )
        return None

    @staticmethod
    def _process_ldif_line(
        line: str,
        current_dn: str | None,
        current_attrs: t.Ldif.MutableEntryAttributesDict,
        entries: MutableSequence[tuple[str, t.Ldif.MutableEntryAttributesDict]],
    ) -> tuple[str | None, t.Ldif.MutableEntryAttributesDict]:
        """Process single LDIF line with RFC 2849 base64 detection."""
        if not line:
            if current_dn is not None:
                entries.append((current_dn, current_attrs))
            return (None, {})
        if line.startswith("#"):
            return (current_dn, current_attrs)
        if c.Ldif.LDIF_REGULAR_INDICATOR not in line:
            return (current_dn, current_attrs)
        original_line = line
        is_base64 = False
        if c.Ldif.LDIF_BASE64_INDICATOR in line:
            key, value = line.split(c.Ldif.LDIF_BASE64_INDICATOR, 1)
            key = key.strip()
            value = value.strip()
            is_base64 = True
            with contextlib.suppress(ValueError, UnicodeDecodeError):
                value = base64.b64decode(value).decode(c.DEFAULT_ENCODING)
        else:
            key, _, value = line.partition(c.Ldif.LDIF_REGULAR_INDICATOR)
            key = key.strip()
            value = value.lstrip()
        if key.lower() == "dn":
            if current_dn is not None:
                entries.append((current_dn, current_attrs))
            new_attrs: t.Ldif.MutableEntryAttributesDict = {}
            if is_base64:
                new_attrs["_base64_dn"] = ["true"]
            new_attrs["_original_dn_line"] = [original_line]
            return (value, new_attrs)
        if "_original_lines" not in current_attrs:
            original_lines_list: MutableSequence[str] = []
            current_attrs["_original_lines"] = original_lines_list
        current_attrs["_original_lines"].append(original_line)
        current_attrs.setdefault(key, []).append(value)
        return (current_dn, current_attrs)

    @staticmethod
    def append_attribute_value(
        attributes: t.MutableStrSequenceMapping,
        attribute_metadata: MutableMapping[str, t.MutableAttributeMapping],
        attr_name: str,
        value: str,
        value_origin: c.Ldif.ValueOriginLiteral,
        raw_value: str | None,
    ) -> None:
        """Append value while tracking its RFC serialization details."""
        attributes.setdefault(attr_name, []).append(value)
        metadata = attribute_metadata.setdefault(attr_name, {})
        value_origins = metadata.setdefault("value_origins", [])
        if isinstance(value_origins, list):
            value_origins.append(str(value_origin))
        if raw_value is None:
            return
        raw_values = metadata.setdefault("raw_values", [])
        if isinstance(raw_values, list):
            raw_values.append(raw_value)

    @staticmethod
    def build_control(payload: str) -> m.Ldif.Control:
        """Parse RFC 2849 control payload into a structured model."""
        minimum_control_tokens = 2
        control_tokens_with_value = 3
        tokens = payload.split(maxsplit=2)
        control_type = tokens[0] if tokens else ""
        criticality: bool | None = None
        value: str | None = None
        value_origin: c.Ldif.ValueOriginLiteral | None = None
        raw_value: str | None = None
        value_token: str | None = None
        if len(tokens) >= minimum_control_tokens:
            if tokens[1].lower() in {"true", "false"}:
                criticality = tokens[1].lower() == "true"
                if len(tokens) == control_tokens_with_value:
                    value_token = tokens[2]
            else:
                value_token = " ".join(tokens[1:])
        if value_token is not None:
            value, value_origin, raw_value = FlextLdifUtilitiesParser.decode_value(
                value_token,
            )
        return m.Ldif.Control(
            control_type=control_type,
            criticality=criticality,
            value=value,
            value_origin=value_origin,
            raw_value=raw_value,
        )

    @staticmethod
    def build_rfc_entry_metadata(
        dn: str,
        raw_record_lines: MutableSequence[str],
        comments: MutableSequence[str],
    ) -> m.Ldif.QuirkMetadata:
        """Build RFC metadata for a parsed LDIF record."""
        metadata = m.Ldif.QuirkMetadata.create_for("rfc")
        metadata.original_server_type = c.Ldif.ServerTypes.RFC
        metadata.target_server_type = c.Ldif.ServerTypes.RFC
        metadata.original_strings["dn_original"] = dn
        metadata.original_strings["entry_original_ldif"] = "\n".join(raw_record_lines)
        if comments:
            metadata.extensions["entry_comments"] = list(comments)
        return metadata

    @staticmethod
    def decode_value(
        remainder: str,
    ) -> tuple[str, c.Ldif.ValueOriginLiteral, str | None]:
        """Decode an LDIF value-spec preserving origin details."""
        payload = remainder.lstrip()
        if payload.startswith(":"):
            encoded_value = payload[1:].lstrip()
            try:
                decoded_value = base64.b64decode(encoded_value).decode(
                    c.DEFAULT_ENCODING,
                    errors="replace",
                )
            except ValueError:
                decoded_value = encoded_value
            return (decoded_value, c.Ldif.ValueOrigin.BASE64, encoded_value)
        if payload.startswith("<"):
            url_value = payload[1:].lstrip()
            origin = (
                c.Ldif.ValueOrigin.FILE
                if url_value.startswith("file://")
                else c.Ldif.ValueOrigin.URL
            )
            return (url_value, origin, url_value)
        return (payload, c.Ldif.ValueOrigin.PLAIN, payload)

    @staticmethod
    def finalize_change_operation(
        current_op: m.Ldif.ChangeOperation | None,
        change_operations: MutableSequence[m.Ldif.ChangeOperation],
    ) -> None:
        """Append a pending modify block when present."""
        if current_op is not None:
            change_operations.append(current_op)

    @staticmethod
    def parse_ldif_record(
        lines: MutableSequence[str],
    ) -> r[m.Ldif.Entry]:
        """Parse a single unfolded LDIF record into Entry."""
        dn = ""
        attrs: t.MutableStrSequenceMapping = {}
        attribute_metadata: MutableMapping[str, t.MutableAttributeMapping] = {}
        comments: MutableSequence[str] = []
        raw_record_lines: MutableSequence[str] = []
        controls: MutableSequence[m.Ldif.Control] = []
        change_operations: MutableSequence[m.Ldif.ChangeOperation] = []
        current_change_operation: m.Ldif.ChangeOperation | None = None
        changetype: c.Ldif.LdifChangeTypeLiteral | None = None
        record_kind = c.Ldif.RecordKind.CONTENT
        newrdn: str | None = None
        deleteoldrdn: bool | None = None
        newsuperior: str | None = None
        modify_ops = {
            "add": c.Ldif.ChangeOperation.ADD,
            "delete": c.Ldif.ChangeOperation.DELETE,
            "replace": c.Ldif.ChangeOperation.REPLACE,
            "increment": c.Ldif.ChangeOperation.INCREMENT,
        }
        for raw_line in lines:
            line = raw_line.rstrip()
            if not line:
                continue
            if line.startswith("#"):
                comments.append(line)
                continue
            raw_record_lines.append(line)
            if line == "-":
                FlextLdifUtilitiesParser.finalize_change_operation(
                    current_change_operation,
                    change_operations,
                )
                current_change_operation = None
                continue
            if ":" not in line:
                continue
            key, _, remainder = line.partition(":")
            key = key.strip()
            key_lower = key.lower()
            if key_lower == "control":
                controls.append(
                    FlextLdifUtilitiesParser.build_control(remainder.lstrip())
                )
                continue
            value, value_origin, raw_value = FlextLdifUtilitiesParser.decode_value(
                remainder,
            )
            if key_lower == "dn":
                dn = value
                continue
            if key_lower == "changetype":
                normalized_change_type = value.lower()
                try:
                    changetype = c.Ldif.LdifChangeType(normalized_change_type)
                except ValueError:
                    changetype = None
                    continue
                record_kind = c.Ldif.RecordKind.CHANGE
                continue
            if changetype in {
                c.Ldif.ChangeTypeOperations.MODDN,
                c.Ldif.ChangeTypeOperations.MODRDN,
            }:
                if key_lower == "newrdn":
                    newrdn = value
                    continue
                if key_lower == "deleteoldrdn":
                    deleteoldrdn = value.lower() in {"1", "true", "yes"}
                    continue
                if key_lower == "newsuperior":
                    newsuperior = value
                    continue
            if changetype == c.Ldif.ChangeTypeOperations.MODIFY:
                if key_lower in modify_ops:
                    FlextLdifUtilitiesParser.finalize_change_operation(
                        current_change_operation,
                        change_operations,
                    )
                    current_change_operation = m.Ldif.ChangeOperation(
                        operation=modify_ops[key_lower],
                        attribute=value,
                    )
                    continue
                if current_change_operation is not None:
                    current_change_operation.values.append(
                        m.Ldif.ChangeOperationValue(
                            value=value,
                            value_origin=value_origin,
                            raw_value=raw_value,
                        ),
                    )
                    FlextLdifUtilitiesParser.append_attribute_value(
                        attrs,
                        attribute_metadata,
                        current_change_operation.attribute,
                        value,
                        value_origin,
                        raw_value,
                    )
                    continue
            FlextLdifUtilitiesParser.append_attribute_value(
                attrs,
                attribute_metadata,
                key,
                value,
                value_origin,
                raw_value,
            )
        FlextLdifUtilitiesParser.finalize_change_operation(
            current_change_operation,
            change_operations,
        )
        if not dn:
            return r[m.Ldif.Entry].fail("No DN found in entry")
        try:
            entry = m.Ldif.Entry(
                dn=m.Ldif.DN(value=dn.strip()),
                attributes=m.Ldif.Attributes.model_validate({
                    "attributes": attrs,
                    "attribute_metadata": attribute_metadata,
                }),
                record_kind=record_kind,
                controls=list(controls),
                change_operations=list(change_operations),
                changetype=changetype,
                newrdn=newrdn,
                deleteoldrdn=deleteoldrdn,
                newsuperior=newsuperior,
                raw_record_lines=list(raw_record_lines),
                metadata=FlextLdifUtilitiesParser.build_rfc_entry_metadata(
                    dn.strip(),
                    raw_record_lines,
                    comments,
                ),
            )
            return r[m.Ldif.Entry].ok(entry)
        except ValueError as exc:
            return r[m.Ldif.Entry].fail(f"Failed to create entry {dn}: {exc}")

    @staticmethod
    def split_ldif_records(ldif_content: str) -> MutableSequence[MutableSequence[str]]:
        """Split unfolded LDIF content into record blocks."""
        unfolded_lines = FlextLdifUtilitiesParser.unfold_lines(ldif_content)
        records: MutableSequence[MutableSequence[str]] = []
        current_record: MutableSequence[str] = []
        for raw_line in unfolded_lines:
            line = raw_line.rstrip("\r")
            if not current_record and line.lower().startswith("version:"):
                continue
            if not line.strip():
                if current_record:
                    records.append(current_record)
                    current_record = []
                continue
            current_record.append(line)
        if current_record:
            records.append(current_record)
        return records

    @staticmethod
    def _validate_syntax_oid(syntax: str | None) -> str | None:
        """Validate syntax OID format."""
        if syntax is None or not syntax.strip():
            return None
        validate_result = FlextLdifUtilitiesOID.validate_format(syntax)
        if validate_result.failure:
            return f"Syntax OID validation failed: {validate_result.error}"
        if not validate_result.value:
            return f"Invalid syntax OID format: {syntax}"
        return None

    @staticmethod
    def ext(
        metadata: m.Ldif.DynamicMetadata,
    ) -> t.MutableStrSequenceMapping:
        """Extract extension information from parsed metadata."""

        def _is_metadata_value(
            value: t.NormalizedValue,
        ) -> TypeIs[t.Ldif.MetadataValue]:
            return value is None or isinstance(
                value,
                (str, int, float, bool, list, Mapping),
            )

        def _as_str_list(value: t.Ldif.MetadataValue) -> MutableSequence[str] | None:
            if isinstance(value, list):
                normalized: MutableSequence[str] = []
                for item in value:
                    if not isinstance(item, str):
                        return None
                    normalized.append(item)
                return normalized
            return None

        result = metadata.get("extensions")
        if not isinstance(result, Mapping):
            extensions: t.MutableStrSequenceMapping = {}
            for key, value in metadata.items():
                if not _is_metadata_value(value):
                    continue
                str_list = _as_str_list(value)
                if str_list is not None:
                    extensions[key] = str_list
            return extensions
        extensions_metadata = FlextLdifModelsMetadata.DynamicMetadata.from_dict(result)
        strict_result: t.MutableStrSequenceMapping = {}
        for key, value in extensions_metadata.items():
            if not _is_metadata_value(value):
                continue
            str_list = _as_str_list(value)
            if str_list is not None:
                strict_result[key] = str_list
        return strict_result

    @staticmethod
    def extract_boolean_flag(definition: str, pattern: re.Pattern[str] | str) -> bool:
        """Check if boolean flag exists in definition."""
        if not definition:
            return False
        if isinstance(pattern, str):
            pattern = re.compile(pattern)
        return re.search(pattern, definition) is not None

    @staticmethod
    def extract_extensions(
        definition: str,
    ) -> t.MutableStrSequenceMapping:
        """Extract extension information from schema definition string."""
        if not definition:
            return {}
        extensions: t.MutableStrSequenceMapping = {}
        x_pattern = re.compile(
            r"X-([A-Z0-9_-]+)\s+[\"']?([^\"']*)[\"']?(?:\s|$)",
            re.IGNORECASE,
        )
        for match in x_pattern.finditer(definition):
            key = f"X-{match.group(1)}"
            value = match.group(2).strip()
            extensions[key] = [value]
        desc_pattern = re.compile(r"DESC\s+['\\\"]([^'\\\"]*)['\\\"]")
        desc_match = desc_pattern.search(definition)
        if desc_match:
            extensions["DESC"] = [desc_match.group(1)]
        ordering_pattern = re.compile(r"ORDERING\s+([A-Za-z0-9_-]+)")
        ordering_match = ordering_pattern.search(definition)
        if ordering_match:
            extensions["ORDERING"] = [ordering_match.group(1)]
        substr_pattern = re.compile(r"SUBSTR\s+([A-Za-z0-9_-]+)")
        substr_match = substr_pattern.search(definition)
        if substr_match:
            extensions["SUBSTR"] = [substr_match.group(1)]
        return extensions

    @staticmethod
    def extract_oid(definition: str) -> r[str]:
        """Extract OID from schema definition string."""
        if not definition:
            return r[str].fail("Empty definition: cannot extract OID")
        oid_pattern = re.compile(r"\(\s*([0-9.]+)")
        match = re.match(oid_pattern, definition.strip())
        if match:
            return r[str].ok(match.group(1))
        return r[str].fail(f"missing an OID in definition: {definition!r}")

    @staticmethod
    def extract_optional_field(
        definition: str,
        pattern: re.Pattern[str] | str,
        default: str | None = None,
    ) -> str | None:
        """Extract optional field via regex pattern."""
        if not definition:
            return default
        if isinstance(pattern, str):
            pattern = re.compile(pattern)
        match = re.search(pattern, definition)
        return match.group(1) if match else default

    @staticmethod
    def extract_regex_field(
        definition: str,
        pattern: str,
        default: str | None = None,
    ) -> str | None:
        """Extract field from definition using regex pattern."""
        match = re.search(pattern, definition)
        return match.group(1) if match else default

    @staticmethod
    def extract_syntax_and_length(definition: str) -> tuple[str | None, int | None]:
        """Extract syntax OID and optional length from definition."""
        syntax_match = re.search(c.Ldif.SCHEMA_SYNTAX_LENGTH, definition)
        if not syntax_match:
            return (None, None)
        syntax = syntax_match.group(1)
        length = int(syntax_match.group(2)) if syntax_match.group(2) else None
        return (syntax, length)

    @staticmethod
    def finalize_pending_attribute(
        current_attr: str | None,
        current_values: MutableSequence[str],
        entry_dict: t.Ldif.MutableRawEntryDict,
    ) -> None:
        """Finalize and save pending attribute to entry dictionary."""
        if not current_attr or not current_values:
            return
        if current_attr == "_base64_attrs":
            return
        if len(current_values) == 1:
            entry_dict[current_attr] = current_values[0]
        else:
            entry_dict[current_attr] = [*current_values]

    @staticmethod
    def handle_multivalued_attribute(
        attr_name: str,
        attr_value: str,
        entry_dict: t.Ldif.MutableRawEntryDict,
    ) -> bool:
        """Handle multi-valued attribute accumulation."""
        if attr_name not in entry_dict or attr_name == "_base64_attrs":
            return False
        existing = entry_dict[attr_name]
        if isinstance(existing, set):
            entry_dict[attr_name] = [*existing, attr_value]
            return True
        if isinstance(existing, str):
            entry_dict[attr_name] = [existing, attr_value]
        else:
            existing_list: MutableSequence[str]
            existing_list = [str(item) for item in existing]
            existing_list.append(attr_value)
            entry_dict[attr_name] = existing_list
        return True

    @staticmethod
    def parse_attribute_line(line: str) -> r[tuple[str, str, bool]]:
        """Parse LDIF attribute line into name, value, and base64 flag."""
        if ":" not in line:
            return r[tuple[str, str, bool]].fail(
                f"No colon separator in line: {line!r}",
            )
        attr_name, attr_value = line.split(":", 1)
        attr_name = attr_name.strip()
        attr_value = attr_value.strip()
        is_base64 = False
        if attr_value.startswith(":"):
            is_base64 = True
            attr_value = attr_value[1:].strip()
        return r[tuple[str, str, bool]].ok((attr_name, attr_value, is_base64))

    @staticmethod
    def track_base64_attribute(
        attr_name: str, entry_dict: t.Ldif.MutableRawEntryDict
    ) -> None:
        """Track attribute that uses base64 encoding."""
        if "_base64_attrs" not in entry_dict:
            entry_dict["_base64_attrs"] = set[str]()
        if isinstance(entry_dict["_base64_attrs"], set):
            entry_dict["_base64_attrs"].add(attr_name)

    @staticmethod
    def unfold_lines(ldif_content: str) -> MutableSequence[str]:
        """Unfold LDIF lines folded across multiple lines per RFC 2849 §3."""
        lines: MutableSequence[str] = []
        current_line: str | None = None
        # c.Ldif.LINE_CONTINUATION_SPACE = c.Ldif.LINE_CONTINUATION_SPACE
        for raw_line in ldif_content.split(c.Ldif.LINE_SEPARATOR):
            if (
                raw_line.startswith(c.Ldif.LINE_CONTINUATION_SPACE) and current_line
            ) or (raw_line.startswith("\t") and current_line):
                current_line += raw_line[1:]
                continue
            if current_line is not None:
                lines.append(current_line)
            if not raw_line:
                lines.append("")
                current_line = None
                continue
            current_line = raw_line
        if current_line is not None:
            lines.append(current_line)
        return lines


__all__ = ["FlextLdifUtilitiesParser"]
