"""Extracted nested class from FlextLdifUtilities."""

from __future__ import annotations

import base64
import re
from collections.abc import (
    Mapping,
    MutableMapping,
    MutableSequence,
)

from flext_core import u

from flext_ldif import (
    FlextLdifUtilitiesOID as uo,
    FlextLdifUtilitiesServer as us,
    c,
    m,
    r,
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
            us.normalize_server_type(server_type)
            if server_type
            else us.normalize_server_type("rfc")
        )
        if metadata_extensions:
            extensions_typed: t.Ldif.MutableMetadataMapping = {}
            for key, val in metadata_extensions.items():
                extensions_typed[key] = list(val)
            return m.Ldif.QuirkMetadata(
                quirk_type=quirk_type,
                extensions=m.Ldif.DynamicMetadata.from_dict(
                    extensions_typed,
                ),
            )
        return None

    @staticmethod
    def append_attribute_value(
        attributes: t.MutableStrSequenceMapping,
        attribute_metadata: MutableMapping[str, t.MutableAttributeMapping],
        attr_name: str,
        value: str,
        value_origin: c.Ldif.ValueOrigin,
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
        value_origin: c.Ldif.ValueOrigin | None = None
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
    ) -> tuple[str, c.Ldif.ValueOrigin, str | None]:
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
        changetype: c.Ldif.LdifChangeType | None = None
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
                c.Ldif.LdifChangeType.MODDN,
                c.Ldif.LdifChangeType.MODRDN,
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
            if changetype == c.Ldif.LdifChangeType.MODIFY:
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
        validate_result = uo.validate_format(syntax)
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

        def _as_str_list(value: t.JsonValue) -> MutableSequence[str] | None:
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
                str_list = _as_str_list(value)
                if str_list is not None:
                    extensions[key] = str_list
            return extensions
        extensions_metadata = m.Ldif.DynamicMetadata.from_dict({
            str(key): u.normalize_to_metadata(value) for key, value in result.items()
        })
        strict_result: t.MutableStrSequenceMapping = {}
        for key, value in extensions_metadata.items():
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
        x_pattern = re.compile(c.Ldif.SCHEMA_X_EXTENSION, re.IGNORECASE)
        for match in x_pattern.finditer(definition):
            key = f"X-{match.group(1)}"
            value = match.group(2).strip()
            extensions[key] = [value]
        desc_pattern = re.compile(c.Ldif.SCHEMA_DESC_FLEX)
        desc_match = desc_pattern.search(definition)
        if desc_match:
            extensions["DESC"] = [desc_match.group(1)]
        ordering_pattern = re.compile(c.Ldif.SCHEMA_ORDERING_TOKEN)
        ordering_match = ordering_pattern.search(definition)
        if ordering_match:
            extensions["ORDERING"] = [ordering_match.group(1)]
        substr_pattern = re.compile(c.Ldif.SCHEMA_SUBSTR_TOKEN)
        substr_match = substr_pattern.search(definition)
        if substr_match:
            extensions["SUBSTR"] = [substr_match.group(1)]
        return extensions

    @staticmethod
    def extract_oid(definition: str) -> r[str]:
        """Extract OID from schema definition string."""
        if not definition:
            return r[str].fail("Empty definition: cannot extract OID")
        oid_pattern = re.compile(c.Ldif.SCHEMA_OID_CAPTURE)
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


__all__: list[str] = ["FlextLdifUtilitiesParser"]
