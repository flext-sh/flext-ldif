"""Extracted nested class from FlextLdifUtilities."""

from __future__ import annotations

import base64
import contextlib
import re

from flext_core import FlextLogger, FlextRuntime
from pydantic import BaseModel, ConfigDict, Field

from flext_ldif._models.metadata import FlextLdifModelsMetadata
from flext_ldif._utilities.oid import FlextLdifUtilitiesOID
from flext_ldif._utilities.server import FlextLdifUtilitiesServer
from flext_ldif.constants import c
from flext_ldif.models import m
from flext_ldif.typings import t

logger = FlextLogger(__name__)


class MetadataModel(BaseModel):
    """Pydantic model for parsed metadata structures. Replaces TypedDict."""

    model_config = ConfigDict(frozen=False, extra="allow")

    extensions: t.Ldif.Extensions.ExtensionsDict | None = Field(default=None)


MetadataDict = MetadataModel


class FlextLdifUtilitiesParser:
    """Generic LDIF parsing utilities - simple helper functions."""

    @staticmethod
    def ext(
        metadata: MetadataModel,
    ) -> t.Ldif.Extensions.ExtensionsDict:
        """Extract extension information from parsed metadata."""
        result = metadata.extensions
        if result is None or not isinstance(result, dict):
            empty: t.Ldif.Extensions.ExtensionsDict = {}
            return empty
        return result

    @staticmethod
    def extract_oid(definition: str) -> str | None:
        """Extract OID from schema definition string."""
        if not definition or not isinstance(definition, str):
            return None

        oid_pattern = re.compile(r"\(\s*([0-9.]+)")
        match = re.match(oid_pattern, definition.strip())
        return match.group(1) if match else None

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
    def extract_boolean_flag(
        definition: str,
        pattern: re.Pattern[str] | str,
    ) -> bool:
        """Check if boolean flag exists in definition."""
        if not definition:
            return False

        if isinstance(pattern, str):
            pattern = re.compile(pattern)

        return re.search(pattern, definition) is not None

    @staticmethod
    def extract_extensions(
        definition: str,
    ) -> t.Ldif.Extensions.ExtensionsDict:
        """Extract extension information from schema definition string."""
        if not definition or not isinstance(definition, str):
            return {}

        extensions: t.Ldif.Extensions.ExtensionsDict = {}

        x_pattern = re.compile(
            r'X-([A-Z0-9_-]+)\s+["\']?([^"\']*)["\']?(?:\s|$)',
            re.IGNORECASE,
        )
        for match in x_pattern.finditer(definition):
            key = f"X-{match.group(1)}"
            value = match.group(2).strip()
            extensions[key] = [value]

        desc_pattern = re.compile(r"DESC\s+['\"]([^'\"]*)['\"]")
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
    def unfold_lines(ldif_content: str) -> list[str]:
        """Unfold LDIF lines folded across multiple lines per RFC 2849 §3."""
        lines: list[str] = []
        current_line = ""
        continuation_space = c.Ldif.Format.LINE_CONTINUATION_SPACE

        for raw_line in ldif_content.split(c.Ldif.Format.LINE_SEPARATOR):
            if (raw_line.startswith(continuation_space) and current_line) or (
                raw_line.startswith("\t") and current_line
            ):
                current_line += raw_line[1:]
            else:
                if current_line:
                    lines.append(current_line)
                current_line = raw_line

        if current_line:
            lines.append(current_line)

        return lines

    @staticmethod
    def _process_ldif_line(
        line: str,
        current_dn: str | None,
        current_attrs: m.Ldif.EntryAttributesDict,
        entries: list[tuple[str, m.Ldif.EntryAttributesDict]],
    ) -> tuple[str | None, m.Ldif.EntryAttributesDict]:
        """Process single LDIF line with RFC 2849 base64 detection."""
        if not line:
            if current_dn is not None:
                entries.append((current_dn, current_attrs))
            return None, {}

        if line.startswith("#"):
            return current_dn, current_attrs

        if c.Ldif.LDIF_REGULAR_INDICATOR not in line:
            return current_dn, current_attrs

        original_line = line

        is_base64 = False
        if c.Ldif.LDIF_BASE64_INDICATOR in line:
            key, value = line.split(c.Ldif.LDIF_BASE64_INDICATOR, 1)
            key = key.strip()
            value = value.strip()
            is_base64 = True

            with contextlib.suppress(ValueError, UnicodeDecodeError):
                value = base64.b64decode(value).decode(
                    c.Ldif.LDIF_DEFAULT_ENCODING,
                )
        else:
            key, _, value = line.partition(c.Ldif.LDIF_REGULAR_INDICATOR)
            key = key.strip()
            value = value.lstrip()  # Preserve trailing spaces per RFC 2849

        if key.lower() == "dn":
            if current_dn is not None:
                entries.append((current_dn, current_attrs))

            new_attrs: m.Ldif.EntryAttributesDict = {}
            if is_base64:
                new_attrs["_base64_dn"] = ["true"]

            new_attrs["_original_dn_line"] = [original_line]

            return value, new_attrs

        if "_original_lines" not in current_attrs:
            current_attrs["_original_lines"] = []
        current_attrs["_original_lines"].append(original_line)

        current_attrs.setdefault(key, []).append(value)
        return current_dn, current_attrs

    @staticmethod
    def parse_ldif_lines(
        ldif_content: str,
    ) -> list[tuple[str, m.Ldif.EntryAttributesDict]]:
        """Parse LDIF content into (dn, attributes_dict) tuples - RFC 2849 compliant."""
        if not ldif_content or not isinstance(ldif_content, str):
            return []

        entries: list[tuple[str, m.Ldif.EntryAttributesDict]] = []
        current_dn: str | None = None
        current_attrs: m.Ldif.EntryAttributesDict = {}
        unfolded_lines = FlextLdifUtilitiesParser.unfold_lines(ldif_content)

        for raw_line in unfolded_lines:
            line = raw_line.rstrip("\r\n").strip()
            current_dn, current_attrs = FlextLdifUtilitiesParser._process_ldif_line(
                line,
                current_dn,
                current_attrs,
                entries,
            )

        if current_dn is not None:
            entries.append((current_dn, current_attrs))
        return entries

    @staticmethod
    def parse_attribute_line(line: str) -> tuple[str, str, bool] | None:
        """Parse LDIF attribute line into name, value, and base64 flag."""
        if ":" not in line:
            return None

        attr_name, attr_value = line.split(":", 1)
        attr_name = attr_name.strip()
        attr_value = attr_value.strip()

        is_base64 = False
        if attr_value.startswith(":"):
            is_base64 = True
            attr_value = attr_value[1:].strip()

        return (attr_name, attr_value, is_base64)

    @staticmethod
    def finalize_pending_attribute(
        current_attr: str | None,
        current_values: list[str],
        entry_dict: m.Ldif.RawEntryDict,
    ) -> None:
        """Finalize and save pending attribute to entry dictionary."""
        if not current_attr or not current_values:
            return

        if current_attr == "_base64_attrs":
            return

        if len(current_values) == 1:
            entry_dict[current_attr] = current_values[0]
        else:
            entry_dict[current_attr] = current_values

    @staticmethod
    def handle_multivalued_attribute(
        attr_name: str,
        attr_value: str,
        entry_dict: m.Ldif.RawEntryDict,
    ) -> bool:
        """Handle multi-valued attribute accumulation."""
        if attr_name not in entry_dict or attr_name == "_base64_attrs":
            return False

        existing = entry_dict[attr_name]
        if isinstance(existing, set):
            entry_dict[attr_name] = [*existing, attr_value]
            return True
        if not FlextRuntime.is_list_like(existing):
            if isinstance(existing, str):
                entry_dict[attr_name] = [existing, attr_value]
            else:
                entry_dict[attr_name] = [str(existing), attr_value]
        else:
            existing_list = (
                list(existing) if not isinstance(existing, list) else existing
            )
            existing_list.append(attr_value)
            entry_dict[attr_name] = [
                str(item) if not isinstance(item, str) else item
                for item in existing_list
            ]

        return True

    @staticmethod
    def track_base64_attribute(
        attr_name: str,
        entry_dict: m.Ldif.RawEntryDict,
    ) -> None:
        """Track attribute that uses base64 encoding."""
        if "_base64_attrs" not in entry_dict:
            entry_dict["_base64_attrs"] = set()

        if isinstance(entry_dict["_base64_attrs"], set):
            entry_dict["_base64_attrs"].add(attr_name)

    @staticmethod
    def parse_ldif(
        ldif_lines: list[str],
    ) -> list[m.Ldif.RawEntryDict]:
        """Parse list of LDIF lines into entries (simple version)."""
        entries: list[m.Ldif.RawEntryDict] = []
        current_entry: m.Ldif.RawEntryDict = {}

        for line in ldif_lines:
            if not line.strip():
                if current_entry:
                    entries.append(current_entry)
                    current_entry = {}
                continue

            if ":" in line:
                key, value = line.split(":", 1)
                current_entry[key.strip()] = value.strip()

        if current_entry:
            entries.append(current_entry)

        return entries

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
    def extract_syntax_and_length(
        definition: str,
    ) -> tuple[str | None, int | None]:
        """Extract syntax OID and optional length from definition."""
        syntax_match = re.search(
            c.Ldif.LdifPatterns.SCHEMA_SYNTAX_LENGTH,
            definition,
        )
        if not syntax_match:
            return (None, None)

        syntax = syntax_match.group(1)

        length = int(syntax_match.group(2)) if syntax_match.group(2) else None

        return (syntax, length)

    @staticmethod
    def _validate_syntax_oid(syntax: str | None) -> str | None:
        """Validate syntax OID format."""
        if syntax is None or not syntax.strip():
            return None

        validate_result = FlextLdifUtilitiesOID.validate_format(syntax)
        if validate_result.is_failure:
            return f"Syntax OID validation failed: {validate_result.error}"
        if not validate_result.value:
            return f"Invalid syntax OID format: {syntax}"

        return None

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
            extensions_typed: dict[str, t.MetadataAttributeValue] = {}
            for key, val in metadata_extensions.items():
                typed_val: t.MetadataAttributeValue = list(val)
                extensions_typed[key] = typed_val
            return m.Ldif.QuirkMetadata(
                quirk_type=quirk_type,
                extensions=FlextLdifModelsMetadata.DynamicMetadata.from_dict(
                    extensions_typed,
                ),
            )

        return None


__all__ = [
    "FlextLdifUtilitiesParser",
]
