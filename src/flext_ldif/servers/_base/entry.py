"""Base Quirk Classes for LDIF/LDAP Server Extensions.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Defines base classes for implementing server-specific quirks that extend
RFC-compliant LDIF/LDAP parsing with vendor-specific features.

Quirks allow extending the RFC base without modifying core parser logic.

ARCHITECTURE:
    Base classes use Python 3.13+ abstract base classes (ABC) with
    decorators for explicit inheritance contracts, while also implementing
    all methods required by p for structural typing
    validation.

    This dual approach provides:
    - Explicit inheritance contracts through ABC
    - Structural typing validation through protocols
    - isinstance() checks for protocol compliance
    - Type safety at development and runtime

PROTOCOL COMPLIANCE:
    All base classes and implementations MUST satisfy corresponding protocols:
    - FlextLdifServersBase.Schema -> SchemaProtocol (structural typing)
    - FlextLdifServersBase.Acl -> AclProtocol (structural typing)
    - FlextLdifServersBase.Entry -> EntryProtocol (structural typing)

    All method signatures must match protocol definitions exactly for type safety.
"""

from __future__ import annotations

import base64
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import ClassVar

from flext_core import FlextLogger, FlextResult, FlextService
from pydantic import Field

from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif._models.settings import FlextLdifModelsSettings
from flext_ldif.constants import c
from flext_ldif.models import m
from flext_ldif.servers._base.constants import QuirkMethodsMixin
from flext_ldif.typings import t

logger = FlextLogger(__name__)


class FlextLdifServersBaseEntry(
    QuirkMethodsMixin,
    FlextService[m.Ldif.Entry | str],
):
    """Base class for entry processing quirks - satisfies EntryProtocol (structural typing).

    NOTE: This is an implementation detail - DO NOT import directly.
    Use FlextLdifServersBase.Entry instead.

    Entry quirks handle server-specific entry attributes and transformations
    for LDAP entry processing.

    **STANDARDIZED CONSTANTS REQUIRED**: Each Entry implementation MUST define
    a Constants nested class with:
    - CANONICAL_NAME: Unique server identifier (e.g., "oid", "oud")
    - ALIASES: All valid names for this server including canonical
    - PRIORITY: Selection priority (lower = higher priority)
    - CAN_NORMALIZE_FROM: What source types this quirk can normalize
    - CAN_DENORMALIZE_TO: What target types this quirk can denormalize to


    **Protocol Compliance**: All implementations MUST satisfy
    EntryProtocol through structural typing (hasattr checks).
    This means all public methods must match protocol signatures exactly.

    **Validation**: Use hasattr(quirk, "parse") and hasattr(quirk, "write")
    to check protocol compliance at runtime (structural typing).

    Common entry transformation patterns:
    - Vendor operational attributes
    - Configuration entries (e.g., cn=config subtree)
    - Vendor-specific attributes
    - Server-specific DN formats
    - RFC baseline entry handling

    """

    # Protocol-required fields
    server_type: str = "unknown"
    """Server type identifier."""

    priority: int = 0
    """Quirk priority (lower number = higher priority)."""

    # Registry method for DI-based automatic registration
    # NOTE: server_type and priority are ClassVar in the PARENT SERVER CLASS ONLY
    # NOT in nested Schema/Acl/Entry classes
    # (e.g., FlextLdifServersOid.server_type, FlextLdifServersOid.priority)
    # All constants must be in FlextLdifServers[Server].Constants, NOT in subclasses

    # Parent quirk reference for accessing server-level configuration
    parent_quirk: object | None = Field(
        default=None,
        exclude=True,
        repr=False,
        description=("Reference to parent quirk instance for server-level access"),
    )

    def __init__(
        self,
        entry_service: object | None = None,
        _parent_quirk: object | None = None,
        **kwargs: str | float | bool | None,
    ) -> None:
        """Initialize entry quirk service with optional DI service injection.

        Args:
            entry_service: Injected FlextLdifEntry service (optional, lazy-created if None)
            **kwargs: Passed to FlextService for initialization (includes parent_quirk)

        Note:
            server_type and priority are no longer passed to nested classes.
            They should be accessed via _get_server_type() and Constants.PRIORITY
            from the parent server class.

        """
        super().__init__(**kwargs)
        self._entry_service = entry_service  # Store for use by subclasses
        # Store _parent_quirk using object.__setattr__ to avoid Pydantic validation
        # (it's not a Pydantic field, just an internal reference)
        if _parent_quirk is not None:
            object.__setattr__(self, "_parent_quirk", _parent_quirk)
        # Note: server_type and priority descriptors are only available on parent server classes
        # Nested classes (Schema/Acl/Entry) access them via _get_server_type() when needed
        # _get_server_type(), _get_priority(), _get_parent_quirk_safe()
        # are inherited from QuirkMethodsMixin

    # Control auto-execution
    auto_execute: ClassVar[bool] = False

    # =====================================================================
    # Public Parse/Write Interface
    # =====================================================================
    # Concrete Routing Methods - Moved to rfc.py.Entry
    # =====================================================================
    # parse, write, _route_parse, _route_write, _route_write_many,
    # _handle_parse_entry, _handle_write_entry, execute, __call__, __new__,
    # _auto_detect_entry_operation, _route_entry_operation are now
    # concrete implementations in FlextLdifServersRfc.Entry

    def _hook_validate_entry_raw(
        self,
        dn: str,
        attrs: dict[str, list[str | bytes]],
    ) -> FlextResult[bool]:
        """Hook to validate raw entry before parsing.

        Called before parse_entry() to allow server-specific validation of raw DN and attributes.

        Default behavior: validates DN is not empty.

        **When to use:**
        - Validate DN format before parsing
        - Check required attributes exist
        - Enforce server-specific rules
        - Filter out invalid entries early

        Args:
            dn: Distinguished Name
            attrs: Raw attributes dict (not used in base implementation)

        Returns:
            FlextResult[bool] with True on success, fail() on failure

        """
        _ = attrs
        if not dn:
            return FlextResult.fail("DN cannot be empty")
        return FlextResult.ok(True)

    def _hook_post_parse_entry(
        self,
        entry: m.Ldif.Entry,
    ) -> FlextResult[m.Ldif.Entry]:
        """Hook called after parsing an entry.

        Override in subclasses for server-specific post-processing of parsed entries.

        Default behavior: returns entry unchanged (pass-through).

        **When to use:**
        - Normalize entry properties after parsing
        - Add server-specific metadata
        - Transform entry attributes

        Args:
            entry: Parsed Entry from parse_entry()

        Returns:
            FlextResult[Entry] - modified or original entry

        """
        return FlextResult.ok(entry)

    def _hook_pre_write_entry(
        self,
        entry: m.Ldif.Entry,
    ) -> FlextResult[m.Ldif.Entry]:
        """Hook called before writing an entry.

        Override in subclasses for server-specific pre-processing before write_entry_to_rfc().

        Default behavior: returns entry unchanged (pass-through).

        **When to use:**
        - Normalize entry properties before writing
        - Add server-specific metadata for write
        - Transform entry format for output

        Args:
            entry: Entry to write

        Returns:
            FlextResult[Entry] - modified or original entry

        """
        return FlextResult.ok(entry)

    def can_handle_attribute(
        self,
        attribute: m.Ldif.SchemaAttribute,
    ) -> bool:
        """Check if this quirk can handle a schema attribute.

        Entry quirks typically don't handle schema attributes - that's handled
        by Schema quirks. Base implementation returns False.

        Args:
            attribute: SchemaAttribute model

        Returns:
            False in base class (Entry doesn't handle attributes)

        """
        _ = attribute  # Entry doesn't handle attributes
        return False

    def can_handle_objectclass(
        self,
        objectclass: m.Ldif.SchemaObjectClass,
    ) -> bool:
        """Check if this quirk can handle a schema objectClass.

        Entry quirks typically don't handle objectclasses - that's handled
        by Schema quirks. Base implementation returns False.

        Args:
            objectclass: SchemaObjectClass model

        Returns:
            False in base class (Entry doesn't handle objectclasses)

        """
        _ = objectclass  # Entry doesn't handle objectclasses
        return False

    def can_handle(
        self,
        entry_dn: str,
        attributes: dict[str, list[str]],
    ) -> bool:
        """Check if this quirk can handle the entry.

        Called BEFORE parsing to detect if this quirk should process the entry.
        Receives raw entry data (DN and attributes) from LDIF parser.

        Args:
            entry_dn: Entry distinguished name
            attributes: Entry attributes mapping

        Returns:
            True if this quirk should process this entry

        """
        _ = entry_dn  # Explicitly mark as intentionally unused in base
        _ = attributes  # Explicitly mark as intentionally unused in base
        return (
            False  # Must be implemented by subclass  # Must be implemented by subclass
        )

    def _normalize_attribute_name(self, attr_name: str) -> str:
        """Normalize attribute name to RFC 2849 canonical form.

        RFC 2849 specifies: Attribute names are case-insensitive.
        This method normalizes to canonical form for consistent matching.

        Key rule: objectclass (any case) → objectClass (canonical)
        All other attributes: preserved as-is (most are already lowercase)

        Args:
            attr_name: Attribute name from LDIF (any case)

        Returns:
            Canonical form of the attribute name

        """
        # Handle empty strings
        if not attr_name:
            return attr_name
        # RFC 2849: objectclass → objectClass (canonical form)
        if attr_name.lower() == "objectclass":
            return "objectClass"
        # All other attributes: preserved as-is
        return attr_name

    def _convert_raw_attributes(
        self,
        entry_attrs: dict[str, list[str | bytes]],
    ) -> dict[str, list[str]]:
        """Convert raw LDIF attributes to dict[str, list[str]] format.

        Handles bytes values from ldif3 parser and normalizes attribute names.

        Args:
            entry_attrs: Raw attributes mapping from LDIF parser

        Returns:
            Converted attributes with normalized names and string values

        """
        converted_attrs: dict[str, list[str]] = {}
        # Business Rule: entry_attrs is dict[str, list[str | bytes]] but pyrefly may infer
        # attr_values as Sequence[Unknown] | list[bytes | str] due to type inference limitations.
        # Implication: We validate and convert explicitly to ensure type safety.
        for attr_name, attr_values_raw in entry_attrs.items():
            # Normalize attribute name to canonical case (RFC 2849)
            canonical_attr_name = self._normalize_attribute_name(attr_name)

            # Convert values to strings
            # Type guard: Ensure attr_values is a list before processing
            if not isinstance(attr_values_raw, list):
                # Business Rule: LDIF attribute values must be lists per RFC 2849
                # Implication: Skip non-list values (shouldn't happen in practice)
                continue
            attr_values: list[str | bytes] = attr_values_raw
            string_values: list[str] = []
            if isinstance(attr_values, list):
                # Type narrowing: attr_values is list[str | bytes]
                string_values = [
                    (
                        value.decode("utf-8", errors="replace")
                        if isinstance(value, bytes)
                        else str(value)
                    )
                    for value in attr_values
                ]
            elif isinstance(attr_values, bytes):
                string_values = [
                    attr_values.decode("utf-8", errors="replace"),
                ]
            elif isinstance(attr_values, (list, tuple)):
                # Handle Sequence types (tuple, etc.) - convert to list[str]
                string_values = [
                    (
                        value.decode("utf-8", errors="replace")
                        if isinstance(value, bytes)
                        else str(value)
                    )
                    for value in attr_values
                ]
            else:
                string_values = [str(attr_values)]

            # RFC 2849: If attribute already exists, append values
            if canonical_attr_name in converted_attrs:
                converted_attrs[canonical_attr_name].extend(string_values)
            else:
                converted_attrs[canonical_attr_name] = string_values

        return converted_attrs

    def _parse_content(
        self,
        ldif_content: str,
    ) -> FlextResult[list[m.Ldif.Entry]]:
        """Parse raw LDIF content string into Entry models (internal).

        PRIMARY parsing entry point - called by framework with raw LDIF.

        **You must:**
        1. Use ldif3.LDIFParser to parse LDIF content
        2. For each (dn, attrs) pair from ldif3:
           - Call _hook_validate_entry_raw(dn, attrs) [optional hook]
           - Call _parse_entry(dn, attrs) [required]
           - Call _hook_post_parse_entry(entry) [optional hook]
        3. Return list of all parsed entries

        **Edge cases:**
        - Empty string -> return ok([])
        - Whitespace only -> return ok([])
        - Malformed LDIF -> return fail(message)
        - Encoding errors -> catch UnicodeDecodeError, return fail()

        **NEVER raise exceptions** - return FlextResult.fail()

        Args:
            ldif_content: Raw LDIF content as string

        Returns:
            FlextResult with list[Entry] on success or fail(message)

        """
        _ = ldif_content  # Explicitly mark as intentionally unused in base
        return FlextResult.fail("Must be implemented by subclass")

    # =====================================================================
    # Concrete Helper Methods - Moved to rfc.py.Entry
    # =====================================================================
    # parse_entry is now a concrete implementation in FlextLdifServersRfc.Entry
    # NOTE: can_handle_attribute() and can_handle_objectclass() are Schema-level
    # methods only. Entry detection uses can_handle(dn, attributes) instead.

    def _write_entry(
        self,
        entry_data: m.Ldif.Entry,
    ) -> FlextResult[str]:
        r"""Write Entry model to RFC-compliant LDIF string (internal).

        Converts Entry model back to LDIF text format.

        **RFC 2849 Format:**
        - Start with "dn: <distinguished-name>"
        - Follow with "attribute: value" pairs
        - Use "attribute:: <base64>" for binary/non-ASCII
        - Blank line after last attribute
        - Proper line continuations for long values

        **Edge cases:**
        - Null entry -> return fail("Entry is None")
        - Missing DN -> return fail("Entry DN is None")
        - Empty attributes -> return ok("dn: ...

        ")
        - Special chars in DN -> proper escaping

        Args:
            entry_data: Entry model to write

        Returns:
            FlextResult with LDIF string or fail(message)

        """
        # Basic RFC 2849 LDIF writing implementation
        # ASCII printable range limit (0-127)
        ascii_printable_limit = 127
        output_lines: list[str] = []

        # Extract write options from metadata for line folding
        fold_long_lines = True  # Default per RFC 2849
        line_width = c.Ldif.Format.LINE_FOLD_WIDTH  # 76 bytes

        if entry_data.metadata and entry_data.metadata.write_options:
            write_opts = entry_data.metadata.write_options
            # Check if write_options contains the nested write_options dict
            if isinstance(write_opts, dict) and "write_options" in write_opts:
                nested_opts = write_opts.get("write_options")
                if hasattr(nested_opts, "fold_long_lines"):
                    fold_long_lines = bool(nested_opts.fold_long_lines)
                if hasattr(nested_opts, "line_width"):
                    line_width = int(nested_opts.line_width or line_width)
            elif hasattr(write_opts, "fold_long_lines"):
                fold_long_lines = bool(write_opts.fold_long_lines)
                if hasattr(write_opts, "line_width"):
                    line_width = int(write_opts.line_width or line_width)

        def fold_line(line: str) -> list[str]:
            """Fold a line per RFC 2849 if fold_long_lines is enabled."""
            if not fold_long_lines or len(line.encode("utf-8")) <= line_width:
                return [line]
            # RFC 2849 line folding: continuation lines start with single space
            folded: list[str] = []
            line_bytes = line.encode("utf-8")
            pos = 0
            while pos < len(line_bytes):
                if not folded:
                    # First line: full width
                    chunk_end = min(pos + line_width, len(line_bytes))
                else:
                    # Continuation lines: width - 1 (space prefix takes 1 byte)
                    chunk_end = min(pos + line_width - 1, len(line_bytes))
                # Find valid UTF-8 boundary
                while chunk_end > pos:
                    try:
                        chunk = line_bytes[pos:chunk_end].decode("utf-8")
                        break
                    except UnicodeDecodeError:
                        chunk_end -= 1
                else:
                    chunk_end = pos + 1
                    chunk = line_bytes[pos:chunk_end].decode("utf-8", errors="replace")
                if folded:
                    folded.append(" " + chunk)
                else:
                    folded.append(chunk)
                pos = chunk_end
            return folded

        # Write DN (with folding if enabled)
        if entry_data.dn:
            dn_line = f"dn: {entry_data.dn.value}"
            output_lines.extend(fold_line(dn_line))
        else:
            return FlextResult.fail("Entry DN is None")

        # Write attributes
        if hasattr(entry_data, "attributes") and entry_data.attributes:
            for attr_name, values in entry_data.attributes.items():
                if isinstance(values, list):
                    for value in values:
                        # Simple encoding - for production this would be more complex
                        str_value = str(value)
                        if any(ord(char) > ascii_printable_limit for char in str_value):
                            # Base64 encode for non-ASCII
                            encoded = base64.b64encode(
                                str_value.encode("utf-8"),
                            ).decode("ascii")
                            attr_line = f"{attr_name}:: {encoded}"
                        else:
                            attr_line = f"{attr_name}: {str_value}"
                        output_lines.extend(fold_line(attr_line))
                else:
                    str_value = str(values)
                    attr_line = f"{attr_name}: {str_value}"
                    output_lines.extend(fold_line(attr_line))

        # Add blank line after entry
        output_lines.append("")

        ldif_content = "\n".join(output_lines)
        return FlextResult.ok(ldif_content)

    def parse(self, ldif_content: str) -> FlextResult[list[m.Ldif.Entry]]:
        """Parse LDIF content string into Entry models.

        This satisfies EntryProtocol (structural typing via hasattr checks).

        Args:
            ldif_content: Raw LDIF content as string

        Returns:
            FlextResult with list of Entry models

        """
        return self._parse_content(ldif_content)

    def _build_header_lines(
        self,
        write_options: FlextLdifModelsSettings.WriteFormatOptions | None,
        entry_count: int,
    ) -> list[str]:
        """Build header lines based on write options."""
        lines: list[str] = []
        if write_options is None:
            return lines
        if write_options.include_version_header:
            lines.append("version: 1")
        if write_options.include_timestamps:
            timestamp = datetime.now(UTC).isoformat()
            lines.extend((
                f"# Generated on: {timestamp}",
                f"# Total entries: {entry_count}",
            ))
        return lines

    def _resolve_write_options_for_header(
        self,
        write_options: FlextLdifModelsSettings.WriteFormatOptions | None,
    ) -> FlextLdifModelsSettings.WriteFormatOptions | None:
        """Resolve write options for header generation."""
        if write_options is None:
            return None
        if isinstance(write_options, FlextLdifModelsSettings.WriteFormatOptions):
            return write_options
        if isinstance(write_options, FlextLdifModelsDomains.WriteOptions):
            return FlextLdifModelsSettings.WriteFormatOptions()
        return None

    def _convert_write_options(
        self,
        write_options: FlextLdifModelsSettings.WriteFormatOptions
        | FlextLdifModelsDomains.WriteOptions
        | dict[str, t.GeneralValueType],
    ) -> (
        FlextLdifModelsSettings.WriteFormatOptions | FlextLdifModelsDomains.WriteOptions
    ):
        """Convert write options to appropriate typed model."""
        if isinstance(write_options, FlextLdifModelsSettings.WriteFormatOptions):
            return write_options
        if isinstance(write_options, FlextLdifModelsDomains.WriteOptions):
            return write_options
        if isinstance(write_options, dict):
            try:
                return FlextLdifModelsSettings.WriteFormatOptions.model_validate(
                    write_options,
                )
            except Exception:
                return FlextLdifModelsDomains.WriteOptions.model_validate(write_options)
        msg = f"Expected WriteFormatOptions | WriteOptions | dict, got {type(write_options)}"
        raise TypeError(msg)

    def _inject_write_options(
        self,
        entry: m.Ldif.Entry,
        write_options: FlextLdifModelsSettings.WriteFormatOptions,
    ) -> m.Ldif.Entry:
        """Inject write options into entry metadata."""
        write_options_typed = self._convert_write_options(write_options)
        new_write_opts: dict[str, t.GeneralValueType] = (
            dict(entry.metadata.write_options)
            if entry.metadata and entry.metadata.write_options
            else {}
        )

        new_write_opts["write_options"] = write_options_typed

        if entry.metadata:
            updated_metadata = entry.metadata.model_copy(
                update={"write_options": new_write_opts},
            )
        else:
            write_opts_for_meta: FlextLdifModelsDomains.WriteOptions | None = None
            if isinstance(write_options_typed, FlextLdifModelsDomains.WriteOptions):
                write_opts_for_meta = write_options_typed
            elif isinstance(
                write_options_typed,
                FlextLdifModelsSettings.WriteFormatOptions,
            ):
                write_opts_for_meta = (
                    FlextLdifModelsDomains.WriteOptions.model_validate(
                        write_options_typed.model_dump(),
                    )
                )
            updated_metadata = m.Ldif.QuirkMetadata(
                quirk_type="rfc",
                write_options=write_opts_for_meta,
            )
        return entry.model_copy(update={"metadata": updated_metadata})

    def write(
        self,
        entry_data: m.Ldif.Entry | list[m.Ldif.Entry],
        write_options: FlextLdifModelsSettings.WriteFormatOptions | None = None,
    ) -> FlextResult[str]:
        """Write Entry model(s) to LDIF string format.

        Business Rule: Handles both single Entry and list of Entries.
        Optionally injects write_options into metadata for format control.

        Args:
            entry_data: Entry model or list of Entry models
            write_options: Optional write format options

        Returns:
            FlextResult with LDIF string

        """
        if isinstance(entry_data, list):
            return self._write_entry_list(entry_data, write_options)
        return self._write_single_entry(entry_data, write_options)

    def _write_entry_list(
        self,
        entries: list[m.Ldif.Entry],
        write_options: FlextLdifModelsSettings.WriteFormatOptions | None,
    ) -> FlextResult[str]:
        """Write list of entries to LDIF."""
        opts = self._resolve_write_options_for_header(write_options)
        header_lines = self._build_header_lines(opts, len(entries))

        # Use traverse pattern for fail-fast processing
        def format_output(results: list[str]) -> str:
            all_lines = header_lines + results
            ldif_output = "\n".join(all_lines) if all_lines else ""
            if header_lines and not ldif_output.endswith("\n"):
                ldif_output += "\n"
            return ldif_output

        return FlextResult.traverse(
            entries,
            lambda e: self._write_single_entry(e, write_options),
        ).map(format_output)

    def _write_single_entry(
        self,
        entry: m.Ldif.Entry,
        write_options: FlextLdifModelsSettings.WriteFormatOptions | None,
    ) -> FlextResult[str]:
        """Write single entry to LDIF."""
        if write_options is not None:
            entry = self._inject_write_options(entry, write_options)
        return self._write_entry(entry)

    def _normalize_entry(
        self,
        entry: m.Ldif.Entry,
    ) -> m.Ldif.Entry:
        """Normalize entry to RFC format with metadata tracking.

        Hook for server-specific normalization. Override in server quirks
        to transform server-specific attributes/formats to RFC baseline.

        Base Implementation: Returns entry as-is (no normalization).
        Servers override to convert their formats to RFC.

        Args:
            entry: Entry to normalize

        Returns:
            Normalized entry (base implementation returns unchanged)

        Example Override (OID):
            def _normalize_entry(self, entry):
                # Convert OID boolean "1"/"0" to RFC "TRUE"/"FALSE"
                # Track in metadata via entry.track_transformation(...)
                return normalized_entry

        """
        return entry

    def _denormalize_entry(
        self,
        entry: m.Ldif.Entry,
        target_server: str | None = None,
    ) -> m.Ldif.Entry:
        """Denormalize entry from RFC format to target server format.

        Hook for server-specific denormalization. Override in server quirks
        to convert RFC format back to server-specific representation.

        Base Implementation: Returns entry as-is (no denormalization).
        Servers override to convert RFC back to their native format.

        Args:
            entry: RFC-normalized entry
            target_server: Target server type (optional hint)

        Returns:
            Denormalized entry for target server (base implementation returns unchanged)

        Example Override (OUD):
            def _denormalize_entry(self, entry, target_server):
                # Convert RFC booleans back to OUD format
                # Use metadata.conversion_notes for context
                return denormalized_entry

        """
        _ = target_server
        return entry

    def execute(
        self,
        **kwargs: dict[str, t.GeneralValueType],
    ) -> FlextResult[m.Ldif.Entry | str]:
        """Execute entry operation (parse/write)."""
        ldif_content = kwargs.get("ldif_content")
        entry_model = kwargs.get("entry_model")

        if isinstance(ldif_content, str):
            entries_result = self._parse_content(ldif_content)
            if entries_result.is_success:
                entries = entries_result.value
                return FlextResult[m.Ldif.Entry | str].ok(
                    entries[0] if entries else "",
                )
            return FlextResult[m.Ldif.Entry | str].ok("")
        if isinstance(entry_model, m.Ldif.Entry):
            str_result = self._write_entry(entry_model)
            return FlextResult[m.Ldif.Entry | str].ok(
                str_result.map_or(""),
            )

        return FlextResult[m.Ldif.Entry | str].ok("")

    def parse_entry(
        self,
        entry_dn: str,
        entry_attrs: dict[str, list[str]],
    ) -> FlextResult[m.Ldif.Entry]:
        """Parse a single entry from DN and attributes.

        Base implementation delegates to _parse_content() after constructing
        LDIF content string. Subclasses should override for server-specific parsing.

        Args:
            entry_dn: Entry distinguished name
            entry_attrs: Entry attributes mapping (dict[str, list[str]])

        Returns:
            FlextResult[Entry] with parsed entry model

        """
        # Convert entry_attrs to dict if needed
        if isinstance(entry_attrs, Mapping):
            attrs_dict: dict[
                str,
                str | list[str] | bytes | list[bytes] | int | float | bool | None,
            ] = dict(entry_attrs)
        elif isinstance(entry_attrs, dict):
            attrs_dict = entry_attrs
        else:
            msg = f"Expected Mapping | dict, got {type(entry_attrs)}"
            raise TypeError(msg)

        # Build LDIF content string from DN and attributes
        ldif_lines = [f"dn: {entry_dn}"]
        for attr_name, attr_values in attrs_dict.items():
            if isinstance(attr_values, (list, tuple)):
                if not isinstance(attr_values, list):
                    msg = f"Expected list, got {type(attr_values)}"
                    raise TypeError(msg)
                # Decode bytes to string before formatting
                ldif_lines.extend(
                    f"{attr_name}: {value.decode('utf-8') if isinstance(value, bytes) else value}"
                    for value in attr_values
                )
            else:
                # Decode bytes to string before formatting
                value_str = (
                    attr_values.decode("utf-8")
                    if isinstance(attr_values, bytes)
                    else attr_values
                )
                ldif_lines.append(f"{attr_name}: {value_str}")
        ldif_content = "\n".join(ldif_lines) + "\n"

        # Parse using _parse_content and return first entry (using flat_map pattern)
        return self._parse_content(ldif_content).flat_map(
            lambda entries: (
                FlextResult[m.Ldif.Entry].ok(entries[0])
                if entries
                else FlextResult[m.Ldif.Entry].fail("No entries parsed")
            ),
        )
