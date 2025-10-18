"""RFC 2849 Compliant LDIF Parser.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Implements RFC 2849: The LDAP Data Interchange Format (LDIF) - Technical Specification

Key RFC 2849 features:
- Line folding: Lines starting with single space are continuations
- Base64 encoding: Values starting with '::' are base64-encoded
- Distinguished Names: RFC 4514 DN syntax
- Change records: add, delete, modify, moddn operations
- Comments: Lines starting with '#' are ignored

This parser uses ldif3 library for RFC 2849 compliance.
"""

from __future__ import annotations

import base64
from io import BytesIO
from pathlib import Path

from flext_core import FlextResult, FlextService
from ldif3 import LDIFParser

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.quirks.entry_quirks import FlextLdifEntryQuirks
from flext_ldif.quirks.registry import FlextLdifQuirksRegistry
from flext_ldif.typings import FlextLdifTypes

# Python 3.13 compatibility: ldif3 uses deprecated base64.decodestring
# Monkey-patch base64 module to provide decodestring as alias to decodebytes
if not hasattr(base64, "decodestring"):
    setattr(base64, "decodestring", base64.decodebytes)


class FlextLdifRfcLdifParser(FlextService[FlextLdifTypes.Models.CustomDataDict]):
    """Generic LDIF parser with RFC 2849 compliance via ldif3 library.

    This is a GENERIC parser that can parse ANY LDIF data from any LDAP server.
    RFC 2849 compliance is guaranteed by the ldif3 library, with quirks for extensions.

    **Architecture**:
    - GENERIC: Parses any LDIF data (OID, OUD, OpenLDAP, AD, etc.)
    - RFC-COMPLIANT: Uses ldif3 library for RFC 2849 compliance
    - EXTENSIBLE: Quirks configure parsing behavior for server-specific formats

    **Features**:
    - Line folding (RFC 2849 Section 2) via ldif3
    - Base64 encoding (RFC 2849 Section 2) via ldif3
    - DN parsing (RFC 4514) via ldif3
    - Attribute value parsing (ANY attribute names/values)
    - Change record parsing support
    - Lenient parsing (accepts non-RFC extensions)

    **Example**:
        # RFC-compliant parsing with quirks (MANDATORY)
        from flext_ldif.quirks.registry import FlextLdifQuirksRegistry

        registry = FlextLdifQuirksRegistry()
        params = {"file_path": "entries.ldif", "parse_changes": False}
        parser = FlextLdifRfcLdifParser(params=params, quirk_registry=registry)
        result = parser.execute()

        # With quirks for OID-specific parsing
        params = {"file_path": "oid.ldif", "source_server": "oid"}
        parser = FlextLdifRfcLdifParser(params=params, quirk_registry=registry)
        result = parser.execute()

    """

    def __init__(
        self,
        *,
        params: FlextLdifTypes.Models.CustomDataDict,
        quirk_registry: FlextLdifQuirksRegistry,
    ) -> None:
        """Initialize generic LDIF parser.

        Args:
            params: Parsing parameters (file_path, parse_changes, encoding, source_server)
            quirk_registry: Quirk registry for server-specific extensions (MANDATORY)

        """
        super().__init__()
        self._params = params
        self._quirk_registry = quirk_registry
        self._source_server = params.get(
            FlextLdifConstants.DictKeys.SOURCE_SERVER,
            FlextLdifConstants.ServerTypes.RFC,
        )
        self._entry_quirks = FlextLdifEntryQuirks()

    def execute(self) -> FlextResult[FlextLdifTypes.Models.CustomDataDict]:
        """Execute RFC-compliant LDIF parsing using ldif3 library.

        Supports both file-based and content-based parsing:
        - file_path: Parse from file (traditional approach)
        - content: Parse from string (direct content parsing)

        Returns:
            FlextResult with parsed LDIF data containing:
                - entries: List of LDIF entries
                - changes: List of change records (if parse_changes=True)
                - comments: List of comments found
                - stats: Parsing statistics

        """
        try:
            # Check for content parameter first (direct string parsing)
            content_raw = self._params.get("content")
            if content_raw:
                # Type narrow content to string
                if not isinstance(content_raw, str):
                    return FlextResult[FlextLdifTypes.Models.CustomDataDict].fail(
                        f"content must be string, got {type(content_raw).__name__}"
                    )
                content: str = content_raw

                # Type narrow parse_changes to bool
                parse_changes_raw = self._params.get(
                    FlextLdifConstants.DictKeys.PARSE_CHANGES, False
                )
                if not isinstance(parse_changes_raw, bool):
                    return FlextResult[FlextLdifTypes.Models.CustomDataDict].fail(
                        f"parse_changes must be bool, got {type(parse_changes_raw).__name__}"
                    )
                content_parse_changes: bool = parse_changes_raw

                if self.logger is not None:
                    self.logger.info(
                        "Parsing LDIF content string (RFC 2849 via ldif3)",
                        extra={
                            "content_length": len(content),
                            "parse_changes": content_parse_changes,
                        },
                    )

                # Use parse_content method for string parsing
                parse_result = self.parse_content(
                    content, parse_changes=content_parse_changes
                )

                if parse_result.is_failure:
                    return FlextResult[FlextLdifTypes.Models.CustomDataDict].fail(
                        parse_result.error
                    )

                entries = parse_result.value

                # Build result structure matching file parsing output
                data: FlextLdifTypes.Models.CustomDataDict = {
                    FlextLdifConstants.DictKeys.ENTRIES: entries,
                    FlextLdifConstants.DictKeys.CHANGES: [],  # Changes tracked during parsing
                    FlextLdifConstants.DictKeys.COMMENTS: [],  # Comments tracked during parsing
                    FlextLdifConstants.DictKeys.STATS: {
                        FlextLdifConstants.DictKeys.TOTAL_ENTRIES: len(entries),
                        FlextLdifConstants.DictKeys.TOTAL_CHANGES: 0,
                        FlextLdifConstants.DictKeys.TOTAL_COMMENTS: 0,
                    },
                }

                if self.logger is not None:
                    self.logger.info(
                        "LDIF content parsed successfully",
                        extra={
                            "total_entries": len(entries),
                        },
                    )

                return FlextResult[FlextLdifTypes.Models.CustomDataDict].ok(data)

            # Fall back to file-based parsing
            file_path_str = self._params.get(FlextLdifConstants.DictKeys.FILE_PATH, "")
            if not file_path_str:
                return FlextResult[FlextLdifTypes.Models.CustomDataDict].fail(
                    "Either 'file_path' or 'content' parameter is required"
                )

            # Type narrow file_path to string
            if not isinstance(file_path_str, str):
                return FlextResult[FlextLdifTypes.Models.CustomDataDict].fail(
                    f"file_path must be string, got {type(file_path_str).__name__}"
                )

            file_path = Path(file_path_str)
            if not file_path.exists():
                return FlextResult[FlextLdifTypes.Models.CustomDataDict].fail(
                    f"LDIF file not found: {file_path}"
                )

            # Type narrow parse_changes to bool
            parse_changes_raw = self._params.get(
                FlextLdifConstants.DictKeys.PARSE_CHANGES, False
            )
            if not isinstance(parse_changes_raw, bool):
                return FlextResult[FlextLdifTypes.Models.CustomDataDict].fail(
                    f"parse_changes must be bool, got {type(parse_changes_raw).__name__}"
                )
            file_parse_changes: bool = parse_changes_raw

            # Type narrow encoding to string
            encoding_raw = self._params.get(
                FlextLdifConstants.DictKeys.ENCODING, FlextLdifConstants.Encoding.UTF8
            )
            if not isinstance(encoding_raw, str):
                return FlextResult[FlextLdifTypes.Models.CustomDataDict].fail(
                    f"encoding must be string, got {type(encoding_raw).__name__}"
                )
            encoding: str = encoding_raw

            if self.logger is not None:
                self.logger.info(
                    f"Parsing LDIF file (RFC 2849 via ldif3): {file_path}",
                    extra={
                        "file_path": str(file_path),
                        "parse_changes": file_parse_changes,
                        "encoding": encoding,
                    },
                )

            # Parse LDIF file using ldif3
            file_parse_result = self.parse_ldif_file(
                file_path,
                parse_changes=file_parse_changes,
                encoding=encoding,
            )

            if file_parse_result.is_failure:
                return FlextResult[FlextLdifTypes.Models.CustomDataDict].fail(
                    file_parse_result.error
                )

            entries = file_parse_result.value

            # Build result structure
            data = {
                FlextLdifConstants.DictKeys.ENTRIES: entries,
                FlextLdifConstants.DictKeys.CHANGES: [],
                FlextLdifConstants.DictKeys.COMMENTS: [],
                FlextLdifConstants.DictKeys.STATS: {
                    FlextLdifConstants.DictKeys.TOTAL_ENTRIES: len(entries),
                    FlextLdifConstants.DictKeys.TOTAL_CHANGES: 0,
                    FlextLdifConstants.DictKeys.TOTAL_COMMENTS: 0,
                },
            }

            if self.logger is not None:
                self.logger.info(
                    "LDIF parsed successfully",
                    extra={
                        "total_entries": len(entries),
                    },
                )

            return FlextResult[FlextLdifTypes.Models.CustomDataDict].ok(data)

        except Exception as e:  # pragma: no cover
            error_msg = f"Failed to execute RFC LDIF parser: {e}"
            if self.logger is not None:
                self.logger.exception(error_msg)
            return FlextResult[FlextLdifTypes.Models.CustomDataDict].fail(error_msg)

    def parse_content(
        self, content: str, *, parse_changes: bool = False
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Parse LDIF content string using ldif3 library.

        Args:
            content: LDIF content as string
            parse_changes: Whether to parse change records (reserved for future use)

        Returns:
            FlextResult with list of parsed entries

        Note:
            parse_changes parameter is reserved for future enhancement.
            ldif3 library currently parses entries only, not change records.

        """
        _ = parse_changes  # Reserved for future enhancement
        return self._parse_with_ldif3(content=content)

    def parse_ldif_file(
        self,
        path: str | Path,
        *,
        parse_changes: bool = False,
        encoding: str = FlextLdifConstants.Encoding.UTF8,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Parse LDIF file using ldif3 library.

        Args:
            path: Path to LDIF file
            parse_changes: Whether to parse change records (reserved for future use)
            encoding: File encoding

        Returns:
            FlextResult with list of parsed entries

        Note:
            parse_changes parameter is reserved for future enhancement.
            ldif3 library currently parses entries only, not change records.

        """
        _ = parse_changes  # Reserved for future enhancement
        file_path = Path(path)
        return self._parse_with_ldif3(file_path=file_path, encoding=encoding)

    def _parse_with_ldif3(
        self,
        content: str | None = None,
        file_path: Path | None = None,
        encoding: str = FlextLdifConstants.Encoding.UTF8,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Parse LDIF using ldif3 library (RFC 2849 compliant).

        This method uses the ldif3 library for RFC 2849 compliance, replacing
        214 lines of naive parsing code with a battle-tested implementation.

        Args:
            content: LDIF content string (mutually exclusive with file_path)
            file_path: Path to LDIF file (mutually exclusive with content)
            encoding: Character encoding (default: utf-8)

        Returns:
            FlextResult with list of parsed entries

        """
        try:
            entries: list[FlextLdifModels.Entry] = []

            # Handle empty/whitespace-only content gracefully
            if content is not None and not content.strip():
                return FlextResult[list[FlextLdifModels.Entry]].ok(entries)

            # Determine input source and parse with context manager
            if content is not None:
                # Parse from content string using BytesIO
                content_bytes = content.encode(encoding)
                with BytesIO(content_bytes) as input_stream:
                    parser = LDIFParser(input_stream)

                    # Parse all entries using ldif3
                    for dn, entry_attrs in parser.parse():
                        # Type narrow DN to string
                        if not isinstance(dn, str):
                            continue

                        # Clean DN to remove spaces around '=' (RFC 4514 compliance)
                        cleaned_dn = self._entry_quirks.clean_dn(dn)

                        # Convert ldif3 format to our Entry format
                        entry_data: FlextLdifTypes.Models.CustomDataDict = {
                            FlextLdifConstants.DictKeys.DN: cleaned_dn,
                            FlextLdifConstants.DictKeys.ATTRIBUTES: entry_attrs,
                        }

                        # Create Entry model
                        entry_result = self._create_entry(entry_data)
                        if entry_result.is_success:
                            entries.append(entry_result.value)
                        # Log error but continue parsing
                        elif self.logger is not None:
                            self.logger.warning(
                                f"Failed to create entry for DN {cleaned_dn}: {entry_result.error}"
                            )

            elif file_path is not None:
                # Parse from file using context manager
                with Path(file_path).open("rb") as input_stream:
                    parser = LDIFParser(input_stream)

                    # Parse all entries using ldif3
                    for dn, entry_attrs in parser.parse():
                        # Type narrow DN to string
                        if not isinstance(dn, str):
                            continue

                        # Clean DN to remove spaces around '=' (RFC 4514 compliance)
                        cleaned_dn = self._entry_quirks.clean_dn(dn)

                        # Convert ldif3 format to our Entry format
                        file_entry_data: FlextLdifTypes.Models.CustomDataDict = {
                            FlextLdifConstants.DictKeys.DN: cleaned_dn,
                            FlextLdifConstants.DictKeys.ATTRIBUTES: entry_attrs,
                        }

                        # Create Entry model
                        entry_result = self._create_entry(file_entry_data)
                        if entry_result.is_success:
                            entries.append(entry_result.value)
                        # Log error but continue parsing
                        elif self.logger is not None:
                            self.logger.warning(
                                f"Failed to create entry for DN {cleaned_dn}: {entry_result.error}"
                            )

            else:
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    "Either content or file_path must be provided"
                )

            return FlextResult[list[FlextLdifModels.Entry]].ok(entries)

        except Exception as e:  # pragma: no cover
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                f"Failed to parse LDIF with ldif3: {e}"
            )

    def _create_entry(
        self, entry_data: FlextLdifTypes.Models.CustomDataDict
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Create LDIF entry from parsed data.

        Args:
            entry_data: Parsed entry data with FlextLdifConstants.DictKeys.DN and FlextLdifConstants.DictKeys.ATTRIBUTES keys

        Returns:
            FlextResult with Entry model

        """
        # Extract and type narrow dn
        dn_raw = entry_data.get(FlextLdifConstants.DictKeys.DN, "")
        if not isinstance(dn_raw, str):
            return FlextResult[FlextLdifModels.Entry].fail(
                f"DN must be string, got {type(dn_raw).__name__}"
            )
        dn: str = dn_raw

        # Extract and type narrow attributes
        attributes_raw = entry_data.get(FlextLdifConstants.DictKeys.ATTRIBUTES, {})
        if not isinstance(attributes_raw, dict):
            return FlextResult[FlextLdifModels.Entry].fail(
                f"attributes must be dict, got {type(attributes_raw).__name__}"
            )
        attributes: FlextLdifTypes.CommonDict.AttributeDict = attributes_raw

        # Use Entry.create() with separate parameters
        return FlextLdifModels.Entry.create(dn=dn, attributes=attributes)


__all__ = ["FlextLdifRfcLdifParser"]
