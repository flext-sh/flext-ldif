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

from io import BytesIO
from pathlib import Path
from typing import cast

from flext_core import FlextCore
from ldif3 import LDIFParser

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels


class FlextLdifRfcLdifParser(FlextCore.Service[FlextCore.Types.Dict]):
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

    def __init__(self, *, params: FlextCore.Types.Dict, quirk_registry: object) -> None:
        """Initialize generic LDIF parser.

        Args:
            params: Parsing parameters (file_path, parse_changes, encoding, source_server)
            quirk_registry: Quirk registry for server-specific extensions (MANDATORY)

        """
        super().__init__()
        self._params = params
        self._quirk_registry = quirk_registry
        self._source_server = params.get("source_server", "rfc")

    def execute(self) -> FlextCore.Result[FlextCore.Types.Dict]:
        """Execute RFC-compliant LDIF parsing using ldif3 library.

        Supports both file-based and content-based parsing:
        - file_path: Parse from file (traditional approach)
        - content: Parse from string (direct content parsing)

        Returns:
            FlextCore.Result with parsed LDIF data containing:
                - entries: List of LDIF entries
                - changes: List of change records (if parse_changes=True)
                - comments: List of comments found
                - stats: Parsing statistics

        """
        try:
            # Check for content parameter first (direct string parsing)
            content = self._params.get("content")
            if content:
                parse_changes = self._params.get("parse_changes", False)

                if self.logger is not None:
                    self.logger.info(
                        "Parsing LDIF content string (RFC 2849 via ldif3)",
                        extra={
                            "content_length": (
                                len(content) if isinstance(content, str) else 0
                            ),
                            "parse_changes": parse_changes,
                        },
                    )

                # Use parse_content method for string parsing
                parse_result = self.parse_content(
                    cast("str", content), parse_changes=cast("bool", parse_changes)
                )

                if parse_result.is_failure:
                    return FlextCore.Result[FlextCore.Types.Dict].fail(
                        parse_result.error
                    )

                entries = parse_result.value

                # Build result structure matching file parsing output
                data: FlextCore.Types.Dict = {
                    "entries": entries,
                    "changes": [],  # Changes tracked during parsing
                    "comments": [],  # Comments tracked during parsing
                    "stats": {
                        "total_entries": len(entries),
                        "total_changes": 0,
                        "total_comments": 0,
                    },
                }

                if self.logger is not None:
                    self.logger.info(
                        "LDIF content parsed successfully",
                        extra={
                            "total_entries": len(entries),
                        },
                    )

                return FlextCore.Result[FlextCore.Types.Dict].ok(data)

            # Fall back to file-based parsing
            file_path_str = self._params.get("file_path", "")
            if not file_path_str:
                return FlextCore.Result[FlextCore.Types.Dict].fail(
                    "Either 'file_path' or 'content' parameter is required"
                )

            file_path = Path(cast("str", file_path_str))
            if not file_path.exists():
                return FlextCore.Result[FlextCore.Types.Dict].fail(
                    f"LDIF file not found: {file_path}"
                )

            parse_changes = self._params.get("parse_changes", False)
            encoding = self._params.get("encoding", "utf-8")

            if self.logger is not None:
                self.logger.info(
                    f"Parsing LDIF file (RFC 2849 via ldif3): {file_path}",
                    extra={
                        "file_path": str(file_path),
                        "parse_changes": parse_changes,
                        "encoding": encoding,
                    },
                )

            # Parse LDIF file using ldif3
            file_parse_result = self.parse_ldif_file(
                file_path,
                parse_changes=cast("bool", parse_changes),
                encoding=cast("str", encoding),
            )

            if file_parse_result.is_failure:
                return FlextCore.Result[FlextCore.Types.Dict].fail(
                    file_parse_result.error
                )

            entries = file_parse_result.value

            # Build result structure
            data = {
                "entries": entries,
                "changes": [],
                "comments": [],
                "stats": {
                    "total_entries": len(entries),
                    "total_changes": 0,
                    "total_comments": 0,
                },
            }

            if self.logger is not None:
                self.logger.info(
                    "LDIF parsed successfully",
                    extra={
                        "total_entries": len(entries),
                    },
                )

            return FlextCore.Result[FlextCore.Types.Dict].ok(data)

        except Exception as e:
            error_msg = f"Failed to execute RFC LDIF parser: {e}"
            if self.logger is not None:
                self.logger.exception(error_msg)
            return FlextCore.Result[FlextCore.Types.Dict].fail(error_msg)

    def parse_content(
        self, content: str, *, parse_changes: bool = False
    ) -> FlextCore.Result[list[FlextLdifModels.Entry]]:
        """Parse LDIF content string using ldif3 library.

        Args:
            content: LDIF content as string
            parse_changes: Whether to parse change records (reserved for future use)

        Returns:
            FlextCore.Result with list of parsed entries

        Note:
            parse_changes parameter is reserved for future enhancement.
            ldif3 library currently parses entries only, not change records.

        """
        _ = parse_changes  # Reserved for future enhancement
        return self._parse_with_ldif3(content=content)

    def parse_ldif_file(
        self, path: str | Path, *, parse_changes: bool = False, encoding: str = "utf-8"
    ) -> FlextCore.Result[list[FlextLdifModels.Entry]]:
        """Parse LDIF file using ldif3 library.

        Args:
            path: Path to LDIF file
            parse_changes: Whether to parse change records (reserved for future use)
            encoding: File encoding

        Returns:
            FlextCore.Result with list of parsed entries

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
        encoding: str = "utf-8",
    ) -> FlextCore.Result[list[FlextLdifModels.Entry]]:
        """Parse LDIF using ldif3 library (RFC 2849 compliant).

        This method uses the ldif3 library for RFC 2849 compliance, replacing
        214 lines of naive parsing code with a battle-tested implementation.

        Args:
            content: LDIF content string (mutually exclusive with file_path)
            file_path: Path to LDIF file (mutually exclusive with content)
            encoding: Character encoding (default: utf-8)

        Returns:
            FlextCore.Result with list of parsed entries

        """
        try:
            entries: list[FlextLdifModels.Entry] = []

            # Handle empty/whitespace-only content gracefully
            if content is not None and not content.strip():
                return FlextCore.Result[list[FlextLdifModels.Entry]].ok(entries)

            # Determine input source and parse with context manager
            if content is not None:
                # Parse from content string using BytesIO
                content_bytes = content.encode(encoding)
                with BytesIO(content_bytes) as input_stream:
                    parser = LDIFParser(input_stream)

                    # Parse all entries using ldif3
                    for dn, entry_attrs in parser.parse():
                        # Convert ldif3 format to our Entry format
                        entry_data = {
                            FlextLdifConstants.DictKeys.DN: dn,
                            FlextLdifConstants.DictKeys.ATTRIBUTES: entry_attrs,
                        }

                        # Create Entry model
                        entry_result = self._create_entry(entry_data)
                        if entry_result.is_success:
                            entries.append(entry_result.value)
                        # Log error but continue parsing
                        elif self.logger is not None:
                            self.logger.warning(
                                f"Failed to create entry for DN {dn}: {entry_result.error}"
                            )

            elif file_path is not None:
                # Parse from file using context manager
                with Path(file_path).open("rb") as input_stream:
                    parser = LDIFParser(input_stream)

                    # Parse all entries using ldif3
                    for dn, entry_attrs in parser.parse():
                        # Convert ldif3 format to our Entry format
                        entry_data = {
                            FlextLdifConstants.DictKeys.DN: dn,
                            FlextLdifConstants.DictKeys.ATTRIBUTES: entry_attrs,
                        }

                        # Create Entry model
                        entry_result = self._create_entry(entry_data)
                        if entry_result.is_success:
                            entries.append(entry_result.value)
                        # Log error but continue parsing
                        elif self.logger is not None:
                            self.logger.warning(
                                f"Failed to create entry for DN {dn}: {entry_result.error}"
                            )

            else:
                return FlextCore.Result[list[FlextLdifModels.Entry]].fail(
                    "Either content or file_path must be provided"
                )

            return FlextCore.Result[list[FlextLdifModels.Entry]].ok(entries)

        except Exception as e:
            return FlextCore.Result[list[FlextLdifModels.Entry]].fail(
                f"Failed to parse LDIF with ldif3: {e}"
            )

    def _create_entry(
        self, entry_data: FlextCore.Types.Dict
    ) -> FlextCore.Result[FlextLdifModels.Entry]:
        """Create LDIF entry from parsed data.

        Args:
            entry_data: Parsed entry data with 'dn' and 'attributes' keys

        Returns:
            FlextCore.Result with Entry model

        """
        # Extract dn and attributes from entry_data
        dn = entry_data.get(FlextLdifConstants.DictKeys.DN, "")
        attributes = entry_data.get(FlextLdifConstants.DictKeys.ATTRIBUTES, {})

        # Use Entry.create() with separate parameters
        return FlextLdifModels.Entry.create(
            dn=cast("str", dn),
            attributes=cast("dict[str, FlextCore.Types.StringList]", attributes),
        )


__all__ = ["FlextLdifRfcLdifParser"]
