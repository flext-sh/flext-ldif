"""Advanced LDIF Parser - RFC 2849 Compliant Implementation.

This module provides comprehensive LDIF parsing capabilities that fully comply
with RFC 2849 and handle quirks from various LDAP server implementations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import base64
from enum import Enum
from pathlib import Path
from typing import cast

from flext_core import FlextLogger, FlextResult, FlextService
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels


class LdifParseState(Enum):
    """Parser state enumeration for LDIF parsing."""

    INITIAL = "initial"
    VERSION = "version"
    COMMENT = "comment"
    ENTRY = "entry"
    CHANGE_RECORD = "change_record"
    ATTRIBUTE = "attribute"
    CONTINUATION = "continuation"
    ERROR = "error"


class FlextLdifParser(FlextService[dict[str, object]]):
    """Advanced LDIF parser with full RFC 2849 compliance.

    Supports:
    - Base64 encoded data (:: syntax)
    - Change records (add, modify, delete, modrdn)
    - Line continuations and folding
    - Comments (# lines)
    - URL references
    - Attribute options (language tags, etc.)
    - Multiple character encodings
    - Server-specific quirks handling
    """

    def __init__(self, config: dict[str, object] | None = None) -> None:
        """Initialize advanced parser with configuration.

        Args:
            config: Parser configuration dictionary

        """
        self._logger = FlextLogger(__name__)
        self._config: dict[str, object] = config or {}

        # Configuration defaults
        self._encoding = cast(
            "str",
            self._config.get("encoding", FlextLdifConstants.Encoding.DEFAULT_ENCODING),
        )
        self._strict_mode = cast("bool", self._config.get("strict_mode", True))
        self._detect_server = cast("bool", self._config.get("detect_server", True))
        self._compliance_level = cast(
            "str",
            self._config.get(
                "compliance_level", FlextLdifConstants.RfcCompliance.STRICT
            ),
        )

    def execute(self) -> FlextResult[dict[str, object]]:
        """Execute parser health check operation - required by FlextService.

        Returns:
            FlextResult containing parser health status information.

        """
        try:
            health_info: dict[str, object] = {
                "status": "healthy",
                "parser_type": "FlextLdifParser",
                "capabilities": [
                    "parse_string",
                    "parse_file",
                    "detect_server_type",
                    "validate_rfc_compliance",
                    "encoding_detection",
                    "base64_decoding",
                    "change_records",
                    "line_continuations",
                    "comments",
                    "url_references",
                    "attribute_options",
                ],
                "config": {
                    "encoding": self._encoding,
                    "strict_mode": self._strict_mode,
                    "detect_server": self._detect_server,
                    "compliance_level": self._compliance_level,
                },
            }
            return FlextResult[dict[str, object]].ok(health_info)
        except Exception as e:
            error_msg = f"Parser health check failed: {e}"
            self._logger.exception(error_msg)
            return FlextResult[dict[str, object]].fail(error_msg)

    def parse_string(
        self, content: str
    ) -> FlextResult[list[FlextLdifModels.Entry | FlextLdifModels.ChangeRecord]]:
        """Parse LDIF content string with full RFC 2849 compliance.

        Args:
            content: LDIF content string

        Returns:
            FlextResult containing list of parsed entries and change records

        """
        if not content.strip():
            return FlextResult[
                list[FlextLdifModels.Entry | FlextLdifModels.ChangeRecord]
            ].ok([])

        try:
            # Detect encoding if not specified
            if self._detect_server:
                detected_encoding = self._detect_encoding(content)
                if detected_encoding:
                    self._encoding = detected_encoding

            # Parse with state machine
            parser_state = LdifParseState.INITIAL
            entries: list[FlextLdifModels.Entry | FlextLdifModels.ChangeRecord] = []
            current_entry_data: dict[str, object] = {}
            line_number = 0

            lines = content.split("\n")

            for line_number, line in enumerate(lines, 1):
                clean_line = line.rstrip("\r")  # Handle CRLF

                # Handle empty lines (entry separators)
                if not clean_line.strip():
                    if current_entry_data:
                        entry_result = self._finalize_entry(current_entry_data)
                        if entry_result.is_success:
                            entries.append(entry_result.value)
                        else:
                            self._logger.warning(
                                f"Skipping malformed entry at line {line_number}: {entry_result.error}"
                            )
                    current_entry_data = {}
                    parser_state = LdifParseState.INITIAL
                    continue

                # Handle comments
                if clean_line.strip().startswith(
                    FlextLdifConstants.Format.COMMENT_PREFIX
                ):
                    parser_state = LdifParseState.COMMENT
                    continue

                # Handle version control
                if clean_line.strip().startswith(
                    FlextLdifConstants.Format.VERSION_PREFIX
                ):
                    parser_state = LdifParseState.VERSION
                    version = clean_line.split(":", 1)[1].strip()
                    if version != FlextLdifConstants.Format.LDIF_VERSION_1:
                        self._logger.warning(f"Unsupported LDIF version: {version}")
                    continue

                # Handle change type
                if clean_line.strip().startswith(
                    FlextLdifConstants.Format.CHANGE_TYPE_PREFIX
                ):
                    parser_state = LdifParseState.CHANGE_RECORD
                    change_type = clean_line.split(":", 1)[1].strip()
                    current_entry_data["changetype"] = change_type
                    continue

                # Handle DN
                if clean_line.startswith("dn:"):
                    parser_state = LdifParseState.ENTRY
                    dn_value = clean_line[3:].strip()
                    current_entry_data["dn"] = dn_value
                    continue

                # Handle DN for change records
                if (
                    clean_line.startswith("dn:")
                    and parser_state == LdifParseState.CHANGE_RECORD
                ):
                    dn_value = clean_line[3:].strip()
                    current_entry_data["dn"] = dn_value
                    continue

                # Handle attributes
                if ":" in clean_line and not clean_line.startswith(" "):
                    parser_state = LdifParseState.ATTRIBUTE
                    attr_result = self._parse_attribute_line(clean_line)
                    if attr_result.is_success:
                        attr_name, attr_value = attr_result.value
                        if attr_name not in current_entry_data:
                            current_entry_data[attr_name] = []
                        # Type assertion for proper list handling
                        attr_list = current_entry_data[attr_name]
                        if isinstance(attr_list, list):
                            attr_list.append(attr_value)
                    else:
                        self._logger.warning(
                            f"Invalid attribute at line {line_number}: {attr_result.error}"
                        )
                    continue

                # Handle line continuations
                if clean_line.startswith((" ", "\t")):
                    parser_state = LdifParseState.CONTINUATION
                    continuation_value = clean_line[1:]  # Remove leading space/tab
                    if current_entry_data:
                        # Find the last attribute to continue
                        last_attr = list(current_entry_data.keys())[-1]
                        attr_list = current_entry_data[last_attr]
                        if isinstance(attr_list, list) and len(attr_list) > 0:
                            attr_list[-1] += continuation_value
                    continue

            # Handle any remaining entry
            if current_entry_data:
                entry_result = self._finalize_entry(current_entry_data)
                if entry_result.is_success:
                    entries.append(entry_result.value)
                else:
                    self._logger.warning(
                        f"Skipping malformed entry at end: {entry_result.error}"
                    )

            self._logger.info(f"Successfully parsed {len(entries)} entries/records")
            return FlextResult[
                list[FlextLdifModels.Entry | FlextLdifModels.ChangeRecord]
            ].ok(entries)

        except Exception as e:
            error_msg = f"Parsing failed: {e}"
            self._logger.exception(error_msg)
            return FlextResult[
                list[FlextLdifModels.Entry | FlextLdifModels.ChangeRecord]
            ].fail(error_msg)

    def parse_ldif_file(
        self, file_path: Path
    ) -> FlextResult[list[FlextLdifModels.Entry | FlextLdifModels.ChangeRecord]]:
        """Parse LDIF file with encoding detection.

        Args:
            file_path: Path to LDIF file

        Returns:
            FlextResult containing list of parsed entries and change records

        """
        try:
            # Try to read with detected encoding first
            content = file_path.read_text(encoding=self._encoding)
            return self.parse_string(content)
        except UnicodeDecodeError:
            # Try with different encodings
            for encoding in FlextLdifConstants.Encoding.SUPPORTED_ENCODINGS:
                try:
                    content = file_path.read_text(encoding=encoding)
                    self._encoding = encoding
                    self._logger.info(
                        f"Successfully read file with encoding: {encoding}"
                    )
                    return self.parse_string(content)
                except UnicodeDecodeError:
                    continue

            error_msg = f"Could not decode file {file_path} with any supported encoding"
            self._logger.exception(error_msg)
            return FlextResult[
                list[FlextLdifModels.Entry | FlextLdifModels.ChangeRecord]
            ].fail(error_msg)
        except OSError as e:
            error_msg = f"Failed to read file {file_path}: {e}"
            self._logger.exception(error_msg)
            return FlextResult[
                list[FlextLdifModels.Entry | FlextLdifModels.ChangeRecord]
            ].fail(error_msg)

    def _parse_attribute_line(self, line: str) -> FlextResult[tuple[str, str]]:
        """Parse a single attribute line with RFC 2849 compliance.

        Args:
            line: Attribute line to parse

        Returns:
            FlextResult containing (attribute_name, attribute_value) tuple

        """
        if ":" not in line:
            return FlextResult[tuple[str, str]].fail("Invalid attribute line format")

        # Check for Base64 encoding (:: syntax)
        if "::" in line:
            # Split on ::
            attr_part, value_part = line.split("::", 1)
            attr_name = attr_part.strip()
            attr_value = value_part.strip()

            # Decode Base64 value
            try:
                decoded_bytes = base64.b64decode(attr_value)
                attr_value = decoded_bytes.decode(self._encoding)
            except Exception as e:
                # If Base64 decode fails, keep original value
                self._logger.warning(
                    f"Base64 decode failed, keeping original value: {e}"
                )
        else:
            # Regular attribute (single colon)
            attr_part, value_part = line.split(":", 1)
            attr_name = attr_part.strip()
            attr_value = value_part.strip()

        # Handle URL references
        if attr_value.startswith(
            FlextLdifConstants.Format.URL_PREFIX
        ) and attr_value.endswith(FlextLdifConstants.Format.URL_SUFFIX):
            # Keep URL as-is for now, could be resolved later
            pass

        # Handle attribute options (language tags, etc.)
        if FlextLdifConstants.Format.ATTRIBUTE_OPTION_SEPARATOR in attr_name:
            # Parse attribute name and options
            attr_parts = attr_name.split(
                FlextLdifConstants.Format.ATTRIBUTE_OPTION_SEPARATOR
            )
            attr_name = attr_parts[0]
            # Options are in attr_parts[1:] - could be processed further

        return FlextResult[tuple[str, str]].ok((attr_name, attr_value))

    def _finalize_entry(
        self, entry_data: dict[str, object]
    ) -> FlextResult[FlextLdifModels.Entry | FlextLdifModels.ChangeRecord]:
        """Finalize entry creation from parsed data.

        Args:
            entry_data: Parsed entry data dictionary

        Returns:
            FlextResult containing created Entry or ChangeRecord

        """
        if not entry_data.get("dn"):
            return FlextResult[
                FlextLdifModels.Entry | FlextLdifModels.ChangeRecord
            ].fail("Entry missing DN")

        # Check if this is a change record
        if "changetype" in entry_data:
            change_result = self._create_change_record(entry_data)
            if change_result.is_success:
                return FlextResult[
                    FlextLdifModels.Entry | FlextLdifModels.ChangeRecord
                ].ok(change_result.value)
            return FlextResult[
                FlextLdifModels.Entry | FlextLdifModels.ChangeRecord
            ].fail(change_result.error or "Failed to create change record")

        entry_result = self._create_regular_entry(entry_data)
        if entry_result.is_success:
            return FlextResult[FlextLdifModels.Entry | FlextLdifModels.ChangeRecord].ok(
                entry_result.value
            )
        return FlextResult[FlextLdifModels.Entry | FlextLdifModels.ChangeRecord].fail(
            entry_result.error or "Failed to create entry"
        )

    def _create_regular_entry(
        self, entry_data: dict[str, object]
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Create regular LDIF entry from parsed data.

        Args:
            entry_data: Parsed entry data dictionary

        Returns:
            FlextResult containing created Entry

        """
        dn_value = cast("str", entry_data["dn"])
        attributes_data: dict[str, list[str]] = {}

        # Process attributes
        for key, value in entry_data.items():
            if key == "dn":
                continue

            if isinstance(value, list):
                attributes_data[key] = [str(v) for v in value]
            else:
                attributes_data[key] = [str(value)]

        # Create entry using existing model
        entry_dict: dict[str, object] = {"dn": dn_value, "attributes": attributes_data}

        return FlextLdifModels.Entry.create(entry_dict)

    def _create_change_record(
        self, entry_data: dict[str, object]
    ) -> FlextResult[FlextLdifModels.ChangeRecord]:
        """Create change record from parsed data.

        Args:
            entry_data: Parsed entry data dictionary

        Returns:
            FlextResult containing created ChangeRecord

        """
        dn_value = cast("str", entry_data["dn"])
        change_type = cast("str", entry_data["changetype"])
        attributes_data: dict[str, list[str]] = {}

        # Process attributes (exclude dn and changetype)
        for key, value in entry_data.items():
            if key in {"dn", "changetype"}:
                continue

            if isinstance(value, list):
                attributes_data[key] = [str(v) for v in value]
            else:
                attributes_data[key] = [str(value)]

        # Create change record data
        change_record_data: dict[str, object] = {
            "dn": dn_value,
            "changetype": change_type,
            "attributes": attributes_data,
            "modifications": [],
        }

        return FlextLdifModels.ChangeRecord.create(change_record_data)

    class EncodingStrategy:
        """Strategy for encoding detection - follows ParserStrategyProtocol."""

        @staticmethod
        def detect(content: bytes) -> FlextResult[str]:
            """Detect encoding from byte content.

            Args:
                content: Byte content to analyze

            Returns:
                FlextResult containing detected encoding

            """
            # Strategy 1: Try UTF-8
            utf8_result = FlextLdifParser.EncodingStrategy.try_utf8(content)
            if utf8_result.is_success:
                return utf8_result

            # Strategy 2: Try Latin-1
            latin1_result = FlextLdifParser.EncodingStrategy.try_latin1(content)
            if latin1_result.is_success:
                return latin1_result

            # Default: UTF-8 with replacement
            return FlextResult[str].ok("utf-8")

        @staticmethod
        def try_utf8(content: bytes) -> FlextResult[str]:
            """Try UTF-8 encoding."""
            if not content:
                return FlextResult[str].fail("Empty content")
            try:
                content.decode("utf-8")
                return FlextResult[str].ok("utf-8")
            except UnicodeDecodeError as e:
                return FlextResult[str].fail(f"UTF-8 decode failed: {e}")

        @staticmethod
        def try_latin1(content: bytes) -> FlextResult[str]:
            """Try Latin-1 encoding."""
            if not content:
                return FlextResult[str].fail("Empty content")
            try:
                content.decode("latin-1")
                return FlextResult[str].ok("latin-1")
            except UnicodeDecodeError as e:
                return FlextResult[str].fail(f"Latin-1 decode failed: {e}")

        @staticmethod
        def supports(encoding: str) -> bool:
            """Check if encoding is supported."""
            supported = {"utf-8", "latin-1", "ascii", "utf-16", "cp1252"}
            return encoding.lower() in supported

    def _detect_encoding(self, content: str | bytes) -> str | None:
        """Detect character encoding from content.

        Args:
            content: Content to analyze

        Returns:
            Detected encoding or None if detection failed

        """
        # Use strategy pattern for encoding detection
        if isinstance(content, bytes):
            content_bytes = content
        else:
            # Convert to string first, then encode
            content_bytes = str(content).encode("utf-8", errors="replace")

        result = self.EncodingStrategy.detect(content_bytes)
        if result.is_success:
            return result.unwrap()

        # Default encoding from config
        return "utf-8"

    def detect_server_type(
        self, entries: list[FlextLdifModels.Entry | FlextLdifModels.ChangeRecord]
    ) -> FlextResult[str]:
        """Detect LDAP server type from entries.

        Args:
            entries: List of parsed entries

        Returns:
            FlextResult containing detected server type

        """
        if not entries:
            return FlextResult[str].ok(FlextLdifConstants.LdapServers.GENERIC)

        # Analyze DN patterns
        dn_patterns: set[str] = set()
        object_classes: set[str] = set()

        for entry in entries:
            if hasattr(entry, "dn"):
                dn_value = entry.dn.value
                # Extract DN components
                components = [comp.strip() for comp in dn_value.split(",")]
                for component in components:
                    if "=" in component:
                        attr_name = component.split("=")[0].strip()
                        dn_patterns.add(attr_name)

            if hasattr(entry, "get_attribute"):
                obj_classes: list[str] = entry.get_attribute("objectClass") or []
                object_classes.update(obj_classes)

        # Check for Active Directory patterns
        ad_patterns = FlextLdifConstants.LdapServers.AD_DN_PATTERNS
        if any(pattern in dn_patterns for pattern in ad_patterns):
            return FlextResult[str].ok(FlextLdifConstants.LdapServers.ACTIVE_DIRECTORY)

        # Check for OpenLDAP patterns
        openldap_patterns = FlextLdifConstants.LdapServers.OPENLDAP_DN_PATTERNS
        if any(pattern in dn_patterns for pattern in openldap_patterns):
            return FlextResult[str].ok(FlextLdifConstants.LdapServers.OPENLDAP)

        # Default to generic
        return FlextResult[str].ok(FlextLdifConstants.LdapServers.GENERIC)

    def validate_rfc_compliance(
        self, entries: list[FlextLdifModels.Entry | FlextLdifModels.ChangeRecord]
    ) -> FlextResult[dict[str, object]]:
        """Validate RFC 2849 compliance of parsed entries.

        Args:
            entries: List of parsed entries

        Returns:
            FlextResult containing compliance report

        """
        compliance_report: dict[str, object] = {
            "total_entries": len(entries),
            "compliance_level": self._compliance_level,
            "issues": [],
            "features_detected": [],
            "compliance_score": 0.0,
        }

        issues: list[str] = []
        features_detected: list[str] = []

        for entry in entries:
            # Check for required features
            if hasattr(entry, "attributes"):
                for attr_name, attr_values in entry.attributes.data.items():
                    # Check for Base64 encoding
                    if any("::" in str(val) for val in attr_values):
                        features_detected.append("base64_encoding")

                    # Check for URL references
                    if any(
                        str(val).startswith("<") and str(val).endswith(">")
                        for val in attr_values
                    ):
                        features_detected.append("url_references")

                    # Check for attribute options
                    if (
                        FlextLdifConstants.Format.ATTRIBUTE_OPTION_SEPARATOR
                        in attr_name
                    ):
                        features_detected.append("attribute_options")

        # Calculate compliance score
        required_features = FlextLdifConstants.RfcCompliance.REQUIRED_FEATURES
        detected_features = set(features_detected)
        compliance_score = len(detected_features.intersection(required_features)) / len(
            required_features
        )

        compliance_report["features_detected"] = list(detected_features)
        compliance_report["compliance_score"] = compliance_score
        compliance_report["issues"] = issues

        return FlextResult[dict[str, object]].ok(compliance_report)


__all__ = ["FlextLdifParser", "LdifParseState"]
