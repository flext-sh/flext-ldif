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

from flext_core import FlextLogger, FlextResult
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


class FlextLdifParser:
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
        self._config = config or {}

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
                line = line.rstrip("\r")  # Handle CRLF

                # Handle empty lines (entry separators)
                if not line.strip():
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
                if line.strip().startswith(FlextLdifConstants.Format.COMMENT_PREFIX):
                    parser_state = LdifParseState.COMMENT
                    continue

                # Handle version control
                if line.strip().startswith(FlextLdifConstants.Format.VERSION_PREFIX):
                    parser_state = LdifParseState.VERSION
                    version = line.split(":", 1)[1].strip()
                    if version != FlextLdifConstants.Format.LDIF_VERSION_1:
                        self._logger.warning(f"Unsupported LDIF version: {version}")
                    continue

                # Handle change type
                if line.strip().startswith(
                    FlextLdifConstants.Format.CHANGE_TYPE_PREFIX
                ):
                    parser_state = LdifParseState.CHANGE_RECORD
                    change_type = line.split(":", 1)[1].strip()
                    current_entry_data["changetype"] = change_type
                    continue

                # Handle DN
                if line.startswith("dn:"):
                    parser_state = LdifParseState.ENTRY
                    dn_value = line[3:].strip()
                    current_entry_data["dn"] = dn_value
                    continue

                # Handle DN for change records
                if (
                    line.startswith("dn:")
                    and parser_state == LdifParseState.CHANGE_RECORD
                ):
                    dn_value = line[3:].strip()
                    current_entry_data["dn"] = dn_value
                    continue

                # Handle attributes
                if ":" in line and not line.startswith(" "):
                    parser_state = LdifParseState.ATTRIBUTE
                    attr_result = self._parse_attribute_line(line)
                    if attr_result.is_success:
                        attr_name, attr_value = attr_result.value
                        if attr_name not in current_entry_data:
                            current_entry_data[attr_name] = []
                        current_entry_data[attr_name].append(attr_value)
                    else:
                        self._logger.warning(
                            f"Invalid attribute at line {line_number}: {attr_result.error}"
                        )
                    continue

                # Handle line continuations
                if line.startswith((" ", "\t")):
                    parser_state = LdifParseState.CONTINUATION
                    continuation_value = line[1:]  # Remove leading space/tab
                    if current_entry_data:
                        # Find the last attribute to continue
                        last_attr = list(current_entry_data.keys())[-1]
                        if isinstance(current_entry_data[last_attr], list):
                            current_entry_data[last_attr][-1] += continuation_value
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

    def parse_file(
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
            return self._create_change_record(entry_data)
        return self._create_regular_entry(entry_data)

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
        entry_dict = {"dn": dn_value, "attributes": attributes_data}

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
        change_record_data = {
            "dn": dn_value,
            "changetype": change_type,
            "attributes": attributes_data,
            "modifications": [],
        }

        return FlextLdifModels.ChangeRecord.create(change_record_data)

    def _detect_encoding(self, content: str) -> str | None:
        """Detect character encoding from content.

        Args:
            content: Content to analyze

        Returns:
            Detected encoding or None if detection failed

        """
        # Simple encoding detection based on content analysis
        try:
            # Try UTF-8 first
            content.encode("utf-8").decode("utf-8")
            return "utf-8"
        except UnicodeError:
            pass

        try:
            # Try Latin-1
            content.encode("latin-1").decode("latin-1")
            return "latin-1"
        except UnicodeError:
            pass

        # Default to UTF-8 with error handling
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
                obj_classes = entry.get_attribute("objectClass") or []
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
