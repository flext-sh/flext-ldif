"""Test suite for OID deviation metadata tracking.

Modules tested: FlextLdifServersOid.Entry, FlextLdifModels.QuirkMetadata
Scope: Zero data loss metadata tracking during OID→RFC conversions. Validates that
original values (boolean conversions, DN spacing, schema quirks) are preserved in
QuirkMetadata for round-trip support. Tests boolean_conversions, original_format_details,
and schema_quirks_applied fields.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import Mapping

import pytest

from flext_ldif import FlextLdifModels
from flext_ldif.servers.oid import FlextLdifServersOid


def build_ldif_text(dn: str, attrs: Mapping[str, object]) -> str:
    """Build LDIF text from DN and attributes dict.

    Args:
        dn: Distinguished Name
        attrs: Attributes dict (name → value or list of values)

    Returns:
        LDIF text string ready for parse()

    """
    lines = [f"dn: {dn}"]
    for attr_name, attr_values in attrs.items():
        if isinstance(attr_values, list):
            for val in attr_values:
                lines.append(f"{attr_name}: {val}")
        else:
            lines.append(f"{attr_name}: {attr_values}")
    return "\n".join(lines) + "\n"


def parse_entry_and_unwrap(
    entry_quirk: FlextLdifServersOid.Entry,
    dn: str,
    attrs: Mapping[str, object],
) -> FlextLdifModels.Entry:
    """Parse entry using public API and unwrap result.

    Args:
        entry_quirk: OID Entry quirk instance
        dn: Distinguished Name
        attrs: Attributes dict

    Returns:
        Parsed Entry model

    Raises:
        AssertionError: If parse fails

    """
    ldif_text = build_ldif_text(dn, attrs)
    result = entry_quirk.parse(ldif_text)
    assert result.is_success, f"Parse failed: {result.error}"
    entries = result.unwrap()
    assert len(entries) > 0, "No entries parsed"
    return entries[0]


class TestOidBooleanConversionMetadata:
    """Test suite for boolean conversion metadata tracking."""

    @pytest.fixture
    def oid_entry(self) -> object:
        """Create OID entry quirk instance."""
        return FlextLdifServersOid().entry_quirk

    def test_boolean_conversions_field_populated(
        self,
        oid_entry: FlextLdifServersOid.Entry,
    ) -> None:
        """Test that boolean_conversions field is populated in metadata."""
        # Create entry with OID boolean attributes
        entry_attrs = {
            "objectClass": ["top", "person"],
            "cn": ["test"],
            "orcldasisenabled": ["1"],  # OID boolean format
            "pwdlockout": ["0"],  # Another OID boolean
        }

        # Use public API via helper
        entry = parse_entry_and_unwrap(
            oid_entry,
            "cn=test,dc=example,dc=com",
            entry_attrs,
        )

        # Verify metadata exists
        assert entry.metadata is not None

        # Verify boolean_conversions field is populated
        assert len(entry.metadata.boolean_conversions) > 0

        # Verify conversion details
        if "orcldasisenabled" in entry.metadata.boolean_conversions:
            conv = entry.metadata.boolean_conversions["orcldasisenabled"]
            assert conv["original"] == "1"
            assert conv["converted"] == "TRUE"
            assert conv["format"] == "OID->RFC"

        if "pwdlockout" in entry.metadata.boolean_conversions:
            conv = entry.metadata.boolean_conversions["pwdlockout"]
            assert conv["original"] == "0"
            assert conv["converted"] == "FALSE"
            assert conv["format"] == "OID->RFC"

    def test_original_format_details_populated(
        self,
        oid_entry: FlextLdifServersOid.Entry,
    ) -> None:
        """Test that original_format_details is populated for round-trip."""
        entry_attrs = {
            "objectClass": ["top", "person"],
            "cn": ["test"],
            "orcldasisenabled": ["1"],
        }

        result = oid_entry._parse_entry(
            "cn=test,dc=example,dc=com",
            entry_attrs,
        )

        assert result.is_success
        entry = result.unwrap()

        # Verify original_format_details is populated
        assert entry.metadata is not None
        assert len(entry.metadata.original_format_details) > 0

        # Verify essential fields
        assert entry.metadata.original_format_details.get("server_type") == "oid"
        assert entry.metadata.original_format_details.get("boolean_format") == "0/1"
        assert "dn_spacing" in entry.metadata.original_format_details

    def test_no_boolean_conversion_metadata_when_no_conversions(
        self,
        oid_entry: FlextLdifServersOid.Entry,
    ) -> None:
        """Test no boolean metadata when no conversions needed."""
        # Entry without OID boolean attributes
        entry_attrs = {
            "objectClass": ["top", "person"],
            "cn": ["test"],
            "sn": ["User"],
        }

        result = oid_entry._parse_entry(
            "cn=test,dc=example,dc=com",
            entry_attrs,
        )

        assert result.is_success
        entry = result.unwrap()

        # Verify boolean_conversions is empty
        assert entry.metadata is not None
        assert len(entry.metadata.boolean_conversions) == 0

        # But original_format_details should still indicate RFC format
        assert entry.metadata.original_format_details.get("boolean_format") == "RFC"


class TestOidSchemaQuirkMetadata:
    """Test suite for schema quirk metadata tracking."""

    @pytest.fixture
    def oid_entry(self) -> object:
        """Create OID entry quirk instance."""
        return FlextLdifServersOid().entry_quirk

    def test_schema_dn_quirk_tracked(
        self,
        oid_entry: FlextLdifServersOid.Entry,
    ) -> None:
        """Test that schema DN normalization is tracked in metadata."""
        # OID uses cn=subschemasubentry, RFC uses cn=schema
        entry_attrs = {
            "objectClass": ["top", "subentry"],
            "cn": ["subschemasubentry"],
        }

        result = oid_entry._parse_entry(
            "cn=subschemasubentry",  # OID schema DN quirk
            entry_attrs,
        )

        assert result.is_success
        entry = result.unwrap()

        # Verify schema quirk is tracked
        assert entry.metadata is not None
        assert "schema_dn_normalization" in entry.metadata.schema_quirks_applied


class TestOidMetadataRoundTrip:
    """Test suite for round-trip metadata support."""

    @pytest.fixture
    def oid_entry(self) -> object:
        """Create OID entry quirk instance."""
        return FlextLdifServersOid().entry_quirk

    def test_metadata_contains_all_conversion_details(
        self,
        oid_entry: FlextLdifServersOid.Entry,
    ) -> None:
        """Test metadata has all details needed for reverse conversion."""
        entry_attrs = {
            "objectClass": ["top", "person"],
            "cn": ["test"],
            "orcldasisenabled": ["1"],
            "pwdlockout": ["0"],
            "pwdmustchange": ["1"],
        }

        result = oid_entry._parse_entry(
            "cn=test,dc=example,dc=com",
            entry_attrs,
        )

        assert result.is_success
        entry = result.unwrap()

        # Count tracked conversions
        assert entry.metadata is not None
        conversion_count = len(entry.metadata.boolean_conversions)

        # All boolean attributes should be tracked
        assert conversion_count >= 2  # At least orcldasisenabled and pwdlockout

        # Each conversion should have original, converted, and format
        for attr_name, conv in entry.metadata.boolean_conversions.items():
            assert "original" in conv, f"Missing 'original' for {attr_name}"
            assert "converted" in conv, f"Missing 'converted' for {attr_name}"
            assert "format" in conv, f"Missing 'format' for {attr_name}"

    def test_original_dn_preserved_in_metadata(
        self,
        oid_entry: FlextLdifServersOid.Entry,
    ) -> None:
        """Test original DN is preserved for round-trip."""
        original_dn = "cn=test, dc=example, dc=com"  # DN with spaces
        entry_attrs = {
            "objectClass": ["top", "person"],
            "cn": ["test"],
        }

        result = oid_entry._parse_entry(
            original_dn,
            entry_attrs,
        )

        assert result.is_success
        entry = result.unwrap()

        # Verify original DN is preserved
        assert entry.metadata is not None
        preserved_dn = entry.metadata.original_format_details.get("dn_spacing")
        assert preserved_dn == original_dn


class TestMetadataUtilitiesIntegration:
    """Test suite for metadata utilities integration."""

    def test_quirk_metadata_boolean_conversions_field_type(self) -> None:
        """Test that boolean_conversions field has correct type."""
        metadata = FlextLdifModels.QuirkMetadata(quirk_type="oid")

        # Field should be dict[str, dict[str, str]]
        metadata.boolean_conversions["test_attr"] = {
            "original": "1",
            "converted": "TRUE",
            "format": "OID->RFC",
        }

        assert len(metadata.boolean_conversions) == 1
        assert metadata.boolean_conversions["test_attr"]["original"] == "1"

    def test_quirk_metadata_original_format_details_field_type(self) -> None:
        """Test that original_format_details field has correct type."""
        metadata = FlextLdifModels.QuirkMetadata(quirk_type="oid")

        # Field should be dict[str, object]
        metadata.original_format_details = {
            "dn_spacing": "cn=test,dc=example",
            "boolean_format": "0/1",
            "server_type": "oid",
        }

        assert metadata.original_format_details["server_type"] == "oid"

    def test_quirk_metadata_schema_quirks_applied_field_type(self) -> None:
        """Test that schema_quirks_applied field has correct type."""
        metadata = FlextLdifModels.QuirkMetadata(quirk_type="oid")

        # Field should be list[str]
        metadata.schema_quirks_applied.append("schema_dn_normalization")
        metadata.schema_quirks_applied.append("matching_rule_normalization")

        assert len(metadata.schema_quirks_applied) == 2
        assert "schema_dn_normalization" in metadata.schema_quirks_applied
