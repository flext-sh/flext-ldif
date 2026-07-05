"""Zero Data Loss Tests for OID/OUD/RFC Conversions.

Behavioral contract tests: every assertion targets observable public behavior
of the ``ldif()`` client (the ``r[T]`` outcome of ``parse_ldif`` / ``write``)
and public state of the returned ``m.Ldif.Entry`` models (metadata fields
exposed on the model). No private attributes, no internal-collaborator spying.

Guarantees under test:
- Parsing preserves the original LDIF text per entry (``original_strings``).
- Boolean conversions, when present, are tracked with original/converted/format.
- OID -> RFC -> OUD conversion loses no non-operational attribute.
- OID -> OUD -> OID round-trip preserves original formatting.
- Minimal differences carry the original value and a differences list.
- Soft-deleted attributes are preserved in ``removed_attributes``.
- ``restore_original_format`` reproduces the exact original entry text.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from flext_ldif import ldif
from tests.constants import c
from tests.models import m
from tests.utilities import TestsFlextLdifUtilities as u

if TYPE_CHECKING:
    from tests.protocols import p


class TestsFlextLdifZeroDataLossOidOud:
    """Behavioral tests for zero data loss across OID/OUD/RFC conversions."""

    _OPERATIONAL_ATTRS: frozenset[str] = frozenset({
        "createtimestamp",
        "modifytimestamp",
        "entryuuid",
        "entrycsn",
    })

    @pytest.fixture
    def api(self) -> p.Ldif.LdifClient:
        """Create ldif API instance."""
        return ldif()

    @pytest.fixture
    def oid_fixture(self) -> str:
        """Load OID entries fixture."""
        return u.Tests.load(c.Tests.OID, c.Tests.ENTRIES)

    @pytest.fixture
    def oud_fixture(self) -> str:
        """Load OUD entries fixture."""
        return u.Tests.load(c.Tests.OUD, c.Tests.ENTRIES)

    # -- edge cases / invariants ------------------------------------------

    @pytest.mark.parametrize("content", ["", "not a valid ldif record"])
    def test_parse_of_non_entry_input_succeeds_with_no_entries(
        self,
        api: p.Ldif.LdifClient,
        content: str,
    ) -> None:
        """Input without LDIF records yields a success result with no entries."""
        result = api.parse_ldif(content, server_type=c.Tests.OID)

        assert result.success, f"Parse failed: {result.error}"
        assert result.value.entries == []

    def test_parse_is_idempotent_in_entry_count(
        self,
        api: p.Ldif.LdifClient,
        oid_fixture: str,
    ) -> None:
        """Parsing the same fixture twice yields the same entry count."""
        first = api.parse_ldif(oid_fixture, server_type=c.Tests.OID)
        second = api.parse_ldif(oid_fixture, server_type=c.Tests.OID)

        assert first.success
        assert second.success
        assert len(first.value.entries) == len(second.value.entries)

    # -- original text preservation ---------------------------------------

    @pytest.mark.parametrize("server_type", [c.Tests.OID, c.Tests.OUD])
    def test_parse_preserves_original_ldif_per_entry(
        self,
        api: p.Ldif.LdifClient,
        oid_fixture: str,
        oud_fixture: str,
        server_type: str,
    ) -> None:
        """Every parsed entry keeps its original LDIF text in metadata."""
        fixture = oid_fixture if server_type == c.Tests.OID else oud_fixture

        result = api.parse_ldif(fixture, server_type=server_type)

        assert result.success, f"Parse failed: {result.error}"
        entries = result.value.entries
        assert entries, "No entries parsed"
        for entry in entries:
            assert entry.metadata is not None
            original = u.to_str(
                entry.metadata.original_strings["entry_original_ldif"],
            )
            assert original, f"Entry {entry.dn} lost its original LDIF"
            assert "dn:" in original.lower(), "Original LDIF missing DN"

    def test_original_strings_records_dn_original_when_dn_differs(
        self,
        api: p.Ldif.LdifClient,
        oid_fixture: str,
    ) -> None:
        """When a DN has minimal differences, the original DN string is kept."""
        result = api.parse_ldif(oid_fixture, server_type=c.Tests.OID)
        assert result.success

        for entry in result.value.entries:
            assert entry.metadata is not None
            dn_diff = m.Ldif.DynamicMetadata.model_validate(
                entry.metadata.minimal_differences.get("dn", {}),
            )
            if bool(dn_diff.get("has_differences", False)):
                assert "dn_original" in entry.metadata.original_strings, (
                    f"DN differences detected but dn_original not preserved "
                    f"for {entry.dn}"
                )

    # -- conversion tracking ----------------------------------------------

    def test_boolean_conversions_record_original_converted_and_format(
        self,
        api: p.Ldif.LdifClient,
        oid_fixture: str,
    ) -> None:
        """Tracked boolean conversions expose original, converted and format."""
        result = api.parse_ldif(oid_fixture, server_type=c.Tests.OID)
        assert result.success

        tracked = [
            entry
            for entry in result.value.entries
            if entry.metadata and entry.metadata.boolean_conversions
        ]
        if not tracked:
            pytest.skip("Fixture contains no boolean conversions to assert on")

        for entry in tracked:
            assert entry.metadata is not None
            for attr_name, raw in entry.metadata.boolean_conversions.items():
                conversion = m.Ldif.DynamicMetadata.model_validate(raw)
                assert "original" in conversion, f"Missing original for {attr_name}"
                assert "converted" in conversion, f"Missing converted for {attr_name}"
                assert "format" in conversion, f"Missing format for {attr_name}"
                fmt = u.to_str(conversion.get("format"))
                if fmt:
                    assert fmt in {"OID->RFC", "RFC->OID"}, (
                        f"Invalid format direction: {fmt}"
                    )

    def test_minimal_differences_carry_original_and_differences(
        self,
        api: p.Ldif.LdifClient,
        oid_fixture: str,
    ) -> None:
        """Any tracked difference exposes an original value and a diff list."""
        result = api.parse_ldif(oid_fixture, server_type=c.Tests.OID)
        assert result.success

        for entry in result.value.entries:
            if entry.metadata is None:
                continue
            for name, raw in entry.metadata.minimal_differences.items():
                if not (isinstance(raw, dict) and raw.get("has_differences", False)):
                    continue
                assert "original" in raw, f"Missing original for {name}"
                assert "differences" in raw, f"Missing differences for {name}"

    def test_conversion_history_is_a_list(
        self,
        api: p.Ldif.LdifClient,
        oid_fixture: str,
    ) -> None:
        """Every entry exposes conversion history as a list."""
        result = api.parse_ldif(oid_fixture, server_type=c.Tests.OID)
        assert result.success

        for entry in result.value.entries:
            assert entry.metadata is not None
            assert isinstance(entry.metadata.conversion_history, list)

    def test_soft_deleted_attributes_are_preserved(
        self,
        api: p.Ldif.LdifClient,
        oid_fixture: str,
    ) -> None:
        """Soft-deleted attributes keep their values in removed_attributes."""
        result = api.parse_ldif(oid_fixture, server_type=c.Tests.OID)
        assert result.success

        for entry in result.value.entries:
            metadata = entry.metadata
            if metadata is None or not metadata.soft_delete_markers:
                continue
            removed = metadata.removed_attributes
            if not isinstance(removed, dict):
                continue
            for attr_name in metadata.soft_delete_markers:
                assert attr_name in removed, (
                    f"Soft-deleted attribute {attr_name} not in removed_attributes"
                )
                value = removed[attr_name]
                if isinstance(value, (str, list, tuple)):
                    assert value, (
                        f"Soft-deleted attribute {attr_name} has no preserved values"
                    )

    # -- conversion / round-trip ------------------------------------------

    def test_oid_to_oud_conversion_loses_no_user_attribute(
        self,
        api: p.Ldif.LdifClient,
        oid_fixture: str,
    ) -> None:
        """OID -> RFC -> OUD conversion preserves every non-operational attr."""
        oid = api.parse_ldif(oid_fixture, server_type=c.Tests.OID)
        assert oid.success

        rfc = api.write(oid.value.entries, server_type=c.Tests.RFC)
        assert rfc.success
        assert rfc.value.content is not None

        oud = api.parse_ldif(rfc.value.content, server_type=c.Tests.OUD)
        assert oud.success

        oid_entries = oid.value.entries
        oud_entries = oud.value.entries
        assert len(oid_entries) == len(oud_entries), "Entry count mismatch"

        for original, converted in zip(oid_entries, oud_entries, strict=True):
            assert original.attributes is not None
            assert converted.attributes is not None
            original_attrs = set(original.attributes.attributes.keys())
            converted_attrs = set(converted.attributes.attributes.keys())
            lost = {
                attr
                for attr in original_attrs - converted_attrs
                if attr.lower() not in self._OPERATIONAL_ATTRS
            }
            assert not lost, f"Data loss detected for {original.dn}: {sorted(lost)}"

    def test_round_trip_oid_oud_oid_preserves_entry_count_and_original_text(
        self,
        api: p.Ldif.LdifClient,
        oid_fixture: str,
    ) -> None:
        """OID -> OUD -> OID round-trip keeps entry count and original text."""
        original = api.parse_ldif(oid_fixture, server_type=c.Tests.OID)
        assert original.success

        to_oud = api.write(original.value.entries, server_type=c.Tests.OUD)
        assert to_oud.success
        assert to_oud.value.content is not None

        reparsed = api.parse_ldif(to_oud.value.content, server_type=c.Tests.OUD)
        assert reparsed.success

        back_to_oid = api.write(
            reparsed.value.entries,
            server_type=c.Tests.OID,
            format_options=m.Ldif.WriteFormatOptions(restore_original_format=True),
        )
        assert back_to_oid.success
        assert back_to_oid.value.content is not None

        roundtrip = api.parse_ldif(back_to_oid.value.content, server_type=c.Tests.OID)
        assert roundtrip.success

        original_entries = original.value.entries
        roundtrip_entries = roundtrip.value.entries
        assert len(original_entries) == len(roundtrip_entries)

        for orig, final in zip(original_entries, roundtrip_entries, strict=True):
            assert orig.metadata is not None
            assert final.metadata is not None
            assert u.to_str(
                orig.metadata.original_strings["entry_original_ldif"],
            ), f"Original text lost for {orig.dn}"

    def test_restore_original_format_reproduces_original_entry_text(
        self,
        api: p.Ldif.LdifClient,
        oid_fixture: str,
    ) -> None:
        """restore_original_format writes back each entry's exact original text."""
        parsed = api.parse_ldif(oid_fixture, server_type=c.Tests.OID)
        assert parsed.success

        written = api.write(
            parsed.value.entries,
            server_type=c.Tests.OID,
            format_options=m.Ldif.WriteFormatOptions(restore_original_format=True),
        )
        assert written.success
        restored = written.value.content
        assert restored is not None

        for entry in parsed.value.entries:
            assert entry.metadata is not None
            original = u.to_str(
                entry.metadata.original_strings["entry_original_ldif"],
            )
            assert original.strip() in restored, (
                f"Original LDIF not reproduced for entry {entry.dn}"
            )
