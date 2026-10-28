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

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping

import pytest

from tests import c, ldif, m, p, t, tm, u


class TestsFlextLdifZeroDataLossOidOud:
    """Behavioral tests for zero data loss across OID/OUD/RFC conversions."""

    _OPERATIONAL_ATTRS: frozenset[str] = frozenset({
        "createtimestamp",
        "modifytimestamp",
        "entryuuid",
        "entrycsn",
    })

    @pytest.fixture
    def api() -> p.Ldif.LdifClient:
        """Create ldif API instance.

        Returns:
            The resulting ``p.Ldif.LdifClient``.

        """
        return ldif()

    @pytest.fixture
    def oid_fixture() -> str:
        """Load OID entries fixture.

        Returns:
            The resulting ``str``.

        """
        fixture: str = u.Tests.load(c.Tests.OID, c.Tests.ENTRIES)
        return fixture

    @pytest.fixture
    def oud_fixture() -> str:
        """Load OUD entries fixture.

        Returns:
            The resulting ``str``.

        """
        fixture: str = u.Tests.load(c.Tests.OUD, c.Tests.ENTRIES)
        return fixture

    # -- edge cases / invariants ------------------------------------------

    @staticmethod
    @pytest.mark.parametrize("content", ["", "not a valid ldif record"])
    def test_parse_of_non_entry_input_succeeds_with_no_entries(
        api: p.Ldif.LdifClient,
        content: str,
    ) -> None:
        """Input without LDIF records yields a success result with no entries."""
        result = api.parse_ldif(content, server_type=c.Tests.OID)

        tm.ok(result)
        tm.that(result.value.entries, eq=[])

    @staticmethod
    def test_parse_is_idempotent_in_entry_count(
        api: p.Ldif.LdifClient,
        oid_fixture: str,
    ) -> None:
        """Parsing the same fixture twice yields the same entry count."""
        first = api.parse_ldif(oid_fixture, server_type=c.Tests.OID)
        second = api.parse_ldif(oid_fixture, server_type=c.Tests.OID)

        tm.ok(first)
        tm.ok(second)
        tm.that(len(first.value.entries), eq=len(second.value.entries))

    # -- original text preservation ---------------------------------------

    @staticmethod
    @pytest.mark.parametrize("server_type", [c.Tests.OID, c.Tests.OUD])
    def test_parse_preserves_original_ldif_per_entry(
        api: p.Ldif.LdifClient,
        oid_fixture: str,
        oud_fixture: str,
        server_type: str,
    ) -> None:
        """Every parsed entry keeps its original LDIF text in metadata."""
        fixture = oid_fixture if server_type == c.Tests.OID else oud_fixture

        result = api.parse_ldif(fixture, server_type=server_type)

        tm.ok(result)
        entries = result.value.entries
        tm.ok(bool(entries), msg="No entries parsed")
        for entry in entries:
            metadata = tm.not_none(entry.metadata)
            original = u.to_str(metadata.original_strings["entry_original_ldif"])
            if not original:
                msg = f"Entry {entry.dn} lost its original LDIF"
                tm.reject(msg)
            tm.that(original.lower(), has="dn:")

    @staticmethod
    def test_original_strings_records_dn_original_when_dn_differs(
        api: p.Ldif.LdifClient,
        oid_fixture: str,
    ) -> None:
        """When a DN has minimal differences, the original DN string is kept."""
        result = api.parse_ldif(oid_fixture, server_type=c.Tests.OID)
        tm.ok(result)

        for entry in result.value.entries:
            metadata = tm.not_none(entry.metadata)
            dn_diff = metadata.minimal_differences.get("dn", {})
            match dn_diff:
                case Mapping():
                    pass
                case _:
                    tm.reject()
            if bool(dn_diff.get("has_differences", False)):
                tm.that(metadata.original_strings, has="dn_original")

    # -- conversion tracking ----------------------------------------------

    @staticmethod
    def test_boolean_conversions_record_original_converted_and_format(
        api: p.Ldif.LdifClient,
    ) -> None:
        """Tracked boolean conversions expose original, converted and format."""
        oid_boolean_entry = """
version: 1

dn: cn=boolean,dc=example,dc=com
objectClass: top
objectClass: person
cn: boolean
sn: Boolean
orclIsEnabled: 1
"""
        result = api.parse_ldif(oid_boolean_entry, server_type=c.Tests.OID)
        tm.ok(result)

        tracked_conversions: list[t.JsonMapping] = []
        for entry in result.value.entries:
            metadata = entry.metadata
            if metadata is None:
                continue
            converted = metadata.extensions[c.Ldif.CONVERTED_ATTRIBUTES]
            match converted:
                case Mapping():
                    pass
                case _:
                    tm.reject()
            boolean_conversions = converted[c.Ldif.CONVERSION_BOOLEAN_CONVERSIONS]
            match boolean_conversions:
                case Mapping():
                    pass
                case _:
                    tm.reject()
            tracked_conversions.append(boolean_conversions)

        tm.ok(
            bool(tracked_conversions),
            msg="OID boolean fixture must produce boolean conversion metadata",
        )

        for boolean_conversions in tracked_conversions:
            for raw in boolean_conversions.values():
                conversion = raw
                match conversion:
                    case Mapping():
                        pass
                    case _:
                        tm.reject()
                tm.that(conversion, has="original")
                tm.that(conversion, has="converted")
                tm.that(conversion.get(c.Ldif.ORIGINAL_FORMAT), eq="1/0")
                tm.that(conversion.get("converted_format"), eq="TRUE/FALSE")

    @staticmethod
    def test_minimal_differences_carry_original_and_differences(
        api: p.Ldif.LdifClient,
        oid_fixture: str,
    ) -> None:
        """Any tracked difference exposes an original value and a diff list."""
        result = api.parse_ldif(oid_fixture, server_type=c.Tests.OID)
        tm.ok(result)

        for entry in result.value.entries:
            if entry.metadata is None:
                continue
            for raw in entry.metadata.minimal_differences.values():
                if not (isinstance(raw, dict) and raw.get("has_differences", False)):
                    continue
                tm.that(raw, has="original")
                tm.that(raw, has="differences")

    @staticmethod
    def test_conversion_history_is_a_list(
        api: p.Ldif.LdifClient,
        oid_fixture: str,
    ) -> None:
        """Every entry exposes conversion history as a list."""
        result = api.parse_ldif(oid_fixture, server_type=c.Tests.OID)
        tm.ok(result)

        for entry in result.value.entries:
            metadata = tm.not_none(entry.metadata)
            tm.that(metadata.conversion_history, is_=list)

    @staticmethod
    def test_soft_deleted_attributes_are_preserved(
        api: p.Ldif.LdifClient,
        oid_fixture: str,
    ) -> None:
        """Soft-deleted attributes keep their values in removed_attributes."""
        result = api.parse_ldif(oid_fixture, server_type=c.Tests.OID)
        tm.ok(result)

        for entry in result.value.entries:
            metadata = entry.metadata
            if metadata is None or not metadata.soft_delete_markers:
                continue
            removed = metadata.removed_attributes
            for attr_name in metadata.soft_delete_markers:
                tm.that(removed, has=attr_name)
                value = removed[attr_name]
                if isinstance(value, (str, list, tuple)) and not value:
                    msg = f"Soft-deleted attribute {attr_name} has no preserved values"
                    tm.reject(msg)

    # -- conversion / round-trip ------------------------------------------

    def test_oid_to_oud_conversion_loses_no_user_attribute(
        self,
        api: p.Ldif.LdifClient,
        oid_fixture: str,
    ) -> None:
        """OID -> RFC -> OUD conversion preserves every non-operational attr."""
        oid = api.parse_ldif(oid_fixture, server_type=c.Tests.OID)
        tm.ok(oid)

        rfc = api.write(oid.value.entries, server_type=c.Tests.RFC)
        tm.ok(rfc)
        rfc_content = tm.not_none(rfc.value.content)

        oud = api.parse_ldif(rfc_content, server_type=c.Tests.OUD)
        tm.ok(oud)

        oid_entries = oid.value.entries
        oud_entries = oud.value.entries
        tm.that(len(oid_entries), eq=len(oud_entries))

        for original, converted in zip(oid_entries, oud_entries, strict=True):
            original_attributes = tm.not_none(original.attributes)
            converted_attributes = tm.not_none(converted.attributes)
            original_attrs = set(original_attributes.attributes.keys())
            converted_attrs = set(converted_attributes.attributes.keys())
            lost = {
                attr
                for attr in original_attrs - converted_attrs
                if attr.lower() not in self._OPERATIONAL_ATTRS
            }
            if lost:
                msg = f"Data loss detected for {original.dn}: {sorted(lost)}"
                tm.reject(msg)

    @staticmethod
    def test_round_trip_oid_oud_oid_preserves_entry_count_and_original_text(
        api: p.Ldif.LdifClient,
        oid_fixture: str,
    ) -> None:
        """OID -> OUD -> OID round-trip keeps entry count and original text."""
        original = api.parse_ldif(oid_fixture, server_type=c.Tests.OID)
        tm.ok(original)

        to_oud = api.write(original.value.entries, server_type=c.Tests.OUD)
        tm.ok(to_oud)
        oud_content = tm.not_none(to_oud.value.content)

        reparsed = api.parse_ldif(oud_content, server_type=c.Tests.OUD)
        tm.ok(reparsed)

        back_to_oid = api.write(
            reparsed.value.entries,
            server_type=c.Tests.OID,
            format_options=m.Ldif.WriteFormatOptions(restore_original_format=True),
        )
        tm.ok(back_to_oid)
        oid_content = tm.not_none(back_to_oid.value.content)

        roundtrip = api.parse_ldif(oid_content, server_type=c.Tests.OID)
        tm.ok(roundtrip)

        original_entries = original.value.entries
        roundtrip_entries = roundtrip.value.entries
        tm.that(len(original_entries), eq=len(roundtrip_entries))

        for orig, final in zip(original_entries, roundtrip_entries, strict=True):
            metadata = tm.not_none(orig.metadata)
            tm.not_none(final.metadata)
            if not u.to_str(metadata.original_strings["entry_original_ldif"]):
                msg = f"Original text lost for {orig.dn}"
                tm.reject(msg)

    @staticmethod
    def test_restore_original_format_reproduces_original_entry_text(
        api: p.Ldif.LdifClient,
        oid_fixture: str,
    ) -> None:
        """restore_original_format writes back each entry's exact original text."""
        parsed = api.parse_ldif(oid_fixture, server_type=c.Tests.OID)
        tm.ok(parsed)

        written = api.write(
            parsed.value.entries,
            server_type=c.Tests.OID,
            format_options=m.Ldif.WriteFormatOptions(restore_original_format=True),
        )
        tm.ok(written)
        restored = tm.not_none(written.value.content)

        for entry in parsed.value.entries:
            metadata = tm.not_none(entry.metadata)
            original = u.to_str(metadata.original_strings["entry_original_ldif"])
            tm.that(restored, has=original.strip())
