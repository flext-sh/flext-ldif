"""Behavioral tests for minimal-differences metadata tracking.

Exercises the public contract of the LDIF parse -> Entry(metadata) -> write
pipeline: fallible ``r[T]`` outcomes, ``Entry.metadata`` public fields, the
boolean-conversion metadata payload, verbatim DN preservation, and round-trip
``write()`` output. No private attributes, collaborators, or internal call
spying are touched -- only observable public behavior.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

import pytest

from flext_ldif import FlextLdif, ldif
from flext_ldif.services import FlextLdifParser
from tests import c, m, p, tm


class TestsFlextLdifMinimalDifferencesMetadata:
    """Public-contract tests for minimal-differences metadata capture."""

    @pytest.fixture
    @staticmethod
    def parser() -> FlextLdifParser:
        """Provide a parser instance.

        Returns:
            The resulting ``FlextLdifParser``.

        """
        return FlextLdifParser(registry=FlextLdif().registry)

    @pytest.fixture
    @staticmethod
    def writer() -> p.Ldif.LdifClient:
        """Provide a writer client via the public ``ldif()`` entry point.

        Returns:
            The resulting ``p.Ldif.LdifClient``.

        """
        return ldif()

    @pytest.fixture
    @staticmethod
    def fixtures_dir() -> Path:
        """Locate the shared LDIF fixtures directory.

        Returns:
            The resulting ``Path``.

        """
        return Path(__file__).parent.parent / "fixtures"

    # -- server_type propagation ------------------------------------------

    @staticmethod
    @pytest.mark.parametrize(
        ("server_type", "effective_server_type"),
        [
            (c.Tests.OID, c.Tests.OID),
            (c.Tests.OUD, c.Tests.RFC),
            (c.Tests.RFC, c.Tests.RFC),
        ],
    )
    def test_parsed_entry_metadata_reports_effective_server_type(
        parser: FlextLdifParser,
        server_type: str,
        effective_server_type: str,
    ) -> None:
        """Entry metadata records the effective (normalized) server family.

        OUD is RFC-compliant, so its metadata normalizes to ``rfc``; OID keeps
        its own identity.
        """
        content = (
            "dn: cn=test,dc=example,dc=com\n"
            "objectClass: top\n"
            "objectClass: person\n"
            "cn: test\n"
        )

        result = parser.parse_string(content=content, server_type=server_type)

        tm.ok(result)
        entries = result.value.entries
        tm.that(len(entries), eq=1)
        metadata = tm.not_none(entries[0].metadata)
        tm.that(str(metadata.server_type), eq=effective_server_type)

    # -- fixture-driven capture -------------------------------------------

    @staticmethod
    @pytest.mark.parametrize(
        ("server_type", "effective_server_type", "fixture_name"),
        [
            (c.Tests.OID, c.Tests.OID, "oid_entries_fixtures.ldif"),
            (c.Tests.OUD, c.Tests.RFC, "oud_entries_fixtures.ldif"),
        ],
    )
    def test_fixture_entries_all_carry_matching_server_metadata(
        parser: FlextLdifParser,
        fixtures_dir: Path,
        server_type: str,
        effective_server_type: str,
        fixture_name: str,
    ) -> None:
        """Every entry parsed from a server fixture carries its effective type."""
        fixture_path = fixtures_dir / server_type / fixture_name

        result = parser.parse_ldif_file(path=fixture_path, server_type=server_type)

        tm.ok(result)
        entries = result.value.entries
        if not entries:
            msg = f"No entries parsed from {fixture_path}"
            tm.reject(msg)
        for entry in entries:
            metadata = tm.not_none(entry.metadata)
            tm.that(str(metadata.server_type), eq=effective_server_type)

    # -- original DN capture ----------------------------------------------

    @staticmethod
    def test_oid_parse_captures_complete_original_dn(
        parser: FlextLdifParser,
    ) -> None:
        """OID parsing records the complete original DN under extensions."""
        content = "dn: cn=test,dc=example,dc=com\nobjectClass: top\ncn: test\n"

        result = parser.parse_string(content=content, server_type=c.Tests.OID)

        tm.ok(result)
        metadata = tm.not_none(result.value.entries[0].metadata)
        tm.that(
            metadata.extensions["original_dn_complete"], eq="cn=test,dc=example,dc=com"
        )

    @staticmethod
    def test_dn_whitespace_preserved_verbatim_on_parse(
        parser: FlextLdifParser,
    ) -> None:
        """DN spacing is preserved exactly as written through the parse."""
        content = "dn: cn=test, dc=example, dc=com\nobjectClass: top\ncn: test\n"

        result = parser.parse_string(content=content, server_type=c.Tests.RFC)

        tm.ok(result)
        entry = result.value.entries[0]
        tm.that(str(entry.dn), eq="cn=test, dc=example, dc=com")

    # -- boolean conversion metadata --------------------------------------

    @staticmethod
    @pytest.mark.parametrize(
        ("attribute", "raw_value", "converted_value"),
        [
            ("orcldasisenabled", c.ParserBooleanToken.ONE, "TRUE"),
            ("pwdlockout", c.ParserBooleanToken.ZERO, "FALSE"),
        ],
    )
    def test_oid_boolean_conversion_recorded_in_metadata(
        parser: FlextLdifParser,
        attribute: str,
        raw_value: str,
        converted_value: str,
    ) -> None:
        """OID 0/1 booleans are recorded with original and converted values."""
        content = (
            "dn: cn=test,dc=example,dc=com\n"
            "objectClass: top\n"
            "cn: test\n"
            f"{attribute}: {raw_value}\n"
        )

        result = parser.parse_string(content=content, server_type=c.Tests.OID)

        tm.ok(result)
        metadata = tm.not_none(result.value.entries[0].metadata)
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
        tm.that(boolean_conversions, has=attribute)
        entry_conversion = boolean_conversions[attribute]
        match entry_conversion:
            case Mapping():
                pass
            case _:
                tm.reject()
        tm.that(entry_conversion[c.Ldif.CONVERSION_ORIGINAL_VALUE], eq=[raw_value])
        tm.that(
            entry_conversion[c.Ldif.CONVERSION_CONVERTED_VALUE],
            eq=[converted_value],
        )

    # -- round-trip write --------------------------------------------------

    @staticmethod
    def test_round_trip_write_emits_converted_boolean_value(
        parser: FlextLdifParser,
        writer: p.Ldif.LdifClient,
    ) -> None:
        """OID -> write converts the boolean and preserves the DN in output."""
        content = (
            "dn: cn=test,dc=example,dc=com\n"
            "objectClass: top\n"
            "cn: test\n"
            "orcldasisenabled: 1\n"
        )
        parse_result = parser.parse_string(content=content, server_type=c.Tests.OID)
        tm.ok(parse_result)
        entry = m.Ldif.Entry.model_validate(parse_result.value.entries[0])

        write_result = writer.write(entries=[entry])

        tm.ok(write_result)
        written = tm.not_none(write_result.value.content)
        tm.that(written, has="dn: cn=test,dc=example,dc=com")
        tm.that(written, has="orcldasisenabled: TRUE")

    # -- operational attribute preservation -------------------------------

    @staticmethod
    @pytest.mark.parametrize(
        ("attribute", "value"),
        [
            ("creatorsName", "cn=Directory Manager"),
            ("createTimestamp", "20250101000000Z"),
        ],
    )
    def test_operational_attributes_preserved_through_parse(
        parser: FlextLdifParser,
        attribute: str,
        value: str,
    ) -> None:
        """Operational attributes survive parsing and stay publicly readable."""
        content = (
            "dn: cn=test,dc=example,dc=com\n"
            "objectClass: top\n"
            "cn: test\n"
            "creatorsName: cn=Directory Manager\n"
            "createTimestamp: 20250101000000Z\n"
        )

        result = parser.parse_string(content=content, server_type=c.Tests.RFC)

        tm.ok(result)
        entry = result.value.entries[0]
        tm.not_none(entry.metadata)
        attributes = tm.not_none(entry.attributes)
        tm.that(attributes.get(attribute), eq=[value])

    # -- invariants and error paths ---------------------------------------

    @staticmethod
    def test_metadata_capture_is_idempotent_across_repeated_parses(
        parser: FlextLdifParser,
    ) -> None:
        """Parsing identical content twice yields identical metadata."""
        content = (
            "dn: cn=test,dc=example,dc=com\n"
            "objectClass: top\n"
            "cn: test\n"
            "orcldasisenabled: 1\n"
        )

        first = parser.parse_string(content=content, server_type=c.Tests.OID)
        second = parser.parse_string(content=content, server_type=c.Tests.OID)

        tm.ok(first.success)
        tm.ok(second.success)
        first_meta = tm.not_none(first.value.entries[0].metadata)
        second_meta = tm.not_none(second.value.entries[0].metadata)
        tm.that(str(first_meta.server_type), eq=str(second_meta.server_type))
        tm.that(first_meta.extensions, eq=second_meta.extensions)

    @staticmethod
    def test_unknown_server_type_returns_failure_with_reason(
        parser: FlextLdifParser,
    ) -> None:
        """An unknown server_type fails with a descriptive error, not a crash."""
        content = "dn: cn=test,dc=example,dc=com\ncn: test\n"

        result = parser.parse_string(content=content, server_type="nonexistent_server")

        tm.fail(result)
        tm.not_none(result.error)
        tm.that(result.error, has="nonexistent_server")
