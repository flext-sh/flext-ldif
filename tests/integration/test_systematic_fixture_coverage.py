"""Systematic fixture coverage for all serverxfixture type combinations.

Behavioral contract tests: every LDAP server fixture type must survive the
public parse -> write -> parse cycle exposed by ``flext_ldif.ldif()``. Only the
public API is exercised (``parse_ldif``, ``write``, ``r[T]`` outcomes and the
public model surface of parse/write responses and entries); no private state,
no internal collaborator spying, no mock-based testing.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_ldif import ldif
from tests import p, tm


class TestsFlextLdifSystematicFixtureCoverage:
    """Public parse/write contract across the serverxfixture-type matrix."""

    @staticmethod
    @pytest.fixture(scope="class")
    def api() -> p.Ldif.LdifClient:
        """Public LDIF client under test.

        Returns:
            The resulting ``p.Ldif.LdifClient``.

        """
        return ldif()

    @staticmethod
    def _fixture_content(request: pytest.FixtureRequest, name: str) -> str:
        """Require native nonempty fixture text at its input boundary.

        Returns:
            The original fixture string without copying or converting it.

        """
        content = request.getfixturevalue(name)
        if not content:
            message = f"Fixture {name} is empty"
            tm.reject(message)
        return tm.instance(content, str)

    # ------------------------------------------------------------------
    # Test-data shaping helper (bounds oversized schema fixtures — this is
    # input preparation, NOT inspection of the unit under test).
    # ------------------------------------------------------------------
    @staticmethod
    def _bounded_schema_sample(fixture_data: str, max_definitions: int = 50) -> str:
        """Return a schema LDIF sample capped to ``max_definitions`` defs."""
        lines = fixture_data.splitlines()
        first_dn = next(
            (line for line in lines if line.startswith("dn:")),
            "dn: cn=schema",
        )
        selected_lines: list[str] = [first_dn]
        current_chunk: list[str] = []
        definitions_count = 0

        def flush_chunk() -> None:
            nonlocal definitions_count, current_chunk
            if not current_chunk:
                return
            if definitions_count < max_definitions:
                selected_lines.extend(current_chunk)
                definitions_count += 1
            current_chunk = []

        for line in lines:
            if line.startswith(("attributeTypes:", "objectClasses:")):
                flush_chunk()
                if definitions_count >= max_definitions:
                    break
                current_chunk = [line]
                continue
            if current_chunk and line[:1].isspace():
                current_chunk.append(line)
                continue
            flush_chunk()
        flush_chunk()
        selected_lines.append("")
        return "\n".join(selected_lines)

    # ------------------------------------------------------------------
    # Shared behavioral assertion: the roundtrip contract.
    # ------------------------------------------------------------------
    @staticmethod
    def _assert_roundtrip_preserves_dns(
        api: p.Ldif.LdifClient,
        content: str,
    ) -> int:
        """Parse -> write -> parse ``content`` and assert DN-set preservation.

        Returns the number of entries parsed from the original content so
        callers can add fixture-specific invariants.

        Returns:
            The resulting ``int``.

        """
        parse_result = api.parse_ldif(content)
        tm.ok(parse_result)
        entries = parse_result.unwrap().entries
        tm.that(entries, truth=True, msg="Expected at least one parsed entry")
        original_count = len(entries)
        original_dns = {entry.dn_str for entry in entries}

        write_result = api.write(entries)
        tm.ok(write_result)
        written = write_result.unwrap().content
        if not written:
            message = "Write produced empty content"
            tm.reject(message)

        roundtrip_result = api.parse_ldif(written)
        tm.ok(roundtrip_result)
        roundtrip_entries = roundtrip_result.unwrap().entries

        tm.that(len(roundtrip_entries), eq=original_count)
        roundtrip_dns = {e.dn_str for e in roundtrip_entries}
        tm.that(original_dns, eq=roundtrip_dns)
        return original_count

    # ------------------------------------------------------------------
    # Schema fixtures.
    # ------------------------------------------------------------------
    @pytest.mark.parametrize(
        "server_fixture",
        ["oid_schema_fixture", "oud_schema_fixture"],
        ids=["OID Schema", "OUD Schema"],
    )
    def test_schema_fixture_survives_parse_write_roundtrip(
        self,
        api: p.Ldif.LdifClient,
        server_fixture: str,
        request: pytest.FixtureRequest,
    ) -> None:
        """Schema fixtures parse to entries preserved across the roundtrip."""
        fixture_data = self._fixture_content(request, server_fixture)
        sample = self._bounded_schema_sample(fixture_data)
        tm.that(sample.strip(), truth=True, msg="Bounded schema sample is empty")

        self._assert_roundtrip_preserves_dns(api, sample)

    # ------------------------------------------------------------------
    # ACL fixtures (ACLs are attributes on entries, not standalone entries).
    # ------------------------------------------------------------------
    @staticmethod
    @pytest.mark.parametrize(
        "server_fixture",
        ["oid_acl_fixture", "oud_acl_fixture"],
        ids=["OID ACL", "OUD ACL"],
    )
    def test_acl_fixture_parses_and_writes(
        api: p.Ldif.LdifClient,
        server_fixture: str,
        request: pytest.FixtureRequest,
    ) -> None:
        """ACL fixtures parse successfully and re-serialize non-empty output."""
        fixture_data = TestsFlextLdifSystematicFixtureCoverage._fixture_content(
            request, server_fixture
        )

        parse_result = api.parse_ldif(fixture_data)
        tm.ok(parse_result)
        entries = parse_result.unwrap().entries

        write_result = api.write(entries)
        tm.ok(write_result)
        written = write_result.unwrap().content
        if entries:
            tm.that(written, truth=True, msg="Write produced empty ACL content")

    # ------------------------------------------------------------------
    # Entry fixtures.
    # ------------------------------------------------------------------
    @pytest.mark.parametrize(
        "server_fixture",
        ["oid_entries_fixture", "oud_entries_fixture"],
        ids=["OID Entries", "OUD Entries"],
    )
    def test_entries_fixture_yields_valid_entries_and_roundtrips(
        self,
        api: p.Ldif.LdifClient,
        server_fixture: str,
        request: pytest.FixtureRequest,
    ) -> None:
        """Each parsed entry exposes a DN and attributes; roundtrip is stable."""
        fixture_data = self._fixture_content(request, server_fixture)

        parse_result = api.parse_ldif(fixture_data)
        tm.ok(parse_result)
        entries = parse_result.unwrap().entries
        tm.that(
            entries,
            truth=True,
            msg="Entry fixture should parse to at least one entry",
        )

        for entry in entries:
            tm.that(entry.dn_str, truth=True, msg="Parsed entry exposes an empty DN")
            if not entry.attributes_dict:
                message = f"Entry {entry.dn_str} exposes no attributes"
                tm.reject(message)

        self._assert_roundtrip_preserves_dns(api, fixture_data)

    # ------------------------------------------------------------------
    # Integration fixtures (full directory exports).
    # ------------------------------------------------------------------
    @pytest.mark.parametrize(
        "server_fixture",
        ["oid_integration_fixture", "oud_integration_fixture"],
        ids=["OID Integration", "OUD Integration"],
    )
    def test_integration_fixture_roundtrips_without_data_loss(
        self,
        api: p.Ldif.LdifClient,
        server_fixture: str,
        request: pytest.FixtureRequest,
    ) -> None:
        """Large exports keep unique DNs and roughly their size on rewrite."""
        fixture_data = self._fixture_content(request, server_fixture)

        parse_result = api.parse_ldif(fixture_data)
        tm.ok(parse_result)
        entries = parse_result.unwrap().entries
        min_fixture_entries = 5
        if len(entries) < min_fixture_entries:
            message = (
                f"Integration fixture should hold multiple entries, got {len(entries)}"
            )
            tm.reject(message)

        dn_list = [e.dn_str for e in entries]
        tm.that(len(set(dn_list)), eq=len(dn_list))

        write_result = api.write(entries)
        tm.ok(write_result)
        written = write_result.unwrap().content
        if not written:
            message = "Write produced empty content"
            tm.reject(message)
        tm.that(
            len(written) > len(fixture_data) * 0.5,
            truth=True,
            msg="Rewritten content is far smaller than the source (possible data loss)",
        )

        self._assert_roundtrip_preserves_dns(api, fixture_data)

    # ------------------------------------------------------------------
    # Baseline RFC operations (always available).
    # ------------------------------------------------------------------
    @staticmethod
    def test_basic_ldif_operations_are_available_for_any_server(
        api: p.Ldif.LdifClient,
    ) -> None:
        """A minimal RFC entry parses, writes, and roundtrips with DN intact."""
        content = (
            "dn: cn=Test,dc=example,dc=com\n"
            "objectClass: person\n"
            "cn: Test\n"
            "sn: User\n"
            "mail: test@example.com\n"
        )

        parse_result = api.parse_ldif(content)
        tm.ok(parse_result)
        entries = parse_result.unwrap().entries
        tm.that(len(entries), eq=1)

        entry = entries[0]
        tm.that(entry.dn_str.lower(), has="cn=test,dc=example,dc=com")
        tm.that(
            entry.attributes_dict, truth=True, msg="Baseline entry lost its attributes"
        )

        write_result = api.write(entries)
        tm.ok(write_result)
        written = write_result.unwrap().content
        if not written:
            message = "Write produced empty content"
            tm.reject(message)
        tm.that(written.lower(), has="cn=test,dc=example,dc=com")

        roundtrip_result = api.parse_ldif(written)
        tm.ok(roundtrip_result)
        roundtrip_entries = roundtrip_result.unwrap().entries
        tm.that(len(roundtrip_entries), eq=1)
        tm.that(roundtrip_entries[0].dn_str, eq=entry.dn_str)

    @staticmethod
    def test_parse_ldif_reports_failure_as_result_for_invalid_input(
        api: p.Ldif.LdifClient,
    ) -> None:
        """Malformed LDIF surfaces through the ``r[T]`` channel, not a crash."""
        # A continuation line with no preceding attribute is not valid LDIF.
        result = api.parse_ldif(" orphan continuation line\n")
        if result.success:
            # If tolerated, it must not fabricate entries out of garbage.
            tm.that(result.unwrap().entries, eq=[])
        else:
            tm.that(
                result.error,
                truth=True,
                msg="Failure result must carry an error message",
            )
