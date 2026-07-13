"""Behavioral tests for public LDIF statistics service APIs.

Every assertion exercises the observable contract of
``LdifClient.calculate_for_entries`` — the ``r[T]`` success outcome and the
public fields of :class:`m.Ldif.EntriesStatistics` (``total_entries`` and the
``DynamicCounts`` distributions). No private attribute, collaborator spying, or
patching of the unit under test is used.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from flext_tests import tm

from tests.constants import c
from tests.models import m
from tests.utilities import TestsFlextLdifUtilities as u

if TYPE_CHECKING:
    from tests.protocols import p


class TestsFlextLdifStatisticsService:
    """Validate entries statistics generation through public methods only."""

    @staticmethod
    def _entry(dn: str, server_type: str) -> m.Ldif.Entry:
        """Build a real Entry carrying ``server_type`` in its public metadata."""
        entry = u.Tests.create_real_entry(
            dn=dn,
            attributes={
                "objectClass": [c.Tests.STATS_EXPECTED_OBJECTCLASS, "top"],
                "cn": ["stats-user"],
            },
            server_type=server_type,
        )
        if entry.metadata is None or entry.metadata.extensions is None:
            return entry
        metadata_with_server = entry.metadata.model_copy(
            update={
                "extensions": {
                    **entry.metadata.extensions,
                    "server_type": server_type,
                },
            },
        )
        return entry.model_copy(update={"metadata": metadata_with_server})

    def _entries(self, count: int) -> list[m.Ldif.Entry]:
        """Build ``count`` entries alternating across the known server types."""
        server_types = c.Tests.STATS_SERVER_TYPES
        return [
            self._entry(
                f"cn=stats-{index},dc=example,dc=com",
                server_types[index % len(server_types)],
            )
            for index in range(count)
        ]

    def test_returns_success_result_for_entry_list(
        self,
        api: p.Ldif.LdifClient,
    ) -> None:
        result = api.calculate_for_entries(self._entries(2))

        stats: m.Ldif.EntriesStatistics = u.Tests.assert_success(result)
        assert isinstance(stats, m.Ldif.EntriesStatistics)

    @pytest.mark.parametrize("count", [0, 1, 2, 5])
    def test_total_entries_equals_input_count(
        self,
        api: p.Ldif.LdifClient,
        count: int,
    ) -> None:
        result = api.calculate_for_entries(self._entries(count))

        stats: m.Ldif.EntriesStatistics = u.Tests.assert_success(result)
        tm.that(stats.total_entries, eq=count)

    def test_object_class_distribution_counts_shared_objectclass(
        self,
        api: p.Ldif.LdifClient,
    ) -> None:
        result = api.calculate_for_entries(self._entries(3))

        stats: m.Ldif.EntriesStatistics = u.Tests.assert_success(result)
        tm.that(
            stats.object_class_distribution.get(c.Tests.STATS_EXPECTED_OBJECTCLASS, 0),
            eq=3,
        )
        tm.that(stats.object_class_distribution.get("top", 0), eq=3)

    def test_server_type_distribution_partitions_by_server_type(
        self,
        api: p.Ldif.LdifClient,
    ) -> None:
        entries = [
            self._entry("cn=stats-rfc,dc=example,dc=com", c.Tests.RFC),
            self._entry("cn=stats-oid,dc=example,dc=com", c.Tests.OID),
        ]

        result = api.calculate_for_entries(entries)

        stats: m.Ldif.EntriesStatistics = u.Tests.assert_success(result)
        tm.that(stats.server_type_distribution.get(c.Tests.RFC, 0), eq=1)
        tm.that(stats.server_type_distribution.get(c.Tests.OID, 0), eq=1)

    @pytest.mark.parametrize("server_type", [c.Tests.RFC, c.Tests.OID])
    def test_single_server_type_produces_single_count(
        self,
        api: p.Ldif.LdifClient,
        server_type: str,
    ) -> None:
        entries = [
            self._entry(f"cn=stats-{index},dc=example,dc=com", server_type)
            for index in range(3)
        ]

        result = api.calculate_for_entries(entries)

        stats: m.Ldif.EntriesStatistics = u.Tests.assert_success(result)
        tm.that(stats.server_type_distribution.get(server_type, 0), eq=3)

    def test_empty_entries_yields_zero_totals_and_empty_distributions(
        self,
        api: p.Ldif.LdifClient,
    ) -> None:
        result = api.calculate_for_entries([])

        stats: m.Ldif.EntriesStatistics = u.Tests.assert_success(result)
        tm.that(stats.total_entries, eq=0)
        tm.that(len(stats.object_class_distribution), eq=0)
        tm.that(len(stats.server_type_distribution), eq=0)

    def test_parse_response_input_equals_entry_list_input(
        self,
        api: p.Ldif.LdifClient,
    ) -> None:
        entries = [
            self._entry("cn=stats-parse,dc=example,dc=com", c.Tests.RFC),
            self._entry("cn=stats-parse2,dc=example,dc=com", c.Tests.OID),
        ]
        parse_response = m.Ldif.ParseResponse(
            entries=entries,
            statistics=m.Ldif.Statistics(),
            detected_server_type=c.Ldif.ServerTypes.RFC,
        )

        from_list: m.Ldif.EntriesStatistics = u.Tests.assert_success(
            api.calculate_for_entries(entries),
        )
        from_response: m.Ldif.EntriesStatistics = u.Tests.assert_success(
            api.calculate_for_entries(parse_response),
        )

        assert from_response.model_dump() == from_list.model_dump()

    def test_repeated_calls_are_idempotent(
        self,
        api: p.Ldif.LdifClient,
    ) -> None:
        entries = self._entries(4)

        first: m.Ldif.EntriesStatistics = u.Tests.assert_success(
            api.calculate_for_entries(entries),
        )
        second: m.Ldif.EntriesStatistics = u.Tests.assert_success(
            api.calculate_for_entries(entries),
        )

        assert first.model_dump() == second.model_dump()
