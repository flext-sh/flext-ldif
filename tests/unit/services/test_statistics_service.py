"""Behavioral tests for public LDIF statistics service APIs."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_tests import tm

from tests.constants import c
from tests.models import m
from tests.utilities import TestsFlextLdifUtilities as u

if TYPE_CHECKING:
    from tests.protocols import p


class TestsFlextLdifStatisticsService:
    """Validate entries statistics generation from public methods."""

    @staticmethod
    def _entry(dn: str, server_type: str) -> m.Ldif.Entry:
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
                "extensions": entry.metadata.extensions.model_copy(
                    update={"server_type": server_type},
                ),
            },
        )
        updated_entry: m.Ldif.Entry = entry.model_copy(
            update={"metadata": metadata_with_server},
        )
        return updated_entry

    def test_calculate_for_entries_from_entry_list(
        self,
        api: p.Ldif.LdifClient,
    ) -> None:
        entries = [
            self._entry(
                "cn=stats-rfc,dc=example,dc=com",
                c.Tests.STATS_SERVER_TYPES[0],
            ),
            self._entry(
                "cn=stats-oid,dc=example,dc=com",
                c.Tests.STATS_SERVER_TYPES[1],
            ),
        ]

        result = api.calculate_for_entries(entries)
        stats: m.Ldif.EntriesStatistics = u.Tests.assert_success(result)
        tm.that(stats.total_entries, eq=2)
        tm.that(
            stats.object_class_distribution.get(c.Tests.STATS_EXPECTED_OBJECTCLASS, 0),
            gte=2,
        )
        tm.that(stats.server_type_distribution.get(c.Tests.RFC, 0), eq=1)
        tm.that(stats.server_type_distribution.get(c.Tests.OID, 0), eq=1)

    def test_calculate_for_entries_from_parse_response(
        self,
        api: p.Ldif.LdifClient,
    ) -> None:
        entries = [
            self._entry("cn=stats-parse,dc=example,dc=com", c.Tests.RFC),
        ]
        parse_response = m.Ldif.ParseResponse(
            entries=entries,
            statistics=m.Ldif.Statistics(),
            detected_server_type=c.Ldif.ServerTypes.RFC,
        )

        result = api.calculate_for_entries(parse_response)
        stats: m.Ldif.EntriesStatistics = u.Tests.assert_success(result)
        tm.that(stats.total_entries, eq=1)
        tm.that(stats.server_type_distribution.get(c.Tests.RFC, 0), eq=1)
