"""Behavioral tests for public LDIF statistics service APIs."""

from __future__ import annotations

from flext_tests import tm

from flext_ldif import FlextLdif, m
from tests import c, u


class TestsFlextLdifStatisticsService:
    """Validate entries statistics generation from public methods."""

    @staticmethod
    def _entry(dn: str, server_type: str) -> m.Ldif.Entry:
        entry = u.Ldif.Tests.create_real_entry(
            dn=dn,
            attributes={
                "objectClass": [c.Ldif.STATS_EXPECTED_OBJECTCLASS, "top"],
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
                )
            },
        )
        return entry.model_copy(update={"metadata": metadata_with_server})

    def test_calculate_for_entries_from_entry_list(self, api: FlextLdif) -> None:
        entries = [
            self._entry("cn=stats-rfc,dc=example,dc=com", c.Ldif.STATS_SERVER_TYPES[0]),
            self._entry("cn=stats-oid,dc=example,dc=com", c.Ldif.STATS_SERVER_TYPES[1]),
        ]

        result = api.calculate_for_entries(entries)
        stats = u.Tests.assert_success(result)
        tm.that(stats.total_entries, eq=2)
        tm.that(
            stats.object_class_distribution.get(c.Ldif.STATS_EXPECTED_OBJECTCLASS, 0),
            gte=2,
        )
        tm.that(stats.server_type_distribution.get(c.Ldif.RFC, 0), eq=1)
        tm.that(stats.server_type_distribution.get(c.Ldif.OID, 0), eq=1)

    def test_calculate_for_entries_from_parse_response(self, api: FlextLdif) -> None:
        entries = [
            self._entry("cn=stats-parse,dc=example,dc=com", c.Ldif.RFC),
        ]
        parse_response = m.Ldif.ParseResponse(
            entries=entries,
            statistics=m.Ldif.Statistics(),
            detected_server_type=c.Ldif.ServerTypes.RFC,
        )

        result = api.calculate_for_entries(parse_response)
        stats = u.Tests.assert_success(result)
        tm.that(stats.total_entries, eq=1)
        tm.that(stats.server_type_distribution.get(c.Ldif.RFC, 0), eq=1)
