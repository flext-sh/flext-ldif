"""Config Integration Tests - FlextLdifSettings behavioral contract.

Behavioral integration tests for FlextLdifSettings driven through the public
``ldif`` facade. Every assertion targets observable public behavior:

- the public settings contract (``FlextLdifSettings.Ldif`` field values);
- the parse result contract (``r[ParseResponse]`` success + parsed entry DNs);
- invariants: entry-count fidelity, DN preservation, idempotence, cross-instance
  independence, and no-fabrication on empty input.

No private attributes, internal collaborators, or line-coverage pokes are used.

Modules tested: flext_ldif (facade), flext_ldif.settings

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

import pytest
from flext_tests import tm

from flext_ldif import ldif
from tests.base import s
from tests.constants import c

if TYPE_CHECKING:
    from tests.models import m
    from tests.settings import TestsFlextLdifSettings

# Expected DN observable in CONFIG_BASIC_ENTRY.
_BASIC_DN = "cn=Test,dc=example,dc=com"

# Server type -> label used to build CONFIG_SERVER_CONTENT, so the expected DN
# is a function of the label (see tests.constants.CONFIG_SERVER_CONTENT).
_SERVER_TYPE_LABELS: tuple[tuple[str, str], ...] = (
    (c.Tests.RFC, "RFC"),
    (c.Tests.OID, "OID"),
    (c.Tests.OUD, "OUD"),
    (c.Tests.OPENLDAP, "OpenLDAP"),
)


class TestsFlextLdifConfigIntegration:
    """FlextLdifSettings behavioral contract through the ldif facade.

    Real implementations only; no mocks and no patching of the unit under test.
    """

    @staticmethod
    def create_settings() -> TestsFlextLdifSettings:
        """Return an independent clone of the shared test settings singleton."""
        settings: TestsFlextLdifSettings = s.fetch_settings().clone()
        return settings

    @staticmethod
    def dn_values(entries: Sequence[m.Ldif.Entry]) -> list[str]:
        """Return each entry's public DN string (asserting the DN is present)."""
        values: list[str] = []
        for entry in entries:
            dn = entry.dn
            assert dn is not None, "parsed entry must expose a DN"
            values.append(dn.value)
        return values

    def test_default_facade_parses_basic_entry_preserving_dn(self) -> None:
        """Default facade parses one entry and preserves its DN verbatim."""
        parsed = tm.ok(ldif.parse_ldif(c.Tests.CONFIG_BASIC_ENTRY))

        tm.that(len(parsed.entries), eq=1)
        tm.that(self.dn_values(parsed.entries)[0], eq=_BASIC_DN)

    def test_custom_settings_expose_default_ldif_contract(self) -> None:
        """Cloned settings expose the documented public Ldif field defaults."""
        settings = self.create_settings()

        tm.that(settings.Ldif.ldif_encoding, eq=c.Ldif.Encoding.UTF8)
        tm.that(
            settings.Ldif.ldif_strict_validation,
            eq=c.Ldif.DEFAULT_STRICT_VALIDATION,
        )

    def test_cloned_settings_preserve_public_field_values(self) -> None:
        """Independent clones agree on the public Ldif field contract."""
        first = self.create_settings()
        second = self.create_settings()

        tm.that(first.Ldif.ldif_encoding, eq=second.Ldif.ldif_encoding)
        tm.that(
            first.Ldif.ldif_strict_validation,
            eq=second.Ldif.ldif_strict_validation,
        )

    @pytest.mark.parametrize("server_type", c.Tests.CONFIG_SERVER_TYPES)
    def test_configured_facade_parses_entry_for_each_server_type(
        self,
        server_type: str,
    ) -> None:
        """A configured facade parses the basic entry identically per server."""
        api = ldif(settings=self.create_settings())

        parsed = tm.ok(api.parse_ldif(c.Tests.CONFIG_BASIC_ENTRY, server_type=server_type))

        tm.that(len(parsed.entries), eq=1)
        tm.that(self.dn_values(parsed.entries)[0], eq=_BASIC_DN)

    @pytest.mark.parametrize(("server_type", "label"), _SERVER_TYPE_LABELS)
    def test_server_specific_content_round_trips_dn(
        self,
        server_type: str,
        label: str,
    ) -> None:
        """Server-specific content parses to the DN encoded in that content."""
        api = ldif(settings=self.create_settings())
        content = c.Tests.CONFIG_SERVER_CONTENT[server_type]

        parsed = tm.ok(api.parse_ldif(content, server_type=server_type))

        tm.that(len(parsed.entries), eq=1)
        tm.that(
            self.dn_values(parsed.entries)[0],
            eq=f"cn={label} Test,dc=example,dc=com",
        )

    def test_independent_facades_produce_identical_dn(self) -> None:
        """Two facades with distinct server types do not corrupt shared input."""
        api_oid = ldif(settings=self.create_settings())
        api_openldap = ldif(settings=self.create_settings())

        parsed_oid = tm.ok(
            api_oid.parse_ldif(c.Tests.CONFIG_BASIC_ENTRY, server_type=c.Tests.OID),
        )
        parsed_openldap = tm.ok(
            api_openldap.parse_ldif(
                c.Tests.CONFIG_BASIC_ENTRY,
                server_type=c.Tests.OPENLDAP,
            ),
        )

        oid_dn = self.dn_values(parsed_oid.entries)[0]
        tm.that(oid_dn, eq=_BASIC_DN)
        tm.that(self.dn_values(parsed_openldap.entries)[0], eq=oid_dn)

    def test_repeated_parses_are_idempotent(self) -> None:
        """The same facade parsing the same input twice yields the same DN."""
        api = ldif(settings=self.create_settings())

        first = tm.ok(api.parse_ldif(c.Tests.CONFIG_BASIC_ENTRY))
        second = tm.ok(api.parse_ldif(c.Tests.CONFIG_BASIC_ENTRY))

        first_dn = self.dn_values(first.entries)[0]
        tm.that(first_dn, eq=_BASIC_DN)
        tm.that(self.dn_values(second.entries)[0], eq=first_dn)

    def test_distinct_contents_parsed_independently(self) -> None:
        """A reused facade keeps successive parses free of shared state."""
        api = ldif(settings=self.create_settings())
        content1 = "dn: cn=Test1,dc=example,dc=com\ncn: Test1\nobjectClass: person\n"
        content2 = "dn: cn=Test2,dc=example,dc=com\ncn: Test2\nobjectClass: person\n"

        parsed1 = tm.ok(api.parse_ldif(content1))
        parsed2 = tm.ok(api.parse_ldif(content2))

        tm.that(self.dn_values(parsed1.entries)[0], eq="cn=Test1,dc=example,dc=com")
        tm.that(self.dn_values(parsed2.entries)[0], eq="cn=Test2,dc=example,dc=com")

    def test_multiple_entries_preserve_all_dns(self) -> None:
        """Multi-entry input yields every entry with its DN in order."""
        api = ldif(settings=self.create_settings())

        parsed = tm.ok(api.parse_ldif(c.Tests.CONFIG_MULTIPLE_ENTRIES))

        tm.that(len(parsed.entries), eq=3)
        tm.that(
            self.dn_values(parsed.entries),
            eq=[
                "cn=User1,dc=example,dc=com",
                "cn=User2,dc=example,dc=com",
                "cn=User3,dc=example,dc=com",
            ],
        )

    def test_empty_content_yields_no_fabricated_entries(self) -> None:
        """Empty input succeeds and fabricates no entries (no-invention invariant)."""
        api = ldif(settings=self.create_settings())

        parsed = tm.ok(api.parse_ldif(""))

        tm.that(len(parsed.entries), eq=0)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
