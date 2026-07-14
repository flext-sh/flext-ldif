"""Behavioral tests for the standardized LDAP server contract.

Every concrete server (RFC baseline, Oracle OID, Oracle OUD) exposes the same
public surface: a ``Constants`` identity (``CANONICAL_NAME`` / ``ALIASES`` /
``PRIORITY``) and an ``Entry`` parser (``parse_server`` returning ``r[list]``,
the ``parse_input`` compatibility entrypoint, ``can_handle`` and
``parse_entry``). These tests pin the *observable* promises of that contract:
return values, ``r[T]`` outcomes, and cross-server agreement -- never internal
structure.
"""

from __future__ import annotations

import pytest
from flext_tests import tm

from flext_ldif.servers.oid import FlextLdifServersOid
from flext_ldif.servers.oud import FlextLdifServersOud
from flext_ldif.servers.rfc import FlextLdifServersRfc
from tests import t

type ServerClass = type[FlextLdifServersRfc | FlextLdifServersOid | FlextLdifServersOud]

# (server class, canonical identity, priority) — the standardized identity table.
_STANDARDIZED_SERVERS: tuple[tuple[ServerClass, str, int], ...] = (
    (FlextLdifServersRfc, "rfc", 100),
    (FlextLdifServersOid, "oid", 10),
    (FlextLdifServersOud, "oud", 10),
)

_EXPECTED_DN = "cn=test,dc=example,dc=com"


@pytest.mark.unit
class TestsFlextLdifServersStandardization:
    """Verify the public server-standardization contract behaviourally."""

    @pytest.fixture
    def valid_ldif(self) -> str:
        """Return a single well-formed RFC 2849 entry every server must accept."""
        return f"dn: {_EXPECTED_DN}\nobjectClass: person\ncn: test\nsn: user\n"

    @pytest.fixture
    def multi_ldif(self) -> str:
        """Two independent entries in one LDIF stream."""
        return (
            "dn: cn=alice,dc=example,dc=com\n"
            "objectClass: person\n"
            "cn: alice\n"
            "\n"
            "dn: cn=bob,dc=example,dc=com\n"
            "objectClass: person\n"
            "cn: bob\n"
        )

    # -- Constants identity contract ---------------------------------------

    @pytest.mark.parametrize(
        ("server_cls", "canonical", "priority"),
        _STANDARDIZED_SERVERS,
    )
    def test_constants_expose_expected_canonical_identity(
        self,
        server_cls: ServerClass,
        canonical: str,
        priority: int,
    ) -> None:
        """Each server advertises its documented canonical name and priority."""
        constants = server_cls.Constants
        tm.that(
            (canonical, priority),
            eq=(
                constants.CANONICAL_NAME,
                constants.PRIORITY,
            ),
        )

    @pytest.mark.parametrize(
        ("server_cls", "canonical", "priority"),
        _STANDARDIZED_SERVERS,
    )
    def test_canonical_name_is_a_registered_alias(
        self,
        server_cls: ServerClass,
        canonical: str,
        priority: int,
    ) -> None:
        """The canonical name resolves through the server's own alias set."""
        _ = priority
        constants = server_cls.Constants
        tm.that(constants.ALIASES, has=constants.CANONICAL_NAME)
        tm.that(constants.ALIASES, has=canonical)
        tm.that(all(constants.ALIASES), eq=True)

    def test_rfc_is_the_lowest_precedence_fallback(self) -> None:
        """RFC's higher PRIORITY number ranks it last behind specific servers."""
        rfc_priority = FlextLdifServersRfc.Constants.PRIORITY
        assert rfc_priority > FlextLdifServersOid.Constants.PRIORITY
        assert rfc_priority > FlextLdifServersOud.Constants.PRIORITY

    # -- Parsing contract --------------------------------------------------

    @pytest.mark.parametrize("server_cls", [s[0] for s in _STANDARDIZED_SERVERS])
    def test_parse_server_returns_parsed_entry_for_valid_ldif(
        self,
        server_cls: ServerClass,
        valid_ldif: str,
    ) -> None:
        """parse_server yields a successful result carrying the parsed entry."""
        result = server_cls.Entry().parse_server(valid_ldif)
        tm.ok(result, len=1)
        tm.that(str(result.value[0].dn), eq=_EXPECTED_DN)

    @pytest.mark.parametrize("server_cls", [s[0] for s in _STANDARDIZED_SERVERS])
    def test_parse_input_mirrors_successful_parse(
        self,
        server_cls: ServerClass,
        valid_ldif: str,
    ) -> None:
        """parse_input hands back the same entry list as parse_server's value."""
        result = server_cls.Entry().parse_input(valid_ldif)
        tm.that(result, none=False)
        tm.that(result, len=1)
        if result:
            tm.that(str(result[0].dn), eq=_EXPECTED_DN)

    @pytest.mark.parametrize("server_cls", [s[0] for s in _STANDARDIZED_SERVERS])
    def test_empty_content_parses_to_no_entries(
        self,
        server_cls: ServerClass,
    ) -> None:
        """Empty input is a valid, empty parse -- success with zero entries."""
        entry = server_cls.Entry()
        result = entry.parse_server("")
        tm.ok(result, len=0)
        tm.that(list(result.value), eq=[])
        tm.that(entry.parse_input(""), eq=[])

    @pytest.mark.parametrize("content", ["", "   \n  \t\n"])
    def test_parse_input_treats_blank_content_as_empty(
        self,
        content: str,
    ) -> None:
        """Blank / whitespace-only content returns an empty list, never None."""
        tm.that(FlextLdifServersRfc.Entry().parse_input(content), eq=[])

    def test_unparseable_content_is_empty_success_not_failure(self) -> None:
        """Non-LDIF text is skipped: success with no entries, and [] via input."""
        entry = FlextLdifServersRfc.Entry()
        result = entry.parse_server("this is not ldif at all")
        tm.ok(result, len=0)
        tm.that(list(result.value), eq=[])
        tm.that(entry.parse_input("this is not ldif at all"), eq=[])

    def test_all_servers_agree_on_standard_ldif(self, valid_ldif: str) -> None:
        """Standard RFC LDIF parses identically across every server type."""
        parsed_dns: list[list[str]] = []
        for server_cls, _canonical, _priority in _STANDARDIZED_SERVERS:
            result = server_cls.Entry().parse_server(valid_ldif)
            tm.ok(result)
            parsed_dns.append([str(entry.dn) for entry in result.value])
        tm.that(parsed_dns, eq=[[_EXPECTED_DN]] * len(_STANDARDIZED_SERVERS))

    def test_parse_input_is_idempotent(self, valid_ldif: str) -> None:
        """Re-parsing identical content yields an equal DN sequence."""
        entry = FlextLdifServersRfc.Entry()
        first = entry.parse_input(valid_ldif)
        second = entry.parse_input(valid_ldif)
        tm.that(first, none=False)
        tm.that(second, none=False)
        if first is not None and second is not None:
            tm.that(
                [str(entry.dn) for entry in first],
                eq=[str(entry.dn) for entry in second],
            )

    def test_multi_record_ldif_parses_every_entry(self, multi_ldif: str) -> None:
        """A multi-record stream produces one entry per record, in order."""
        result = FlextLdifServersRfc.Entry().parse_server(multi_ldif)
        tm.ok(result, len=2)
        tm.that(
            [str(entry.dn) for entry in result.value],
            eq=[
                "cn=alice,dc=example,dc=com",
                "cn=bob,dc=example,dc=com",
            ],
        )

    def test_parse_entry_builds_entry_from_dn_and_attributes(self) -> None:
        """parse_entry composes a successful entry from a DN and attribute map."""
        result = FlextLdifServersRfc.Entry().parse_entry(
            "cn=alice,dc=example,dc=com",
            {"objectClass": ["person"], "cn": ["alice"]},
        )
        tm.ok(result)
        tm.that(str(result.value.dn), eq="cn=alice,dc=example,dc=com")

    # -- can_handle contract ----------------------------------------------

    @pytest.mark.parametrize(
        ("entry_dn", "attributes", "expected"),
        [
            ("cn=x,dc=e", {"objectClass": ["person"]}, True),
            ("cn=x,dc=e", {"changetype": ["add"]}, True),
            ("cn=x,dc=e", {"ObjectClass": ["person"]}, True),
            ("", {"objectClass": ["person"]}, False),
            ("   ", {"objectClass": ["person"]}, False),
            ("cn=x,dc=e", {}, False),
            ("cn=x,dc=e", {"cn": ["x"]}, False),
        ],
    )
    def test_can_handle_recognizes_entries_by_markers(
        self,
        entry_dn: str,
        attributes: t.MutableStrSequenceMapping,
        expected: bool,
    ) -> None:
        """can_handle accepts entries with a DN and object-class/changetype only."""
        assert FlextLdifServersRfc.Entry().can_handle(entry_dn, attributes) is expected
