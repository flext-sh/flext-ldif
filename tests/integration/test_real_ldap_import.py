"""Behavioral tests for LDIF parse -> import against a live LDAP server.

Exercises the PUBLIC LDIF client contract (``p.Ldif.LdifClient.parse_ldif``)
end-to-end: parse LDIF text/file into the promised ``m.Ldif.ParseResponse``,
then push the parsed entries to a real LDAP server through the ldap3 boundary
and assert the observable round-tripped state.

Only public accessors are used to move data out of a parsed entry:
the ``entry.dn`` / ``entry.attributes`` protocol accessors and
``u.Ldif.get_attribute_values`` / ``u.Ldif.has_attribute``. No private
attributes or internal collaborators are
inspected. The ldap3 connection is a genuine external boundary provided by the
docker fixture infrastructure in ``tests/integration/fixtures.py``.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING

import pytest

from flext_ldif import ldif
from tests.constants import c
from tests.utilities import u

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from tests.protocols import p


@pytest.fixture
def flext_api() -> p.Ldif.LdifClient:
    """Public LDIF client under test."""
    return ldif()


@pytest.mark.docker
@pytest.mark.integration
@pytest.mark.real_ldap
class TestsFlextLdifRealLdapImport:
    """Behavioral contract of parsing LDIF and importing it into live LDAP."""

    @staticmethod
    def _dn(entry: p.Ldif.Entry) -> str:
        """Distinguished name string via the public DN protocol accessor."""
        assert entry.dn is not None
        return entry.dn.value

    @staticmethod
    def _object_classes(entry: p.Ldif.Entry) -> list[str]:
        """Object class values via the public attribute accessor."""
        return list(u.Ldif.get_attribute_values(entry, "objectclass"))

    @staticmethod
    def _all_attrs(entry: p.Ldif.Entry) -> dict[str, list[str]]:
        """Full attribute mapping via the public ``Attributes`` protocol."""
        assert entry.attributes is not None
        return {name: list(values) for name, values in entry.attributes.items()}

    @classmethod
    def _non_objectclass_attrs(cls, entry: p.Ldif.Entry) -> dict[str, list[str]]:
        """Public attribute mapping without objectClass/dn, for an LDAP add."""
        return {
            name: values
            for name, values in cls._all_attrs(entry).items()
            if name.lower() not in {"objectclass", "dn"}
        }

    def _read_back(
        self,
        ldap_connection: p.Ldap.Ldap3Connection,
        dn: str,
    ) -> p.Ldap.Ldap3Entry:
        """Search the freshly imported entry and return the single result."""
        found = ldap_connection.search(
            dn,
            "(objectClass=*)",
            search_scope=c.Ldap.Ldap3SearchScope.BASE.value,
            attributes=["*"],
        )
        assert found, f"expected imported entry to be searchable at {dn}"
        ldap_entry: p.Ldap.Ldap3Entry = ldap_connection.entries[0]
        return ldap_entry

    @pytest.mark.parametrize(
        ("attribute", "expected"),
        [
            ("cn", None),  # cn equals the generated unique username
            ("sn", "Test"),
            ("mail", "import@example.com"),
        ],
    )
    def test_parse_exposes_declared_attributes_through_public_api(
        self,
        clean_test_ou: str,
        flext_api: p.Ldif.LdifClient,
        make_test_username: Callable[[str], str],
        attribute: str,
        expected: str | None,
    ) -> None:
        """parse_ldif surfaces every declared attribute via the public contract."""
        username = make_test_username("ParseContract")
        ldif_content = (
            f"dn: cn={username},{clean_test_ou}\n"
            "objectClass: person\n"
            "objectClass: inetOrgPerson\n"
            f"cn: {username}\n"
            "sn: Test\n"
            "mail: import@example.com\n"
        )

        parse_result = flext_api.parse_ldif(ldif_content)

        response = parse_result.unwrap()
        assert len(response.entries) == 1
        entry = response.entries[0]
        assert self._dn(entry) == f"cn={username},{clean_test_ou}"
        assert self._object_classes(entry) == ["person", "inetOrgPerson"]
        assert u.Ldif.has_attribute(entry, attribute)
        values = u.Ldif.get_attribute_values(entry, attribute)
        assert values == [expected if expected is not None else username]

    def test_import_single_entry_roundtrips_to_ldap(
        self,
        ldap_connection: p.Ldap.Ldap3Connection,
        clean_test_ou: str,
        flext_api: p.Ldif.LdifClient,
        make_test_username: Callable[[str], str],
    ) -> None:
        """A parsed entry, imported via public accessors, reads back intact."""
        username = make_test_username("ImportTest")
        ldif_content = (
            f"dn: cn={username},{clean_test_ou}\n"
            "objectClass: person\n"
            "objectClass: inetOrgPerson\n"
            f"cn: {username}\n"
            "sn: Test\n"
            "mail: import@example.com\n"
        )

        entry = flext_api.parse_ldif(ldif_content).unwrap().entries[0]
        dn = self._dn(entry)
        ldap_connection.add(
            dn,
            self._object_classes(entry),
            attributes=self._non_objectclass_attrs(entry),
        )

        imported = self._read_back(ldap_connection, dn)
        assert imported["cn"].value == username
        assert imported["mail"].value == "import@example.com"

    def test_import_preserves_binary_attribute(
        self,
        ldap_connection: p.Ldap.Ldap3Connection,
        clean_test_ou: str,
        flext_api: p.Ldif.LdifClient,
        make_test_username: Callable[[str], str],
    ) -> None:
        """Base64 (``::``) binary attributes survive parse and LDAP round-trip."""
        username = make_test_username("BinaryTest")
        binary_data = b"fake_jpeg_data_here"
        encoded_photo = base64.b64encode(binary_data).decode("ascii")
        ldif_content = (
            f"dn: cn={username},{clean_test_ou}\n"
            "objectClass: person\n"
            "objectClass: inetOrgPerson\n"
            f"cn: {username}\n"
            "sn: Test\n"
            f"jpegPhoto:: {encoded_photo}\n"
        )

        entry = flext_api.parse_ldif(ldif_content).unwrap().entries[0]
        # Parse contract: the base64 payload is decoded and exposed as a value.
        assert u.Ldif.has_attribute(entry, "jpegPhoto")
        assert u.Ldif.get_attribute_values(entry, "jpegPhoto") == [
            binary_data.decode("ascii"),
        ]

        dn = self._dn(entry)
        attributes: dict[str, list[str] | bytes] = dict(
            self._non_objectclass_attrs(entry),
        )
        # ldap3 requires raw bytes for a binary attribute value.
        attributes["jpegPhoto"] = binary_data
        ldap_connection.add(
            dn,
            self._object_classes(entry),
            attributes=attributes,
        )

        imported = self._read_back(ldap_connection, dn)
        assert imported["jpegPhoto"].value == binary_data

    def test_import_from_file_matches_string_parse(
        self,
        ldap_connection: p.Ldap.Ldap3Connection,
        clean_test_ou: str,
        flext_api: p.Ldif.LdifClient,
        tmp_path: Path,
        make_test_username: Callable[[str], str],
    ) -> None:
        """Parsing from a file path yields the same importable entry as text."""
        username = make_test_username("FileImport")
        ldif_content = (
            f"dn: cn={username},{clean_test_ou}\n"
            "objectClass: person\n"
            "objectClass: inetOrgPerson\n"
            f"cn: {username}\n"
            "sn: Test\n"
            "mail: import@example.com\n"
        )
        ldif_file = tmp_path / "import.ldif"
        ldif_file.write_text(ldif_content)

        file_entry = flext_api.parse_ldif(ldif_file).unwrap().entries[0]
        text_entry = flext_api.parse_ldif(ldif_content).unwrap().entries[0]
        # File and string parsing expose the same public state.
        file_dn = self._dn(file_entry)
        assert file_dn == self._dn(text_entry)
        assert self._all_attrs(file_entry) == self._all_attrs(text_entry)

        ldap_connection.add(
            file_dn,
            self._object_classes(file_entry),
            attributes=self._non_objectclass_attrs(file_entry),
        )

        imported = self._read_back(ldap_connection, file_dn)
        assert imported["cn"].value == username
        assert imported["mail"].value == "import@example.com"


__all__: list[str] = ["TestsFlextLdifRealLdapImport"]
