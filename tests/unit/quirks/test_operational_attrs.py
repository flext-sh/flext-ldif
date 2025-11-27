"""Tests for operational attributes stripping in entry quirks.

Modules tested: FlextLdifEntries (remove_operational_attributes)
Scope: Common operational attributes stripping, server-specific preservation
Tests with real entry models using factories.

Uses advanced Python 3.13 patterns: StrEnum, frozen dataclasses, parametrization.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import dataclasses
from enum import StrEnum
from typing import Final

import pytest

from flext_ldif.services.entries import FlextLdifEntries
from tests.helpers.test_factories import FlextLdifTestFactories


class OperationalAttrTestType(StrEnum):
    """Types of operational attributes tests."""

    COMMON_STRIP = "common_strip"
    OID_PRESERVE = "oid_preserve"
    USER_ATTRS = "user_attrs"
    CASE_INSENSITIVE = "case_insensitive"
    REAL_LDIF = "real_ldif"
    OUD_PRESERVE = "oud_preserve"
    OPENLDAP_PRESERVE = "openldap_preserve"
    AD_PRESERVE = "ad_preserve"
    GENERIC_DEFAULT = "generic_default"
    MIXED_ATTRS = "mixed_attrs"


@dataclasses.dataclass(frozen=True)
class OpAttrTestCase:
    """Operational attribute test case."""

    test_type: OperationalAttrTestType
    dn: str
    attributes: dict[str, list[str]]
    expected_preserved: list[str]
    expected_stripped: list[str]
    description: str = ""


# Test cases for comprehensive coverage
OP_ATTR_TESTS: Final[list[OpAttrTestCase]] = [
    OpAttrTestCase(
        OperationalAttrTestType.COMMON_STRIP,
        "cn=test,dc=client-a",
        {
            "cn": ["test"],
            "objectclass": ["person", "top"],
            "createTimestamp": ["20250113100000Z"],
            "modifyTimestamp": ["20250113100000Z"],
            "entryUUID": ["12345-67890-abcdef"],
        },
        expected_preserved=["cn", "objectclass"],
        expected_stripped=["createTimestamp", "modifyTimestamp", "entryUUID"],
        description="Common operational attributes should be stripped",
    ),
    OpAttrTestCase(
        OperationalAttrTestType.OID_PRESERVE,
        "cn=test,dc=client-a",
        {
            "cn": ["test"],
            "objectclass": ["person"],
            "orclGUID": ["ABC123"],
            "orclPasswordChangedTime": ["20250113"],
            "createTimestamp": ["20250113100000Z"],
        },
        expected_preserved=["cn", "orclGUID", "orclPasswordChangedTime"],
        expected_stripped=["createTimestamp"],
        description="OID-specific attrs preserved, COMMON stripped",
    ),
    OpAttrTestCase(
        OperationalAttrTestType.USER_ATTRS,
        "cn=user,ou=Users,dc=client-a",
        {
            "cn": ["user"],
            "sn": ["User"],
            "mail": ["user@client-a.com"],
            "uid": ["user123"],
            "userPassword": ["{SSHA}abcdef"],
            "objectclass": ["inetOrgPerson", "person", "top"],
        },
        expected_preserved=["cn", "sn", "mail", "uid", "userPassword", "objectclass"],
        expected_stripped=[],
        description="User attributes should never be stripped",
    ),
    OpAttrTestCase(
        OperationalAttrTestType.CASE_INSENSITIVE,
        "cn=test,dc=client-a",
        {
            "cn": ["test"],
            "objectclass": ["person"],
            "CreateTimestamp": ["20250113100000Z"],
            "MODIFYTIMESTAMP": ["20250113100000Z"],
        },
        expected_preserved=["cn", "objectclass"],
        expected_stripped=["CreateTimestamp", "MODIFYTIMESTAMP"],
        description="Operational attrs stripped case-insensitively",
    ),
    OpAttrTestCase(
        OperationalAttrTestType.REAL_LDIF,
        "cn=John Doe,ou=Users,dc=ctbc",
        {
            "cn": ["John Doe"],
            "sn": ["Doe"],
            "givenName": ["John"],
            "mail": ["john.doe@ctbc.com.br"],
            "uid": ["jdoe"],
            "objectclass": ["top", "person", "organizationalPerson", "inetOrgPerson"],
            "orclGUID": ["F1234567890ABCDEF"],
            "createTimestamp": ["20230601120000Z"],
            "modifyTimestamp": ["20250113100000Z"],
            "creatorsName": ["cn=orclREDACTED_LDAP_BIND_PASSWORD"],
            "modifiersName": ["cn=orclREDACTED_LDAP_BIND_PASSWORD"],
        },
        expected_preserved=[
            "cn",
            "sn",
            "givenName",
            "mail",
            "uid",
            "objectclass",
            "orclGUID",
        ],
        expected_stripped=[
            "createTimestamp",
            "modifyTimestamp",
            "creatorsName",
            "modifiersName",
        ],
        description="Real LDIF with mixed user and operational attrs",
    ),
    OpAttrTestCase(
        OperationalAttrTestType.OUD_PRESERVE,
        "cn=test,dc=client-a",
        {
            "cn": ["test"],
            "objectclass": ["person"],
            "ds-sync-hist": ["sync-data"],
            "ds-sync-state": ["active"],
            "ds-pwp-account-disabled": ["false"],
            "createTimestamp": ["20250113100000Z"],
        },
        expected_preserved=[
            "cn",
            "ds-sync-hist",
            "ds-sync-state",
            "ds-pwp-account-disabled",
        ],
        expected_stripped=["createTimestamp"],
        description="OUD-specific attrs preserved, COMMON stripped",
    ),
    OpAttrTestCase(
        OperationalAttrTestType.OPENLDAP_PRESERVE,
        "cn=test,dc=client-a",
        {
            "cn": ["test"],
            "objectclass": ["person"],
            "structuralObjectClass": ["person"],
            "contextCSN": ["20250113100000.000000Z#000000#000#000000"],
            "entryCSN": ["20250113100000.000000Z#000000#000#000000"],
            "createTimestamp": ["20250113100000Z"],
        },
        expected_preserved=["cn", "structuralObjectClass", "contextCSN"],
        expected_stripped=["createTimestamp", "entryCSN"],
        description="OpenLDAP non-COMMON attrs preserved",
    ),
    OpAttrTestCase(
        OperationalAttrTestType.AD_PRESERVE,
        "cn=test,dc=client-a",
        {
            "cn": ["test"],
            "objectclass": ["person"],
            "objectGUID": ["guid-12345"],
            "objectSid": ["S-1-5-21-..."],
            "whenCreated": ["20250113100000.0Z"],
            "whenChanged": ["20250113100000.0Z"],
            "uSNCreated": ["12345"],
            "uSNChanged": ["12346"],
            "createTimestamp": ["20250113100000Z"],
        },
        expected_preserved=[
            "cn",
            "objectGUID",
            "objectSid",
            "whenCreated",
            "whenChanged",
            "uSNCreated",
            "uSNChanged",
        ],
        expected_stripped=["createTimestamp"],
        description="AD-specific attrs preserved, COMMON stripped",
    ),
    OpAttrTestCase(
        OperationalAttrTestType.GENERIC_DEFAULT,
        "cn=test,dc=client-a",
        {
            "cn": ["test"],
            "objectClass": ["person"],
            "createTimestamp": ["20250113100000Z"],
            "orclGUID": ["ABC123"],
        },
        expected_preserved=["cn", "orclGUID"],
        expected_stripped=["createTimestamp"],
        description="Generic target strips COMMON only",
    ),
    OpAttrTestCase(
        OperationalAttrTestType.MIXED_ATTRS,
        "cn=mixed,dc=client-a",
        {
            "cn": ["mixed"],
            "sn": ["Test"],
            "mail": ["test@client-a.com"],
            "objectclass": ["inetOrgPerson", "person", "top"],
            "createTimestamp": ["20250113100000Z"],
            "modifyTimestamp": ["20250113100000Z"],
            "orclGUID": ["GUID123"],
            "telephoneNumber": ["+55 11 1234-5678"],
            "title": ["Engineer"],
            "creatorsName": ["cn=REDACTED_LDAP_BIND_PASSWORD"],
            "entryUUID": ["uuid-12345"],
        },
        expected_preserved=[
            "cn",
            "sn",
            "mail",
            "objectclass",
            "orclGUID",
            "telephoneNumber",
            "title",
        ],
        expected_stripped=[
            "createTimestamp",
            "modifyTimestamp",
            "creatorsName",
            "entryUUID",
        ],
        description="Mix of operational and user attributes",
    ),
]


def get_op_attr_tests() -> list[OpAttrTestCase]:
    """Parametrization helper for operational attr tests."""
    return OP_ATTR_TESTS


class TestOperationalAttributesStripping:
    """Test operational attributes stripping functionality."""

    @pytest.mark.parametrize("test_case", get_op_attr_tests())
    def test_operational_attributes_stripping(
        self,
        test_case: OpAttrTestCase,
    ) -> None:
        """Test operational attribute stripping for all scenarios."""
        entrys = FlextLdifEntries()

        # Create entry from test case data
        entry = FlextLdifTestFactories.create_entry(test_case.dn, test_case.attributes)

        # Remove operational attributes
        result = entrys.remove_operational_attributes(entry)

        assert result.is_success, f"Failed to strip attributes: {result.error}"
        adapted = result.unwrap()

        # Verify all expected preserved attributes are present
        for attr in test_case.expected_preserved:
            assert adapted.has_attribute(attr), (
                f"{test_case.description}: {attr} should be preserved"
            )

        # Verify all expected stripped attributes are removed
        for attr in test_case.expected_stripped:
            assert not adapted.has_attribute(attr), (
                f"{test_case.description}: {attr} should be stripped"
            )


__all__ = [
    "OpAttrTestCase",
    "OperationalAttrTestType",
    "TestOperationalAttributesStripping",
]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
