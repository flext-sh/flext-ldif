"""Exemplo de refatoração usando helpers para reduzir duplicação.

Este arquivo mostra como refatorar testes duplicados usando os helpers.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

# ════════════════════════════════════════════════════════════════════════════
# ANTES: Duplicação Massiva
# ════════════════════════════════════════════════════════════════════════════

# ❌ ANTES - Cada teste repete o mesmo padrão:
"""
def test_schema_parse_attribute(self, rfc_schema_quirk) -> None:
    attr_def = TestsRfcConstants.ATTR_DEF_CN_COMPLETE
    result = rfc_schema_quirk._parse_attribute(attr_def)
    assert result.is_success
    attr = result.unwrap()
    assert attr.oid == TestsRfcConstants.ATTR_OID_CN
    assert attr.name == TestsRfcConstants.ATTR_NAME_CN

def test_schema_parse_another_attribute(self, rfc_schema_quirk) -> None:
    attr_def = TestsRfcConstants.ATTR_DEF_SN
    result = rfc_schema_quirk._parse_attribute(attr_def)
    assert result.is_success
    attr = result.unwrap()
    assert attr.oid == TestsRfcConstants.ATTR_OID_SN
    assert attr.name == TestsRfcConstants.ATTR_NAME_SN

def test_schema_parse_objectclass(self, rfc_schema_quirk) -> None:
    oc_def = TestsRfcConstants.OC_DEF_PERSON_FULL
    result = rfc_schema_quirk._parse_objectclass(oc_def)
    assert result.is_success
    oc = result.unwrap()
    assert oc.oid == TestsRfcConstants.OC_OID_PERSON
    assert oc.name == TestsRfcConstants.OC_NAME_PERSON
"""

# ════════════════════════════════════════════════════════════════════════════
# DEPOIS: Usando Helpers
# ════════════════════════════════════════════════════════════════════════════

# ✅ DEPOIS - Testes concisos usando helpers:
"""
from tests.helpers import TestOperations
from ...unit.quirks.servers.fixtures.rfc_constants import TestsRfcConstants

def test_schema_parse_attribute(self, rfc_schema_quirk) -> None:
    TestOperations.parse_attribute_and_validate(
        rfc_schema_quirk,
        TestsRfcConstants.ATTR_DEF_CN_COMPLETE,
        expected_oid=TestsRfcConstants.ATTR_OID_CN,
        expected_name=TestsRfcConstants.ATTR_NAME_CN,
    )

def test_schema_parse_another_attribute(self, rfc_schema_quirk) -> None:
    TestOperations.parse_attribute_and_validate(
        rfc_schema_quirk,
        TestsRfcConstants.ATTR_DEF_SN,
        expected_oid=TestsRfcConstants.ATTR_OID_SN,
        expected_name=TestsRfcConstants.ATTR_NAME_SN,
    )

def test_schema_parse_objectclass(self, rfc_schema_quirk) -> None:
    TestOperations.parse_objectclass_and_validate(
        rfc_schema_quirk,
        TestsRfcConstants.OC_DEF_PERSON_FULL,
        expected_oid=TestsRfcConstants.OC_OID_PERSON,
        expected_name=TestsRfcConstants.OC_NAME_PERSON,
    )
"""

# ════════════════════════════════════════════════════════════════════════════
# EXEMPLO: Testes Parametrizados com Helpers
# ════════════════════════════════════════════════════════════════════════════

# ✅ Usando parametrização para reduzir ainda mais duplicação:
"""
import pytest
from tests.helpers import TestOperations
from ...unit.quirks.servers.fixtures.rfc_constants import TestsRfcConstants

@pytest.mark.parametrize("attr_def,expected_oid,expected_name", [
    (TestsRfcConstants.ATTR_DEF_CN_COMPLETE, TestsRfcConstants.ATTR_OID_CN, TestsRfcConstants.ATTR_NAME_CN),
    (TestsRfcConstants.ATTR_DEF_SN, TestsRfcConstants.ATTR_OID_SN, TestsRfcConstants.ATTR_NAME_SN),
    (TestsRfcConstants.ATTR_DEF_ST, TestsRfcConstants.ATTR_OID_ST, TestsRfcConstants.ATTR_NAME_ST),
])
def test_schema_parse_multiple_attributes(
    rfc_schema_quirk,
    attr_def: str,
    expected_oid: str,
    expected_name: str,
) -> None:
    TestOperations.parse_attribute_and_validate(
        rfc_schema_quirk, attr_def, expected_oid, expected_name
    )
"""

# ════════════════════════════════════════════════════════════════════════════
# EXEMPLO: Roundtrip com Helpers
# ════════════════════════════════════════════════════════════════════════════

# ❌ ANTES:
"""
def test_roundtrip_rfc_entries(self, ldif_api: FlextLdif, tmp_path: Path) -> None:
    entries = FlextLdifTestUtils.load_fixture(ldif_api, "rfc", "rfc_entries_fixtures.ldif")
    
    write_result = ldif_api.write(entries)
    assert write_result.is_success
    ldif = write_result.unwrap()
    
    output_file = tmp_path / "roundtrip.ldif"
    output_file.write_text(ldif)
    
    re_read_result = ldif_api.parse(output_file)
    assert re_read_result.is_success
    roundtripped_entries = re_read_result.unwrap()
    
    assert len(roundtripped_entries) == len(entries)
    for i, (orig, roundtrip) in enumerate(zip(entries, roundtripped_entries)):
        assert orig.dn.value == roundtrip.dn.value
"""

# ✅ DEPOIS:
"""
from tests.helpers import TestOperations

def test_roundtrip_rfc_entries(self, ldif_api: FlextLdif, tmp_path: Path) -> None:
    fixture_path = FlextLdifTestUtils.get_fixture_path("rfc", "rfc_entries_fixtures.ldif")
    original, roundtripped = TestOperations.roundtrip_and_validate(
        ldif_api, fixture_path, tmp_path
    )
    # Helpers já validam count, DN preservation, etc.
"""

# ════════════════════════════════════════════════════════════════════════════
# EXEMPLO: Write Entry com Helpers
# ════════════════════════════════════════════════════════════════════════════

# ❌ ANTES:
"""
def test_write_entry(self, entry_quirk: FlextLdifServersOud.Entry) -> None:
    entry = FlextLdifModels.Entry.create(
        dn="cn=test,dc=example,dc=com",
        attributes={"cn": ["test"], "objectClass": ["person"]},
    ).unwrap()
    result = entry_quirk.write(entry)
    assert result.is_success
    ldif = result.unwrap()
    assert "dn: cn=test,dc=example,dc=com" in ldif
"""

# ✅ DEPOIS:
"""
from tests.helpers import TestOperations

def test_write_entry(self, entry_quirk: FlextLdifServersOud.Entry) -> None:
    entry = FlextLdifModels.Entry.create(
        dn="cn=test,dc=example,dc=com",
        attributes={"cn": ["test"], "objectClass": ["person"]},
    ).unwrap()
    TestOperations.write_entry_and_validate(
        entry_quirk, entry, expected_content="dn: cn=test,dc=example,dc=com"
    )
"""

__all__ = []
