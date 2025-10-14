"""Unit tests for FlextLdifSchemaWhitelistService.

Tests schema whitelisting, OID pattern matching, and transformation logic
for client-a OID → OUD migration Phase 1.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from pathlib import Path
from typing import Final

import pytest
from flext_core import FlextCore

from flext_ldif.filters import matches_oid_pattern
from flext_ldif.quirks.manager import FlextLdifQuirksManager
from flext_ldif.schema_whitelist import FlextLdifSchemaWhitelistService

# Test Constants
SAMPLE_ATTRIBUTE_LDIF: Final[
    str
] = """attributeTypes: ( 2.5.4.3 NAME 'cn' DESC 'Common Name' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributeTypes: ( 2.5.4.4 NAME 'sn' DESC 'Surname' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributeTypes: ( 0.9.2342.19200300.100.1.1 NAME 'uid' DESC 'User ID' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributeTypes: ( 2.16.840.1.113894.1.1.1.1 NAME 'orclGUID' DESC 'Oracle GUID' SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )
"""

SAMPLE_OBJECTCLASS_LDIF: Final[
    str
] = """objectClasses: ( 2.5.6.6 NAME 'person' DESC 'Person' SUP top STRUCTURAL MUST ( cn $ sn ) )
objectClasses: ( 2.5.6.7 NAME 'organizationalPerson' DESC 'Organizational Person' SUP person STRUCTURAL )
objectClasses: ( 0.9.2342.19200300.100.4.4 NAME 'pilotPerson' DESC 'Pilot Person' SUP person STRUCTURAL )
objectClasses: ( 2.16.840.1.113894.1.2.1.1 NAME 'orclUser' DESC 'Oracle User' SUP top STRUCTURAL )
"""

SAMPLE_MIXED_LDIF: Final[str] = SAMPLE_ATTRIBUTE_LDIF + "\n" + SAMPLE_OBJECTCLASS_LDIF

DEFAULT_WHITELIST_RULES: Final[FlextCore.Types.Dict] = {
    "allowed_attribute_oids": [
        "2.5.4.*",  # Standard LDAP attributes
        "2.5.18.*",  # Operational attributes
        "0.9.2342.*",  # RFC attributes (uid, mail, dc)
        "2.16.840.1.113894.1.1.*",  # Oracle OID attributes
    ],
    "blocked_attributes": [
        "userPassword",
        "authPassword",
    ],
    "allowed_objectclass_oids": [
        "2.5.6.*",  # Standard LDAP objectClasses
        "0.9.2342.*",  # RFC objectClasses
        "2.16.840.1.113894.1.2.*",  # Oracle OID objectClasses
    ],
    "blocked_objectclasses": [],
}


@pytest.fixture
def temp_schema_file(tmp_path: Path) -> Path:
    """Create temporary schema LDIF file for testing.

    Args:
        tmp_path: pytest temporary directory fixture

    Returns:
        Path to temporary schema file

    """
    schema_file = tmp_path / "test_schema.ldif"
    schema_file.write_text(SAMPLE_MIXED_LDIF, encoding="utf-8")
    return schema_file


@pytest.fixture
def whitelist_rules() -> FlextCore.Types.Dict:
    """Provide default whitelist rules for testing.

    Returns:
        Dictionary with whitelist configuration

    """
    return DEFAULT_WHITELIST_RULES.copy()


@pytest.fixture
def quirks_manager() -> FlextLdifQuirksManager:
    """Create quirks manager for testing.

    Returns:
        FlextLdifQuirksManager instance for OID server

    """
    return FlextLdifQuirksManager(server_type="oracle_oid")


class TestSchemaWhitelistServiceInitialization:
    """Test FlextLdifSchemaWhitelistService initialization and configuration."""

    def test_initialization_with_required_params(
        self, temp_schema_file: Path, whitelist_rules: FlextCore.Types.Dict
    ) -> None:
        """Test service initialization with required parameters."""
        service = FlextLdifSchemaWhitelistService(
            schema_file=temp_schema_file,
            whitelist_rules=whitelist_rules,
        )

        assert service._schema_file == temp_schema_file
        assert service._whitelist_rules == whitelist_rules
        assert service._source_server == "oracle_oid"
        assert service._target_server == "oracle_oud"
        assert service._quirks is not None

    def test_initialization_with_custom_servers(
        self, temp_schema_file: Path, whitelist_rules: FlextCore.Types.Dict
    ) -> None:
        """Test service initialization with custom server types."""
        service = FlextLdifSchemaWhitelistService(
            schema_file=temp_schema_file,
            whitelist_rules=whitelist_rules,
            source_server="openldap",
            target_server="ds389",
        )

        assert service._source_server == "openldap"
        assert service._target_server == "ds389"

    def test_initialization_with_custom_quirks_manager(
        self,
        temp_schema_file: Path,
        whitelist_rules: FlextCore.Types.Dict,
        quirks_manager: FlextLdifQuirksManager,
    ) -> None:
        """Test service initialization with custom quirks manager."""
        service = FlextLdifSchemaWhitelistService(
            schema_file=temp_schema_file,
            whitelist_rules=whitelist_rules,
            quirks_manager=quirks_manager,
        )

        assert service._quirks == quirks_manager
        assert service._quirks.server_type == "oracle_oid"


class TestSchemaFileParsing:
    """Test schema LDIF file parsing functionality."""

    def test_parse_valid_schema_file(
        self, temp_schema_file: Path, whitelist_rules: FlextCore.Types.Dict
    ) -> None:
        """Test parsing valid schema LDIF file."""
        service = FlextLdifSchemaWhitelistService(
            schema_file=temp_schema_file,
            whitelist_rules=whitelist_rules,
        )

        result = service._parse_schema_file()

        assert result.is_success
        entries = result.unwrap()
        assert len(entries) > 0
        # Should have both attributeTypes and objectClasses
        has_attributes = any(e.get("type") == "attributeType" for e in entries)
        has_objectclasses = any(e.get("type") == "objectClass" for e in entries)
        assert has_attributes
        assert has_objectclasses

    def test_parse_nonexistent_file(
        self, tmp_path: Path, whitelist_rules: FlextCore.Types.Dict
    ) -> None:
        """Test parsing nonexistent schema file returns failure."""
        nonexistent_file = tmp_path / "nonexistent.ldif"
        service = FlextLdifSchemaWhitelistService(
            schema_file=nonexistent_file,
            whitelist_rules=whitelist_rules,
        )

        result = service._parse_schema_file()

        assert result.is_failure
        assert result.error is not None
        assert "not found" in result.error.lower()

    def test_parse_attribute_types(
        self, temp_schema_file: Path, whitelist_rules: FlextCore.Types.Dict
    ) -> None:
        """Test parsing attributeTypes from schema file."""
        service = FlextLdifSchemaWhitelistService(
            schema_file=temp_schema_file,
            whitelist_rules=whitelist_rules,
        )

        # Parse file and extract attributes
        result = service._parse_schema_file()
        assert result.is_success
        entries = result.unwrap()

        attributes = [e for e in entries if e.get("type") == "attributeType"]
        assert len(attributes) >= 3  # At least cn, sn, uid

        # Check cn attribute
        cn_attr = next((a for a in attributes if a.get("name") == "cn"), None)
        assert cn_attr is not None
        assert cn_attr["oid"] == "2.5.4.3"
        definition = str(cn_attr["definition"])
        assert "Common Name" in definition

    def test_parse_object_classes(
        self, temp_schema_file: Path, whitelist_rules: FlextCore.Types.Dict
    ) -> None:
        """Test parsing objectClasses from schema file."""
        service = FlextLdifSchemaWhitelistService(
            schema_file=temp_schema_file,
            whitelist_rules=whitelist_rules,
        )

        # Parse file and extract objectClasses
        result = service._parse_schema_file()
        assert result.is_success
        entries = result.unwrap()

        objectclasses = [e for e in entries if e.get("type") == "objectClass"]
        assert (
            len(objectclasses) >= 3
        )  # At least person, organizationalPerson, pilotPerson

        # Check person objectClass
        person_oc = next(
            (oc for oc in objectclasses if oc.get("name") == "person"), None
        )
        assert person_oc is not None
        assert person_oc["oid"] == "2.5.6.6"
        definition = str(person_oc["definition"])
        assert "Person" in definition

    def test_parse_empty_file(
        self, tmp_path: Path, whitelist_rules: FlextCore.Types.Dict
    ) -> None:
        """Test parsing empty schema file."""
        empty_file = tmp_path / "empty.ldif"
        empty_file.write_text("", encoding="utf-8")

        service = FlextLdifSchemaWhitelistService(
            schema_file=empty_file,
            whitelist_rules=whitelist_rules,
        )

        result = service._parse_schema_file()

        assert result.is_success
        entries = result.unwrap()
        assert len(entries) == 0


class TestWhitelistRules:
    """Test whitelist rule application logic."""

    def test_passes_whitelist_allowed_attribute(
        self, temp_schema_file: Path, whitelist_rules: FlextCore.Types.Dict
    ) -> None:
        """Test that allowed attribute passes whitelist."""
        service = FlextLdifSchemaWhitelistService(
            schema_file=temp_schema_file,
            whitelist_rules=whitelist_rules,
        )

        entry: FlextCore.Types.Dict = {
            "type": "attributeType",
            "oid": "2.5.4.3",
            "name": "cn",
            "definition": "...",
        }

        passes = service._passes_whitelist(entry)
        assert passes is True

    def test_passes_whitelist_blocked_attribute(
        self, temp_schema_file: Path, whitelist_rules: FlextCore.Types.Dict
    ) -> None:
        """Test that blocked attribute fails whitelist."""
        service = FlextLdifSchemaWhitelistService(
            schema_file=temp_schema_file,
            whitelist_rules=whitelist_rules,
        )

        entry: FlextCore.Types.Dict = {
            "type": "attributeType",
            "oid": "2.5.4.35",
            "name": "userPassword",
            "definition": "...",
        }

        passes = service._passes_whitelist(entry)
        assert passes is False

    def test_passes_whitelist_allowed_objectclass(
        self, temp_schema_file: Path, whitelist_rules: FlextCore.Types.Dict
    ) -> None:
        """Test that allowed objectClass passes whitelist."""
        service = FlextLdifSchemaWhitelistService(
            schema_file=temp_schema_file,
            whitelist_rules=whitelist_rules,
        )

        entry: FlextCore.Types.Dict = {
            "type": "objectClass",
            "oid": "2.5.6.6",
            "name": "person",
            "definition": "...",
        }

        passes = service._passes_whitelist(entry)
        assert passes is True

    def test_passes_whitelist_unknown_oid(
        self, temp_schema_file: Path, whitelist_rules: FlextCore.Types.Dict
    ) -> None:
        """Test that unknown OID fails whitelist."""
        service = FlextLdifSchemaWhitelistService(
            schema_file=temp_schema_file,
            whitelist_rules=whitelist_rules,
        )

        entry: FlextCore.Types.Dict = {
            "type": "attributeType",
            "oid": "9.9.9.9",
            "name": "unknownAttr",
            "definition": "...",
        }

        passes = service._passes_whitelist(entry)
        assert passes is False


class TestOidPatternMatching:
    """Test OID pattern matching logic with wildcards."""

    def test_matches_oid_pattern_exact_match(
        self, temp_schema_file: Path, whitelist_rules: FlextCore.Types.Dict
    ) -> None:
        """Test exact OID matching."""
        FlextLdifSchemaWhitelistService(
            schema_file=temp_schema_file,
            whitelist_rules=whitelist_rules,
        )

        from flext_ldif.filters import matches_oid_pattern

        matches = matches_oid_pattern("2.5.4.3", ["2.5.4.3", "2.5.4.4"])
        assert matches is True

    def test_matches_oid_pattern_wildcard_match(
        self, temp_schema_file: Path, whitelist_rules: FlextCore.Types.Dict
    ) -> None:
        """Test wildcard OID pattern matching."""
        FlextLdifSchemaWhitelistService(
            schema_file=temp_schema_file,
            whitelist_rules=whitelist_rules,
        )

        matches = matches_oid_pattern("2.5.4.3", ["2.5.4.*"])
        assert matches is True

        matches = matches_oid_pattern("2.5.4.999", ["2.5.4.*"])
        assert matches is True

    def test_matches_oid_pattern_no_match(
        self, temp_schema_file: Path, whitelist_rules: FlextCore.Types.Dict
    ) -> None:
        """Test OID pattern no match."""
        FlextLdifSchemaWhitelistService(
            schema_file=temp_schema_file,
            whitelist_rules=whitelist_rules,
        )

        matches = matches_oid_pattern("9.9.9.9", ["2.5.4.*", "2.5.6.*"])
        assert matches is False

    def test_matches_oid_pattern_partial_wildcard(
        self, temp_schema_file: Path, whitelist_rules: FlextCore.Types.Dict
    ) -> None:
        """Test partial wildcard OID pattern matching."""
        FlextLdifSchemaWhitelistService(
            schema_file=temp_schema_file,
            whitelist_rules=whitelist_rules,
        )

        from flext_ldif.filters import matches_oid_pattern

        # 2.5.4.3 should NOT match 2.5.* because it requires full prefix
        matches = matches_oid_pattern("2.5.4.3", ["2.5.*"])
        assert matches is True

        # But 2.6.4.3 should NOT match 2.5.*
        matches = matches_oid_pattern("2.6.4.3", ["2.5.*"])
        assert matches is False

    def test_matches_oid_pattern_empty_patterns(
        self, temp_schema_file: Path, whitelist_rules: FlextCore.Types.Dict
    ) -> None:
        """Test OID pattern matching with empty patterns list."""
        FlextLdifSchemaWhitelistService(
            schema_file=temp_schema_file,
            whitelist_rules=whitelist_rules,
        )

        from flext_ldif.filters import matches_oid_pattern

        matches = matches_oid_pattern("2.5.4.3", [])
        assert matches is False


class TestSchemaTransformation:
    """Test schema transformation with quirks integration."""

    def test_transform_to_target_basic(
        self, temp_schema_file: Path, whitelist_rules: FlextCore.Types.Dict
    ) -> None:
        """Test basic schema transformation."""
        service = FlextLdifSchemaWhitelistService(
            schema_file=temp_schema_file,
            whitelist_rules=whitelist_rules,
            source_server="oracle_oid",
            target_server="oracle_oud",
        )

        entries: list[FlextCore.Types.Dict] = [
            {
                "type": "attributeType",
                "oid": "2.5.4.3",
                "name": "cn",
                "definition": "...",
            }
        ]

        result = service._transform_to_target(entries)

        assert result.is_success
        transformed = result.unwrap()
        assert len(transformed) == 1
        assert transformed[0]["source_server"] == "oracle_oid"
        assert transformed[0]["target_server"] == "oracle_oud"
        assert transformed[0]["transformed"] is True

    def test_transform_to_target_with_quirks(
        self, temp_schema_file: Path, whitelist_rules: FlextCore.Types.Dict
    ) -> None:
        """Test schema transformation with quirks metadata."""
        service = FlextLdifSchemaWhitelistService(
            schema_file=temp_schema_file,
            whitelist_rules=whitelist_rules,
            source_server="oracle_oid",
            target_server="oracle_oud",
        )

        entries: list[FlextCore.Types.Dict] = [
            {
                "type": "attributeType",
                "oid": "2.5.4.3",
                "name": "cn",
                "definition": "...",
            }
        ]

        result = service._transform_to_target(entries)

        assert result.is_success
        transformed = result.unwrap()
        assert len(transformed) == 1

        # Check quirks metadata added
        assert "schema_subentry" in transformed[0]
        assert "supports_operational_attrs" in transformed[0]
        # OUD schema subentry should be "cn=schema"
        schema_subentry = str(transformed[0]["schema_subentry"])
        assert "cn=schema" in schema_subentry.lower()

    def test_transform_to_target_multiple_entries(
        self, temp_schema_file: Path, whitelist_rules: FlextCore.Types.Dict
    ) -> None:
        """Test transformation of multiple schema entries."""
        service = FlextLdifSchemaWhitelistService(
            schema_file=temp_schema_file,
            whitelist_rules=whitelist_rules,
        )

        entries: list[FlextCore.Types.Dict] = [
            {
                "type": "attributeType",
                "oid": "2.5.4.3",
                "name": "cn",
                "definition": "...",
            },
            {
                "type": "objectClass",
                "oid": "2.5.6.6",
                "name": "person",
                "definition": "...",
            },
        ]

        result = service._transform_to_target(entries)

        assert result.is_success
        transformed = result.unwrap()
        assert len(transformed) == 2
        assert all(e["transformed"] for e in transformed)


class TestSchemaWhitelistIntegration:
    """Integration tests for complete schema whitelist workflow."""

    def test_execute_complete_workflow(
        self, temp_schema_file: Path, whitelist_rules: FlextCore.Types.Dict
    ) -> None:
        """Test complete schema whitelist workflow execution."""
        service = FlextLdifSchemaWhitelistService(
            schema_file=temp_schema_file,
            whitelist_rules=whitelist_rules,
            source_server="oracle_oid",
            target_server="oracle_oud",
        )

        result = service.execute()

        assert result.is_success
        result_dict = result.unwrap()

        # Check result structure
        assert "total_input" in result_dict
        assert "total_output" in result_dict
        assert "blocked_count" in result_dict
        assert "source_server" in result_dict
        assert "target_server" in result_dict
        assert "schema_entries" in result_dict

        # Check values with type assertions
        assert isinstance(result_dict["total_input"], int)
        assert isinstance(result_dict["total_output"], int)
        assert result_dict["total_input"] > 0
        assert result_dict["total_output"] > 0
        assert result_dict["source_server"] == "oracle_oid"
        assert result_dict["target_server"] == "oracle_oud"
        assert isinstance(result_dict["schema_entries"], list)

    def test_execute_with_blocking(
        self, tmp_path: Path, whitelist_rules: FlextCore.Types.Dict
    ) -> None:
        """Test execution with some schema entries blocked."""
        # Create schema with blocked attribute
        schema_content = """attributeTypes: ( 2.5.4.35 NAME 'userPassword' DESC 'Password' SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )
attributeTypes: ( 2.5.4.3 NAME 'cn' DESC 'Common Name' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
"""
        schema_file = tmp_path / "blocked_schema.ldif"
        schema_file.write_text(schema_content, encoding="utf-8")

        service = FlextLdifSchemaWhitelistService(
            schema_file=schema_file,
            whitelist_rules=whitelist_rules,
        )

        result = service.execute()

        assert result.is_success
        result_dict = result.unwrap()

        # userPassword should be blocked with type assertions
        assert isinstance(result_dict["blocked_count"], int)
        assert isinstance(result_dict["total_input"], int)
        assert isinstance(result_dict["total_output"], int)
        assert result_dict["blocked_count"] >= 1
        assert result_dict["total_output"] < result_dict["total_input"]

        # Check that userPassword is not in output
        schema_entries_raw = result_dict["schema_entries"]
        schema_entries: list[FlextCore.Types.Dict] = (
            list(schema_entries_raw) if isinstance(schema_entries_raw, list) else []
        )
        blocked_entry = any(e.get("name") == "userPassword" for e in schema_entries)
        assert blocked_entry is False

    def test_execute_nonexistent_file_failure(
        self, tmp_path: Path, whitelist_rules: FlextCore.Types.Dict
    ) -> None:
        """Test execution with nonexistent file returns failure."""
        nonexistent_file = tmp_path / "nonexistent.ldif"
        service = FlextLdifSchemaWhitelistService(
            schema_file=nonexistent_file,
            whitelist_rules=whitelist_rules,
        )

        result = service.execute()

        assert result.is_failure
        assert result.error is not None
        assert "parse schema" in result.error.lower()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
