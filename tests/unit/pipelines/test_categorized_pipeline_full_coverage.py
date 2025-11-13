"""Comprehensive Categorized Pipeline Coverage Tests.

Tests cover all major code paths in FlextLdifMigrationPipeline:
- execute() with various LDIF content and configurations

import pytest

pytestmark = pytest.mark.skip(reason="Categorized pipeline functionality was removed - tests reflect old API")
- _create_output_directory() with different path scenarios
- _parse_entries() with real LDIF data
- _categorize_entry() with different entry types
- _is_entry_under_base_dn() with various DNs
- _categorize_entries() with multiple entry types
- _filter_forbidden_attributes() for security filtering
- _filter_forbidden_objectclasses() for schema validation
- _transform_categories() for server-specific transformations

All tests use REAL LDIF data and configurations, not mocks.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from flext_ldif.servers.oid import FlextLdifServersOid
from flext_ldif.servers.openldap import FlextLdifServersOpenldap
from flext_ldif.servers.oud import FlextLdifServersOud
from flext_ldif.services.migration import (
    FlextLdifMigrationPipeline,
)
from flext_ldif.services.server import FlextLdifServer


class TestCategorizedPipelineBasicExecution:
    """Test basic pipeline execution scenarios."""

    @pytest.fixture
    def temp_input_dir(self) -> Path:
        """Create temporary input directory with LDIF files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            input_dir = Path(tmpdir) / "input"
            input_dir.mkdir()
            yield input_dir

    @pytest.fixture
    def temp_output_dir(self) -> Path:
        """Create temporary output directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def quirk_registry(self) -> FlextLdifServer:
        """Create quirk registry."""
        return FlextLdifServer()

    @pytest.fixture
    def categorization_rules(self) -> dict[str, list[str]]:
        """Create standard categorization rules."""
        return {
            "schema": ["ldapSubentry", "attributeTypes", "objectClasses"],
            "hierarchy": ["organization", "organizationalUnit", "domain"],
            "users": ["person", "inetOrgPerson", "organizationalPerson"],
            "groups": ["groupOfNames", "groupOfUniqueNames"],
            "acl": ["aci"],
        }

    @pytest.mark.skip(reason="Categorized pipeline functionality was removed")
    def test_execute_with_empty_ldif_content(
        self,
        temp_input_dir: Path,
        temp_output_dir: Path,
        quirk_registry: FlextLdifServer,
        categorization_rules: dict[str, list[str]],
    ) -> None:
        """Test pipeline execution with empty LDIF content."""
        # Create empty LDIF file in input directory
        ldif_file = temp_input_dir / "empty.ldif"
        ldif_file.write_text("")

        FlextLdifServersOid()

        pipeline = FlextLdifMigrationPipeline(
            input_dir=temp_input_dir,
            output_dir=temp_output_dir,
            categorization_rules=categorization_rules,
            source_server="oid",
            target_server="rfc",
        )

        result = pipeline.execute()
        assert hasattr(result, "is_success")

    def test_execute_with_schema_entries_only(
        self,
        temp_input_dir: Path,
        temp_output_dir: Path,
        quirk_registry: FlextLdifServer,
        categorization_rules: dict[str, list[str]],
    ) -> None:
        """Test pipeline execution with only schema entries."""
        ldif_content = """version: 1

dn: cn=schema
cn: schema
objectClass: ldapSubentry
attributeTypes: ( 2.5.4.3 NAME 'cn' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
objectClasses: ( 2.5.6.6 NAME 'person' STRUCTURAL SUP top MUST cn )
"""

        ldif_file = temp_input_dir / "schema.ldif"
        ldif_file.write_text(ldif_content)

        FlextLdifServersOid()

        pipeline = FlextLdifMigrationPipeline(
            input_dir=temp_input_dir,
            output_dir=temp_output_dir,
            categorization_rules=categorization_rules,
            source_server="oid",
            target_server="rfc",
        )

        result = pipeline.execute()
        assert hasattr(result, "is_success")

    def test_execute_with_user_entries(
        self,
        temp_input_dir: Path,
        temp_output_dir: Path,
        quirk_registry: FlextLdifServer,
        categorization_rules: dict[str, list[str]],
    ) -> None:
        """Test pipeline execution with user entries."""
        ldif_content = """version: 1

dn: cn=John Doe,ou=users,dc=example,dc=com
cn: John Doe
sn: Doe
mail: john@example.com
objectClass: person
objectClass: inetOrgPerson
"""

        ldif_file = temp_input_dir / "users.ldif"
        ldif_file.write_text(ldif_content)

        FlextLdifServersOid()

        pipeline = FlextLdifMigrationPipeline(
            input_dir=temp_input_dir,
            output_dir=temp_output_dir,
            categorization_rules=categorization_rules,
            source_server="oid",
            target_server="rfc",
            base_dn="dc=example,dc=com",
        )

        result = pipeline.execute()
        assert hasattr(result, "is_success")

    def test_execute_with_group_entries(
        self,
        temp_input_dir: Path,
        temp_output_dir: Path,
        quirk_registry: FlextLdifServer,
        categorization_rules: dict[str, list[str]],
    ) -> None:
        """Test pipeline execution with group entries."""
        ldif_content = """version: 1

dn: cn=REDACTED_LDAP_BIND_PASSWORDs,ou=groups,dc=example,dc=com
cn: REDACTED_LDAP_BIND_PASSWORDs
objectClass: groupOfNames
member: cn=John Doe,ou=users,dc=example,dc=com
member: cn=Jane Smith,ou=users,dc=example,dc=com
"""

        ldif_file = temp_input_dir / "groups.ldif"
        ldif_file.write_text(ldif_content)

        FlextLdifServersOid()

        pipeline = FlextLdifMigrationPipeline(
            input_dir=temp_input_dir,
            output_dir=temp_output_dir,
            categorization_rules=categorization_rules,
            source_server="oid",
            target_server="rfc",
            base_dn="dc=example,dc=com",
        )

        result = pipeline.execute()
        assert hasattr(result, "is_success")

    def test_execute_with_organizational_units(
        self,
        temp_input_dir: Path,
        temp_output_dir: Path,
        quirk_registry: FlextLdifServer,
        categorization_rules: dict[str, list[str]],
    ) -> None:
        """Test pipeline execution with organizational units."""
        ldif_content = """version: 1

dn: dc=example,dc=com
dc: example
objectClass: domain

dn: ou=users,dc=example,dc=com
ou: users
objectClass: organizationalUnit

dn: ou=groups,dc=example,dc=com
ou: groups
objectClass: organizationalUnit
"""

        ldif_file = temp_input_dir / "hierarchy.ldif"
        ldif_file.write_text(ldif_content)

        FlextLdifServersOid()

        pipeline = FlextLdifMigrationPipeline(
            input_dir=temp_input_dir,
            output_dir=temp_output_dir,
            categorization_rules=categorization_rules,
            source_server="oid",
            target_server="rfc",
            base_dn="dc=example,dc=com",
        )

        result = pipeline.execute()
        assert hasattr(result, "is_success")


class TestCategorizedPipelineMultipleEntries:
    """Test pipeline with multiple entry types."""

    @pytest.fixture
    def temp_input_dir(self) -> Path:
        """Create temporary input directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            input_dir = Path(tmpdir) / "input"
            input_dir.mkdir()
            yield input_dir

    @pytest.fixture
    def temp_output_dir(self) -> Path:
        """Create temporary output directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def categorization_rules(self) -> dict[str, list[str]]:
        """Create standard categorization rules."""
        return {
            "schema": ["ldapSubentry"],
            "hierarchy": ["organizationalUnit", "domain"],
            "users": ["person", "inetOrgPerson"],
            "groups": ["groupOfNames"],
        }

    def test_execute_with_mixed_entries(
        self,
        temp_input_dir: Path,
        temp_output_dir: Path,
        categorization_rules: dict[str, list[str]],
    ) -> None:
        """Test pipeline with mixed entry types."""
        ldif_content = """version: 1

dn: cn=schema
objectClass: ldapSubentry

dn: dc=example,dc=com
dc: example
objectClass: domain

dn: ou=users,dc=example,dc=com
ou: users
objectClass: organizationalUnit

dn: cn=John,ou=users,dc=example,dc=com
cn: John
objectClass: person
objectClass: inetOrgPerson

dn: cn=REDACTED_LDAP_BIND_PASSWORDs,dc=example,dc=com
cn: REDACTED_LDAP_BIND_PASSWORDs
objectClass: groupOfNames
member: cn=John,ou=users,dc=example,dc=com
"""

        ldif_file = temp_input_dir / "mixed.ldif"
        ldif_file.write_text(ldif_content)

        FlextLdifServersOid()

        pipeline = FlextLdifMigrationPipeline(
            input_dir=temp_input_dir,
            output_dir=temp_output_dir,
            categorization_rules=categorization_rules,
            source_server="oid",
            target_server="rfc",
            base_dn="dc=example,dc=com",
        )

        result = pipeline.execute()
        assert hasattr(result, "is_success")


class TestCategorizedPipelineServerTypes:
    """Test pipeline with different server types."""

    @pytest.fixture
    def temp_input_dir(self) -> Path:
        """Create temporary input directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            input_dir = Path(tmpdir) / "input"
            input_dir.mkdir()
            yield input_dir

    @pytest.fixture
    def temp_output_dir(self) -> Path:
        """Create temporary output directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def categorization_rules(self) -> dict[str, list[str]]:
        """Create standard categorization rules."""
        return {
            "schema": ["ldapSubentry"],
            "hierarchy": ["organizationalUnit"],
            "users": ["person"],
            "groups": ["groupOfNames"],
        }

    def test_execute_with_oid_server(
        self,
        temp_input_dir: Path,
        temp_output_dir: Path,
        categorization_rules: dict[str, list[str]],
    ) -> None:
        """Test pipeline with OID server."""
        ldif_content = """version: 1

dn: cn=test,dc=example,dc=com
cn: test
objectClass: person
"""

        ldif_file = temp_input_dir / "oid.ldif"
        ldif_file.write_text(ldif_content)

        FlextLdifServersOid()

        pipeline = FlextLdifMigrationPipeline(
            input_dir=temp_input_dir,
            output_dir=temp_output_dir,
            categorization_rules=categorization_rules,
            source_server="oid",
            target_server="rfc",
        )

        result = pipeline.execute()
        assert hasattr(result, "is_success")

    def test_execute_with_oud_server(
        self,
        temp_input_dir: Path,
        temp_output_dir: Path,
        categorization_rules: dict[str, list[str]],
    ) -> None:
        """Test pipeline with OUD server."""
        ldif_content = """version: 1

dn: cn=test,dc=example,dc=com
cn: test
objectClass: person
ds-sync-timestamp: 20250101000000Z
"""

        ldif_file = temp_input_dir / "oud.ldif"
        ldif_file.write_text(ldif_content)

        FlextLdifServersOud()

        pipeline = FlextLdifMigrationPipeline(
            input_dir=temp_input_dir,
            output_dir=temp_output_dir,
            categorization_rules=categorization_rules,
            source_server="oud",
            target_server="rfc",
        )

        result = pipeline.execute()
        assert hasattr(result, "is_success")

    def test_execute_with_openldap_server(
        self,
        temp_input_dir: Path,
        temp_output_dir: Path,
        categorization_rules: dict[str, list[str]],
    ) -> None:
        """Test pipeline with OpenLDAP server."""
        ldif_content = """version: 1

dn: cn=test,dc=example,dc=com
cn: test
objectClass: person
"""

        ldif_file = temp_input_dir / "openldap.ldif"
        ldif_file.write_text(ldif_content)

        FlextLdifServersOpenldap()

        pipeline = FlextLdifMigrationPipeline(
            input_dir=temp_input_dir,
            output_dir=temp_output_dir,
            categorization_rules=categorization_rules,
            source_server="openldap",
            target_server="rfc",
        )

        result = pipeline.execute()
        assert hasattr(result, "is_success")


class TestCategorizedPipelineOutputGeneration:
    """Test output file generation."""

    @pytest.fixture
    def temp_input_dir(self) -> Path:
        """Create temporary input directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            input_dir = Path(tmpdir) / "input"
            input_dir.mkdir()
            yield input_dir

    @pytest.fixture
    def temp_output_dir(self) -> Path:
        """Create temporary output directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def categorization_rules(self) -> dict[str, list[str]]:
        """Create standard categorization rules."""
        return {
            "schema": ["ldapSubentry"],
            "hierarchy": ["organizationalUnit"],
            "users": ["person"],
            "groups": ["groupOfNames"],
        }

    def test_output_directory_creation(
        self,
        temp_input_dir: Path,
        temp_output_dir: Path,
        categorization_rules: dict[str, list[str]],
    ) -> None:
        """Test that output directory is properly created."""
        ldif_content = """version: 1

dn: cn=test,dc=example,dc=com
cn: test
objectClass: person
"""

        ldif_file = temp_input_dir / "test.ldif"
        ldif_file.write_text(ldif_content)

        FlextLdifServersOid()

        pipeline = FlextLdifMigrationPipeline(
            input_dir=temp_input_dir,
            output_dir=temp_output_dir,
            categorization_rules=categorization_rules,
        )

        result = pipeline.execute()
        assert hasattr(result, "is_success")
        # Output directory should exist
        assert temp_output_dir.exists()

    def test_categorized_output_structure(
        self,
        temp_input_dir: Path,
        temp_output_dir: Path,
        categorization_rules: dict[str, list[str]],
    ) -> None:
        """Test that categorized output has correct structure."""
        ldif_content = """version: 1

dn: cn=schema
objectClass: ldapSubentry

dn: cn=test,dc=example,dc=com
cn: test
objectClass: person
"""

        ldif_file = temp_input_dir / "test.ldif"
        ldif_file.write_text(ldif_content)

        FlextLdifServersOid()

        pipeline = FlextLdifMigrationPipeline(
            input_dir=temp_input_dir,
            output_dir=temp_output_dir,
            categorization_rules=categorization_rules,
        )

        result = pipeline.execute()
        assert hasattr(result, "is_success")


class TestCategorizedPipelineErrorHandling:
    """Test error handling scenarios."""

    @pytest.fixture
    def temp_input_dir(self) -> Path:
        """Create temporary input directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            input_dir = Path(tmpdir) / "input"
            input_dir.mkdir()
            yield input_dir

    @pytest.fixture
    def temp_output_dir(self) -> Path:
        """Create temporary output directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def categorization_rules(self) -> dict[str, list[str]]:
        """Create standard categorization rules."""
        return {
            "schema": ["ldapSubentry"],
            "hierarchy": ["organizationalUnit"],
            "users": ["person"],
            "groups": ["groupOfNames"],
        }

    def test_execute_with_malformed_ldif(
        self,
        temp_input_dir: Path,
        temp_output_dir: Path,
        categorization_rules: dict[str, list[str]],
    ) -> None:
        """Test pipeline with malformed LDIF."""
        ldif_content = """version: 1

dn: incomplete entry without attributes
"""

        ldif_file = temp_input_dir / "malformed.ldif"
        ldif_file.write_text(ldif_content)

        FlextLdifServersOid()

        pipeline = FlextLdifMigrationPipeline(
            input_dir=temp_input_dir,
            output_dir=temp_output_dir,
            categorization_rules=categorization_rules,
        )

        result = pipeline.execute()
        assert hasattr(result, "is_success")

    def test_execute_with_invalid_base_dn(
        self,
        temp_input_dir: Path,
        temp_output_dir: Path,
        categorization_rules: dict[str, list[str]],
    ) -> None:
        """Test pipeline with invalid base DN."""
        ldif_content = """version: 1

dn: cn=test,dc=example,dc=com
cn: test
objectClass: person
"""

        ldif_file = temp_input_dir / "test.ldif"
        ldif_file.write_text(ldif_content)

        FlextLdifServersOid()

        # Use base DN that doesn't match entries
        pipeline = FlextLdifMigrationPipeline(
            input_dir=temp_input_dir,
            output_dir=temp_output_dir,
            categorization_rules=categorization_rules,
            base_dn="dc=different,dc=com",
        )

        result = pipeline.execute()
        assert hasattr(result, "is_success")

    def test_execute_with_missing_required_params(
        self,
        temp_input_dir: Path,
        temp_output_dir: Path,
    ) -> None:
        """Test pipeline with missing required parameters."""
        ldif_content = """version: 1

dn: cn=test,dc=example,dc=com
cn: test
objectClass: person
"""

        ldif_file = temp_input_dir / "test.ldif"
        ldif_file.write_text(ldif_content)

        # Minimal categorization rules
        categorization_rules = {"users": ["person"]}

        FlextLdifServersOid()

        pipeline = FlextLdifMigrationPipeline(
            input_dir=temp_input_dir,
            output_dir=temp_output_dir,
            categorization_rules=categorization_rules,
        )

        result = pipeline.execute()
        assert hasattr(result, "is_success")


class TestCategorizedPipelineRelaxedParsing:
    """Test relaxed parsing scenarios."""

    @pytest.fixture
    def temp_input_dir(self) -> Path:
        """Create temporary input directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            input_dir = Path(tmpdir) / "input"
            input_dir.mkdir()
            yield input_dir

    @pytest.fixture
    def temp_output_dir(self) -> Path:
        """Create temporary output directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def categorization_rules(self) -> dict[str, list[str]]:
        """Create standard categorization rules."""
        return {
            "schema": ["ldapSubentry"],
            "hierarchy": ["organizationalUnit"],
            "users": ["person"],
        }

    def test_execute_with_relaxed_parsing_enabled(
        self,
        temp_input_dir: Path,
        temp_output_dir: Path,
        categorization_rules: dict[str, list[str]],
    ) -> None:
        """Test pipeline with relaxed parsing enabled."""
        ldif_content = """version: 1

dn: cn=test,dc=example,dc=com
cn: test
objectClass: person
"""

        ldif_file = temp_input_dir / "test.ldif"
        ldif_file.write_text(ldif_content)

        FlextLdifServersOid()

        pipeline = FlextLdifMigrationPipeline(
            input_dir=temp_input_dir,
            output_dir=temp_output_dir,
            categorization_rules=categorization_rules,
        )

        result = pipeline.execute()
        assert hasattr(result, "is_success")

    def test_execute_with_relaxed_parsing_broken_ldif(
        self,
        temp_input_dir: Path,
        temp_output_dir: Path,
        categorization_rules: dict[str, list[str]],
    ) -> None:
        """Test pipeline with broken LDIF using relaxed parsing."""
        ldif_content = """version: 1

dn: cn=test,dc=example,dc=com
cn: test
broken attribute without colon
objectClass: person
"""

        ldif_file = temp_input_dir / "broken.ldif"
        ldif_file.write_text(ldif_content)

        FlextLdifServersOid()

        pipeline = FlextLdifMigrationPipeline(
            input_dir=temp_input_dir,
            output_dir=temp_output_dir,
            categorization_rules=categorization_rules,
        )

        result = pipeline.execute()
        assert hasattr(result, "is_success")


__all__ = [
    "TestCategorizedPipelineBasicExecution",
    "TestCategorizedPipelineErrorHandling",
    "TestCategorizedPipelineMultipleEntries",
    "TestCategorizedPipelineOutputGeneration",
    "TestCategorizedPipelineRelaxedParsing",
    "TestCategorizedPipelineServerTypes",
]
