"""Test configuration and fixtures for flext-ldif tests.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import os
import tempfile
from collections.abc import Callable, Generator
from pathlib import Path
from typing import cast

import pytest
from flext_core import FlextCore

from flext_ldif.quirks.registry import FlextLdifQuirksRegistry
from flext_ldif.rfc.rfc_ldif_parser import FlextLdifRfcLdifParser
from flext_ldif.rfc.rfc_ldif_writer import FlextLdifRfcLdifWriter
from tests.fixtures.loader import FlextLdifFixtures

from .test_support import FileManager, LdifTestData, RealServiceFactory, TestValidators


class TestFileManager:
    """Simple file manager for tests."""

    def __init__(self, temp_dir: Path) -> None:
        """Initialize with temp directory."""
        self.temp_dir = temp_dir

    def create_file(self, filename: str, content: str) -> Path:
        """Create a temporary file with content."""
        file_path = self.temp_dir / filename
        file_path.write_text(content, encoding="utf-8")
        return file_path


# Test environment setup
@pytest.fixture(autouse=True)
def set_test_environment() -> Generator[None]:
    """Set test environment variables."""
    os.environ["FLEXT_ENV"] = "test"
    os.environ["FLEXT_LOG_LEVEL"] = "debug"
    yield
    # Cleanup
    os.environ.pop("FLEXT_ENV", None)
    os.environ.pop("FLEXT_LOG_LEVEL", None)


# ============================================================================
# DOCKER CONTAINER MANAGEMENT (CENTRALIZED FIXTURES)
# ============================================================================
#
# Docker fixtures are provided by flext_tests.fixtures.docker_fixtures:
#   - ldap_container: OpenLDAP container (port 3390) - PRIMARY FOR LDIF TESTING
#   - oracle_container: Oracle DB container (port 1522)
#   - client-a_oud_container: client-a OUD container (port 3389)
#   - postgres_container: PostgreSQL container (port 5432)
#   - redis_container: Redis container (port 6379)
#
# The ldap_container fixture is automatically available for all tests that need it.
# FlextTestDocker is also available via flext_test_docker fixture if direct
# container management is needed.
#
# Example usage:
#   def test_ldif_with_ldap(ldap_container: str):
#       # ldap_container provides connection string like "ldap://localhost:3390"
#       # Container is automatically started and cleaned up
#       pass
#


# LDIF processing fixtures - optimized with real services
@pytest.fixture
def ldif_processor_config() -> FlextCore.Types.Dict:
    """LDIF processor configuration for testing."""
    return {
        "encoding": FlextCore.Constants.Mixins.DEFAULT_ENCODING,
        "strict_parsing": True,
        "max_entries": 10000,
        "validate_dn": True,
        "normalize_attributes": True,
    }


@pytest.fixture
def real_ldif_api() -> dict:
    """Real LDIF API services for functional testing (RFC-first)."""
    return RealServiceFactory.create_api()


@pytest.fixture
def strict_ldif_api() -> dict:
    """Strict LDIF API services for validation testing (RFC-first)."""
    return RealServiceFactory.create_strict_api()


@pytest.fixture
def lenient_ldif_api() -> dict:
    """Lenient LDIF API services for error recovery testing (RFC-first)."""
    return RealServiceFactory.create_lenient_api()


@pytest.fixture
def ldif_test_data() -> LdifTestData:
    """LDIF test data provider."""
    return LdifTestData()


@pytest.fixture
def test_file_manager() -> Generator[FileManager]:
    """Test file manager with automatic cleanup.

    Yields:
        FileManager: File manager instance for testing

    """
    with FileManager() as manager:
        yield manager


@pytest.fixture
def test_validators() -> TestValidators:
    """Test validators for comprehensive validation."""
    return TestValidators()


@pytest.fixture
def test_ldif_dir() -> Generator[Path]:
    """Temporary directory for LDIF test files.

    Yields:
        Path: Temporary directory path for LDIF test files

    """
    with tempfile.TemporaryDirectory() as temp_dir:
        ldif_dir = Path(temp_dir) / "ldif_files"
        ldif_dir.mkdir()
        yield ldif_dir


# Sample LDIF data fixtures - using real test data
@pytest.fixture
def sample_ldif_entries(ldif_test_data: LdifTestData) -> str:
    """Sample LDIF entries for testing."""
    return ldif_test_data.basic_entries().content


@pytest.fixture
def sample_ldif_with_changes(ldif_test_data: LdifTestData) -> str:
    """Sample LDIF with change records for testing."""
    return ldif_test_data.with_changes().content


@pytest.fixture
def sample_ldif_with_binary(ldif_test_data: LdifTestData) -> str:
    """Sample LDIF with binary data for testing."""
    return ldif_test_data.with_binary_data().content


# LDIF file fixtures
@pytest.fixture
def ldif_test_file(test_ldif_dir: Path, sample_ldif_entries: str) -> Path:
    """LDIF test file with sample entries."""
    ldif_file = test_ldif_dir / "test_entries.ldif"
    ldif_file.write_text(sample_ldif_entries, encoding="utf-8")
    return ldif_file


@pytest.fixture
def ldif_changes_file(test_ldif_dir: Path, sample_ldif_with_changes: str) -> Path:
    """LDIF test file with change records."""
    ldif_file = test_ldif_dir / "test_changes.ldif"
    ldif_file.write_text(sample_ldif_with_changes, encoding="utf-8")
    return ldif_file


@pytest.fixture
def ldif_binary_file(test_ldif_dir: Path, sample_ldif_with_binary: str) -> Path:
    """LDIF test file with binary data."""
    ldif_file = test_ldif_dir / "test_binary.ldif"
    ldif_file.write_text(sample_ldif_with_binary, encoding="utf-8")
    return ldif_file


# Quirk registry fixture for RFC-first architecture enforcement
@pytest.fixture
def quirk_registry() -> FlextLdifQuirksRegistry:
    """Provide quirk registry for RFC-first testing (MANDATORY)."""
    # Registry auto-discovers and registers all standard quirks
    return FlextLdifQuirksRegistry()


# Real service fixtures for functional testing
@pytest.fixture
def real_parser_service(
    quirk_registry: FlextLdifQuirksRegistry,
) -> FlextLdifRfcLdifParser:
    """Real parser service for functional testing (RFC-first with quirks)."""
    return RealServiceFactory.create_parser(quirk_registry=quirk_registry)


@pytest.fixture
def real_writer_service(
    quirk_registry: FlextLdifQuirksRegistry,
) -> FlextLdifRfcLdifWriter:
    """Real writer service for functional testing (RFC-first with quirks)."""
    return RealServiceFactory.create_writer(quirk_registry=quirk_registry)


@pytest.fixture
def integration_services() -> FlextCore.Types.Dict:
    """Complete service set for integration testing."""
    return RealServiceFactory.services_for_integration_test()


# FlextTests integration for result validation
@pytest.fixture
def assert_result_success(
    flext_matchers: LocalTestMatchers,
) -> Callable[[FlextCore.Result[object]], None]:
    """Fixture providing result success assertion."""
    return flext_matchers.assert_result_success


@pytest.fixture
def assert_result_failure(
    flext_matchers: LocalTestMatchers,
) -> Callable[[FlextCore.Result[object]], None]:
    """Fixture providing result failure assertion."""
    return flext_matchers.assert_result_failure


# Enhanced flext-core result validation fixtures
@pytest.fixture
def validate_flext_result_success() -> Callable[
    [FlextCore.Result[object]], FlextCore.Types.BoolDict
]:
    """Validate FlextCore.Result success characteristics using flext-core patterns."""

    def validator(result: FlextCore.Result[object]) -> FlextCore.Types.BoolDict:
        return {
            "is_success": result.is_success,
            "has_value": result.is_success and result.value is not None,
            "no_error": result.error is None,
            "has_error_code": result.error_code is not None,
            "has_error_data": bool(result.error_data),
        }

    return validator


@pytest.fixture
def validate_flext_result_failure() -> Callable[
    [FlextCore.Result[object]], FlextCore.Types.BoolDict
]:
    """Validate FlextCore.Result failure characteristics using flext-core patterns."""

    def validator(result: FlextCore.Result[object]) -> FlextCore.Types.BoolDict:
        return {
            "is_failure": result.is_failure,
            "has_error": result.error is not None,
            "error_not_empty": bool(result.error and result.error.strip()),
            "has_error_code": result.error_code is not None,
            "has_error_data": bool(result.error_data),
        }

    return validator


@pytest.fixture
def flext_result_composition_helper() -> Callable[
    [list[FlextCore.Result[object]]], FlextCore.Types.Dict
]:
    """Helper for testing FlextCore.Result composition patterns."""

    def helper(results: list[FlextCore.Result[object]]) -> FlextCore.Types.Dict:
        successes = [r for r in results if r.is_success]
        failures = [r for r in results if r.is_failure]

        return {
            "total_results": len(results),
            "success_count": len(successes),
            "failure_count": len(failures),
            "success_rate": len(successes) / len(results) if results else 0.0,
            "all_successful": all(r.is_success for r in results),
            "any_successful": any(r.is_success for r in results),
            "error_messages": [r.error for r in failures if r.error],
        }

    return helper


# Schema validation fixtures
@pytest.fixture
def ldap_schema_config() -> FlextCore.Types.Dict:
    """LDAP schema configuration for validation."""
    return {
        "validate_object_classes": True,
        "validate_attributes": True,
        "required_object_classes": ["top"],
        "allowed_attributes": {
            "inetOrgPerson": [
                "uid",
                "cn",
                "sn",
                "givenName",
                "mail",
                "telephoneNumber",
                "employeeNumber",
                "departmentNumber",
                "title",
            ],
            "groupOfNames": ["cn", "description", "member"],
        },
    }


# Entry transformation fixtures
@pytest.fixture
def transformation_rules() -> FlextCore.Types.Dict:
    """Provide transformation rules for LDIF processing."""

    def _transform_mail(x: str | float | None) -> str:
        """Transform mail attribute to lowercase."""
        return str(x).lower() if x else ""

    def _transform_cn(x: str | float | None) -> str:
        """Transform cn attribute to title case."""
        return str(x).title() if x else ""

    return {
        "attribute_mappings": {
            "telephoneNumber": "phone",
            "employeeNumber": "employee_id",
            "departmentNumber": "department",
        },
        "value_transformations": {
            "mail": _transform_mail,
            "cn": _transform_cn,
        },
        "dn_transformations": {
            "base_dn": "dc=newdomain,dc=com",
            "ou_mappings": {
                "people": "users",
                "groups": "groups",
            },
        },
    }


# Filter fixtures
@pytest.fixture
def ldif_filters() -> FlextCore.Types.Dict:
    """LDIF entry filters for testing."""
    return {
        "include_object_classes": ["inetOrgPerson", "groupOfNames"],
        "exclude_attributes": ["userPassword", "pwdHistory"],
        "dn_patterns": [".*,ou=people,.*", ".*,ou=groups,.*"],
        "attribute_filters": {
            "mail": r".*@example\.com$",
            "departmentNumber": ["IT", "HR", "Finance"],
        },
    }


# Statistics fixtures
@pytest.fixture
def expected_ldif_stats() -> FlextCore.Types.Dict:
    """Provide expected LDIF processing statistics."""
    return {
        "total_entries": 4,
        "successful_entries": 4,
        "failed_entries": 0,
        "object_class_counts": {
            "inetOrgPerson": 2,
            "groupOfNames": 2,
        },
        "attribute_counts": {
            "uid": 2,
            "cn": 4,
            "mail": 2,
        },
    }


# Error handling fixtures
@pytest.fixture
def invalid_ldif_data() -> str:
    """Invalid LDIF data for error testing."""
    return """dn: invalid-dn-format
objectClass: nonExistentClass
invalidAttribute: value without proper formatting
# Missing required attributes

dn:
objectClass: person
# Empty DN

dn: uid=test,ou=people,dc=example,dc=com
objectClass: person
# Missing required attributes for person class"""


# Performance fixtures
@pytest.fixture
def large_ldif_config() -> FlextCore.Types.Dict:
    """Provide configuration for large LDIF processing tests."""
    return {
        "batch_size": 1000,
        "memory_limit": "100MB",
        "progress_reporting": True,
        "parallel_processing": True,
        "max_workers": 4,
    }


# FlextTests* Integration Fixtures
# Local test utilities to replace flext_tests dependency
class LocalTestMatchers:
    """Local test matchers to replace FlextTestsMatchers."""

    @staticmethod
    def assert_result_success(result: FlextCore.Result[object]) -> None:
        """Assert that a FlextCore.Result is successful."""
        assert result.is_success, f"Expected success but got failure: {result.error}"

    @staticmethod
    def assert_result_failure(result: FlextCore.Result[object]) -> None:
        """Assert that a FlextCore.Result is a failure."""
        assert result.is_failure, f"Expected failure but got success: {result.value}"


class LocalTestDomains:
    """Local test domains to replace FlextTestsDomains."""

    def create_configuration(self, **kwargs: object) -> FlextCore.Types.Dict:
        """Create a test configuration dictionary."""
        return kwargs


@pytest.fixture
def flext_domains() -> LocalTestDomains:
    """Local domain-specific test data generator."""
    return LocalTestDomains()


@pytest.fixture
def flext_matchers() -> LocalTestMatchers:
    """Local matchers for assertions."""
    return LocalTestMatchers()


# LDIF-specific test data using FlextTests patterns
@pytest.fixture
def ldif_test_entries() -> list[FlextCore.Types.Dict]:
    """Generate LDIF test entries using FlextTests domain patterns."""
    # Create realistic LDIF entries using domain patterns
    # Create test users using FlextTestsDomains patterns
    users: list[FlextCore.Types.StringDict] = [
        {"name": "Test User 1", "email": "user1@example.com"},
        {"name": "Test User 2", "email": "user2@example.com"},
        {"name": "Test User 3", "email": "user3@example.com"},
    ]
    entries: list[FlextCore.Types.Dict] = []

    for i, user in enumerate(users):
        entry: FlextCore.Types.Dict = {
            "dn": f"uid={user.get('name', 'testuser')}{i},ou=people,dc=example,dc=com",
            "attributes": {
                "objectClass": ["inetOrgPerson", "person"],
                "cn": [user.get("name", "Test User")],
                "sn": [
                    (
                        user.get("name", "User").split()[-1]
                        if " " in user.get("name", "")
                        else "User"
                    ),
                ],
                "mail": [user.get("email", f"test{i}@example.com")],
                "uid": [f"testuser{i}"],
            },
        }
        entries.append(entry)

    # Add a group entry
    group_entry: FlextCore.Types.Dict = {
        "dn": "cn=testgroup,ou=groups,dc=example,dc=com",
        "attributes": {
            "objectClass": ["groupOfNames"],
            "cn": ["Test Group"],
            "description": ["Test group for LDIF processing"],
            "member": [entry["dn"] for entry in entries],
        },
    }
    entries.append(group_entry)

    return entries


@pytest.fixture
def ldif_test_content(ldif_test_entries: list[FlextCore.Types.Dict]) -> str:
    """Generate LDIF content string from test entries."""
    content_lines: FlextCore.Types.StringList = []

    for entry in ldif_test_entries:
        content_lines.append(f"dn: {entry['dn']}")
        attributes = entry["attributes"]
        assert isinstance(attributes, dict), "attributes must be a dictionary"

        # Cast to proper type for type checker
        typed_attributes = cast("dict[str, FlextCore.Types.StringList]", attributes)

        # Process attributes - all values are lists of strings based on actual structure
        for attr_key, attr_values in typed_attributes.items():
            attr_name: str = str(attr_key)
            # Based on actual code structure, all attribute values are lists
            # attr_values is already typed as FlextCore.Types.StringList from the cast above
            content_lines.extend(
                f"{attr_name}: {value_item!s}" for value_item in attr_values
            )
        content_lines.append("")  # Empty line between entries

    return "\n".join(content_lines)


@pytest.fixture
def ldif_error_scenarios() -> FlextCore.Types.StringDict:
    """Error scenarios for LDIF processing tests."""
    return {
        "invalid_dn": "dn: invalid-dn-format\nobjectClass: person\n",
        "missing_dn": "objectClass: person\ncn: Test User\n",
        "empty_content": "",
        "malformed_attribute": (
            "dn: cn=test,dc=example,dc=com\ninvalid-attribute-line\n"
        ),
        "circular_reference": (
            "dn: cn=group1,dc=example,dc=com\n"
            "member: cn=group2,dc=example,dc=com\n\n"
            "dn: cn=group2,dc=example,dc=com\n"
            "member: cn=group1,dc=example,dc=com\n"
        ),
    }


@pytest.fixture
def ldif_performance_config(flext_domains: LocalTestDomains) -> FlextCore.Types.Dict:
    """Performance testing configuration using FlextTests patterns."""
    config = flext_domains.create_configuration(
        batch_size=1000,
        memory_limit="50MB",
        timeout=30,
        max_workers=2,
    )
    return {
        "large_entry_count": 5000,
        "complex_attributes_per_entry": 20,
        "deep_nesting_levels": 5,
        **config,
    }


# Pytest markers for test categorization
def pytest_configure(config: pytest.Config) -> None:
    """Configure pytest markers."""
    config.addinivalue_line("markers", "unit: Unit tests")
    config.addinivalue_line("markers", "integration: Integration tests")
    config.addinivalue_line("markers", "e2e: End-to-end tests")
    config.addinivalue_line("markers", "ldif: LDIF processing tests")
    config.addinivalue_line("markers", "parser: LDIF parser tests")
    config.addinivalue_line("markers", "writer: LDIF writer tests")
    config.addinivalue_line("markers", "transformation: Data transformation tests")
    config.addinivalue_line("markers", "validation: Schema validation tests")
    config.addinivalue_line("markers", "performance: Performance tests")
    config.addinivalue_line("markers", "slow: Slow tests")
    config.addinivalue_line(
        "markers",
        "docker: Tests requiring Docker OpenLDAP container",
    )
    config.addinivalue_line("markers", "real_ldap: Tests using real LDAP server")
    config.addinivalue_line("markers", "flext_tests: Tests using FlextTests utilities")


# Common test constants using FlextTests patterns
class LDIFTestConstants:
    """Constants for LDIF testing."""

    # Test file paths
    SAMPLE_LDIF_FILE = "tests/fixtures/sample_basic.ldif"
    COMPLEX_LDIF_FILE = "tests/fixtures/sample_complex.ldif"
    INVALID_LDIF_FILE = "tests/fixtures/sample_invalid.ldif"

    # Test data
    SAMPLE_DN = "cn=test,ou=users,dc=example,dc=com"
    SAMPLE_ATTRIBUTE = "cn"
    SAMPLE_VALUE = "test user"

    # Test limits
    MAX_TEST_ENTRIES = 100
    MAX_TEST_ATTRIBUTES = 50
    MAX_TEST_VALUES = 20

    # Test timeouts (in milliseconds)
    DEFAULT_TIMEOUT_MS = 5000
    MAX_PARSE_TIME_PER_ENTRY = 1000  # 1 second per entry


@pytest.fixture
def ldif_test_constants() -> LDIFTestConstants:
    """Provide centralized test constants."""
    return LDIFTestConstants()


# ============================================================================
# LDAP SERVER QUIRKS FIXTURES (FlextLdifFixtures)
# ============================================================================


@pytest.fixture
def fixtures_loader() -> FlextLdifFixtures.Loader:
    """Generic fixture loader for all LDAP servers.

    Returns:
        FlextLdifFixtures.Loader: Generic fixture loader instance

    """
    from tests.fixtures import FlextLdifFixtures

    return FlextLdifFixtures.Loader()


@pytest.fixture
def oid_fixtures() -> FlextLdifFixtures.OID:
    """Oracle Internet Directory fixture loader.

    Returns:
        FlextLdifFixtures.OID: OID-specific fixture loader instance

    Example:
        def test_oid_schema(oid_fixtures):
            schema = oid_fixtures.schema()
            assert "orclUser" in schema

    """
    from tests.fixtures import FlextLdifFixtures

    return FlextLdifFixtures.OID()


@pytest.fixture
def oid_schema(oid_fixtures: FlextLdifFixtures.OID) -> str:
    """OID schema fixtures content.

    Returns:
        str: LDIF content with Oracle OID schema definitions

    """
    return oid_fixtures.schema()


@pytest.fixture
def oid_acl(oid_fixtures: FlextLdifFixtures.OID) -> str:
    """OID ACL fixtures content.

    Returns:
        str: LDIF content with Oracle OID ACL patterns

    """
    return oid_fixtures.acl()


@pytest.fixture
def oid_entries(oid_fixtures: FlextLdifFixtures.OID) -> str:
    """OID entry fixtures content.

    Returns:
        str: LDIF content with anonymized OID user/group entries

    """
    return oid_fixtures.entries()


@pytest.fixture
def oid_integration(oid_fixtures: FlextLdifFixtures.OID) -> str:
    """OID integration fixtures content with real quirks.

    Returns:
        str: LDIF content with complete OID directory structure and real quirks

    """
    return oid_fixtures.integration()


@pytest.fixture
def oud_fixtures() -> FlextLdifFixtures.OUD:
    """Oracle Unified Directory fixture loader.

    Returns:
        FlextLdifFixtures.OUD: OUD-specific fixture loader instance

    """
    from tests.fixtures import FlextLdifFixtures

    return FlextLdifFixtures.OUD()


@pytest.fixture
def openldap_fixtures() -> FlextLdifFixtures.OpenLDAP:
    """OpenLDAP fixture loader.

    Returns:
        FlextLdifFixtures.OpenLDAP: OpenLDAP-specific fixture loader instance

    """
    from tests.fixtures import FlextLdifFixtures

    return FlextLdifFixtures.OpenLDAP()
