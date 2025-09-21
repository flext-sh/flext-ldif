"""Test configuration and fixtures for flext-ldif tests.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import os
import tempfile
from collections.abc import Callable, Collection, Generator
from pathlib import Path
from typing import ClassVar

import pytest
from flext_tests import (
    FlextTestsBuilders,
    FlextTestsDomains,
    FlextTestsFixtures,
    FlextTestsMatchers,
    FlextTestsUtilities,
)

from flext_core import FlextResult, FlextTypes
from flext_ldif import FlextLdifAPI
from tests.test_support import (
    FileManager,
    LdifTestData,
    RealServiceFactory,
    TestValidators,
)


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


# Docker container initialization (session-scoped, started once)
# Temporarily disabled to fix test execution
# @pytest.fixture(scope="session", autouse=True)
# def ensure_docker_container(docker_openldap_container: object) -> None:
#     """Ensure Docker container is started for the test session."""
#     # Suppress unused parameter warning - fixture is used for side effects
#     _ = docker_openldap_container
#     # The docker_openldap_container fixture will be invoked automatically
#     # and will start/stop the container for the entire test session


# LDIF processing fixtures - optimized with real services
@pytest.fixture
def ldif_processor_config() -> FlextTypes.Core.Dict:
    """LDIF processor configuration for testing."""
    return {
        "encoding": "utf-8",
        "strict_parsing": True,
        "max_entries": 10000,
        "validate_dn": True,
        "normalize_attributes": True,
    }


@pytest.fixture
def real_ldif_api() -> FlextLdifAPI:
    """Real LDIF API instance for functional testing."""
    return RealServiceFactory.create_api()


@pytest.fixture
def strict_ldif_api() -> FlextLdifAPI:
    """Strict LDIF API for validation testing."""
    return RealServiceFactory.create_strict_api()


@pytest.fixture
def lenient_ldif_api() -> FlextLdifAPI:
    """Lenient LDIF API for error recovery testing."""
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


# Real service fixtures for functional testing
@pytest.fixture
def real_parser_service() -> FlextLdifAPI:
    """Real parser service for functional testing - using unified API."""
    return RealServiceFactory.create_parser()


@pytest.fixture
def real_writer_service() -> FlextLdifAPI:
    """Real writer service for functional testing - using unified API."""
    return RealServiceFactory.create_writer()


@pytest.fixture
def integration_services() -> FlextTypes.Core.Dict:
    """Complete service set for integration testing."""
    return RealServiceFactory.services_for_integration_test()


# Legacy fixture for backward compatibility
@pytest.fixture
def ldif_api(real_ldif_api: FlextLdifAPI) -> FlextLdifAPI:
    """Backward compatibility fixture."""
    return real_ldif_api


# FlextTests integration for result validation
@pytest.fixture
def assert_result_success(
    flext_matchers: FlextTestsMatchers,
) -> Callable[[FlextResult[object]], None]:
    """Fixture providing FlextTests result success assertion."""
    return flext_matchers.assert_result_success


@pytest.fixture
def assert_result_failure(
    flext_matchers: FlextTestsMatchers,
) -> Callable[[FlextResult[object]], None]:
    """Fixture providing FlextTests result failure assertion."""
    return flext_matchers.assert_result_failure


# Schema validation fixtures
@pytest.fixture
def ldap_schema_config() -> FlextTypes.Core.Dict:
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
def transformation_rules() -> FlextTypes.Core.Dict:
    """Provide transformation rules for LDIF processing."""
    return {
        "attribute_mappings": {
            "telephoneNumber": "phone",
            "employeeNumber": "employee_id",
            "departmentNumber": "department",
        },
        "value_transformations": {
            "mail": lambda x: str(x).lower() if x else "",
            "cn": lambda x: str(x).title() if x else "",
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
def ldif_filters() -> FlextTypes.Core.Dict:
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
def expected_ldif_stats() -> FlextTypes.Core.Dict:
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
def large_ldif_config() -> FlextTypes.Core.Dict:
    """Provide configuration for large LDIF processing tests."""
    return {
        "batch_size": 1000,
        "memory_limit": "100MB",
        "progress_reporting": True,
        "parallel_processing": True,
        "max_workers": 4,
    }


# FlextTests* Integration Fixtures
@pytest.fixture
def flext_builders() -> FlextTestsBuilders:
    """FlextTests builders for complex test object creation."""
    return FlextTestsBuilders()


@pytest.fixture
def flext_domains() -> FlextTestsDomains:
    """FlextTests domain-specific test data generator."""
    return FlextTestsDomains()


@pytest.fixture
def flext_fixtures() -> FlextTestsFixtures:
    """FlextTests fixtures and utilities."""
    return FlextTestsFixtures()


@pytest.fixture
def flext_matchers() -> FlextTestsMatchers:
    """FlextTests matchers for assertions."""
    return FlextTestsMatchers()


@pytest.fixture
def flext_utilities() -> FlextTestsUtilities:
    """FlextTests utilities and helpers."""
    return FlextTestsUtilities()


# LDIF-specific test data using FlextTests patterns
@pytest.fixture
def ldif_test_entries() -> list[dict[str, Collection[str] | str]]:
    """Generate LDIF test entries using FlextTests domain patterns."""
    # Create realistic LDIF entries using domain patterns
    # Create test users using FlextTestsDomains patterns
    users = [
        {"name": "Test User 1", "email": "user1@example.com"},
        {"name": "Test User 2", "email": "user2@example.com"},
        {"name": "Test User 3", "email": "user3@example.com"},
    ]
    entries = []

    for i, user in enumerate(users):
        entry = {
            "dn": f"uid={user.get('name', 'testuser')}{i},ou=people,dc=example,dc=com",
            "attributes": {
                "objectClass": ["inetOrgPerson", "person"],
                "cn": [user.get("name", "Test User")],
                "sn": [
                    user.get("name", "User").split()[-1]
                    if " " in user.get("name", "")
                    else "User",
                ],
                "mail": [user.get("email", f"test{i}@example.com")],
                "uid": [f"testuser{i}"],
            },
        }
        entries.append(entry)

    # Add a group entry
    entries.append(
        {
            "dn": "cn=testgroup,ou=groups,dc=example,dc=com",
            "attributes": {
                "objectClass": ["groupOfNames"],
                "cn": ["Test Group"],
                "description": ["Test group for LDIF processing"],
                "member": [entry["dn"] for entry in entries],
            },
        },
    )

    return entries


@pytest.fixture
def ldif_test_content(ldif_test_entries: list[dict[str, object]]) -> str:
    """Generate LDIF content string from test entries."""
    content_lines = []

    for entry in ldif_test_entries:
        content_lines.append(f"dn: {entry['dn']}")
        attributes = entry["attributes"]
        assert isinstance(attributes, dict), "attributes must be a dictionary"
        for attr, values in attributes.items():
            content_lines.extend(f"{attr}: {value}" for value in values)
        content_lines.append("")  # Empty line between entries

    return "\n".join(content_lines)


@pytest.fixture
def ldif_error_scenarios() -> dict[str, str]:
    """Error scenarios for LDIF processing tests."""
    return {
        "invalid_dn": "dn: invalid-dn-format\nobjectClass: person\n",
        "missing_dn": "objectClass: person\ncn: Test User\n",
        "empty_content": "",
        "malformed_attribute": "dn: cn=test,dc=example,dc=com\ninvalid-attribute-line\n",
        "circular_reference": "dn: cn=group1,dc=example,dc=com\nmember: cn=group2,dc=example,dc=com\n\ndn: cn=group2,dc=example,dc=com\nmember: cn=group1,dc=example,dc=com\n",
    }


@pytest.fixture
def ldif_performance_config(flext_domains: FlextTestsDomains) -> dict[str, object]:
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
    """Centralized test constants for LDIF testing."""

    # Standard LDAP object classes
    OBJECT_CLASSES: ClassVar[dict[str, list[str]]] = {
        "person": ["top", "person"],
        "inetOrgPerson": ["top", "person", "organizationalPerson", "inetOrgPerson"],
        "groupOfNames": ["top", "groupOfNames"],
        "organizationalUnit": ["top", "organizationalUnit"],
    }

    # Standard LDAP attributes by object class
    REQUIRED_ATTRIBUTES: ClassVar[dict[str, list[str]]] = {
        "person": ["sn", "cn"],
        "inetOrgPerson": ["sn", "cn"],
        "groupOfNames": ["member", "cn"],
        "organizationalUnit": ["ou"],
    }

    # Common attribute patterns
    ATTRIBUTE_PATTERNS: ClassVar[dict[str, list[str]]] = {
        "dn_patterns": [
            "uid={uid},ou=people,dc=example,dc=com",
            "cn={cn},ou=groups,dc=example,dc=com",
            "ou={ou},dc=example,dc=com",
        ],
        "mail_domains": ["example.com", "test.org", "company.net"],
        "phone_formats": ["+1-555-{:04d}", "(555) {:04d}", "555.{:04d}"],
    }

    # Error conditions for testing
    ERROR_CONDITIONS: ClassVar[dict[str, list[str]]] = {
        "invalid_dn_formats": [
            "invalid-dn-no-equals",
            "=missing-attribute",
            "attr=,missing-value",
            "uid=test,,double-comma",
        ],
        "malformed_attributes": [
            "no-colon-separator",
            ": missing-attribute-name",
            "attr: ",  # empty value
            "attr:\t\tonly-whitespace",
        ],
        "encoding_issues": [
            "attr:: invalid-base64",
            "attr:< invalid-url",
            "binary:: not-base64-encoded",
        ],
    }

    # Performance test parameters
    PERFORMANCE_THRESHOLDS: ClassVar[dict[str, object]] = {
        "max_parse_time_per_entry": 0.001,  # 1ms per entry
        "max_memory_per_entry": 1024,  # 1KB per entry
        "max_total_parse_time": 10.0,  # 10 seconds total
        "batch_sizes": [1, 10, 100, 1000],
    }


@pytest.fixture
def ldif_test_constants() -> LDIFTestConstants:
    """Provide centralized test constants."""
    return LDIFTestConstants()
