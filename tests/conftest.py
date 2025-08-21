"""FLEXT-LDIF Test Configuration and Fixtures.

This module provides comprehensive pytest configuration, fixtures, and test utilities
for the FLEXT-LDIF test suite, implementing enterprise-grade testing patterns with
comprehensive test data, real service integration, and functional test support.

The test configuration supports multiple test categories including unit tests,
integration tests, end-to-end tests, and performance benchmarks with proper
isolation, realistic test data, and Docker-based integration testing capabilities.

Key Components:
    - Core Fixtures: API instances, configuration objects, and real service instances
    - Test Data Fixtures: Sample LDIF content, entries, and validation scenarios
    - Integration Fixtures: Docker containers, external service mocks, and test databases
    - Utility Fixtures: Temporary files, directories, and cleanup management

Test Categories:
    - unit: Isolated component testing with real service functionality
    - integration: Cross-component testing with real service integration
    - e2e: End-to-end workflow testing with complete system integration
    - ldif: LDIF-specific domain testing with RFC compliance validation
    - parser: Parsing functionality testing with edge cases and error scenarios
    - performance: Performance benchmarking and scalability validation

Example:
    Using fixtures for comprehensive testing:

    >>> def test_ldif_parsing_with_fixtures(flext_ldif_api, sample_ldif_content):
    ...     # API fixture provides configured instance
    ...     result = flext_ldif_api.parse(sample_ldif_content)
    ...     assert result.is_success
    ...
    ...     # Sample content fixture provides realistic test data
    ...     entries = result.value
    ...     assert len(entries) > 0
    ...
    ...     # Validate domain rules
    ...     for entry in entries:
    ...         result = entry.validate_business_rules()
    ...         assert result.is_success

Integration:
    - Docker fixtures for external service integration testing
    - Comprehensive test data with realistic LDIF scenarios
    - Performance benchmarking fixtures with configurable parameters
    - Real service integration with dependency injection patterns

Author: FLEXT Development Team
Version: 0.9.0
License: MIT

"""

from __future__ import annotations

import os
import tempfile
from collections.abc import Generator
from pathlib import Path

import pytest

from flext_ldif import (
    FlextLdifAPI,
    FlextLdifParserService,
    FlextLdifValidatorService,
    TLdif,
)

# Try to import Docker fixtures - optional for testing without Docker
try:
    from tests.docker_fixtures import (
        docker_openldap_container,
        ldif_test_config,
        real_ldif_data,
        skip_if_no_docker,
        temporary_ldif_data,
    )

    DOCKER_FIXTURES_AVAILABLE = True
except ImportError:
    DOCKER_FIXTURES_AVAILABLE = False

    # Create dummy fixtures when Docker is not available
    def skip_if_no_docker() -> object:
        """Skip tests when Docker is not available."""
        return pytest.mark.skip(reason="Docker not available")

    docker_openldap_container = None
    ldif_test_config = None
    real_ldif_data = None
    temporary_ldif_data = None

DOCKER_AVAILABLE = True

# Make fixtures available by importing them into this module's namespace
__all__: list[str] = [
    "docker_openldap_container",
    "ldif_test_config",
    "real_ldif_data",
    "skip_if_no_docker",
    "temporary_ldif_data",
]


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


# LDIF processing fixtures
@pytest.fixture
def ldif_processor_config() -> dict[str, object]:
    """LDIF processor configuration for testing."""
    return {
        "encoding": "utf-8",
        "strict_parsing": True,
        "max_entries": 10000,
        "validate_dn": True,
        "normalize_attributes": True,
    }


@pytest.fixture
def test_ldif_dir() -> Generator[Path]:
    """Temporary directory for LDIF test files."""
    with tempfile.TemporaryDirectory() as temp_dir:
        ldif_dir = Path(temp_dir) / "ldif_files"
        ldif_dir.mkdir()
        yield ldif_dir


# Sample LDIF data fixtures
@pytest.fixture
def sample_ldif_entries() -> str:
    """Sample LDIF entries for testing."""
    return """dn: uid=john.doe,ou=people,dc=example,dc=com
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
uid: john.doe
cn: John Doe
sn: Doe
givenName: John
mail: john.doe@example.com
telephoneNumber: +1 555 123 4567
employeeNumber: 12345
departmentNumber: IT
title: Software Engineer

dn: uid=jane.smith,ou=people,dc=example,dc=com
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
uid: jane.smith
cn: Jane Smith
sn: Smith
givenName: Jane
mail: jane.smith@example.com
telephoneNumber: +1 555 234 5678
employeeNumber: 23456
departmentNumber: HR
title: HR Manager

dn: cn=IT Department,ou=groups,dc=example,dc=com
objectClass: groupOfNames
objectClass: top
cn: IT Department
description: Information Technology Department
member: uid=john.doe,ou=people,dc=example,dc=com

dn: cn=HR Department,ou=groups,dc=example,dc=com
objectClass: groupOfNames
objectClass: top
cn: HR Department
description: Human Resources Department
member: uid=jane.smith,ou=people,dc=example,dc=com"""


@pytest.fixture
def sample_ldif_with_changes() -> str:
    """Sample LDIF with change records for testing."""
    return """dn: uid=john.doe,ou=people,dc=example,dc=com
changetype: modify
replace: mail
mail: john.doe.new@example.com
-
replace: telephoneNumber
telephoneNumber: +1 555 999 8888

dn: uid=new.user,ou=people,dc=example,dc=com
changetype: add
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
uid: new.user
cn: New User
sn: User
givenName: New
mail: new.user@example.com

dn: uid=old.user,ou=people,dc=example,dc=com
changetype: delete"""


@pytest.fixture
def sample_ldif_with_binary() -> str:
    """Sample LDIF with binary data for testing."""
    return """dn: uid=user.photo,ou=people,dc=example,dc=com
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
uid: user.photo
cn: User Photo
sn: Photo
givenName: User
mail: user.photo@example.com
jpegPhoto:: /9j/4AAQSkZJRgABAQEAYABgAAD/2wBDAAEBAQEBAQEBAQEBAQEBAQEBAQEB
 AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAf/2wBDAQEBAQEB
 AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAf/wAARC
 AAEAAQADAREAAhEBAxEB/8QAFQABAQAAAAAAAAAAAAAAAAAAAAv/8QAFQEBAQAAAAAAAAAAAAAAAAAAv//aAAwDAQACEQMRAD8Av"""


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


# LDIF parsing fixtures
@pytest.fixture
def ldif_api() -> FlextLdifAPI:
    """Provide a LDIF API for testing."""
    return FlextLdifAPI()


@pytest.fixture
def ldif_core() -> type[TLdif]:
    """Provide LDIF core functionality for testing."""
    return TLdif


# Schema validation fixtures
@pytest.fixture
def ldap_schema_config() -> dict[str, object]:
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
def transformation_rules() -> dict[str, object]:
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
def ldif_filters() -> dict[str, object]:
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
def expected_ldif_stats() -> dict[str, object]:
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
def large_ldif_config() -> dict[str, object]:
    """Provide configuration for large LDIF processing tests."""
    return {
        "batch_size": 1000,
        "memory_limit": "100MB",
        "progress_reporting": True,
        "parallel_processing": True,
        "max_workers": 4,
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


# Real service fixtures for functional testing
@pytest.fixture
def real_ldif_service() -> object:
    """Real LDIF service for functional testing."""
    return FlextLdifAPI()


@pytest.fixture
def real_parser_service() -> object:
    """Real parser service for functional testing."""
    return FlextLdifParserService()


@pytest.fixture
def real_validator_service() -> object:
    """Real validator service for functional testing."""
    return FlextLdifValidatorService()
