"""Test configuration for flext-ldif.

Provides pytest fixtures and configuration for testing LDIF processing functionality
using real LDIF data and flext-core patterns.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

if TYPE_CHECKING:
    from collections.abc import Generator

# Import Docker fixtures if available
try:
    from .docker_fixtures import (
        docker_openldap_container,
        ldif_test_config,
        real_ldif_data,
        skip_if_no_docker,
        temporary_ldif_data,
    )
    DOCKER_AVAILABLE = True
    
    # Make fixtures available by importing them into this module's namespace
    __all__ = [
        'docker_openldap_container',
        'ldif_test_config', 
        'real_ldif_data',
        'skip_if_no_docker',
        'temporary_ldif_data',
    ]
    
except ImportError:
    DOCKER_AVAILABLE = False


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
def ldif_processor_config() -> dict[str, Any]:
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
async def ldif_parser() -> Any:
    """Provide a LDIF parser for testing."""
    from flext_ldif import FlextLdifParser

    return FlextLdifParser()


@pytest.fixture
async def ldif_writer() -> Any:
    """Provide a LDIF writer for testing."""
    from flext_ldif import FlextLdifWriter

    return FlextLdifWriter()


# Schema validation fixtures
@pytest.fixture
def ldap_schema_config() -> dict[str, Any]:
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
def transformation_rules() -> dict[str, Any]:
    """Transformation rules for LDIF processing."""
    return {
        "attribute_mappings": {
            "telephoneNumber": "phone",
            "employeeNumber": "employee_id",
            "departmentNumber": "department",
        },
        "value_transformations": {
            "mail": lambda x: x.lower(),
            "cn": lambda x: x.title(),
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
def ldif_filters() -> dict[str, Any]:
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
def expected_ldif_stats() -> dict[str, Any]:
    """Expected LDIF processing statistics."""
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
def large_ldif_config() -> dict[str, Any]:
    """Configuration for large LDIF processing tests."""
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
    config.addinivalue_line("markers", "docker: Tests requiring Docker OpenLDAP container")
    config.addinivalue_line("markers", "real_ldap: Tests using real LDAP server")


# Mock services
@pytest.fixture
def mock_ldif_service() -> Any:
    """Mock LDIF service for testing."""

    class MockLdifService:
        async def parse_ldif(self, content: str) -> list[dict[str, Any]]:
            return [{"dn": "test", "attributes": {}}]

        async def write_ldif(self, entries: list[dict[str, Any]]) -> str:
            return "dn: test\nobjectClass: top\n"

        async def transform_entries(
            self,
            entries: list[dict[str, Any]],
            rules: dict[str, Any],
        ) -> list[dict[str, Any]]:
            return entries

        async def validate_entries(
            self,
            entries: list[dict[str, Any]],
            schema: dict[str, Any],
        ) -> dict[str, Any]:
            return {"valid": True, "errors": []}

    return MockLdifService()


@pytest.fixture
def mock_schema_validator() -> Any:
    """Mock schema validator for testing."""

    class MockSchemaValidator:
        def validate_entry(self, entry: dict[str, Any]) -> dict[str, Any]:
            return {"valid": True, "errors": []}

        def validate_object_class(self, object_class: str) -> bool:
            return True

        def validate_attribute(self, attribute: str, value: Any) -> bool:
            return True

    return MockSchemaValidator()
