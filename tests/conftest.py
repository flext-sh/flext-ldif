"""Test configuration and fixtures for flext-ldif tests."""

from __future__ import annotations

import os
import tempfile
from collections.abc import Generator
from pathlib import Path

import pytest
from flext_core import FlextTypes

from flext_ldif import (
    FlextLDIFAPI,
)
from flext_ldif.parser_service import FlextLDIFParserService
from flext_ldif.validator_service import FlextLDIFValidatorService
from flext_ldif.writer_service import FlextLDIFWriterService
from tests.test_support import (
    LdifTestData,
    RealServiceFactory,
    TestFileManager,
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
def real_ldif_api() -> FlextLDIFAPI:
    """Real LDIF API instance for functional testing."""
    return RealServiceFactory.create_api()


@pytest.fixture
def strict_ldif_api() -> FlextLDIFAPI:
    """Strict LDIF API for validation testing."""
    return RealServiceFactory.create_strict_api()


@pytest.fixture
def lenient_ldif_api() -> FlextLDIFAPI:
    """Lenient LDIF API for error recovery testing."""
    return RealServiceFactory.create_lenient_api()


@pytest.fixture
def ldif_test_data() -> LdifTestData:
    """LDIF test data provider."""
    return LdifTestData()


@pytest.fixture
def test_file_manager() -> Generator[TestFileManager]:
    """Test file manager with automatic cleanup."""
    with TestFileManager() as manager:
        yield manager


@pytest.fixture
def test_validators() -> TestValidators:
    """Test validators for comprehensive validation."""
    return TestValidators()


@pytest.fixture
def test_ldif_dir() -> Generator[Path]:
    """Temporary directory for LDIF test files."""
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
def real_parser_service() -> FlextLDIFParserService:
    """Real parser service for functional testing."""
    return RealServiceFactory.create_parser()


@pytest.fixture
def real_validator_service() -> FlextLDIFValidatorService:
    """Real validator service for functional testing."""
    return RealServiceFactory.create_validator()


@pytest.fixture
def real_writer_service() -> FlextLDIFWriterService:
    """Real writer service for functional testing."""
    return RealServiceFactory.create_writer()


@pytest.fixture
def integration_services() -> FlextTypes.Core.Dict:
    """Complete service set for integration testing."""
    return RealServiceFactory.services_for_integration_test()


# Legacy fixture for backward compatibility
@pytest.fixture
def ldif_api(real_ldif_api: FlextLDIFAPI) -> FlextLDIFAPI:
    """Backward compatibility fixture."""
    return real_ldif_api


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
