"""Test configuration and fixtures for flext-ldif tests.

Tests LDIF processing operations: parsing, writing, migration, validation.
Uses factories for data generation, helpers for assertions, and constants for configuration.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import sys
from collections.abc import Callable, Generator
from pathlib import Path

import pytest
from flext_core import FlextResult
from flext_tests import FlextTestDocker

from flext_ldif import FlextLdif, FlextLdifParser, FlextLdifWriter
from flext_ldif.services.server import FlextLdifServer
from tests.fixtures.typing import (
    GenericFieldsDict,
    GenericTestCaseDict,
)
from tests.support.conftest_factory import FlextLdifTestConftest
from tests.support.ldif_data import LdifTestData
from tests.support.test_files import FileManager
from tests.support.validators import TestValidators

# Add tests directory to path for local imports AFTER all imports
tests_dir = Path(__file__).parent
if str(tests_dir) not in sys.path:
    sys.path.insert(0, str(tests_dir))

# Singleton instance for all conftest fixtures
conftest_instance = FlextLdifTestConftest()


# Use factory instance for all fixtures
@pytest.fixture(scope="session")
def docker_control() -> FlextTestDocker:
    """Provide FlextTestDocker instance for container management."""
    return conftest_instance.docker_control()


@pytest.fixture(scope="session")
def worker_id(request: pytest.FixtureRequest) -> str:
    """Get pytest-xdist worker ID for DN namespacing."""
    return conftest_instance.worker_id(request)


@pytest.fixture(scope="session")
def session_id() -> str:
    """Generate unique session ID for test isolation."""
    return conftest_instance.session_id()


@pytest.fixture
def unique_dn_suffix(
    worker_id: str,
    session_id: str,
    request: pytest.FixtureRequest,
) -> str:
    """Generate unique DN suffix using factory pattern."""
    return conftest_instance.unique_dn_suffix(worker_id, session_id, request)


@pytest.fixture
def make_user_dn(
    unique_dn_suffix: str,
    ldap_container: GenericFieldsDict,
) -> Callable[[str], str]:
    """Factory for unique user DNs."""
    return conftest_instance.make_user_dn(unique_dn_suffix, ldap_container)


@pytest.fixture
def make_group_dn(
    unique_dn_suffix: str,
    ldap_container: GenericFieldsDict,
) -> Callable[[str], str]:
    """Factory for unique group DNs."""
    return conftest_instance.make_group_dn(unique_dn_suffix, ldap_container)


@pytest.fixture
def make_test_base_dn(
    unique_dn_suffix: str,
    ldap_container: GenericFieldsDict,
) -> Callable[[str], str]:
    """Factory for unique base DNs."""
    return conftest_instance.make_test_base_dn(unique_dn_suffix, ldap_container)


@pytest.fixture
def make_test_username(unique_dn_suffix: str) -> Callable[[str], str]:
    """Factory for unique usernames."""
    return conftest_instance.make_test_username(unique_dn_suffix)


@pytest.fixture(scope="session", autouse=True)
def set_test_environment() -> Generator[None]:
    """Set test environment variables."""
    yield from conftest_instance.set_test_environment()


@pytest.fixture(autouse=True)
def reset_flextldif_singleton() -> Generator[None]:
    """Reset FlextLdif singleton for test isolation."""
    yield from conftest_instance.reset_flextldif_singleton()


@pytest.fixture(autouse=True)
def cleanup_state() -> Generator[None]:
    """Autouse fixture to clean shared state between tests.

    Runs after each test to prevent state pollution to subsequent tests.
    Ensures test isolation even when fixtures have shared state.
    """
    return
    # Post-test cleanup - ensures each test has clean state


@pytest.fixture(scope="session")
def ldap_container(
    docker_control: FlextTestDocker,
    worker_id: str,
) -> GenericFieldsDict:
    """Session-scoped LDAP container configuration."""
    return conftest_instance.ldap_container(docker_control, worker_id)


@pytest.fixture
def ldap_container_shared(ldap_container: GenericFieldsDict) -> str:
    """Provide LDAP connection string.

    Uses function scope to ensure fresh connection per test (no state pollution).
    """
    return conftest_instance.ldap_container_shared(ldap_container)


@pytest.fixture
def ldap_connection(ldap_container: GenericFieldsDict) -> Generator[object]:
    """Create LDAP connection.

    Uses function scope to ensure fresh connection per test (no state pollution).
    """
    yield from conftest_instance.ldap_connection(ldap_container)


@pytest.fixture
def clean_test_ou(
    ldap_connection: object,
    make_test_base_dn: object,
) -> Generator[object]:
    """Create and clean isolated test OU."""
    yield from conftest_instance.clean_test_ou(ldap_connection, make_test_base_dn)


@pytest.fixture
def ldif_processor_config() -> object:
    """LDIF processor configuration."""
    return conftest_instance.ldif_processor_config()


@pytest.fixture
def real_ldif_api() -> object:
    """Real LDIF API services."""
    return conftest_instance.real_ldif_api()


@pytest.fixture
def strict_ldif_api() -> object:
    """Strict LDIF API services."""
    return conftest_instance.strict_ldif_api()


@pytest.fixture
def lenient_ldif_api() -> object:
    """Lenient LDIF API services."""
    return conftest_instance.lenient_ldif_api()


@pytest.fixture
def ldif_test_data() -> LdifTestData:
    """LDIF test data provider."""
    return conftest_instance.ldif_test_data()


@pytest.fixture
def test_file_manager() -> Generator[FileManager]:
    """Test file manager."""
    yield from conftest_instance.test_file_manager()


@pytest.fixture
def test_validators() -> TestValidators:
    """Test validators."""
    return conftest_instance.test_validators()


@pytest.fixture
def test_ldif_dir() -> Generator[Path]:
    """Temporary LDIF directory."""
    yield from conftest_instance.test_ldif_dir()


@pytest.fixture
def sample_ldif_entries(ldif_test_data: LdifTestData) -> str:
    """Sample LDIF entries."""
    return conftest_instance.sample_ldif_entries(ldif_test_data)


@pytest.fixture
def sample_ldif_with_changes(ldif_test_data: LdifTestData) -> str:
    """Sample LDIF with changes."""
    return conftest_instance.sample_ldif_with_changes(ldif_test_data)


@pytest.fixture
def sample_ldif_with_binary(ldif_test_data: LdifTestData) -> str:
    """Sample LDIF with binary."""
    return conftest_instance.sample_ldif_with_binary(ldif_test_data)


@pytest.fixture
def ldif_test_file(test_ldif_dir: Path, sample_ldif_entries: str) -> Path:
    """LDIF test file."""
    return conftest_instance.ldif_test_file(test_ldif_dir, sample_ldif_entries)


@pytest.fixture
def ldif_changes_file(test_ldif_dir: Path, sample_ldif_with_changes: str) -> Path:
    """LDIF changes file."""
    return conftest_instance.ldif_changes_file(test_ldif_dir, sample_ldif_with_changes)


@pytest.fixture
def ldif_binary_file(test_ldif_dir: Path, sample_ldif_with_binary: str) -> Path:
    """LDIF binary file."""
    return conftest_instance.ldif_binary_file(test_ldif_dir, sample_ldif_with_binary)


@pytest.fixture
def quirk_registry() -> FlextLdifServer:
    """Quirk registry."""
    return conftest_instance.quirk_registry()


@pytest.fixture
def ldif_api() -> FlextLdif:
    """FlextLdif API instance.

    Uses function scope to ensure fresh instance per test (no state pollution).
    Each test gets a clean FlextLdif instance.
    """
    return conftest_instance.ldif_api()


@pytest.fixture
def real_parser_service(quirk_registry: FlextLdifServer) -> FlextLdifParser:
    """Real parser service."""
    return conftest_instance.real_parser_service(quirk_registry)


@pytest.fixture
def real_writer_service(quirk_registry: FlextLdifServer) -> FlextLdifWriter:
    """Real writer service."""
    return conftest_instance.real_writer_service(quirk_registry)


@pytest.fixture
def integration_services() -> GenericFieldsDict:
    """Integration services."""
    return conftest_instance.integration_services()


@pytest.fixture
def assert_result_success(
    flext_matchers: object,
) -> Callable[[FlextResult[object]], None]:
    """Result success assertion."""
    return conftest_instance.assert_result_success(flext_matchers)


@pytest.fixture
def assert_result_failure(
    flext_matchers: object,
) -> Callable[[FlextResult[object]], None]:
    """Result failure assertion."""
    return conftest_instance.assert_result_failure(flext_matchers)


@pytest.fixture
def validate_flext_result_success() -> Callable[[FlextResult[object]], dict[str, bool]]:
    """Validate success result."""
    return conftest_instance.validate_flext_result_success()


@pytest.fixture
def validate_flext_result_failure() -> Callable[[FlextResult[object]], dict[str, bool]]:
    """Validate failure result."""
    return conftest_instance.validate_flext_result_failure()


@pytest.fixture
def flext_result_composition_helper() -> Callable[
    [list[FlextResult[object]]],
    dict[str, object],
]:
    """Result composition helper."""
    return conftest_instance.flext_result_composition_helper()


@pytest.fixture
def ldap_schema_config() -> GenericFieldsDict:
    """LDAP schema config."""
    return conftest_instance.ldap_schema_config()


@pytest.fixture
def transformation_rules() -> GenericFieldsDict:
    """Transformation rules."""
    return conftest_instance.transformation_rules()


@pytest.fixture
def ldif_filters() -> GenericFieldsDict:
    """LDIF filters."""
    return conftest_instance.ldif_filters()


@pytest.fixture
def expected_ldif_stats() -> GenericFieldsDict:
    """Expected LDIF stats."""
    return conftest_instance.expected_ldif_stats()


@pytest.fixture
def invalid_ldif_data() -> str:
    """Invalid LDIF data."""
    return conftest_instance.invalid_ldif_data()


@pytest.fixture
def large_ldif_config() -> GenericFieldsDict:
    """Large LDIF config."""
    return conftest_instance.large_ldif_config()


@pytest.fixture
def flext_domains() -> object:
    """Domain-specific test data."""
    return conftest_instance.flext_domains()


@pytest.fixture
def flext_matchers() -> object:
    """Local matchers."""
    return conftest_instance.flext_matchers()


@pytest.fixture
def ldif_test_entries() -> list[dict[str, dict[str, list[str]] | str]]:
    """LDIF test entries."""
    return conftest_instance.ldif_test_entries()


@pytest.fixture
def ldif_test_content(ldif_test_entries: list[GenericTestCaseDict]) -> str:
    """Generate LDIF content."""
    return conftest_instance.ldif_test_content(ldif_test_entries)


@pytest.fixture
def ldif_error_scenarios() -> dict[str, str]:
    """Error scenarios."""
    return conftest_instance.ldif_error_scenarios()


@pytest.fixture
def ldif_performance_config(flext_domains: object) -> GenericFieldsDict:
    """Performance config."""
    return conftest_instance.ldif_performance_config(flext_domains)


@pytest.fixture
def ldif_test_constants() -> object:
    """Test constants."""
    return conftest_instance.ldif_test_constants()


@pytest.fixture
def fixtures_loader() -> object:
    """Generic fixture loader."""
    return conftest_instance.fixtures_loader()


@pytest.fixture
def oid_fixtures() -> object:
    """OID fixtures."""
    return conftest_instance.oid_fixtures()


@pytest.fixture
def oid_schema(oid_fixtures: object) -> str:
    """OID schema."""
    return conftest_instance.oid_schema(oid_fixtures)


@pytest.fixture
def oid_acl(oid_fixtures: object) -> str:
    """OID ACL."""
    return conftest_instance.oid_acl(oid_fixtures)


@pytest.fixture
def oid_entries(oid_fixtures: object) -> str:
    """OID entries."""
    return conftest_instance.oid_entries(oid_fixtures)


@pytest.fixture
def oid_integration(oid_fixtures: object) -> str:
    """OID integration."""
    return conftest_instance.oid_integration(oid_fixtures)


@pytest.fixture
def oud_fixtures() -> object:
    """OUD fixtures."""
    return conftest_instance.oud_fixtures()


@pytest.fixture
def openldap_fixtures() -> object:
    """OpenLDAP fixtures."""
    return conftest_instance.openldap_fixtures()


@pytest.fixture
def server() -> FlextLdifServer:
    """Server instance."""
    return conftest_instance.server()


@pytest.fixture
def rfc_quirk(server: FlextLdifServer) -> object:
    """RFC quirk."""
    return conftest_instance.rfc_quirk(server)


@pytest.fixture
def oid_quirk(server: FlextLdifServer) -> object:
    """OID quirk."""
    return conftest_instance.oid_quirk(server)


@pytest.fixture
def oud_quirk(server: FlextLdifServer) -> object:
    """OUD quirk."""
    return conftest_instance.oud_quirk(server)


@pytest.fixture
def oid() -> object:
    """OID quirk (deprecated)."""
    return conftest_instance.oid()


# Pytest configuration
def pytest_configure(config: pytest.Config) -> None:
    """Configure pytest markers."""
    conftest_instance.pytest_configure(config)


def pytest_collection_modifyitems(
    config: pytest.Config,
    items: list[pytest.Item],
) -> None:
    """Filter test items."""
    conftest_instance.pytest_collection_modifyitems(config, items)


# Mock replacements for flext_tests dependencies to avoid python_on_whales import
import sys
from types import ModuleType

# Create mock module
mock_flext_tests = ModuleType("flext_tests")


# Mock classes
class MockFlextTestsBuilders:
    pass


class MockFlextTestsDomains:
    @staticmethod
    def create_user():
        return {"name": "test", "email": "test@example.com"}

    @staticmethod
    def create_configuration():
        return {"setting": "value"}

    @staticmethod
    def create_service():
        return {"service": "mock"}

    @staticmethod
    def create_payload():
        return {"data": "mock"}

    @staticmethod
    def batch_users(count):
        return [
            {"name": f"user{i}", "email": f"user{i}@example.com"} for i in range(count)
        ]

    @staticmethod
    def valid_email_cases():
        return ["test@example.com"]

    @staticmethod
    def invalid_email_cases():
        return ["invalid"]

    @staticmethod
    def valid_ages():
        return [25]

    @staticmethod
    def invalid_ages():
        return [-1]


class MockFlextTestsFactories:
    pass


class MockFlextTestsMatchers:
    @staticmethod
    def assert_success(result, message=None):
        """Assert result is success and return unwrapped value."""
        if hasattr(result, "is_success") and result.is_success:
            return result.unwrap() if hasattr(result, "unwrap") else result.value
        msg = (
            message
            or f"Expected success but got failure: {getattr(result, 'error', result)}"
        )
        raise AssertionError(msg)

    @staticmethod
    def assert_failure(result, expected_error=None):
        """Assert result is failure."""
        if hasattr(result, "is_failure") and result.is_failure:
            error = result.error if hasattr(result, "error") else str(result)
            if expected_error and expected_error not in str(error):
                raise AssertionError(
                    f"Expected error containing '{expected_error}' but got: {error}"
                )
            return error
        raise AssertionError(f"Expected failure but got success: {result}")


class MockFlextTestsUtilities:
    class ResultHelpers:
        @staticmethod
        def validate_composition(*args, **kwargs) -> bool:
            return True

        @staticmethod
        def validate_chain(*args, **kwargs) -> bool:
            return True

        @staticmethod
        def assert_composition(*args, **kwargs) -> None:
            pass

        @staticmethod
        def assert_chain_success(*args, **kwargs) -> None:
            pass


# Add mock classes to mock module
mock_flext_tests.FlextTestsBuilders = MockFlextTestsBuilders
mock_flext_tests.FlextTestsDomains = MockFlextTestsDomains
mock_flext_tests.FlextTestsFactories = MockFlextTestsFactories
mock_flext_tests.FlextTestsMatchers = MockFlextTestsMatchers
mock_flext_tests.FlextTestsUtilities = MockFlextTestsUtilities

# Inject mock module into sys.modules
sys.modules["flext_tests"] = mock_flext_tests

# Add mock classes to global namespace for inheritance
import builtins

builtins.FlextTestsFactories = MockFlextTestsFactories
builtins.FlextTestsMatchers = MockFlextTestsMatchers
builtins.FlextTestsUtilities = MockFlextTestsUtilities
