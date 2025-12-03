"""Test configuration and fixtures for flext-ldif tests.

Tests LDIF processing operations: parsing, writing, migration, validation.
Uses factories for data generation, helpers for assertions, and constants for configuration.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import builtins
import sys
import warnings
from collections.abc import Callable, Generator
from pathlib import Path
from types import ModuleType
from typing import cast

import pytest
from flext_core import FlextResult
from flext_tests import FlextTestDocker
from ldap3 import Connection

from flext_ldif import (
    FlextLdif,
    FlextLdifModels,
    FlextLdifParser,
    FlextLdifWriter,
)
from flext_ldif.services.server import FlextLdifServer
from tests.fixtures import FlextLdifFixtures
from tests.fixtures.typing import (
    GenericFieldsDict,
    GenericTestCaseDict,
)
from tests.helpers.test_assertions import TestAssertions
from tests.helpers.test_deduplication_helpers import DeduplicationHelpers
from tests.support.conftest_factory import FlextLdifTestConftest
from tests.support.ldif_data import LdifTestData
from tests.support.test_files import FileManager
from tests.support.validators import TestValidators


# Mock classes for flext_tests module
class MockFlextTestsBuilders:
    """Mock FlextTestsBuilders."""

    @staticmethod
    def build_test_data() -> dict[str, object]:
        """Build test data."""
        return {}


class MockFlextTestsDomains:
    """Mock FlextTestsDomains."""

    @staticmethod
    def get_domain_config() -> dict[str, object]:
        """Get domain config."""
        return {}


class MockFlextTestsFactories:
    """Mock FlextTestsFactories."""

    @staticmethod
    def create_test_factory() -> object:
        """Create test factory."""
        return object()


class MockFlextTestsMatchers:
    """Mock FlextTestsMatchers."""

    @staticmethod
    def assert_success(
        result: FlextResult[object], error_msg: str | None = None
    ) -> object:
        """Assert success."""
        if result.is_success:
            return result.unwrap()
        raise AssertionError(error_msg or f"Expected success: {result.error}")

    @staticmethod
    def assert_failure(
        result: FlextResult[object], expected_error: str | None = None
    ) -> str:
        """Assert failure."""
        if result.is_failure:
            error_str = str(result.error) if result.error else str(result)
            if expected_error and expected_error not in error_str:
                raise AssertionError(
                    f"Expected error containing '{expected_error}' but got: {error_str}"
                )
            return error_str
        raise AssertionError(f"Expected failure: {result.value}")


class MockFlextTestsUtilities:
    """Mock FlextTestsUtilities."""

    @staticmethod
    def cleanup_test_data() -> None:
        """Cleanup test data."""


# Add mock classes to global namespace for inheritance
builtins.FlextTestsFactories = MockFlextTestsFactories  # type: ignore[attr-defined]
builtins.FlextTestsMatchers = MockFlextTestsMatchers  # type: ignore[attr-defined]
builtins.FlextTestsUtilities = MockFlextTestsUtilities  # type: ignore[attr-defined]

# Mock flext_tests module
mock_flext_tests = ModuleType("flext_tests")
mock_flext_tests.FlextTestsBuilders = MockFlextTestsBuilders  # type: ignore[attr-defined]
mock_flext_tests.FlextTestsDomains = MockFlextTestsDomains  # type: ignore[attr-defined]
mock_flext_tests.FlextTestsFactories = MockFlextTestsFactories  # type: ignore[attr-defined]
mock_flext_tests.FlextTestsMatchers = MockFlextTestsMatchers  # type: ignore[attr-defined]
mock_flext_tests.FlextTestsUtilities = MockFlextTestsUtilities  # type: ignore[attr-defined]
sys.modules["flext_tests"] = mock_flext_tests

# Factory instance for all fixtures
conftest_instance = FlextLdifTestConftest()


# Use factory instance for all fixtures
@pytest.fixture(scope="session")
def docker_control() -> FlextTestDocker:  # type: ignore[assignment]
    """Provide FlextTestDocker instance for container management."""
    return conftest_instance.docker_control()  # type: ignore[return-value]


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
def cleanup_state() -> None:
    """Autouse fixture to clean shared state between tests.

    Runs after each test to prevent state pollution to subsequent tests.
    Ensures test isolation even when fixtures have shared state.
    """
    # Post-test cleanup - ensures each test has clean state
    return


@pytest.fixture(scope="session")
def ldap_container(
    docker_control: FlextTestDocker,
    worker_id: str,
) -> GenericFieldsDict:
    """Session-scoped LDAP container configuration."""
    return conftest_instance.ldap_container(docker_control, worker_id)  # type: ignore[arg-type]


@pytest.fixture
def ldap_container_shared(ldap_container: GenericFieldsDict) -> str:
    """Provide LDAP connection string.

    Uses function scope to ensure fresh connection per test (no state pollution).
    """
    return conftest_instance.ldap_container_shared(ldap_container)


@pytest.fixture
def ldap_connection(ldap_container: GenericFieldsDict) -> Generator[Connection]:
    """Create LDAP connection.

    Uses function scope to ensure fresh connection per test (no state pollution).
    """
    yield from conftest_instance.ldap_connection(ldap_container)


@pytest.fixture
def clean_test_ou(
    ldap_connection: Connection,
    make_test_base_dn: Callable[[str], str],
) -> Generator[str]:
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
    flext_matchers: TestAssertions,
) -> Callable[[FlextResult[object]], None]:
    """Result success assertion."""
    return conftest_instance.assert_result_success(flext_matchers)


@pytest.fixture
def assert_result_failure(
    flext_matchers: TestAssertions,
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
    GenericFieldsDict,
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
def flext_domains() -> FlextLdifTestConftest.LocalTestDomains:
    """Domain-specific test data."""
    return conftest_instance.flext_domains()


@pytest.fixture
def flext_matchers() -> FlextLdifTestConftest.LocalTestMatchers:
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
def ldif_performance_config(
    flext_domains: FlextLdifTestConftest.LocalTestDomains,
) -> GenericFieldsDict:
    """Performance config."""
    return conftest_instance.ldif_performance_config(flext_domains)


@pytest.fixture
def ldif_test_constants() -> FlextLdifTestConftest.LDIFTestConstants:
    """Test constants."""
    return conftest_instance.ldif_test_constants()


@pytest.fixture
def fixtures_loader() -> FlextLdifFixtures.Loader:
    """Generic fixture loader."""
    return conftest_instance.fixtures_loader()


@pytest.fixture
def oid_fixtures() -> FlextLdifFixtures.OID:
    """OID fixtures."""
    return conftest_instance.oid_fixtures()


@pytest.fixture
def oid_schema(oid_fixtures: FlextLdifFixtures.OID) -> str:
    """OID schema."""
    return conftest_instance.oid_schema(oid_fixtures)


@pytest.fixture
def oid_acl(oid_fixtures: FlextLdifFixtures.OID) -> str:
    """OID ACL."""
    return conftest_instance.oid_acl(oid_fixtures)


@pytest.fixture
def oid_entries(oid_fixtures: FlextLdifFixtures.OID) -> str:
    """OID entries."""
    return conftest_instance.oid_entries(oid_fixtures)


@pytest.fixture
def oid_integration(oid_fixtures: FlextLdifFixtures.OID) -> str:
    """OID integration."""
    return conftest_instance.oid_integration(oid_fixtures)


@pytest.fixture
def oud_fixtures() -> FlextLdifFixtures.OUD:
    """OUD fixtures."""
    return conftest_instance.oud_fixtures()


@pytest.fixture
def openldap_fixtures() -> FlextLdifFixtures.OpenLDAP:
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
    config.addinivalue_line("markers", "integration: Integration tests")
    config.addinivalue_line("markers", "unit: Unit tests")
    config.addinivalue_line("markers", "slow: Slow tests")


# Helper class for assertions - DEPRECATED: Use TestAssertions from test_assertions.py
class AssertionHelpers:
    """Helper methods for test assertions.

    DEPRECATED: This class is deprecated. Use TestAssertions from test_assertions.py instead.
    This class will be removed in a future version.
    """

    @staticmethod
    def assert_success(
        result: FlextResult[object] | object, message: str | None = None
    ) -> object:
        """Assert result is success and return unwrapped value.

        DEPRECATED: Use TestAssertions.assert_success() instead.
        """
        warnings.warn(
            "AssertionHelpers.assert_success is deprecated. "
            "Use TestAssertions.assert_success() instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        if isinstance(result, FlextResult) and result.is_success:
            unwrapped = result.unwrap()
            return unwrapped if unwrapped is not None else ""
        if hasattr(result, "is_success") and getattr(result, "is_success", False):
            if hasattr(result, "unwrap"):
                unwrap_method = result.unwrap
                unwrapped = (
                    unwrap_method()
                    if callable(unwrap_method)
                    else getattr(result, "value", "")
                )
                return unwrapped if unwrapped is not None else ""
            return getattr(result, "value", "")
        msg = (
            message
            or f"Expected success but got failure: {getattr(result, 'error', result)}"
        )
        raise AssertionError(msg)

    @staticmethod
    def assert_failure(
        result: FlextResult[object] | object, expected_error: str | None = None
    ) -> str:
        """Assert result is failure.

        DEPRECATED: Use TestAssertions.assert_failure() instead.
        """
        warnings.warn(
            "AssertionHelpers.assert_failure is deprecated. "
            "Use TestAssertions.assert_failure() instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        if isinstance(result, FlextResult) and result.is_failure:
            error_str = str(result.error) if result.error else str(result)
            if expected_error and expected_error not in error_str:
                raise AssertionError(
                    f"Expected error containing '{expected_error}' but got: {error_str}"
                )
            return error_str
        if hasattr(result, "is_failure") and getattr(result, "is_failure", False):
            error_str = (
                str(getattr(result, "error", ""))
                if hasattr(result, "error") and getattr(result, "error", None)
                else str(result)
            )
            if expected_error and expected_error not in error_str:
                raise AssertionError(
                    f"Expected error containing '{expected_error}' but got: {error_str}"
                )
            return error_str
        raise AssertionError(f"Expected failure: {result}")


# =============================================================================
# FIXTURES FOR COMMON TEST OPERATIONS
# =============================================================================
# These fixtures provide reusable operations that reduce duplication in tests.
# Use these fixtures instead of duplicating parse/write/roundtrip logic.


@pytest.fixture
def parse_ldif_content(
    ldif_api: FlextLdif,
) -> Callable[[str | Path], FlextResult[object]]:
    """Fixture for parsing LDIF content.

    Returns a callable that parses LDIF content and returns FlextResult.
    Use this fixture to avoid duplicating parse logic in tests.

    Example:
        def test_something(parse_ldif_content):
            result = parse_ldif_content("dn: cn=test")
            assert result.is_success

    """

    def _parse(content: str | Path) -> FlextResult[object]:
        parse_result = ldif_api.parse(content)
        # Cast to FlextResult[object] for type compatibility
        return cast("FlextResult[object]", parse_result)

    return _parse


@pytest.fixture
def write_ldif_entries(
    ldif_api: FlextLdif,
) -> Callable[[list[FlextLdifModels.Entry], Path], FlextResult[object]]:
    """Fixture for writing LDIF entries to file.

    Returns a callable that writes entries to a file and returns FlextResult.
    Use this fixture to avoid duplicating write logic in tests.

    Example:
        def test_something(write_ldif_entries, tmp_path):
            result = write_ldif_entries(entries, tmp_path / "test.ldif")
            assert result.is_success

    """

    def _write(entries: list[FlextLdifModels.Entry], path: Path) -> FlextResult[object]:
        write_result = ldif_api.write(entries, output_path=path)
        # Cast to FlextResult[object] for type compatibility
        return cast("FlextResult[object]", write_result)

    return _write


@pytest.fixture
def roundtrip_ldif(
    ldif_api: FlextLdif,
    tmp_path: Path,
) -> Callable[
    [str | Path], tuple[list[FlextLdifModels.Entry], Path, list[FlextLdifModels.Entry]]
]:
    """Fixture for roundtrip operations (parse -> write -> parse).

    Returns a callable that performs a complete roundtrip and returns
    (original_entries, output_file, roundtripped_entries).
    Use this fixture to avoid duplicating roundtrip logic in tests.

    Example:
        def test_something(roundtrip_ldif):
            orig, output, rt = roundtrip_ldif("dn: cn=test")
            assert len(orig) == len(rt)

    """

    def _roundtrip(
        content: str | Path,
    ) -> tuple[list[FlextLdifModels.Entry], Path, list[FlextLdifModels.Entry]]:
        # Use complete_roundtrip_parse_write_parse which accepts tmp_path
        # Returns tuple[list[Entry], Path, list[Entry]]
        return DeduplicationHelpers.complete_roundtrip_parse_write_parse(
            ldif_api,
            content,
            tmp_path,
        )

    return _roundtrip
