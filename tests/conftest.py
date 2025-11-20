"""Test configuration and fixtures for flext-ldif tests.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import tempfile
from collections.abc import Callable, Generator
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from flext_core import FlextConstants, FlextResult
from flext_tests.docker import FlextTestDocker

from flext_ldif.api import FlextLdif
from flext_ldif.servers.base import FlextLdifServersBase
from flext_ldif.services.parser import FlextLdifParser
from flext_ldif.services.server import FlextLdifServer
from flext_ldif.services.writer import FlextLdifWriter

from .fixtures import FlextLdifFixtures
from .support import (
    FileManager,
    LdifTestData,
    RealServiceFactory,
    TestValidators,
)

if TYPE_CHECKING:
    from ldap3 import Connection

# =============================================================================
# TEST DATA CONSTANTS (Pre-built for performance)
# =============================================================================

# Pre-defined test users to avoid repeated dictionary creation
_TEST_USERS: list[dict[str, str]] = [
    {"name": "Test User 1", "email": "user1@example.com"},
    {"name": "Test User 2", "email": "user2@example.com"},
    {"name": "Test User 3", "email": "user3@example.com"},
]

# Pre-built LDIF test entries (computed once at module load)
_LDIF_TEST_ENTRIES: list[dict[str, object]] = [
    {
        "dn": f"uid={user.get('name', 'testuser')}{i},ou=people,dc=example,dc=com",
        "attributes": {
            "objectclass": ["inetOrgPerson", "person"],
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
    for i, user in enumerate(_TEST_USERS)
] + [
    {
        "dn": "cn=testgroup,ou=groups,dc=example,dc=com",
        "attributes": {
            "objectclass": ["groupOfNames"],
            "cn": ["Test Group"],
            "description": ["Test group for LDIF processing"],
            "member": [
                f"uid={user.get('name', 'testuser')}{i},ou=people,dc=example,dc=com"
                for i, user in enumerate(_TEST_USERS)
            ],
        },
    }
]

# =============================================================================
# FLEXT TEST DOCKER INTEGRATION (SHARED CONTAINER)
# =============================================================================


@pytest.fixture(scope="session")
def docker_control() -> FlextTestDocker:
    """Provide FlextTestDocker instance for container management.

    Session-scoped to reuse across all tests.
    """
    return FlextTestDocker()


@pytest.fixture(scope="session")
def worker_id(request: pytest.FixtureRequest) -> str:
    """Get pytest-xdist worker ID for DN namespacing.

    Returns:
        str: Worker ID (e.g., "gw0", "gw1", "master")
            - "master": single-process execution
            - "gw0", "gw1", ...: parallel workers from pytest-xdist

    """
    worker_input = getattr(request.config, "workerinput", {})
    return worker_input.get("workerid", "master")


@pytest.fixture(scope="session")
def session_id() -> str:
    """Unique session ID for this test run.

    Returns:
        str: Timestamp in milliseconds as string

    Used for DN namespacing to ensure test isolation.

    """
    import time

    return str(int(time.time() * 1000))


@pytest.fixture
def unique_dn_suffix(
    worker_id: str,
    session_id: str,
    request: pytest.FixtureRequest,
) -> str:
    """Generate unique DN suffix for this worker and test.

    Combines worker ID, session ID, test function name, and microsecond timestamp
    to create globally unique DN suffix that prevents conflicts in parallel execution.
    This ensures complete isolation between tests even when running in parallel.

    Args:
        worker_id: pytest-xdist worker ID (e.g., "gw0", "master")
        session_id: Test session timestamp
        request: Pytest request object for test identification

    Returns:
        str: Unique suffix (e.g., "gw0-1733000000-test_function-123456")

    Example:
        >>> suffix = unique_dn_suffix
        >>> dn = f"uid=testuser-{suffix},ou=people,dc=flext,dc=local"

    """
    import time

    # Get test function name for additional isolation
    test_name = request.node.name if hasattr(request, "node") else "unknown"
    # Sanitize test name (remove special chars that could break DN)
    allowed_chars = {"-", "_"}
    test_name_clean = "".join(
        c if c.isalnum() or c in allowed_chars else "-" for c in test_name
    )[:20]

    # Microsecond precision for intra-second uniqueness
    test_id = int(time.time() * 1000000) % 1000000

    return f"{worker_id}-{session_id}-{test_name_clean}-{test_id}"


@pytest.fixture
def make_user_dn(
    unique_dn_suffix: str,
    ldap_container: dict[str, object],
) -> Callable[[str], str]:
    """Factory to create unique user DNs with base DN isolation.

    Uses the base_dn from ldap_container to ensure complete isolation.
    This allows multiple tests to run in parallel without conflicts.

    Args:
        unique_dn_suffix: Unique suffix from fixture
        ldap_container: Container configuration with base_dn

    Returns:
        callable: Factory function that takes uid and returns unique DN

    Example:
        >>> make_dn = make_user_dn
        >>> dn = make_dn("testuser")  # uid=testuser-gw0-...,ou=people,dc=flext,dc=local

    """
    base_dn = str(ldap_container.get("base_dn", "dc=flext,dc=local"))

    def _make(uid: str) -> str:
        """Create unique user DN.

        Args:
            uid: User ID (e.g., "testuser")

        Returns:
            str: Unique DN (e.g., "uid=testuser-gw0-123...,ou=people,dc=flext,dc=local")

        """
        return f"uid={uid}-{unique_dn_suffix},ou=people,{base_dn}"

    return _make


@pytest.fixture
def make_group_dn(
    unique_dn_suffix: str,
    ldap_container: dict[str, object],
) -> Callable[[str], str]:
    """Factory to create unique group DNs with base DN isolation.

    Uses the base_dn from ldap_container to ensure complete isolation.
    This allows multiple tests to run in parallel without conflicts.

    Args:
        unique_dn_suffix: Unique suffix from fixture
        ldap_container: Container configuration with base_dn

    Returns:
        callable: Factory function that takes cn and returns unique DN

    Example:
        >>> make_dn = make_group_dn
        >>> dn = make_dn(
        ...     "testgroup"
        ... )  # cn=testgroup-gw0-...,ou=groups,dc=flext,dc=local

    """
    base_dn = str(ldap_container.get("base_dn", "dc=flext,dc=local"))

    def _make(cn: str) -> str:
        """Create unique group DN.

        Args:
            cn: Common name (e.g., "testgroup")

        Returns:
            str: Unique DN (e.g., "cn=testgroup-gw0-123...,ou=groups,dc=flext,dc=local")

        """
        return f"cn={cn}-{unique_dn_suffix},ou=groups,{base_dn}"

    return _make


@pytest.fixture
def make_test_base_dn(
    unique_dn_suffix: str,
    ldap_container: dict[str, object],
) -> Callable[[str], str]:
    """Factory to create unique base DNs for test isolation.

    Uses the base_dn from ldap_container to ensure complete isolation.
    This allows multiple tests to run in parallel without conflicts.

    Args:
        unique_dn_suffix: Unique suffix from fixture
        ldap_container: Container configuration with base_dn

    Returns:
        callable: Factory function that takes ou and returns unique base DN

    Example:
        >>> make_base = make_test_base_dn
        >>> base_dn = make_base("test")  # ou=test-gw0-...,dc=flext,dc=local

    """
    base_dn = str(ldap_container.get("base_dn", "dc=flext,dc=local"))

    def _make(ou: str) -> str:
        """Create unique base DN.

        Args:
            ou: Organizational unit name (e.g., "test")

        Returns:
            str: Unique base DN (e.g., "ou=test-gw0-123...,dc=flext,dc=local")

        """
        return f"ou={ou}-{unique_dn_suffix},{base_dn}"

    return _make


@pytest.fixture
def make_test_username(unique_dn_suffix: str) -> Callable[[str], str]:
    """Factory to create unique usernames for test isolation.

    Ensures idempotency and parallel test execution by namespacing
    usernames with worker-specific suffix.

    Args:
        unique_dn_suffix: Unique suffix from fixture

    Returns:
        callable: Factory function that takes username and returns unique username

    Example:
        >>> make_user = make_test_username
        >>> username = make_user("testuser")  # testuser-gw0-123...

    """

    def _make(username: str) -> str:
        """Create unique username.

        Args:
            username: Base username (e.g., "testuser")

        Returns:
            str: Unique username (e.g., "testuser-gw0-123...")

        """
        return f"{username}-{unique_dn_suffix}"

    return _make


class TestFileManager:
    """Simple file manager for tests."""

    def __init__(self, temp_dir: Path) -> None:
        """Initialize with temp directory."""
        super().__init__()
        self.temp_dir = temp_dir

    def create_file(self, filename: str, content: str) -> Path:
        """Create a temporary file with content."""
        file_path = self.temp_dir / filename
        file_path.write_text(content, encoding="utf-8")
        return file_path


# Test environment setup
@pytest.fixture(scope="session", autouse=True)
def set_test_environment() -> Generator[None]:
    """Set test environment variables.

    Session-scoped for performance - environment doesn't change between tests.
    """
    # NO environment-specific modes - remove all dev/test/prod mode logic
    # Use FlextConfig for environment variable management instead of os.environ
    yield
    # Cleanup - reset config instances instead of manipulating os.environ
    from flext_core import FlextConfig

    # Reset global config instance to clear any test-specific state
    FlextConfig.reset_global_instance()


@pytest.fixture(autouse=True)
def reset_flextldif_singleton() -> Generator[None]:
    """Reset FlextLdif singleton before each test to ensure test isolation.

    This fixture ensures tests are idempotent and parallelizable by preventing
    state leakage between tests through the FlextLdif singleton instance.

    Addresses requirement: "o testes precisam ser idepontente, paralelizareis
    par rodar no container compartilhaod e que um nao atrapalhe o outro"
    (tests must be idempotent, parallelizable, run in shared containers
    without interfering with each other).

    The fixture runs automatically before each test (autouse=True) and resets
    the singleton so each test gets a fresh FlextLdif instance.

    """
    # Reset singleton before test
    FlextLdif._reset_instance()
    yield
    # Reset singleton after test (cleanup)
    FlextLdif._reset_instance()


# ============================================================================
# DOCKER CONTAINER MANAGEMENT (CENTRALIZED FIXTURES)
# ============================================================================
#
# Docker fixtures provide container connection strings for testing.
# The ldap_container_shared fixture provides connection to OpenLDAP server (port 3390).
# All tests use the shared container with indepotency via unique username/basedn.
#
# Example usage:
#   def test_ldif_with_ldap(ldap_container_shared: str, unique_dn_suffix: str):
#       # ldap_container_shared provides connection string "ldap://localhost:3390"
#       # unique_dn_suffix provides isolation (e.g., "gw0-abc123")
#       # Use unique_dn_suffix to create isolated test data
#       pass
#


@pytest.fixture(scope="session")
def ldap_container(
    docker_control: FlextTestDocker,
    worker_id: str,
) -> dict[str, object]:
    """Session-scoped LDAP container configuration with worker isolation.

    Uses FlextTestDocker to manage flext-openldap-test container on port 3390.
    Container is automatically started/stopped by FlextTestDocker.
    All tests share the SAME container but use unique DNs for isolation.

    IMPORTANT: This fixture uses ONLY flext-openldap-test on port 3390.
    NO random ports, NO dynamic containers. All tests share the same container
    but are isolated by unique DNs (via unique_dn_suffix fixture).

    Args:
        docker_control: FlextTestDocker instance from fixture
        worker_id: Worker ID for logging (e.g., "gw0", "master")

    Returns:
        dict with connection parameters including base_dn

    """
    from flext_core import FlextLogger

    logger = FlextLogger(__name__)

    # Use the actual container name from SHARED_CONTAINERS
    container_name = "flext-openldap-test"
    container_config = FlextTestDocker.SHARED_CONTAINERS.get(container_name)

    if not container_config:
        pytest.skip(f"Container {container_name} not found in SHARED_CONTAINERS")

    # Get compose file path
    compose_file = str(container_config["compose_file"])
    if not compose_file.startswith("/"):
        # Relative path, make it absolute from workspace root
        workspace_root = Path("/home/marlonsc/flext")
        compose_file = str(workspace_root / "flext-ldap" / compose_file)

    # REGRA: Só recriar se estiver dirty, senão apenas iniciar se não estiver rodando
    is_dirty = docker_control.is_container_dirty(container_name)

    if is_dirty:
        # Container está dirty - recriar completamente (down -v + up)
        logger.info(
            f"Container {container_name} is dirty, recreating with fresh volumes",
        )
        cleanup_result = docker_control.cleanup_dirty_containers()
        if cleanup_result.is_failure:
            pytest.skip(
                f"Failed to recreate dirty container {container_name}: {cleanup_result.error}",
            )
    else:
        # Container não está dirty - apenas verificar se está rodando e iniciar se necessário
        status = docker_control.get_container_status(container_name)
        if not status.is_success or (
            isinstance(status.value, FlextTestDocker.ContainerInfo)
            and status.value.status != FlextTestDocker.ContainerStatus.RUNNING
        ):
            # Container não está rodando mas não está dirty - apenas iniciar (sem recriar)
            logger.info(
                f"Container {container_name} is not running (but not dirty), starting...",
            )
            start_result = docker_control.start_compose_stack(compose_file)
            if start_result.is_failure:
                pytest.skip(f"Failed to start LDAP container: {start_result.error}")

    # AGUARDAR container estar pronto antes de permitir testes
    import time

    max_wait = 30  # segundos
    wait_interval = 0.5  # segundos
    waited = 0

    while waited < max_wait:
        # Verificar se container está realmente pronto tentando uma conexão simples
        try:
            from ldap3 import Connection, Server

            server = Server("ldap://localhost:3390", get_info="NONE")
            test_conn = Connection(
                server,
                user="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
                password="REDACTED_LDAP_BIND_PASSWORD",
                auto_bind=False,
            )
            # Tentar bind com timeout curto
            if test_conn.bind(timeout=2):
                test_conn.unbind()
                logger.debug(f"Container {container_name} is ready after {waited:.1f}s")
                break
            test_conn.unbind()
        except Exception:
            # Container ainda não está pronto, continuar aguardando
            pass

        time.sleep(wait_interval)
        waited += wait_interval

    if waited >= max_wait:
        pytest.skip(
            f"Container {container_name} did not become ready within {max_wait}s",
        )

    # Provide connection info (matches docker-compose.yml)
    # ALWAYS use port 3390 - NO random ports
    container_info: dict[str, object] = {
        "server_url": "ldap://localhost:3390",
        "host": "localhost",
        "bind_dn": "cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
        "password": "REDACTED_LDAP_BIND_PASSWORD",  # From docker-compose.yml
        "base_dn": "dc=flext,dc=local",
        "port": 3390,  # FIXED PORT - NO RANDOM PORTS
        "use_ssl": False,
        "worker_id": worker_id,  # For logging/debugging
    }

    logger.info(
        f"LDAP container configured for worker {worker_id}: "
        f"{container_name} on port 3390",
    )

    return container_info


@pytest.fixture(scope="module")
def ldap_container_shared(ldap_container: dict[str, object]) -> str:
    """Provide LDAP container connection string (alias for compatibility).

    This fixture provides the connection URL string for backward compatibility.
    New code should use ldap_container dict directly.

    Args:
        ldap_container: Container configuration dict

    Returns:
        str: LDAP connection URL (e.g., "ldap://localhost:3390")

    """
    return str(ldap_container["server_url"])


# ============================================================================
# LDAP CONNECTION FIXTURES (SHARED WITH ISOLATION)
# ============================================================================


@pytest.fixture(scope="module")
def ldap_connection(ldap_container: dict[str, object]) -> Generator[Connection]:
    """Create connection to real LDAP server via Docker fixture with isolation.

    **INDEPOTENCY**: This fixture provides a shared LDAP connection. Tests must
    use unique_dn_suffix and make_test_base_dn/make_test_username fixtures to
    create isolated test data and avoid conflicts in parallel execution.

    Args:
        ldap_container: Container configuration dict with connection parameters

    Yields:
        Connection: ldap3 connection to LDAP server

    """
    from ldap3 import ALL, Connection, Server

    # Extract connection parameters from container config
    host = str(ldap_container["host"])
    port = int(ldap_container["port"])
    bind_dn = str(ldap_container["bind_dn"])
    password = str(ldap_container["password"])

    server = Server(f"ldap://{host}:{port}", get_info=ALL)
    conn = Connection(
        server,
        user=bind_dn,
        password=password,
    )

    # Check if server is available
    try:
        if not conn.bind():
            pytest.skip(f"LDAP server not available at {host}:{port}")
    except Exception as e:
        pytest.skip(f"LDAP server not available at {host}:{port}: {e}")

    yield conn
    conn.unbind()


@pytest.fixture
def clean_test_ou(
    ldap_connection: Connection,
    make_test_base_dn: Callable[[str], str],
) -> Generator[str]:
    """Create and clean up isolated test OU with automatic cleanup.

    **INDEPOTENCY**: Uses make_test_base_dn to create unique OU DNs per test
    execution, ensuring parallel tests don't interfere with each other.

    Args:
        ldap_connection: LDAP connection from fixture
        make_test_base_dn: Factory to create unique base DNs

    Yields:
        str: Isolated test OU DN (e.g., "ou=test-gw0-abc123,dc=flext,dc=local")

    """
    # Create isolated test OU using unique suffix
    test_ou_dn = make_test_base_dn("FlextLdifTests")

    # Try to delete existing test OU (ignore errors - may not exist)
    try:
        # Search for all entries under test OU
        found = ldap_connection.search(
            test_ou_dn,
            "(objectClass=*)",
            search_scope="SUBTREE",
            attributes=["*"],
        )
        if found:
            # Delete in reverse order (leaves first)
            dns_to_delete = [entry.entry_dn for entry in ldap_connection.entries]
            for dn in reversed(dns_to_delete):
                try:
                    ldap_connection.delete(dn)
                except Exception:
                    # Ignore delete errors during cleanup - entries may already be deleted
                    # or dependencies may prevent deletion. Cleanup should not fail tests.
                    pass
    except Exception:
        # OU doesn't exist yet - this is expected for first test run
        pass

    # Create test OU (or recreate if deleted above)
    try:
        ldap_connection.add(
            test_ou_dn,
            ["organizationalUnit"],
            {"ou": "FlextLdifTests"},
        )
    except Exception:
        # OU already exists - this is expected if previous test didn't clean up
        pass

    yield test_ou_dn

    # Cleanup after test - delete all entries under test OU
    try:
        found = ldap_connection.search(
            test_ou_dn,
            "(objectClass=*)",
            search_scope="SUBTREE",
            attributes=["*"],
        )
        if found:
            dns_to_delete = [entry.entry_dn for entry in ldap_connection.entries]
            for dn in reversed(dns_to_delete):
                try:
                    ldap_connection.delete(dn)
                except Exception:
                    # Ignore cleanup errors - entries may have dependencies or already be deleted
                    pass
    except Exception:
        # Cleanup failed, but that's okay - test should not fail due to cleanup issues
        pass


# LDIF processing fixtures - optimized with real services
@pytest.fixture
def ldif_processor_config() -> dict[str, object]:
    """LDIF processor configuration for testing."""
    return {
        "encoding": FlextConstants.Mixins.DEFAULT_ENCODING,
        "strict_parsing": True,
        "max_entries": 10000,
        "validate_dn": True,
        "normalize_attributes": True,
    }


@pytest.fixture
def real_ldif_api() -> dict[str, object]:
    """Real LDIF API services for functional testing (RFC-first)."""
    return RealServiceFactory.create_api()


@pytest.fixture
def strict_ldif_api() -> dict[str, object]:
    """Strict LDIF API services for validation testing (RFC-first)."""
    return RealServiceFactory.create_strict_api()


@pytest.fixture
def lenient_ldif_api() -> dict[str, object]:
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
def quirk_registry() -> FlextLdifServer:
    """Provide quirk registry for RFC-first testing (MANDATORY)."""
    # Registry auto-discovers and registers all standard quirks
    return FlextLdifServer()


# FlextLdif API fixture
@pytest.fixture(scope="module")
def ldif_api() -> FlextLdif:
    """Provides a FlextLdif API instance for the test module.

    Creates a FlextLdif instance using the singleton pattern.
    """
    return FlextLdif.get_instance()


# Real service fixtures for functional testing
@pytest.fixture
def real_parser_service(
    quirk_registry: FlextLdifServer,
) -> FlextLdifParser:
    """Real parser service for functional testing (RFC-first with quirks)."""
    return RealServiceFactory.create_parser()


@pytest.fixture
def real_writer_service(
    quirk_registry: FlextLdifServer,
) -> FlextLdifWriter:
    """Real writer service for functional testing (RFC-first with quirks)."""
    return RealServiceFactory.create_writer(quirk_registry=quirk_registry)


@pytest.fixture
def integration_services() -> dict[str, object]:
    """Complete service set for integration testing."""
    return RealServiceFactory.services_for_integration_test()


# FlextTests integration for result validation
@pytest.fixture
def assert_result_success(
    flext_matchers: LocalTestMatchers,
) -> Callable[[FlextResult[object]], None]:
    """Fixture providing result success assertion."""
    return flext_matchers.assert_result_success


@pytest.fixture
def assert_result_failure(
    flext_matchers: LocalTestMatchers,
) -> Callable[[FlextResult[object]], None]:
    """Fixture providing result failure assertion."""
    return flext_matchers.assert_result_failure


# Enhanced flext-core result validation fixtures
@pytest.fixture
def validate_flext_result_success() -> Callable[[FlextResult[object]], dict[str, bool]]:
    """Validate FlextResult success characteristics using flext-core patterns."""

    def validator(result: FlextResult[object]) -> dict[str, bool]:
        return {
            "is_success": result.is_success,
            "has_value": result.is_success and result.value is not None,
            "no_error": result.error is None,
            "has_error_code": result.error_code is not None,
            "has_error_data": bool(result.error_data),
        }

    return validator


@pytest.fixture
def validate_flext_result_failure() -> Callable[[FlextResult[object]], dict[str, bool]]:
    """Validate FlextResult failure characteristics using flext-core patterns."""

    def validator(result: FlextResult[object]) -> dict[str, bool]:
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
    [list[FlextResult[object]]],
    dict[str, object],
]:
    """Helper for testing FlextResult composition patterns."""

    def helper(results: list[FlextResult[object]]) -> dict[str, object]:
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


# FlextTests* Integration Fixtures
# Local test utilities to replace flext_tests dependency
class LocalTestMatchers:
    """Local test matchers to replace FlextTestsMatchers."""

    @staticmethod
    def assert_result_success(result: FlextResult[object]) -> None:
        """Assert that a FlextResult is successful."""
        assert result.is_success, f"Expected success but got failure: {result.error}"

    @staticmethod
    def assert_result_failure(result: FlextResult[object]) -> None:
        """Assert that a FlextResult is a failure."""
        assert result.is_failure, f"Expected failure but got success: {result.value}"


class LocalTestDomains:
    """Local test domains to replace FlextTestsDomains."""

    def create_configuration(self, **kwargs: object) -> dict[str, object]:
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
def ldif_test_entries() -> list[dict[str, object]]:
    """Generate LDIF test entries using FlextTests domain patterns.

    Returns a copy of pre-built entries for performance.
    """
    import copy

    return copy.deepcopy(_LDIF_TEST_ENTRIES)


@pytest.fixture
def ldif_test_content(ldif_test_entries: list[dict[str, object]]) -> str:
    """Generate LDIF content string from test entries."""
    content_lines: list[str] = []

    for entry in ldif_test_entries:
        content_lines.append(f"dn: {entry['dn']}")
        attributes = entry["attributes"]
        assert isinstance(attributes, dict), "attributes must be a dictionary"

        # Process attributes - all values are lists of strings based on actual structure
        for attr_key, attr_values in attributes.items():
            attr_name: str = str(attr_key)
            # Based on actual code structure, all attribute values are lists
            content_lines.extend(
                f"{attr_name}: {value_item!s}" for value_item in attr_values
            )
        content_lines.append("")  # Empty line between entries

    return "\n".join(content_lines)


@pytest.fixture
def ldif_error_scenarios() -> dict[str, str]:
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
def ldif_performance_config(flext_domains: LocalTestDomains) -> dict[str, object]:
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


def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    """Filter out static methods that start with 'test_' in classes with __test__ = False.

    This prevents pytest from discovering helper methods as tests.
    """
    filtered_items = []
    for item in items:
        # Check if this is a test method from a class
        if hasattr(item, "parent") and hasattr(item.parent, "cls"):
            test_class = item.parent.cls
            # Check if class has __test__ = False
            if test_class and getattr(test_class, "__test__", True) is False:
                # Skip all methods from this class (they are helpers, not tests)
                continue
        filtered_items.append(item)

    # Replace items list
    items[:] = filtered_items


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
    return FlextLdifFixtures.OUD()


@pytest.fixture
def openldap_fixtures() -> FlextLdifFixtures.OpenLDAP:
    """OpenLDAP fixture loader.

    Returns:
        FlextLdifFixtures.OpenLDAP: OpenLDAP-specific fixture loader instance

    """
    return FlextLdifFixtures.OpenLDAP()


# ============================================================================
# SERVER QUIRKS FIXTURES (Via FlextLdifServer API)
# ============================================================================
#
# IMPORTANT: Always use FlextLdifServer().quirk() to get server instances
# NEVER instantiate servers directly (FlextLdifServersOid(), etc.)
# This ensures proper registry management and singleton behavior.


@pytest.fixture
def server() -> FlextLdifServer:
    """Get FlextLdifServer instance for quirk management.

    Returns:
        FlextLdifServer: Server instance for getting quirks

    Example:
        def test_with_server(server: FlextLdifServer):
            oid = server.quirk("oid")
            assert oid is not None

    """
    return FlextLdifServer()


@pytest.fixture
def rfc_quirk(server: FlextLdifServer) -> FlextLdifServersBase:
    """Get RFC server quirk via FlextLdifServer API.

    Args:
        server: FlextLdifServer instance

    Returns:
        FlextLdifServersBase: RFC server quirk

    """
    quirk = server.quirk("rfc")
    assert quirk is not None, "RFC quirk must be registered"
    return quirk


@pytest.fixture
def oid_quirk(server: FlextLdifServer) -> FlextLdifServersBase:
    """Get OID server quirk via FlextLdifServer API.

    Args:
        server: FlextLdifServer instance

    Returns:
        FlextLdifServersBase: OID server quirk

    """
    quirk = server.quirk("oid")
    assert quirk is not None, "OID quirk must be registered"
    return quirk


@pytest.fixture
def oud_quirk(server: FlextLdifServer) -> FlextLdifServersBase:
    """Get OUD server quirk via FlextLdifServer API.

    Args:
        server: FlextLdifServer instance

    Returns:
        FlextLdifServersBase: OUD server quirk

    """
    quirk = server.quirk("oud")
    assert quirk is not None, "OUD quirk must be registered"
    return quirk


@pytest.fixture
def oid() -> object:
    """OID quirk instance for tests (DEPRECATED - use oid_quirk).

    Returns:
        FlextLdifServersBase: OID server quirk instance

    """
    server = FlextLdifServer()
    quirk = server.quirk("oid")
    assert quirk is not None, "OID quirk must be registered"
    return quirk
