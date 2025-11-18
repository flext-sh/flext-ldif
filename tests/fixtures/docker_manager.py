"""Docker container manager for idempotent and parallelizable tests.

This module provides fixtures and utilities to manage Docker containers
for integration tests in a way that:
1. Allows parallel test execution without conflicts
2. Ensures idempotency - tests can run multiple times with same results
3. Manages container lifecycle automatically
4. Uses random ports to avoid conflicts
5. Provides proper cleanup

Usage:
    @pytest.mark.docker
    @pytest.mark.integration
    def test_something(ldap_container_dynamic):
        connection_string = ldap_container_dynamic
        # Use connection_string for LDAP operations
"""

from __future__ import annotations

import socket
import time
from typing import TYPE_CHECKING, Final, Self

import docker
import pytest
from docker.errors import DockerException, NotFound
from flext_core import FlextResult

if TYPE_CHECKING:
    from docker.models.containers import Container

# Constants for Docker container management
OPENLDAP_IMAGE: Final[str] = "osixia/openldap:latest"
OPENLDAP_BASE_DN: Final[str] = "dc=flext,dc=local"
OPENLDAP_ADMIN_PASSWORD: Final[str] = "REDACTED_LDAP_BIND_PASSWORD123"
OPENLDAP_CONFIG_PASSWORD: Final[str] = "config123"

# Port range for random port allocation
MIN_PORT: Final[int] = 10000
MAX_PORT: Final[int] = 65000

# Container startup timeout
CONTAINER_START_TIMEOUT: Final[int] = 30  # seconds
CONTAINER_READY_CHECK_INTERVAL: Final[float] = 0.5  # seconds


def find_free_port() -> int:
    """Find a free port on localhost.

    Uses socket binding to find an available port. This is more reliable
    than random selection, but there's still a small race condition window.

    Returns:
        int: Available port number

    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        s.listen(1)
        return s.getsockname()[1]


def wait_for_ldap_ready(
    host: str,
    port: int,
    timeout: int = CONTAINER_START_TIMEOUT,
) -> FlextResult[bool]:
    """Wait for LDAP server to be ready to accept connections.

    Args:
        host: LDAP server hostname
        port: LDAP server port
        timeout: Maximum seconds to wait

    Returns:
        FlextResult[bool]: Success if LDAP is ready within timeout

    """
    start_time = time.time()

    while time.time() - start_time < timeout:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                result = sock.connect_ex((host, port))
                if result == 0:
                    # Port is open, wait a bit more for LDAP to be fully ready
                    time.sleep(2)
                    return FlextResult[bool].ok(True)
        except OSError:
            pass

        time.sleep(CONTAINER_READY_CHECK_INTERVAL)

    return FlextResult[bool].fail(
        f"LDAP server not ready after {timeout}s on {host}:{port}",
    )


class DockerLdapContainer:
    """Manages OpenLDAP Docker container for testing.

    Provides methods to start, stop, and manage an OpenLDAP container
    with automatic cleanup and port management.

    """

    def __init__(self) -> None:
        """Initialize Docker client."""
        try:
            self.client = docker.from_env()
        except DockerException as e:
            msg = f"Failed to connect to Docker daemon: {e}"
            raise RuntimeError(msg) from e

        self.container: Container | None = None
        self.port: int = 0
        self.connection_string: str = ""

    def start(self, port: int | None = None) -> FlextResult[str]:
        """Start OpenLDAP container with specified or random port.

        Args:
            port: Optional port number. If None, uses random free port.

        Returns:
            FlextResult[str]: Connection string if successful

        """
        # Find free port if not specified
        if port is None:
            self.port = find_free_port()
        else:
            self.port = port

        # Generate unique container name to avoid conflicts
        container_name = f"flext-ldap-test-{self.port}"

        # Remove existing container with same name if exists
        try:
            existing = self.client.containers.get(container_name)
            existing.remove(force=True)
        except NotFound:
            pass  # Container doesn't exist, which is fine

        try:
            # Start OpenLDAP container
            self.container = self.client.containers.run(
                OPENLDAP_IMAGE,
                name=container_name,
                detach=True,
                ports={"389/tcp": self.port},
                environment={
                    "LDAP_ORGANISATION": "FLEXT Test",
                    "LDAP_DOMAIN": "internal.invalid",
                    "LDAP_ADMIN_PASSWORD": OPENLDAP_ADMIN_PASSWORD,
                    "LDAP_CONFIG_PASSWORD": OPENLDAP_CONFIG_PASSWORD,
                    "LDAP_READONLY_USER": "false",
                    "LDAP_RFC2307BIS_SCHEMA": "false",
                    "LDAP_BACKEND": "mdb",
                    "LDAP_TLS": "false",
                    "LDAP_REMOVE_CONFIG_AFTER_SETUP": "false",
                },
                remove=False,  # We'll remove manually in cleanup
            )

            # Wait for LDAP to be ready
            ready_result = wait_for_ldap_ready("localhost", self.port)
            if ready_result.is_failure:
                self.stop()
                return FlextResult[str].fail(
                    f"Container started but LDAP not ready: {ready_result.error}",
                )

            self.connection_string = f"ldap://localhost:{self.port}"
            return FlextResult[str].ok(self.connection_string)

        except DockerException as e:
            return FlextResult[str].fail(f"Failed to start container: {e}")

    def stop(self) -> None:
        """Stop and remove the container."""
        if self.container:
            try:
                self.container.stop(timeout=5)
                self.container.remove(force=True)
            except (DockerException, NotFound):
                pass  # Best effort cleanup
            finally:
                self.container = None

    def __enter__(self) -> Self:
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:  # type: ignore[no-untyped-def]
        """Context manager exit with cleanup."""
        self.stop()


@pytest.fixture(scope="session")
def docker_client() -> docker.DockerClient:
    """Provide Docker client for tests.

    Session-scoped fixture to avoid recreating Docker client.

    Returns:
        docker.DockerClient: Connected Docker client

    Raises:
        RuntimeError: If Docker daemon is not available

    """
    try:
        client = docker.from_env()
        # Test connection
        client.ping()
        return client
    except DockerException as e:
        pytest.skip(f"Docker not available: {e}")
        msg = "Docker not available"
        raise RuntimeError(msg) from e


@pytest.fixture
def ldap_container_dynamic(docker_client: docker.DockerClient) -> str:
    """Provide dynamic OpenLDAP container with random port.

    Function-scoped fixture that starts a fresh container for each test,
    ensuring complete isolation and idempotency.

    Args:
        docker_client: Docker client from session fixture

    Yields:
        str: LDAP connection string (e.g., "ldap://localhost:12345")

    """
    manager = DockerLdapContainer()

    try:
        result = manager.start()
        if result.is_failure:
            pytest.skip(f"Failed to start LDAP container: {result.error}")

        yield result.unwrap()
    finally:
        manager.stop()


@pytest.fixture(scope="module")
def ldap_container_shared(docker_client: docker.DockerClient) -> str:
    """Provide shared OpenLDAP container for module tests.

    Module-scoped fixture that reuses same container for all tests in module.
    More efficient but requires tests to be idempotent (clean up after themselves).

    Args:
        docker_client: Docker client from session fixture

    Yields:
        str: LDAP connection string (e.g., "ldap://localhost:12345")

    """
    manager = DockerLdapContainer()

    try:
        result = manager.start()
        if result.is_failure:
            pytest.skip(f"Failed to start LDAP container: {result.error}")

        yield result.unwrap()
    finally:
        manager.stop()


__all__ = [
    "DockerLdapContainer",
    "docker_client",
    "find_free_port",
    "ldap_container_dynamic",
    "ldap_container_shared",
    "wait_for_ldap_ready",
]
