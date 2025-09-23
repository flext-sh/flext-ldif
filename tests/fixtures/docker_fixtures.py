"""Docker fixtures for flext-ldif tests.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import shutil
import time
from collections.abc import AsyncGenerator, Generator
from contextlib import asynccontextmanager

import docker
import pytest
from docker import DockerClient
from docker.models.containers import Container

from flext_core import FlextLogger, FlextTypes

logger = FlextLogger(__name__)

# Type alias for exec result to avoid type issues


class ExecResult:
    """Type stub for Docker exec_run result."""

    def __init__(self, exit_code: int, output: tuple[bytes, bytes] | bytes) -> None:
        """Initialize ExecResult with exit code and output."""
        self.exit_code = exit_code
        self.output = output


def _exec_container_command(
    container: Container,
    cmd: list[str] | str,
    *,
    demux: bool = False,
    stdout: bool = True,
    stderr: bool = True,
    stdin: bool = False,
    tty: bool = False,
    privileged: bool = False,
    user: str = "",
    detach: bool = False,
    stream: bool = False,
    socket: bool = False,
    environment: dict[str, str] | None = None,
    workdir: str | None = None,
) -> ExecResult:
    """Execute a command in a Docker container with proper typing."""
    from typing import cast

    exec_result = container.exec_run(
        cmd=cmd,
        demux=demux,
        stdout=stdout,
        stderr=stderr,
        stdin=stdin,
        tty=tty,
        privileged=privileged,
        user=user,
        detach=detach,
        stream=stream,
        socket=socket,
        environment=environment,
        workdir=workdir,
    )

    # Cast to our ExecResult type to satisfy type checker
    return cast("ExecResult", exec_result)


DOCKER_AVAILABLE = True

# OpenLDAP Container Configuration
OPENLDAP_IMAGE = "osixia/openldap:1.5.0"
OPENLDAP_CONTAINER_NAME = "flext-ldif-test-server"
OPENLDAP_PORT = 3390  # Use unique port to avoid conflicts with flext-ldap
OPENLDAP_ADMIN_PASSWORD = "admin123"
OPENLDAP_DOMAIN = "flext-ldif.local"
OPENLDAP_BASE_DN = f"dc={',dc='.join(OPENLDAP_DOMAIN.split('.'))}"
OPENLDAP_ADMIN_DN = f"cn=admin,{OPENLDAP_BASE_DN}"

# Test Environment Variables
TEST_ENV_VARS = {
    "LDIF_TEST_SERVER": f"ldap://localhost:{OPENLDAP_PORT}",
    "LDIF_TEST_BIND_DN": OPENLDAP_ADMIN_DN,
    "LDIF_TEST_PASSWORD": OPENLDAP_ADMIN_PASSWORD,
    "LDIF_TEST_BASE_DN": OPENLDAP_BASE_DN,
}


class OpenLDAPContainerManager:
    """Manages OpenLDAP Docker container for LDIF testing."""

    def __init__(self) -> None:
        """Initialize the container manager."""
        super().__init__()
        self.client: DockerClient | None = None
        if DOCKER_AVAILABLE:
            self.client = docker.from_env()
        self.container: Container | None = None

    def start_container(self) -> Container | None:
        """Start OpenLDAP container with proper configuration for LDIF testing."""
        if not self.client:
            return None

        # Stop and remove existing container if it exists
        self.stop_container()

        # Start new container
        self.container = self.client.containers.run(
            OPENLDAP_IMAGE,
            name=OPENLDAP_CONTAINER_NAME,
            ports={"389/tcp": OPENLDAP_PORT},
            environment={
                "LDAP_ORGANISATION": "FLEXT LDIF Test Org",
                "LDAP_DOMAIN": OPENLDAP_DOMAIN,
                "LDAP_ADMIN_PASSWORD": OPENLDAP_ADMIN_PASSWORD,
                "LDAP_CONFIG_PASSWORD": "config123",
                "LDAP_READONLY_USER": "false",
                "LDAP_RFC2307BIS_SCHEMA": "true",
                "LDAP_BACKEND": "mdb",
                "LDAP_TLS": "false",
                "LDAP_REMOVE_CONFIG_AFTER_SETUP": "true",
                "LDAP_SSL_HELPER_PREFIX": "ldap",
            },
            detach=True,
            remove=True,  # Automatically remove when stopped
        )

        # Wait for container to be ready
        self._wait_for_container_ready()

        # Populate with test data
        self._populate_test_data()

        return self.container

    def stop_container(self) -> None:
        """Stop and remove OpenLDAP container."""
        if not self.client:
            return

        try:
            # Try to get existing container by name
            existing = self.client.containers.get(OPENLDAP_CONTAINER_NAME)
            if existing.status in {"running", "created", "paused"}:
                existing.stop(timeout=5)
            existing.remove(force=True)
        except Exception as e:
            # Container doesn't exist or failed to stop - this is expected
            logger.debug("Container cleanup failed (expected): %s", e)

        self.container = None

    def _wait_for_container_ready(self, timeout: int = 30) -> None:
        """Wait for OpenLDAP container to be ready to accept connections."""
        if not self.container:
            msg = "No container to wait for"
            raise RuntimeError(msg)

        start_time = time.time()
        while time.time() - start_time < timeout:

            def _check_container_status() -> None:
                if self.container is None:
                    container_error = "Container is None"
                    raise RuntimeError(container_error)
                if self.container.status != "running":
                    status_msg: str = (
                        f"Container failed to start: {self.container.status}"
                    )
                    raise RuntimeError(status_msg)

            try:
                # Check if container is still running
                self.container.reload()
                _check_container_status()

                # Try to connect to LDAP port
                exec_result: ExecResult = _exec_container_command(
                    self.container,
                    cmd=[
                        "ldapsearch",
                        "-x",
                        "-H",
                        "ldap://localhost:389",
                        "-D",
                        OPENLDAP_ADMIN_DN,
                        "-w",
                        OPENLDAP_ADMIN_PASSWORD,
                        "-b",
                        OPENLDAP_BASE_DN,
                        "-s",
                        "base",
                        "(objectClass=*)",
                    ],
                    demux=True,
                )

                if exec_result.exit_code == 0:
                    # Success! Container is ready
                    return

            except (RuntimeError, ValueError, TypeError):
                pass  # Continue waiting

            time.sleep(1)

        timeout_msg: str = (
            f"OpenLDAP container failed to become ready within {timeout} seconds"
        )
        raise RuntimeError(timeout_msg)

    def _populate_test_data(self) -> None:
        """Populate OpenLDAP container with test data for LDIF testing."""
        if not self.container:
            return

        # LDIF data to populate
        test_ldif = f"""

# Create organizational units
dn: ou=people,{OPENLDAP_BASE_DN}
objectClass: organizationalUnit
ou: people

dn: ou=groups,{OPENLDAP_BASE_DN}
objectClass: organizationalUnit
ou: groups

# Create test users
dn: uid=john.doe,ou=people,{OPENLDAP_BASE_DN}
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
uid: john.doe
cn: John Doe
sn: Doe
givenName: John
displayName: John Doe
mail: john.doe@flext-ldif.local
telephoneNumber: +1 555 123 4567
employeeNumber: 12345
departmentNumber: IT
title: Software Engineer

dn: uid=jane.smith,ou=people,{OPENLDAP_BASE_DN}
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
uid: jane.smith
cn: Jane Smith
sn: Smith
givenName: Jane
displayName: Jane Smith
mail: jane.smith@flext-ldif.local
telephoneNumber: +1 555 234 5678
employeeNumber: 23456
departmentNumber: HR
title: HR Manager

dn: uid=bob.wilson,ou=people,{OPENLDAP_BASE_DN}
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
uid: bob.wilson
cn: Bob Wilson
sn: Wilson
givenName: Bob
displayName: Bob Wilson
mail: bob.wilson@flext-ldif.local
telephoneNumber: +1 555 345 6789
employeeNumber: 34567
departmentNumber: Engineering
title: Senior Developer

# Create test groups
dn: cn=IT Department,ou=groups,{OPENLDAP_BASE_DN}
objectClass: groupOfNames
objectClass: top
cn: IT Department
description: Information Technology Department
member: uid=john.doe,ou=people,{OPENLDAP_BASE_DN}

dn: cn=HR Department,ou=groups,{OPENLDAP_BASE_DN}
objectClass: groupOfNames
objectClass: top
cn: HR Department
description: Human Resources Department
member: uid=jane.smith,ou=people,{OPENLDAP_BASE_DN}

dn: cn=Engineering,ou=groups,{OPENLDAP_BASE_DN}
objectClass: groupOfNames
objectClass: top
cn: Engineering
description: Engineering Team
member: uid=john.doe,ou=people,{OPENLDAP_BASE_DN}
member: uid=bob.wilson,ou=people,{OPENLDAP_BASE_DN}

dn: cn=All Employees,ou=groups,{OPENLDAP_BASE_DN}
objectClass: groupOfNames
objectClass: top
cn: All Employees
description: All company employees
member: uid=john.doe,ou=people,{OPENLDAP_BASE_DN}
member: uid=jane.smith,ou=people,{OPENLDAP_BASE_DN}
member: uid=bob.wilson,ou=people,{OPENLDAP_BASE_DN}
"""

        try:
            # Create temp file and import LDIF inside the container without hardcoded /tmp
            shell_cmd = (
                "TF=$(mktemp -t flext_ldif.XXXXXX.ldif); "
                "cat > \"$TF\" << 'EOF'\n"
                f"{test_ldif}\n"
                "EOF\n"
                f'/usr/bin/ldapadd -x -H ldap://localhost:389 -D "{OPENLDAP_ADMIN_DN}" '
                f'-w "{OPENLDAP_ADMIN_PASSWORD}" -f "$TF"; '
                'RC=$?; rm -f "$TF"; exit $RC'
            )
            exec_result: ExecResult = _exec_container_command(
                self.container, cmd=["sh", "-c", shell_cmd], demux=True
            )
            if exec_result.exit_code != 0:
                return
        except (RuntimeError, ValueError, TypeError):
            pass

    def get_ldif_export(self, base_dn: str | None = None, scope: str = "sub") -> str:
        """Export LDIF data from the container."""
        if not self.container:
            return ""

        search_base = base_dn or OPENLDAP_BASE_DN

        try:
            exec_result: ExecResult = _exec_container_command(
                self.container,
                cmd=[
                    "ldapsearch",
                    "-x",
                    "-H",
                    "ldap://localhost:389",
                    "-D",
                    OPENLDAP_ADMIN_DN,
                    "-w",
                    OPENLDAP_ADMIN_PASSWORD,
                    "-b",
                    search_base,
                    "-s",
                    scope,
                    "(objectClass=*)",
                    "-LLL",  # LDIF format without comments
                ],
                demux=True,
            )

            if exec_result.exit_code == 0:
                if isinstance(exec_result.output, tuple):
                    stdout, _stderr = exec_result.output
                    return stdout.decode() if stdout else ""
                # Single bytes output
                return exec_result.output.decode() if exec_result.output else ""

        except (RuntimeError, ValueError, TypeError):
            pass

        return ""

    def is_container_running(self) -> bool:
        """Check if the OpenLDAP container is running."""
        if not self.container:
            return False

        try:
            self.container.reload()
        except (RuntimeError, ValueError, TypeError):
            return False
        else:
            return self.container.status == "running"

    def get_logs(self) -> str:
        """Get container logs for debugging."""
        if not self.container:
            return "No container running"

        try:
            return self.container.logs().decode()
        except (RuntimeError, ValueError, TypeError) as e:
            return f"Failed to get logs: {e}"


@pytest.fixture(scope="session")
def container_manager() -> Generator[OpenLDAPContainerManager]:
    """Session-scoped manager to control lifecycle without globals."""
    mgr = OpenLDAPContainerManager()
    try:
        yield mgr
    finally:
        with contextlib.suppress(Exception):
            mgr.stop_container()


@pytest.fixture(scope="session")
def docker_openldap_container(
    container_manager: OpenLDAPContainerManager,
) -> Generator[Container | None]:
    """Session-scoped fixture that provides OpenLDAP Docker container for LDIF testing.

    This fixture starts an OpenLDAP container with test data at the beginning of the test
    session and stops it at the end. The container is shared across all tests.
    """
    # Start container using session manager
    container = container_manager.start_container()

    # Set environment variables for tests
    for key, value in TEST_ENV_VARS.items():
        os.environ[key] = value

    yield container

    # Cleanup
    container_manager.stop_container()

    # Clean up environment variables
    for key in TEST_ENV_VARS:
        os.environ.pop(key, None)


@pytest.fixture
def ldif_test_config(
    docker_openldap_container: Container | None,
) -> FlextTypes.Core.Dict:
    """Provide LDIF test configuration for individual tests."""
    return {
        "server_url": TEST_ENV_VARS["LDIF_TEST_SERVER"],
        "bind_dn": TEST_ENV_VARS["LDIF_TEST_BIND_DN"],
        "password": TEST_ENV_VARS["LDIF_TEST_PASSWORD"],
        "base_dn": TEST_ENV_VARS["LDIF_TEST_BASE_DN"],
        "container": docker_openldap_container,
    }


@pytest.fixture
def real_ldif_data(
    ldif_test_config: FlextTypes.Core.Dict,
    container_manager: OpenLDAPContainerManager,
) -> str:
    """Provide real LDIF data exported from the OpenLDAP container."""
    if container_manager and container_manager.is_container_running():
        # Export LDIF data from container
        ldif_data = container_manager.get_ldif_export()
        if ldif_data:
            return ldif_data

    # Return static test data if container export fails
    return f"""dn: {ldif_test_config["base_dn"]}
objectClass: dcObject
objectClass: organization
dc: flext-ldif
o: FLEXT LDIF Test Org

dn: ou=people,{ldif_test_config["base_dn"]}
objectClass: organizationalUnit
ou: people

dn: uid=john.doe,ou=people,{ldif_test_config["base_dn"]}
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
uid: john.doe
cn: John Doe
sn: Doe
givenName: John
mail: john.doe@flext-ldif.local
"""


@asynccontextmanager
async def temporary_ldif_data(
    container: Container | None,
    ldif_content: str,
) -> AsyncGenerator[str]:
    """Context manager for temporary LDIF data that is auto-cleaned."""
    await asyncio.sleep(0)  # Make it truly async
    if container is None:
        msg = "Container is required but not provided"
        raise RuntimeError(msg)

    # Create temp file path in container safely without hardcoded /tmp
    mktemp_result: ExecResult = _exec_container_command(
        container,
        cmd=["mktemp", "-t", "flext_ldif.XXXXXX.ldif"],
        demux=True,
    )
    if mktemp_result.exit_code != 0 or not mktemp_result.output:
        err_msg = "Failed to create temporary file in container"
        raise RuntimeError(err_msg)

    # Handle both tuple and single bytes output
    if isinstance(mktemp_result.output, tuple):
        if not mktemp_result.output[0]:
            err_msg = "Failed to create temporary file in container"
            raise RuntimeError(err_msg)
        temp_file: str = mktemp_result.output[0].decode().strip()
    else:
        temp_file = mktemp_result.output.decode().strip()

    try:
        # Write LDIF to container
        exec_result: ExecResult = _exec_container_command(
            container,
            cmd=["sh", "-c", f"cat > {temp_file} << 'EOF'\n{ldif_content}\nEOF"],
            demux=True,
        )

        if exec_result.exit_code != 0:
            output_str = (
                exec_result.output.decode()
                if isinstance(exec_result.output, bytes)
                else str(exec_result.output)
            )
            write_msg: str = f"Failed to write temporary LDIF: {output_str}"
            raise RuntimeError(write_msg)

        yield temp_file

    finally:
        # Auto-cleanup
        with contextlib.suppress(RuntimeError, ValueError, TypeError):
            _exec_container_command(container, cmd=["rm", "-f", temp_file])


def check_docker_available() -> bool:
    """Check if Docker is available on the system."""
    return bool(shutil.which("docker"))


def skip_if_no_docker() -> object:
    """Pytest skip decorator if Docker is not available."""
    return pytest.mark.skipif(
        not check_docker_available(),
        reason="Docker is not available - skipping container tests",
    )
