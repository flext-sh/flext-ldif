"""Factory for conftest fixtures using advanced Python patterns.

Provides centralized fixture management with factories, helpers, and constants.
Reduces code duplication and improves maintainability.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import copy
import tempfile
import time
from collections.abc import Callable, Generator
from pathlib import Path
from typing import ClassVar

import pytest
from flext_core import FlextConfig, FlextConstants, FlextLogger, FlextResult
from flext_tests.docker import FlextTestDocker
from ldap3 import ALL, Connection, Server

from flext_ldif import FlextLdif, FlextLdifParser, FlextLdifWriter
from flext_ldif.servers.base import FlextLdifServersBase
from flext_ldif.services.server import FlextLdifServer
from tests.fixtures import FlextLdifFixtures
from tests.helpers.test_assertions import TestAssertions

from .ldif_data import LdifTestData
from .real_services import RealServiceFactory
from .test_files import FileManager
from .validators import TestValidators


class FlextLdifTestConftest:
    """Centralized conftest factory using advanced Python patterns.

    Provides all pytest fixtures with factories, helpers, and constants.
    Reduces conftest.py from 1400+ lines to ~20 lines using DRY principles.
    """

    # Pre-built test data for performance
    _TEST_USERS: ClassVar[list[dict[str, str]]] = [
        {"name": "Test User 1", "email": "user1@example.com"},
        {"name": "Test User 2", "email": "user2@example.com"},
        {"name": "Test User 3", "email": "user3@example.com"},
    ]

    _LDIF_TEST_ENTRIES: ClassVar[list[dict[str, dict[str, list[str]] | str]]] = [
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
        },
    ]

    def docker_control(self) -> FlextTestDocker:
        """Provide FlextTestDocker instance for container management.

        Uses the FLEXT workspace root to ensure compose file paths
        are resolved correctly regardless of which project runs the tests.
        """
        workspace_root = Path("/home/marlonsc/flext")
        return FlextTestDocker(workspace_root=workspace_root)

    def worker_id(self, request: pytest.FixtureRequest) -> str:
        """Get pytest-xdist worker ID for DN namespacing."""
        worker_input = getattr(request.config, "workerinput", {})
        return worker_input.get("workerid", "master")

    def session_id(self) -> str:
        """Generate unique session ID for test isolation."""
        return str(int(time.time() * 1000))

    def unique_dn_suffix(
        self,
        worker_id: str,
        session_id: str,
        request: pytest.FixtureRequest,
    ) -> str:
        """Generate unique DN suffix using factory pattern."""
        test_name = request.node.name if hasattr(request, "node") else "unknown"
        allowed_chars = {"-", "_"}
        test_name_clean = "".join(
            c if c.isalnum() or c in allowed_chars else "-" for c in test_name
        )[:20]
        test_id = int(time.time() * 1000000) % 1000000
        return f"{worker_id}-{session_id}-{test_name_clean}-{test_id}"

    def make_user_dn(
        self,
        unique_dn_suffix: str,
        ldap_container: dict[str, object],
    ) -> Callable[[str], str]:
        """Factory for unique user DNs."""
        base_dn = str(ldap_container.get("base_dn", "dc=flext,dc=local"))

        def _make(uid: str) -> str:
            return f"uid={uid}-{unique_dn_suffix},ou=people,{base_dn}"

        return _make

    def make_group_dn(
        self,
        unique_dn_suffix: str,
        ldap_container: dict[str, object],
    ) -> Callable[[str], str]:
        """Factory for unique group DNs."""
        base_dn = str(ldap_container.get("base_dn", "dc=flext,dc=local"))

        def _make(cn: str) -> str:
            return f"cn={cn}-{unique_dn_suffix},ou=groups,{base_dn}"

        return _make

    def make_test_base_dn(
        self,
        unique_dn_suffix: str,
        ldap_container: dict[str, object],
    ) -> Callable[[str], str]:
        """Factory for unique base DNs."""
        base_dn = str(ldap_container.get("base_dn", "dc=flext,dc=local"))

        def _make(ou: str) -> str:
            return f"ou={ou}-{unique_dn_suffix},{base_dn}"

        return _make

    def make_test_username(self, unique_dn_suffix: str) -> Callable[[str], str]:
        """Factory for unique usernames."""

        def _make(username: str) -> str:
            return f"{username}-{unique_dn_suffix}"

        return _make

    def set_test_environment(self) -> Generator[None]:
        """Set test environment variables."""
        yield
        # Reset global config for test isolation
        FlextConfig.reset_global_instance()

    def reset_flextldif_singleton(self) -> Generator[None]:
        """Reset FlextLdif singleton for test isolation."""
        FlextLdif._reset_instance()
        yield
        FlextLdif._reset_instance()

    def ldap_container(
        self,
        docker_control: FlextTestDocker,
        worker_id: str,
    ) -> dict[str, object]:
        """Session-scoped LDAP container configuration.

        Uses FlextTestDocker.SHARED_CONTAINERS for container config.
        Compose file paths in SHARED_CONTAINERS are relative to the
        FLEXT workspace root (which is set in docker_control).
        """
        logger = FlextLogger(__name__)
        container_name = "flext-openldap-test"
        container_config = FlextTestDocker.SHARED_CONTAINERS.get(container_name)

        if not container_config:
            pytest.skip(f"Container {container_name} not found")

        # Resolve compose file path using docker_control's workspace_root
        compose_file = str(container_config["compose_file"])
        if not compose_file.startswith("/"):
            compose_file = str(docker_control.workspace_root / compose_file)

        is_dirty = docker_control.is_container_dirty(container_name)

        if is_dirty:
            logger.info("Container %s is dirty, recreating", container_name)
            cleanup_result = docker_control.cleanup_dirty_containers()
            if cleanup_result.is_failure:
                pytest.skip(
                    f"Failed to recreate dirty container {container_name}: {cleanup_result.error}",
                )
        else:
            status = docker_control.get_container_status(container_name)
            if not status.is_success or (
                isinstance(status.value, FlextTestDocker.ContainerInfo)
                and status.value.status != FlextTestDocker.ContainerStatus.RUNNING
            ):
                logger.info("Container %s not running, starting...", container_name)
                start_result = docker_control.start_compose_stack(compose_file)
                if start_result.is_failure:
                    pytest.skip(f"Failed to start LDAP container: {start_result.error}")

        # Wait for container readiness
        port_ready = docker_control.wait_for_port_ready("localhost", 3390, max_wait=30)
        if port_ready.is_failure or not port_ready.unwrap():
            pytest.skip("Container port 3390 not ready within 30s")

        # Verify LDAP is functional
        max_wait = 30.0
        wait_interval = 0.5
        waited = 0.0

        while waited < max_wait:
            try:
                server = Server("ldap://localhost:3390", get_info=ALL)
                conn = Connection(
                    server,
                    user="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
                    password="REDACTED_LDAP_BIND_PASSWORD",
                    auto_bind=False,
                )
                if conn.bind():
                    conn.unbind()
                    logger.debug("Container ready after %.1fs", waited)
                    break
                conn.unbind()
            except Exception:
                pass

            time.sleep(wait_interval)
            waited += wait_interval

        if waited >= max_wait:
            pytest.skip("Container did not become ready within 30s")

        return {
            "server_url": "ldap://localhost:3390",
            "host": "localhost",
            "bind_dn": "cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            "password": "REDACTED_LDAP_BIND_PASSWORD",
            "base_dn": "dc=flext,dc=local",
            "port": 3390,
            "use_ssl": False,
            "worker_id": worker_id,
        }

    def ldap_container_shared(self, ldap_container: dict[str, object]) -> str:
        """Provide LDAP connection string."""
        return str(ldap_container["server_url"])

    def ldap_connection(
        self,
        ldap_container: dict[str, object],
    ) -> Generator[Connection]:
        """Create LDAP connection."""
        host = str(ldap_container["host"])
        port = int(ldap_container["port"])
        bind_dn = str(ldap_container["bind_dn"])
        password = str(ldap_container["password"])

        server = Server(f"ldap://{host}:{port}", get_info=ALL)
        conn = Connection(server, user=bind_dn, password=password)

        try:
            if not conn.bind():
                pytest.skip(f"LDAP server not available at {host}:{port}")
        except Exception as e:
            pytest.skip(f"LDAP server not available: {e}")

        yield conn
        conn.unbind()

    def clean_test_ou(
        self,
        ldap_connection: Connection,
        make_test_base_dn: Callable[[str], str],
    ) -> Generator[str]:
        """Create and clean isolated test OU."""
        test_ou_dn = make_test_base_dn("FlextLdifTests")

        # Clean existing entries
        try:
            ldap_connection.search(
                test_ou_dn,
                "(objectClass=*)",
                search_scope="SUBTREE",
            )
            if ldap_connection.entries:
                dns_to_delete = [entry.entry_dn for entry in ldap_connection.entries]
                for dn in reversed(dns_to_delete):
                    try:
                        ldap_connection.delete(dn)
                    except Exception:
                        pass
        except Exception:
            pass

        # Create test OU
        try:
            ldap_connection.add(
                test_ou_dn,
                ["organizationalUnit"],
                {"ou": "FlextLdifTests"},
            )
        except Exception:
            pass

        yield test_ou_dn

        # Cleanup
        try:
            ldap_connection.search(
                test_ou_dn,
                "(objectClass=*)",
                search_scope="SUBTREE",
            )
            if ldap_connection.entries:
                dns_to_delete = [entry.entry_dn for entry in ldap_connection.entries]
                for dn in reversed(dns_to_delete):
                    try:
                        ldap_connection.delete(dn)
                    except Exception:
                        pass
        except Exception:
            pass

    # LDIF processing fixtures
    def ldif_processor_config(self) -> dict[str, object]:
        """LDIF processor configuration."""
        return {
            "encoding": FlextConstants.Mixins.DEFAULT_ENCODING,
            "strict_parsing": True,
            "max_entries": 10000,
            "validate_dn": True,
            "normalize_attributes": True,
        }

    def real_ldif_api(self) -> dict[str, object]:
        """Real LDIF API services."""
        return RealServiceFactory.create_api()

    def strict_ldif_api(self) -> dict[str, object]:
        """Strict LDIF API services."""
        return RealServiceFactory.create_strict_api()

    def lenient_ldif_api(self) -> dict[str, object]:
        """Lenient LDIF API services."""
        return RealServiceFactory.create_lenient_api()

    def ldif_test_data(self) -> LdifTestData:
        """LDIF test data provider."""
        return LdifTestData()

    def test_file_manager(self) -> Generator[FileManager]:
        """Test file manager."""
        with FileManager() as manager:
            yield manager

    def test_validators(self) -> TestValidators:
        """Test validators."""
        return TestValidators()

    def test_ldif_dir(self) -> Generator[Path]:
        """Temporary LDIF directory."""
        with tempfile.TemporaryDirectory() as temp_dir:
            ldif_dir = Path(temp_dir) / "ldif_files"
            ldif_dir.mkdir()
            yield ldif_dir

    def sample_ldif_entries(self, ldif_test_data: LdifTestData) -> str:
        """Sample LDIF entries."""
        return ldif_test_data.basic_entries().content

    def sample_ldif_with_changes(self, ldif_test_data: LdifTestData) -> str:
        """Sample LDIF with changes."""
        return ldif_test_data.with_changes().content

    def sample_ldif_with_binary(self, ldif_test_data: LdifTestData) -> str:
        """Sample LDIF with binary."""
        return ldif_test_data.with_binary_data().content

    def ldif_test_file(self, test_ldif_dir: Path, sample_ldif_entries: str) -> Path:
        """LDIF test file."""
        ldif_file = test_ldif_dir / "test_entries.ldif"
        ldif_file.write_text(sample_ldif_entries, encoding="utf-8")
        return ldif_file

    def ldif_changes_file(
        self,
        test_ldif_dir: Path,
        sample_ldif_with_changes: str,
    ) -> Path:
        """LDIF changes file."""
        ldif_file = test_ldif_dir / "test_changes.ldif"
        ldif_file.write_text(sample_ldif_with_changes, encoding="utf-8")
        return ldif_file

    def ldif_binary_file(
        self,
        test_ldif_dir: Path,
        sample_ldif_with_binary: str,
    ) -> Path:
        """LDIF binary file."""
        ldif_file = test_ldif_dir / "test_binary.ldif"
        ldif_file.write_text(sample_ldif_with_binary, encoding="utf-8")
        return ldif_file

    def quirk_registry(self) -> FlextLdifServer:
        """Quirk registry."""
        return FlextLdifServer()

    def ldif_api(self) -> FlextLdif:
        """FlextLdif API instance."""
        return FlextLdif.get_instance()

    def real_parser_service(self, quirk_registry: FlextLdifServer) -> FlextLdifParser:
        """Real parser service."""
        return RealServiceFactory.create_parser()

    def real_writer_service(self, quirk_registry: FlextLdifServer) -> FlextLdifWriter:
        """Real writer service."""
        return RealServiceFactory.create_writer(quirk_registry=quirk_registry)

    def integration_services(self) -> dict[str, object]:
        """Integration services."""
        return RealServiceFactory.services_for_integration_test()

    def assert_result_success(
        self,
        flext_matchers: TestAssertions,
    ) -> Callable[[FlextResult[object]], None]:
        """Result success assertion."""
        return flext_matchers.assert_result_success

    def assert_result_failure(
        self,
        flext_matchers: TestAssertions,
    ) -> Callable[[FlextResult[object]], None]:
        """Result failure assertion."""
        return flext_matchers.assert_result_failure

    def validate_flext_result_success(
        self,
    ) -> Callable[[FlextResult[object]], dict[str, bool]]:
        """Validate success result."""

        def validator(result: FlextResult[object]) -> dict[str, bool]:
            return {
                "is_success": result.is_success,
                "has_value": result.is_success and result.value is not None,
                "no_error": result.error is None,
                "has_error_code": result.error_code is not None,
                "has_error_data": bool(result.error_data),
            }

        return validator

    def validate_flext_result_failure(
        self,
    ) -> Callable[[FlextResult[object]], dict[str, bool]]:
        """Validate failure result."""

        def validator(result: FlextResult[object]) -> dict[str, bool]:
            return {
                "is_failure": result.is_failure,
                "has_error": result.error is not None,
                "error_not_empty": bool(result.error and result.error.strip()),
                "has_error_code": result.error_code is not None,
                "has_error_data": bool(result.error_data),
            }

        return validator

    def flext_result_composition_helper(
        self,
    ) -> Callable[[list[FlextResult[object]]], dict[str, object]]:
        """Result composition helper."""

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

    # Schema and other fixtures
    def ldap_schema_config(self) -> dict[str, object]:
        """LDAP schema config."""
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

    def transformation_rules(self) -> dict[str, object]:
        """Transformation rules."""

        def _transform_mail(x: str | float | None) -> str:
            return str(x).lower() if x else ""

        def _transform_cn(x: str | float | None) -> str:
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
                "ou_mappings": {"people": "users", "groups": "groups"},
            },
        }

    def ldif_filters(self) -> dict[str, object]:
        """LDIF filters."""
        return {
            "include_object_classes": ["inetOrgPerson", "groupOfNames"],
            "exclude_attributes": ["userPassword", "pwdHistory"],
            "dn_patterns": [".*,ou=people,.*", ".*,ou=groups,.*"],
            "attribute_filters": {
                "mail": r".*@example\.com$",
                "departmentNumber": ["IT", "HR", "Finance"],
            },
        }

    def expected_ldif_stats(self) -> dict[str, object]:
        """Expected LDIF stats."""
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

    def invalid_ldif_data(self) -> str:
        """Invalid LDIF data."""
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

    def large_ldif_config(self) -> dict[str, object]:
        """Large LDIF config."""
        return {
            "batch_size": 1000,
            "memory_limit": "100MB",
            "progress_reporting": True,
            "parallel_processing": True,
            "max_workers": 4,
        }

    # Local test utilities
    class LocalTestMatchers:
        """Local test matchers."""

        @staticmethod
        def assert_result_success(result: FlextResult[object]) -> None:
            """Assert success."""
            assert result.is_success, f"Expected success: {result.error}"

        @staticmethod
        def assert_result_failure(result: FlextResult[object]) -> None:
            """Assert failure."""
            assert result.is_failure, f"Expected failure: {result.value}"

    class LocalTestDomains:
        """Local test domains."""

        def create_configuration(self, **kwargs: object) -> dict[str, object]:
            """Create config."""
            return kwargs

    def flext_domains(self) -> LocalTestDomains:
        """Domain-specific test data."""
        return self.LocalTestDomains()

    def flext_matchers(self) -> LocalTestMatchers:
        """Local matchers."""
        return self.LocalTestMatchers()

    def ldif_test_entries(self) -> list[dict[str, dict[str, list[str]] | str]]:
        """LDIF test entries."""
        return copy.deepcopy(self._LDIF_TEST_ENTRIES)

    def ldif_test_content(self, ldif_test_entries: list[dict[str, object]]) -> str:
        """Generate LDIF content."""
        content_lines: list[str] = []

        for entry in ldif_test_entries:
            content_lines.append(f"dn: {entry['dn']}")
            attributes = entry["attributes"]
            assert isinstance(attributes, dict)

            for attr_key, attr_values in attributes.items():
                attr_name: str = str(attr_key)
                content_lines.extend(
                    f"{attr_name}: {value_item!s}" for value_item in attr_values
                )
            content_lines.append("")

        return "\n".join(content_lines)

    def ldif_error_scenarios(self) -> dict[str, str]:
        """Error scenarios."""
        return {
            "invalid_dn": "dn: invalid-dn-format\nobjectClass: person\n",
            "missing_dn": "objectClass: person\ncn: Test User\n",
            "empty_content": "",
            "malformed_attribute": "dn: cn=test,dc=example,dc=com\ninvalid-attribute-line\n",
            "circular_reference": (
                "dn: cn=group1,dc=example,dc=com\n"
                "member: cn=group2,dc=example,dc=com\n\n"
                "dn: cn=group2,dc=example,dc=com\n"
                "member: cn=group1,dc=example,dc=com\n"
            ),
        }

    def ldif_performance_config(
        self,
        flext_domains: LocalTestDomains,
    ) -> dict[str, object]:
        """Performance config."""
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

    # Pytest markers
    def pytest_configure(self, config: pytest.Config) -> None:
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
        config.addinivalue_line(
            "markers",
            "flext_tests: Tests using FlextTests utilities",
        )

    def pytest_collection_modifyitems(
        self,
        config: pytest.Config,
        items: list[pytest.Item],
    ) -> None:
        """Filter test items."""
        filtered_items = []
        for item in items:
            if hasattr(item, "parent") and item.parent is not None:
                parent = item.parent
                if hasattr(parent, "cls"):
                    test_class = getattr(parent, "cls", None)
                    if test_class and getattr(test_class, "__test__", True) is False:
                        continue
            filtered_items.append(item)

        items[:] = filtered_items

    # Test constants
    class LDIFTestConstants:
        """Test constants."""

        SAMPLE_LDIF_FILE = "tests/fixtures/sample_basic.ldif"
        COMPLEX_LDIF_FILE = "tests/fixtures/sample_complex.ldif"
        INVALID_LDIF_FILE = "tests/fixtures/sample_invalid.ldif"

        SAMPLE_DN = "cn=test,ou=users,dc=example,dc=com"
        SAMPLE_ATTRIBUTE = "cn"
        SAMPLE_VALUE = "test user"

        MAX_TEST_ENTRIES = 100
        MAX_TEST_ATTRIBUTES = 50
        MAX_TEST_VALUES = 20

        DEFAULT_TIMEOUT_MS = 5000
        MAX_PARSE_TIME_PER_ENTRY = 1000

    def ldif_test_constants(self) -> LDIFTestConstants:
        """Test constants."""
        return self.LDIFTestConstants()

    # Server fixtures
    def fixtures_loader(self) -> FlextLdifFixtures.Loader:
        """Generic fixture loader."""
        return FlextLdifFixtures.Loader()

    def oid_fixtures(self) -> FlextLdifFixtures.OID:
        """OID fixtures."""
        return FlextLdifFixtures.OID()

    def oid_schema(self, oid_fixtures: FlextLdifFixtures.OID) -> str:
        """OID schema."""
        return oid_fixtures.schema()

    def oid_acl(self, oid_fixtures: FlextLdifFixtures.OID) -> str:
        """OID ACL."""
        return oid_fixtures.acl()

    def oid_entries(self, oid_fixtures: FlextLdifFixtures.OID) -> str:
        """OID entries."""
        return oid_fixtures.entries()

    def oid_integration(self, oid_fixtures: FlextLdifFixtures.OID) -> str:
        """OID integration."""
        return oid_fixtures.integration()

    def oud_fixtures(self) -> FlextLdifFixtures.OUD:
        """OUD fixtures."""
        return FlextLdifFixtures.OUD()

    def openldap_fixtures(self) -> FlextLdifFixtures.OpenLDAP:
        """OpenLDAP fixtures."""
        return FlextLdifFixtures.OpenLDAP()

    def server(self) -> FlextLdifServer:
        """Server instance."""
        return FlextLdifServer()

    def rfc_quirk(self, server: FlextLdifServer) -> FlextLdifServersBase:
        """RFC quirk."""
        quirk = server.quirk("rfc")
        assert quirk is not None, "RFC quirk must be registered"
        return quirk

    def oid_quirk(self, server: FlextLdifServer) -> FlextLdifServersBase:
        """OID quirk."""
        quirk = server.quirk("oid")
        assert quirk is not None, "OID quirk must be registered"
        return quirk

    def oud_quirk(self, server: FlextLdifServer) -> FlextLdifServersBase:
        """OUD quirk."""
        quirk = server.quirk("oud")
        assert quirk is not None, "OUD quirk must be registered"
        return quirk

    def oid(self) -> object:
        """OID quirk (deprecated)."""
        server = FlextLdifServer()
        quirk = server.quirk("oid")
        assert quirk is not None, "OID quirk must be registered"
        return quirk
