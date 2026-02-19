"""Factory for conftest fixtures using advanced Python patterns.

Provides centralized fixture management with factories, helpers, and constants.
Reduces code duplication and improves maintainability.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import contextlib
import copy
import tempfile
import time
from collections.abc import Callable, Collection, Generator
from pathlib import Path
from typing import ClassVar

import pytest
from flext_core import FlextConstants, FlextLogger, FlextResult, FlextSettings
from flext_ldif import FlextLdif, FlextLdifParser, FlextLdifWriter
from flext_ldif.servers.base import FlextLdifServersBase
from flext_ldif.services.server import FlextLdifServer
from flext_tests import FlextTestsDocker
from ldap3 import ALL, Connection, Server

# TypedDicts (GenericFieldsDict, GenericTestCaseDict, etc.) are available from conftest.py
# Use unified test helpers from tests/__init__.py instead of deprecated helpers
from ..conftest import FlextLdifFixtures
from ..helpers.compat import TestAssertions
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

    _LDIF_TEST_ENTRIES: ClassVar[list[dict[str, dict[str, Collection[str]] | str]]] = [
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

    def docker_control(self) -> FlextTestsDocker:
        """Provide FlextTestsDocker instance for container management.

        Uses the FLEXT workspace root to ensure compose file paths
        are resolved correctly regardless of which project runs the tests.
        """
        workspace_root = Path(__file__).resolve().parents[4]
        return FlextTestsDocker(workspace_root=workspace_root)

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
        FlextSettings.reset_global_instance()

    def reset_flextldif_singleton(self) -> Generator[None]:
        """Reset FlextLdif singleton for test isolation.

        Note: FlextLdif may not have _reset_instance method (Pydantic models).
        Use getattr with noop fallback to handle missing method gracefully.
        """
        # Safe reset - method may not exist
        reset_fn = getattr(FlextLdif, "_reset_instance", lambda: None)
        reset_fn()
        yield
        reset_fn()

    # LDAP container constants (matches docker/docker-compose.openldap.yml)
    LDAP_CONTAINER_NAME = "flext-openldap-test"
    LDAP_COMPOSE_FILE = "docker/docker-compose.openldap.yml"
    LDAP_SERVICE_NAME = "openldap"
    LDAP_PORT = 3390
    LDAP_BASE_DN = "dc=flext,dc=local"
    LDAP_ADMIN_DN = "cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local"
    LDAP_ADMIN_PASSWORD = "REDACTED_LDAP_BIND_PASSWORD123"

    def ldap_container(
        self,
        docker_control: FlextTestsDocker,
        worker_id: str,
    ) -> dict[str, object]:
        """Session-scoped LDAP container configuration.

        Uses direct container configuration for flext-openldap-test.
        This fixture does NOT create or destroy containers - it only verifies
        that an existing container is running. The container should be started
        manually or via a separate script before running integration tests.

        IMPORTANT: This fixture never calls compose_down to avoid killing
        other sessions that may be using the shared LDAP container.
        """
        logger = FlextLogger(__name__)
        container_name = self.LDAP_CONTAINER_NAME

        # Check if container is dirty - warn but don't kill other sessions
        if docker_control.is_container_dirty(container_name):
            logger.warning(
                "Container %s is marked dirty but will NOT be recreated "
                "to avoid killing other sessions. Run 'docker compose down -v && "
                "docker compose up -d' manually if needed.",
                container_name,
            )

        # Try to start existing container (does NOT use compose_down)
        start_result = docker_control.start_existing_container(container_name)
        if start_result.is_failure:
            pytest.skip(
                f"Container {container_name} not found. "
                f"Start it manually with: cd {Path(__file__).resolve().parents[4] / 'docker'} && "
                f"docker compose -f docker-compose.openldap.yml up -d",
            )

        # Wait for container readiness
        port_ready = docker_control.wait_for_port_ready(
            "localhost",
            self.LDAP_PORT,
            max_wait=30,
        )
        if port_ready.is_failure or not port_ready.value:
            pytest.skip(f"Container port {self.LDAP_PORT} not ready within 30s")

        # Verify LDAP is functional
        max_wait = 30.0
        wait_interval = 0.5
        waited = 0.0

        while waited < max_wait:
            try:
                server = Server(f"ldap://localhost:{self.LDAP_PORT}", get_info=ALL)
                conn = Connection(
                    server,
                    user=self.LDAP_ADMIN_DN,
                    password=self.LDAP_ADMIN_PASSWORD,
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
            "server_url": f"ldap://localhost:{self.LDAP_PORT}",
            "host": "localhost",
            "bind_dn": self.LDAP_ADMIN_DN,
            "password": self.LDAP_ADMIN_PASSWORD,
            "base_dn": self.LDAP_BASE_DN,
            "port": self.LDAP_PORT,
            "use_ssl": False,
            "worker_id": worker_id,
        }

    def ldap_container_shared(self, ldap_container: dict[str, object]) -> str:
        """Provide LDAP connection string."""
        default_url = f"ldap://localhost:{self.LDAP_PORT}"
        return str(ldap_container.get("server_url", default_url))

    def ldap_connection(
        self,
        ldap_container: dict[str, object],
    ) -> Generator[Connection]:
        """Create LDAP connection."""
        host = str(ldap_container.get("host", "localhost"))
        port = int(ldap_container.get("port", self.LDAP_PORT))
        bind_dn = str(ldap_container.get("bind_dn", self.LDAP_ADMIN_DN))
        password = str(ldap_container.get("password", self.LDAP_ADMIN_PASSWORD))

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
                    with contextlib.suppress(Exception):
                        ldap_connection.delete(dn)
        except Exception:
            pass

        # Create test OU
        with contextlib.suppress(Exception):
            ldap_connection.add(
                test_ou_dn,
                ["organizationalUnit"],
                {"ou": "FlextLdifTests"},
            )

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
                    with contextlib.suppress(Exception):
                        ldap_connection.delete(dn)
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
        return FlextLdif()

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
        return self._assert_result_success

    def assert_result_failure(
        self,
        flext_matchers: TestAssertions,
    ) -> Callable[[FlextResult[object]], None]:
        """Result failure assertion."""
        return self._assert_result_failure

    @staticmethod
    def _assert_result_success(result: FlextResult[object]) -> None:
        """Assert success."""
        assert result.is_success, f"Expected success: {result.error}"

    @staticmethod
    def _assert_result_failure(result: FlextResult[object]) -> None:
        """Assert failure."""
        assert result.is_failure, f"Expected failure: {result.value}"

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

        # value_transformations contains callables - they are objects in Python
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
        # attribute_filters contains mixed types - all are objects in Python
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
            return dict(kwargs)

    def flext_domains(self) -> LocalTestDomains:
        """Domain-specific test data."""
        return self.LocalTestDomains()

    def flext_matchers(self) -> LocalTestMatchers:
        """Local matchers."""
        return self.LocalTestMatchers()

    def ldif_test_entries(self) -> list[dict[str, dict[str, list[str]] | str]]:
        """LDIF test entries."""
        # Convert Collection[str] to list[str] for type compatibility
        entries = copy.deepcopy(self._LDIF_TEST_ENTRIES)
        return [
            {
                key: (
                    {
                        k: list(v) if isinstance(v, Collection) else v
                        for k, v in value.items()
                    }
                    if isinstance(value, dict)
                    else value
                )
                for key, value in entry.items()
            }
            for entry in entries
        ]

    def ldif_test_content(self, ldif_test_entries: list[dict[str, object]]) -> str:
        """Generate LDIF content."""
        content_lines: list[str] = []

        for entry in ldif_test_entries:
            dn = entry.get("dn", "")
            content_lines.append(f"dn: {dn}")
            attributes = entry.get("attributes")
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
        quirk_result = server.quirk("rfc")
        assert quirk_result.is_success, (
            f"RFC quirk must be registered: {quirk_result.error}"
        )
        quirk = quirk_result.value
        assert quirk is not None, "RFC quirk must be registered"
        return quirk

    def oid_quirk(self, server: FlextLdifServer) -> FlextLdifServersBase:
        """OID quirk."""
        quirk_result = server.quirk("oid")
        assert quirk_result.is_success, (
            f"OID quirk must be registered: {quirk_result.error}"
        )
        quirk = quirk_result.value
        assert quirk is not None, "OID quirk must be registered"
        return quirk

    def oud_quirk(self, server: FlextLdifServer) -> FlextLdifServersBase:
        """OUD quirk."""
        quirk_result = server.quirk("oud")
        assert quirk_result.is_success, (
            f"OUD quirk must be registered: {quirk_result.error}"
        )
        quirk = quirk_result.value
        assert quirk is not None, "OUD quirk must be registered"
        return quirk

    def oid(self) -> object:
        """OID quirk (deprecated)."""
        server = FlextLdifServer()
        quirk = server.quirk("oid")
        assert quirk is not None, "OID quirk must be registered"
        return quirk


__all__ = ["FlextLdifTestConftest", "FlextTestsDocker"]
