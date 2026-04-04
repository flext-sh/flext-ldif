"""Test utilities facade with shared helper re-exports."""

from __future__ import annotations

import fcntl
import os
import types
import uuid
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import ClassVar, TextIO

from flext_tests import FlextTestsDocker, FlextTestsUtilities
from ldap3 import Connection as Ldap3Connection, Server as Ldap3Server
from ldap3.core.exceptions import LDAPException

from flext_core import FlextLogger
from flext_ldif import FlextLdifUtilities
from tests.constants import FlextLdifTestConstants
from tests.models import FlextLdifTestModels
from tests.protocols import FlextLdifTestProtocols


class FlextLdifTestUtilities(FlextTestsUtilities, FlextLdifUtilities):
    """Project test utility namespace extension."""

    class Ldif(FlextLdifUtilities.Ldif):
        """LDIF test utility namespace."""

        class Tests(FlextTestsUtilities.Tests):
            """Test utilities with Matchers, Docker, and LDAP infra support."""

            Docker = FlextTestsDocker

            LdapConnectionLike = FlextLdifTestProtocols.Ldif.Tests.LdapConnectionLike

            class Factory:
                """Automated factory for generating real test data."""

                @staticmethod
                def create_real_entry(
                    dn: str | None = None,
                    attributes: Mapping[str, Sequence[str]] | None = None,
                    server_type: str = "generic",
                ) -> FlextLdifTestModels.Ldif.Entry:
                    """Create a real Entry model with valid data."""
                    if dn is None:
                        dn = (
                            f"cn=test-{uuid.uuid4().hex[:8]},ou=users,dc=example,dc=com"
                        )
                    if attributes is None:
                        attributes = {
                            "cn": [f"test-{uuid.uuid4().hex[:8]}"],
                            "sn": ["Test"],
                            "mail": [f"test-{uuid.uuid4().hex[:8]}@example.com"],
                            "objectClass": [
                                "person",
                                "organizationalPerson",
                                "inetOrgPerson",
                            ],
                        }
                    mutable_attrs: dict[str, list[str]] = {
                        k: list(v) for k, v in attributes.items()
                    }
                    attrs = FlextLdifTestModels.Ldif.Attributes.model_validate({
                        "attributes": mutable_attrs
                    })
                    return FlextLdifTestModels.Ldif.Entry.model_validate({
                        "dn": FlextLdifTestModels.Ldif.DN(value=dn),
                        "attributes": attrs,
                        "server_type": server_type,
                    })

                @staticmethod
                def create_real_ldif_content(
                    entries_count: int = 3,
                    *,
                    include_schema: bool = False,
                ) -> str:
                    """Create real LDIF content for testing."""
                    lines: list[str] = []
                    if include_schema:
                        lines.extend([
                            "dn: cn=schema",
                            "objectClass: top",
                            "objectClass: ldapSubentry",
                            "objectClass: subschema",
                            "",
                            "attributeTypes: ( 2.5.4.3 NAME 'cn' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
                            "",
                        ])
                    for i in range(entries_count):
                        entry_id = uuid.uuid4().hex[:8]
                        lines.extend([
                            f"dn: cn=user-{entry_id},ou=users,dc=example,dc=com",
                            "objectClass: person",
                            "objectClass: organizationalPerson",
                            "objectClass: inetOrgPerson",
                            f"cn: User {entry_id}",
                            f"sn: Test{i}",
                            f"mail: user{entry_id}@example.com",
                            "",
                        ])
                    return "\n".join(lines)

                @staticmethod
                def parametrize_real_data() -> Sequence[
                    FlextLdifTestModels.Ldif.Tests.LdifTestData
                ]:
                    """Generate parametrized test data for comprehensive coverage."""
                    return [
                        FlextLdifTestModels.Ldif.Tests.LdifTestData(
                            id=f"entry_{server_type}",
                            server_type=server_type,
                            dn=f"cn=test-{server_type},ou=users,dc=example,dc=com",
                            attributes={
                                "cn": [f"test-{server_type}"],
                                "objectClass": ["person", "organizationalPerson"],
                            },
                        )
                        for server_type in ["generic", "openldap", "ad", "oid", "oud"]
                    ]

            @staticmethod
            def _unbind_connection(
                connection: FlextLdifTestProtocols.Ldif.Tests.LdapConnectionLike,
            ) -> None:
                """Close a typed LDAP connection."""
                connection.unbind()

            class FileLock:
                """File-based locking for pytest-xdist parallel test isolation."""

                def __init__(self, lock_file: Path) -> None:
                    self.lock_file = lock_file
                    self._fd: int | None = None
                    self._file_obj: TextIO | None = None

                def __enter__(self) -> None:
                    """Acquire exclusive file lock."""
                    self.lock_file.parent.mkdir(parents=True, exist_ok=True)
                    self._file_obj = self.lock_file.open("w")
                    self._fd = self._file_obj.fileno()
                    fcntl.flock(self._fd, fcntl.LOCK_EX)

                def __exit__(
                    self,
                    exc_type: type[BaseException] | None,
                    exc_val: BaseException | None,
                    exc_tb: types.TracebackType | None,
                ) -> None:
                    """Release file lock and clean up."""
                    if self._fd is not None:
                        fcntl.flock(self._fd, fcntl.LOCK_UN)
                    if self._file_obj is not None:
                        self._file_obj.close()
                    self.lock_file.unlink(missing_ok=True)

            _logger: ClassVar[FlextLogger] = FlextLogger(__name__)
            _workspace_root: ClassVar[Path] = Path(__file__).resolve().parent.parent
            _resolved_admin_credentials: ClassVar[list[tuple[str, str] | None]] = [None]

            @staticmethod
            def get_docker_control(worker_id: str = "master") -> FlextTestsDocker:
                """Create tk instance for Docker container management."""
                return FlextTestsDocker(
                    workspace_root=FlextLdifTestUtilities.Ldif.Tests._workspace_root,
                    worker_id=worker_id,
                )

            @staticmethod
            def get_admin_credentials() -> tuple[str, str]:
                """Resolve LDAP admin credentials, trying env vars then known defaults."""
                cache = FlextLdifTestUtilities.Ldif.Tests._resolved_admin_credentials
                if cache[0] is not None:
                    return cache[0]
                d = FlextLdifTestConstants.Ldif.Docker
                env_dn = os.getenv("FLEXT_LDAP_BIND_DN")
                env_password = os.getenv("FLEXT_LDAP_BIND_PASSWORD")
                candidates: list[tuple[str, str]] = []
                if env_dn and env_password:
                    candidates.append((env_dn, env_password))
                candidates.extend([
                    (d.ADMIN_DN, d.ADMIN_PASSWORD),
                    (d.LEGACY_ADMIN_DN, d.LEGACY_ADMIN_PASSWORD),
                ])
                for candidate_dn, candidate_password in candidates:
                    try:
                        server = Ldap3Server(
                            "localhost",
                            port=d.PORT,
                            get_info="NO_INFO",
                        )
                        test_conn: FlextLdifTestUtilities.Ldif.Tests.LdapConnectionLike = Ldap3Connection(
                            server,
                            user=candidate_dn,
                            password=candidate_password,
                            auto_bind=True,
                            receive_timeout=1,
                        )
                        if test_conn.bound:
                            FlextLdifTestUtilities.Ldif.Tests._unbind_connection(
                                test_conn
                            )
                            cache[0] = (candidate_dn, candidate_password)
                            return (candidate_dn, candidate_password)
                    except (ConnectionError, LDAPException, OSError, ValueError):
                        continue
                cache[0] = (d.ADMIN_DN, d.ADMIN_PASSWORD)
                return (d.ADMIN_DN, d.ADMIN_PASSWORD)


u = FlextLdifTestUtilities

__all__ = ["FlextLdifTestUtilities", "u"]
