"""Test utilities facade with shared helper re-exports."""

from __future__ import annotations

import fcntl
import os
import types
from pathlib import Path
from typing import ClassVar, TextIO

from flext_core import FlextLogger
from flext_ldap import FlextLdapLdap3Wrappers, u as ldap_u
from flext_tests import FlextTestsDocker, FlextTestsUtilities

from flext_ldif import FlextLdifUtilities
from tests.constants import FlextLdifTestConstants


class FlextLdifTestUtilities(FlextTestsUtilities, FlextLdifUtilities):
    """Project test utility namespace extension."""

    class Ldif(FlextLdifUtilities.Ldif):
        """LDIF test utility namespace."""

        class Tests(FlextTestsUtilities.Tests):
            """Test utilities with Matchers, Docker, and LDAP infra support."""

            Docker = FlextTestsDocker

            class FileLock:
                """File-based locking for pytest-xdist parallel test isolation.

                Mirrors u.Ldap.Tests.FileLock from flext-ldap tests.
                """

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
                """Resolve LDAP admin credentials, trying env vars then known defaults.

                Mirrors u.Ldap.Tests.get_admin_credentials from flext-ldap tests.
                """
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
                        server = ldap_u.Ldap.create_bare_server(
                            "localhost",
                            port=d.PORT,
                        )
                        test_conn = ldap_u.Ldap.create_connection(
                            server,
                            user=candidate_dn,
                            password=candidate_password,
                            auto_bind=True,
                            receive_timeout=1,
                        )
                        if test_conn.bound:
                            FlextLdapLdap3Wrappers.unbind(test_conn)
                            cache[0] = (candidate_dn, candidate_password)
                            return (candidate_dn, candidate_password)
                    except (ConnectionError, OSError, ValueError):
                        continue
                cache[0] = (d.ADMIN_DN, d.ADMIN_PASSWORD)
                return (d.ADMIN_DN, d.ADMIN_PASSWORD)


u = FlextLdifTestUtilities

__all__ = ["FlextLdifTestUtilities", "u"]
