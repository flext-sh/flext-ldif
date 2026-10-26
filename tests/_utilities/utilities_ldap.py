"""LDAP client connectivity and shared-container test helpers.

Focused utility module split out of ``tests.utilities``; the public surface is
re-exported through ``tests.utilities`` (see ``TestsFlextLdifLdapClientMixin``).

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import os
from importlib.util import find_spec
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar, Final

import pytest
from flext_tests.docker import FlextTestsDocker

from tests import c, p, tk

if TYPE_CHECKING:
    from types import ModuleType


class TestsFlextLdifLdapClientMixin:
    """Helpers that drive the optional real-directory LDAP client.

    The real-directory tests drive a live LDAP server through the FLEXT LDAP
    client, but that client is built ON TOP of flext-ldif: declaring it here
    would invert the layer and close a dependency cycle, so it can never belong
    to this project's dependency set. Availability is probed through
    ``importlib.util.find_spec`` and every test that needs the client skips
    explicitly through the declared pytest surface when it is absent — which
    is the case for any standalone checkout, CI included.
    """

    _LDAP_CLIENT_MODULE: Final[str] = "flext_ldap"

    _LDAP_ENTRY_ADAPTER_MODULE: Final[str] = "flext_ldap.adapters.entry"

    _LDAP_CLIENT_MISSING_REASON: Final[str] = (
        f"LDAP client {_LDAP_CLIENT_MODULE!r} is unavailable: it depends on"
        " flext-ldif and cannot be a dependency of it, so real-directory tests"
        " only run in a workspace checkout that provides the client."
    )

    _resolved_admin_credentials: ClassVar[list[tuple[str, str] | None]] = [None]

    @classmethod
    def ldap_client_available(cls) -> bool:
        """Whether the optional LDAP client is importable.

        Returns:
            The resulting ``bool``.

        """
        return find_spec(cls._LDAP_CLIENT_MODULE) is not None

    @classmethod
    def require_ldap_client(cls) -> ModuleType:
        """Return the LDAP client module, skipping when it is unavailable."""
        module: ModuleType = pytest.importorskip(
            cls._LDAP_CLIENT_MODULE,
            reason=cls._LDAP_CLIENT_MISSING_REASON,
        )
        return module

    @classmethod
    def create_ldap_entry_adapter(cls) -> p.Ldap3EntryAdapter:
        """Return an ldap3-to-LDIF entry adapter, skipping when unavailable."""
        module: ModuleType = pytest.importorskip(
            cls._LDAP_ENTRY_ADAPTER_MODULE,
            reason=cls._LDAP_CLIENT_MISSING_REASON,
        )
        adapter: p.Ldap3EntryAdapter = module.FlextLdapEntryAdapter()
        return adapter

    @classmethod
    def ldap_connectivity_errors(cls) -> tuple[type[BaseException], ...]:
        """Exception types signalling that the LDAP server is unreachable.

        Returns:
            The resulting ``tuple[type[BaseException], ...]``.

        """
        transport: tuple[type[BaseException], ...] = (
            ConnectionError,
            TimeoutError,
            OSError,
        )
        if find_spec(cls._LDAP_CLIENT_MODULE) is None:
            return transport
        client: ModuleType = pytest.importorskip(
            cls._LDAP_CLIENT_MODULE,
            reason=cls._LDAP_CLIENT_MISSING_REASON,
        )
        protocol_error: type[BaseException] = client.t.Ldap.LDAPException
        return (protocol_error, *transport)

    @classmethod
    def create_server_from_url(
        cls,
        server_url: str,
        *,
        get_info: c.Ldap3GetInfo = c.Ldap3GetInfo.ALL,
    ) -> p.Ldap3Server:
        """Create an LDAP server from a URL for test connectivity checks.

        Returns:
            The resulting ``p.Ldap3Server``.

        """
        client = cls.require_ldap_client()
        server: p.Ldap3Server = client.FlextLdapUtilities.Ldap.create_server_from_url(
            server_url,
            get_info=get_info,
        )
        return server

    @classmethod
    def create_bare_server(
        cls,
        host: str,
        *,
        port: int = c.Tests.DOCKER_PORT,
        get_info: c.Ldap3GetInfo = c.Ldap3GetInfo.NO_INFO,
    ) -> p.Ldap3Server:
        """Create a minimal LDAP server for connectivity checks.

        Returns:
            The resulting ``p.Ldap3Server``.

        """
        return cls.create_server_from_url(
            f"ldap://{host}:{port}",
            get_info=get_info,
        )

    @staticmethod
    def create_connection(
        server: p.Ldap3Server,
        user: str,
        password: str,
        *,
        auto_bind: bool = True,
        receive_timeout: int | None = None,
    ) -> p.Ldap3Connection:
        """Create an LDAP connection for test workflows.

        Returns:
            The resulting ``p.Ldap3Connection``.

        """
        client = TestsFlextLdifLdapClientMixin.require_ldap_client()
        create = client.FlextLdapUtilities.Ldap.create_connection
        if receive_timeout is None:
            connection: p.Ldap3Connection = create(
                server,
                user=user,
                password=password,
                auto_bind=auto_bind,
            )
            return connection
        timed_connection: p.Ldap3Connection = create(
            server,
            user=user,
            password=password,
            auto_bind=auto_bind,
            receive_timeout=receive_timeout,
        )
        return timed_connection

    @classmethod
    def _probe_admin_credentials(
        cls,
        candidate_dn: str,
        candidate_password: str,
    ) -> tuple[str, str] | None:
        """Return candidate credentials when LDAP bind succeeds."""
        server = cls.create_bare_server(
            "localhost",
            port=c.Tests.DOCKER_PORT,
            get_info=c.Ldap3GetInfo.NO_INFO,
        )
        connection = cls.create_connection(
            server,
            user=candidate_dn,
            password=candidate_password,
            auto_bind=True,
            receive_timeout=1,
        )
        bound: bool = connection.bound
        if bound:
            connection.unbind()
        if bound:
            return (candidate_dn, candidate_password)
        return None

    @classmethod
    def get_admin_credentials(cls) -> tuple[str, str]:
        """Resolve LDAP admin credentials, preferring a working pair.

        Returns:
            The resulting ``tuple[str, str]``.

        """
        cache = cls._resolved_admin_credentials
        cached = cache[0]
        if cached is not None:
            return cached
        env_dn = os.getenv("FLEXT_LDAP_BIND_DN")
        env_password = os.getenv("FLEXT_LDAP_BIND_PASSWORD")
        candidates: list[tuple[str, str]] = [
            *([(env_dn, env_password)] if env_dn and env_password else []),
            (c.Tests.DOCKER_ADMIN_DN, c.Tests.DOCKER_ADMIN_CREDENTIAL),
            (
                c.Tests.DOCKER_LEGACY_ADMIN_DN,
                c.Tests.DOCKER_LEGACY_ADMIN_CREDENTIAL,
            ),
        ]
        for candidate_dn, candidate_password in candidates:
            credentials = cls._probe_admin_credentials(
                candidate_dn,
                candidate_password,
            )
            if credentials is None:
                continue
            cache[0] = credentials
            return credentials
        default_credentials = (
            c.Tests.DOCKER_ADMIN_DN,
            c.Tests.DOCKER_ADMIN_CREDENTIAL,
        )
        cache[0] = default_credentials
        return default_credentials

    @staticmethod
    def get_docker_control() -> FlextTestsDocker:
        """Create Docker test infrastructure controller.

        Returns:
            The resulting ``tk``.

        """
        compose_file = Path(
            str(
                c.Tests.SHARED_CONTAINERS[c.Tests.DOCKER_CONTAINER_NAME][
                    "compose_file"
                ],
            ),
        )
        repository_root = next(
            (
                candidate
                for candidate in (
                    c.Tests.PROJECT_ROOT,
                    *c.Tests.PROJECT_ROOT.parents,
                )
                if (candidate / compose_file).is_file()
            ),
            c.Tests.PROJECT_ROOT,
        )
        return tk.shared(
            c.Tests.DOCKER_CONTAINER_NAME,
            repository_root=repository_root,
        )


__all__: list[str] = ["TestsFlextLdifLdapClientMixin"]
