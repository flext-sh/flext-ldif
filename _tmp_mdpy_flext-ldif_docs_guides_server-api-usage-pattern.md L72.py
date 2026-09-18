# from flext-ldif/docs/guides/server-api-usage-pattern.md:72
from __future__ import annotations

import pytest
from flext_ldif import FlextLdifServer
from flext_ldif import FlextLdifServersBase


@pytest.fixture
def server() -> FlextLdifServer:
    """Get FlextLdifServer instance for server management."""
    return FlextLdifServer()


@pytest.fixture
def oid_server(server: FlextLdifServer) -> FlextLdifServersBase:
    """Get OID server server via FlextLdifServer API."""
    server = server.server("oid")
    assert server is not None, "OID server must be registered"
    return server


@pytest.fixture
def oud_server(server: FlextLdifServer) -> FlextLdifServersBase:
    """Get OUD server server via FlextLdifServer API."""
    server = server.server("oud")
    assert server is not None, "OUD server must be registered"
    return server


@pytest.fixture
def rfc_server(server: FlextLdifServer) -> FlextLdifServersBase:
    """Get RFC server server via FlextLdifServer API."""
    server = server.server("rfc")
    assert server is not None, "RFC server must be registered"
    return server```
### Uso nas Funções de Teste

