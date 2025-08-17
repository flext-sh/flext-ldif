from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

import pytest
from _typeshed import Incomplete
from docker import Container as Container, DockerClient

OPENLDAP_IMAGE: str
OPENLDAP_CONTAINER_NAME: str
OPENLDAP_PORT: int
OPENLDAP_ADMIN_PASSWORD: str
OPENLDAP_DOMAIN: str
OPENLDAP_BASE_DN: Incomplete
OPENLDAP_ADMIN_DN: Incomplete
TEST_ENV_VARS: Incomplete

class OpenLDAPContainerManager:
    client: DockerClient
    container: Container | None
    def __init__(self) -> None: ...
    def start_container(self) -> Container: ...
    def stop_container(self) -> None: ...
    def get_ldif_export(
        self, base_dn: str | None = None, scope: str = "sub"
    ) -> str: ...
    def is_container_running(self) -> bool: ...
    def get_logs(self) -> str: ...

def container_manager() -> OpenLDAPContainerManager: ...
def docker_openldap_container(
    container_manager: OpenLDAPContainerManager,
) -> Container: ...
@pytest.fixture
def ldif_test_config(docker_openldap_container: Container) -> dict[str, object]: ...
@pytest.fixture
def real_ldif_data(
    ldif_test_config: dict[str, object], container_manager: OpenLDAPContainerManager
) -> str: ...
@asynccontextmanager
async def temporary_ldif_data(
    container: Container, ldif_content: str
) -> AsyncGenerator[str]: ...
def check_docker_available() -> bool: ...
def skip_if_no_docker() -> object: ...
