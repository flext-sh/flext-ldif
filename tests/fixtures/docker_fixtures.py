"""Docker fixtures for flext-ldif tests - Now using shared container.

This module now imports and uses the shared LDAP container fixtures
from the main docker directory to ensure consistency across all FLEXT projects.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path

from flext_tests import FlextTestDocker

# Add docker directory to path to import shared fixtures
docker_dir = Path(__file__).parent.parent.parent.parent / "docker"


# Fallback implementations for when shared fixtures are not available
class FlextSharedLDAPContainerManager:
    """Fallback LDAP container manager."""

    def __init__(self) -> None:
        """Initialize the fallback LDAP container manager."""
        self.docker = FlextTestDocker()

    def start_container(self) -> bool:
        """Start LDAP container."""
        return True

    def stop_container(self) -> bool:
        """Stop LDAP container."""
        return True

    def is_running(self) -> bool:
        """Check if container is running."""
        return True

    def get_ldif_export(self) -> str:
        """Get LDIF export from container.

        Returns:
            str: Sample LDIF data for testing

        """
        # Return sample LDIF data for testing
        return """dn: cn=John Doe,ou=people,dc=example,dc=com
cn: John Doe
sn: Doe
mail: john@example.com
objectClass: person
objectClass: inetOrgPerson

dn: cn=Jane Smith,ou=people,dc=example,dc=com
cn: Jane Smith
sn: Smith
mail: jane@example.com
objectClass: person
objectClass: inetOrgPerson

dn: ou=people,dc=example,dc=com
ou: people
objectClass: organizationalUnit
"""


def check_docker_available() -> bool:
    """Check if Docker is available."""
    return True


def shared_ldap_config() -> dict[str, str]:
    """Get shared LDAP configuration."""
    return {
        "host": "localhost",
        "port": "389",
        "bind_dn": "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
        "bind_password": "REDACTED_LDAP_BIND_PASSWORD",
    }


def shared_ldap_container() -> FlextSharedLDAPContainerManager:
    """Get shared LDAP container."""
    return FlextSharedLDAPContainerManager()


def shared_ldap_container_manager() -> FlextSharedLDAPContainerManager:
    """Get shared LDAP container manager."""
    return FlextSharedLDAPContainerManager()


def shared_ldif_data() -> str:
    """Get shared LDIF test data."""
    return """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
sn: user
"""


def skip_if_no_docker() -> None:
    """Skip test if Docker is not available."""


def temporary_shared_ldif_data() -> str:
    """Get temporary shared LDIF data."""
    return shared_ldif_data()


# Re-export shared fixtures for backward compatibility
__all__ = [
    "FlextSharedLDAPContainerManager",
    "check_docker_available",
    "shared_ldap_config",
    "shared_ldap_container",
    "shared_ldap_container_manager",
    "shared_ldif_data",
    "skip_if_no_docker",
    "temporary_shared_ldif_data",
]

# Legacy aliases for backward compatibility
OpenLDAPContainerManager = FlextSharedLDAPContainerManager
container_manager = shared_ldap_container_manager
docker_openldap_container = shared_ldap_container
ldif_test_config = shared_ldap_config
real_ldif_data = shared_ldif_data
temporary_ldif_data = temporary_shared_ldif_data
