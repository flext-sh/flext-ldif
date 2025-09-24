"""Docker fixtures for flext-ldif tests - Now using shared container.

This module now imports and uses the shared LDAP container fixtures
from the main docker directory to ensure consistency across all FLEXT projects.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path

# Add docker directory to path to import shared fixtures
docker_dir = Path(__file__).parent.parent.parent.parent / "docker"

# Import shared fixtures
try:
    from .shared_ldap_fixtures import (
        FlextSharedLDAPContainerManager,
        check_docker_available,
        shared_ldap_config,
        shared_ldap_container,
        shared_ldap_container_manager,
        shared_ldif_data,
        skip_if_no_docker,
        temporary_shared_ldif_data,
    )
except ImportError:
    # Fallback for when shared fixtures are not available
    FlextSharedLDAPContainerManager = None
    check_docker_available = None
    shared_ldap_config = None
    shared_ldap_container = None
    shared_ldap_container_manager = None
    shared_ldif_data = None
    skip_if_no_docker = None
    temporary_shared_ldif_data = None

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
