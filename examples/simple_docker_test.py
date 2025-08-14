#!/usr/bin/env python3
"""Simple example of how to use Docker OpenLDAP container for testing.

This demonstrates how to manually use the Docker container functionality
for testing and development purposes.
"""

from __future__ import annotations

import sys

try:
    # Prefer local fixtures if running from algar-oud-mig context
    from tests.docker_fixtures import (
        OpenLDAPContainerManager,
        check_docker_available,
    )
except Exception:  # pragma: no cover - fallback to shared fixtures path
    try:
        from algar_oud_mig.tests.docker_fixtures import (
            OpenLDAPContainerManager,
            check_docker_available,
        )
    except Exception:
        # Last resort: provide stubs that disable the test gracefully
        def check_docker_available() -> bool:  # type: ignore[no-redef]
            return False

        class OpenLDAPContainerManager:  # type: ignore[no-redef]
            def start_container(self) -> None: ...
            def get_ldif_export(self) -> str: return ""

from flext_ldif import flext_ldif_parse, flext_ldif_validate


def test_with_docker_container() -> bool | None:
    """Example of manual Docker container usage for testing."""
    # Check if Docker is available
    if not check_docker_available():
        return False

    # Create container manager
    manager = OpenLDAPContainerManager()

    try:
        # Start container (this will populate it with test data)
        manager.start_container()

        # Export LDIF data from container
        ldif_data = manager.get_ldif_export()

        if not ldif_data:
            return False

        # Test parsing
        entries = flext_ldif_parse(ldif_data)

        # Constants for testing
        max_entries_to_show = 3

        # Show entry details
        for _i, entry in enumerate(entries[:max_entries_to_show]):
            if entry.has_attribute("cn"):
                pass

        if len(entries) > max_entries_to_show:
            pass

        # Test validation
        flext_ldif_validate(ldif_data)

        # Usar API real para filtrar pessoas e grupos
        api = __import__("flext_ldif").flext_ldif.FlextLdifAPI
        api = api()

        # Filter pessoas usando API real
        person_result = api.filter_persons(entries)
        if person_result.success:
            len(person_result.data or [])

        # Contar entries por objectClass usando API real
        sum(1 for entry in entries if entry.has_object_class("groupOfNames"))
        sum(1 for entry in entries if entry.has_object_class("organizationalUnit"))

        return True

    except (RuntimeError, ValueError, TypeError):
        return False

    finally:
        # Always cleanup
        manager.stop_container()


if __name__ == "__main__":
    success = test_with_docker_container()

    if success:
        pass
    else:
        sys.exit(1)
