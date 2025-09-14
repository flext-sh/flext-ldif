#!/usr/bin/env python3
"""Simple example of how to use Docker OpenLDAP container for testing.

This demonstrates how to manually use the Docker container functionality
for testing and development purposes.
"""

from __future__ import annotations

import sys

from flext_core import FlextResult
from tests.fixtures.docker_fixtures import (
    OpenLDAPContainerManager,
    check_docker_available,
)

from flext_ldif import FlextLDIFAPI, FlextLDIFFormatHandler


def test_with_docker_container() -> bool | None:
    """Example of manual Docker container usage for testing.

    Returns:
      bool | None: Description.

    """  # Check if Docker is available
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
        handler = FlextLDIFFormatHandler()
        parse_result = handler.parse_ldif(ldif_data)
        entries = FlextResult.unwrap_or_raise(parse_result)

        # Constants for testing
        max_entries_to_show = 3

        # Show entry details
        for _i, entry in enumerate(entries[:max_entries_to_show]):
            if entry.has_attribute("cn"):
                pass

        if len(entries) > max_entries_to_show:
            pass

        # Test validation - parse first, then validate
        parse_result2 = handler.parse_ldif(ldif_data)
        entries2 = FlextResult.unwrap_or_raise(parse_result2)
        api = FlextLDIFAPI()
        validate_result = api.validate_entries(entries2)
        FlextResult.unwrap_or_raise(validate_result)

        # Usar API real para filtrar pessoas e grupos
        api = __import__("flext_ldif").flext_ldif.FlextLDIFAPI
        api = api()

        # Filter pessoas usando API real com modern FlextResult pattern
        person_filter_result = api.filter_persons(entries)
        person_entries = person_filter_result.unwrap_or([])
        len(person_entries)

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
