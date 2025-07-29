#!/usr/bin/env python3
"""Simple example of how to use Docker OpenLDAP container for testing.

This demonstrates how to manually use the Docker container functionality
for testing and development purposes.
"""

from docker_fixtures import OpenLDAPContainerManager, check_docker_available
from flext_ldif import parse_ldif, validate_ldif
from flext_ldif.domain.specifications import (


from __future__ import annotations

import sys
from pathlib import Path

# Add src and tests to path for local testing
src_path = Path(__file__).parent.parent / "src"
tests_path = Path(__file__).parent.parent / "tests"
sys.path.insert(0, str(src_path))
sys.path.insert(0, str(tests_path))


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
        entries = parse_ldif(ldif_data)

        # Show entry details
        for _i, entry in enumerate(entries[:3]):
            if entry.has_attribute("cn"):
                pass

        if len(entries) > 3:
            pass

        # Test validation
        validate_ldif(ldif_data)

        # Test domain specifications

            FlextLdifGroupSpecification,
            FlextLdifOrganizationalUnitSpecification,
            FlextLdifPersonSpecification,
        )

        person_spec = FlextLdifPersonSpecification()
        group_spec = FlextLdifGroupSpecification()
        ou_spec = FlextLdifOrganizationalUnitSpecification()

        sum(1 for entry in entries if person_spec.is_satisfied_by(entry))
        sum(1 for entry in entries if group_spec.is_satisfied_by(entry))
        sum(1 for entry in entries if ou_spec.is_satisfied_by(entry))

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
