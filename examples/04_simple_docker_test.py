#!/usr/bin/env python3
"""Simple example of how to use Docker OpenLDAP container for testing.

This demonstrates how to manually use the Docker container functionality
for testing and development purposes.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

from flext_ldif import FlextLdifAPI

# Add tests directory to path for imports
tests_dir = Path(__file__).parent.parent / "tests"

# Import directly from the docker_fixtures module
docker_fixtures_path = tests_dir / "fixtures" / "docker_fixtures.py"
spec = importlib.util.spec_from_file_location("docker_fixtures", docker_fixtures_path)
if spec is None or spec.loader is None:
    error_msg = "Could not load docker_fixtures module"
    raise ImportError(error_msg)
docker_fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(docker_fixtures)

# Dynamically loaded module attributes are available at runtime


def test_with_docker_container() -> None:
    """Example of manual Docker container usage for testing."""
    # Check if Docker is available
    pytest.fail(
        "Docker is not available"
    ) if not docker_fixtures.check_docker_available() else None

    # Create container manager
    manager = docker_fixtures.OpenLDAPContainerManager()

    try:
        # Start container (this will populate it with test data)
        manager.start_container()

        # Export LDIF data from container
        ldif_data = manager.get_ldif_export()
        pytest.fail(
            "Failed to export LDIF data from container"
        ) if not ldif_data else None

        # Test parsing
        api = FlextLdifAPI()
        parse_result = api.parse(ldif_data)
        pytest.fail(
            f"Failed to parse LDIF data: {parse_result.error}"
        ) if not parse_result.is_success else None
        entries = parse_result.unwrap()

        # Constants for testing
        max_entries_to_show = 3

        # Show entry details
        for _i, entry in enumerate(entries[:max_entries_to_show]):
            if hasattr(entry, "has_attribute") and entry.has_attribute("cn"):
                pass

        if len(entries) > max_entries_to_show:
            pass

        # Test validation - parse first, then validate
        parse_result2 = api.parse(ldif_data)
        pytest.fail(
            f"Failed to parse LDIF data (second time): {parse_result2.error}"
        ) if not parse_result2.is_success else None
        entries2 = parse_result2.unwrap()
        validate_result = api.validate_entries(entries2)
        pytest.fail(
            f"Failed to validate entries: {validate_result.error}"
        ) if not validate_result.is_success else None

        # Filter pessoas usando API real com modern FlextResult pattern
        person_filter_result = api.filter_persons(entries)
        if person_filter_result.is_success:
            person_entries = person_filter_result.unwrap()
            _person_count = len(person_entries)

        # Contar entries por objectClass usando API real
        _group_count = sum(
            1
            for entry in entries
            if hasattr(entry, "is_group_entry") and entry.is_group_entry()
        )
        _ou_count = sum(
            1
            for entry in entries
            if hasattr(entry, "is_organizational_unit")
            and entry.is_organizational_unit()
        )

        # Test passed successfully
        # Test passed successfully

    except (RuntimeError, ValueError, TypeError) as e:
        pytest.fail(f"Test failed with exception: {e}")

    finally:
        # Always cleanup
        manager.stop_container()


if __name__ == "__main__":
    try:
        test_with_docker_container()
        print("✅ Test passed successfully!")
    except Exception as e:
        print(f"❌ Test failed: {e}")
        sys.exit(1)
