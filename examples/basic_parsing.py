#!/usr/bin/env python3
"""Basic LDIF Parsing Example.

This example demonstrates fundamental LDIF parsing operations using the FLEXT-LDIF
library with Clean Architecture patterns, FlextResult error handling, and
enterprise-grade configuration management.

The example showcases the most common LDIF processing operations including
file parsing, entry validation, attribute access, and proper error handling
using railway-oriented programming patterns.

Operations Demonstrated:
    - LDIF file parsing with FlextLdifAPI
    - Configuration setup with FlextLdifConfig
    - FlextResult pattern for error handling
    - Domain entity operations and attribute access
    - Entry validation and business rule enforcement

Example Output:
    Successfully parsed 3 LDIF entries:
    ✓ cn=John Doe,ou=people,dc=example,dc=com (person, inetOrgPerson)
    ✓ cn=Jane Smith,ou=people,dc=example,dc=com (person, inetOrgPerson)
    ✓ ou=people,dc=example,dc=com (organizationalUnit)

Usage:
    python examples/basic_parsing.py

Requirements:
    - sample_basic.ldif file in examples directory
    - FLEXT-LDIF installed and configured

Author: FLEXT Development Team
Version: 0.9.0
License: MIT
"""

from __future__ import annotations

from pathlib import Path

from flext_ldif import FlextLdifAPI, FlextLdifConfig


def main() -> None:
    """Demonstrate basic LDIF parsing operations."""
    # Create API with configuration
    config = FlextLdifConfig(
        strict_validation=True,
        max_entries=100,
    )
    api = FlextLdifAPI(config)

    # Parse LDIF from file
    sample_file = Path(__file__).parent / "sample_basic.ldif"

    result = api.parse_file(sample_file)

    if not result.success:
        return

    entries = result.data
    if not entries:
        return

    # Display basic statistics
    stats_result = api.get_entry_statistics(entries)
    if stats_result.success:
        stats = stats_result.data
        for _key, _value in stats.items():
            pass

    # Display first entry details
    if entries:
        first_entry = entries[0]

        # Validate domain rules
        validation_result = first_entry.validate_semantic_rules()
        if validation_result.success:
            pass

    # Demonstrate filtering
    filter_result = api.filter_persons(entries)

    if filter_result.success and filter_result.data is not None:
        person_entries = filter_result.data

        for entry in person_entries:
            attributes = entry.attributes.attributes
            attributes.get("cn", ["Unknown"])[0]
            attributes.get("mail", ["No email"])[0]

    # Demonstrate writing back to LDIF
    output_file = Path(__file__).parent / "output_basic.ldif"

    if filter_result.success and filter_result.data is not None:
        write_result = api.write_file(filter_result.data, output_file)

        if write_result.success:
            pass


if __name__ == "__main__":
    main()
