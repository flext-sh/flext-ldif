#!/usr/bin/env python3
"""Basic LDIF Parsing Example.

This example demonstrates fundamental LDIF parsing operations using the FLEXT-LDIF
library with Clean Architecture patterns, FlextResult error handling, and
enterprise-grade configuration management.

The example showcases the most common LDIF processing operations including
file parsing, entry validation, attribute access, and proper error handling
using railway-oriented programming patterns.

Operations Demonstrated:
    - LDIF file parsing with FlextLDIFAPI
    - Configuration setup with FlextLDIFModels.Config
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

from flext_core import FlextLogger

from flext_ldif import FlextLDIFAPI, FlextLDIFModels

logger = FlextLogger(__name__)


def main() -> None:
    """Demonstrate basic LDIF parsing operations."""
    # Create API with configuration
    config = FlextLDIFModels.Config(
        strict_validation=True,
        max_entries=100,
    )
    api = FlextLDIFAPI(config)

    # Parse LDIF from file
    sample_file = Path(__file__).parent / "sample_basic.ldif"

    result = api.parse_file(sample_file)

    # Use railway programming with modern FlextResult pattern
    if not result.is_success:
        return

    entries = result.value
    if not entries:
        return

    # Display basic statistics with railway programming
    def display_stats(stats: dict[str, int]) -> None:
        for _key, _value in stats.items():
            pass

    api.get_entry_statistics(entries).tap(display_stats)

    # Display first entry details
    if entries:
        first_entry = entries[0]

        # Validate domain rules with railway programming
        first_entry.validate_business_rules().tap(
            lambda _: logger.info("   ✅ Domain validation passed")
        ).tap_error(
            lambda error: logger.error(f"   ❌ Domain validation failed: {error}")
        )

    # Demonstrate filtering with railway programming
    output_file = Path(__file__).parent / "output_basic.ldif"

    def process_person_entries(person_entries: list[FlextLDIFModels.Entry]) -> None:
        for entry in person_entries:
            entry.get_single_attribute("cn") or "Unknown"
            entry.get_single_attribute("mail") or "No email"

    api.filter_persons(entries).tap(process_person_entries).flat_map(
        lambda person_entries: api.write_file(person_entries, str(output_file))
    ).tap(
        lambda _: logger.info("✅ Successfully wrote filtered entries to output file")
    ).tap_error(lambda error: logger.error(f"❌ Operation failed: {error}"))


if __name__ == "__main__":
    main()
