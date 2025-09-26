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

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path

from flext_core import FlextLogger
from flext_ldif import FlextLdifAPI, FlextLdifConfig, FlextLdifModels, FlextLdifTypes

logger = FlextLogger(__name__)


def main() -> None:
    """Demonstrate basic LDIF parsing operations."""
    # Create API with configuration - fix chunk size validation issue
    config = FlextLdifConfig(
        ldif_strict_validation=True,
        ldif_max_entries=100,
        ldif_chunk_size=50,  # Must be less than ldif_max_entries
    )
    api = FlextLdifAPI(config)

    # Parse LDIF from file
    sample_file = Path(__file__).parent / "sample_basic.ldif"

    result = api.parse_ldif_file(sample_file)

    # Use railway programming with modern FlextResult pattern
    if not result.is_success:
        return

    entries = result.value
    if not entries:
        return

    # Display basic statistics with railway programming
    def display_stats(stats: FlextLdifTypes.LdifStatistics) -> None:
        for _key, _value in stats.items():
            pass

    api.entry_statistics(entries).map(display_stats)

    # Display first entry details
    if entries:
        first_entry = entries[0]

        # Validate domain rules with railway programming
        def log_success(*, success: bool) -> None:
            logger.info(f"   ✅ Domain validation passed (success: {success})")

        def log_error(error: str) -> None:
            logger.error(f"   ❌ Domain validation failed: {error}")

        first_entry.validate_business_rules().tap(
            lambda x: log_success(success=x)
        ).tap_error(log_error)

    # Demonstrate filtering with railway programming
    output_file = Path(__file__).parent / "output_basic.ldif"

    def process_person_entries(person_entries: list[FlextLdifModels.Entry]) -> None:
        for entry in person_entries:
            cn = entry.get_single_value("cn") or "Unknown"
            mail = entry.get_single_value("mail") or "No email"
            print(f"Person: {cn}, Email: {mail}")

    def log_write_success(_: object) -> None:
        logger.info("✅ Successfully wrote filtered entries to output file")

    def log_write_error(error: str) -> None:
        logger.error(f"❌ Operation failed: {error}")

    api.filter_persons(entries).tap(process_person_entries).flat_map(
        lambda person_entries: api.write_file(person_entries, str(output_file)),
    ).tap(log_write_success).tap_error(log_write_error)


if __name__ == "__main__":
    main()
