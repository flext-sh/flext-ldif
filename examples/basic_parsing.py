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
    print("🚀 FLEXT-LDIF Basic Parsing Example")
    print("=" * 40)

    # Create API with configuration
    config = FlextLdifConfig(
        strict_validation=True,
        max_entries=100,
    )
    api = FlextLdifAPI(config)
    print(f"✅ FlextLdifAPI initialized with max_entries={config.max_entries}")

    # Parse LDIF from file
    sample_file = Path(__file__).parent / "sample_basic.ldif"
    print(f"📁 Parsing file: {sample_file}")

    result = api.parse_file(sample_file)

    # Use railway programming with chaining
    entries = result.tap_error(
        lambda error: print(f"❌ Parse failed: {error}")
    ).unwrap_or([])

    if not entries:
        print("⚠️  No entries found in LDIF file")
        return

    print(f"✅ Successfully parsed {len(entries)} LDIF entries")

    # Display basic statistics with railway programming
    api.get_entry_statistics(entries).tap(
        lambda stats: [
            print("📊 Entry statistics:"),
            [print(f"   {key}: {value}") for key, value in stats.items()],
        ]
    )

    # Display first entry details
    if entries:
        first_entry = entries[0]
        print("🔍 First entry details:")
        print(f"   DN: {first_entry.dn.value}")
        print(f"   Attributes: {len(first_entry.attributes.attributes)} total")

        # Validate domain rules with railway programming
        first_entry.validate_semantic_rules().tap(
            lambda _: print("   ✅ Domain validation passed")
        ).tap_error(lambda error: print(f"   ❌ Domain validation failed: {error}"))

    # Demonstrate filtering with railway programming
    print("🔎 Filtering person entries...")
    output_file = Path(__file__).parent / "output_basic.ldif"

    api.filter_persons(entries).tap(
        lambda person_entries: [
            print(f"👥 Found {len(person_entries)} person entries:"),
            [
                print(
                    f"   {i + 1}. {entry.attributes.attributes.get('cn', ['Unknown'])[0]} "
                    f"({entry.attributes.attributes.get('mail', ['No email'])[0]})"
                )
                for i, entry in enumerate(person_entries)
            ],
            print(f"💾 Writing filtered entries to: {output_file}"),
        ]
    ).flat_map(lambda person_entries: api.write_file(person_entries, output_file)).tap(
        lambda _: print("✅ Successfully wrote filtered entries to output file")
    ).tap_error(lambda error: print(f"❌ Operation failed: {error}"))

    print("\n🎉 Example completed successfully!")


if __name__ == "__main__":
    main()
