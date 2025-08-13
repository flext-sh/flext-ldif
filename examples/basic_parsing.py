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

    if not result.success:
        print(f"❌ Parse failed: {result.error}")
        return

    entries = result.data
    if not entries:
        print("⚠️  No entries found in LDIF file")
        return

    print(f"✅ Successfully parsed {len(entries)} LDIF entries")

    # Display basic statistics
    stats_result = api.get_entry_statistics(entries)
    if stats_result.success and stats_result.data:
        stats = stats_result.data
        print("📊 Entry statistics:")
        for key, value in stats.items():
            print(f"   {key}: {value}")

    # Display first entry details
    if entries:
        first_entry = entries[0]
        print("🔍 First entry details:")
        print(f"   DN: {first_entry.dn.value}")
        print(f"   Attributes: {len(first_entry.attributes.attributes)} total")

        # Validate domain rules
        validation_result = first_entry.validate_semantic_rules()
        if validation_result.success:
            print("   ✅ Domain validation passed")
        else:
            print(f"   ❌ Domain validation failed: {validation_result.error}")

    # Demonstrate filtering
    print("🔎 Filtering person entries...")
    filter_result = api.filter_persons(entries)

    if filter_result.success and filter_result.data is not None:
        person_entries = filter_result.data
        print(f"👥 Found {len(person_entries)} person entries:")

        for i, entry in enumerate(person_entries):
            attributes = entry.attributes.attributes
            cn = attributes.get("cn", ["Unknown"])[0]
            mail = attributes.get("mail", ["No email"])[0]
            print(f"   {i+1}. {cn} ({mail})")

        # Demonstrate writing back to LDIF
        output_file = Path(__file__).parent / "output_basic.ldif"
        print(f"💾 Writing filtered entries to: {output_file}")

        write_result = api.write_file(person_entries, output_file)

        if write_result.success:
            print("✅ Successfully wrote filtered entries to output file")
        else:
            print(f"❌ Write failed: {write_result.error}")
    else:
        print(f"❌ Filter failed: {filter_result.error}")

    print("\n🎉 Example completed successfully!")


if __name__ == "__main__":
    main()
