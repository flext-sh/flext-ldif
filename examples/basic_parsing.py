#!/usr/bin/env python3
"""Basic LDIF parsing example.

Demonstrates simple LDIF parsing and entry manipulation using
flext-ldif with Clean Architecture patterns.
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

    if not result.is_success:
        return

    entries = result.data
    if not entries:
        return

    # Display basic statistics
    stats = api.get_entry_statistics(entries)
    for _key, _value in stats.items():
        pass

    # Display first entry details
    if entries:
        first_entry = entries[0]

        # Validate domain rules
        validation_result = first_entry.validate_domain_rules()
        if validation_result.is_success:
            pass

    # Demonstrate filtering
    filter_result = api.filter_persons(entries)

    if filter_result.is_success and filter_result.data is not None:
        person_entries = filter_result.data

        for entry in person_entries:
            entry.attributes.get("cn", ["Unknown"])[0]
            entry.attributes.get("mail", ["No email"])[0]

    # Demonstrate writing back to LDIF
    output_file = Path(__file__).parent / "output_basic.ldif"

    if filter_result.is_success and filter_result.data is not None:
        write_result = api.write(filter_result.data, output_file)

        if write_result.is_success:
            pass


if __name__ == "__main__":
    main()
