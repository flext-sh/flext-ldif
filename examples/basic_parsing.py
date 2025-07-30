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
    print("🚀 FLEXT LDIF Basic Parsing Example")
    print("=" * 50)

    # Create API with configuration
    config = FlextLdifConfig(
        strict_validation=True,
        max_entries=100,
    )
    api = FlextLdifAPI(config)

    # Parse LDIF from file
    sample_file = Path(__file__).parent / "sample_basic.ldif"
    print(f"📖 Parsing LDIF file: {sample_file}")
    
    result = api.parse_file(sample_file)
    
    if not result.is_success:
        print(f"❌ Parsing failed: {result.error}")
        return
    
    entries = result.data
    if not entries:
        print("❌ No entries found")
        return
        
    print(f"✅ Successfully parsed {len(entries)} entries")
    
    # Display basic statistics
    stats = api.get_entry_statistics(entries)
    print("\n📊 Entry Statistics:")
    for key, value in stats.items():
        print(f"  {key}: {value}")
    
    # Display first entry details
    if entries:
        first_entry = entries[0]
        print(f"\n👤 First Entry Details:")
        print(f"  DN: {first_entry.dn}")
        print(f"  Attributes: {len(first_entry.attributes)}")
        
        # Validate domain rules
        validation_result = first_entry.validate_domain_rules()
        if validation_result.is_success:
            print("  ✅ Domain validation: PASSED")
        else:
            print(f"  ❌ Domain validation: {validation_result.error}")
    
    # Demonstrate filtering
    print("\n🔍 Filtering person entries...")
    filter_result = api.filter_persons(entries)
    
    if filter_result.is_success and filter_result.data is not None:
        person_entries = filter_result.data
        print(f"✅ Found {len(person_entries)} person entries")
        
        for entry in person_entries:
            cn = entry.attributes.get("cn", ["Unknown"])[0]
            mail = entry.attributes.get("mail", ["No email"])[0]
            print(f"  👤 {cn} - {mail}")
    else:
        print(f"❌ Filtering failed: {filter_result.error}")
    
    # Demonstrate writing back to LDIF
    print("\n💾 Writing filtered entries to new file...")
    output_file = Path(__file__).parent / "output_basic.ldif"
    
    if filter_result.is_success and filter_result.data is not None:
        write_result = api.write(filter_result.data, output_file)
        
        if write_result.is_success:
            print(f"✅ Written to: {output_file}")
        else:
            print(f"❌ Write failed: {write_result.error}")
    
    print("\n🎉 Basic parsing example completed!")


if __name__ == "__main__":
    main()