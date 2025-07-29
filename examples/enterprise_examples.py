"""Enterprise examples demonstrating all flext-ldif functionality.

This module provides comprehensive examples showing how to use flext-ldif
in enterprise scenarios with real-world LDIF processing tasks.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

from flext_ldif import (
    FlextLdifAPI,
    FlextLdifConfig,
    TLdif,
    flext_ldif_get_api,
    flext_ldif_parse,
    flext_ldif_validate,
    flext_ldif_write,
)


def example_basic_ldif_processing() -> None:
    """Example: Basic LDIF parsing, validation, and writing."""
    print("=== Basic LDIF Processing Example ===")
    
    # Sample LDIF content
    ldif_content = """dn: cn=John Doe,ou=people,dc=example,dc=com
objectClass: person
objectClass: inetOrgPerson
cn: John Doe
sn: Doe
givenName: John
mail: john.doe@example.com
uid: johndoe

dn: cn=Jane Smith,ou=people,dc=example,dc=com
objectClass: person
objectClass: organizationalPerson
cn: Jane Smith
sn: Smith
givenName: Jane
mail: jane.smith@example.com
uid: janesmith

"""
    
    # Using TLdif core functionality
    print("1. Parsing with TLdif core:")
    parse_result = TLdif.parse(ldif_content)
    
    if parse_result.is_success:
        entries = parse_result.data
        print(f"   ✅ Successfully parsed {len(entries)} entries")
        
        # Validate entries
        print("2. Validating entries:")
        validate_result = TLdif.validate_entries(entries)
        if validate_result.is_success:
            print("   ✅ All entries are valid")
        else:
            print(f"   ❌ Validation failed: {validate_result.error}")
        
        # Write back to LDIF
        print("3. Writing entries to LDIF:")
        write_result = TLdif.write(entries)
        if write_result.is_success:
            print(f"   ✅ Generated LDIF ({len(write_result.data)} characters)")
            print(f"   Preview: {write_result.data[:100]}...")
        else:
            print(f"   ❌ Write failed: {write_result.error}")
    else:
        print(f"   ❌ Parse failed: {parse_result.error}")
    
    print()


def example_api_usage() -> None:
    """Example: Using FlextLdifAPI for advanced processing."""
    print("=== FlextLdifAPI Usage Example ===")
    
    ldif_content = """dn: ou=people,dc=company,dc=com
objectClass: organizationalUnit
ou: people
description: People container

dn: cn=Alice Johnson,ou=people,dc=company,dc=com
objectClass: person
objectClass: inetOrgPerson
cn: Alice Johnson
sn: Johnson
givenName: Alice
mail: alice.johnson@company.com
uid: ajohnson
title: Software Engineer

dn: cn=Bob Wilson,ou=people,dc=company,dc=com
objectClass: person
objectClass: organizationalPerson
cn: Bob Wilson
sn: Wilson
givenName: Bob
mail: bob.wilson@company.com
uid: bwilson
title: Manager

dn: cn=developers,ou=groups,dc=company,dc=com
objectClass: groupOfNames
cn: developers
member: cn=Alice Johnson,ou=people,dc=company,dc=com

"""
    
    # Initialize API with configuration
    config = FlextLdifConfig.model_validate({
        "strict_validation": True,
        "max_entries": 100,
    })
    api = FlextLdifAPI(config)
    
    print("1. Parsing with FlextLdifAPI:")
    parse_result = api.parse(ldif_content)
    
    if parse_result.is_success:
        entries = parse_result.data
        print(f"   ✅ Parsed {len(entries)} entries")
        
        # Filter person entries
        print("2. Filtering person entries:")
        person_result = api.filter_persons(entries)
        if person_result.is_success:
            person_entries = person_result.data
            print(f"   ✅ Found {len(person_entries)} person entries")
            for entry in person_entries:
                print(f"      - {entry.get_attribute('cn')[0]}")
        
        # Filter by objectClass
        print("3. Filtering by objectClass (inetOrgPerson):")
        inetorg_entries = api.filter_by_objectclass(entries, "inetOrgPerson")
        print(f"   ✅ Found {len(inetorg_entries)} inetOrgPerson entries")
        
        # Find specific entry by DN
        print("4. Finding entry by DN:")
        target_dn = "cn=Alice Johnson,ou=people,dc=company,dc=com"
        found_entry = api.find_entry_by_dn(entries, target_dn)
        if found_entry:
            print(f"   ✅ Found entry: {found_entry.get_attribute('cn')[0]}")
            print(f"      Title: {found_entry.get_attribute('title')[0]}")
        
        # Sort hierarchically
        print("5. Sorting entries hierarchically:")
        sort_result = api.sort_hierarchically(entries)
        if sort_result.is_success:
            sorted_entries = sort_result.data
            print("   ✅ Entries sorted by hierarchy:")
            for entry in sorted_entries:
                depth = str(entry.dn).count(",")
                print(f"      {' ' * depth}- {entry.dn}")
    
    print()


def example_file_operations() -> None:
    """Example: File-based LDIF operations."""
    print("=== File Operations Example ===")
    
    ldif_content = """dn: dc=filetest,dc=com
objectClass: top
objectClass: domain
dc: filetest

dn: ou=users,dc=filetest,dc=com
objectClass: top
objectClass: organizationalUnit
ou: users

dn: cn=Test User,ou=users,dc=filetest,dc=com
objectClass: top
objectClass: person
cn: Test User
sn: User
mail: test.user@filetest.com

"""
    
    # Create temporary files
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.ldif') as input_file:
        input_file.write(ldif_content)
        input_path = Path(input_file.name)
    
    with tempfile.NamedTemporaryFile(delete=False, suffix='.ldif') as output_file:
        output_path = Path(output_file.name)
    
    try:
        print(f"1. Reading LDIF from file: {input_path.name}")
        
        # Using TLdif for file operations
        read_result = TLdif.read_file(input_path)
        if read_result.is_success:
            entries = read_result.data
            print(f"   ✅ Read {len(entries)} entries from file")
            
            # Process entries
            print("2. Processing entries (filter persons):")
            api = FlextLdifAPI()
            person_result = api.filter_persons(entries)
            if person_result.is_success:
                person_entries = person_result.data
                print(f"   ✅ Filtered to {len(person_entries)} person entries")
                
                # Write to output file
                print(f"3. Writing processed entries to: {output_path.name}")
                write_result = TLdif.write_file(person_entries, output_path)
                if write_result.is_success:
                    print("   ✅ Successfully wrote to file")
                    
                    # Verify output
                    if output_path.exists():
                        content = output_path.read_text(encoding='utf-8')
                        print(f"   📄 Output file size: {len(content)} characters")
                        print(f"   📄 Contains: {'person entries' if 'objectClass: person' in content else 'processed data'}")
        
        # Using API for file operations
        print("4. Using API for file operations:")
        api = FlextLdifAPI()
        file_parse_result = api.parse_file(input_path)
        if file_parse_result.is_success:
            print(f"   ✅ API parsed {len(file_parse_result.data)} entries from file")
    
    finally:
        # Cleanup
        input_path.unlink(missing_ok=True)
        output_path.unlink(missing_ok=True)
    
    print()


def example_convenience_functions() -> None:
    """Example: Using convenience functions for simple tasks."""
    print("=== Convenience Functions Example ===")
    
    ldif_content = """dn: cn=convenience,dc=example,dc=com
objectClass: person
cn: convenience
sn: example
mail: convenience@example.com

"""
    
    print("1. Using convenience functions:")
    
    # Parse using convenience function
    entries = flext_ldif_parse(ldif_content)
    print(f"   ✅ flext_ldif_parse: {len(entries)} entries")
    
    # Validate using convenience function
    is_valid = flext_ldif_validate(ldif_content)
    print(f"   ✅ flext_ldif_validate: {is_valid}")
    
    # Write using convenience function
    output = flext_ldif_write(entries)
    print(f"   ✅ flext_ldif_write: {len(output)} characters")
    
    # Global API instance
    print("2. Using global API instance:")
    api = flext_ldif_get_api()
    result = api.parse(ldif_content)
    if result.is_success:
        print(f"   ✅ Global API parsed {len(result.data)} entries")
    
    print()


def example_configuration_scenarios() -> None:
    """Example: Different configuration scenarios."""
    print("=== Configuration Scenarios Example ===")
    
    # Test content with multiple entries
    large_ldif = ""
    for i in range(15):
        large_ldif += f"""dn: cn=user{i:02d},ou=people,dc=config,dc=com
objectClass: person
cn: user{i:02d}
sn: user{i:02d}

"""
    
    print("1. Strict configuration (max 10 entries):")
    strict_config = FlextLdifConfig.model_validate({
        "strict_validation": True,
        "max_entries": 10,
        "max_entry_size": 1024,
    })
    
    strict_api = FlextLdifAPI(strict_config)
    strict_result = strict_api.parse(large_ldif)
    if strict_result.is_success:
        print(f"   ✅ Strict config: parsed {len(strict_result.data)} entries")
    else:
        print(f"   ❌ Strict config failed: {strict_result.error}")
    
    print("2. Permissive configuration (max 100 entries):")
    permissive_config = FlextLdifConfig.model_validate({
        "strict_validation": False,
        "max_entries": 100,
        "max_entry_size": 10240,
    })
    
    permissive_api = FlextLdifAPI(permissive_config)
    permissive_result = permissive_api.parse(large_ldif)
    if permissive_result.is_success:
        print(f"   ✅ Permissive config: parsed {len(permissive_result.data)} entries")
    else:
        print(f"   ❌ Permissive config failed: {permissive_result.error}")
    
    print()


def example_error_handling() -> None:
    """Example: Proper error handling patterns."""
    print("=== Error Handling Example ===")
    
    # Invalid LDIF content
    invalid_ldif = """This is not LDIF content
It has no proper structure
And should fail parsing"""
    
    print("1. Handling parse errors:")
    parse_result = TLdif.parse(invalid_ldif)
    if not parse_result.is_success:
        print(f"   ❌ Expected parse failure: {parse_result.error}")
        print("   ✅ Error handled gracefully")
    
    # File not found error
    print("2. Handling file not found:")
    nonexistent_file = Path("/nonexistent/path/file.ldif")
    file_result = TLdif.read_file(nonexistent_file)
    if not file_result.is_success:
        print(f"   ❌ Expected file error: {file_result.error}")
        print("   ✅ File error handled gracefully")
    
    # Validation errors
    print("3. Handling validation errors:")
    incomplete_ldif = """dn: cn=incomplete,dc=example,dc=com
cn: incomplete
# Missing objectClass"""
    
    api = FlextLdifAPI()
    incomplete_result = api.parse(incomplete_ldif)
    if incomplete_result.is_success:
        # Parse might succeed, but validation should catch issues
        entries = incomplete_result.data
        validate_result = api.validate(entries)
        if not validate_result.is_success:
            print(f"   ❌ Expected validation failure: {validate_result.error}")
            print("   ✅ Validation error handled gracefully")
    
    print()


def example_advanced_filtering() -> None:
    """Example: Advanced filtering and processing."""
    print("=== Advanced Filtering Example ===")
    
    complex_ldif = """dn: dc=advanced,dc=com
objectClass: top
objectClass: domain
dc: advanced

dn: ou=people,dc=advanced,dc=com
objectClass: top
objectClass: organizationalUnit
ou: people

dn: ou=groups,dc=advanced,dc=com
objectClass: top
objectClass: organizationalUnit
ou: groups

dn: cn=John Engineer,ou=people,dc=advanced,dc=com
objectClass: top
objectClass: person
objectClass: inetOrgPerson
cn: John Engineer
sn: Engineer
title: Software Engineer
departmentNumber: IT

dn: cn=Mary Manager,ou=people,dc=advanced,dc=com
objectClass: top
objectClass: person
objectClass: organizationalPerson
cn: Mary Manager
sn: Manager
title: Engineering Manager
departmentNumber: IT

dn: cn=Bob Admin,ou=people,dc=advanced,dc=com
objectClass: top
objectClass: person
cn: Bob Admin
sn: Admin
title: System Administrator
departmentNumber: IT

dn: cn=engineers,ou=groups,dc=advanced,dc=com
objectClass: top
objectClass: groupOfNames
cn: engineers
member: cn=John Engineer,ou=people,dc=advanced,dc=com

dn: cn=managers,ou=groups,dc=advanced,dc=com
objectClass: top
objectClass: groupOfNames
cn: managers
member: cn=Mary Manager,ou=people,dc=advanced,dc=com

"""
    
    api = FlextLdifAPI()
    parse_result = api.parse(complex_ldif)
    
    if parse_result.is_success:
        entries = parse_result.data
        print(f"1. Parsed {len(entries)} total entries")
        
        # Filter different types
        print("2. Filtering by entry types:")
        
        # Person entries
        person_entries = api.filter_persons(entries).data
        print(f"   👤 Person entries: {len(person_entries)}")
        
        # inetOrgPerson entries (more specific)
        inetorg_entries = api.filter_by_objectclass(entries, "inetOrgPerson")
        print(f"   👤 inetOrgPerson entries: {len(inetorg_entries)}")
        
        # Group entries
        group_entries = api.filter_by_objectclass(entries, "groupOfNames")
        print(f"   👥 Group entries: {len(group_entries)}")
        
        # Organizational units
        ou_entries = api.filter_by_objectclass(entries, "organizationalUnit")
        print(f"   🏢 OU entries: {len(ou_entries)}")
        
        print("3. Advanced processing:")
        
        # Custom filtering example
        def filter_by_title_containing(entries: list, keyword: str) -> list:
            """Custom filter for entries with title containing keyword."""
            result = []
            for entry in entries:
                title_attr = entry.get_attribute("title")
                if title_attr and any(keyword.lower() in title.lower() for title in title_attr):
                    result.append(entry)
            return result
        
        engineer_entries = filter_by_title_containing(person_entries, "engineer")
        print(f"   ⚙️ Engineer entries: {len(engineer_entries)}")
        
        manager_entries = filter_by_title_containing(person_entries, "manager")
        print(f"   👔 Manager entries: {len(manager_entries)}")
        
        # Hierarchical analysis
        print("4. Hierarchical analysis:")
        sort_result = api.sort_hierarchically(entries)
        if sort_result.is_success:
            sorted_entries = sort_result.data
            print("   📊 Hierarchy (by DN depth):")
            for entry in sorted_entries:
                depth = str(entry.dn).count(",")
                indent = "   " + "  " * depth
                entry_type = "domain" if entry.has_object_class("domain") else \
                            "OU" if entry.has_object_class("organizationalUnit") else \
                            "person" if entry.has_object_class("person") else \
                            "group" if entry.has_object_class("groupOfNames") else "other"
                print(f"{indent}[{entry_type}] {entry.dn}")
    
    print()


def example_performance_monitoring() -> None:
    """Example: Performance monitoring and optimization."""
    print("=== Performance Monitoring Example ===")
    
    import time
    
    # Generate larger dataset
    print("1. Generating test dataset...")
    large_ldif = "dn: dc=perf,dc=com\nobjectClass: top\nobjectClass: domain\ndc: perf\n\n"
    
    for i in range(100):
        large_ldif += f"""dn: cn=user{i:03d},dc=perf,dc=com
objectClass: top
objectClass: person
objectClass: inetOrgPerson
cn: user{i:03d}
sn: User{i:03d}
givenName: Test{i:03d}
mail: user{i:03d}@perf.com
uid: user{i:03d}
employeeNumber: EMP{i:03d}
description: Test user {i:03d} for performance monitoring

"""
    
    print(f"   📊 Generated LDIF with ~101 entries ({len(large_ldif)} characters)")
    
    # Measure parsing performance
    print("2. Measuring parsing performance:")
    start_time = time.time()
    parse_result = TLdif.parse(large_ldif)
    parse_time = time.time() - start_time
    
    if parse_result.is_success:
        entries = parse_result.data
        print(f"   ⏱️ Parsed {len(entries)} entries in {parse_time:.3f} seconds")
        print(f"   📈 Rate: {len(entries)/parse_time:.0f} entries/second")
        
        # Measure filtering performance
        print("3. Measuring filtering performance:")
        api = FlextLdifAPI()
        
        start_time = time.time()
        person_result = api.filter_persons(entries)
        filter_time = time.time() - start_time
        
        if person_result.is_success:
            print(f"   ⏱️ Filtered {len(person_result.data)} persons in {filter_time:.3f} seconds")
            
            # Measure writing performance
            print("4. Measuring writing performance:")
            start_time = time.time()
            write_result = TLdif.write(person_result.data)
            write_time = time.time() - start_time
            
            if write_result.is_success:
                print(f"   ⏱️ Wrote {len(person_result.data)} entries in {write_time:.3f} seconds")
                print(f"   📄 Output size: {len(write_result.data)} characters")
                
                # Total performance
                total_time = parse_time + filter_time + write_time
                print(f"5. Total workflow time: {total_time:.3f} seconds")
    
    print()


def main() -> None:
    """Run all enterprise examples."""
    print("🚀 FLEXT-LDIF Enterprise Examples")
    print("=" * 50)
    print()
    
    # Run all examples
    example_basic_ldif_processing()
    example_api_usage()
    example_file_operations()
    example_convenience_functions()
    example_configuration_scenarios()
    example_error_handling()
    example_advanced_filtering()
    example_performance_monitoring()
    
    print("✅ All examples completed successfully!")
    print()
    print("📚 Key takeaways:")
    print("   • Use TLdif for direct core functionality")
    print("   • Use FlextLdifAPI for advanced processing and filtering")
    print("   • Use convenience functions for simple one-off tasks")
    print("   • Configure API for enterprise requirements")
    print("   • Always handle errors gracefully")
    print("   • Monitor performance for large datasets")


if __name__ == "__main__":
    main()