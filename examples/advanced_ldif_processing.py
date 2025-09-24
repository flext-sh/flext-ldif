#!/usr/bin/env python3
"""Advanced LDIF Processing Example - RFC 2849 Compliance Demo.

This example demonstrates the advanced LDIF processing capabilities of flext-ldif,
including RFC 2849 compliance, server-specific adaptations, and comprehensive
validation features.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import base64
from pathlib import Path

from flext_ldif.models import FlextLdifModels
from flext_ldif.processor import FlextLdifProcessor
from flext_ldif.server_quirks import FlextLdifServerQuirks


def create_sample_ldif_content() -> str:
    """Create sample LDIF content demonstrating various RFC 2849 features."""
    # Create Base64 encoded content
    binary_data = base64.b64encode(b"Binary data example").decode("ascii")

    return f"""# LDIF file with RFC 2849 features
version: 1

# Regular entry with line continuation
dn: cn=john doe,ou=users,dc=example,dc=com
cn: john doe
sn: doe
givenName: john
description: This is a very long description that
 continues on the next line with additional information
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
mail: john.doe@example.com
telephoneNumber: +1-555-0123

# Entry with Base64 encoded binary data
dn: cn=jane smith,ou=users,dc=example,dc=com
cn: jane smith
sn: smith
givenName: jane
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
mail: jane.smith@example.com
# Binary data (Base64 encoded)
userCertificate:: {binary_data}

# Entry with URL reference
dn: cn=bob wilson,ou=users,dc=example,dc=com
cn: bob wilson
sn: wilson
givenName: bob
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
mail: bob.wilson@example.com
# URL reference to external file
jpegPhoto: <file:///path/to/photos/bob.jpg>

# Entry with attribute options (language tags)
dn: cn=maria garcia,ou=users,dc=example,dc=com
cn: maria garcia
cn;lang-en: Maria Garcia
cn;lang-es: María García
sn: garcia
givenName: maria
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
mail: maria.garcia@example.com

# Change record - Add operation
dn: cn=new user,ou=users,dc=example,dc=com
changetype: add
cn: new user
sn: user
givenName: new
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
mail: new.user@example.com

# Change record - Modify operation
dn: cn=existing user,ou=users,dc=example,dc=com
changetype: modify
cn: existing user
sn: user
givenName: existing
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
mail: existing.user@example.com"""


def demonstrate_basic_parsing() -> None:
    """Demonstrate basic LDIF parsing capabilities."""
    print("=== Basic LDIF Parsing ===")

    processor = FlextLdifProcessor()
    ldif_content = create_sample_ldif_content()

    # Parse with basic method
    result = processor.parse_string(ldif_content)
    if result.is_success:
        print(f"✓ Parsed {len(result.value)} entries successfully")
        for i, entry in enumerate(result.value):
            print(f"  Entry {i + 1}: {entry.dn.value}")
    else:
        print(f"✗ Parsing failed: {result.error}")


def demonstrate_advanced_parsing() -> None:
    """Demonstrate advanced RFC 2849 compliant parsing."""
    print("\n=== Advanced RFC 2849 Parsing ===")

    processor = FlextLdifProcessor()
    ldif_content = create_sample_ldif_content()

    # Parse with advanced method
    result = processor.parse_string_advanced(ldif_content)
    if result.is_success:
        print(f"✓ Advanced parsing: {len(result.value)} entries/records")

        # Separate entries and change records
        entries = []
        change_records = []

        for item in result.value:
            if hasattr(item, "changetype"):
                change_records.append(item)
            else:
                entries.append(item)

        print(f"  Regular entries: {len(entries)}")
        print(f"  Change records: {len(change_records)}")

        # Show change record details
        for i, change_record in enumerate(change_records):
            print(
                f"  Change Record {i + 1}: {change_record.changetype} - {change_record.dn.value}"
            )
    else:
        print(f"✗ Advanced parsing failed: {result.error}")


def demonstrate_server_detection() -> None:
    """Demonstrate LDAP server type detection."""
    print("\n=== LDAP Server Detection ===")

    processor = FlextLdifProcessor()
    ldif_content = create_sample_ldif_content()

    # Parse entries first
    result = processor.parse_string(ldif_content)
    if result.is_success:
        # Detect server type
        detection_result = processor.detect_server_type(result.value)
        if detection_result.is_success:
            server_type = detection_result.value
            print(f"✓ Detected server type: {server_type}")

            # Get server information
            info_result = processor.get_server_info(server_type)
            if info_result.is_success:
                info = info_result.value
                print(f"  Server: {info.get('description', 'Unknown')}")
                print(f"  DN Case Sensitive: {info.get('dn_case_sensitive', False)}")
                print(
                    f"  Required Object Classes: {info.get('required_object_classes', [])}"
                )
        else:
            print(f"✗ Server detection failed: {detection_result.error}")


def demonstrate_server_adaptation() -> None:
    """Demonstrate server-specific entry adaptation."""
    print("\n=== Server-Specific Adaptation ===")

    # Create a sample entry
    entry_data = {
        "dn": "cn=test user,ou=users,dc=example,dc=com",
        "attributes": {
            "cn": ["test user"],
            "sn": ["user"],
            "givenName": ["test"],
            "objectClass": ["person", "organizationalPerson"],
            "mail": ["test.user@example.com"],
        },
    }

    entry_result = FlextLdifModels.Entry.create(entry_data)
    if entry_result.is_success:
        entry = entry_result.value

        # Test adaptation for different servers
        server_types = ["active_directory", "openldap", "apache_directory"]

        for server_type in server_types:
            print(f"\nAdapting for {server_type}:")

            quirks_handler = FlextLdifServerQuirks()
            adaptation_result = quirks_handler.adapt_entry(entry, server_type)

            if adaptation_result.is_success:
                adapted_entry = adaptation_result.value
                print("  ✓ Successfully adapted entry")
                print(f"    DN: {adapted_entry.dn.value}")
                print(
                    f"    Object Classes: {adapted_entry.get_attribute('objectClass')}"
                )
            else:
                print(f"  ✗ Adaptation failed: {adaptation_result.error}")


def demonstrate_compliance_validation() -> None:
    """Demonstrate RFC 2849 compliance validation."""
    print("\n=== RFC 2849 Compliance Validation ===")

    processor = FlextLdifProcessor()
    ldif_content = create_sample_ldif_content()

    # Parse with advanced method
    result = processor.parse_string_advanced(ldif_content)
    if result.is_success:
        # Validate RFC compliance
        compliance_result = processor.validate_rfc_compliance(result.value)
        if compliance_result.is_success:
            compliance_data = compliance_result.value
            print("✓ Compliance validation completed")
            print(f"  Total entries: {compliance_data.get('total_entries', 0)}")
            print(
                f"  Compliance level: {compliance_data.get('compliance_level', 'unknown')}"
            )
            print(
                f"  Compliance score: {compliance_data.get('compliance_score', 0.0):.2f}"
            )
            print(
                f"  Features detected: {compliance_data.get('features_detected', [])}"
            )
        else:
            print(f"✗ Compliance validation failed: {compliance_result.error}")


def demonstrate_server_compliance_validation() -> None:
    """Demonstrate server-specific compliance validation."""
    print("\n=== Server-Specific Compliance Validation ===")

    processor = FlextLdifProcessor()
    ldif_content = create_sample_ldif_content()

    # Parse entries
    result = processor.parse_string(ldif_content)
    if result.is_success:
        # Validate against different server types
        server_types = ["active_directory", "openldap", "generic"]

        for server_type in server_types:
            print(f"\nValidating against {server_type}:")

            validation_result = processor.validate_server_compliance(
                result.value, server_type
            )
            if validation_result.is_success:
                validation_data = validation_result.value
                print(f"  Server type: {validation_data.get('server_type', 'unknown')}")
                print(f"  Total entries: {validation_data.get('total_entries', 0)}")
                print(
                    f"  Compliant entries: {validation_data.get('compliant_entries', 0)}"
                )
                print(
                    f"  Compliance percentage: {validation_data.get('compliance_percentage', 0.0):.1f}%"
                )
                print(
                    f"  Overall compliant: {validation_data.get('overall_compliant', False)}"
                )

                issues = validation_data.get("issues", [])
                if issues:
                    print(f"  Issues: {len(issues)}")
                    for issue in issues[:3]:  # Show first 3 issues
                        print(f"    - {issue}")

                warnings = validation_data.get("warnings", [])
                if warnings:
                    print(f"  Warnings: {len(warnings)}")
                    for warning in warnings[:3]:  # Show first 3 warnings
                        print(f"    - {warning}")
            else:
                print(f"  ✗ Validation failed: {validation_result.error}")


def demonstrate_file_processing() -> None:
    """Demonstrate file processing with encoding detection."""
    print("\n=== File Processing with Encoding Detection ===")

    # Create a temporary LDIF file
    ldif_content = create_sample_ldif_content()
    temp_file = Path("temp_sample.ldif")

    try:
        # Write file with UTF-8 encoding
        temp_file.write_text(ldif_content, encoding="utf-8")
        print(f"✓ Created temporary file: {temp_file}")

        # Process file with advanced parser
        processor = FlextLdifProcessor()
        result = processor.parse_file_advanced(temp_file)

        if result.is_success:
            print(f"✓ File processed successfully: {len(result.value)} entries/records")
        else:
            print(f"✗ File processing failed: {result.error}")

    finally:
        # Clean up
        if temp_file.exists():
            temp_file.unlink()
            print("✓ Cleaned up temporary file")


def demonstrate_error_handling() -> None:
    """Demonstrate error handling and recovery."""
    print("\n=== Error Handling and Recovery ===")

    processor = FlextLdifProcessor()

    # Test with malformed LDIF
    malformed_content = """dn: cn=test,dc=example,dc=com
invalid line without colon
cn: test
objectClass: person

dn: cn=valid,dc=example,dc=com
cn: valid
objectClass: person"""

    result = processor.parse_string_advanced(malformed_content)
    if result.is_success:
        print(
            f"✓ Gracefully handled malformed LDIF: {len(result.value)} entries parsed"
        )
    else:
        print(f"✗ Failed to handle malformed LDIF: {result.error}")

    # Test with empty content
    empty_result = processor.parse_string_advanced("")
    if empty_result.is_success:
        print(f"✓ Handled empty content: {len(empty_result.value)} entries")
    else:
        print(f"✗ Failed to handle empty content: {empty_result.error}")


def main() -> None:
    """Main demonstration function."""
    print("FLEXT-LDIF Advanced Processing Demonstration")
    print("=" * 50)

    try:
        demonstrate_basic_parsing()
        demonstrate_advanced_parsing()
        demonstrate_server_detection()
        demonstrate_server_adaptation()
        demonstrate_compliance_validation()
        demonstrate_server_compliance_validation()
        demonstrate_file_processing()
        demonstrate_error_handling()

        print("\n" + "=" * 50)
        print("✓ All demonstrations completed successfully!")

    except Exception as e:
        print(f"\n✗ Demonstration failed: {e}")
        raise


if __name__ == "__main__":
    main()
