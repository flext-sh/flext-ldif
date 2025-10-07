#!/usr/bin/env python3
"""LDIF Processing Service Showcase.

This example demonstrates the complete FlextLdif API using FlextService patterns
from flext-core Phase 3 enhancements.

KEY FEATURES DEMONSTRATED:
- Automatic service infrastructure with inherited properties
- FlextResult railway-oriented programming
- Comprehensive LDIF processing workflows
- Server migration patterns
- Schema validation and ACL processing

USAGE PATTERNS:
- Service infrastructure best practices
- Integration with FlextService base class
- Structured logging with automatic context

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextResult, FlextService, FlextTypes

from flext_ldif import FlextLdif


class LdifProcessingService(FlextService[FlextTypes.Dict]):
    """Service demonstrating LDIF processing with FlextMixins.Service infrastructure.

    This service inherits from Flext.Service to demonstrate:
    - Inherited container property (FlextContainer singleton)
    - Inherited logger property (FlextLogger with service context - LDIF PROCESSING FOCUS!)
    - Inherited context property (FlextContext for request/correlation tracking)
    - Inherited config property (FlextConfig with LDIF processing settings)
    - Inherited metrics property (FlextMetrics for LDIF observability)

    FlextLdif provides:
    - RFC-compliant LDIF parsing and writing
    - Server-specific quirks and migrations
    - Generic server-agnostic migration pipeline
    - Schema validation and ACL processing
    - Entry building and transformation
    """

    def __init__(self) -> None:
        """Initialize with inherited FlextMixins.Service infrastructure.

        Inherited properties (no manual instantiation needed):
        - self.logger: FlextLogger with service context (LDIF processing operations)
        - self.container: FlextContainer singleton (for service dependencies)
        - self.context: FlextContext (for correlation tracking)
        - self.config: FlextConfig (for LDIF configuration)
        - self.metrics: FlextMetrics (for LDIF observability)
        """
        super().__init__()

        # Demonstrate inherited logger (no manual instantiation needed!)
        self.logger.info(
            "LdifProcessingService initialized with inherited infrastructure",
            extra={
                "service_type": "LDIF Processing demonstration",
                "ldif_features": [
                    "rfc_parsing",
                    "server_migration",
                    "schema_validation",
                    "acl_processing",
                    "entry_building",
                ],
            },
        )

        # Initialize LDIF API
        self._ldif = FlextLdif()

    def execute(self) -> FlextResult[FlextTypes.Dict]:
        """Execute all LDIF processing pattern demonstrations.

        Runs comprehensive LDIF demonstrations:
        1. Basic LDIF parsing and writing
        2. Server-specific quirks handling
        3. Generic server migration
        4. Schema validation
        5. Entry building and transformation

        Returns:
            FlextResult containing demonstration summary

        """
        self.logger.info("Starting comprehensive LDIF processing demonstration")

        try:
            # Run all demonstrations
            self.demonstrate_basic_parsing()
            self.demonstrate_writing()
            self.demonstrate_server_migration()
            self.demonstrate_entry_building()

            summary: FlextTypes.Dict = {
                "status": "completed",
                "demonstrations": 4,
                "patterns": [
                    "basic_parsing",
                    "ldif_writing",
                    "server_quirks",
                    "entry_validation",
                ],
                "ldif_executed": True,
            }

            self.logger.info(
                "LDIF processing demonstration completed successfully",
                extra={"summary": summary},
            )

            return FlextResult[FlextTypes.Dict].ok(summary)

        except Exception as e:
            error_msg = f"LDIF processing demonstration failed: {e}"
            self.logger.exception(error_msg, extra={"error_type": type(e).__name__})
            return FlextResult[FlextTypes.Dict].fail(error_msg)

    def demonstrate_basic_parsing(self) -> None:
        """Demonstrate basic LDIF parsing with FlextResult pattern."""
        print("\n" + "=" * 80)
        print("DEMONSTRATION 1: Basic LDIF Parsing")
        print("=" * 80)

        # Sample LDIF content
        ldif_content = """dn: cn=John Doe,ou=People,dc=example,dc=com
objectClass: person
objectClass: inetOrgPerson
cn: John Doe
sn: Doe
mail: john.doe@example.com

dn: cn=Jane Smith,ou=People,dc=example,dc=com
objectClass: person
objectClass: inetOrgPerson
cn: Jane Smith
sn: Smith
mail: jane.smith@example.com
"""

        self.logger.info("Parsing LDIF content with RFC 2849 compliance")

        # Parse using FlextResult pattern
        parse_result = self._ldif.parse(ldif_content)

        if parse_result.is_success:
            entries = parse_result.unwrap()
            print(f"✅ Successfully parsed {len(entries)} LDIF entries")

            for entry in entries:
                print(f"   Entry DN: {entry.dn}")
                # attributes is a custom type, count by iterating
                attr_count = sum(1 for _ in entry.attributes)
                print(f"   Attributes: {attr_count} attributes")

            self.logger.info(
                "LDIF parsing completed",
                extra={"entries_parsed": len(entries)},
            )
        else:
            print(f"❌ Parse failed: {parse_result.error}")
            self.logger.error(
                "LDIF parsing failed",
                extra={"error": parse_result.error},
            )

    def demonstrate_writing(self) -> None:
        """Demonstrate LDIF writing with FlextResult pattern."""
        print("\n" + "=" * 80)
        print("DEMONSTRATION 2: LDIF Writing")
        print("=" * 80)

        # First parse some entries to get proper Entry objects
        ldif_content = """dn: cn=Test User,ou=People,dc=example,dc=com
objectClass: person
objectClass: inetOrgPerson
cn: Test User
sn: User
mail: test.user@example.com
"""

        parse_result = self._ldif.parse(ldif_content)
        if parse_result.is_failure:
            print(f"❌ Parse failed: {parse_result.error}")
            return

        entries = parse_result.unwrap()

        self.logger.info("Writing entries to LDIF format")

        # Write to string
        write_result = self._ldif.write(entries)

        if write_result.is_success:
            ldif_output = write_result.unwrap()
            max_preview_length = 200
            print(f"✅ Successfully wrote {len(entries)} entries to LDIF")
            print("\nLDIF Output (preview):")
            if len(ldif_output) > max_preview_length:
                print(ldif_output[:max_preview_length] + "...")
            else:
                print(ldif_output)

            self.logger.info(
                "LDIF writing completed",
                extra={
                    "entries_written": len(entries),
                    "output_length": len(ldif_output),
                },
            )
        else:
            print(f"❌ Write failed: {write_result.error}")
            self.logger.error(
                "LDIF writing failed",
                extra={"error": write_result.error},
            )

    def demonstrate_server_migration(self) -> None:
        """Demonstrate server-specific quirks handling."""
        print("\n" + "=" * 80)
        print("DEMONSTRATION 3: Server-Specific Quirks")
        print("=" * 80)

        # Sample entry with server-specific attributes
        ldif_content = """dn: cn=Migration Test,ou=People,dc=example,dc=com
objectClass: person
cn: Migration Test
sn: Test
"""

        self.logger.info("Demonstrating server-specific quirks")

        # Parse from OID server type
        parse_result_oid = self._ldif.parse(ldif_content, server_type="oid")

        # Parse from OUD server type
        parse_result_oud = self._ldif.parse(ldif_content, server_type="oud")

        # Parse with RFC-compliant (default)
        parse_result_rfc = self._ldif.parse(ldif_content, server_type="rfc")

        if (
            parse_result_oid.is_success
            and parse_result_oud.is_success
            and parse_result_rfc.is_success
        ):
            print("✅ Successfully parsed with multiple server types:")
            print(f"   OID: {len(parse_result_oid.unwrap())} entries")
            print(f"   OUD: {len(parse_result_oud.unwrap())} entries")
            print(f"   RFC: {len(parse_result_rfc.unwrap())} entries")

            self.logger.info(
                "Server quirks demonstration completed",
                extra={
                    "server_types_tested": ["oid", "oud", "rfc"],
                },
            )
        else:
            print("❌ Some parsing operations failed")
            self.logger.error("Server quirks demonstration had failures")

    def demonstrate_entry_building(self) -> None:
        """Demonstrate entry validation."""
        print("\n" + "=" * 80)
        print("DEMONSTRATION 4: Entry Validation")
        print("=" * 80)

        self.logger.info("Validating LDIF entries")

        # Parse entries first
        ldif_content = """dn: cn=Valid User,ou=People,dc=example,dc=com
objectClass: person
objectClass: inetOrgPerson
cn: Valid User
sn: User
mail: valid.user@example.com
"""

        parse_result = self._ldif.parse(ldif_content)
        if parse_result.is_failure:
            print(f"❌ Parse failed: {parse_result.error}")
            return

        entries = parse_result.unwrap()

        # Validate entries
        validation_result = self._ldif.validate_entries(entries)

        if validation_result.is_success:
            report = validation_result.unwrap()
            print("✅ Entry validation completed")
            print(f"   Valid: {report.get('is_valid', False)}")
            print(f"   Entries checked: {len(entries)}")

            self.logger.info(
                "Entry validation completed",
                extra={
                    "entries_validated": len(entries),
                    "validation_passed": report.get("is_valid", False),
                },
            )
        else:
            print(f"❌ Validation failed: {validation_result.error}")
            self.logger.error(
                "Entry validation failed",
                extra={"error": validation_result.error},
            )


# =============================================================================
# DEMONSTRATION
# =============================================================================


def main() -> None:
    """Demonstrate LDIF processing in action."""
    print("=" * 80)
    print("FLEXT-LDIF SERVICE SHOWCASE")
    print("Demonstrating LDIF processing with FlextService infrastructure")
    print("=" * 80)

    # Create and execute service
    service = LdifProcessingService()
    result = service.execute()

    # Display results
    if result.is_success:
        summary = result.unwrap()
        print("\n" + "=" * 80)
        print("DEMONSTRATION COMPLETE")
        print("=" * 80)
        print(f"Status: {summary['status']}")
        print(f"Demonstrations: {summary['demonstrations']}")
        patterns = summary.get("patterns", [])
        if isinstance(patterns, list):
            print(f"Patterns: {', '.join(str(p) for p in patterns)}")
        print("=" * 80)
    else:
        print(f"\n❌ Demonstration failed: {result.error}")


if __name__ == "__main__":
    main()
