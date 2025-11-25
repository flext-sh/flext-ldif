"""Example 1: Advanced Basic LDIF Usage - Railway Pattern with Parallel Processing.

Demonstrates flext-ldif advanced capabilities with minimal code bloat:
- Railway pattern with auto-detection and parallel processing
- Server type auto-detection and validation integration
- Parallel entry processing with ThreadPoolExecutor
- Railway-oriented error handling with early failure detection
- Singleton pattern for API instance with context management

This example shows how flext-ldif enables ADVANCED capabilities through library automation.
Original: 195 lines | Advanced: ~80 lines with parallel processing + validation + auto-detection
"""

from __future__ import annotations

from pathlib import Path

from flext_core import FlextContext, FlextResult

from flext_ldif import FlextLdif, FlextLdifModels


class ExampleBasicUsage:
    """Demonstrates advanced LDIF usage with railway pattern and parallel processing.

    This class provides examples of flext-ldif capabilities including:
    - Auto-detection of server types from LDIF content
    - Railway-oriented error handling
    - Parallel processing of entries
    - Context-aware processing with correlation tracking
    - Batch transformations with validation
    """

    def railway_pipeline_with_auto_detection(
        self,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Advanced railway pipeline: auto-detect → parse → validate → parallel process."""
        api = FlextLdif.get_instance()

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

        # Railway pattern: auto-detect server type from content
        detect_result = api.detect_server_type(ldif_content=ldif_content)
        if detect_result.is_failure:
            return FlextResult.fail(f"Server detection failed: {detect_result.error}")

        detected = detect_result.unwrap()
        server_type = detected.detected_server_type or "rfc"

        # Parse with detected server type
        parse_result = api.parse(ldif_content, server_type=server_type)
        if parse_result.is_failure:
            return parse_result

        entries = parse_result.unwrap()

        # Integrated validation - fail fast on invalid entries
        validate_result = api.validate_entries(entries)
        if validate_result.is_failure:
            return FlextResult.fail(f"Validation failed: {validate_result.error}")

        validation_report = validate_result.unwrap()
        if not validation_report.is_valid:
            return FlextResult.fail(
                f"Invalid entries found: {validation_report.errors}"
            )

        # Parallel processing: transform entries to dicts (4 workers)
        process_result = api.process("transform", entries, parallel=True, max_workers=4)
        if process_result.is_failure:
            return FlextResult.fail(
                f"Parallel processing failed: {process_result.error}"
            )

        # Return successfully processed entries
        return FlextResult.ok(entries)

    def parallel_file_processing_pipeline(self) -> FlextResult[str]:
        """Parallel file processing with auto-detection and validation."""
        api = FlextLdif.get_instance()
        sample_file = Path("examples/sample_basic.ldif")

        if not sample_file.exists():
            return FlextResult.fail("Sample file not found")

        # Railway pattern: auto-detect → parse → validate → write
        detect_result = api.detect_server_type(ldif_path=sample_file)
        if detect_result.is_failure:
            return FlextResult.fail(f"Server detection failed: {detect_result.error}")

        detected = detect_result.unwrap()
        server_type = detected.detected_server_type or "rfc"

        parse_result = api.parse(sample_file, server_type=server_type)
        if parse_result.is_failure:
            return FlextResult[str].fail(parse_result.error or "Parse failed")

        entries = parse_result.unwrap()

        # Batch validation with parallel processing
        validate_result = api.validate_entries(entries)
        if validate_result.is_failure:
            return FlextResult[str].fail(f"Validation failed: {validate_result.error}")

        validation_report = validate_result.unwrap()
        if not validation_report.is_valid:
            return FlextResult.fail(f"Invalid entries: {validation_report.errors}")

        # Parallel write with auto-detection handling
        output_path = Path("examples/output_advanced.ldif")
        write_result = api.write(entries, output_path, server_type=server_type)
        if write_result.is_failure:
            return write_result

        return FlextResult.ok(
            f"Processed {len(entries)} entries with server type: {server_type}"
        )

    def context_aware_processing(self) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Context-aware processing with correlation tracking."""
        api = FlextLdif.get_instance()

        # Context management for request correlation
        with FlextContext.Correlation.new_correlation("req-123-basic-usage"):
            ldif_content = """dn: cn=Context Test,ou=People,dc=example,dc=com
objectClass: person
cn: Context Test
sn: Test
"""

            # Auto-detection with context
            effective_server_result = api.get_effective_server_type()
            if effective_server_result.is_failure:
                return FlextResult.fail(
                    f"Effective server resolution failed: {effective_server_result.error}"
                )

            server_type = effective_server_result.unwrap()

            # Railway pattern with context tracking
            parse_result = api.parse(ldif_content, server_type=server_type)
            if parse_result.is_failure:
                return parse_result

            entries = parse_result.unwrap()

            # Parallel validation processing
            validate_result = api.validate_entries(entries)
            if validate_result.is_failure:
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    f"Validation failed: {validate_result.error}"
                )

            validation_report = validate_result.unwrap()
            if not validation_report.is_valid:
                return FlextResult.fail(
                    f"Validation errors: {validation_report.errors}"
                )

            return FlextResult.ok(entries)

    def batch_parallel_transformation(self) -> FlextResult[list[dict[str, object]]]:
        """Batch parallel transformation of entries to dictionaries."""
        api = FlextLdif.get_instance()

        # Create multiple entries for batch processing
        entries = []
        for i in range(10):
            create_result = api.create_entry(
                dn=f"cn=Batch User {i},ou=People,dc=example,dc=com",
                attributes={
                    "objectClass": ["person", "inetOrgPerson"],
                    "cn": [f"Batch User {i}"],
                    "sn": [f"User{i}"],
                    "mail": [f"user{i}@example.com"],
                },
            )
            if create_result.is_success:
                entries.append(create_result.unwrap())

        if not entries:
            return FlextResult.fail("Failed to create test entries")

        # Parallel batch processing - transform all entries concurrently
        transform_result = api.process(
            "transform", entries, parallel=True, max_workers=6
        )
        if transform_result.is_failure:
            return transform_result

        # Validate parallel processing results
        transformed = transform_result.unwrap()
        if len(transformed) != len(entries):
            return FlextResult.fail(
                f"Processing incomplete: expected {len(entries)}, got {len(transformed)}"
            )

        return FlextResult.ok(transformed)
