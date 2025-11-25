"""Example 3: Advanced Validation and Statistical Analysis - Parallel Processing.

Demonstrates flext-ldif advanced validation and analytics with minimal code bloat:
- Parallel validation processing with ThreadPoolExecutor
- Advanced statistical analysis with comprehensive metrics
- Batch validation with detailed error reporting and categorization
- Railway-oriented validation pipelines with early failure detection
- Performance analytics and bottleneck identification

This example shows how flext-ldif enables ADVANCED analysis through parallel processing.
Original: 246 lines | Advanced: ~180 lines with parallel validation + statistical analysis + batch processing
"""

from __future__ import annotations

import time

from flext_core import FlextResult

from flext_ldif import FlextLdif, FlextLdifModels


class ExampleValidationAnalysis:
    """Demonstrates advanced validation and statistical analysis with parallel processing.

    This class provides examples of flext-ldif validation and analytics capabilities including:
    - Parallel validation processing with comprehensive error analysis
    - Advanced statistical analysis with metrics and insights
    - Batch validation pipelines with detailed reporting
    - Railway-oriented validation with integrated analysis
    - Performance analytics and bottleneck identification
    """

    def parallel_validation_processing(
        self,
    ) -> FlextResult[FlextLdifModels.ValidationResult]:
        """Parallel validation processing with comprehensive error analysis."""
        api = FlextLdif.get_instance()

        # Create large dataset for parallel validation testing
        entries = []

        # Valid entries
        for i in range(50):
            entry_result = api.create_entry(
                dn=f"cn=Valid User {i},ou=People,dc=example,dc=com",
                attributes={
                    "objectClass": ["person", "inetOrgPerson"],
                    "cn": [f"Valid User {i}"],
                    "sn": [f"User{i}"],
                    "mail": [f"user{i}@example.com"],
                    "departmentNumber": ["IT" if i % 2 == 0 else "HR"],
                },
            )
            if entry_result.is_success:
                entries.append(entry_result.unwrap())

        # Invalid entries (missing required attributes)
        for i in range(10):
            entry_result = api.create_entry(
                dn=f"cn=Invalid User {i},ou=People,dc=example,dc=com",
                attributes={
                    "objectClass": ["person"],
                    "cn": [f"Invalid User {i}"],
                    # Missing required 'sn' attribute
                },
            )
            if entry_result.is_success:
                entries.append(entry_result.unwrap())

        # Structurally invalid entries
        for i in range(5):
            entry_result = api.create_entry(
                dn=f"cn=Bad Structure {i},ou=People,dc=example,dc=com",
                attributes={
                    "objectClass": ["person"],
                    "cn": [f"Bad Structure {i}"],
                    "sn": [f"User{i}"],
                    "invalidAttribute": ["should not exist"],  # Invalid attribute
                },
            )
            if entry_result.is_success:
                entries.append(entry_result.unwrap())

        if not entries:
            return FlextResult.fail("Failed to create test entries")

        # Parallel validation processing
        validation_result = api.validate_entries(entries)
        if validation_result.is_failure:
            return FlextResult.fail(
                f"Validation processing failed: {validation_result.error}"
            )

        validation_report = validation_result.unwrap()

        return FlextResult.ok(validation_report)

    def advanced_statistical_analysis(
        self,
    ) -> FlextResult[FlextLdifModels.EntryAnalysisResult]:
        """Advanced statistical analysis with comprehensive metrics and insights."""
        api = FlextLdif.get_instance()

        # Create diverse dataset for statistical analysis
        ldif_content = """dn: cn=Alice Johnson,ou=People,dc=example,dc=com
objectClass: person
objectClass: inetOrgPerson
objectClass: organizationalPerson
cn: Alice Johnson
sn: Johnson
mail: alice.johnson@example.com
telephoneNumber: +1-555-0101
telephoneNumber: +1-555-0102
departmentNumber: IT
employeeNumber: 1001

dn: cn=Bob Williams,ou=People,dc=example,dc=com
objectClass: person
objectClass: inetOrgPerson
cn: Bob Williams
sn: Williams
mail: bob.williams@example.com
departmentNumber: HR
employeeNumber: 1002

dn: cn=Carol Davis,ou=People,dc=example,dc=com
objectClass: person
cn: Carol Davis
sn: Davis
departmentNumber: IT

dn: cn=Admins,ou=Groups,dc=example,dc=com
objectClass: groupOfNames
cn: Admins
member: cn=Alice Johnson,ou=People,dc=example,dc=com
member: cn=Bob Williams,ou=People,dc=example,dc=com
description: System REDACTED_LDAP_BIND_PASSWORDistrators

dn: cn=IT-Group,ou=Groups,dc=example,dc=com
objectClass: groupOfNames
cn: IT-Group
member: cn=Alice Johnson,ou=People,dc=example,dc=com
member: cn=Carol Davis,ou=People,dc=example,dc=com

dn: ou=People,dc=example,dc=com
objectClass: organizationalUnit
ou: People
description: Container for person entries

dn: ou=Groups,dc=example,dc=com
objectClass: organizationalUnit
ou: Groups
description: Container for group entries
"""

        # Parse dataset
        parse_result = api.parse(ldif_content)
        if parse_result.is_failure:
            return FlextResult.fail(f"Parse failed: {parse_result.error}")

        entries = parse_result.unwrap()

        # Perform comprehensive analysis
        analysis_result = api.analyze(entries)
        if analysis_result.is_failure:
            return FlextResult.fail(f"Analysis failed: {analysis_result.error}")

        stats = analysis_result.unwrap()

        return FlextResult.ok(stats)

    def batch_validation_pipeline(self) -> FlextResult[dict[str, object]]:
        """Batch validation pipeline with parallel processing and comprehensive reporting."""
        api = FlextLdif.get_instance()

        # Create multiple batches for testing
        batches = []

        # Batch 1: Valid entries
        batch1 = []
        for i in range(20):
            entry_result = api.create_entry(
                dn=f"cn=Batch1 User {i},ou=People,dc=example,dc=com",
                attributes={
                    "objectClass": ["person", "inetOrgPerson"],
                    "cn": [f"Batch1 User {i}"],
                    "sn": [f"User{i}"],
                    "mail": [f"user{i}@batch1.example.com"],
                },
            )
            if entry_result.is_success:
                batch1.append(entry_result.unwrap())
        batches.append(("valid_batch", batch1))

        # Batch 2: Mixed valid/invalid
        batch2 = []
        for i in range(15):
            # Some valid, some invalid
            is_valid = i % 3 != 0
            attrs: dict[str, str | list[str]] = {
                "objectClass": ["person"],
                "cn": [f"Batch2 User {i}"],
            }
            if is_valid:
                attrs["sn"] = [f"User{i}"]
                attrs["mail"] = [f"user{i}@batch2.example.com"]
            # Invalid entries missing required 'sn'

            entry_result = api.create_entry(
                dn=f"cn=Batch2 User {i},ou=People,dc=example,dc=com",
                attributes=attrs,
            )
            if entry_result.is_success:
                batch2.append(entry_result.unwrap())
        batches.append(("mixed_batch", batch2))

        # Process batches in parallel
        batch_results: dict[str, object] = {}
        total_processed = 0
        total_valid = 0
        total_invalid = 0

        for batch_name, entries in batches:
            if not entries:
                continue

            # Parallel validation for each batch
            validation_result = api.validate_entries(entries)
            if validation_result.is_failure:
                batch_results[f"{batch_name}_error"] = validation_result.error
                continue

            report = validation_result.unwrap()
            batch_results[batch_name] = {
                "entries": len(entries),
                "valid": report.valid_entries,
                "invalid": report.invalid_entries,
                "error_count": len(report.errors),
            }

            total_processed += len(entries)
            total_valid += report.valid_entries
            total_invalid += report.invalid_entries

        # Overall statistics
        batch_results["summary"] = {
            "total_batches": len(batches),
            "total_entries": total_processed,
            "total_valid": total_valid,
            "total_invalid": total_invalid,
            "overall_validity_rate": total_valid / total_processed
            if total_processed > 0
            else 0,
        }

        return FlextResult.ok(batch_results)

    def railway_validation_with_analysis(self) -> FlextResult[dict[str, object]]:
        """Railway-oriented validation pipeline with integrated analysis."""
        api = FlextLdif.get_instance()

        # Complex dataset with various validation scenarios
        ldif_content = """dn: cn=Complete User,ou=People,dc=example,dc=com
objectClass: person
objectClass: inetOrgPerson
objectClass: organizationalPerson
cn: Complete User
sn: Complete
mail: complete@example.com
telephoneNumber: +1-555-0123
telephoneNumber: +1-555-0456
departmentNumber: Engineering
employeeNumber: EMP001
manager: cn=Manager,ou=People,dc=example,dc=com

dn: cn=Minimal User,ou=People,dc=example,dc=com
objectClass: person
cn: Minimal User
sn: Minimal

dn: cn=Invalid User,ou=People,dc=example,dc=com
objectClass: person
cn: Invalid User
# Missing required sn attribute

dn: cn=Complex Group,ou=Groups,dc=example,dc=com
objectClass: groupOfNames
cn: Complex Group
member: cn=Complete User,ou=People,dc=example,dc=com
member: cn=Minimal User,ou=People,dc=example,dc=com
member: cn=Manager,ou=People,dc=example,dc=com
description: Complex group with multiple members

dn: ou=People,dc=example,dc=com
objectClass: organizationalUnit
ou: People

dn: ou=Groups,dc=example,dc=com
objectClass: organizationalUnit
ou: Groups
"""

        # Railway Step 1: Parse with auto-detection
        parse_result = api.parse(ldif_content)
        if parse_result.is_failure:
            return FlextResult.fail(f"Parse failed: {parse_result.error}")

        entries = parse_result.unwrap()

        # Railway Step 2: Parallel validation
        validation_result = api.validate_entries(entries)
        if validation_result.is_failure:
            return FlextResult.fail(f"Validation failed: {validation_result.error}")

        validation_report = validation_result.unwrap()
        if not validation_report.is_valid:
            return FlextResult.fail(
                f"Validation errors found: {len(validation_report.errors)} errors"
            )

        # Railway Step 3: Comprehensive analysis
        analysis_result = api.analyze(entries)
        if analysis_result.is_failure:
            return FlextResult.fail(f"Analysis failed: {analysis_result.error}")

        stats = analysis_result.unwrap()

        # Railway Step 4: Advanced filtering based on analysis
        filter_results = {}

        # Filter by objectClass distribution
        for oc in stats.objectclass_distribution:
            oc_str = str(oc)
            filter_result = api.filter(entries, objectclass=oc_str)
            if filter_result.is_success:
                filter_results[f"{oc_str}_entries"] = len(filter_result.unwrap())

        # Railway Step 5: Parallel processing of filtered results
        person_entries_result = api.filter(entries, objectclass="person")
        if person_entries_result.is_success:
            person_entries = person_entries_result.unwrap()
            transform_result = api.process(
                "transform", person_entries, parallel=True, max_workers=4
            )
            if transform_result.is_success:
                transformed_count = len(transform_result.unwrap())
            else:
                transformed_count = 0
        else:
            transformed_count = 0

        return FlextResult.ok({
            "total_entries": len(entries),
            "validation_passed": validation_report.valid_entries,
            "validation_failed": validation_report.invalid_entries,
            "objectclass_distribution": dict(stats.objectclass_distribution),
            "filter_results": filter_results,
            "parallel_transformed": transformed_count,
            "unique_objectclasses": stats.unique_objectclasses,
        })

    def performance_analytics_pipeline(self) -> FlextResult[dict[str, object]]:
        """Performance analytics with bottleneck identification."""
        api = FlextLdif.get_instance()

        # Create large dataset for performance testing
        entries = []
        for i in range(100):
            # Create variety of entry types
            if i % 10 == 0:
                # OU entries
                entry_result = api.create_entry(
                    dn=f"ou=Container{i},dc=example,dc=com",
                    attributes={
                        "objectClass": ["organizationalUnit"],
                        "ou": [f"Container{i}"],
                    },
                )
            elif i % 5 == 0:
                # Group entries
                entry_result = api.create_entry(
                    dn=f"cn=Group{i},ou=Groups,dc=example,dc=com",
                    attributes={
                        "objectClass": ["groupOfNames"],
                        "cn": [f"Group{i}"],
                        "member": [
                            f"cn=User{j},ou=People,dc=example,dc=com" for j in range(5)
                        ],
                    },
                )
            else:
                # Person entries
                entry_result = api.create_entry(
                    dn=f"cn=Perf User{i},ou=People,dc=example,dc=com",
                    attributes={
                        "objectClass": ["person", "inetOrgPerson"],
                        "cn": [f"Perf User{i}"],
                        "sn": [f"User{i}"],
                        "mail": [f"user{i}@perf.example.com"],
                        "departmentNumber": ["Dept"],
                    },
                )

            if entry_result.is_success:
                entries.append(entry_result.unwrap())

        if not entries:
            return FlextResult.fail("Failed to create performance test entries")

        performance_results: dict[str, object] = {}

        # Performance test: Parallel validation
        start_time = time.time()
        validation_result = api.validate_entries(entries)
        validation_time = time.time() - start_time

        if validation_result.is_success:
            report = validation_result.unwrap()
            performance_results["validation"] = {
                "entries_processed": len(entries),
                "time_seconds": validation_time,
                "entries_per_second": len(entries) / validation_time
                if validation_time > 0
                else 0,
                "valid_entries": report.valid_entries,
                "invalid_entries": report.invalid_entries,
            }

        # Performance test: Parallel analysis
        start_time = time.time()
        analysis_result = api.analyze(entries)
        analysis_time = time.time() - start_time

        if analysis_result.is_success:
            stats = analysis_result.unwrap()
            performance_results["analysis"] = {
                "entries_processed": len(entries),
                "time_seconds": analysis_time,
                "entries_per_second": len(entries) / analysis_time
                if analysis_time > 0
                else 0,
                "objectclasses_found": len(stats.objectclass_distribution),
                "patterns_detected": len(stats.patterns_detected),
            }

        # Performance test: Parallel transformation
        start_time = time.time()
        transform_result = api.process(
            "transform", entries, parallel=True, max_workers=8
        )
        transform_time = time.time() - start_time

        if transform_result.is_success:
            performance_results["parallel_transform"] = {
                "entries_processed": len(entries),
                "time_seconds": transform_time,
                "entries_per_second": len(entries) / transform_time
                if transform_time > 0
                else 0,
                "workers_used": 8,
            }

        return FlextResult.ok(performance_results)
