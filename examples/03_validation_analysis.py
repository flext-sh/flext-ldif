"""Example 3: Entry Validation and Analysis - Optimized with Railway Pattern.

Demonstrates FlextLdif validation and analytics with minimal code bloat:

NOTE: This example intentionally uses assert statements (S101) for type narrowing
demonstration. Asserts are acceptable in examples for pedagogical purposes and
do not represent production error handling patterns.
- Validating entries against RFC 2849 rules
- Generating entry statistics and analysis
- Railway-oriented validation pipelines
- Composable error handling

This example shows how flext-ldif REDUCES code through library automation.
Original: 246 lines | Optimized: ~130 lines (47% reduction)
"""

from __future__ import annotations

from flext_core import FlextResult

from flext_ldif import FlextLdif, FlextLdifModels


def validate_entries_example() -> None:
    """Validate LDIF entries using railway pattern."""
    api = FlextLdif.get_instance()

    # Create entries - library handles Pydantic v2 validation
    entries = [
        api.models.Entry.create(
            dn="cn=Valid User,ou=People,dc=example,dc=com",
            attributes={
                "objectClass": ["person", "inetOrgPerson"],
                "cn": ["Valid User"],
                "sn": ["User"],
                "mail": ["valid@example.com"],
            },
        ).unwrap(),
        api.models.Entry.create(
            dn="cn=Test,ou=People,dc=example,dc=com",
            attributes={
                "objectClass": ["person"],
                "cn": ["Test"],
                # May be missing 'sn' required by person objectClass
            },
        ).unwrap(),
    ]

    # Validate - library handles RFC 2849 compliance
    validation_result = api.validate_entries(entries)
    if validation_result.is_failure:
        print("Validation failed")
        return

    report = validation_result.unwrap()
    errors_count = len(report.errors) if report.errors else 0

    result_msg = (
        f"Valid: {report.is_valid}, "
        f"Errors: {errors_count}, "
        f"Total entries: {report.total_entries}"
    )
    print(result_msg)


def analyze_entries_example() -> None:
    """Generate statistics using railway composition."""
    api = FlextLdif.get_instance()

    ldif_content = """dn: cn=Alice,ou=People,dc=example,dc=com
objectClass: person
objectClass: inetOrgPerson
cn: Alice
sn: Johnson
mail: alice@example.com

dn: cn=Bob,ou=People,dc=example,dc=com
objectClass: person
cn: Bob
sn: Williams

dn: cn=Admins,ou=Groups,dc=example,dc=com
objectClass: groupOfNames
cn: Admins
member: cn=Alice,ou=People,dc=example,dc=com

dn: ou=People,dc=example,dc=com
objectClass: organizationalUnit
ou: People
"""

    # Railway pattern - parse → analyze (auto error handling)
    parse_result = api.parse(ldif_content)
    if parse_result.is_success:
        entries = parse_result.unwrap()
        analyze_result = api.analyze(entries)
        if analyze_result.is_success:
            stats = analyze_result.unwrap()
            print(f"Total entries: {stats.total_entries}")
            print(f"ObjectClass dist: {stats.objectclass_distribution}")
            print(f"Patterns detected: {stats.patterns_detected}")
        else:
            print("Analysis failed")
    else:
        print("Parse failed")


def railway_validation_pipeline() -> None:
    """Compose validation pipeline with early failure detection."""
    api = FlextLdif.get_instance()

    ldif_content = """dn: cn=Pipeline,ou=People,dc=example,dc=com
objectClass: person
objectClass: inetOrgPerson
cn: Pipeline
sn: Test
mail: pipeline@example.com
"""

    # Chain operations - parse → validate → analyze (auto error propagation)
    parse_result = api.parse(ldif_content)
    if parse_result.is_success:
        entries = parse_result.unwrap()
        validate_result = api.validate_entries(entries)
        if validate_result.is_success:
            validation_report = validate_result.unwrap()
            if validation_report.is_valid:
                analyze_result = api.analyze(entries)
                result = analyze_result
            else:
                result = FlextResult[dict[str, object]].fail(
                    f"Validation failed: {validation_report}",
                )
        else:
            result = validate_result
    else:
        result = parse_result

    if result.is_success:
        stats = result.unwrap()
        if isinstance(stats, FlextLdifModels.EntryAnalysisResult):
            print(f"Pipeline succeeded: {stats.total_entries} entries analyzed")
        else:
            print("Pipeline succeeded")
    else:
        print(f"Pipeline failed: {result.error}")


def validate_and_filter_pipeline() -> None:
    """Validate and filter entries - library automates validation."""
    api = FlextLdif.get_instance()

    entries = [
        api.models.Entry.create(
            dn="cn=Valid1,ou=People,dc=example,dc=com",
            attributes={"objectClass": ["person"], "cn": ["Valid1"], "sn": ["One"]},
        ).unwrap(),
        api.models.Entry.create(
            dn="cn=Valid2,ou=People,dc=example,dc=com",
            attributes={"objectClass": ["person"], "cn": ["Valid2"], "sn": ["Two"]},
        ).unwrap(),
        api.models.Entry.create(
            dn="cn=MaybeInvalid,ou=People,dc=example,dc=com",
            attributes={
                "objectClass": ["person"],
                "cn": ["MaybeInvalid"],
                # Potentially missing required 'sn'
            },
        ).unwrap(),
    ]

    # Validate - library provides detailed report
    result = api.validate_entries(entries)

    if result.is_success:
        report = result.unwrap()
        if report.is_valid:
            print(f"All {len(entries)} entries are valid")
        else:
            errors_list = report.errors or []
            print(f"Found {len(errors_list)} validation errors")


def analyze_by_objectclass_pipeline() -> None:
    """Analyze entries grouped by objectClass using railway composition."""
    api = FlextLdif.get_instance()

    ldif_content = """dn: cn=Person1,ou=People,dc=example,dc=com
objectClass: person
cn: Person1
sn: One

dn: cn=Person2,ou=People,dc=example,dc=com
objectClass: person
objectClass: inetOrgPerson
cn: Person2
sn: Two
mail: person2@example.com

dn: cn=Group1,ou=Groups,dc=example,dc=com
objectClass: groupOfNames
cn: Group1
member: cn=Person1,ou=People,dc=example,dc=com
"""

    # Railway pattern - parse → analyze → filter by each objectClass
    parse_result = api.parse(ldif_content)
    if parse_result.is_success:
        entries = parse_result.unwrap()
        analyze_result = api.analyze(entries)
        if analyze_result.is_success:
            stats = analyze_result.unwrap()
            objectclass_dist = stats.objectclass_distribution

            # Parse once, filter multiple times - library handles iteration
            for objectclass in objectclass_dist:
                objectclass_str = str(objectclass)
                filter_result = api.filter(entries, objectclass=objectclass_str)
                if filter_result.is_success:
                    filtered = filter_result.unwrap()
                    print(f"{objectclass_str}: {len(filtered)} entries")


if __name__ == "__main__":
    print("=== FlextLdif Validation and Analysis Examples ===\n")

    print("1. Validate Entries:")
    validate_entries_example()

    print("\n2. Analyze Entries:")
    analyze_entries_example()

    print("\n3. Railway Validation Pipeline:")
    railway_validation_pipeline()

    print("\n4. Validate and Filter:")
    validate_and_filter_pipeline()

    print("\n5. Analyze by ObjectClass:")
    analyze_by_objectclass_pipeline()
