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

from typing import cast

from flext_core import FlextResult

from flext_ldif import FlextLdif
from flext_ldif.models import FlextLdifModels


def validate_entries_example() -> None:
    """Validate LDIF entries using railway pattern."""
    api = FlextLdif.get_instance()

    # Create entries - api.models.Entry.create() returns FlextLdifModelsDomains.Entry
    # but FlextLdifModels.Entry inherits from it, so cast is safe
    entry1_result = api.models.Entry.create(
        dn="cn=Valid User,ou=People,dc=example,dc=com",
        attributes={
            "objectClass": ["person", "inetOrgPerson"],
            "cn": ["Valid User"],
            "sn": ["User"],
            "mail": ["valid@example.com"],
        },
    )
    if entry1_result.is_failure:
        return
    entry1 = cast("FlextLdifModels.Entry", entry1_result.unwrap())

    entry2_result = api.models.Entry.create(
        dn="cn=Test,ou=People,dc=example,dc=com",
        attributes={
            "objectClass": ["person"],
            "cn": ["Test"],
            # May be missing 'sn' required by person objectClass
        },
    )
    if entry2_result.is_failure:
        return
    entry2 = cast("FlextLdifModels.Entry", entry2_result.unwrap())

    entries = [entry1, entry2]

    # Validate - library handles RFC 2849 compliance
    validation_result = api.validate_entries(entries)
    if validation_result.is_failure:
        return

    report = validation_result.unwrap()
    len(report.errors) if report.errors else 0


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
            analyze_result.unwrap()


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
                result = cast("FlextResult[object]", analyze_result)
            else:
                result = cast(
                    "FlextResult[object]",
                    FlextResult[dict[str, object]].fail(
                        f"Validation failed: {validation_report}",
                    ),
                )
        else:
            result = cast("FlextResult[object]", validate_result)
    else:
        result = cast("FlextResult[object]", parse_result)

    if result.is_success:
        stats = result.unwrap()
        if isinstance(stats, FlextLdifModels.EntryAnalysisResult):
            pass


def validate_and_filter_pipeline() -> None:
    """Validate and filter entries - library automates validation."""
    api = FlextLdif.get_instance()

    # Create entries - api.models.Entry.create() returns FlextLdifModelsDomains.Entry
    # but FlextLdifModels.Entry inherits from it, so cast is safe
    entry1_result = api.models.Entry.create(
        dn="cn=Valid1,ou=People,dc=example,dc=com",
        attributes={"objectClass": ["person"], "cn": ["Valid1"], "sn": ["One"]},
    )
    if entry1_result.is_failure:
        return
    entry1 = cast("FlextLdifModels.Entry", entry1_result.unwrap())

    entry2_result = api.models.Entry.create(
        dn="cn=Valid2,ou=People,dc=example,dc=com",
        attributes={"objectClass": ["person"], "cn": ["Valid2"], "sn": ["Two"]},
    )
    if entry2_result.is_failure:
        return
    entry2 = cast("FlextLdifModels.Entry", entry2_result.unwrap())

    entry3_result = api.models.Entry.create(
        dn="cn=MaybeInvalid,ou=People,dc=example,dc=com",
        attributes={
            "objectClass": ["person"],
            "cn": ["MaybeInvalid"],
            # Potentially missing required 'sn'
        },
    )
    if entry3_result.is_failure:
        return
    entry3 = cast("FlextLdifModels.Entry", entry3_result.unwrap())

    entries = [entry1, entry2, entry3]

    # Validate - library provides detailed report
    result = api.validate_entries(entries)

    if result.is_success:
        report = result.unwrap()
        if report.is_valid:
            pass


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
                    filter_result.unwrap()


if __name__ == "__main__":
    validate_entries_example()

    analyze_entries_example()

    railway_validation_pipeline()

    validate_and_filter_pipeline()

    analyze_by_objectclass_pipeline()
