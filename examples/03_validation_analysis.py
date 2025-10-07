"""Example 3: Entry Validation and Analysis.

Demonstrates FlextLdif validation and analytics functionality:
- Validating entries against RFC 2849 rules
- Generating entry statistics and analysis
- Railway-oriented validation pipelines
- Error handling for validation failures

All functionality accessed through FlextLdif facade.
"""

from __future__ import annotations

from flext_ldif import FlextLdif


def validate_entries() -> None:
    """Validate LDIF entries against RFC rules."""
    api = FlextLdif.get_instance()

    # Create entries for validation
    valid_entry = api.models.Entry(
        dn="cn=Valid User,ou=People,dc=example,dc=com",
        attributes={
            "objectClass": ["person", "inetOrgPerson"],
            "cn": ["Valid User"],
            "sn": ["User"],
            "mail": ["valid@example.com"],
        },
    )

    # Entry potentially missing required attributes
    questionable_entry = api.models.Entry(
        dn="cn=Test,ou=People,dc=example,dc=com",
        attributes={
            "objectClass": ["person"],
            "cn": ["Test"],
            # May be missing 'sn' required by person objectClass
        },
    )

    entries = [valid_entry, questionable_entry]

    # Validate entries
    validation_result = api.validate_entries(entries)

    if validation_result.is_success:
        report = validation_result.unwrap()
        # Validation report contains details
        is_valid = report.get("is_valid", False)
        errors = report.get("errors", [])
        warnings = report.get("warnings", [])
        _ = (is_valid, errors, warnings)
    else:
        _ = validation_result.error


def analyze_entries() -> None:
    """Generate statistics and analysis for entries."""
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

    parse_result = api.parse(ldif_content)

    if parse_result.is_failure:
        return

    entries = parse_result.unwrap()

    # Analyze entries
    analysis_result = api.analyze(entries)

    if analysis_result.is_success:
        stats = analysis_result.unwrap()

        # Analysis contains comprehensive statistics
        total_entries = stats.get("total_entries", 0)
        entry_types = stats.get("entry_types", {})
        objectclass_distribution = stats.get("objectclass_distribution", {})
        attribute_usage = stats.get("attribute_usage", {})

        _ = (total_entries, entry_types, objectclass_distribution, attribute_usage)
    else:
        _ = analysis_result.error


def railway_validation_pipeline() -> None:
    """Demonstrate validation pipeline with early failure detection."""
    api = FlextLdif.get_instance()

    ldif_content = """dn: cn=Pipeline,ou=People,dc=example,dc=com
objectClass: person
objectClass: inetOrgPerson
cn: Pipeline
sn: Test
mail: pipeline@example.com
"""

    # Parse
    parse_result = api.parse(ldif_content)
    if parse_result.is_failure:
        _ = parse_result.error
        return

    entries = parse_result.unwrap()

    # Validate
    validation_result = api.validate_entries(entries)
    if validation_result.is_failure:
        _ = validation_result.error
        return

    validation_report = validation_result.unwrap()

    if not validation_report.get("is_valid", False):
        # Validation failed - handle errors
        _ = validation_report.get("errors", [])
        return

    # Analyze valid entries
    analysis_result = api.analyze(entries)
    if analysis_result.is_failure:
        _ = analysis_result.error
        return

    stats = analysis_result.unwrap()

    # Pipeline succeeded - all operations passed
    _ = stats


def validate_and_filter_valid_entries() -> None:
    """Validate entries and filter to keep only valid ones."""
    api = FlextLdif.get_instance()

    # Mix of valid and potentially invalid entries
    entries = [
        api.models.Entry(
            dn="cn=Valid1,ou=People,dc=example,dc=com",
            attributes={
                "objectClass": ["person"],
                "cn": ["Valid1"],
                "sn": ["One"],
            },
        ),
        api.models.Entry(
            dn="cn=Valid2,ou=People,dc=example,dc=com",
            attributes={
                "objectClass": ["person"],
                "cn": ["Valid2"],
                "sn": ["Two"],
            },
        ),
        api.models.Entry(
            dn="cn=MaybeInvalid,ou=People,dc=example,dc=com",
            attributes={
                "objectClass": ["person"],
                "cn": ["MaybeInvalid"],
                # Potentially missing required 'sn'
            },
        ),
    ]

    # Validate all entries
    validation_result = api.validate_entries(entries)

    if validation_result.is_success:
        report = validation_result.unwrap()

        if report.get("is_valid", False):
            # All entries are valid
            _ = entries
        else:
            # Some entries have validation errors
            # In a real scenario, you'd filter based on specific errors
            errors = report.get("errors", [])
            _ = errors


def analyze_by_objectclass() -> None:
    """Analyze entries grouped by objectClass."""
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

    parse_result = api.parse(ldif_content)

    if parse_result.is_failure:
        return

    entries = parse_result.unwrap()

    # First analyze to get distribution
    analysis_result = api.analyze(entries)

    if analysis_result.is_failure:
        return

    stats = analysis_result.unwrap()
    objectclass_dist = stats.get("objectclass_distribution", {})

    # Then filter by specific objectClass
    for objectclass in objectclass_dist:
        filter_result = api.filter_by_objectclass(entries, objectclass)

        if filter_result.is_success:
            filtered = filter_result.unwrap()
            _ = (objectclass, len(filtered))
