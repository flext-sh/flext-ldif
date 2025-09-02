"""Enterprise examples demonstrating all flext-ldif functionality.

This module provides comprehensive examples showing how to use flext-ldif
in enterprise scenarios with real-world LDIF processing tasks.
"""

from __future__ import annotations

import tempfile
import time
from pathlib import Path

from flext_core import FlextLogger

from flext_ldif import (
    FlextLDIFAPI,
    FlextLDIFConfig,
    FlextLDIFCore,
    FlextLDIFEntry,
    FlextLDIFFormatHandler,
)

logger = FlextLogger(__name__)


def example_basic_ldif_processing() -> None:
    """Demonstrate basic LDIF parsing, validation, and writing."""
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

    # Using modern FlextLDIFAPI functionality
    api = FlextLDIFAPI()
    parse_result = api.parse(ldif_content)

    # Use railway programming for cleaner flow - modern FlextResult pattern
    if parse_result.is_success:
        entries = parse_result.value
    else:
        return

    if entries:
        # Validate entries with railway programming
        api.validate(entries).tap(
            lambda _: logger.info("Validation successful")
        ).tap_error(lambda error: logger.error(f"Validation failed: {error}"))

        # Write back to LDIF with railway programming
        api.write(entries).tap(lambda _: logger.info("Write successful")).tap_error(
            lambda error: logger.error(f"Write failed: {error}")
        )


def example_api_usage() -> None:
    """Demonstrate using ``FlextLDIFAPI`` for advanced processing."""
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
    config = FlextLDIFConfig.model_validate(
        {
            "strict_validation": True,
            "max_entries": 100,
        },
    )
    api = FlextLDIFAPI(config)

    # Railway programming chain for parsing and filtering - modern pattern
    parse_result = api.parse(ldif_content)
    if not parse_result.is_success:
        return
    entries = parse_result.value

    if entries:
        # Filter person entries with railway programming - modern pattern
        person_filter_result = api.filter_persons(entries)
        if person_filter_result.is_success:
            person_entries = person_filter_result.value
        else:
            person_entries = []
        for _entry in person_entries:
            pass  # Process each person entry

        # Filter by objectClass
        api.filter_by_objectclass(entries, "inetOrgPerson")

        # Find specific entry by DN
        target_dn = "cn=Alice Johnson,ou=people,dc=company,dc=com"
        found_entry = api.find_entry_by_dn(entries, target_dn)
        if found_entry:
            pass

        # Sort hierarchically with railway programming - modern pattern
        sort_result = api.sort_hierarchically(entries)
        sorted_entries = sort_result.value if sort_result.is_success else entries
        for entry in sorted_entries:
            str(entry.dn).count(",")


def example_file_operations() -> None:
    """Demonstrate file-based LDIF operations."""
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
    with tempfile.NamedTemporaryFile(
        encoding="utf-8",
        mode="w",
        delete=False,
        suffix=".ldif",
    ) as input_file:
        input_file.write(ldif_content)
        input_path = Path(input_file.name)

    with tempfile.NamedTemporaryFile(delete=False, suffix=".ldif") as output_file:
        output_path = Path(output_file.name)

    try:
        # Using modern FlextLDIFAPI for file operations with railway programming
        api = FlextLDIFAPI()
        api.parse_file(input_path).flat_map(api.filter_persons).flat_map(
            lambda person_entries: api.write_file(person_entries, output_path)
        ).tap(lambda _: logger.info(f"Wrote filtered entries to {output_path}"))

        # Using API for file operations with railway programming
        api.parse_file(input_path).tap(lambda _: None)

    finally:
        # Cleanup
        input_path.unlink(missing_ok=True)
        output_path.unlink(missing_ok=True)


def example_convenience_functions() -> None:
    """Demonstrate convenience functions for simple tasks."""
    ldif_content = """dn: cn=convenience,dc=example,dc=com
objectClass: person
cn: convenience
sn: example
mail: convenience@example.com

"""

    # Parse using convenience function
    entries = FlextLDIFFormatHandler.parse_ldif(ldif_content).unwrap_or_raise()

    # Validate using convenience function - parse first, then validate
    FlextLDIFCore().validate_entries(entries).unwrap_or_raise()

    # Write using convenience function
    FlextLDIFFormatHandler.write_ldif(entries).unwrap_or_raise()

    # Global API instance with railway programming
    FlextLDIFAPI().parse(ldif_content).tap(lambda _: None)


def example_configuration_scenarios() -> None:
    """Demonstrate different configuration scenarios."""
    # Test content with multiple entries
    large_ldif = ""
    for i in range(15):
        large_ldif += f"""dn: cn=user{i:02d},ou=people,dc=config,dc=com
objectClass: person
cn: user{i:02d}
sn: user{i:02d}

"""

    strict_config = FlextLDIFConfig.model_validate(
        {
            "strict_validation": True,
            "max_entries": 10,
            "max_entry_size": 1024,
        },
    )

    strict_api = FlextLDIFAPI(strict_config)
    strict_api.parse(large_ldif).tap(lambda _: None)

    permissive_config = FlextLDIFConfig.model_validate(
        {
            "strict_validation": False,
            "max_entries": 100,
            "max_entry_size": 10240,
        },
    )

    permissive_api = FlextLDIFAPI(permissive_config)
    permissive_api.parse(large_ldif).tap(lambda _: None)


def example_error_handling() -> None:
    """Demonstrate proper error handling patterns."""
    # Invalid LDIF content
    invalid_ldif = """This is not LDIF content
It has no proper structure
And should fail parsing"""

    # Use railway programming for error handling
    api = FlextLDIFAPI()
    api.parse(invalid_ldif).tap_error(lambda _: None)

    # File not found error
    nonexistent_file = Path("/nonexistent/path/file.ldif")
    api.parse_file(nonexistent_file).tap_error(lambda _: None)

    # Validation errors
    incomplete_ldif = """dn: cn=incomplete,dc=example,dc=com
cn: incomplete
# Missing objectClass"""

    api = FlextLDIFAPI()
    # Railway programming for validation chain
    api.parse(incomplete_ldif).flat_map(api.validate).tap_error(lambda _: None)


def _parse_sample_ldif_data() -> str:
    """Provide sample LDIF data for advanced filtering demonstration."""
    return """dn: dc=advanced,dc=com
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


def _demonstrate_basic_object_class_filtering(
    api: FlextLDIFAPI,
    entries: list[FlextLDIFEntry],
    person_entries: list[FlextLDIFEntry],
) -> None:
    """Demonstrate basic object class filtering operations."""
    # Touch parameter to demonstrate usage in examples and satisfy linters
    _ = len(person_entries)
    # inetOrgPerson entries (more specific)
    api.filter_by_objectclass(entries, "inetOrgPerson")

    # Group entries
    api.filter_by_objectclass(entries, "groupOfNames")

    # Organizational units
    api.filter_by_objectclass(entries, "organizationalUnit")


def _filter_by_title_containing(
    entries: list[FlextLDIFEntry], keyword: str
) -> list[FlextLDIFEntry]:
    """Custom filter for entries with title containing keyword."""
    result: list[FlextLDIFEntry] = []
    for entry in entries:
        title_attr = entry.get_attribute("title")
        if title_attr and any(keyword.lower() in title.lower() for title in title_attr):
            result.append(entry)
    return result


def _demonstrate_custom_title_filtering(person_entries: list[FlextLDIFEntry]) -> None:
    """Demonstrate custom filtering by title keywords."""
    _filter_by_title_containing(person_entries, "engineer")
    _filter_by_title_containing(person_entries, "manager")


def _determine_entry_type(entry: FlextLDIFEntry) -> str:
    """Determine the type of an LDAP entry based on object classes."""
    has_object_class = entry.has_object_class
    if has_object_class("domain"):
        return "domain"
    if has_object_class("organizationalUnit"):
        return "OU"
    if has_object_class("person"):
        return "person"
    if has_object_class("groupOfNames"):
        return "group"
    return "other"


def _demonstrate_hierarchical_analysis(
    api: FlextLDIFAPI,
    entries: list[FlextLDIFEntry],
) -> None:
    """Demonstrate hierarchical analysis and entry categorization."""

    def print_hierarchy(sorted_entries: list[FlextLDIFEntry]) -> None:
        for entry in sorted_entries:
            "   " + "  " * str(entry.dn).count(",")
            _determine_entry_type(entry)

    api.sort_hierarchically(entries).tap(print_hierarchy)


def example_advanced_filtering() -> None:
    """Demonstrate advanced filtering and processing."""
    complex_ldif = _parse_sample_ldif_data()

    api = FlextLDIFAPI()
    parse_result = api.parse(complex_ldif)

    # Use railway programming with chaining
    def demonstrate_all_filtering(entries: list[FlextLDIFEntry]) -> None:
        person_filter_result = api.filter_persons(entries)
        person_entries = person_filter_result.unwrap_or([])
        _demonstrate_basic_object_class_filtering(api, entries, person_entries)
        _demonstrate_custom_title_filtering(person_entries)
        _demonstrate_hierarchical_analysis(api, entries)

    parse_result.tap(demonstrate_all_filtering)


def example_performance_monitoring() -> None:
    """Demonstrate performance monitoring and optimization."""
    # Generate larger dataset
    large_ldif = (
        "dn: dc=perf,dc=com\nobjectClass: top\nobjectClass: domain\ndc: perf\n\n"
    )

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

    # Measure parsing performance with railway programming
    start_time = time.time()
    api = FlextLDIFAPI()

    def measure_performance(entries: list[FlextLDIFEntry]) -> None:
        time.time() - start_time

        filter_start = time.time()
        person_filter_result = api.filter_persons(entries)
        person_entries = person_filter_result.unwrap_or([])
        time.time() - filter_start

        write_start = time.time()
        api.write(person_entries)
        time.time() - write_start

    api.parse(large_ldif).tap(measure_performance)


def main() -> None:
    """Run all enterprise examples."""
    # Run all examples
    example_basic_ldif_processing()
    example_api_usage()
    example_file_operations()
    example_convenience_functions()
    example_configuration_scenarios()
    example_error_handling()
    example_advanced_filtering()
    example_performance_monitoring()


if __name__ == "__main__":
    main()
