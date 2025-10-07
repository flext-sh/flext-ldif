"""Example 5: Schema Building and Validation.

Demonstrates FlextLdif schema-related functionality:
- Building schema definitions with SchemaBuilder
- Validating entries against schemas with SchemaValidator
- Creating standard schemas (person, group)
- Custom schema definitions
- Schema-based entry validation

All functionality accessed through FlextLdif facade.
"""

from __future__ import annotations

from flext_ldif import FlextLdif


def build_basic_schema() -> None:
    """Build a basic schema definition."""
    api = FlextLdif.get_instance()

    # Access SchemaBuilder through API
    builder = api.SchemaBuilder(server_type="rfc")

    # Add attribute definitions
    builder.add_attribute(
        name="cn",
        description="Common Name",
        syntax="1.3.6.1.4.1.1466.115.121.1.15",  # DirectoryString
        single_value=False,
    )

    builder.add_attribute(
        name="sn",
        description="Surname",
        syntax="1.3.6.1.4.1.1466.115.121.1.15",
        single_value=False,
    )

    builder.add_attribute(
        name="mail",
        description="Email Address",
        syntax="1.3.6.1.4.1.1466.115.121.1.26",  # IA5String
        single_value=False,
    )

    # Add objectClass definition
    builder.add_object_class(
        name="person",
        description="Person object class",
        superior="top",
        structural=True,
        required_attributes=["cn", "sn"],
        optional_attributes=["mail"],
    )

    # Build schema
    schema_result = builder.build()

    if schema_result.is_success:
        schema = schema_result.unwrap()
        attributes = schema.get("attributes", {})
        object_classes = schema.get("object_classes", {})
        _ = (attributes, object_classes)


def build_standard_person_schema() -> None:
    """Build standard person schema using helper method."""
    api = FlextLdif.get_instance()

    builder = api.SchemaBuilder(server_type="rfc")

    # Use standard person schema builder
    schema_result = builder.build_standard_person_schema()

    if schema_result.is_success:
        schema = schema_result.unwrap()
        # Schema contains standard person attributes and objectClass
        _ = schema


def build_standard_group_schema() -> None:
    """Build standard group schema using helper method."""
    api = FlextLdif.get_instance()

    builder = api.SchemaBuilder(server_type="rfc")

    # Use standard group schema builder
    schema_result = builder.build_standard_group_schema()

    if schema_result.is_success:
        schema = schema_result.unwrap()
        # Schema contains standard group attributes and objectClass
        _ = schema


def build_custom_schema() -> None:
    """Build a custom schema with multiple objectClasses."""
    api = FlextLdif.get_instance()

    builder = api.SchemaBuilder(server_type="rfc")

    # Add custom attributes
    builder.add_attribute(
        name="employeeNumber",
        description="Employee Identifier",
        syntax="1.3.6.1.4.1.1466.115.121.1.15",
        single_value=True,
    )

    builder.add_attribute(
        name="department",
        description="Department Name",
        syntax="1.3.6.1.4.1.1466.115.121.1.15",
        single_value=False,
    )

    # Add custom objectClass
    builder.add_object_class(
        name="employee",
        description="Employee object class",
        superior="person",
        structural=True,
        required_attributes=["employeeNumber"],
        optional_attributes=["department"],
    )

    # Build complete schema
    schema_result = builder.build()

    if schema_result.is_success:
        schema = schema_result.unwrap()
        _ = schema


def validate_entries_with_schema() -> None:
    """Validate entries using SchemaValidator."""
    api = FlextLdif.get_instance()

    # Create test entries
    valid_entry = api.models.Entry(
        dn="cn=Valid,ou=People,dc=example,dc=com",
        attributes={
            "objectClass": ["person"],
            "cn": ["Valid"],
            "sn": ["User"],
        },
    )

    # Entry missing required 'sn' attribute
    invalid_entry = api.models.Entry(
        dn="cn=Invalid,ou=People,dc=example,dc=com",
        attributes={
            "objectClass": ["person"],
            "cn": ["Invalid"],
            # Missing 'sn'
        },
    )

    entries = [valid_entry, invalid_entry]

    # Access SchemaValidator through API
    validator = api.SchemaValidator()

    # Validate entries
    validation_result = validator.validate_entries(entries)

    if validation_result.is_success:
        report = validation_result.unwrap()

        is_valid = report.get("is_valid", False)
        errors = report.get("errors", [])
        valid_count = report.get("valid_entries", 0)
        invalid_count = report.get("invalid_entries", 0)

        _ = (is_valid, errors, valid_count, invalid_count)


def validate_single_entry_against_schema() -> None:
    """Validate a single entry against schema requirements."""
    api = FlextLdif.get_instance()

    entry = api.models.Entry(
        dn="cn=Test,ou=People,dc=example,dc=com",
        attributes={
            "objectClass": ["person", "inetOrgPerson"],
            "cn": ["Test"],
            "sn": ["User"],
            "mail": ["test@example.com"],
        },
    )

    validator = api.SchemaValidator()

    # Validate single entry
    validation_result = validator.validate_entry_against_schema(entry)

    if validation_result.is_success:
        result = validation_result.unwrap()

        is_valid = result.get("is_valid", False)
        errors = result.get("errors", [])

        _ = (is_valid, errors)


def schema_building_pipeline() -> None:
    """Complete pipeline: build schema, create entries, validate."""
    api = FlextLdif.get_instance()

    # Build schema
    builder = api.SchemaBuilder(server_type="rfc")
    schema_result = builder.build_standard_person_schema()

    if schema_result.is_failure:
        return

    # Create entry
    entry_builder = api.EntryBuilder()
    person_result = entry_builder.build_person_entry(
        cn="Pipeline User",
        sn="User",
        base_dn="ou=People,dc=example,dc=com",
        mail="pipeline@example.com",
    )

    if person_result.is_failure:
        return

    person = person_result.unwrap()

    # Validate entry
    validator = api.SchemaValidator()
    validation_result = validator.validate_entries([person])

    if validation_result.is_success:
        report = validation_result.unwrap()
        _ = report.get("is_valid", False)


def work_with_schema_models() -> None:
    """Access schema models through API."""
    api = FlextLdif.get_instance()

    # Access schema models via api.models
    # These are available for direct instantiation if needed
    # Example: api.models.SchemaAttribute, api.models.SchemaObjectClass

    # Build schema using builder (recommended approach)
    builder = api.SchemaBuilder(server_type="rfc")

    builder.add_attribute(
        name="testAttr",
        description="Test attribute",
        syntax="1.3.6.1.4.1.1466.115.121.1.15",
    )

    schema_result = builder.build()

    if schema_result.is_success:
        schema = schema_result.unwrap()
        # Schema contains attribute definitions
        _ = schema.get("attributes", {})


def reset_and_rebuild_schema() -> None:
    """Demonstrate schema builder reset functionality."""
    api = FlextLdif.get_instance()

    builder = api.SchemaBuilder(server_type="rfc")

    # Build first schema
    builder.add_attribute(
        name="attr1",
        description="First attribute",
        syntax="1.3.6.1.4.1.1466.115.121.1.15",
    )

    first_schema_result = builder.build()

    if first_schema_result.is_success:
        first_schema = first_schema_result.unwrap()
        _ = len(first_schema.get("attributes", {}))

    # Reset builder
    builder.reset()

    # Build new schema
    builder.add_attribute(
        name="attr2",
        description="Second attribute",
        syntax="1.3.6.1.4.1.1466.115.121.1.15",
    )

    second_schema_result = builder.build()

    if second_schema_result.is_success:
        second_schema = second_schema_result.unwrap()
        # Second schema only contains attr2
        _ = len(second_schema.get("attributes", {}))
