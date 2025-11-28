"""Type definitions for flext-ldif test fixtures using Python 3.13 patterns.

Module functionality: Centralized TypedDict definitions for test fixtures.
Provides type-safe configuration dictionaries replacing generic dict[str, object].

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TypedDict


class SchemaAttributeDict(TypedDict, total=False):
    """Schema attribute test data."""

    oid: str
    name: str
    must_contain: list[str]
    may_contain: list[str]
    syntax: str
    description: str
    single_value: bool


class ObjectClassDict(TypedDict, total=False):
    """Object class test data."""

    oid: str
    name: str
    must_contain: list[str]
    may_contain: list[str]
    description: str


class EntryDataDict(TypedDict, total=False):
    """Entry test data for write operations."""

    dn: str
    objectClass: list[str]
    cn: list[str]
    mail: list[str]
    description: list[str]
    uid: list[str]
    sn: list[str]
    givenName: list[str]


class DirectoryEntryDataDict(TypedDict, total=False):
    """Flexible directory entry data for testing (supports any attribute)."""

    dn: str
    cn: str | list[str]
    member: str | list[str]
    owner: str | list[str]
    manager: str | list[str]
    secretary: str | list[str]
    objectClass: str | list[str]
    someField: str | int | bool


class AttributeValueDict(TypedDict, total=False):
    """Attribute value mapping."""

    values: list[str]
    syntax: str
    description: str


class ModificationDict(TypedDict, total=False):
    """Modification operation data."""

    operation: str
    attribute: str
    values: list[str]


class LdifEntryDict(TypedDict, total=False):
    """LDIF entry representation."""

    dn: str
    changeType: str
    objectClass: list[str]
    attributes: dict[str, list[str]]
    modifications: dict[str, ModificationDict]


class QuirksTestScenarioDict(TypedDict, total=False):
    """Generic test scenario for quirks testing."""

    scenario_name: str
    input_data: dict[str, list[str] | str]
    expected_output: dict[str, list[str] | str]
    error_expected: bool
    error_message: str


class FilterTestDict(TypedDict, total=False):
    """LDAP filter test data."""

    filter_string: str
    expected_entries: list[str]
    should_match: list[str]
    should_not_match: list[str]


class TransformationRuleDict(TypedDict, total=False):
    """Transformation rule mapping."""

    source_attribute: str
    target_attribute: str
    conversion_type: str


class ValidationRuleDict(TypedDict, total=False):
    """Validation rule mapping."""

    rule_type: str
    pattern: str
    required: bool


class SchemaTransformDict(TypedDict, total=False):
    """Schema transformation test data."""

    input_schema: str
    output_schema: str
    transformations: dict[str, TransformationRuleDict]
    validation_rules: dict[str, ValidationRuleDict]


class AclRuleDict(TypedDict, total=False):
    """ACL rule data."""

    rule_type: str
    permission: str
    attribute: str


class AclTestDict(TypedDict, total=False):
    """ACL test data for Oracle Access Control."""

    dn: str
    permissions: list[str]
    rules: dict[str, AclRuleDict]
    expected_result: str


class BooleanAttributeDict(TypedDict, total=False):
    """Boolean attribute test data."""

    attribute_name: str
    true_values: list[str]
    false_values: list[str]
    attribute_oid: str


class SyntaxMatchingDict(TypedDict, total=False):
    """Syntax and matching rule test data."""

    oid: str
    syntax_description: str
    matching_rules: list[str]
    comparison_values: list[str]


class DeviationMetadataDict(TypedDict, total=False):
    """Deviation metadata for OUD compatibility."""

    attribute_name: str
    deviation_type: str
    description: str
    compatibility_level: str


class MigrationTransformationDict(TypedDict, total=False):
    """Migration transformation data."""

    source_format: str
    target_format: str
    mapping_rules: list[str]


class CrossServerMigrationDict(TypedDict, total=False):
    """Cross-server migration test data."""

    source_server: str
    target_server: str
    entry_data: dict[str, list[str]]
    expected_transformations: dict[str, MigrationTransformationDict]


class CategorizationRulesDict(TypedDict, total=False):
    """Migration pipeline categorization rules configuration."""

    hierarchy_objectclasses: list[str]
    user_objectclasses: list[str]
    group_objectclasses: list[str]
    acl_attributes: list[str]


class TestCaseDataDict(TypedDict, total=False):
    """Generic test case data for flexible test scenarios."""

    entry_dict: dict[str, str | list[str]]
    expected_fields: dict[str, str | list[str]]
    validate_fields: dict[str, str | list[str] | bool]
    output_files: dict[str, str]


class GenericFieldsDict(TypedDict, total=False):
    """Generic dictionary for field validation in helpers.

    Used by helper methods for validating, comparing, and transforming
    flexible field dictionaries with any key-value pairs.
    """

    # Total flexibility - any keys/values allowed via cast


class GenericTestCaseDict(TypedDict, total=False):
    """Generic test case dictionary for helper deduplication.

    Provides type-safe wrapper for test cases passed to deduplication
    helpers while maintaining flexibility for different test scenarios.
    """

    # Total flexibility - any keys/values allowed via cast


class GenericCallableParameterDict(TypedDict, total=False):
    """Generic dictionary parameter for callable operations in helpers.

    Used for operations passed to helper methods that need flexible
    dictionary input with any key-value combination.
    """

    # Total flexibility - any keys/values allowed via cast


__all__ = [
    "AclRuleDict",
    "AclTestDict",
    "AttributeValueDict",
    "BooleanAttributeDict",
    "CategorizationRulesDict",
    "CrossServerMigrationDict",
    "DeviationMetadataDict",
    "DirectoryEntryDataDict",
    "EntryDataDict",
    "FilterTestDict",
    "GenericCallableParameterDict",
    "GenericFieldsDict",
    "GenericTestCaseDict",
    "LdifEntryDict",
    "MigrationTransformationDict",
    "ModificationDict",
    "ObjectClassDict",
    "QuirksTestScenarioDict",
    "SchemaAttributeDict",
    "SchemaTransformDict",
    "SyntaxMatchingDict",
    "TestCaseDataDict",
    "TransformationRuleDict",
    "ValidationRuleDict",
]
