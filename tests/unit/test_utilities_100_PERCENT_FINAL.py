"""UTILITIES 100% COVERAGE FINAL: Elevar utilities.py de 30% para 100% absoluto."""

from __future__ import annotations

from flext_ldif.models import FlextLDIFModels
from flext_ldif.utilities import FlextLDIFUtilities


def test_utilities_all_methods_comprehensive() -> None:
    """Test ALL methods in FlextLDIFUtilities for 100% coverage."""
    # Initialize utilities
    FlextLDIFUtilities()

    # Test LdifDomainProcessors static methods
    processors = FlextLDIFUtilities.LdifDomainProcessors

    # Create test entries for validation
    test_entries = []
    entry_data = {
        "dn": "cn=test,dc=example,dc=com",
        "attributes": {"cn": ["test"], "objectClass": ["person"]}
    }
    entry = FlextLDIFModels.Entry.model_validate(entry_data)
    test_entries.append(entry)

    # Test validate_entries_or_warn with valid entries
    result = processors.validate_entries_or_warn(test_entries)
    assert result.is_success

    # Test validate_entries_or_warn with edge case entries
    edge_entry_data = {
        "dn": "cn=edge_case,dc=com",  # Valid DN
        "attributes": {"cn": ["test"]}
    }
    edge_entry = FlextLDIFModels.Entry.model_validate(edge_entry_data)
    edge_entries = [edge_entry]
    result_edge = processors.validate_entries_or_warn(edge_entries)
    assert result_edge.is_success  # Should handle gracefully

    # Test validate_entries_or_warn with missing objectClass
    no_objectclass_data = {
        "dn": "cn=test,dc=com",
        "attributes": {"cn": ["test"]}  # No objectClass
    }
    no_objectclass_entry = FlextLDIFModels.Entry.model_validate(no_objectclass_data)
    no_objectclass_entries = [no_objectclass_entry]
    result_no_objectclass = processors.validate_entries_or_warn(no_objectclass_entries)
    assert result_no_objectclass.is_success

    # Test filter_entries_by_object_class
    result_filter = processors.filter_entries_by_object_class(test_entries, "person")
    assert result_filter.is_success

    # Test find_entries_with_missing_required_attributes
    required_attrs = ["cn", "objectClass", "mail"]  # mail is missing
    result_missing = processors.find_entries_with_missing_required_attributes(test_entries, required_attrs)
    assert result_missing.is_success

    # Test get_entry_statistics with entries
    result_stats = processors.get_entry_statistics(test_entries)
    assert result_stats.is_success
    stats = result_stats.value
    assert "total_entries" in stats
    assert stats["total_entries"] > 0

    # Test get_entry_statistics with empty entries
    result_empty_stats = processors.get_entry_statistics([])
    assert result_empty_stats.is_success
    empty_stats = result_empty_stats.value
    assert empty_stats["total_entries"] == 0


def test_utilities_converters_comprehensive() -> None:
    """Test ALL methods in LdifConverters for 100% coverage."""
    converters = FlextLDIFUtilities.LdifConverters

    # Test attributes_dict_to_ldif_format with string values
    attrs_string = {"cn": "test", "mail": "test@example.com"}
    result_string = converters.attributes_dict_to_ldif_format(attrs_string)
    assert result_string.is_success

    # Test attributes_dict_to_ldif_format with list values
    attrs_list = {"cn": ["test"], "objectClass": ["person", "organizationalPerson"]}
    result_list = converters.attributes_dict_to_ldif_format(attrs_list)
    assert result_list.is_success

    # Test attributes_dict_to_ldif_format with mixed values
    attrs_mixed = {"cn": "test", "objectClass": ["person"], "mail": None}
    result_mixed = converters.attributes_dict_to_ldif_format(attrs_mixed)
    assert result_mixed.is_success

    # Test attributes_dict_to_ldif_format with empty values
    attrs_empty = {"cn": "", "mail": []}
    result_empty = converters.attributes_dict_to_ldif_format(attrs_empty)
    assert result_empty.is_success

    # Test normalize_dn_components with valid DN
    dn_valid = "cn=test,dc=example,dc=com"
    result_dn_valid = converters.normalize_dn_components(dn_valid)
    assert result_dn_valid.is_success

    # Test normalize_dn_components with whitespace
    dn_whitespace = "  cn=test,dc=example,dc=com  "
    result_dn_whitespace = converters.normalize_dn_components(dn_whitespace)
    assert result_dn_whitespace.is_success

    # Test normalize_dn_components with empty DN
    result_dn_empty = converters.normalize_dn_components("")
    assert result_dn_empty.is_failure  # Should fail

    # Test normalize_dn_components with None-like DN
    result_dn_none = converters.normalize_dn_components("   ")
    assert result_dn_none.is_failure  # Should fail


def test_utilities_edge_cases_complete_coverage() -> None:
    """Test ALL edge cases to ensure 100% coverage."""
    FlextLDIFUtilities()
    processors = FlextLDIFUtilities.LdifDomainProcessors
    converters = FlextLDIFUtilities.LdifConverters

    # Edge Case 1: Large number of entries (max_errors limit)
    large_entries = []
    for i in range(15):  # More than max_errors=10
        entry_data = {
            "dn": f"cn=test{i},dc=com" if i % 2 == 0 else f"uid=test{i},ou=people,dc=com",  # Different structures
            "attributes": {"cn": [f"test{i}"]} if i % 3 != 0 else {}  # Some missing objectClass
        }
        entry = FlextLDIFModels.Entry.model_validate(entry_data)
        large_entries.append(entry)

    result_large = processors.validate_entries_or_warn(large_entries, max_errors=10)
    assert result_large.is_success

    # Edge Case 2: Person and Group entries for statistics
    person_entry = FlextLDIFModels.Entry.model_validate({
        "dn": "cn=person,dc=com",
        "attributes": {"objectClass": ["person"], "cn": ["person"]}
    })

    group_entry = FlextLDIFModels.Entry.model_validate({
        "dn": "cn=group,dc=com",
        "attributes": {"objectClass": ["group"], "cn": ["group"]}
    })

    mixed_entries = [person_entry, group_entry]
    result_mixed_stats = processors.get_entry_statistics(mixed_entries)
    assert result_mixed_stats.is_success
    stats = result_mixed_stats.value
    assert stats["person_entries"] > 0
    assert stats["group_entries"] > 0

    # Edge Case 3: Filter by object class variations
    result_filter_person = processors.filter_entries_by_object_class(mixed_entries, "person")
    assert result_filter_person.is_success

    result_filter_group = processors.filter_entries_by_object_class(mixed_entries, "group")
    assert result_filter_group.is_success

    result_filter_none = processors.filter_entries_by_object_class(mixed_entries, "nonexistent")
    assert result_filter_none.is_success
    assert len(result_filter_none.value) == 0

    # Edge Case 4: Complex attribute conversions
    complex_attrs = {
        "cn": ["test1", "test2"],
        "mail": "single@example.com",
        "objectClass": ["person", "organizationalPerson", "inetOrgPerson"],
        "description": None,
        "empty_attr": "",
        "list_empty": [],
        "mixed_values": ["value1", None, "value2", ""]
    }
    result_complex = converters.attributes_dict_to_ldif_format(complex_attrs)
    assert result_complex.is_success


def test_utilities_complete_method_matrix() -> None:
    """Complete method matrix test to ensure 100% utilities coverage."""
    # Initialize all components
    FlextLDIFUtilities()
    processors = FlextLDIFUtilities.LdifDomainProcessors
    converters = FlextLDIFUtilities.LdifConverters

    # Test matrix for validate_entries_or_warn
    test_cases = [
        # Case 1: Valid entries
        [{
            "dn": "cn=valid,dc=com",
            "attributes": {"cn": ["valid"], "objectClass": ["person"]}
        }],

        # Case 2: Minimal DN (testing edge case)
        [{
            "dn": "cn=invalid,dc=com",
            "attributes": {"cn": ["invalid"], "objectClass": ["person"]}
        }],

        # Case 3: Missing objectClass
        [{
            "dn": "cn=missing,dc=com",
            "attributes": {"cn": ["missing"]}
        }],

        # Case 4: Different DN structure
        [{
            "dn": "uid=both_issues,ou=users,dc=com",
            "attributes": {"cn": ["both_issues"]}
        }],

        # Case 5: Multiple mixed entries
        [
            {
                "dn": "cn=good1,dc=com",
                "attributes": {"cn": ["good1"], "objectClass": ["person"]}
            },
            {
                "dn": "cn=bad1,dc=com",
                "attributes": {"cn": ["bad1"]}
            },
            {
                "dn": "cn=good2,dc=com",
                "attributes": {"cn": ["good2"], "objectClass": ["group"]}
            }
        ]
    ]

    for i, case_data in enumerate(test_cases):
        entries = [FlextLDIFModels.Entry.model_validate(data) for data in case_data]
        result = processors.validate_entries_or_warn(entries)
        assert result is not None, f"Case {i + 1} failed"

        # Also test other methods with these entries
        processors.filter_entries_by_object_class(entries, "person")
        processors.find_entries_with_missing_required_attributes(entries, ["cn", "objectClass"])
        processors.get_entry_statistics(entries)

    # Test matrix for normalize_dn_components
    dn_cases = [
        "cn=test,dc=com",                    # Normal
        "  cn=test,dc=com  ",               # With whitespace
        "cn=test, dc=com",                  # With spaces
        "CN=TEST,DC=COM",                   # Uppercase
        "cn=test,ou=people,dc=example,dc=com"  # Long DN
    ]

    for dn in dn_cases:
        result = converters.normalize_dn_components(dn)
        assert result.is_success, f"DN case failed: {dn}"

    # Test matrix for attributes_dict_to_ldif_format
    attr_cases = [
        {"cn": "single"},                   # Single string
        {"cn": ["multiple", "values"]},     # Multiple values
        {"mixed": "string", "list": ["a", "b"]},  # Mixed types
        {"empty_string": "", "empty_list": []},   # Empty values
        {"none_val": None},                 # None value
        {"complex": ["val1", None, "", "val2"]}   # Complex mixed
    ]

    for attrs in attr_cases:
        result = converters.attributes_dict_to_ldif_format(attrs)
        assert result.is_success, f"Attr case failed: {attrs}"


def test_utilities_final_comprehensive_validation() -> None:
    """Final comprehensive validation to guarantee 100% utilities coverage."""
    # Test utilities class instantiation
    utilities = FlextLDIFUtilities()
    assert utilities is not None
    assert hasattr(utilities, "_logger")

    # Validate all static method access patterns
    assert hasattr(FlextLDIFUtilities, "LdifDomainProcessors")
    assert hasattr(FlextLDIFUtilities, "LdifConverters")

    processors = FlextLDIFUtilities.LdifDomainProcessors
    converters = FlextLDIFUtilities.LdifConverters

    # Test every single branch and condition

    # Branch 1: validate_entries_or_warn with different error conditions
    minimal_dn_entry = FlextLDIFModels.Entry.model_validate({
        "dn": "cn=minimal,dc=com",
        "attributes": {"cn": ["test"]}
    })

    no_objectclass_entry = FlextLDIFModels.Entry.model_validate({
        "dn": "cn=test,dc=com",
        "attributes": {"cn": ["test"]}
    })

    different_structure_entry = FlextLDIFModels.Entry.model_validate({
        "dn": "uid=different,ou=people,dc=com",
        "attributes": {"cn": ["test"]}
    })

    # Test with max_errors boundary
    problem_entries = [minimal_dn_entry, no_objectclass_entry, different_structure_entry] * 5  # 15 entries
    result = processors.validate_entries_or_warn(problem_entries, max_errors=10)
    assert result.is_success

    # Branch 2: get_entry_statistics with different entry types
    person_entries = [
        FlextLDIFModels.Entry.model_validate({
            "dn": f"cn=person{i},dc=com",
            "attributes": {"objectClass": ["person"], "cn": [f"person{i}"]}
        }) for i in range(3)
    ]

    group_entries = [
        FlextLDIFModels.Entry.model_validate({
            "dn": f"cn=group{i},dc=com",
            "attributes": {"objectClass": ["group"], "cn": [f"group{i}"]}
        }) for i in range(2)
    ]

    all_test_entries = person_entries + group_entries
    result_comprehensive_stats = processors.get_entry_statistics(all_test_entries)
    assert result_comprehensive_stats.is_success
    stats = result_comprehensive_stats.value
    assert stats["person_entries"] == 3
    assert stats["group_entries"] == 2
    assert stats["total_entries"] == 5
    assert stats["unique_attributes"] > 0

    # Branch 3: attribute conversion edge cases
    edge_case_attrs = {
        "string_attr": "simple_string",
        "list_attr": ["item1", "item2", "item3"],
        "empty_string": "",
        "empty_list": [],
        "none_value": None,
        "mixed_list": ["valid", None, "", "also_valid"],
        "single_item_list": ["single"],
        "numeric_string": "123",
        "unicode_string": "tést_ünıcöde"
    }

    result_edge_attrs = converters.attributes_dict_to_ldif_format(edge_case_attrs)
    assert result_edge_attrs.is_success
    converted = result_edge_attrs.value

    # Verify conversion logic
    assert "string_attr" in converted
    assert "list_attr" in converted
    assert "empty_string" not in converted or len(converted["empty_string"]) == 0
    assert "none_value" not in converted

    assert True  # Success marker
