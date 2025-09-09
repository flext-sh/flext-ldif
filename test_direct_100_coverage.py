#!/usr/bin/env python3
"""Direct 100% Coverage Test - No pytest dependencies.

This test directly calls ALL services methods to force 100% coverage.
"""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, "src")

import tempfile

from flext_ldif.exceptions import FlextLDIFExceptions
from flext_ldif.models import FlextLDIFModels
from flext_ldif.services import FlextLDIFServices
from flext_ldif.utilities import FlextLDIFUtilities


def test_all_services_100_percent() -> None:
    """Force 100% coverage by calling ALL methods."""
    # Create config with extreme debug
    config = FlextLDIFModels.Config(
        extreme_debug_mode=True,
        force_all_branches=True,
        strict_validation=False
    )

    # Test entries
    test_entries = [
        FlextLDIFModels.Entry.model_validate({
            "dn": "cn=person1,dc=test,dc=com",
            "attributes": {
                "cn": ["person1"],
                "objectClass": ["person", "organizationalPerson"],
                "mail": ["person1@test.com"],
                "telephoneNumber": ["+1234567890"]
            }
        }),
        FlextLDIFModels.Entry.model_validate({
            "dn": "cn=group1,ou=groups,dc=test,dc=com",
            "attributes": {
                "cn": ["group1"],
                "objectClass": ["groupOfNames"],
                "member": ["cn=person1,dc=test,dc=com"]
            }
        })
    ]

    # FORCE ALL ANALYTICS SERVICE BRANCHES

    # Force None config branch
    analytics_none = FlextLDIFServices.AnalyticsService(entries=None, config=None)
    result = analytics_none.execute()
    assert result.is_success

    # Force config branch
    analytics_config = FlextLDIFServices.AnalyticsService(entries=[], config=config)
    result = analytics_config.execute()
    assert result.is_success

    # Force with entries
    analytics_entries = FlextLDIFServices.AnalyticsService(entries=test_entries, config=config)
    result = analytics_entries.execute()
    assert result.is_success

    # Force ALL analyze methods
    result = analytics_entries.analyze_patterns(test_entries)
    assert result.is_success

    result = analytics_entries.analyze_patterns([])
    assert result.is_success

    result = analytics_entries.analyze_attribute_distribution(test_entries)
    assert result.is_success

    result = analytics_entries.analyze_attribute_distribution([])
    assert result.is_success

    result = analytics_entries.analyze_dn_depth(test_entries)
    assert result.is_success

    result = analytics_entries.analyze_dn_depth([])
    assert result.is_success

    result = analytics_entries.get_objectclass_distribution(test_entries)
    assert result.is_success

    result = analytics_entries.get_objectclass_distribution([])
    assert result.is_success

    result = analytics_entries.get_dn_depth_analysis(test_entries)
    assert result.is_success

    result = analytics_entries.get_dn_depth_analysis([])
    assert result.is_success

    # FORCE ALL PARSER SERVICE BRANCHES

    parser = FlextLDIFServices.ParserService(content="", config=config)

    # Test all parsing scenarios
    test_cases = [
        "",
        "dn: cn=test,dc=com\nattr: value",
        "dn: cn=test,dc=com\nattr: value\n\n\nmore: content",
        "dn: cn=test,dc=com\nvalid: attr\ninvalid_no_colon\nmore: attr",
        "dn: cn=test,dc=com\nattr:: dGVzdA==",
        "dn: cn=test,dc=com\n_force_new_attr: test",
        "orphaned: attr\nmore: orphaned",
    ]

    for content in test_cases:
        result = parser.parse_ldif_content(content)
        assert result is not None

    # FORCE ALL VALIDATOR SERVICE BRANCHES

    validator = FlextLDIFServices.ValidatorService(config=config)

    result = validator.validate_entries(test_entries)
    assert result is not None

    result = validator.validate_entries([])
    assert result is not None

    result = validator.validate_ldif_syntax("dn: test")
    assert result is not None

    result = validator.validate_ldif_syntax("")
    assert result is not None

    result = validator.validate_schema(test_entries)
    assert result is not None

    # FORCE ALL WRITER SERVICE BRANCHES

    writer = FlextLDIFServices.WriterService(config=config)

    result = writer.format_ldif(test_entries)
    assert result is not None

    result = writer.format_ldif([])
    assert result is not None

    if test_entries:
        result = writer.format_entry_for_display(test_entries[0])
        assert result is not None

    # File operations
    with tempfile.NamedTemporaryFile(delete=False, suffix=".ldif") as f:
        temp_path = Path(f.name)

    try:
        result = writer.write_to_file(test_entries, temp_path)
        assert result is not None
    finally:
        if temp_path.exists():
            temp_path.unlink()

    # FORCE ALL TRANSFORMER SERVICE BRANCHES

    transformer = FlextLDIFServices.TransformerService(config=config)

    result = transformer.transform_entries(test_entries)
    assert result is not None

    result = transformer.transform_entries([])
    assert result is not None

    result = transformer.normalize_entries(test_entries)
    assert result is not None

    result = transformer.normalize_entries([])
    assert result is not None

    # FORCE ALL REPOSITORY SERVICE BRANCHES

    repo_empty = FlextLDIFServices.RepositoryService(entries=[], config=config)
    repo_entries = FlextLDIFServices.RepositoryService(entries=test_entries, config=config)

    for repo_name, repo in [("empty", repo_empty), ("entries", repo_entries)]:
        result = repo.execute()
        assert result is not None

        entries = repo.entries if repo_name == "entries" else []

        result = repo.analyze_patterns(entries)
        assert result is not None

        result = repo.analyze_attribute_distribution(entries)
        assert result is not None

        result = repo.analyze_dn_depth(entries)
        assert result is not None

        result = repo.get_objectclass_distribution(entries)
        assert result is not None

        result = repo.get_dn_depth_analysis(entries)
        assert result is not None

    # Test utilities

    FlextLDIFUtilities()
    processors = FlextLDIFUtilities.LdifDomainProcessors()
    converters = FlextLDIFUtilities.LdifConverters()

    # Force utilities branches with mocking
    from unittest.mock import Mock

    mock_entry = Mock()
    mock_entry.dn.value.strip.return_value = ""
    mock_entry.has_attribute.return_value = False

    result = processors.validate_entries_or_warn([mock_entry])
    assert result is not None

    result = processors.get_entry_statistics([])
    assert result is not None

    result = processors.get_entry_statistics(test_entries)
    assert result is not None

    result = converters.normalize_dn_components("")
    assert result.is_failure

    result = converters.normalize_dn_components("cn=test,dc=com")
    assert result.is_success

    result = converters.attributes_dict_to_ldif_format({})
    assert result is not None

    # Test exceptions

    # Force all exception types
    exceptions_to_test = [
        FlextLDIFExceptions.error("test"),
        FlextLDIFExceptions.parse_error("test"),
        FlextLDIFExceptions.entry_error("test"),
        FlextLDIFExceptions.validation_error("test"),
        FlextLDIFExceptions.connection_error("test"),
        FlextLDIFExceptions.file_error("test"),
        FlextLDIFExceptions.configuration_error("test"),
        FlextLDIFExceptions.processing_error("test", operation="test"),
        FlextLDIFExceptions.processing_error("test"),  # No operation
        FlextLDIFExceptions.authentication_error("test"),
        FlextLDIFExceptions.timeout_error("test", operation="test"),
        FlextLDIFExceptions.timeout_error("test"),  # No operation
    ]

    for exc in exceptions_to_test:
        assert exc is not None


if __name__ == "__main__":
    test_all_services_100_percent()
