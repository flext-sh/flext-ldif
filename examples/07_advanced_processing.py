"""Example 7: Advanced Processing with Processors and Utilities.

Demonstrates FlextLdif advanced functionality:
- Batch processing with direct API methods (no manual setup!)
- Parallel processing for performance (simplified)
- Utility functions (DN, text, time, validation, encoding, file)
- Processing pipelines (streamlined)

All functionality accessed through FlextLdif facade using direct methods.
No manual processor creation or conversion loops required.
"""

from __future__ import annotations

from pathlib import Path

from flext_ldif import FlextLdif


def basic_batch_processing() -> None:
    """Process entries in batches using direct API method."""
    api = FlextLdif.get_instance()

    # Parse some entries
    ldif_content = """dn: cn=User1,ou=People,dc=example,dc=com
objectClass: person
cn: User1
sn: One

dn: cn=User2,ou=People,dc=example,dc=com
objectClass: person
cn: User2
sn: Two

dn: cn=User3,ou=People,dc=example,dc=com
objectClass: person
cn: User3
sn: Three
"""

    parse_result = api.parse(ldif_content)

    if parse_result.is_failure:
        return

    entries = parse_result.unwrap()

    # Process in batch mode - ONE LINE! (was 15+ lines)
    # No processor creation, no manual conversion loops!
    batch_result = api.process_batch("transform", entries)

    if batch_result.is_success:
        processed = batch_result.unwrap()
        _ = len(processed)


def parallel_processing() -> None:
    """Process entries in parallel using direct API method."""
    api = FlextLdif.get_instance()

    # Create larger dataset for parallel processing benefit
    entries = []
    for i in range(10):
        result = api.models.Entry.create(
            dn=f"cn=User{i},ou=People,dc=example,dc=com",
            attributes={
                "objectClass": ["person"],
                "cn": [f"User{i}"],
                "sn": [f"User{i}"],
            },
        )
        if result.is_success:
            entries.append(result.unwrap())

    # Process in parallel - ONE LINE! (was 15+ lines)
    # No processor creation, no manual conversion loops!
    parallel_result = api.process_parallel("validate", entries)

    if parallel_result.is_success:
        processed = parallel_result.unwrap()
        _ = len(processed)


def use_dn_utilities() -> None:
    """Use DN (Distinguished Name) utilities."""
    api = FlextLdif.get_instance()

    # Access DN utilities
    dn_utils = api.utilities.DnUtilities

    # Parse DN
    dn = "cn=John Doe,ou=People,dc=example,dc=com"
    parse_result = dn_utils.parse_dn_components(dn)

    if parse_result.is_success:
        components = parse_result.unwrap()
        # Components is list of (attribute, value) pairs
        _ = len(components)

    # Validate DN
    validation_result = dn_utils.validate_dn_format(dn)

    if validation_result.is_success:
        is_valid = validation_result.unwrap()
        _ = is_valid

    # Normalize DN
    normalize_result = dn_utils.normalize_dn(dn)

    if normalize_result.is_success:
        normalized = normalize_result.unwrap()
        _ = normalized


def use_text_utilities() -> None:
    """Use text formatting utilities."""
    api = FlextLdif.get_instance()

    # Access text utilities
    text_utils = api.utilities.TextUtilities

    # Format byte size
    size_str = text_utils.format_byte_size(1024 * 1024)  # 1 MB
    _ = size_str

    # Note: truncate_text and format_timestamp are not available in TextUtilities
    # Only format_byte_size is available


def use_time_utilities() -> None:
    """Use time/timestamp utilities."""
    api = FlextLdif.get_instance()

    # Access time utilities
    time_utils = api.utilities.TimeUtilities

    # Get current timestamp
    timestamp = time_utils.get_timestamp()
    _ = timestamp

    # Get formatted timestamp
    formatted_timestamp = time_utils.get_formatted_timestamp()
    _ = formatted_timestamp


def use_validation_utilities() -> None:
    """Use validation utilities."""
    api = FlextLdif.get_instance()

    # Access validation utilities
    validation_utils = api.utilities.ValidationUtilities

    # Validate attribute name
    attr_name = "cn"
    attr_valid = validation_utils.validate_attribute_name(attr_name)
    _ = attr_valid

    # Validate attribute name
    attr_valid = validation_utils.validate_attribute_name("cn")
    _ = attr_valid

    # Validate object class name
    oc_name = "person"
    oc_valid = validation_utils.validate_object_class_name(oc_name)
    _ = oc_valid


def use_ldif_utilities() -> None:
    """Use LDIF-specific utilities."""
    api = FlextLdif.get_instance()

    # Access LDIF utilities
    ldif_utils = api.utilities.LdifUtilities

    # Validate LDIF syntax
    ldif_content = (
        "dn: cn=test,dc=example,dc=com\nobjectClass: person\ncn: test\nsn: user\n"
    )
    syntax_result = ldif_utils.validate_ldif_syntax(ldif_content)
    _ = syntax_result

    # Count LDIF entries
    count_result = ldif_utils.count_ldif_entries(ldif_content)
    _ = count_result


def use_encoding_utilities() -> None:
    """Use encoding utilities."""
    api = FlextLdif.get_instance()

    # Access encoding utilities
    encoding_utils = api.utilities.EncodingUtilities

    # Detect encoding
    sample_bytes = b"test value"
    encoding_result = encoding_utils.detect_encoding(sample_bytes)
    _ = encoding_result


def use_file_utilities() -> None:
    """Use file operation utilities."""
    api = FlextLdif.get_instance()

    # Access file utilities
    file_utils = api.utilities.FileUtilities

    # Validate file path
    test_file = Path("examples/sample_basic.ldif")
    path_result = file_utils.validate_file_path(test_file)
    _ = path_result

    # Get file info
    if test_file.exists():
        info_result = file_utils.get_file_info(test_file)
        _ = info_result

    # Ensure file extension
    output_file = Path("examples/util_output")
    ensured_path = file_utils.ensure_file_extension(output_file, "ldif")
    _ = ensured_path


def complete_processing_pipeline() -> None:
    """Complete pipeline using utilities and direct processing methods."""
    api = FlextLdif.get_instance()

    # Parse LDIF
    ldif_content = """dn: cn=Pipeline,ou=People,dc=example,dc=com
objectClass: person
cn: Pipeline
sn: User
"""

    parse_result = api.parse(ldif_content)

    if parse_result.is_failure:
        return

    entries = parse_result.unwrap()

    # Validate using utilities
    for entry in entries:
        # Use DnUtilities for DN validation
        dn_result = api.utilities.DnUtilities.validate_dn_format(str(entry.dn))

        if dn_result.is_failure:
            continue

    # Batch process - ONE LINE! (was 15+ lines)
    batch_result = api.process_batch("transform", entries)

    if batch_result.is_success:
        processed = batch_result.unwrap()

        # Analyze processed results
        analysis_result = api.analyze(entries)

        if analysis_result.is_success:
            stats = analysis_result.unwrap()
            _ = (len(processed), stats)


def access_all_utilities() -> None:
    """Demonstrate access to all utility classes."""
    api = FlextLdif.get_instance()

    # All utility classes available through api.utilities
    time_utils = api.utilities.TimeUtilities
    text_utils = api.utilities.TextUtilities
    dn_utils = api.utilities.DnUtilities

    # Use timestamp utility
    timestamp = time_utils.get_timestamp()

    # Use text utility
    formatted_size = text_utils.format_byte_size(1024)

    # Use DN utility
    dn_result = dn_utils.validate_dn_format("cn=test,dc=example,dc=com")

    # All utilities integrated
    _ = (timestamp, formatted_size, dn_result)
