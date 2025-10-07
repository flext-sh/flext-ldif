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
    entries = [
        api.models.Entry(
            dn=f"cn=User{i},ou=People,dc=example,dc=com",
            attributes={
                "objectClass": ["person"],
                "cn": [f"User{i}"],
                "sn": [f"User{i}"],
            },
        )
        for i in range(10)
    ]

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
    parse_result = dn_utils.parse_dn(dn)

    if parse_result.is_success:
        components = parse_result.unwrap()
        # Components is list of (attribute, value) pairs
        _ = len(components)

    # Validate DN
    validation_result = dn_utils.validate_dn(dn)

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

    # Truncate text
    long_text = "A" * 1000
    truncated = text_utils.truncate_text(long_text, max_length=100)
    _ = len(truncated)

    # Format timestamp
    formatted = text_utils.format_timestamp()
    _ = formatted


def use_time_utilities() -> None:
    """Use time/timestamp utilities."""
    api = FlextLdif.get_instance()

    # Access time utilities
    time_utils = api.utilities.TimeUtilities

    # Get current timestamp
    timestamp = time_utils.get_timestamp()
    _ = timestamp

    # Get ISO format timestamp
    iso_timestamp = time_utils.get_iso_timestamp()
    _ = iso_timestamp


def use_validation_utilities() -> None:
    """Use validation utilities."""
    api = FlextLdif.get_instance()

    # Access validation utilities
    validation_utils = api.utilities.ValidationUtilities

    # Validate DN format
    dn = "cn=test,dc=example,dc=com"
    dn_valid = validation_utils.validate_dn_format(dn)
    _ = dn_valid

    # Validate attribute name
    attr_valid = validation_utils.validate_attribute_name("cn")
    _ = attr_valid

    # Validate entry structure
    entry = api.models.Entry(
        dn="cn=test,dc=example,dc=com",
        attributes={"objectClass": ["person"], "cn": ["test"], "sn": ["user"]},
    )

    entry_valid = validation_utils.validate_entry_structure(entry)
    _ = entry_valid


def use_ldif_utilities() -> None:
    """Use LDIF-specific utilities."""
    api = FlextLdif.get_instance()

    # Access LDIF utilities
    ldif_utils = api.utilities.LdifUtilities

    # Check if line needs base64 encoding
    needs_encoding = ldif_utils.needs_base64_encoding("cn: test")
    _ = needs_encoding

    # Fold long line (RFC 2849 compliance)
    long_line = "description: " + "A" * 200
    folded = ldif_utils.fold_line(long_line)
    _ = len(folded)

    # Unfold line
    folded_line = "cn: test\n value"
    unfolded = ldif_utils.unfold_line(folded_line)
    _ = unfolded


def use_encoding_utilities() -> None:
    """Use encoding utilities."""
    api = FlextLdif.get_instance()

    # Access encoding utilities
    encoding_utils = api.utilities.EncodingUtilities

    # Encode to UTF-8
    encoded = encoding_utils.encode_utf8("test value")
    _ = encoded

    # Decode from UTF-8
    decoded = encoding_utils.decode_utf8(b"test value")
    _ = decoded

    # Base64 encode
    b64_encoded = encoding_utils.base64_encode("test value")
    _ = b64_encoded

    # Base64 decode
    b64_decoded = encoding_utils.base64_decode(b64_encoded)
    _ = b64_decoded


def use_file_utilities() -> None:
    """Use file operation utilities."""
    api = FlextLdif.get_instance()

    # Access file utilities
    file_utils = api.utilities.FileUtilities

    # Read file safely (with error handling)
    test_file = Path("examples/sample_basic.ldif")

    if test_file.exists():
        read_result = file_utils.read_file_safe(test_file)

        if read_result.is_success:
            content = read_result.unwrap()
            _ = len(content)

    # Write file safely
    output_file = Path("examples/util_output.ldif")
    write_result = file_utils.write_file_safe(output_file, "test content")

    if write_result.is_success:
        _ = write_result.unwrap()


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
        dn_valid = api.utilities.ValidationUtilities.validate_dn_format(entry.dn)

        if not dn_valid:
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
    dn_result = dn_utils.validate_dn("cn=test,dc=example,dc=com")

    # All utilities integrated
    _ = (timestamp, formatted_size, dn_result)
