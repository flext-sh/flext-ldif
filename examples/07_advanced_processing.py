"""Example 7: Advanced Processing with Processors and Utilities.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

⚠️ DEPRECATED: This example uses the old utilities.py API which has been removed.
This file needs updating to use the new service-based architecture:
- Use services.DnService for DN operations
- Use services.ValidationService for validation
- Use client methods for LDIF/encoding operations

For updated examples, see:
- examples/01_basic_usage.py (parse, write, validate)
- examples/02_dn_operations.py (DN parsing with services)

Demonstrates FlextLdif advanced functionality:
- Batch processing with direct API methods (no manual setup!)
- Parallel processing for performance (simplified)
- Utility functions (DN, text, time, validation, encoding, file) [DEPRECATED]
- Processing pipelines (streamlined)

All functionality accessed through FlextLdif facade using direct methods.
No manual processor creation or conversion loops required.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from flext_core import u

from flext_ldif import FlextLdif, FlextLdifModels
from flext_ldif.services.dn import FlextLdifDn


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
    batch_result = api.process("transform", entries, parallel=False)

    if batch_result.is_success:
        processed = batch_result.unwrap()
        _ = len(processed)


def parallel_processing() -> None:
    """Process entries in parallel using direct API method.

    Uses LdifParallelProcessor with ThreadPoolExecutor for true parallel execution.
    Supports 'transform' (convert to dict) and 'validate' (validate entries).
    Results may be in different order due to parallel execution.
    """
    api = FlextLdif.get_instance()

    # Create larger dataset for parallel processing benefit
    entries: list[FlextLdifModels.Entry] = []
    for i in range(10):
        result = api.create_entry(
            dn=f"cn=User{i},ou=People,dc=example,dc=com",
            attributes={
                "objectClass": ["person"],
                "cn": [f"User{i}"],
                "sn": [f"User{i}"],
            },
        )
        if result.is_success:
            entries.append(result.unwrap())

    # Process in parallel using ThreadPoolExecutor
    parallel_result = api.process("validate", entries, parallel=True)

    if parallel_result.is_success:
        processed = parallel_result.unwrap()
        _ = len(processed)
        # Note: Results may be in different order than input due to parallel execution


def use_dn_utilities() -> None:
    """Use DN (Distinguished Name) utilities."""
    # Use DN service class methods directly
    dn = "cn=John Doe,ou=People,dc=example,dc=com"

    # Parse DN
    parse_result = FlextLdifDn.parse_components(dn)

    if parse_result.is_success:
        components = parse_result.unwrap()
        # Components is list of (attribute, value) pairs
        _ = len(components)

    # Validate DN
    validation_result = FlextLdifDn.validate_format(dn)

    if validation_result.is_success:
        is_valid = validation_result.unwrap()
        _ = is_valid

    # Normalize DN
    normalize_result = FlextLdifDn.normalize(dn)

    if normalize_result.is_success:
        normalized = normalize_result.unwrap()
        _ = normalized


def use_text_utilities() -> None:
    """Use text formatting utilities."""
    # Text utilities functionality moved to standard library or removed
    # Format byte size using standard approach
    size_bytes: float = 1024 * 1024  # 1 MB
    for unit in ["", "K", "M", "G", "T"]:
        if size_bytes < 1024.0:
            size_str = f"{size_bytes:.1f} {unit}B"
            break
        size_bytes /= 1024.0
    else:
        size_str = f"{size_bytes:.1f} PB"

    _ = size_str


def use_time_utilities() -> None:
    """Use time/timestamp utilities."""
    # Get current timestamp using standard library
    timestamp = datetime.now(UTC).timestamp()
    _ = timestamp

    # Get formatted timestamp using standard library
    formatted_timestamp = datetime.now(UTC).isoformat()
    _ = formatted_timestamp


def use_validation_utilities() -> None:
    """Use validation utilities."""
    # NOTE: ValidationService was removed - validation now integrated in models/services
    # validation_service = ValidationService()  # REMOVED - no longer exists

    # Validate attribute name - now done via models
    # attr_valid = validation_service.validate_attribute_name(attr_name)  # REMOVED
    attr_valid = True  # Placeholder - use FlextLdif models for validation
    _ = attr_valid

    # Validate attribute name
    # attr_valid = validation_service.validate_attribute_name("cn")  # REMOVED
    attr_valid = True  # Placeholder
    _ = attr_valid

    # Validate object class name
    # oc_valid = validation_service.validate_objectclass_name(oc_name)  # REMOVED
    oc_valid = True  # Placeholder - use FlextLdif models for validation
    _ = oc_valid


def use_ldif_utilities() -> None:
    """Use LDIF-specific utilities."""
    # LDIF utilities functionality moved to main API
    api = FlextLdif.get_instance()

    # Validate LDIF syntax using API
    ldif_content = (
        "dn: cn=test,dc=example,dc=com\nobjectClass: person\ncn: test\nsn: user\n"
    )
    syntax_result = api.parse(ldif_content)
    _ = syntax_result.is_success

    # Count LDIF entries using API
    if syntax_result.is_success:
        entries = syntax_result.unwrap()
        _ = len(entries)


def use_encoding_utilities() -> None:
    """Use encoding utilities."""
    # Simple encoding detection using standard library
    sample_bytes = b"test value"
    # Try UTF-8 first, fallback to other encodings
    try:
        sample_bytes.decode("utf-8")
        encoding = "utf-8"
    except UnicodeDecodeError:
        try:
            sample_bytes.decode("latin-1")
            encoding = "latin-1"
        except UnicodeDecodeError:
            encoding = "unknown"
    _ = encoding


def use_file_utilities() -> None:
    """Use file operation utilities."""
    # Use standard library for file operations
    test_file = Path("examples/sample_basic.ldif")

    # Validate file path using standard library
    _ = test_file.exists() and test_file.is_file()

    # Get file info using standard library
    if test_file.exists():
        stat = test_file.stat()
        _ = {
            "size": stat.st_size,
            "modified": stat.st_mtime,
            "is_file": test_file.is_file(),
        }

    # Ensure file extension using standard library
    output_file = Path("examples/util_output")
    if not output_file.suffix:
        ensured_path = output_file.with_suffix(".ldif")
    else:
        ensured_path = output_file
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

    # Validate using services
    def validate_entry(entry: FlextLdifModels.Entry) -> bool:
        """Validate entry DN."""
        dn_result = FlextLdifDn.validate_format(str(entry.dn))
        return dn_result.is_success

    _ = u.process(
        entries,
        validate_entry,
        on_error="skip",
    )
    )

    # Batch process - ONE LINE! (was 15+ lines)
    batch_result = api.process("transform", entries, parallel=False)

    if batch_result.is_success:
        processed = batch_result.unwrap()

        # Analyze processed results
        analysis_result = api.analyze(entries)

        if analysis_result.is_success:
            stats = analysis_result.unwrap()
            _ = (len(processed), stats)


def access_all_utilities() -> None:
    """Demonstrate access to all utility classes."""
    # Use services and standard library for utility functions
    time_utils = datetime.now(UTC)

    # Use timestamp utility
    timestamp = time_utils.timestamp()

    # Use text utility
    size_bytes: float = 1024
    for unit in ["", "K", "M", "G", "T"]:
        if size_bytes < 1024.0:
            formatted_size = f"{size_bytes:.1f} {unit}B"
            break
        size_bytes /= 1024.0
    else:
        formatted_size = f"{size_bytes:.1f} PB"

    # Use DN utility
    dn_result = FlextLdifDn.validate_format("cn=test,dc=example,dc=com")

    # All utilities integrated
    _ = (timestamp, formatted_size, dn_result)
