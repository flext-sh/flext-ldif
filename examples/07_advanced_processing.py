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

from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from flext_ldif import FlextLdif, FlextLdifDn, FlextLdifModels, u


def basic_batch_processing() -> None:
    """Process entries in batches using direct API method."""
    api = FlextLdif.get_instance()
    ldif_content = "dn: cn=User1,ou=People,dc=example,dc=com\nobjectClass: person\ncn: User1\nsn: One\n\ndn: cn=User2,ou=People,dc=example,dc=com\nobjectClass: person\ncn: User2\nsn: Two\n\ndn: cn=User3,ou=People,dc=example,dc=com\nobjectClass: person\ncn: User3\nsn: Three\n"
    parse_result = api.parse(ldif_content)
    if parse_result.is_failure:
        return
    entries = parse_result.value
    batch_result = api.process("transform", entries, parallel=False)
    if batch_result.is_success:
        processed = batch_result.value
        _ = len(processed)


def parallel_processing() -> None:
    """Process entries in parallel using direct API method.

    Uses LdifParallelProcessor with ThreadPoolExecutor for true parallel execution.
    Supports 'transform' (convert to dict) and 'validate' (validate entries).
    Results may be in different order due to parallel execution.
    """
    api = FlextLdif.get_instance()
    entries: Sequence[FlextLdifModels.Ldif.Entry] = []
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
            entries.append(result.value)
    parallel_result = api.process("validate", entries, parallel=True)
    if parallel_result.is_success:
        processed = parallel_result.value
        _ = len(processed)


def use_dn_utilities() -> None:
    """Use DN (Distinguished Name) utilities."""
    dn = "cn=John Doe,ou=People,dc=example,dc=com"
    parse_result = FlextLdifDn.parse_components(dn)
    if parse_result.is_success:
        components = parse_result.value
        _ = len(components)
    validation_result = FlextLdifDn.validate_format(dn)
    if validation_result.is_success:
        is_valid = validation_result.value
        _ = is_valid
    normalize_result = FlextLdifDn.normalize(dn)
    if normalize_result.is_success:
        normalized = normalize_result.value
        _ = normalized


def use_text_utilities() -> None:
    """Use text formatting utilities."""
    size_bytes: float = 1024 * 1024
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
    timestamp = datetime.now(UTC).timestamp()
    _ = timestamp
    formatted_timestamp = datetime.now(UTC).isoformat()
    _ = formatted_timestamp


def use_validation_utilities() -> None:
    """Use validation utilities."""
    attr_valid = True
    _ = attr_valid
    attr_valid = True
    _ = attr_valid
    oc_valid = True
    _ = oc_valid


def use_ldif_utilities() -> None:
    """Use LDIF-specific utilities."""
    api = FlextLdif.get_instance()
    ldif_content = (
        "dn: cn=test,dc=example,dc=com\nobjectClass: person\ncn: test\nsn: user\n"
    )
    syntax_result = api.parse(ldif_content)
    _ = syntax_result.is_success
    if syntax_result.is_success:
        entries = syntax_result.value
        _ = len(entries)


def use_encoding_utilities() -> None:
    """Use encoding utilities."""
    sample_bytes = b"test value"
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
    test_file = Path("examples/sample_basic.ldif")
    _ = test_file.exists() and test_file.is_file()
    if test_file.exists():
        stat = test_file.stat()
        _ = {
            "size": stat.st_size,
            "modified": stat.st_mtime,
            "is_file": test_file.is_file(),
        }
    output_file = Path("examples/util_output")
    if not output_file.suffix:
        ensured_path = output_file.with_suffix(".ldif")
    else:
        ensured_path = output_file
    _ = ensured_path


def complete_processing_pipeline() -> None:
    """Complete pipeline using utilities and direct processing methods."""
    api = FlextLdif.get_instance()
    ldif_content = "dn: cn=Pipeline,ou=People,dc=example,dc=com\nobjectClass: person\ncn: Pipeline\nsn: User\n"
    parse_result = api.parse(ldif_content)
    if parse_result.is_failure:
        return
    entries = parse_result.value

    def validate_entry(entry: FlextLdifModels.Ldif.Entry) -> bool:
        """Validate entry DN."""
        dn_result = FlextLdifDn.validate_format(str(entry.dn))
        return dn_result.is_success

    _ = u.process(entries, validate_entry, on_error="skip")
    batch_result = api.process("transform", entries, parallel=False)
    if batch_result.is_success:
        processed = batch_result.value
        analysis_result = api.get_entry_statistics(entries)
        if analysis_result.is_success:
            stats = analysis_result.value
            _ = (len(processed), stats)


def access_all_utilities() -> None:
    """Demonstrate access to all utility classes."""
    time_utils = datetime.now(UTC)
    timestamp = time_utils.timestamp()
    size_bytes: float = 1024
    for unit in ["", "K", "M", "G", "T"]:
        if size_bytes < 1024.0:
            formatted_size = f"{size_bytes:.1f} {unit}B"
            break
        size_bytes /= 1024.0
    else:
        formatted_size = f"{size_bytes:.1f} PB"
    dn_result = FlextLdifDn.validate_format("cn=test,dc=example,dc=com")
    _ = (timestamp, formatted_size, dn_result)
