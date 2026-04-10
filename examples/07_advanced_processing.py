"""Example 7: Advanced Processing with Processors and Utilities.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Demonstrates ldif advanced functionality:
- Batch processing with direct API methods (no manual setup!)
- Utility functions (DN parsing, validation)
- Processing pipelines (streamlined)

All functionality accessed through ldif facade using direct methods.
No manual processor creation or conversion loops required.
"""

from __future__ import annotations

from collections.abc import MutableSequence
from datetime import UTC, datetime
from pathlib import Path

from flext_ldif import FlextLdif, ldif, m, u


def basic_batch_processing() -> None:
    """Process entries in batches using direct API method."""
    api: FlextLdif = ldif.get_instance()
    ldif_content = "dn: cn=User1,ou=People,dc=example,dc=com\nobjectClass: person\ncn: User1\nsn: One\n\ndn: cn=User2,ou=People,dc=example,dc=com\nobjectClass: person\ncn: User2\nsn: Two\n\ndn: cn=User3,ou=People,dc=example,dc=com\nobjectClass: person\ncn: User3\nsn: Three\n"
    parse_result = api.parse_ldif(ldif_content)
    if parse_result.is_failure:
        return
    parse_response = parse_result.unwrap()
    entries = parse_response.entries
    validation_result = api.validate_entries(entries)
    if validation_result.is_success:
        report = validation_result.unwrap()
        _ = report.total_entries


def parallel_processing() -> None:
    """Process multiple entries by building and validating them.

    Demonstrates creating entries directly via models and validating in batch.
    """
    api: FlextLdif = ldif.get_instance()
    entries: list[m.Ldif.Entry] = []
    for i in range(10):
        entry = m.Ldif.Entry(
            dn=m.Ldif.DN(value=f"cn=User{i},ou=People,dc=example,dc=com"),
            attributes=m.Ldif.Attributes(
                attributes={
                    "objectClass": ["person"],
                    "cn": [f"User{i}"],
                    "sn": [f"User{i}"],
                },
                attribute_metadata={},
            ),
        )
        entries.append(entry)
    validation_result = api.validate_entries(entries)
    if validation_result.is_success:
        report = validation_result.unwrap()
        _ = report.total_entries


def use_dn_utilities() -> None:
    """Use DN (Distinguished Name) utilities."""
    dn = "cn=John Doe,ou=People,dc=example,dc=com"
    parse_result = u.Ldif.parse_dn(dn)
    if parse_result.is_success:
        components = parse_result.value
        _ = len(components)
    normalize_result = u.Ldif.norm(dn)
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
    oid_result = u.Ldif.validate_format("2.5.4.3")
    if oid_result.is_success:
        _ = oid_result.value


def use_ldif_utilities() -> None:
    """Use LDIF-specific utilities."""
    api: FlextLdif = ldif.get_instance()
    ldif_content = (
        "dn: cn=test,dc=example,dc=com\nobjectClass: person\ncn: test\nsn: user\n"
    )
    syntax_result = api.parse_ldif(ldif_content)
    _ = syntax_result.is_success
    if syntax_result.is_success:
        parse_response = syntax_result.unwrap()
        entries = parse_response.entries
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
    api: FlextLdif = ldif.get_instance()
    ldif_content = "dn: cn=Pipeline,ou=People,dc=example,dc=com\nobjectClass: person\ncn: Pipeline\nsn: User\n"
    parse_result = api.parse_ldif(ldif_content)
    if parse_result.is_failure:
        return
    parse_response = parse_result.unwrap()
    entries = parse_response.entries

    valid_entries: MutableSequence[m.Ldif.Entry] = []
    for entry in entries:
        dn_result = u.Ldif.parse_dn(str(entry.dn.value) if entry.dn else "")
        if dn_result.is_success:
            valid_entries.append(entry)

    validation_result = api.validate_entries(valid_entries)
    if validation_result.is_success:
        report = validation_result.unwrap()
        _ = (len(valid_entries), report.total_entries)


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
    dn_result = u.Ldif.parse_dn("cn=test,dc=example,dc=com")
    _ = (timestamp, formatted_size, dn_result)
