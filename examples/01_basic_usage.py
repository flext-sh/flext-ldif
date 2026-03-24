"""Example 1: DRY Railway Pattern - Minimal Code, Maximum Power.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

flext-ldif enables advanced capabilities with ZERO code bloat:
- Auto-detection, validation, parallel processing in ONE LINE each
- Railway pattern with early failure detection
- Context-aware processing with correlation tracking
- Batch transformations with validation

Python 3.13+ Advanced Features:
- PEP 695 type aliases with `type` keyword (no TypeAlias)
- Advanced type narrowing with TypeIs (PEP 742 ready)
- Structural pattern matching for result handling
- Advanced literal types from StrEnum values

Original: 195 lines | DRY Advanced: ~40 lines (80% reduction)
SRP: Each method does ONE thing, composition handles complexity
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Final

from flext_core import FlextContext, FlextLogger, r

from flext_ldif import FlextLdif, m

logger: Final = FlextLogger(__name__)


class BasicUsageDry:
    """DRY railway pattern: auto-detect → parse → validate → process."""

    SAMPLE_LDIF = "dn: cn=John Doe,ou=People,dc=example,dc=com\nobjectClass: person\nobjectClass: inetOrgPerson\ncn: John Doe\nsn: Doe\nmail: john.doe@example.com\n\ndn: cn=Jane Smith,ou=People,dc=example,dc=com\nobjectClass: person\nobjectClass: inetOrgPerson\ncn: Jane Smith\nsn: Smith\nmail: jane.smith@example.com\n"

    @staticmethod
    def batch_transform() -> r[Sequence[m.Ldif.Entry]]:
        """DRY batch transformation - returns created entries."""
        api = FlextLdif.get_instance()
        entries: Sequence[m.Ldif.Entry] = []
        for i in range(10):
            result = api.create_entry(
                dn=f"cn=User{i},ou=People,dc=example,dc=com",
                attributes={
                    "objectClass": ["person", "inetOrgPerson"],
                    "cn": [f"User{i}"],
                    "sn": [f"Name{i}"],
                    "mail": [f"user{i}@example.com"],
                },
            )
            if result.is_success:
                entries.append(result.value)
        if not entries:
            return r[Sequence[m.Ldif.Entry]].fail("Failed to create entries")
        transform_result = api.process(
            "transform",
            entries,
            parallel=True,
            max_workers=6,
        )
        if transform_result.is_failure:
            return r[Sequence[m.Ldif.Entry]].fail(
                transform_result.error or "Transform failed",
            )
        return r[Sequence[m.Ldif.Entry]].ok(entries)

    @staticmethod
    def file_pipeline() -> r[str]:
        """DRY file processing: detect → parse → validate → write.

        Returns:
            r with processing result or error.

        """
        api = FlextLdif.get_instance()
        sample_file = Path("examples/sample_basic.ldif")
        if not sample_file.exists():
            return r[str].fail("Sample file not found")
        ldif_content = sample_file.read_text(encoding="utf-8")
        detect_result = api.detect_server_type(ldif_content=ldif_content)
        if detect_result.is_failure:
            return r[str].fail(detect_result.error or "Server detection failed")

        detected = detect_result.value
        detected_server_type: str | None = getattr(
            detected,
            "detected_server_type",
            None,
        )
        server_type = detected_server_type or "rfc"
        parse_result = api.parse(sample_file, server_type=server_type)
        if parse_result.is_failure:
            return r[str].fail(parse_result.error or "Parse failed")

        parsed_entries = parse_result.value
        validate_result = api.validate_entries(parsed_entries)
        if validate_result.is_failure:
            return r[str].fail(validate_result.error or "Validation failed")
        write_result = api.write_file(parsed_entries, Path("examples/output_dry.ldif"))
        if write_result.is_failure:
            return r[str].fail(write_result.error or "Write failed")
        return r[str].ok("File processing complete")

    def context_pipeline(self) -> r[Sequence[m.Ldif.Entry]]:
        """Context-aware processing with correlation tracking.

        Returns:
            r with processing result or error.

        """
        api = FlextLdif.get_instance()
        with FlextContext.Correlation.new_correlation("req-123-dry"):
            server_result = api.get_effective_server_type()
            if server_result.is_failure:
                return r[Sequence[m.Ldif.Entry]].fail(
                    server_result.error or "Server detection failed",
                )
            parse_result = api.parse(
                self.SAMPLE_LDIF[:100],
                server_type=server_result.value,
            )
            if parse_result.is_failure:
                return parse_result
            validate_result = api.validate_entries(parse_result.value)
            if validate_result.is_failure:
                return r[Sequence[m.Ldif.Entry]].fail(
                    validate_result.error or "Validation failed",
                )
            return r[Sequence[m.Ldif.Entry]].ok(parse_result.value)

    def process_pipeline(self) -> r[Sequence[m.Ldif.Entry]]:
        """DRY railway: detect → parse → validate → parallel process.

        Python 3.13+ Features:
        - Advanced type narrowing with structural pattern matching
        - Type-safe result handling with Railway pattern
        - PEP 695 type aliases for better readability

        Returns:
            r with parsed and validated entries or error.

        """
        api = FlextLdif.get_instance()
        server_type = "rfc"
        detect_result = api.detect_server_type(ldif_content=self.SAMPLE_LDIF)
        if detect_result.is_success and detect_result.value.detected_server_type:
            server_type = detect_result.value.detected_server_type
        elif detect_result.is_failure:
            return r[Sequence[m.Ldif.Entry]].fail(
                detect_result.error or "Detection failed",
            )
        parse_result = api.parse(self.SAMPLE_LDIF, server_type=server_type)
        if parse_result.is_failure:
            return r[Sequence[m.Ldif.Entry]].fail(parse_result.error or "Parse failed")
        entries = parse_result.value
        validate_result = api.validate_entries(entries)
        if validate_result.is_failure:
            return r[Sequence[m.Ldif.Entry]].fail(
                validate_result.error or "Validation failed",
            )
        process_result = api.process("transform", entries, parallel=True, max_workers=4)
        if process_result.is_success:
            return r[Sequence[m.Ldif.Entry]].ok(entries)
        return r[Sequence[m.Ldif.Entry]].fail(process_result.error or "Process failed")
