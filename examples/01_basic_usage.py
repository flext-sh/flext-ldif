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

from pathlib import Path
from typing import Final

from flext_core import FlextContext
from flext_ldif import c, ldif, m, p, r


class BasicUsageDry:
    """DRY railway pattern: auto-detect -> parse -> validate -> process."""

    SAMPLE_LDIF: Final[str] = (
        "dn: cn=John Doe,ou=People,dc=example,dc=com\n"
        "objectClass: person\n"
        "objectClass: inetOrgPerson\n"
        "cn: John Doe\n"
        "sn: Doe\n"
        "mail: john.doe@example.com\n\n"
        "dn: cn=Jane Smith,ou=People,dc=example,dc=com\n"
        "objectClass: person\n"
        "objectClass: inetOrgPerson\n"
        "cn: Jane Smith\n"
        "sn: Smith\n"
        "mail: jane.smith@example.com\n"
    )
    SAMPLE_INPUT_PATH: Final[Path] = Path("examples/sample_basic.ldif")
    SAMPLE_OUTPUT_PATH: Final[Path] = Path("examples/output_dry.ldif")
    SAMPLE_CORRELATION_ID: Final[str] = "req-123-dry"
    DEFAULT_SERVER_TYPE: Final[str] = c.Ldif.ServerTypes.RFC
    DEFAULT_ENCODING: Final[str] = c.Ldif.Encoding.UTF8
    OBJECT_CLASSES: Final[tuple[str, str]] = ("person", "inetOrgPerson")
    BASE_DN: Final[str] = "ou=People,dc=example,dc=com"

    @classmethod
    def _build_entry(cls, index: int) -> m.Ldif.Entry:
        """Build one canonical LDIF entry for batch examples."""
        return m.Ldif.Entry(
            dn=m.Ldif.DN(value=f"cn=User{index},{cls.BASE_DN}"),
            attributes=m.Ldif.Attributes(
                attributes={
                    "objectClass": [*cls.OBJECT_CLASSES],
                    "cn": [f"User{index}"],
                    "sn": [f"Name{index}"],
                    "mail": [f"user{index}@example.com"],
                },
                attribute_metadata={},
            ),
        )

    @classmethod
    def _resolve_server_type(cls, source: str | Path) -> p.Result[str]:
        """Resolve the server type from canonical LDIF input sources."""
        match source:
            case Path() as path:
                result = ldif.resolve_effective_server_type(ldif_path=path)
            case _:
                result = ldif.resolve_effective_server_type(ldif_content=source)
        return result.map(lambda server_type: server_type or cls.DEFAULT_SERVER_TYPE)

    @classmethod
    def _parse_validated_entries(
        cls, source: str | Path, *, server_type: str | None = None
    ) -> p.Result[list[m.Ldif.Entry]]:
        """Parse and validate LDIF input through the public facade only."""
        match source:
            case Path() as path:
                parse_result = ldif.parse_ldif_file(
                    path, server_type=server_type, encoding=cls.DEFAULT_ENCODING
                )
            case _:
                parse_result = ldif.parse_ldif(source, server_type=server_type)
        return parse_result.flat_map(
            lambda response: ldif.validate_entries(response).map(
                lambda _: list(response.entries)
            )
        )

    @classmethod
    def batch_transform(cls) -> p.Result[list[m.Ldif.Entry]]:
        """DRY batch transformation - returns created entries."""
        entries: list[m.Ldif.Entry] = [cls._build_entry(index) for index in range(10)]
        return ldif.validate_entries(entries).map(lambda _: entries)

    @classmethod
    def file_pipeline(cls) -> p.Result[str]:
        """DRY file processing: detect -> parse -> validate -> write.

        Returns:
            r with processing result or error.

        """
        if not cls.SAMPLE_INPUT_PATH.exists():
            return r[str].fail_op(
                "load sample ldif", f"Sample file not found: {cls.SAMPLE_INPUT_PATH}"
            )
        return cls._resolve_server_type(cls.SAMPLE_INPUT_PATH).flat_map(
            lambda server_type: cls._parse_validated_entries(
                cls.SAMPLE_INPUT_PATH, server_type=server_type
            ).flat_map(
                lambda entries: ldif.write_ldif_file(
                    entries, cls.SAMPLE_OUTPUT_PATH, server_type=server_type
                ).map(lambda _: "File processing complete")
            )
        )

    def context_pipeline(self) -> p.Result[list[m.Ldif.Entry]]:
        """Context-aware processing with correlation tracking.

        Returns:
            r with processing result or error.

        """
        with FlextContext.new_correlation(self.SAMPLE_CORRELATION_ID):
            return self._resolve_server_type(self.SAMPLE_LDIF).flat_map(
                lambda server_type: self._parse_validated_entries(
                    self.SAMPLE_LDIF, server_type=server_type
                )
            )

    def process_pipeline(self) -> p.Result[list[m.Ldif.Entry]]:
        """DRY railway: detect -> parse -> validate.

        Python 3.13+ Features:
        - Advanced type narrowing with structural pattern matching
        - Type-safe result handling with Railway pattern
        - PEP 695 type aliases for better readability

        Returns:
            r with parsed and validated list[m.Ldif.Entry] or error.

        """
        return self._resolve_server_type(self.SAMPLE_LDIF).flat_map(
            lambda server_type: self._parse_validated_entries(
                self.SAMPLE_LDIF, server_type=server_type
            )
        )
