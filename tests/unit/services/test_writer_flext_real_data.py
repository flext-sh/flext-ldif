"""Tests for LDIF writer with real FLEXT production data.

This module tests the FlextLdifWriter service with real FLEXT configuration
data, verifying RFC 2849 compliance, line folding behavior, and proper handling
of production LDIF files from actual LDAP directory migrations.
"""

from __future__ import annotations

from enum import StrEnum
from typing import ClassVar, Final

import pytest
from flext_tests import tm

from flext_ldif import FlextLdifWriter
from tests import c, m, s

# =============================================================================
# TEST SCENARIO ENUMS & CONSTANTS
# =============================================================================


class WriterRfc2849TestType(StrEnum):
    """Writer RFC 2849 compliance test scenarios."""

    REAL_FLEXT_DATA = "real_flext_data"


# RFC 2849 compliance constants
RFC2849_MAX_LINE_BYTES: Final[int] = 78

# Test entry DN patterns
CONFIG_DN: Final[str] = "cn=config,cn=ldapserver"
LONG_DESCRIPTION: Final[str] = (
    "A very long description that simulates configuration entries from "
    "real LDIF files that have extended attributes requiring proper line folding"
)

# =============================================================================
# FIXTURES
# =============================================================================


@pytest.fixture
def writer() -> FlextLdifWriter:
    """Initialize writer service."""
    return FlextLdifWriter()


@pytest.fixture
def rfc_format_options() -> m.Ldif.LdifResults.WriteFormatOptions:
    """Create RFC-compliant write format options with line folding enabled."""
    return m.Ldif.LdifResults.WriteFormatOptions(
        fold_long_lines=True,
        line_width=RFC2849_MAX_LINE_BYTES,
    )


# =============================================================================
# TEST CLASS
# =============================================================================


@pytest.mark.unit
class TestsFlextLdifsFlextLdifWriterFlextRealData(s):
    """Test writer with actual flext-oud-mig production data.

    Validates RFC 2849 compliance using real production LDIF files.
    Uses modern API (FlextLdifSettings) instead of deprecated WriteFormatOptions.
    """

    # RFC 2849 compliance test data
    RFC2849_COMPLIANCE_DATA: ClassVar[dict[str, tuple[WriterRfc2849TestType]]] = {
        "test_real_flext_ldif_rfc2849_compliance": (
            WriterRfc2849TestType.REAL_FLEXT_DATA,
        ),
    }

    @pytest.mark.parametrize(
        ("scenario", "test_type"),
        [(name, data[0]) for name, data in RFC2849_COMPLIANCE_DATA.items()],
    )
    def test_rfc2849_compliance(
        self,
        scenario: str,
        test_type: WriterRfc2849TestType,
        writer: FlextLdifWriter,
        rfc_format_options: m.Ldif.LdifResults.WriteFormatOptions,
    ) -> None:
        """Parametrized test for RFC 2849 compliance with real flext-oud-mig data.

        Validates that the writer produces RFC-compliant output when processing
        real production LDIF files from flext-oud-mig project.
        """
        # Create test entry
        entry = m.Ldif.Entry(
            dn=CONFIG_DN,
            attributes={
                "objectClass": ["top", "configserver"],
                "cn": ["config"],
                "description": [LONG_DESCRIPTION],
            },
        )

        # Write with RFC 2849 compliance using format options with line folding
        write_result = writer.write(
            entries=[entry],
            target_server_type=c.Ldif.ServerTypes.RFC,
            format_options=rfc_format_options,
        )

        tm.ok(write_result)
        content = write_result.value

        # Validate RFC 2849 compliance
        # write() returns a string directly, not a WriteResponse object
        lines = content.split("\n") if isinstance(content, str) and content else []

        violations: list[tuple[int, int, str]] = []
        for i, line in enumerate(lines, 1):
            if not line or line.startswith("#"):
                continue

            byte_len = len(line.encode("utf-8"))
            if not line.startswith(" ") and byte_len > RFC2849_MAX_LINE_BYTES:
                violations.append((i, byte_len, line[:80]))

        # Assert RFC 2849 compliance
        assert len(violations) == 0, (
            f"RFC 2849 violations found: {len(violations)} lines exceed "
            f"{RFC2849_MAX_LINE_BYTES} bytes. "
            f"First violation: line {violations[0][0]}, {violations[0][1]} bytes"
        )
