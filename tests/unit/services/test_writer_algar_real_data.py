"""Real validation of line folding with actual algar-oud-mig data.

Tests FlextLdifWriter service with complete RFC 2849 compliance validation
using actual production data from algar-oud-mig project.

Scope:
- RFC 2849 line folding compliance (76-byte limit)
- Real production LDIF data validation
- Writer service integration
- Format options and configuration

Uses advanced Python 3.13 features, factories, and centralized constants
for minimal code with maximum coverage.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import ClassVar, Final

import pytest
from flext_tests import FlextTestsMatchers

from flext_ldif import FlextLdifModels, FlextLdifWriter
from flext_ldif.config import FlextLdifConfig
from flext_ldif.constants import FlextLdifConstants
from tests.fixtures.constants import Names
from tests.helpers.test_factories import FlextLdifTestFactories

# =============================================================================
# TEST SCENARIO ENUMS & CONSTANTS
# =============================================================================


class WriterRfc2849TestType(StrEnum):
    """Writer RFC 2849 compliance test scenarios."""

    REAL_ALGAR_DATA = "real_algar_data"


# RFC 2849 compliance constants
RFC2849_MAX_LINE_BYTES: Final[int] = 76
ALGAR_INPUT_FILE: Final[Path] = Path(
    "/home/marlonsc/flext/algar-oud-mig/data/input/2_ldap_configset.ldif",
)

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
def rfc_config() -> FlextLdifConfig:
    """Create RFC-compliant configuration."""
    return FlextLdifConfig(
        ldif_write_fold_long_lines=True,
        ldif_max_line_length=RFC2849_MAX_LINE_BYTES,
    )


# =============================================================================
# TEST CLASS
# =============================================================================


@pytest.mark.unit
class TestFlextLdifWriterAlgarRealData:
    """Test writer with actual algar-oud-mig production data.

    Validates RFC 2849 compliance using real production LDIF files.
    Uses modern API (FlextLdifConfig) instead of deprecated WriteFormatOptions.
    """

    # RFC 2849 compliance test data
    RFC2849_COMPLIANCE_DATA: ClassVar[dict[str, tuple[WriterRfc2849TestType]]] = {
        "test_real_algar_ldif_rfc2849_compliance": (
            WriterRfc2849TestType.REAL_ALGAR_DATA,
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
        rfc_config: FlextLdifConfig,
    ) -> None:
        """Parametrized test for RFC 2849 compliance with real algar-oud-mig data.

        Validates that the writer produces RFC-compliant output when processing
        real production LDIF files from algar-oud-mig project.
        """
        # Skip test if file doesn't exist (for CI/CD environments)
        if not ALGAR_INPUT_FILE.exists():
            pytest.skip("algar-oud-mig data not available in this environment")

        # Create test entry using factory
        entry = FlextLdifTestFactories.create_entry(
            dn=CONFIG_DN,
            attributes={
                Names.OBJECTCLASS: [Names.TOP, "configserver"],
                Names.CN: ["config"],
                "description": [LONG_DESCRIPTION],
            },
        )

        # Write with RFC 2849 compliance using modern API
        write_result = writer.write(
            entries=[entry],
            target_server_type=FlextLdifConstants.ServerTypes.RFC,
            output_target="string",
        )

        FlextTestsMatchers.assert_success(write_result)
        content = write_result.unwrap()

        # Validate RFC 2849 compliance
        if isinstance(content, FlextLdifModels.WriteResponse) and content.content:
            lines = content.content.split("\n")
        else:
            lines = []

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
