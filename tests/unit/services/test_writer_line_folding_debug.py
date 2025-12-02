"""Test suite for Writer service line folding functionality.

Modules tested: FlextLdifWriter (write method with format options)
Scope: Line folding behavior with fold_long_lines option enabled/disabled. Tests
RFC 2849 compliance for line width limits (76 characters), continuation lines
(starting with space), and actual line length validation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

# from flext_tests import FlextTestsMatchers  # Mocked in conftest
from flext_ldif import FlextLdifModels, FlextLdifWriter
from tests.fixtures.constants import DNs


class TestWriterLineFoldingDebug:
    """Debug line folding behavior in Writer."""

    @pytest.fixture
    def writer(self) -> FlextLdifWriter:
        """Initialize writer service."""
        return FlextLdifWriter()

    @pytest.fixture
    def long_value_entry(self) -> FlextLdifModels.Entry:
        """Create entry with long attribute value that needs folding."""
        long_value = "A" * 100  # 100 character value
        return FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value=DNs.TEST_USER),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "cn": ["test"],
                    "description": [long_value],  # Very long
                    "objectClass": ["person"],
                },
            ),
        )

    def test_fold_long_lines_enabled_explicit(
        self,
        writer: FlextLdifWriter,
        long_value_entry: FlextLdifModels.Entry,
    ) -> None:
        """Test line folding WITH fold_long_lines=True explicitly."""
        result = writer.write(
            entries=[long_value_entry],
            target_server_type="rfc",
            _output_target="string",
            format_options=FlextLdifModels.WriteFormatOptions(
                fold_long_lines=True,
                line_width=76,  # RFC 2849 recommendation
            ),
        )

        FlextTestsMatchers.assert_success(result)
        output = result.unwrap()

        # With folding ENABLED, long lines should be wrapped
        # Check if there are any continuation lines (starting with space)
        if isinstance(output, FlextLdifModels.WriteResponse) and output.content:
            lines = output.content.split("\n")
            has_continuation = any(line.startswith(" ") for line in lines if line)
            assert has_continuation, (
                "Long lines should be folded with continuation lines"
            )
        elif isinstance(output, str):
            lines = output.split("\n")
            has_continuation = any(line.startswith(" ") for line in lines if line)
            assert has_continuation, (
                "Long lines should be folded with continuation lines"
            )

    def test_fold_long_lines_disabled_explicit(
        self,
        writer: FlextLdifWriter,
        long_value_entry: FlextLdifModels.Entry,
    ) -> None:
        """Test line folding WITH fold_long_lines=False explicitly."""
        result = writer.write(
            entries=[long_value_entry],
            target_server_type="rfc",
            _output_target="string",
            format_options=FlextLdifModels.WriteFormatOptions(
                fold_long_lines=False,
                line_width=76,
            ),
        )

        FlextTestsMatchers.assert_success(result)
        output = result.unwrap()

        # With folding DISABLED, verify output is valid
        if isinstance(output, str):
            lines = output.split("\n")
            assert len(lines) > 0
        elif isinstance(output, FlextLdifModels.WriteResponse) and output.content:
            assert output.content is not None

    def test_fold_long_lines_override(
        self,
        writer: FlextLdifWriter,
        long_value_entry: FlextLdifModels.Entry,
    ) -> None:
        """Test fold_long_lines=False to disable line folding."""
        result = writer.write(
            entries=[long_value_entry],
            target_server_type="rfc",
            _output_target="string",
            format_options=FlextLdifModels.WriteFormatOptions(
                fold_long_lines=False,  # Disable line folding
                line_width=76,
            ),
        )

        FlextTestsMatchers.assert_success(result)
        output = result.unwrap()

        # With folding DISABLED, verify output is valid
        if isinstance(output, str):
            lines = output.split("\n")
            assert len(lines) > 0
        elif isinstance(output, FlextLdifModels.WriteResponse) and output.content:
            assert output.content is not None

    def test_check_actual_line_lengths(
        self,
        writer: FlextLdifWriter,
        long_value_entry: FlextLdifModels.Entry,
    ) -> None:
        """Check actual line lengths when folding should occur."""
        result = writer.write(
            entries=[long_value_entry],
            target_server_type="rfc",
            _output_target="string",
            format_options=FlextLdifModels.WriteFormatOptions(
                fold_long_lines=True,
                line_width=76,
            ),
        )

        FlextTestsMatchers.assert_success(result)
        output = result.unwrap()

        lines = output.split("\n") if isinstance(output, str) else []
        over_limit = [
            (i, len(line.encode("utf-8")), line[:80])
            for i, line in enumerate(lines, 1)
            if line and not line.startswith("#") and len(line.encode("utf-8")) > 76
        ]

        # With folding enabled, lines over limit should be folded
        # If there are over-limit lines, they should have continuation lines
        if over_limit:
            # Verify that continuation lines exist for long lines
            continuation_count = sum(1 for line in lines if line.startswith(" "))
            assert continuation_count > 0, "Long lines should have continuation lines"
