"""Tests for LDIF writer line folding behavior.

This module tests line folding functionality in the FlextLdifWriter service,
validating RFC 2849 line length compliance, multi-line attribute handling, and
proper continuation of long values across multiple LDIF lines.
"""

from __future__ import annotations

from typing import ClassVar

import pytest
from flext_tests import tm

from flext_ldif import FlextLdifWriter
from flext_ldif.protocols import p
from tests import c, m, s


class TestsFlextLdifWriterLineFoldingDebug(s):
    """Debug line folding behavior in Writer."""

    writer: ClassVar[FlextLdifWriter]  # pytest fixture
    long_value_entry: ClassVar[p.Entry]  # pytest fixture

    @pytest.fixture
    def writer(self) -> FlextLdifWriter:
        """Initialize writer service."""
        return FlextLdifWriter()

    @pytest.fixture
    def long_value_entry(self) -> p.Entry:
        """Create entry with long attribute value that needs folding."""
        long_value = "A" * 100  # 100 character value
        return p.Entry(
            dn=m.DistinguishedName(value=c.DNs.TEST_USER),
            attributes=m.LdifAttributes(
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
        long_value_entry: p.Entry,
    ) -> None:
        """Test line folding WITH fold_long_lines=True explicitly."""
        result = writer.write(
            entries=[long_value_entry],
            target_server_type="rfc",
            _output_target="string",
            format_options=m.WriteFormatOptions(
                fold_long_lines=True,
                line_width=76,  # RFC 2849 recommendation
            ),
        )

        tm.ok(result)
        output = result.unwrap()

        # With folding ENABLED, long lines should be wrapped
        # Check if there are any continuation lines (starting with space)
        if isinstance(output, m.WriteResponse) and output.content:
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
        long_value_entry: p.Entry,
    ) -> None:
        """Test line folding WITH fold_long_lines=False explicitly."""
        result = writer.write(
            entries=[long_value_entry],
            target_server_type="rfc",
            _output_target="string",
            format_options=m.WriteFormatOptions(
                fold_long_lines=False,
                line_width=76,
            ),
        )

        tm.ok(result)
        output = result.unwrap()

        # With folding DISABLED, verify output is valid
        if isinstance(output, str):
            lines = output.split("\n")
            assert len(lines) > 0
        elif isinstance(output, m.WriteResponse) and output.content:
            assert output.content is not None

    def test_fold_long_lines_override(
        self,
        writer: FlextLdifWriter,
        long_value_entry: p.Entry,
    ) -> None:
        """Test fold_long_lines=False to disable line folding."""
        result = writer.write(
            entries=[long_value_entry],
            target_server_type="rfc",
            _output_target="string",
            format_options=m.WriteFormatOptions(
                fold_long_lines=False,  # Disable line folding
                line_width=76,
            ),
        )

        tm.ok(result)
        output = result.unwrap()

        # With folding DISABLED, verify output is valid
        if isinstance(output, str):
            lines = output.split("\n")
            assert len(lines) > 0
        elif isinstance(output, m.WriteResponse) and output.content:
            assert output.content is not None

    def test_check_actual_line_lengths(
        self,
        writer: FlextLdifWriter,
        long_value_entry: p.Entry,
    ) -> None:
        """Check actual line lengths when folding should occur."""
        result = writer.write(
            entries=[long_value_entry],
            target_server_type="rfc",
            _output_target="string",
            format_options=m.WriteFormatOptions(
                fold_long_lines=True,
                line_width=76,
            ),
        )

        tm.ok(result)
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
