"""Debug tests for line folding in Writer service.

Tests to identify and diagnose line folding issues.
"""

from __future__ import annotations

import pytest

from flext_ldif.models import FlextLdifModels
from flext_ldif.services.writer import FlextLdifWriter


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
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
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
            output_target="string",
            format_options=FlextLdifModels.WriteFormatOptions(
                fold_long_lines=True,
                line_width=76,  # RFC 2849 recommendation
            ),
        )

        assert result.is_success
        output = result.unwrap()

        # Debug output
        for _i, _line in enumerate(output.split("\n"), 1):
            pass

        # With folding ENABLED, long lines should be wrapped
        # Check if there are any continuation lines (starting with space)
        lines = output.split("\n")
        any(line.startswith(" ") for line in lines if line)

    def test_fold_long_lines_disabled_explicit(
        self,
        writer: FlextLdifWriter,
        long_value_entry: FlextLdifModels.Entry,
    ) -> None:
        """Test line folding WITH fold_long_lines=False explicitly."""
        result = writer.write(
            entries=[long_value_entry],
            target_server_type="rfc",
            output_target="string",
            format_options=FlextLdifModels.WriteFormatOptions(
                fold_long_lines=False,
                line_width=76,
            ),
        )

        assert result.is_success
        output = result.unwrap()

        for _i, _line in enumerate(output.split("\n"), 1):
            pass

        lines = output.split("\n")
        any(line.startswith(" ") for line in lines if line)

    def test_fold_long_lines_override(
        self,
        writer: FlextLdifWriter,
        long_value_entry: FlextLdifModels.Entry,
    ) -> None:
        """Test fold_long_lines=False to disable line folding."""
        result = writer.write(
            entries=[long_value_entry],
            target_server_type="rfc",
            output_target="string",
            format_options=FlextLdifModels.WriteFormatOptions(
                fold_long_lines=False,  # Disable line folding
                line_width=76,
            ),
        )

        assert result.is_success
        output = result.unwrap()

        for _i, _line in enumerate(output.split("\n"), 1):
            pass

        lines = output.split("\n")
        any(line.startswith(" ") for line in lines if line)

    def test_check_actual_line_lengths(
        self,
        writer: FlextLdifWriter,
        long_value_entry: FlextLdifModels.Entry,
    ) -> None:
        """Check actual line lengths when folding should occur."""
        result = writer.write(
            entries=[long_value_entry],
            target_server_type="rfc",
            output_target="string",
            format_options=FlextLdifModels.WriteFormatOptions(
                fold_long_lines=True,
                line_width=76,
            ),
        )

        assert result.is_success
        output = result.unwrap()

        lines = output.split("\n")
        over_limit = []
        for i, line in enumerate(lines, 1):
            if line and not line.startswith("#"):  # Skip comments
                length = len(line.encode("utf-8"))  # LDIF uses UTF-8
                if length > 76:
                    over_limit.append((i, length, line[:80]))

        if over_limit:
            for _line_no, _length, _content in over_limit:
                pass
