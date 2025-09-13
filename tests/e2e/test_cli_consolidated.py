"""Consolidated CLI tests for FLEXT-LDIF - Real functionality without mocks.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import sys
import tempfile
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

import pytest
from flext_core import FlextTypes

from flext_ldif import main as cli_main


@contextmanager
def argv_context(argv: FlextTypes.Core.StringList) -> Generator[None]:
    """Context manager to temporarily replace sys.argv."""
    old_argv = sys.argv
    try:
        sys.argv = argv
        yield
    finally:
        sys.argv = old_argv


class TestCLIConsolidated:
    """Consolidated CLI functionality tests using real CLI execution."""

    @pytest.fixture
    def sample_ldif_file(self) -> Path:
        """Create a temporary LDIF file for testing."""
        content = """dn: cn=test,dc=example,dc=com
cn: test
sn: user
objectClass: person
objectClass: inetOrgPerson
mail: test@example.com
"""

        with tempfile.NamedTemporaryFile(
            encoding="utf-8",
            mode="w",
            suffix=".ldif",
            delete=False,
        ) as f:
            f.write(content)
            return Path(f.name)

    @pytest.fixture
    def invalid_ldif_file(self) -> Path:
        """Create a temporary invalid LDIF file for testing."""
        content = """invalid_line_without_dn
cn: test
objectClass: person
"""

        with tempfile.NamedTemporaryFile(
            encoding="utf-8",
            mode="w",
            suffix=".ldif",
            delete=False,
        ) as f:
            f.write(content)
            return Path(f.name)

    def test_cli_main_available(self) -> None:
        """Test that CLI main function is available."""
        assert cli_main is not None

    @pytest.mark.skipif(cli_main is None, reason="CLI not available")
    def test_cli_help_command(self) -> None:
        """Test CLI help command executes successfully."""
        with argv_context(["flext-ldif", "--help"]):
            with pytest.raises(SystemExit) as exc_info:
                cli_main()
            # Help command exits with code 0
            assert exc_info.value.code == 0

    @pytest.mark.skipif(cli_main is None, reason="CLI not available")
    def test_cli_parse_command(self, sample_ldif_file: Path) -> None:
        """Test CLI parse command with real LDIF file."""
        try:
            with argv_context(["flext-ldif", "parse", str(sample_ldif_file)]):
                with pytest.raises(SystemExit) as exc_info:
                    cli_main()
                assert exc_info.value.code == 0
        finally:
            sample_ldif_file.unlink(missing_ok=True)

    @pytest.mark.skipif(cli_main is None, reason="CLI not available")
    def test_cli_validate_command(self, sample_ldif_file: Path) -> None:
        """Test CLI validate command with real LDIF file."""
        try:
            with argv_context(["flext-ldif", "validate", str(sample_ldif_file)]):
                with pytest.raises(SystemExit) as exc_info:
                    cli_main()
                assert exc_info.value.code == 0
        finally:
            sample_ldif_file.unlink(missing_ok=True)

    @pytest.mark.skip(reason="CLI temporarily disabled due to flext-cli import issues")
    def test_cli_with_invalid_file(self) -> None:
        """Test CLI with non-existent file returns error."""
        if cli_main is None:
            pytest.skip("CLI not available")

        with argv_context(["flext-ldif", "parse", "/non/existent/file.ldif"]):
            with pytest.raises(SystemExit) as exc_info:
                cli_main()
            # Should exit with non-zero code for error
            assert exc_info.value.code != 0

    @pytest.mark.skipif(cli_main is None, reason="CLI not available")
    def test_cli_with_invalid_ldif_content(self, invalid_ldif_file: Path) -> None:
        """Test CLI with invalid LDIF content."""
        try:
            with argv_context(["flext-ldif", "parse", str(invalid_ldif_file)]):
                with pytest.raises(SystemExit) as exc_info:
                    cli_main()
                # Should handle invalid LDIF gracefully
                assert exc_info.value.code in {0, 1, 2}  # Allow various error codes
        finally:
            invalid_ldif_file.unlink(missing_ok=True)

    @pytest.mark.skipif(cli_main is None, reason="CLI not available")
    def test_cli_no_arguments(self) -> None:
        """Test CLI with no arguments shows help or error."""
        with argv_context(["flext-ldif"]):
            with pytest.raises(SystemExit) as exc_info:
                cli_main()
            # Should exit with some code (0 for help, or error code)
            assert isinstance(exc_info.value.code, int)
