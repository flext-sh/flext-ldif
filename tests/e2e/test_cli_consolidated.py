"""Consolidated CLI tests for FLEXT-LDIF."""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from flext_ldif import cli_main


class TestCLIConsolidated:
    """Consolidated CLI functionality tests."""

    @pytest.fixture
    def sample_ldif_file(self) -> Path:
      """Create a temporary LDIF file for testing."""
      content = """dn: cn=test,dc=example,dc=com
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
      """Test CLI help command."""
      with patch("sys.argv", ["flext-ldif", "--help"]):
          with pytest.raises(SystemExit) as exc_info:
              cli_main()
          # Help command exits with code 0
          assert exc_info.value.code == 0

    @pytest.mark.skipif(cli_main is None, reason="CLI not available")
    def test_cli_parse_command(self, sample_ldif_file: Path) -> None:
      """Test CLI parse command."""
      try:
          with patch("sys.argv", ["flext-ldif", "parse", str(sample_ldif_file)]):
              with pytest.raises(SystemExit) as exc_info:
                  cli_main()
              assert exc_info.value.code == 0
      finally:
          sample_ldif_file.unlink()

    @pytest.mark.skipif(cli_main is None, reason="CLI not available")
    def test_cli_validate_command(self, sample_ldif_file: Path) -> None:
      """Test CLI validate command."""
      try:
          with patch("sys.argv", ["flext-ldif", "validate", str(sample_ldif_file)]):
              with pytest.raises(SystemExit) as exc_info:
                  cli_main()
              assert exc_info.value.code == 0
      finally:
          sample_ldif_file.unlink()

    def test_cli_with_invalid_file(self) -> None:
      """Test CLI with non-existent file."""
      if cli_main is None:
          pytest.skip("CLI not available")

      with patch("sys.argv", ["flext-ldif", "parse", "/non/existent/file.ldif"]):
          with pytest.raises(SystemExit) as exc_info:
              cli_main()
          # Should exit with non-zero code for error
          assert exc_info.value.code != 0
