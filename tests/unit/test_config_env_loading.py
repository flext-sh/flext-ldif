"""Test .env loading and environment variable precedence with Pydantic 2 Settings.

This test validates the complete configuration loading chain:

Order of Preference (Pydantic 2 Settings automatic behavior):
1. Direct instantiation parameters (highest priority)
2. Environment variables (FLEXT_LDIF_*)
3. .env file values
4. Default values from FlextLdifConstants (lowest priority)

Inheritance:
- FlextLdifConfig → FlextCore.Config → BaseSettings
- FlextCore.Config: FLEXT_ prefix, loads from .env
- FlextLdifConfig: FLEXT_LDIF_ prefix, inherits .env loading

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from flext_ldif.config import FlextLdifConfig
from flext_ldif.constants import FlextLdifConstants


class TestEnvVariableLoading:
    """Test environment variable loading with Pydantic 2 Settings."""

    def test_default_values_from_constants(self) -> None:
        """Test that defaults come from FlextLdifConstants."""
        config = FlextLdifConfig()

        # Verify defaults match constants
        assert config.ldif_encoding == FlextLdifConstants.Encoding.DEFAULT_ENCODING
        assert config.ldif_max_line_length == FlextLdifConstants.Format.MAX_LINE_LENGTH
        assert (
            config.ldif_skip_comments
            == FlextLdifConstants.ConfigDefaults.LDIF_SKIP_COMMENTS
        )
        assert (
            config.ldif_strict_validation
            == FlextLdifConstants.ConfigDefaults.LDIF_STRICT_VALIDATION
        )
        assert config.ldif_chunk_size == FlextLdifConstants.DEFAULT_BATCH_SIZE
        assert (
            config.max_workers
            == FlextLdifConstants.LdifProcessing.PERFORMANCE_MIN_WORKERS
        )

    def test_env_variable_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test environment variables override defaults.

        Note: max_workers is inherited from FlextCore.Config, so it uses FLEXT_MAX_WORKERS.
        LDIF-specific fields use FLEXT_LDIF_* environment variables.
        """
        # LDIF-specific fields use FLEXT_LDIF_ prefix
        monkeypatch.setenv("FLEXT_LDIF_ENCODING", "utf-16")
        monkeypatch.setenv("FLEXT_LDIF_MAX_LINE_LENGTH", "100")
        monkeypatch.setenv("FLEXT_LDIF_SKIP_COMMENTS", "true")
        monkeypatch.setenv("FLEXT_LDIF_STRICT_VALIDATION", "false")
        monkeypatch.setenv("FLEXT_LDIF_CHUNK_SIZE", "2000")

        # Inherited field from FlextCore.Config uses FLEXT_ prefix
        monkeypatch.setenv("FLEXT_MAX_WORKERS", "8")

        config = FlextLdifConfig()

        # Verify environment variables override defaults
        assert config.ldif_encoding == "utf-16"
        assert config.ldif_max_line_length == 100
        assert config.ldif_skip_comments is True
        assert config.ldif_strict_validation is False
        assert config.ldif_chunk_size == 2000
        assert config.max_workers == 8

    def test_direct_instantiation_override(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test direct parameters override environment variables (highest priority)."""
        # Set environment variables
        monkeypatch.setenv("FLEXT_LDIF_ENCODING", "utf-16")
        monkeypatch.setenv(
            "FLEXT_MAX_WORKERS", "8"
        )  # Inherited field uses FLEXT_ prefix

        # Direct instantiation overrides env var
        # Note: disable performance mode to allow max_workers < 4
        config = FlextLdifConfig(
            ldif_encoding="latin-1",
            max_workers=2,
            enable_performance_optimizations=False,
        )

        # Direct params win over env vars
        assert config.ldif_encoding == "latin-1"
        assert config.max_workers == 2

    def test_env_prefix_flext_ldif(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test FLEXT_LDIF_ prefix is required for FlextLdifConfig."""
        # Wrong prefix (FLEXT_ instead of FLEXT_LDIF_)
        monkeypatch.setenv("FLEXT_ENCODING", "utf-16")

        config = FlextLdifConfig()

        # Should use default, not FLEXT_ENCODING
        assert config.ldif_encoding == FlextLdifConstants.Encoding.DEFAULT_ENCODING

        # Correct prefix
        monkeypatch.setenv("FLEXT_LDIF_ENCODING", "utf-16")
        config = FlextLdifConfig()
        assert config.ldif_encoding == "utf-16"

    def test_case_insensitive_env_vars(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test environment variables are case-insensitive."""
        # Set with different cases
        monkeypatch.setenv("flext_ldif_encoding", "utf-16")  # lowercase
        monkeypatch.setenv("flext_max_workers", "8")  # lowercase, inherited field

        config = FlextLdifConfig()

        # Both should work (case_sensitive=False)
        assert config.ldif_encoding == "utf-16"
        assert config.max_workers == 8

    def test_type_coercion_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test Pydantic type coercion from string env vars."""
        # Set as strings (as environment variables always are)
        monkeypatch.setenv("FLEXT_LDIF_MAX_LINE_LENGTH", "100")  # string → int
        monkeypatch.setenv("FLEXT_LDIF_SKIP_COMMENTS", "true")  # string → bool
        monkeypatch.setenv("FLEXT_LDIF_ANALYTICS_SAMPLE_RATE", "0.75")  # string → float

        config = FlextLdifConfig()

        # Verify proper type coercion
        assert isinstance(config.ldif_max_line_length, int)
        assert config.ldif_max_line_length == 100

        assert isinstance(config.ldif_skip_comments, bool)
        assert config.ldif_skip_comments is True

        assert isinstance(config.ldif_analytics_sample_rate, float)
        assert config.ldif_analytics_sample_rate == 0.75

    def test_validation_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test field validators work with environment variables."""
        # Invalid encoding
        monkeypatch.setenv("FLEXT_LDIF_ENCODING", "invalid-encoding")

        with pytest.raises(ValidationError, match="Invalid encoding"):
            FlextLdifConfig()

        # Invalid max_workers (too high) - inherited field uses FLEXT_ prefix
        monkeypatch.delenv("FLEXT_LDIF_ENCODING", raising=False)
        monkeypatch.setenv("FLEXT_MAX_WORKERS", "999")

        with pytest.raises(ValidationError, match="less than or equal"):
            FlextLdifConfig()

    def test_nested_delimiter_support(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test nested delimiter __ for complex config (inherited from FlextCore.Config).

        Note: FlextLdifConfig uses env_prefix="FLEXT_" because field names have ldif_ prefix.
        This gives us FLEXT_LDIF_* environment variables (FLEXT_ + ldif_field_name).
        """
        config = FlextLdifConfig()

        # Verify model_config has proper settings
        assert "env_prefix" in config.model_config
        assert (
            config.model_config["env_prefix"] == "FLEXT_"
        )  # Combined with ldif_ field names = FLEXT_LDIF_*
        assert config.model_config.get("env_nested_delimiter") == "__"

    def test_extra_fields_ignored(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test extra environment variables are ignored (extra='ignore')."""
        # Set non-existent field
        monkeypatch.setenv("FLEXT_LDIF_NONEXISTENT_FIELD", "value")

        # Should not raise error
        config = FlextLdifConfig()
        assert not hasattr(config, "nonexistent_field")


class TestDotEnvFileLoading:
    """Test .env file loading with Pydantic 2 Settings."""

    def test_env_file_loading(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test .env file is automatically loaded."""
        # Create .env file
        env_file = tmp_path / ".env"
        env_file.write_text(
            """
FLEXT_LDIF_ENCODING=utf-16
FLEXT_MAX_WORKERS=6
FLEXT_LDIF_SKIP_COMMENTS=true
"""
        )

        # Change to temp directory
        monkeypatch.chdir(tmp_path)

        config = FlextLdifConfig()

        # Verify .env file was loaded
        assert config.ldif_encoding == "utf-16"
        assert config.max_workers == 6
        assert config.ldif_skip_comments is True

    def test_env_var_overrides_env_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test environment variables override .env file values."""
        # Create .env file
        env_file = tmp_path / ".env"
        env_file.write_text("FLEXT_LDIF_ENCODING=utf-16\n")

        monkeypatch.chdir(tmp_path)

        # Set environment variable (higher priority)
        monkeypatch.setenv("FLEXT_LDIF_ENCODING", "latin-1")

        config = FlextLdifConfig()

        # Environment variable wins over .env file
        assert config.ldif_encoding == "latin-1"


class TestConfigInheritance:
    """Test FlextCore.Config inheritance."""

    def test_inherits_from_flext_config(self) -> None:
        """Test FlextLdifConfig inherits from FlextCore.Config."""
        from flext_core import FlextCore

        config = FlextLdifConfig()

        # Verify inheritance
        assert isinstance(config, FlextCore.Config)

        # Verify FlextCore.Config fields are accessible
        assert hasattr(config, "debug")
        assert hasattr(config, "log_level")

    def test_flext_config_env_prefix(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test FlextCore.Config uses FLEXT_ prefix while FlextLdifConfig uses FLEXT_LDIF_."""
        # FlextCore.Config field with FLEXT_ prefix
        monkeypatch.setenv("FLEXT_DEBUG", "true")

        # FlextLdifConfig field with FLEXT_LDIF_ prefix
        monkeypatch.setenv("FLEXT_LDIF_ENCODING", "utf-16")

        config = FlextLdifConfig()

        # Both prefixes should work for their respective fields
        assert config.debug is True  # from FlextCore.Config with FLEXT_
        assert config.ldif_encoding == "utf-16"  # from FlextLdifConfig with FLEXT_LDIF_


class TestOrderOfPrecedence:
    """Test complete order of precedence for configuration loading."""

    def test_complete_precedence_chain(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test complete order: direct > env var > .env file > defaults."""
        # 1. Default from FlextLdifConstants
        default_encoding = FlextLdifConstants.Encoding.DEFAULT_ENCODING

        # 2. .env file (lower priority)
        env_file = tmp_path / ".env"
        env_file.write_text("FLEXT_LDIF_ENCODING=utf-16\n")
        monkeypatch.chdir(tmp_path)

        # 3. Environment variable (higher priority)
        monkeypatch.setenv("FLEXT_LDIF_ENCODING", "latin-1")

        # Test precedence levels

        # Level 1: Only defaults (no .env, no env var, no direct param)
        monkeypatch.delenv("FLEXT_LDIF_ENCODING", raising=False)
        Path(env_file).unlink()
        config1 = FlextLdifConfig()
        assert config1.ldif_encoding == default_encoding

        # Level 2: .env file overrides defaults
        env_file.write_text("FLEXT_LDIF_ENCODING=utf-16\n")
        config2 = FlextLdifConfig()
        assert config2.ldif_encoding == "utf-16"

        # Level 3: Environment variable overrides .env file
        monkeypatch.setenv("FLEXT_LDIF_ENCODING", "latin-1")
        config3 = FlextLdifConfig()
        assert config3.ldif_encoding == "latin-1"

        # Level 4: Direct parameter overrides everything (highest priority)
        config4 = FlextLdifConfig(ldif_encoding="iso-8859-1")
        assert config4.ldif_encoding == "iso-8859-1"


__all__ = [
    "TestConfigInheritance",
    "TestDotEnvFileLoading",
    "TestEnvVariableLoading",
    "TestOrderOfPrecedence",
]
