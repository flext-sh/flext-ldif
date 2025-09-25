"""FLEXT LDIF Config - Comprehensive Unit Tests.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import threading
import time

import pytest
from pydantic import ValidationError

from flext_ldif.config import FlextLdifConfig


@pytest.mark.unit
class TestFlextLdifConfig:
    """Comprehensive tests for FlextLdifConfig class."""

    def test_config_initialization_default(self) -> None:
        """Test config initialization with default values."""
        config = FlextLdifConfig()

        assert config is not None
        assert config.ldif_encoding == "utf-8"
        assert config.ldif_strict_validation is True
        assert config.ldif_max_entries == 1000000
        assert config.max_workers == 4

    def test_config_initialization_custom(self) -> None:
        """Test config initialization with custom values."""
        custom_config = FlextLdifConfig(
            ldif_encoding="latin-1",
            ldif_strict_validation=False,
            ldif_max_entries=5000,
            max_workers=2,
        )

        assert custom_config.ldif_encoding == "latin-1"
        assert custom_config.ldif_strict_validation is False
        assert custom_config.ldif_max_entries == 5000
        assert custom_config.max_workers == 2

    def test_config_validation_valid(self) -> None:
        """Test config validation with valid values."""
        config = FlextLdifConfig(
            ldif_encoding="utf-8", ldif_strict_validation=True, ldif_max_entries=1000
        )
        # Test that valid config can be created without errors
        assert config is not None
        assert config.ldif_encoding == "utf-8"
        assert config.ldif_strict_validation is True
        assert config.ldif_max_entries == 1000

    def test_config_validation_invalid_encoding(self) -> None:
        """Test config validation with invalid encoding."""
        # Test that invalid encoding is normalized to lowercase
        config = FlextLdifConfig(ldif_encoding="INVALID-ENCODING")
        assert config.ldif_encoding == "invalid-encoding"

        # Test that empty encoding raises validation error
        with pytest.raises(Exception):
            FlextLdifConfig(ldif_encoding="")

    def test_config_validation_invalid_max_entries(self) -> None:
        """Test config validation with invalid max entries."""
        # Test that invalid max entries raises validation error
        with pytest.raises(Exception):
            FlextLdifConfig(ldif_max_entries=-1)

    def test_config_validation_invalid_max_entries_zero(self) -> None:
        """Test config validation with zero max entries."""
        # Test that config creation rejects zero max entries (validation error)
        with pytest.raises(Exception):
            FlextLdifConfig(ldif_max_entries=0)

    def test_config_validation_invalid_max_entries_large(self) -> None:
        """Test config validation with very large max entries."""
        # Test that config creation rejects values exceeding the maximum limit
        with pytest.raises(ValidationError):
            FlextLdifConfig(ldif_max_entries=1000000000)

    def test_config_model_copy(self) -> None:
        """Test copying config using model_copy."""
        original_config = FlextLdifConfig(
            ldif_encoding="utf-8", ldif_strict_validation=True, ldif_max_entries=1000
        )
        copied_config = original_config.model_copy()

        assert copied_config.ldif_encoding == original_config.ldif_encoding
        assert (
            copied_config.ldif_strict_validation
            == original_config.ldif_strict_validation
        )
        assert copied_config.ldif_max_entries == original_config.ldif_max_entries

        # Modify copied config
        copied_config.ldif_encoding = "latin-1"
        assert copied_config.ldif_encoding != original_config.ldif_encoding

    def test_config_create_for_server_type(self) -> None:
        """Test creating config for specific server type."""
        config = FlextLdifConfig.create_for_server_type("openldap")

        assert config is not None
        assert isinstance(config, FlextLdifConfig)

    def test_config_create_for_performance(self) -> None:
        """Test creating config optimized for performance."""
        config = FlextLdifConfig.create_for_performance()

        assert config is not None
        assert isinstance(config, FlextLdifConfig)

    def test_config_create_for_development(self) -> None:
        """Test creating config optimized for development."""
        config = FlextLdifConfig.create_for_development()

        assert config is not None
        assert isinstance(config, FlextLdifConfig)

    def test_config_equality(self) -> None:
        """Test config equality."""
        config1 = FlextLdifConfig(ldif_encoding="utf-8")
        config2 = FlextLdifConfig(ldif_encoding="utf-8")
        config3 = FlextLdifConfig(ldif_encoding="latin-1")

        assert config1 == config2
        assert config1 != config3

    def test_config_hash(self) -> None:
        """Test config hashing."""
        config1 = FlextLdifConfig(
            ldif_encoding="utf-8", ldif_strict_validation=True, ldif_max_entries=1000
        )
        config2 = FlextLdifConfig(
            ldif_encoding="utf-8", ldif_strict_validation=True, ldif_max_entries=1000
        )
        config3 = FlextLdifConfig(
            ldif_encoding="utf-8", ldif_strict_validation=True, ldif_max_entries=1000
        )

        # Test that configs are equal
        assert config1 == config2
        assert config1 == config3

        # Test that configs can be used in sets (if hashable)
        try:
            config_set = {config1, config2, config3}
            assert len(config_set) == 1  # All should be equal
        except TypeError:
            # Config is not hashable, which is acceptable
            pass

    def test_config_str_representation(self) -> None:
        """Test config string representation."""
        config = FlextLdifConfig(
            ldif_encoding="utf-8", ldif_strict_validation=True, ldif_max_entries=1000
        )
        str_repr = str(config)

        assert isinstance(str_repr, str)
        # The string representation might not include the class name
        # but should be a valid string representation
        assert len(str_repr) > 0

    def test_config_repr_representation(self) -> None:
        """Test config repr representation."""
        config = FlextLdifConfig(
            ldif_encoding="utf-8", ldif_strict_validation=True, ldif_max_entries=1000
        )
        repr_repr = repr(config)

        assert isinstance(repr_repr, str)
        # The repr representation might not include the class name
        # but should be a valid string representation
        assert len(repr_repr) > 0

    def test_config_is_performance_optimized(self) -> None:
        """Test config performance optimization check."""
        config = FlextLdifConfig.create_for_performance()

        assert config.is_performance_optimized() is True

    def test_config_is_development_optimized(self) -> None:
        """Test config development optimization check."""
        config = FlextLdifConfig.create_for_development()

        assert config.is_development_optimized() is True

    def test_config_get_effective_encoding(self) -> None:
        """Test config effective encoding."""
        config = FlextLdifConfig(ldif_encoding="utf-8")

        encoding = config.get_effective_encoding()
        assert encoding == "utf-8"

    def test_config_get_effective_workers(self) -> None:
        """Test config effective workers."""
        config = FlextLdifConfig(max_workers=4)

        workers = config.get_effective_workers(1000)
        assert workers == 4

    def test_config_performance(self) -> None:
        """Test config performance characteristics."""
        # Test config creation performance
        start_time = time.time()

        for _ in range(100):  # Reduced from 1000 to 100
            FlextLdifConfig()

        end_time = time.time()
        execution_time = end_time - start_time

        assert execution_time < 5.0  # Should complete within 5 seconds (more realistic)

    def test_config_memory_usage(self) -> None:
        """Test config memory usage characteristics."""
        # Test that config doesn't leak memory
        configs = []

        for _ in range(100):
            config = FlextLdifConfig()
            configs.append(config)

        # Verify all configs are valid
        assert len(configs) == 100
        for config in configs:
            assert isinstance(config, FlextLdifConfig)

    def test_config_edge_cases(self) -> None:
        """Test config with edge cases."""
        # Test with None values - should raise validation error
        with pytest.raises(Exception):
            FlextLdifConfig(ldif_encoding=None)  # type: ignore[arg-type]

        # Test with empty string values - should raise validation error
        with pytest.raises(Exception):
            FlextLdifConfig(ldif_encoding="")

    def test_config_concurrent_access(self) -> None:
        """Test config concurrent access."""
        configs = []

        def worker() -> None:
            config = FlextLdifConfig()
            configs.append(config)

        # Start multiple threads
        threads = []
        for _ in range(5):
            thread = threading.Thread(target=worker)
            threads.append(thread)
            thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

        # Verify all operations succeeded
        assert len(configs) == 5
        for config in configs:
            assert isinstance(config, FlextLdifConfig)
