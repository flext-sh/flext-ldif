"""Real service factory for testing.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextTypes
from flext_ldif import FlextLdifAPI, FlextLdifConfig


class RealServiceFactory:
    """Factory for creating real service instances for testing."""

    @staticmethod
    def create_api(config: FlextTypes.Core.Dict | None = None) -> FlextLdifAPI:
        """Create a real LDIF API instance."""
        if config is None:
            config = {}

        # Create proper config object with type casts
        max_entries = config.get("max_entries")
        max_line_length = config.get("max_line_length")

        ldif_config = FlextLdifConfig(
            ldif_encoding=str(config.get("encoding", "utf-8")),
            ldif_strict_validation=bool(config.get("strict_parsing", True)),
            ldif_validate_dn_format=bool(config.get("validate_dn", True)),
            ldif_max_entries=max_entries if isinstance(max_entries, int) else 10000,
            ldif_max_line_length=max_line_length
            if isinstance(max_line_length, int)
            else 76,
        )

        return FlextLdifAPI(config=ldif_config)

    @staticmethod
    def create_parser(
        config: FlextTypes.Core.Dict | None = None,
    ) -> FlextLdifAPI:
        """Create a real parser service - returns unified API."""
        return RealServiceFactory.create_api(config)

    @staticmethod
    def create_validator(
        config: FlextTypes.Core.Dict | None = None,
    ) -> FlextLdifAPI:
        """Create a real validator service - returns unified API."""
        return RealServiceFactory.create_api(config)

    @staticmethod
    def create_writer(
        config: FlextTypes.Core.Dict | None = None,
    ) -> FlextLdifAPI:
        """Create a real writer service - returns unified API."""
        return RealServiceFactory.create_api(config)

    @classmethod
    def create_configured_api(
        cls,
        *,
        strict_parsing: bool = True,
        validate_dn: bool = True,
        max_entries: int = 10000,
        encoding: str = "utf-8",
        max_line_length: int = 76,
    ) -> FlextLdifAPI:
        """Create API with specific configuration."""
        config: FlextTypes.Core.Dict = {
            "strict_parsing": strict_parsing,
            "validate_dn": validate_dn,
            "max_entries": max_entries,
            "encoding": encoding,
            "max_line_length": max_line_length,
        }
        return cls.create_api(config)

    @classmethod
    def create_lenient_api(cls) -> FlextLdifAPI:
        """Create API with lenient parsing for error testing."""
        return cls.create_configured_api(
            strict_parsing=False,
            validate_dn=False,
        )

    @classmethod
    def create_strict_api(cls) -> FlextLdifAPI:
        """Create API with strict parsing and validation."""
        return cls.create_configured_api(
            strict_parsing=True,
            validate_dn=True,
        )

    @classmethod
    def create_performance_api(cls, max_entries: int = 100000) -> FlextLdifAPI:
        """Create API optimized for performance testing."""
        return cls.create_configured_api(
            max_entries=max_entries,
            strict_parsing=False,  # Faster parsing
        )

    @staticmethod
    def create_test_config(
        *,
        encoding: str = "utf-8",
        strict_parsing: bool = True,
        validate_dn: bool = True,
        max_entries: int = 10000,
        max_line_length: int = 76,
    ) -> FlextLdifConfig:
        """Create a test configuration object."""
        # Map old parameter names to new FlextLdifConfig parameter names
        return FlextLdifConfig(
            ldif_encoding=encoding,
            ldif_strict_validation=strict_parsing,
            ldif_validate_dn_format=validate_dn,
            ldif_max_entries=max_entries,
            ldif_max_line_length=max_line_length,
        )

    @classmethod
    def services_for_integration_test(cls) -> FlextTypes.Core.Dict:
        """Create all services configured for integration testing."""
        config = cls.create_test_config()

        api = FlextLdifAPI(config=config)
        return {
            "api": api,
            "parser": api,
            "validator": api,
            "writer": api,
            "config": config,
        }

    @classmethod
    def minimal_services(cls) -> FlextTypes.Core.Dict:
        """Create minimal service set for basic testing."""
        return {
            "api": cls.create_api(),
            "parser": cls.create_parser(),
        }
