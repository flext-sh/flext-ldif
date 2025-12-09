"""Shared service base that provides typed LDIF configuration access.

This module provides the base class for all LDIF services, extending s
with LDIF-specific configuration access. All services inherit from this base to
ensure consistent configuration handling across the codebase.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import s, t
from flext_core.service import FlextService

from flext_ldif.config import FlextLdifConfig


class FlextLdifServiceBase[TDomainResult](FlextService[TDomainResult]):
    """Base class for LDIF services with typed config helper.

    Business Rule: All LDIF services inherit from this base class to ensure
    consistent configuration access via the `ldif_config` property. Configuration
    is accessed through FlextConfig's namespace system, providing type-safe
    access to LDIF-specific settings.

    Implication: Services can access LDIF configuration without direct dependency
    on FlextConfig internals. The `ldif_config` property returns a properly typed
    FlextLdifConfig instance, enabling IDE autocomplete and type checking. This
    follows the Dependency Injection pattern from flext-core.

    Usage:
        class MyService(FlextLdifServiceBase[MyResponse]):
            def some_method(self) -> None:
                # Access LDIF config with proper typing
                server_type = self.ldif_config.ldif_default_server_type
                quirks_mode = self.ldif_config.quirks_detection_mode
    """

    @classmethod
    def _runtime_bootstrap_options(cls) -> t.Types.RuntimeBootstrapOptions:
        """Return runtime bootstrap options for LDIF services.

        Business Rule: This method provides runtime bootstrap configuration for
        all LDIF services, ensuring they use FlextLdifConfig as the configuration
        type. This enables proper DI integration and namespace access.

        Implication: All services extending FlextLdifServiceBase automatically
        use FlextLdifConfig for their runtime configuration, ensuring consistent
        configuration handling across all LDIF services.

        Returns:
            Runtime bootstrap options with config_type set to FlextLdifConfig

        """
        return {"config_type": FlextLdifConfig}

    @property
    def ldif_config(self) -> FlextLdifConfig:
        """Return the LDIF configuration namespace with proper typing.

        Business Rule: Configuration access uses FlextConfig's namespace system
        to retrieve LDIF-specific settings. The namespace "ldif" is registered
        during FlextLdif initialization, ensuring all services have access to
        consistent configuration.

        Implication: This property provides type-safe access to LDIF configuration
        without requiring services to know about FlextConfig internals. The returned
        FlextLdifConfig instance contains all LDIF-specific settings (server types,
        quirks detection mode, parsing options, etc.).

        Returns:
            FlextLdifConfig instance with LDIF-specific configuration settings

        """
        return self.config.get_namespace("ldif", FlextLdifConfig)


# Short alias for service base (s is FlextService from flext-core)
# Export s for consistency with other modules (u, m, c, t, p)
# s is already imported from flext_core, so we just need to export it
__all__ = ["FlextLdifServiceBase", "s"]
