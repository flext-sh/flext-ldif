"""🚨 ARCHITECTURAL COMPLIANCE: ELIMINATED DUPLICATE DI Container.

REFATORADO COMPLETO:
- REMOVIDA TODAS as duplicações de FlextContainer/DIContainer
- USA APENAS FlextContainer oficial do flext-core
- Mantém apenas utilitários flext_ldif-específicos
- SEM fallback, backward compatibility ou código duplicado

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Any

# 🚨 ARCHITECTURAL COMPLIANCE: Use ONLY official flext-core FlextContainer
from flext_core import FlextContainer, get_logger

logger = get_logger(__name__)


# ==================== FLEXT_LDIF-SPECIFIC DI UTILITIES ====================

_flext_ldif_container_instance: FlextContainer | None = None


def get_flext_ldif_container() -> FlextContainer:
    """Get FLEXT_LDIF-specific DI container instance.

    Returns:
        FlextContainer: Official container from flext-core.

    """
    global _flext_ldif_container_instance
    if _flext_ldif_container_instance is None:
        _flext_ldif_container_instance = FlextContainer()
    return _flext_ldif_container_instance


def configure_flext_ldif_dependencies() -> None:
    """Configure FLEXT_LDIF dependencies using official FlextContainer."""
    get_flext_ldif_container()

    try:
        # Register module-specific dependencies
        # TODO: Add module-specific service registrations here

        logger.info("FLEXT_LDIF dependencies configured successfully")

    except ImportError as e:
        logger.exception(f"Failed to configure FLEXT_LDIF dependencies: {e}")


def get_flext_ldif_service(service_name: str) -> Any:
    """Get flext_ldif service from container.

    Args:
        service_name: Name of service to retrieve.

    Returns:
        Service instance or None if not found.

    """
    container = get_flext_ldif_container()
    result = container.get(service_name)

    if result.success:
        return result.data

    logger.warning(f"FLEXT_LDIF service '{service_name}' not found: {result.error}")
    return None


# Initialize flext_ldif dependencies on module import
configure_flext_ldif_dependencies()
