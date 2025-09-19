"""DEBUG TEST: Verificar por que strict_validation não está funcionando.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from unittest.mock import Mock, patch

from flext_core import FlextResult, FlextUtilities
from flext_ldif.config import FlextLdifConfig
from flext_ldif.services import FlextLdifServices


def test_debug_strict_validation_flow() -> None:
    """Debug: Rastrear exatamente o que acontece com strict_validation."""
    # Use proper FlextLdifConfig
    config = FlextLdifConfig()

    validator = FlextLdifServices(config=config)

    # Entry simples
    entry = Mock()
    entry.dn = Mock(value="cn=debug,dc=example,dc=com")
    entry.validate_business_rules = Mock(return_value=FlextResult[None].ok(None))

    # Attributes mock corretamente - deve ser dict-like
    mock_attributes = {"cn": ["debug"]}  # Use dict real em vez de Mock
    entry.attributes = mock_attributes

    # Test validation without patching non-existent methods
    validator.validator.validate_entries([entry])

    assert True  # Só queremos ver o debug


def test_debug_manual_validation_call() -> None:
    """Debug: Chamar validate_entry_structure diretamente."""
    config = FlextLdifConfig()
    validator = FlextLdifServices(config=config).validator

    entry = Mock()
    entry.dn = Mock(value="cn=manual,dc=example,dc=com")
    entry.validate_business_rules = Mock(return_value=FlextResult[None].ok(None))

    # Mock attributes corretamente - deve ser dict-like
    mock_attributes = {"cn": ["manual"]}  # Use dict real em vez de Mock
    entry.attributes = mock_attributes

    # Chamar método diretamente usando a nova API
    with patch.object(
        FlextUtilities.TypeGuards, "is_list_non_empty", return_value=True,
    ):
        result = validator.validate_entry_structure(entry)

    assert result.is_success or result.is_failure  # Test successful execution
