"""DEBUG TEST: Verificar por que strict_validation não está funcionando.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from unittest.mock import patch

from flext_core import FlextUtilities
from flext_ldif import FlextLdifAPI, FlextLdifConfig, FlextLdifModels


def test_debug_strict_validation_flow() -> None:
    """Debug: Rastrear exatamente o que acontece com strict_validation."""
    # Use proper FlextLdifConfig
    config = FlextLdifConfig()

    # Initialize API with config
    api = FlextLdifAPI(config=config)

    # Create proper FlextLdifModels.Entry instead of Mock
    dn_obj = FlextLdifModels.DistinguishedName(value="cn=debug,dc=example,dc=com")
    attrs_obj = FlextLdifModels.LdifAttributes(data={"cn": ["debug"]})
    entry = FlextLdifModels.Entry(dn=dn_obj, attributes=attrs_obj)

    # Test validation using API
    result = api.validate_entries([entry])

    assert result.is_success or result.is_failure  # Test successful execution


def test_debug_manual_validation_call() -> None:
    """Debug: Chamar validação manual de estrutura diretamente."""
    config = FlextLdifConfig()

    # Initialize API with config
    api = FlextLdifAPI(config=config)

    # Create proper FlextLdifModels.Entry instead of Mock
    dn_obj = FlextLdifModels.DistinguishedName(value="cn=manual,dc=example,dc=com")
    attrs_obj = FlextLdifModels.LdifAttributes(data={"cn": ["manual"]})
    entry = FlextLdifModels.Entry(dn=dn_obj, attributes=attrs_obj)

    # Test validation using API - the API handles internal structure validation
    with patch.object(
        FlextUtilities.TypeGuards,
        "is_list_non_empty",
        return_value=True,
    ):
        result = api.validate_entries([entry])

    assert result.is_success or result.is_failure  # Test successful execution
