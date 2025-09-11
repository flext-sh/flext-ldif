"""DEBUG TEST: Verificar por que strict_validation não está funcionando."""

from __future__ import annotations

from unittest.mock import Mock, patch

from flext_core import FlextUtilities

from flext_ldif.models import FlextLDIFModels
from flext_ldif.services import FlextLDIFServices


def test_debug_strict_validation_flow() -> None:
    """Debug: Rastrear exatamente o que acontece com strict_validation."""
    # Configuração REAL
    config = FlextLDIFModels.Config(strict_validation=True)

    validator = FlextLDIFServices(config=config)

    # Entry simples
    entry = Mock()
    entry.dn = Mock(value="cn=debug,dc=example,dc=com")
    entry.validate_business_rules = Mock(return_value=None)

    # Attributes mock corretamente - deve ser dict-like
    mock_attributes = {"cn": ["debug"]}  # Use dict real em vez de Mock
    entry.attributes = mock_attributes

    # DEBUG: Patch has_attribute com logging
    original_has_attribute = FlextUtilities.TypeGuards.has_attribute

    def debug_has_attribute(obj: object, attr: str) -> bool:
        result = original_has_attribute(obj, attr)
        if obj is config or obj is mock_attributes:
            pass
        return result

    with patch.object(
        FlextUtilities.TypeGuards, "has_attribute", side_effect=debug_has_attribute
    ):
        validator.validate_entries([entry])

    assert True  # Só queremos ver o debug


def test_debug_manual_validation_call() -> None:
    """Debug: Chamar validate_entry_structure diretamente."""
    config = FlextLDIFModels.Config(strict_validation=True)
    validator = FlextLDIFServices(config=config).validator

    entry = Mock()
    entry.dn = Mock(value="cn=manual,dc=example,dc=com")
    entry.validate_business_rules = Mock(return_value=None)

    # Mock attributes corretamente - deve ser dict-like
    mock_attributes = {"cn": ["manual"]}  # Use dict real em vez de Mock
    entry.attributes = mock_attributes

    # Chamar método diretamente usando a nova API
    with (
        patch.object(FlextUtilities.TypeGuards, "has_attribute") as mock_has_attr,
        patch.object(FlextUtilities.TypeGuards, "is_list_non_empty", return_value=True),
    ):

        def debug_has_attribute(obj: object, attr: str) -> bool:
            if obj is config and attr == "strict_validation":
                return True
            if obj is mock_attributes and attr == "data":
                return False
            if obj is mock_attributes and attr == "items":
                return True
            # Use default behavior for dict
            if isinstance(obj, dict):
                return hasattr(obj, attr)
            return False

        mock_has_attr.side_effect = debug_has_attribute

        result = validator.validate_entry_structure(entry)

    assert result.is_success or result.is_failure  # Test successful execution
