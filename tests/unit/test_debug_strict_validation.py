"""DEBUG TEST: Verificar por que strict_validation não está funcionando."""

from __future__ import annotations

from unittest.mock import Mock, patch
from flext_ldif.models import FlextLDIFModels
from flext_ldif.services import FlextLDIFServices
from flext_core import FlextUtilities


def test_debug_strict_validation_flow():
    """Debug: Rastrear exatamente o que acontece com strict_validation."""
    
    # Configuração REAL
    config = FlextLDIFModels.Config(strict_validation=True)
    print(f"Config created: {config}")
    print(f"Has strict_validation: {hasattr(config, 'strict_validation')}")
    print(f"strict_validation value: {getattr(config, 'strict_validation', 'NOT_FOUND')}")
    
    validator = FlextLDIFServices.ValidatorService(config=config)
    print(f"Validator config: {validator.config}")
    print(f"Validator config strict_validation: {getattr(validator.config, 'strict_validation', 'NOT_FOUND')}")
    
    # Entry simples
    entry = Mock()
    entry.dn = Mock(value="cn=debug,dc=example,dc=com")
    entry.validate_business_rules = Mock(return_value=None)
    
    # Attributes mock corretamente - deve ser dict-like
    mock_attributes = {"cn": ["debug"]}  # Use dict real em vez de Mock  
    entry.attributes = mock_attributes
    
    # DEBUG: Patch has_attribute com logging
    original_has_attribute = FlextUtilities.TypeGuards.has_attribute
    
    def debug_has_attribute(obj, attr):
        result = original_has_attribute(obj, attr)
        print(f"has_attribute({type(obj).__name__}, '{attr}') = {result}")
        if obj is config:
            print(f"  -> Config check: {attr} = {result}")
        elif obj is mock_attributes:
            print(f"  -> Attributes check: {attr} = {result}")
        return result
    
    with patch.object(FlextUtilities.TypeGuards, 'has_attribute', side_effect=debug_has_attribute):
        print("\nExecuting validation...")
        result = validator.validate_entries([entry])
        print(f"Result: {result}")
    
    assert True  # Só queremos ver o debug


def test_debug_manual_validation_call():
    """Debug: Chamar _validate_configuration_rules diretamente."""
    
    config = FlextLDIFModels.Config(strict_validation=True)
    validator = FlextLDIFServices.ValidatorService(config=config)
    
    entry = Mock()
    entry.dn = Mock(value="cn=manual,dc=example,dc=com")
    entry.validate_business_rules = Mock(return_value=None)
    
    # Mock attributes corretamente - deve ser dict-like
    mock_attributes = {"cn": ["manual"]}  # Use dict real em vez de Mock
    entry.attributes = mock_attributes
    
    print(f"\nDirect call to _validate_configuration_rules")
    print(f"Config: {validator.config}")
    print(f"Config strict_validation: {getattr(validator.config, 'strict_validation', 'NOT_FOUND')}")
    
    # Chamar método diretamente
    with patch.object(FlextUtilities.TypeGuards, 'has_attribute') as mock_has_attr, \
         patch.object(FlextUtilities.TypeGuards, 'is_list_non_empty', return_value=True):
        
        def debug_has_attribute(obj, attr):
            print(f"has_attribute called: {type(obj).__name__}.{attr}")
            if obj is config and attr == "strict_validation":
                return True
            elif obj is mock_attributes and attr == "data":
                return False
            elif obj is mock_attributes and attr == "items":
                return True
            # Use default behavior for dict
            elif isinstance(obj, dict):
                return hasattr(obj, attr)
            return False
        
        mock_has_attr.side_effect = debug_has_attribute
        
        result = validator._validate_configuration_rules(entry)
        print(f"Direct result: {result}")
        
        print(f"has_attribute calls: {mock_has_attr.call_args_list}")
    
    assert True