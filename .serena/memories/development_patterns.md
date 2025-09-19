# FLEXT-LDIF Development Patterns

## Unified Class Architecture

### Single Class Per Module

```python
class UnifiedProjectService(FlextDomainService):
    """Single responsibility class with nested helpers."""

    def __init__(self, **data) -> None:
        super().__init__(**data)
        self._container = FlextContainer.get_global()
        self._logger = FlextLogger(__name__)

    class _ValidationHelper:
        """Nested helper class - no loose functions."""
        @staticmethod
        def validate_business_rules(data: dict) -> FlextResult[dict]:
            pass

    def process_data(self, input_data: dict) -> FlextResult[ProcessedData]:
        """Main processing with explicit error handling."""
        if not input_data:
            return FlextResult[ProcessedData].fail("Input cannot be empty")

        validation_result = self._ValidationHelper.validate_business_rules(input_data)
        if validation_result.is_failure:
            return FlextResult[ProcessedData].fail(f"Validation failed: {validation_result.error}")

        return FlextResult[ProcessedData].ok(processed_data)
```

## FlextResult Pattern (MANDATORY)

### Railway-oriented Programming

```python
# ✅ CORRECT - Railway-oriented programming
result = (
    parse_operation(content)
    .bind(lambda entries: validate_entries(entries))
    .bind(lambda valid_entries: transform_entries(valid_entries))
    .map(lambda transformed: format_output(transformed))
)

# Handle results functionally
if result.is_success:
    data = result.value
else:
    error = result.error
```

### Error Handling Patterns

```python
# ✅ CORRECT - Explicit error handling
def process_ldif_file(file_path: Path) -> FlextResult[list]:
    """Process LDIF file with proper error handling."""
    if not file_path.exists():
        return FlextResult[list].fail(f"File not found: {file_path}")

    parse_result = api.parse_file(file_path)
    if parse_result.is_failure:
        return FlextResult[list].fail(f"Parsing failed: {parse_result.error}")

    return FlextResult[list].ok(parse_result.unwrap())

# ❌ FORBIDDEN - try/except fallbacks
# try:
#     result = risky_operation()
#     return result
# except Exception:
#     return default_value  # ZERO TOLERANCE VIOLATION
```

## LDIF-Specific Patterns

### LDIF Processing Pipeline

```python
from flext_ldif import FlextLdifAPI, FlextLdifModels

def enterprise_ldif_processing(ldif_content: str) -> FlextResult[list]:
    """Enterprise LDIF processing with proper error handling."""
    # Input validation with early return
    if not ldif_content.strip():
        return FlextResult[list].fail("LDIF content cannot be empty")

    # Use flext-ldif API exclusively - NO custom LDIF parsing
    ldif_api = FlextLdifAPI()

    # Parse LDIF through flext-ldif foundation
    parse_result = ldif_api.parse_string(ldif_content)
    if parse_result.is_failure:
        return FlextResult[list].fail(f"LDIF parsing failed: {parse_result.error}")

    # Validate LDIF entries through flext-ldif
    validation_result = ldif_api.validate_entries(parse_result.unwrap())
    if validation_result.is_failure:
        return FlextResult[list].fail(f"LDIF validation failed: {validation_result.error}")

    return FlextResult[list].ok(validation_result.unwrap())
```

### Builder Pattern for Exceptions

```python
from flext_ldif.exceptions import FlextLdifExceptions

def validate_ldif_entry(entry_data: dict) -> FlextResult[None]:
    """Validate LDIF entry using Builder Pattern."""

    # Check required DN field
    if "dn" not in entry_data:
        # Use Builder Pattern for complex LDIF exceptions
        error = (FlextLdifExceptions.builder()
                .message("LDIF entry missing required DN field")
                .code("LDIF_VALIDATION_ERROR")
                .location(line=42, column=10)
                .entry_data(entry_data)
                .validation_rule("required_dn")
                .build())
        return FlextResult[None].fail(error.message)

    return FlextResult[None].ok(None)
```

### Factory Pattern for Object Creation

```python
from flext_ldif.models import FlextLdifModels

def create_ldif_entry(entry_data: dict) -> FlextResult[FlextLdifModels.Entry]:
    """Create LDIF entry using Factory Pattern."""

    # Input validation
    if not entry_data or not isinstance(entry_data, dict):
        return FlextResult[FlextLdifModels.Entry].fail("Invalid entry data provided")

    # Use Factory Pattern for unified object creation
    try:
        entry = FlextLdifModels.Factory.create_entry(entry_data)
        return FlextResult[FlextLdifModels.Entry].ok(entry)
    except Exception as e:
        error = FlextLdifExceptions.validation_error(
            f"Entry creation failed: {e}",
            entry_data=entry_data
        )
        return FlextResult[FlextLdifModels.Entry].fail(error.message)
```

## CLI Implementation Patterns

### flext-cli Integration

```python
from flext_cli import FlextCliApi, FlextCliMain, FlextCliConfigs

class ProjectCliService:
    def __init__(self) -> None:
        self._cli_api = FlextCliApi()

    def create_cli_interface(self) -> FlextResult[FlextCliMain]:
        main_cli = FlextCliMain(name="project-cli")
        # Use flext-cli for ALL output - NO Rich directly
        return FlextResult[FlextCliMain].ok(main_cli)
```

## Import Patterns

### Root-level Imports Only

```python
# ✅ CORRECT
from flext_core import FlextResult, FlextLogger, FlextContainer
from flext_cli import FlextCliApi, FlextCliMain  # CLI projects only

# ❌ FORBIDDEN
from flext_core.result import FlextResult  # Internal imports prohibited
import click  # Direct CLI imports prohibited
```

## Testing Patterns

### Real Functionality Tests

```python
def test_ldif_parsing_real_functionality():
    """Test real LDIF parsing functionality."""
    api = FlextLdifAPI()
    sample_ldif = """dn: cn=test,dc=example,dc=com
cn: test
objectClass: person
"""

    result = api.parse_string(sample_ldif)
    assert result.is_success, f"Parsing failed: {result.error}"

    entries = result.unwrap()
    assert len(entries) == 1
    assert entries[0].dn == "cn=test,dc=example,dc=com"
```

## Prohibited Patterns

### ❌ ABSOLUTELY FORBIDDEN

- Multiple classes per module
- Helper functions outside classes
- try/except fallback mechanisms
- Direct Click/Rich imports
- Custom LDIF parsing implementations
- Internal flext-core imports
- type: ignore without error codes
- object types instead of proper annotations
