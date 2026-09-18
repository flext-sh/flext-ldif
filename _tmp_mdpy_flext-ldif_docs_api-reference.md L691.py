# from flext-ldif/docs/api-reference.md:691
from flext_ldif import (
    FlextLdifParseError,  # LDIF parsing errors
    FlextLdifValidationError,  # Validation errors
)

# Exception builder pattern
try:
    # Operations that might raise exceptions
    pass
except FlextLdifParseError as e:
    u.Cli.print(f"Parse error: {e}")
except FlextLdifValidationError as e:
    u.Cli.print(f"Validation error: {e}")```
## ⚠️ Library-Only Usage

**IMPORTANT**: FLEXT-LDIF is a **library-only** package with NO CLI. All functionality must be accessed programmatically through the API.

**Migration from CLI to API**:

