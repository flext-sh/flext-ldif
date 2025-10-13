"""DEPRECATED: This file has been removed.

This utilities container class was an anti-pattern and has been replaced with
proper domain services following FLEXT architectural standards.

Replacements:
- DnUtilities → services.DnService
- ValidationUtilities → services.ValidationService
- TimeUtilities → Python datetime module
- TextUtilities → Client methods
- LdifUtilities → Client methods
- EncodingUtilities → Client methods
- FileUtilities → Client methods

This file can be safely deleted. It is kept temporarily with this deprecation
notice to prevent import errors during the transition period.

For migration guidance, see:
- services/dn.py (DN operations)
- services/validation.py (validation operations)
- client.py (LDIF/encoding/file operations)
"""

# Deprecated - Do not use
__all__ = []
