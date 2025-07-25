"""Deprecation management for FLEXT LDIF.

Handles backward compatibility and migration warnings pointing users
to the new simplified import patterns.

Old complex paths still work but show clear guidance to simple alternatives.
"""

from __future__ import annotations


class LDIFDeprecationWarning(DeprecationWarning):
    """Custom deprecation warning for LDIF-specific deprecations.

    Provides clear guidance to users on how to migrate from complex
    import paths to simple root-level imports for better developer experience.
    """


def warn_deprecated(
    old_path: str,
    new_path: str,
    version: str = "1.0.0",
) -> None:
    """Issue deprecation warning with migration guidance.

    Args:
        old_path: The deprecated import/usage path
        new_path: The new recommended path
        version: Version when the deprecated feature will be removed

    """
    import warnings

    warnings.warn(
        f"\n\n🚨 DEPRECATED COMPLEX PATH:\n"
        f"Using '{old_path}' is deprecated.\n\n"
        f"🎯 SIMPLE IMPORT SOLUTION:\n"
        f"Use: {new_path}\n\n"
        f"💡 PRODUCTIVITY TIP:\n"
        f"All FLEXT LDIF imports are now available at root level!\n"
        f"No more complex nested paths - just import what you need directly.\n\n"
        f"🔄 MIGRATION:\n"
        f"Support for complex paths will be removed in version {version}.\n"
        f"Use simple root-level imports for better developer experience.\n\n"
        f"Examples:\n"
        f"✅ from flext_ldif import LDIFParser, LDIFWriter, LDIFEntry\n"
        f"✅ from flext_ldif import FlextLDIFProcessor, LDIFValidator\n"
        f"✅ from flext_ldif import DistinguishedName, LDIFAttributes\n",
        LDIFDeprecationWarning,
        stacklevel=3,
    )


def warn_deprecated_path(
    old_path: str,
    recommendation: str,
    version: str = "1.0.0",
) -> None:
    """Issue deprecation warning for complex import paths.

    Args:
        old_path: The deprecated complex import path or pattern
        recommendation: Simple recommendation for replacement
        version: Version when support will be removed

    """
    import warnings

    warnings.warn(
        f"\n\n🚨 DEPRECATED COMPLEX PATH:\n"
        f"Using '{old_path}' is deprecated.\n\n"
        f"🎯 SIMPLE IMPORT SOLUTION:\n"
        f"{recommendation}\n\n"
        f"💡 PRODUCTIVITY TIP:\n"
        f"All FLEXT LDIF imports are now available at root level!\n"
        f"No more complex nested paths - just import what you need directly.\n\n"
        f"🔄 MIGRATION:\n"
        f"Support for complex paths will be removed in version {version}.\n"
        f"Use simple root-level imports for better developer experience.\n\n"
        f"Examples:\n"
        f"✅ from flext_ldif import LDIFParser\n"
        f"✅ from flext_ldif import LDIFEntry, FlextLDIFProcessor\n"
        f"✅ from flext_ldif import DistinguishedName\n",
        LDIFDeprecationWarning,
        stacklevel=3,
    )
