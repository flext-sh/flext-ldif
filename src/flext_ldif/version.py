"""Version and package metadata for flext-ldif using importlib.metadata."""

from __future__ import annotations

from flext_core import FlextCore

from flext_ldif.constants import FlextLdifConstants

# Use constants for FLEXT compliance - ZERO module-level constants
__version__ = FlextLdifConstants.LDIF_VERSION
__version_info__ = FlextLdifConstants.LDIF_VERSION_INFO


class FlextLdifVersion(FlextCore.Models.Value):
    """Simple version class for flext-ldif.

    This is a Pydantic Value Object (frozen/immutable) following flext-core patterns.
    """

    version: str
    version_info: tuple[int | str, ...]

    @classmethod
    def current(cls) -> FlextLdifVersion:
        """Return current version."""
        return cls(version=__version__, version_info=__version_info__)


VERSION = FlextLdifVersion.current()

__all__ = ["VERSION", "FlextLdifVersion", "__version__", "__version_info__"]
