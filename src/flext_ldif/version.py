"""Version and package metadata for flext-ldif using importlib.metadata."""

from __future__ import annotations

from flext_ldif.constants import FlextLdifConstants

# Use constants for FLEXT compliance - ZERO module-level constants
__version__ = FlextLdifConstants.LDIF_VERSION
__version_info__ = FlextLdifConstants.LDIF_VERSION_INFO


class FlextLdifVersion:
    """Simple version class for flext-ldif."""

    def __init__(self, version: str, version_info: tuple[int | str, ...]) -> None:
        """Initialize version object.

        Args:
            version: Version string (e.g., "1.0.0")
            version_info: Tuple of version components

        """
        self.version = version
        self.version_info = version_info

    @classmethod
    def current(cls) -> FlextLdifVersion:
        """Return current version."""
        return cls(__version__, __version_info__)


VERSION = FlextLdifVersion.current()

__all__ = ["VERSION", "FlextLdifVersion", "__version__", "__version_info__"]
