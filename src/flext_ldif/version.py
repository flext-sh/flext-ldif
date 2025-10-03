"""Version and package metadata for flext-ldif using importlib.metadata."""

from __future__ import annotations

from importlib.metadata import metadata

_metadata = metadata("flext-ldif")

__version__ = _metadata["Version"]
__version_info__ = tuple(
    int(part) if part.isdigit() else part for part in __version__.split(".")
)


class FlextLdifVersion:
    """Simple version class for flext-ldif."""

    def __init__(self, version: str, version_info: tuple[int | str, ...]) -> None:
        self.version = version
        self.version_info = version_info

    @classmethod
    def current(cls) -> FlextLdifVersion:
        """Return current version."""
        return cls(__version__, __version_info__)


VERSION = FlextLdifVersion.current()

__all__ = ["VERSION", "FlextLdifVersion", "__version__", "__version_info__"]
