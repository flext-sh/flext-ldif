"""Tests for version.py module.

Tests version information access and FlextLdifVersion class functionality.
"""

from __future__ import annotations


def test_version_import() -> None:
    """Test that version module can be imported."""
    from flext_ldif import version

    assert hasattr(version, "__version__")
    assert hasattr(version, "__version_info__")
    assert hasattr(version, "FlextLdifVersion")
    assert hasattr(version, "VERSION")


def test_version_constants() -> None:
    """Test version constants are defined."""
    from flext_ldif.version import __version__, __version_info__

    assert isinstance(__version__, str)
    assert isinstance(__version_info__, tuple)
    assert len(__version__) > 0
    assert len(__version_info__) > 0


def test_flext_ldif_version_class() -> None:
    """Test FlextLdifVersion class instantiation."""
    from flext_ldif.version import FlextLdifVersion

    version = FlextLdifVersion(version="1.0.0", version_info=(1, 0, 0))
    assert version.version == "1.0.0"
    assert version.version_info == (1, 0, 0)


def test_flext_ldif_version_current() -> None:
    """Test FlextLdifVersion.current() class method."""
    from flext_ldif.version import FlextLdifVersion, __version__, __version_info__

    current = FlextLdifVersion.current()
    assert isinstance(current, FlextLdifVersion)
    assert current.version == __version__
    assert current.version_info == __version_info__


def test_version_module_variable() -> None:
    """Test VERSION module-level variable."""
    from flext_ldif.version import (
        VERSION,
        FlextLdifVersion,
        __version__,
        __version_info__,
    )

    assert isinstance(VERSION, FlextLdifVersion)
    assert VERSION.version == __version__
    assert VERSION.version_info == __version_info__


def test_version_all_exports() -> None:
    """Test __all__ contains expected exports."""
    from flext_ldif import version

    assert hasattr(version, "__all__")
    expected_exports = [
        "VERSION",
        "FlextLdifVersion",
        "__version__",
        "__version_info__",
    ]
    assert set(version.__all__) == set(expected_exports)


def test_version_types() -> None:
    """Test version types are correct."""
    from flext_ldif.version import VERSION

    assert hasattr(VERSION, "version")
    assert hasattr(VERSION, "version_info")
    assert isinstance(VERSION.version, str)
    assert isinstance(VERSION.version_info, tuple)
