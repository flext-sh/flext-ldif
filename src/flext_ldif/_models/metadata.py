"""Metadata models for LDIF processing.

Classes:
    FlextLdifModelsMetadata: Container class with nested metadata models
        - DynamicMetadata: Model with extra="allow" for flexible fields
        - EntryMetadata: Model for entry processing metadata

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Generator, ItemsView, KeysView, ValuesView
from typing import ClassVar, overload

from flext_core._models.base import FlextModelsBase
from pydantic import ConfigDict, Field

from flext_ldif.typings import t


class FlextLdifModelsMetadata:
    """LDIF metadata models container.

    Usage:
        from flext_ldif._models.metadata import FlextLdifModelsMetadata

        metadata = FlextLdifModelsMetadata.DynamicMetadata()
        entry_meta = FlextLdifModelsMetadata.EntryMetadata()

    """

    class DynamicMetadata(FlextModelsBase.ArbitraryTypesModel):
        """Model with extra="allow" for dynamic field storage.

        Replaces ALL dict[str, ...] patterns with proper Pydantic model.
        Extra fields stored in __pydantic_extra__ via Pydantic v2.

        Provides dict-like interface for accessing extra fields.

        Example:
            meta = DynamicMetadata(custom_field="value")
            assert meta.model_extra == {"custom_field": "value"}
            assert meta["custom_field"] == "value"
            assert meta.get("custom_field") == "value"

        """

        model_config = ConfigDict(extra="allow", arbitrary_types_allowed=True)

        transformations: list[object] | None = Field(default=None)

        def __init__(
            self,
            **kwargs: object,
        ) -> None:
            """Initialize DynamicMetadata with arbitrary keyword arguments.

            Args:
                **kwargs: Arbitrary key-value pairs stored as extra fields.
                          Values are validated by Pydantic.

            Example:
                meta = DynamicMetadata(original_format="test", custom_field=123)
                assert meta["original_format"] == "test"
                assert meta["custom_field"] == 123

            """
            super().__init__(**kwargs)

        @overload
        def get(self, key: str) -> t.MetadataAttributeValue: ...

        @overload
        def get(
            self,
            key: str,
            default: t.MetadataAttributeValue,
        ) -> t.MetadataAttributeValue: ...

        def get(
            self,
            key: str,
            default: t.MetadataAttributeValue = None,
        ) -> t.MetadataAttributeValue:
            """Get value by key, returning default if not found."""
            extra = self.__pydantic_extra__
            if extra is not None and key in extra:
                value = extra[key]
                # Type guard: ensure return matches MetadataValue
                if isinstance(value, str | float | bool | list | dict):
                    return value
                return str(value) if value is not None else None
            return default

        def __getitem__(self, key: str) -> t.MetadataAttributeValue:
            """Get value by key, raising KeyError if not found."""
            extra = self.__pydantic_extra__
            if extra is not None and key in extra:
                value = extra[key]
                if isinstance(value, str | float | bool | list | dict):
                    return value
                return str(value) if value is not None else None
            raise KeyError(key)

        def __setitem__(self, key: str, value: t.MetadataAttributeValue) -> None:
            """Set value by key using Pydantic's extra field handling."""
            setattr(self, key, value)

        def __contains__(self, key: str) -> bool:
            """Check if key exists."""
            extra = self.__pydantic_extra__
            return extra is not None and key in extra

        def __len__(self) -> int:
            """Return number of extra fields."""
            extra = self.__pydantic_extra__
            return len(extra) if extra is not None else 0

        def __iter__(
            self,
        ) -> Generator[tuple[str, t.MetadataAttributeValue]]:
            """Iterate over key-value pairs from extra fields."""
            extra = self.__pydantic_extra__
            if extra is not None:
                for key, value in extra.items():
                    if isinstance(value, str | float | bool | list):
                        yield (key, value)
                    else:
                        yield (key, str(value) if value is not None else None)

        def keys(self) -> KeysView[str]:
            """Return keys from extra fields."""
            extra = self.__pydantic_extra__
            return (extra or {}).keys()

        def values(self) -> ValuesView[t.MetadataAttributeValue]:
            """Return values from extra fields."""
            extra = self.__pydantic_extra__
            return (extra or {}).values()

        def items(self) -> ItemsView[str, t.MetadataAttributeValue]:
            """Return items from extra fields."""
            extra = self.__pydantic_extra__
            return (extra or {}).items()

        def pop(
            self,
            key: str,
            default: t.MetadataAttributeValue = None,
        ) -> t.MetadataAttributeValue:
            """Pop value by key."""
            extra = self.__pydantic_extra__
            if extra is not None and key in extra:
                value = extra.pop(key)
                if isinstance(value, str | float | bool | list | dict):
                    return value
                return str(value) if value is not None else None
            return default

        def clear(self) -> None:
            """Clear all extra fields."""
            extra = self.__pydantic_extra__
            if extra is not None:
                extra.clear()

        def update(self, other: dict[str, t.MetadataAttributeValue]) -> None:
            """Update with values from another dict."""
            for key, value in other.items():
                setattr(self, key, value)

        def __hash__(self) -> int:
            """Make unhashable - mutable with extra="allow"."""
            class_name = self.__class__.__name__
            msg = f"{class_name} is unhashable"
            raise TypeError(msg)

        def __eq__(self, other: object) -> bool:
            """Compare with dict or another DynamicMetadata."""
            if isinstance(other, dict):
                return dict(self.items()) == other
            if isinstance(other, FlextLdifModelsMetadata.DynamicMetadata):
                return dict(self.items()) == dict(other.items())
            return NotImplemented

        def to_dict(self) -> dict[str, t.MetadataAttributeValue]:
            """Convert to dict for serialization."""
            return dict(self.items())

    class EntryMetadata(FlextModelsBase.ArbitraryTypesModel):
        """Entry metadata for tracking processing details.

        Stores additional metadata about entries processed.
        Uses extra="allow" for flexible field storage with dict-like interface.

        Example:
            meta = EntryMetadata(original_format="base64", source="oid")
            assert meta["original_format"] == "base64"

        """

        model_config = ConfigDict(
            frozen=True,
            extra="allow",
            use_enum_values=True,
            str_strip_whitespace=True,
        )

        def __getitem__(self, key: str) -> t.MetadataAttributeValue:
            """Get value by key, raising KeyError if not found."""
            extra = self.__pydantic_extra__
            if extra is not None and key in extra:
                value = extra[key]
                if isinstance(value, str | float | bool | list | dict):
                    return value
                return str(value) if value is not None else None
            raise KeyError(key)

        def __contains__(self, key: str) -> bool:
            """Check if key exists."""
            extra = self.__pydantic_extra__
            return extra is not None and key in extra

        def get(
            self,
            key: str,
            default: t.MetadataAttributeValue = None,
        ) -> t.MetadataAttributeValue:
            """Get value by key, returning default if not found."""
            extra = self.__pydantic_extra__
            if extra is not None and key in extra:
                value = extra[key]
                if isinstance(value, str | float | bool | list | dict):
                    return value
                return str(value) if value is not None else None
            return default

    class TransformationInfo(FlextModelsBase.ArbitraryTypesModel):
        """Transformation step information stored in metadata.

        Replaces TypedDict with Pydantic model for better validation and type safety.
        Used to track transformation steps during LDIF processing.

        Example:
            info = TransformationInfo(
                step="attribute_conversion",
                server="oud",
                changes=["cn converted", "sn normalized"]
            )

        """

        model_config = ConfigDict(
            extra="forbid",
            validate_assignment=True,
        )

        step: str | None = None
        """Transformation step identifier."""

        server: str | None = None
        """Server type where transformation occurred."""

        changes: ClassVar[list[str]] = []
        """List of changes made during transformation."""


__all__ = ["FlextLdifModelsMetadata"]
