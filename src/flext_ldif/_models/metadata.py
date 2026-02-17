"""Metadata models for LDIF processing."""

from __future__ import annotations

from collections.abc import Generator, ItemsView, KeysView, Mapping, ValuesView
from typing import ClassVar, overload

from flext_core import t
from flext_core._models.base import FlextModelsBase
from pydantic import ConfigDict, Field


class FlextLdifModelsMetadata:
    """LDIF metadata models container."""

    class DynamicMetadata(FlextModelsBase.ArbitraryTypesModel):
        """Model with extra="allow" for dynamic field storage."""

        model_config = ConfigDict(extra="allow", arbitrary_types_allowed=True)

        transformations: list[object] | None = Field(default=None)

        @classmethod
        def from_dict(
            cls,
            data: Mapping[str, t.MetadataAttributeValue] | None = None,
        ) -> FlextLdifModelsMetadata.DynamicMetadata:
            """Create DynamicMetadata from a dictionary."""
            if data is None:
                return cls()

            return cls.model_validate(dict(data))

        original_format: str | None = Field(default=None)
        schema_source_server: str | None = Field(default=None)
        server_type: str | None = Field(default=None)
        relaxed_mode: bool | None = Field(default=None)

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
            if key in type(self).model_fields:
                field_value = getattr(self, key)
                if isinstance(field_value, str | float | bool | list | dict):
                    return field_value
                if field_value is not None:
                    return str(field_value)
            extra = self.__pydantic_extra__
            if extra is not None and key in extra:
                value = extra[key]

                if isinstance(value, str | float | bool | list | dict):
                    return value
                return str(value) if value is not None else None
            return default

        def __getitem__(self, key: str) -> t.MetadataAttributeValue:
            """Get value by key, raising KeyError if not found."""
            if key in type(self).model_fields:
                field_value = getattr(self, key)
                if isinstance(field_value, str | float | bool | list | dict):
                    return field_value
                if field_value is not None:
                    return str(field_value)
            extra = self.__pydantic_extra__
            if extra is not None and key in extra:
                value = extra[key]
                if isinstance(value, str | float | bool | list | dict):
                    return value
                return str(value) if value is not None else None
            raise KeyError(key)

        def __setitem__(self, key: str, value: object) -> None:
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
        """Entry metadata for tracking processing details."""

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
        """Transformation step information stored in metadata."""

        model_config = ConfigDict(
            extra="forbid",
            validate_assignment=True,
        )

        step: str | None = None

        server: str | None = None

        changes: ClassVar[list[str]] = []


__all__ = ["FlextLdifModelsMetadata"]
