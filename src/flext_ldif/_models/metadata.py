"""Metadata models for LDIF processing."""

from __future__ import annotations

from collections.abc import ItemsView, Iterator, KeysView, Mapping, ValuesView
from typing import ClassVar, override

from flext_core._models.base import FlextModelFoundation
from pydantic import ConfigDict, Field

from flext_ldif import t


class FlextLdifModelsMetadata:
    """LDIF metadata models container."""

    class DynamicMetadata(FlextModelFoundation.ArbitraryTypesModel):
        """Model with extra='allow' for dynamic field storage."""

        model_config = ConfigDict(extra="allow", arbitrary_types_allowed=True)
        __hash__: ClassVar[None] = None

        transformations: list[t.MetadataScalarValue] | None = Field(default=None)
        original_format: str | None = Field(default=None)
        schema_source_server: str | None = Field(default=None)
        server_type: str | None = Field(default=None)
        relaxed_mode: bool | None = Field(default=None)

        @classmethod
        def from_dict(
            cls,
            data: Mapping[str, t.MetadataAttributeValue] | None = None,
        ) -> FlextLdifModelsMetadata.DynamicMetadata:
            """Create DynamicMetadata from a dictionary."""
            if data is None:
                return cls()
            return cls.model_validate(dict(data))

        @staticmethod
        def coerce_metadata_value(
            value: t.MetadataAttributeValue,
        ) -> t.MetadataAttributeValue:
            """Identity coercion — value already typed by MetadataAttributeValue."""
            return value

        def _extra(self) -> dict[str, t.MetadataAttributeValue]:
            return self.__pydantic_extra__ or {}

        def get(
            self,
            key: str,
            default: t.MetadataAttributeValue = None,
        ) -> t.MetadataAttributeValue:
            """Get value by key, returning default if not found."""
            if key in type(self).model_fields:
                return getattr(self, key)
            return self._extra().get(key, default)

        def __getitem__(self, key: str) -> t.MetadataAttributeValue:
            if key in type(self).model_fields:
                return getattr(self, key)
            return self._extra()[key]

        def __setitem__(self, key: str, value: t.MetadataAttributeValue) -> None:
            setattr(self, key, value)

        def __contains__(self, key: str) -> bool:
            return key in self._extra()

        def __len__(self) -> int:
            return len(self._extra())

        @override
        def __iter__(self) -> Iterator[tuple[str, t.MetadataAttributeValue]]:  # type: ignore[override]
            yield from self._extra().items()

        def keys(self) -> KeysView[str]:
            return self._extra().keys()

        def values(self) -> ValuesView[t.MetadataAttributeValue]:
            return self._extra().values()

        def items(self) -> ItemsView[str, t.MetadataAttributeValue]:
            return self._extra().items()

        def pop(
            self,
            key: str,
            default: t.MetadataAttributeValue = None,
        ) -> t.MetadataAttributeValue:
            extra = self.__pydantic_extra__
            if extra is not None and key in extra:
                return extra.pop(key)
            return default

        def clear(self) -> None:
            extra = self.__pydantic_extra__
            if extra is not None:
                extra.clear()

        def update(self, other: Mapping[str, t.MetadataAttributeValue]) -> None:
            for key, value in other.items():
                setattr(self, key, value)

        @override
        def __eq__(self, other: t.GeneralValueType) -> bool:
            if other.__class__ is dict:
                return dict(self.items()) == other
            return NotImplemented

        def to_dict(self) -> Mapping[str, t.MetadataAttributeValue]:
            return dict(self.items())

    class EntryMetadata(FlextModelFoundation.ArbitraryTypesModel):
        """Entry metadata for tracking processing details."""

        model_config = ConfigDict(
            frozen=True,
            extra="allow",
            use_enum_values=True,
            str_strip_whitespace=True,
        )

        def _extra(self) -> dict[str, t.MetadataAttributeValue]:
            return self.__pydantic_extra__ or {}

        def __getitem__(self, key: str) -> t.MetadataAttributeValue:
            return self._extra()[key]

        def __contains__(self, key: str) -> bool:
            return key in self._extra()

        def get(
            self,
            key: str,
            default: t.MetadataAttributeValue = None,
        ) -> t.MetadataAttributeValue:
            return self._extra().get(key, default)

    class TransformationInfo(FlextModelFoundation.ArbitraryTypesModel):
        """Transformation step information stored in metadata."""

        model_config = ConfigDict(extra="forbid", validate_assignment=True)

        step: str | None = None
        server: str | None = None
        changes: ClassVar[list[str]] = []


__all__ = ["FlextLdifModelsMetadata"]
