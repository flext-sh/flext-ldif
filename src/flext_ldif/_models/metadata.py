"""Metadata models for LDIF processing."""

from __future__ import annotations

from collections.abc import ItemsView, Iterator, KeysView, Mapping, ValuesView
from typing import ClassVar, override

from flext_core import FlextModels
from pydantic import ConfigDict, Field

from flext_ldif import t


class FlextLdifModelsMetadata:
    """LDIF metadata models container."""

    class DynamicMetadata(FlextModels.ArbitraryTypesModel):
        """Model with extra='allow' for dynamic field storage."""

        model_config = ConfigDict(extra="allow", arbitrary_types_allowed=True)
        __hash__: ClassVar[None] = None

        transformations: list[t.Scalar] | None = Field(default=None)
        original_format: str | None = Field(default=None)
        schema_source_server: str | None = Field(default=None)
        server_type: str | None = Field(default=None)
        relaxed_mode: bool | None = Field(default=None)

        @classmethod
        def from_dict(
            cls,
            data: Mapping[str, t.MetadataValue] | None = None,
        ) -> FlextLdifModelsMetadata.DynamicMetadata:
            """Create DynamicMetadata from a dictionary."""
            if data is None:
                return cls()
            return cls.model_validate(dict(data))

        @staticmethod
        def coerce_metadata_value(
            value: t.MetadataValue,
        ) -> t.MetadataValue:
            """Identity coercion — value already typed by MetadataAttributeValue."""
            return value

        def _extra(self) -> dict[str, t.MetadataValue]:
            return self.__pydantic_extra__ or {}

        def get(
            self,
            key: str,
            default: t.MetadataValue = None,
        ) -> t.MetadataValue:
            """Get value by key, returning default if not found."""
            if key in type(self).model_fields:
                return getattr(self, key)
            return self._extra().get(key, default)

        def __getitem__(self, key: str) -> t.MetadataValue:
            if key in type(self).model_fields:
                return getattr(self, key)
            return self._extra()[key]

        def __setitem__(self, key: str, value: t.MetadataValue) -> None:
            setattr(self, key, value)

        def __contains__(self, key: str) -> bool:
            return key in self._extra()

        def __len__(self) -> int:
            return len(self._extra())

        @override
        def __iter__(self) -> Iterator[tuple[str, t.MetadataValue]]:  # type: ignore[override]
            yield from self._extra().items()

        def keys(self) -> KeysView[str]:
            return self._extra().keys()

        def values(self) -> ValuesView[t.MetadataValue]:
            return self._extra().values()

        def items(self) -> ItemsView[str, t.MetadataValue]:
            return self._extra().items()

        def pop(
            self,
            key: str,
            default: t.MetadataValue = None,
        ) -> t.MetadataValue:
            extra = self.__pydantic_extra__
            if extra is not None and key in extra:
                return extra.pop(key)
            return default

        def clear(self) -> None:
            extra = self.__pydantic_extra__
            if extra is not None:
                extra.clear()

        def update(self, other: Mapping[str, t.MetadataValue]) -> None:
            for key, value in other.items():
                setattr(self, key, value)

        @override
        def __eq__(self, other: object) -> bool:
            if other.__class__ is dict:
                return dict(self.items()) == other
            return NotImplemented

        def to_dict(self) -> Mapping[str, t.MetadataValue]:
            return dict(self.items())

    class EntryMetadata(FlextModels.ArbitraryTypesModel):
        """Entry metadata for tracking processing details."""

        model_config = ConfigDict(
            frozen=True,
            extra="allow",
            use_enum_values=True,
            str_strip_whitespace=True,
        )

        def _extra(self) -> dict[str, t.MetadataValue]:
            return self.__pydantic_extra__ or {}

        def __getitem__(self, key: str) -> t.MetadataValue:
            return self._extra()[key]

        def __contains__(self, key: str) -> bool:
            return key in self._extra()

        def get(
            self,
            key: str,
            default: t.MetadataValue = None,
        ) -> t.MetadataValue:
            return self._extra().get(key, default)

    class TransformationInfo(FlextModels.ArbitraryTypesModel):
        """Transformation step information stored in metadata."""

        model_config = ConfigDict(extra="forbid", validate_assignment=True)

        step: str | None = None
        server: str | None = None
        changes: ClassVar[list[str]] = []


__all__ = ["FlextLdifModelsMetadata"]
