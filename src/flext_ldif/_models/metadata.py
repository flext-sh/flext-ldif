"""Metadata models for LDIF processing."""

from __future__ import annotations

from collections.abc import (
    ItemsView,
    KeysView,
    MutableMapping,
    MutableSequence,
    ValuesView,
)
from typing import ClassVar, Self, override

from flext_core import FlextModels
from pydantic import ConfigDict

from flext_ldif import t


class FlextLdifModelsMetadata:
    """LDIF metadata models container."""

    class DynamicMetadata(FlextModels.ArbitraryTypesModel):
        """Model with extra='allow' for dynamic field storage."""

        model_config: ClassVar[ConfigDict] = ConfigDict(
            extra="allow",
            arbitrary_types_allowed=True,
            frozen=False,
        )
        transformations: MutableSequence[t.Scalar] | None = None
        original_format: str | None = None
        schema_source_server: str | None = None
        server_type: str | None = None
        relaxed_mode: bool | None = None

        @override
        def __eq__(self, other: t.NormalizedValue) -> bool:
            if isinstance(other, dict):
                return dict(self.items()) == other
            if isinstance(other, type(self)):
                return dict(self.items()) == dict(other.items())
            return NotImplemented

        def __hash__(self) -> int:
            msg = "unhashable type: 'DynamicMetadata'"
            raise TypeError(msg)

        def __getitem__(self, key: str) -> t.Ldif.MetadataValue:
            if key in type(self).model_fields:
                return getattr(self, key)
            return self._extra()[key]

        def __setitem__(self, key: str, value: t.Ldif.MetadataValue) -> None:
            setattr(self, key, value)

        def __len__(self) -> int:
            return len(self._extra())

        def __contains__(self, key: str) -> bool:
            return key in self._extra()

        @classmethod
        def from_dict(cls, data: t.MutableContainerMapping | None = None) -> Self:
            """Create DynamicMetadata from a dictionary."""
            if data is None:
                return cls()
            return cls.model_validate(dict(data))

        @staticmethod
        def coerce_metadata_value(value: t.Ldif.MetadataValue) -> t.Ldif.MetadataValue:
            """Identity coercion — value already typed by MetadataAttributeValue."""
            return value

        def clear(self) -> None:
            extra = self.__pydantic_extra__
            if extra is not None:
                extra.clear()

        def get(
            self,
            key: str,
            default: t.Ldif.MetadataValue | None = None,
        ) -> t.Ldif.MetadataValue | None:
            """Get value by key, returning default if not found."""
            if key in type(self).model_fields:
                return getattr(self, key)
            return self._extra().get(key, default)

        def items(self) -> ItemsView[str, t.Ldif.MetadataValue]:
            return self._extra().items()

        def keys(self) -> KeysView[str]:
            return self._extra().keys()

        def pop(
            self,
            key: str,
            default: t.Ldif.MetadataValue | None = None,
        ) -> t.Ldif.MetadataValue | None:
            extra = self.__pydantic_extra__
            if extra is not None and key in extra:
                return extra.pop(key)
            return default

        def to_dict(self) -> MutableMapping[str, t.Ldif.MetadataValue]:
            return dict(self.items())

        def update(self, other: MutableMapping[str, t.Ldif.MetadataValue]) -> None:
            for key, value in other.items():
                setattr(self, key, value)

        def values(self) -> ValuesView[t.Ldif.MetadataValue]:
            return self._extra().values()

        def _extra(self) -> MutableMapping[str, t.Ldif.MetadataValue]:
            return self.__pydantic_extra__ or {}

    class EntryMetadata(FlextModels.ArbitraryTypesModel):
        """Entry metadata for tracking processing details."""

        model_config: ClassVar[ConfigDict] = ConfigDict(
            frozen=True,
            extra="allow",
            use_enum_values=True,
            str_strip_whitespace=True,
        )

        def __getitem__(self, key: str) -> t.Ldif.MetadataValue:
            return self._extra()[key]

        def __contains__(self, key: str) -> bool:
            return key in self._extra()

        def get(
            self,
            key: str,
            default: t.Ldif.MetadataValue | None = None,
        ) -> t.Ldif.MetadataValue | None:
            return self._extra().get(key, default)

        def _extra(self) -> MutableMapping[str, t.Ldif.MetadataValue]:
            return self.__pydantic_extra__ or {}

    class TransformationInfo(FlextModels.ArbitraryTypesModel):
        """Transformation step information stored in metadata."""

        model_config: ClassVar[ConfigDict] = ConfigDict(
            extra="forbid", validate_assignment=True
        )
        step: str | None = None
        server: str | None = None
        changes: ClassVar[MutableSequence[str]] = []


__all__ = ["FlextLdifModelsMetadata"]
