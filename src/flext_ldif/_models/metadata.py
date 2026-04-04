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

from pydantic import ConfigDict, Field

from flext_core import m
from flext_ldif import t


class FlextLdifModelsMetadata:
    """LDIF metadata models container."""

    class DynamicMetadata(m.DynamicModel):
        """Model with extra='allow' for dynamic field storage."""

        model_config: ClassVar[ConfigDict] = ConfigDict(extra="allow")

        transformations: MutableSequence[t.Scalar] | None = Field(
            default=None, description="List of transformations applied to this metadata"
        )
        original_format: str | None = Field(
            default=None, description="Original LDIF format before conversion"
        )
        schema_source_server: str | None = Field(
            default=None, description="Server type that provided the schema"
        )
        server_type: str | None = Field(
            default=None, description="LDAP server type identifier"
        )
        relaxed_mode: bool | None = Field(
            default=None, description="Whether relaxed parsing mode was used"
        )
        server_specific_violations: MutableSequence[t.Ldif.MetadataValue] | None = (
            Field(default=None, description="Server-specific validation violations")
        )
        schema_transformations: MutableSequence[t.Ldif.MetadataValue] | None = Field(
            default=None,
            description="Schema transformations applied during processing",
        )

        @override
        def __eq__(self, other: object) -> bool:
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
        def from_dict(cls, data: t.ContainerMapping | None = None) -> Self:
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

    class EntryMetadata(m.FrozenDynamicModel):
        """Entry metadata for tracking processing details."""

        model_config: ClassVar[ConfigDict] = ConfigDict(extra="allow")

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


__all__ = ["FlextLdifModelsMetadata"]
