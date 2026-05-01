"""Metadata models for LDIF processing."""

from __future__ import annotations

from collections.abc import (
    ItemsView,
    KeysView,
    MutableMapping,
    ValuesView,
)
from typing import Annotated, ClassVar, Self, override

from flext_cli import m, u
from flext_ldif import t


class FlextLdifModelsMetadata:
    """LDIF metadata models container."""

    class DynamicMetadata(m.DynamicModel):
        """Model with extra='allow' for dynamic field storage."""

        model_config: ClassVar[m.ConfigDict] = m.ConfigDict(extra="allow")

        transformations: Annotated[
            t.MutableSequenceOf[t.Ldif.Scalar] | None,
            u.Field(description="List of transformations applied to this metadata"),
        ] = None
        original_format: Annotated[
            str | None, u.Field(description="Original LDIF format before conversion")
        ] = None
        schema_source_server: Annotated[
            str | None, u.Field(description="Server type that provided the schema")
        ] = None
        server_type: Annotated[
            str | None, u.Field(description="LDAP server type identifier")
        ] = None
        relaxed_mode: Annotated[
            bool | None, u.Field(description="Whether relaxed parsing mode was used")
        ] = None
        server_specific_violations: Annotated[
            t.MutableSequenceOf[t.JsonValue] | None,
            u.Field(description="Server-specific validation violations"),
        ] = None
        schema_transformations: Annotated[
            t.MutableSequenceOf[t.JsonValue] | None,
            u.Field(
                description="Schema transformations applied during processing",
            ),
        ] = None

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

        def __getitem__(self, key: str) -> t.JsonValue:
            if key in type(self).model_fields:
                attr_val: t.JsonValue = getattr(self, key)
                return attr_val
            item: t.JsonValue = self._extra()[key]
            return item

        def __setitem__(self, key: str, value: t.Ldif.MetadataCarrierValue) -> None:
            setattr(self, key, u.normalize_to_metadata(value))

        def __len__(self) -> int:
            return len(self._extra())

        def __contains__(self, key: str) -> bool:
            return key in self._extra()

        @classmethod
        def from_dict(
            cls,
            data: t.Ldif.MetadataInputMapping | None = None,
        ) -> Self:
            """Create DynamicMetadata from a dictionary."""
            if data is None:
                return cls()
            validated: Self = cls.model_validate({
                key: u.normalize_to_metadata(value) for key, value in data.items()
            })
            return validated

        @staticmethod
        def coerce_metadata_value(
            value: t.Ldif.MetadataCarrierValue,
        ) -> t.JsonValue:
            """Normalize metadata payloads into the canonical recursive shape."""
            return u.normalize_to_metadata(value)

        def clear(self) -> None:
            extra = self.__pydantic_extra__
            if extra is not None:
                extra.clear()

        def get(
            self,
            key: str,
            default: t.JsonValue | None = None,
        ) -> t.JsonValue | None:
            """Get value by key, returning default if not found."""
            if key in type(self).model_fields:
                attr_val: t.JsonValue = getattr(self, key)
                return attr_val
            extra_val: t.JsonValue | None = self._extra().get(key, default)
            return extra_val

        def items(self) -> ItemsView[str, t.JsonValue]:
            return self._extra().items()

        def keys(self) -> KeysView[str]:
            return self._extra().keys()

        def pop(
            self,
            key: str,
            default: t.JsonValue | None = None,
        ) -> t.JsonValue | None:
            extra = self.__pydantic_extra__
            if extra is not None and key in extra:
                popped: t.JsonValue | None = extra.pop(key)
                return popped
            return default

        def to_dict(self) -> MutableMapping[str, t.JsonValue]:
            return dict(self.items())

        def update(self, other: MutableMapping[str, t.JsonValue]) -> None:
            for key, value in other.items():
                setattr(self, key, value)

        def values(self) -> ValuesView[t.JsonValue]:
            return self._extra().values()

        def _extra(self) -> MutableMapping[str, t.JsonValue]:
            return self.__pydantic_extra__ or {}

    class EntryMetadata(m.FrozenDynamicModel):
        """Entry metadata for tracking processing details."""

        model_config: ClassVar[m.ConfigDict] = m.ConfigDict(extra="allow")

        def __getitem__(self, key: str) -> t.JsonValue:
            return self._extra()[key]

        def __contains__(self, key: str) -> bool:
            return key in self._extra()

        def get(
            self,
            key: str,
            default: t.JsonValue | None = None,
        ) -> t.JsonValue | None:
            return self._extra().get(key, default)

        def _extra(self) -> MutableMapping[str, t.JsonValue]:
            return self.__pydantic_extra__ or {}


__all__: list[str] = ["FlextLdifModelsMetadata"]
