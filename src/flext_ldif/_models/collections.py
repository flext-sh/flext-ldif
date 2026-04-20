"""Collection and utility models for LDIF processing.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import (
    Iterator,
    MutableMapping,
    MutableSequence,
)
from typing import TYPE_CHECKING, Annotated, override

from flext_cli import m, u
from flext_ldif._models.metadata import FlextLdifModelsMetadata
from flext_ldif.typings import t

if TYPE_CHECKING:
    from flext_ldif._models.domain_entries import FlextLdifModelsDomainsEntries


class FlextLdifModelsCollections:
    class DynamicCounts(m.DynamicModel):
        model_config = m.ConfigDict(extra="allow", validate_assignment=True)

        @override
        def __eq__(self, other: t.ValueOrModel) -> bool:
            if isinstance(other, dict):
                self_dict = {
                    key: value
                    for key, value in self.__dict__.items()
                    if not key.startswith("_")
                }
                extra = self.__pydantic_extra__
                if extra is not None:
                    self_dict.update(extra)
                return self_dict == other
            if isinstance(other, self.__class__):
                return super().__eq__(other)
            return False

        def __hash__(self) -> int:
            return hash(id(self))

        def __getitem__(self, key: str) -> int:
            extra = self._extra()
            if key in extra:
                return self._to_count(extra[key])
            msg = f"Key {key!r} not found"
            raise KeyError(msg)

        def __len__(self) -> int:
            return len(self._extra())

        def __contains__(self, key: str) -> bool:
            return key in self._extra()

        @staticmethod
        def _to_count(value: t.MetadataValue) -> int:
            if isinstance(value, t.NUMERIC_TYPES) and not isinstance(value, bool):
                return int(value)
            if isinstance(value, str):
                try:
                    return int(float(value))
                except (ValueError, TypeError):
                    return 0
            return 0

        def get(self, key: str, default: int | None = None) -> int | None:
            extra = self._extra()
            if key in extra:
                return self._to_count(extra[key])
            return default

        def items(self) -> MutableSequence[tuple[str, int]]:
            extra = self._extra()
            return [(k, self._to_count(v)) for k, v in extra.items()]

        def set_count(self, key: str, value: int) -> None:
            setattr(self, key, value)

        def _extra(self) -> MutableMapping[str, t.MetadataValue]:
            extra = self.__pydantic_extra__
            if extra is None:
                return {}
            return {str(k): v for k, v in extra.items()}

    class SchemaContent(m.FrozenModel):
        attributes: Annotated[
            MutableSequence[FlextLdifModelsDomainsEntries.SchemaAttribute],
            u.Field(description="Schema attribute definitions extracted from LDIF"),
        ]
        object_classes: Annotated[
            MutableSequence[FlextLdifModelsDomainsEntries.SchemaObjectClass],
            u.Field(description="Schema object class definitions extracted from LDIF"),
        ]

    class CategoryPaths(FlextLdifModelsMetadata.DynamicMetadata):
        """Category to file path mapping model."""

    class ConfigSettings(FlextLdifModelsMetadata.DynamicMetadata):
        def set_setting(self, key: str, value: t.Scalar) -> None:
            self[key] = value

    class BooleanFlags(m.FrozenDynamicModel):
        @override
        def __eq__(self, other: t.ValueOrModel) -> bool:
            if isinstance(other, dict):
                extra = self.model_extra
                return (extra or {}) == other
            if isinstance(other, self.__class__):
                return self.model_extra == other.model_extra
            return False

        def __hash__(self) -> int:
            extra = self.__pydantic_extra__
            if extra is None:
                return hash(())
            return hash(tuple(sorted(extra.items())))

        def __getitem__(self, key: str) -> bool:
            extra = self.__pydantic_extra__
            if extra is None or key not in extra:
                msg = f"Key '{key}' not found in flags"
                raise KeyError(msg)
            return bool(extra[key])

    class FlexibleCategories(m.DynamicModel):
        categories: MutableMapping[
            str, MutableSequence[FlextLdifModelsDomainsEntries.Entry]
        ] = u.Field(default_factory=dict)

        @override
        def __eq__(self, other: t.ValueOrModel) -> bool:
            if isinstance(other, self.__class__):
                return self.categories == other.categories
            if isinstance(other, dict):
                return self.categories == other
            return False

        def __hash__(self) -> int:
            msg = f"{self.__class__.__name__} is unhashable"
            raise TypeError(msg)

        def __getitem__(
            self,
            category: str,
        ) -> MutableSequence[FlextLdifModelsDomainsEntries.Entry]:
            key = str(category)
            if key not in self.categories:
                self.categories[key] = []
            return self.categories[key]

        def __setitem__(
            self,
            category: str,
            entries: MutableSequence[FlextLdifModelsDomainsEntries.Entry],
        ) -> None:
            self.categories[str(category)] = list(entries)

        def add_entries(
            self,
            category: str,
            entries: MutableSequence[FlextLdifModelsDomainsEntries.Entry],
        ) -> None:
            key = str(category)
            existing = self.categories.get(key)
            if existing is None:
                existing_entries: list[FlextLdifModelsDomainsEntries.Entry] = []
                existing = existing_entries
            existing.extend(entries)
            self.categories[key] = existing

        def __contains__(self, category: str) -> bool:
            return str(category) in self.categories

        def items(
            self,
        ) -> Iterator[tuple[str, MutableSequence[FlextLdifModelsDomainsEntries.Entry]]]:
            yield from self.categories.items()

        def keys(self) -> Iterator[str]:
            return iter(self.categories.keys())

        def get(
            self,
            category: str,
            default: MutableSequence[FlextLdifModelsDomainsEntries.Entry] | None = None,
        ) -> MutableSequence[FlextLdifModelsDomainsEntries.Entry]:
            entries = self.categories.get(str(category))
            if entries is not None:
                return entries
            return default if default is not None else []

        def values(
            self,
        ) -> Iterator[MutableSequence[FlextLdifModelsDomainsEntries.Entry]]:
            yield from self.categories.values()


__all__: list[str] = ["FlextLdifModelsCollections"]
