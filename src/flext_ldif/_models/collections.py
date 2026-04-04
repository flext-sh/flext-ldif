"""Collection and utility models for LDIF processing.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Iterator, MutableMapping, MutableSequence
from typing import Annotated, override

from pydantic import ConfigDict, Field

from flext_core import m
from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif._models.metadata import FlextLdifModelsMetadata
from flext_ldif.typings import FlextLdifTypes as t


class FlextLdifModelsCollections:
    class DynamicCounts(m.DynamicModel):
        model_config = ConfigDict(extra="allow", validate_assignment=True)

        @override
        def __eq__(self, other: object) -> bool:
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
            MutableSequence[FlextLdifModelsDomains.SchemaAttribute],
            Field(description="Schema attribute definitions extracted from LDIF"),
        ]
        object_classes: Annotated[
            MutableSequence[FlextLdifModelsDomains.SchemaObjectClass],
            Field(description="Schema object class definitions extracted from LDIF"),
        ]

    class CategoryPaths(FlextLdifModelsMetadata.DynamicMetadata):
        """Category to file path mapping model."""

    class ConfigSettings(FlextLdifModelsMetadata.DynamicMetadata):
        def set_setting(self, key: str, value: t.Scalar) -> None:
            self[key] = value

    class BooleanFlags(m.FrozenDynamicModel):
        @override
        def __eq__(self, other: object) -> bool:
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
            str, MutableSequence[FlextLdifModelsDomains.Entry]
        ] = Field(
            default_factory=dict,
            description="Mapping of category names to their LDIF entries",
        )

        @override
        def __eq__(self, other: object) -> bool:
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
        ) -> MutableSequence[FlextLdifModelsDomains.Entry]:
            return self._entry_categories()[category]

        def __setitem__(
            self,
            category: str,
            entries: MutableSequence[FlextLdifModelsDomains.Entry],
        ) -> None:
            domains = FlextLdifModelsDomains
            updated_categories = self._entry_categories()
            updated_categories[category] = [
                domains.Entry.model_validate(entry) for entry in entries
            ]
            object.__setattr__(self, "categories", updated_categories)

        def add_entries(
            self,
            category: str,
            entries: MutableSequence[FlextLdifModelsDomains.Entry]
            | t.MutableContainerList,
        ) -> None:
            domains = FlextLdifModelsDomains
            existing = self._entry_categories().get(category, [])
            normalized_entries = [
                domains.Entry.model_validate(entry) for entry in entries
            ]
            self[category] = [*existing, *normalized_entries]

        def __contains__(self, category: str) -> bool:
            return category in self.categories

        def items(
            self,
        ) -> Iterator[tuple[str, MutableSequence[FlextLdifModelsDomains.Entry]]]:
            domains = FlextLdifModelsDomains
            for category, values in self.categories.items():
                yield (
                    category,
                    [domains.Entry.model_validate(v) for v in values],
                )

        def keys(self) -> Iterator[str]:
            return iter(self.categories.keys())

        def get(
            self,
            category: str,
            default: MutableSequence[FlextLdifModelsDomains.Entry] | None = None,
        ) -> MutableSequence[FlextLdifModelsDomains.Entry]:
            entries = self._entry_categories().get(category)
            if entries is not None:
                return entries
            return default if default is not None else []

        def values(self) -> Iterator[MutableSequence[FlextLdifModelsDomains.Entry]]:
            domains = FlextLdifModelsDomains
            for values in self._entry_categories().values():
                yield [domains.Entry.model_validate(v) for v in values]

        def _entry_categories(
            self,
        ) -> MutableMapping[str, MutableSequence[FlextLdifModelsDomains.Entry]]:
            domains = FlextLdifModelsDomains
            return {
                str(category): [domains.Entry.model_validate(value) for value in values]
                for category, values in self.categories.items()
            }


__all__ = ["FlextLdifModelsCollections"]
