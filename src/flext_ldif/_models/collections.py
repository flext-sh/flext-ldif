"""Collection and utility models for LDIF processing.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from typing import override

from flext_core import m
from pydantic import ConfigDict, Field

from flext_ldif import t
from flext_ldif._models.base import FlextLdifModelsBases
from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif._models.metadata import FlextLdifModelsMetadata


def _schema_attributes_factory() -> list[FlextLdifModelsDomains.SchemaAttribute]:
    return []


def _schema_object_classes_factory() -> list[FlextLdifModelsDomains.SchemaObjectClass]:
    return []


class FlextLdifModelsCollections:
    class DynamicCounts(FlextLdifModelsBases.FlextLdifModelsBase):
        model_config = ConfigDict(
            frozen=False, extra="allow", use_enum_values=True, str_strip_whitespace=True
        )

        @override
        def __eq__(self, other: object) -> bool:
            if other.__class__ is dict:
                self_dict = {
                    key: value
                    for key, value in self.__dict__.items()
                    if not key.startswith("_")
                }
                extra = self.__pydantic_extra__
                if extra is not None:
                    self_dict.update(extra)
                return self_dict == other
            return super().__eq__(other)

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
            if isinstance(value, int | float):
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

        def items(self) -> list[tuple[str, int]]:
            extra = self._extra()
            return [(k, self._to_count(v)) for k, v in extra.items()]

        def max_key(self) -> str | None:
            extra = self._extra()
            if not extra:
                return None
            return max(extra, key=lambda k: self._to_count(extra.get(k, 0)))

        def set_count(self, key: str, value: int) -> None:
            setattr(self, key, value)

        def _extra(self) -> dict[str, t.MetadataValue]:
            return self.__pydantic_extra__ or {}

    class SchemaContent(FlextLdifModelsBases.FlextLdifModelsBase):
        model_config = ConfigDict(frozen=True)
        attributes: list[FlextLdifModelsDomains.SchemaAttribute] = Field(
            default_factory=_schema_attributes_factory
        )
        object_classes: list[FlextLdifModelsDomains.SchemaObjectClass] = Field(
            default_factory=_schema_object_classes_factory
        )

    class CategoryPaths(FlextLdifModelsMetadata.DynamicMetadata):
        """Category to file path mapping model."""

    class ConfigSettings(FlextLdifModelsMetadata.DynamicMetadata):
        def set_setting(self, key: str, value: str | int | bool) -> None:
            self[key] = value

    class BooleanFlags(FlextLdifModelsBases.FlextLdifModelsBase):
        model_config = ConfigDict(
            frozen=True, extra="allow", use_enum_values=True, str_strip_whitespace=True
        )

        @override
        def __eq__(self, other: object) -> bool:
            if isinstance(other, dict):
                extra = self.model_extra
                return (extra or {}) == other
            if isinstance(other, self.__class__):
                return self.model_extra == other.model_extra
            return NotImplemented

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

    class FlexibleCategories(m.Categories):
        model_config = ConfigDict(extra="allow", frozen=False)

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

        def __getitem__(self, category: str) -> list[FlextLdifModelsDomains.Entry]:
            return [
                FlextLdifModelsDomains.Entry.model_validate(v)
                for v in self.categories[category]
            ]

        def __setitem__(
            self, category: str, entries: Sequence[FlextLdifModelsDomains.Entry]
        ) -> None:
            self.categories[category] = list(entries)

        def __contains__(self, category: str) -> bool:
            return category in self.categories

        def items(self) -> Iterator[tuple[str, list[FlextLdifModelsDomains.Entry]]]:
            for category, values in self.categories.items():
                yield (
                    category,
                    [FlextLdifModelsDomains.Entry.model_validate(v) for v in values],
                )

        def keys(self) -> Iterator[str]:
            return iter(self.categories.keys())

        def values(self) -> Iterator[list[FlextLdifModelsDomains.Entry]]:
            for values in self.categories.values():
                yield [FlextLdifModelsDomains.Entry.model_validate(v) for v in values]
