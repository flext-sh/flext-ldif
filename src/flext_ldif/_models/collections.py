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


class FlextLdifModelsCollections:
    class DynamicCounts(FlextLdifModelsBases.FlextLdifModelsBase):
        model_config = ConfigDict(
            frozen=False,
            extra="allow",
            use_enum_values=True,
            str_strip_whitespace=True,
        )

        def set_count(self, key: str, value: int) -> None:
            setattr(self, key, value)

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

        def __getitem__(self, key: str) -> int:
            extra = self._extra()
            if key in extra:
                return self._to_count(extra[key])
            msg = f"Key {key!r} not found"
            raise KeyError(msg)

        def _extra(self) -> dict[str, t.MetadataValue]:
            return self.__pydantic_extra__ or {}

        def get(self, key: str, default: int | None = None) -> int | None:
            extra = self._extra()
            if key in extra:
                return self._to_count(extra[key])
            return default

        def __contains__(self, key: str) -> bool:
            return key in self._extra()

        def __len__(self) -> int:
            return len(self._extra())

        def items(self) -> list[tuple[str, int]]:
            extra = self._extra()
            return [(k, self._to_count(v)) for k, v in extra.items()]

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

        def max_key(self) -> str | None:
            extra = self._extra()
            if not extra:
                return None
            return max(extra, key=lambda k: self._to_count(extra.get(k, 0)))

    class SchemaContent(FlextLdifModelsBases.FlextLdifModelsBase):
        model_config = ConfigDict(frozen=True)
        attributes: Sequence[FlextLdifModelsDomains.SchemaAttribute] = Field(
            default_factory=list,
        )
        object_classes: Sequence[FlextLdifModelsDomains.SchemaObjectClass] = Field(
            default_factory=list,
        )

    class CategoryPaths(FlextLdifModelsMetadata.DynamicMetadata):
        """Category to file path mapping model."""

    class ConfigSettings(FlextLdifModelsMetadata.DynamicMetadata):
        def set_setting(self, key: str, value: str | int | bool) -> None:
            self[key] = value

    class BooleanFlags(FlextLdifModelsBases.FlextLdifModelsBase):
        model_config = ConfigDict(
            frozen=True,
            extra="allow",
            use_enum_values=True,
            str_strip_whitespace=True,
        )

        def __getitem__(self, key: str) -> bool:
            extra = self.__pydantic_extra__
            if extra is None or key not in extra:
                msg = f"Key '{key}' not found in flags"
                raise KeyError(msg)
            return bool(extra[key])

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

    class FlexibleCategories(m.Categories):
        model_config = ConfigDict(extra="allow", frozen=False)

        def __hash__(self) -> int:
            msg = f"{self.__class__.__name__} is unhashable"
            raise TypeError(msg)

        @override
        def __eq__(self, other: object) -> bool:
            if isinstance(other, self.__class__):
                return self.categories == other.categories
            if isinstance(other, dict):
                return self.categories == other
            return False

        def items(self) -> Iterator[tuple[str, list[FlextLdifModelsDomains.Entry]]]:
            for category, values in self.categories.items():
                yield (
                    category,
                    [FlextLdifModelsDomains.Entry.model_validate(v) for v in values],
                )

        def values(self) -> Iterator[list[FlextLdifModelsDomains.Entry]]:
            for values in self.categories.values():
                yield [FlextLdifModelsDomains.Entry.model_validate(v) for v in values]

        def keys(self) -> Iterator[str]:
            return iter(self.categories.keys())

        def __contains__(self, category: str) -> bool:
            return category in self.categories

        def __getitem__(self, category: str) -> list[FlextLdifModelsDomains.Entry]:
            return [
                FlextLdifModelsDomains.Entry.model_validate(v)
                for v in self.categories[category]
            ]

        def __setitem__(
            self,
            category: str,
            entries: Sequence[FlextLdifModelsDomains.Entry],
        ) -> None:
            self.categories[category] = list(entries)
