"""Collection and utility models for LDIF processing.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import (
    Iterator,
    MutableMapping,
)
from typing import Annotated, ClassVar, override

from flext_cli import m, u
from flext_ldif import (
    FlextLdifModelsDomainsEntries as mde,
    FlextLdifModelsMetadata as mdm,
    t,
)


class FlextLdifModelsCollections:
    class DynamicCounts(m.DynamicModel):
        model_config: ClassVar[m.ConfigDict] = m.ConfigDict(
            extra="allow",
            validate_assignment=True,
        )

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
                eq_result: bool = super().__eq__(other)
                return eq_result
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
        def _to_count(value: t.JsonValue) -> int:
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

        def items(self) -> t.MutableSequenceOf[tuple[str, int]]:
            extra = self._extra()
            return [(k, self._to_count(v)) for k, v in extra.items()]

        def update_count(self, key: str, value: int) -> None:
            setattr(self, key, value)

        def _extra(self) -> MutableMapping[str, t.JsonValue]:
            extra = self.__pydantic_extra__
            if extra is None:
                return {}
            return dict(extra.items())

    class SchemaContent(m.FrozenModel):
        attributes: Annotated[
            t.MutableSequenceOf[mde.SchemaAttribute],
            u.Field(description="Schema attribute definitions extracted from LDIF"),
        ]
        object_classes: Annotated[
            t.MutableSequenceOf[mde.SchemaObjectClass],
            u.Field(description="Schema object class definitions extracted from LDIF"),
        ]

    class CategoryPaths(mdm.DynamicMetadata):
        """Category to file path mapping model."""

    class ConfigSettings(mdm.DynamicMetadata):
        def update_setting(self, key: str, value: t.Ldif.MetadataCarrierValue) -> None:
            self[key] = value

    class BooleanFlags(m.FrozenDynamicModel):
        @override
        def __eq__(self, other: object) -> bool:
            if isinstance(other, dict):
                extra = self.model_extra
                dict_eq: bool = (extra or {}) == other
                return dict_eq
            if isinstance(other, self.__class__):
                cls_eq: bool = self.model_extra == other.model_extra
                return cls_eq
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
        categories: Annotated[
            MutableMapping[str, t.MutableSequenceOf[mde.Entry]],
            u.Field(description="Category name to grouped LDIF entries mapping."),
        ] = u.Field(default_factory=dict)

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
        ) -> t.MutableSequenceOf[mde.Entry]:
            key = category
            if key not in self.categories:
                self.categories[key] = []
            return self.categories[key]

        def __setitem__(
            self,
            category: str,
            entries: t.MutableSequenceOf[mde.Entry],
        ) -> None:
            self.categories[category] = list(entries)

        def add_entries(
            self,
            category: str,
            entries: t.MutableSequenceOf[mde.Entry],
        ) -> None:
            key = category
            existing = self.categories.get(key)
            if existing is None:
                existing_entries: list[mde.Entry] = []
                existing = existing_entries
            existing.extend(entries)
            self.categories[key] = existing

        def __contains__(self, category: str) -> bool:
            return category in self.categories

        def items(
            self,
        ) -> Iterator[tuple[str, t.MutableSequenceOf[mde.Entry]]]:
            yield from self.categories.items()

        def keys(self) -> Iterator[str]:
            return iter(self.categories.keys())

        def get(
            self,
            category: str,
            default: t.MutableSequenceOf[mde.Entry] | None = None,
        ) -> t.MutableSequenceOf[mde.Entry]:
            entries = self.categories.get(category)
            if entries is not None:
                return entries
            return default if default is not None else []

        def values(
            self,
        ) -> Iterator[t.MutableSequenceOf[mde.Entry]]:
            yield from self.categories.values()


__all__: list[str] = ["FlextLdifModelsCollections"]
