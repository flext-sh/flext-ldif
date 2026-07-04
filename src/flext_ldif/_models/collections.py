"""Collection and utility models for LDIF processing.

from flext_ldif.models import m
from flext_ldif.utilities import u
Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import MutableMapping
from typing import TYPE_CHECKING, Annotated, ClassVar

from flext_core import m
from flext_core.utilities import FlextUtilities as u
from flext_ldif import t
from flext_ldif._models.domain_entries import FlextLdifModelsDomainsEntries as mde

if TYPE_CHECKING:
    from collections.abc import (
        Iterator,
    )


class FlextLdifModelsCollections:
    class DynamicCounts(m.DynamicModel):
        model_config: ClassVar[m.ConfigDict] = m.ConfigDict(
            extra="allow",
            validate_assignment=True,
        )

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
        def _to_count(value: t.JsonPayload | None) -> int:
            if isinstance(value, bool):
                return 0
            count_value: int = u.to_int(value, default=0)
            return count_value

        def get(self, key: str, default: int | None = None) -> int | None:
            extra = self._extra()
            if key in extra:
                return self._to_count(extra[key])
            fallback_count: int | None = default
            return fallback_count

        def items(self) -> t.MutableSequenceOf[tuple[str, int]]:
            extra = self._extra()
            return [(k, self._to_count(v)) for k, v in extra.items()]

        def update_count(self, key: str, value: int) -> None:
            setattr(self, key, value)

        def _extra(self) -> t.MutableJsonMapping:
            extra = self.__pydantic_extra__
            if extra is None:
                return {}
            data: t.MutableJsonMapping = t.json_dict_adapter().validate_python(extra)
            return data

    class SchemaContent(m.FrozenModel):
        attributes: Annotated[
            t.MutableSequenceOf[mde.SchemaAttribute],
            u.Field(description="Schema attribute definitions extracted from LDIF"),
        ]
        object_classes: Annotated[
            t.MutableSequenceOf[mde.SchemaObjectClass],
            u.Field(description="Schema object class definitions extracted from LDIF"),
        ]

    class FlexibleCategories(m.DynamicModel):
        categories: Annotated[
            MutableMapping[str, t.MutableSequenceOf[mde.Entry]],
            u.Field(description="Category name to grouped LDIF entries mapping."),
        ] = u.Field(default_factory=dict)

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
