"""Collection and utility models for LDIF processing.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import (
    ItemsView,
    Iterator,
    KeysView,
    MutableMapping,
    MutableSequence,
    ValuesView,
)
from typing import Annotated, ClassVar

from flext_cli import m

from flext_ldif import t
from flext_ldif._models import FlextLdifModelsDomainsEntries


class FlextLdifModelsCollections:
    class DynamicCounts(m.RootModel[t.IntMapping]):
        """Strict integer counts exposed through native mapping views."""

        model_config: ClassVar[m.ConfigDict] = m.ConfigDict(
            strict=True,
            frozen=True,
        )
        root: t.IntMapping = m.Field(default_factory=dict)

        def __getitem__(self, key: str) -> int:
            return self.root[key]

        def __len__(self) -> int:
            return len(self.root)

        def __contains__(self, key: str) -> bool:
            return key in self.root

        def get(self, key: str, default: int | None = None) -> int | None:
            return self.root.get(key, default)

        def keys(self) -> KeysView[str]:
            return self.root.keys()

        def values(self) -> ValuesView[int]:
            return self.root.values()

        def items(self) -> ItemsView[str, int]:
            return self.root.items()

    class SchemaContent(m.FrozenModel):
        attributes: Annotated[
            MutableSequence[FlextLdifModelsDomainsEntries.SchemaAttribute],
            m.Field(description="Schema attribute definitions extracted from LDIF"),
        ]
        object_classes: Annotated[
            MutableSequence[FlextLdifModelsDomainsEntries.SchemaObjectClass],
            m.Field(description="Schema object class definitions extracted from LDIF"),
        ]

    class FlexibleCategories(m.DynamicModel):
        categories: Annotated[
            MutableMapping[str, MutableSequence[FlextLdifModelsDomainsEntries.Entry]],
            m.Field(description="Category name to grouped LDIF entries mapping."),
        ] = m.Field(
            default_factory=dict[
                str, MutableSequence[FlextLdifModelsDomainsEntries.Entry]
            ]
        )

        def __hash__(self) -> int:
            msg = f"{self.__class__.__name__} is unhashable"
            raise TypeError(msg)

        def __getitem__(
            self, category: str
        ) -> MutableSequence[FlextLdifModelsDomainsEntries.Entry]:
            key = category
            if key not in self.categories:
                self.categories[key] = []
            return self.categories[key]

        def __setitem__(
            self,
            category: str,
            entries: MutableSequence[FlextLdifModelsDomainsEntries.Entry],
        ) -> None:
            self.categories[category] = list(entries)

        def add_entries(
            self,
            category: str,
            entries: MutableSequence[FlextLdifModelsDomainsEntries.Entry],
        ) -> None:
            key = category
            existing = self.categories.get(key)
            if existing is None:
                existing_entries: list[FlextLdifModelsDomainsEntries.Entry] = []
                existing = existing_entries
            existing.extend(entries)
            self.categories[key] = existing

        def __contains__(self, category: str) -> bool:
            return category in self.categories

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
            entries = self.categories.get(category)
            if entries is not None:
                return entries
            return default if default is not None else []

        def values(
            self,
        ) -> Iterator[MutableSequence[FlextLdifModelsDomainsEntries.Entry]]:
            yield from self.categories.values()


__all__: list[str] = ["FlextLdifModelsCollections"]
