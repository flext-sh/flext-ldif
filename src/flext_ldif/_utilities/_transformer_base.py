"""Base LDIF entry transformer contract.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import ClassVar

from flext_core import r
from flext_ldif import p, t


class FlextLdifUtilitiesTransformer[T]:
    """Base class for entry transformers."""

    __slots__: ClassVar[t.StrSequence] = ()

    def apply(self, item: T) -> p.Result[T]:
        """Apply the transformation to an item."""
        raise NotImplementedError

    def apply_batch(self, items: t.MutableSequenceOf[T]) -> p.Result[t.SequenceOf[T]]:
        """Apply transformation to a batch of items.

        Returns:
            The resulting ``p.Result[t.SequenceOf[T]]``.
        """
        return r[T].traverse(items, self.apply)


__all__: list[str] = ["FlextLdifUtilitiesTransformer"]
