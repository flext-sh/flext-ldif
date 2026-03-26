"""FLEXT LDIF Utilities - Reusable helpers for LDIF operations."""

from __future__ import annotations

from collections.abc import Callable, MutableMapping
from enum import Enum
from typing import ClassVar, override

from flext_core import FlextUtilities, r

from flext_ldif import (
    FlextLdifUtilitiesACL,
    FlextLdifUtilitiesAttribute,
    FlextLdifUtilitiesCollectionLdif,
    FlextLdifUtilitiesDecorators,
    FlextLdifUtilitiesDetection,
    FlextLdifUtilitiesDispatch,
    FlextLdifUtilitiesDN,
    FlextLdifUtilitiesEntry,
    FlextLdifUtilitiesEvents,
    FlextLdifUtilitiesMetadata,
    FlextLdifUtilitiesObjectClass,
    FlextLdifUtilitiesOID,
    FlextLdifUtilitiesParser,
    FlextLdifUtilitiesParsers,
    FlextLdifUtilitiesProcessing,
    FlextLdifUtilitiesSchema,
    FlextLdifUtilitiesServer,
    FlextLdifUtilitiesValidation,
    FlextLdifUtilitiesWriter,
    FlextLdifUtilitiesWriters,
    c,
    t,
)


class FlextLdifUtilities(FlextUtilities):
    """FLEXT LDIF Utilities - Centralized helpers for LDIF operations."""

    class Ldif(
        FlextLdifUtilitiesDispatch,
        FlextLdifUtilitiesProcessing,
        FlextLdifUtilitiesCollectionLdif,
        FlextLdifUtilitiesACL,
        FlextLdifUtilitiesAttribute,
        FlextLdifUtilitiesDecorators,
        FlextLdifUtilitiesDetection,
        FlextLdifUtilitiesDN,
        FlextLdifUtilitiesEntry,
        FlextLdifUtilitiesEvents,
        FlextLdifUtilitiesMetadata,
        FlextLdifUtilitiesObjectClass,
        FlextLdifUtilitiesOID,
        FlextLdifUtilitiesParser,
        FlextLdifUtilitiesParsers,
        FlextLdifUtilitiesSchema,
        FlextLdifUtilitiesServer,
        FlextLdifUtilitiesValidation,
        FlextLdifUtilitiesWriter,
        FlextLdifUtilitiesWriters,
    ):
        """LDIF-specific utility namespace."""

        DN = FlextLdifUtilitiesDN
        """Alias for DN utilities — enables u.Ldif.get_dn_value() access pattern."""

        @staticmethod
        @override
        def or_[T: t.NormalizedValue](
            *values: T | None,
            default: T | None = None,
        ) -> T | None:
            """Return first non-None value (resolves MRO conflict)."""
            return FlextLdifUtilitiesCollectionLdif.or_(*values, default=default)

        @staticmethod
        @override
        def parse_attribute(
            attr_definition: str,
            *,
            validate_syntax: bool = True,
        ) -> r[t.MutableContainerMapping]:
            """Route to Schema.parse_attribute (resolves Attribute vs Schema)."""
            return FlextLdifUtilitiesSchema.parse_attribute(
                attr_definition,
                validate_syntax=validate_syntax,
            )

        @staticmethod
        @override
        def parse_objectclass(
            oc_definition: str,
        ) -> t.MutableContainerMapping:
            """Route to Schema.parse_objectclass (resolves ObjectClass vs Schema)."""
            return FlextLdifUtilitiesSchema.parse_objectclass(oc_definition)

        type VariadicCallable[T] = Callable[..., T]

        CATEGORY_MAP: ClassVar[MutableMapping[str, type[Enum]]] = {
            "server_type": c.Ldif.ServerTypes,
            "encoding": c.Ldif.Encoding,
        }

        @classmethod
        def get_valid_values(cls, category: str) -> set[str]:
            """Get valid values for a category."""
            if category not in cls.CATEGORY_MAP:
                msg = f"Unknown category: {category}"
                raise KeyError(msg)
            enum_class = cls.CATEGORY_MAP[category]
            return {e.value for e in enum_class.__members__.values()}

        @classmethod
        def is_valid(cls, value: str, category: str) -> bool:
            """Check if value is valid for a category."""
            if category not in cls.CATEGORY_MAP:
                return False
            valid_values = cls.get_valid_values(category)
            return value.lower() in {v.lower() for v in valid_values}

        @classmethod
        def validate_many(
            cls,
            values: set[str],
            category: str,
        ) -> tuple[bool, set[str]]:
            """Validate multiple values for a category."""
            if category not in cls.CATEGORY_MAP:
                msg = f"Unknown category: {category}"
                raise KeyError(msg)
            valid_values = cls.get_valid_values(category)
            valid_lower = {v.lower() for v in valid_values}
            invalid = {v for v in values if v.lower() not in valid_lower}
            return (not invalid, invalid)

        TWO_ARG_THRESHOLD: int = 2
        """Minimum parameter count for 2-argument functions."""

        # Methods inherited via MRO from mixin classes (no explicit overrides needed)


u = FlextLdifUtilities

__all__ = ["FlextLdifUtilities", "u"]
