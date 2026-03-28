"""FLEXT LDIF Utilities - Reusable helpers for LDIF operations."""

from __future__ import annotations

from typing import override

from flext_core import FlextUtilities, r

from flext_ldif import (
    FlextLdifUtilitiesACL,
    FlextLdifUtilitiesAttribute,
    FlextLdifUtilitiesCollectionLdif,
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
    FlextLdifUtilitiesPipeline,
    FlextLdifUtilitiesSchema,
    FlextLdifUtilitiesServer,
    FlextLdifUtilitiesTransformers,
    FlextLdifUtilitiesValidation,
    FlextLdifUtilitiesWriter,
    FlextLdifUtilitiesWriters,
    t,
)


class FlextLdifUtilities(FlextUtilities):
    """FLEXT LDIF Utilities - Centralized helpers for LDIF operations."""

    class Ldif(
        FlextLdifUtilitiesDispatch,
        FlextLdifUtilitiesCollectionLdif,
        FlextLdifUtilitiesACL,
        FlextLdifUtilitiesAttribute,
        FlextLdifUtilitiesDetection,
        FlextLdifUtilitiesDN,
        FlextLdifUtilitiesEntry,
        FlextLdifUtilitiesEvents,
        FlextLdifUtilitiesMetadata,
        FlextLdifUtilitiesObjectClass,
        FlextLdifUtilitiesOID,
        FlextLdifUtilitiesParser,
        FlextLdifUtilitiesParsers,
        FlextLdifUtilitiesPipeline,
        FlextLdifUtilitiesSchema,
        FlextLdifUtilitiesServer,
        FlextLdifUtilitiesTransformers,
        FlextLdifUtilitiesValidation,
        FlextLdifUtilitiesWriter,
        FlextLdifUtilitiesWriters,
    ):
        """LDIF-specific utility namespace."""

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

        # Methods inherited via MRO from mixin classes (no explicit overrides needed)


u = FlextLdifUtilities

__all__ = ["FlextLdifUtilities", "u"]
