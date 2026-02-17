"""Service-layer transformers depending on other services."""

from __future__ import annotations

from flext_core import r

from flext_ldif._utilities.transformers import EntryTransformer
from flext_ldif.constants import c
from flext_ldif.models import m
from flext_ldif.services.conversion import FlextLdifConversion


class ServerTransformer(EntryTransformer[m.Ldif.Entry]):
    """Transformer for server-specific conversions."""

    __slots__ = ("_source_server", "_target_server")

    def __init__(
        self,
        source_server: c.Ldif.ServerTypes,
        target_server: c.Ldif.ServerTypes,
    ) -> None:
        """Initialize server transformer."""
        self._source_server = source_server
        self._target_server = target_server

    def apply(self, item: m.Ldif.Entry) -> r[m.Ldif.Entry]:
        """Apply server-specific transformation."""
        service = FlextLdifConversion()
        result = service.convert(
            source=self._source_server.value,
            target=self._target_server.value,
            model_instance=item,
        )

        if result.is_failure:
            return r[m.Ldif.Entry].fail(result.error)

        converted = result.value
        if isinstance(converted, m.Ldif.Entry):
            return r[m.Ldif.Entry].ok(converted)

        return r[m.Ldif.Entry].fail(
            f"Conversion returned unexpected type: {type(converted).__name__}"
        )
