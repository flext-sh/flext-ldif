"""Service-layer transformers depending on other services."""

from __future__ import annotations

from typing import override

from flext_core import r

from flext_ldif._utilities.transformers import FlextLdifUtilitiesTransformer
from flext_ldif.constants import FlextLdifConstants as c
from flext_ldif.models import FlextLdifModels as m
from flext_ldif.services.conversion import FlextLdifConversion


class ServerTransformer(FlextLdifUtilitiesTransformer[m.Ldif.Entry]):
    """Transformer for server-specific conversions."""

    __slots__ = ("_source_server", "_target_server")

    def __init__(
        self,
        source_server: c.Ldif.ServerTypes,
        target_server: c.Ldif.ServerTypes,
    ) -> None:
        """Initialize server transformer."""
        super().__init__()
        self._source_server = source_server
        self._target_server = target_server

    @override
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
        match converted:
            case m.Ldif.Entry() as converted_entry:
                return r[m.Ldif.Entry].ok(converted_entry)
            case _:
                return r[m.Ldif.Entry].fail(
                    f"Conversion returned unexpected type: {type(converted).__name__}",
                )
