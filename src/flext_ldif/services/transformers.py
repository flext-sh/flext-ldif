"""Service-layer transformers depending on other services."""

from __future__ import annotations

from flext_ldif import FlextLdifConversion, c, m, r, s


class FlextLdifTransformer(s[m.Ldif.Entry]):
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

    def apply(self, item: m.Ldif.Entry) -> r[m.Ldif.Entry]:
        """Apply server-specific transformation."""

        def ensure_entry(converted: object) -> r[m.Ldif.Entry]:
            if isinstance(converted, m.Ldif.Entry):
                return r[m.Ldif.Entry].ok(converted)
            return r[m.Ldif.Entry].fail(
                f"Conversion returned unexpected type: {type(converted).__name__}",
            )

        return (
            FlextLdifConversion()
            .convert_entry(
                source=self._source_server.value,
                target=self._target_server.value,
                model_instance=item,
            )
            .flat_map(ensure_entry)
        )
