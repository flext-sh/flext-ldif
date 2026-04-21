"""Service-layer transformers depending on other services."""

from __future__ import annotations

from typing import Annotated

from flext_ldif import FlextLdifConversion, c, m, r, s, u


class FlextLdifTransformer(s):
    """Transformer for server-specific conversions."""

    source_server: Annotated[
        str | c.Ldif.ServerTypes,
        u.Field(
            exclude=True,
            description="Source server type used for the conversion.",
        ),
    ]
    target_server: Annotated[
        str | c.Ldif.ServerTypes,
        u.Field(
            exclude=True,
            description="Target server type used for the conversion.",
        ),
    ]

    @staticmethod
    def _normalize_server_type(
        server_type: str | c.Ldif.ServerTypes,
    ) -> c.Ldif.ServerTypes:
        """Normalize public string inputs into canonical server enums."""
        if isinstance(server_type, c.Ldif.ServerTypes):
            return server_type
        return c.Ldif.ServerTypes(u.Ldif.normalize_server_type(server_type))

    def apply(self, item: m.Ldif.Entry) -> r[m.Ldif.Entry]:
        """Apply server-specific transformation."""
        source_server = self._normalize_server_type(self.source_server)
        target_server = self._normalize_server_type(self.target_server)

        def ensure_entry(converted: object) -> r[m.Ldif.Entry]:
            if isinstance(converted, m.Ldif.Entry):
                return r[m.Ldif.Entry].ok(converted)
            return r[m.Ldif.Entry].fail(
                f"Conversion returned unexpected type: {type(converted).__name__}",
            )

        return (
            FlextLdifConversion()
            .convert_entry(
                source=source_server.value,
                target=target_server.value,
                model_instance=item,
            )
            .flat_map(ensure_entry)
        )
