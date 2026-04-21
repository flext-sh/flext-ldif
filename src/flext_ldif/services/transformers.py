"""Service-layer transformers depending on other services."""

from __future__ import annotations

from typing import Annotated

from flext_ldif import FlextLdifConversion, c, m, r, s, u


class FlextLdifTransformer(s):
    """Transformer for server-specific conversions."""

    source_server: Annotated[
        c.Ldif.ServerTypes,
        u.Field(
            exclude=True,
            description="Source server type used for the conversion.",
        ),
    ]
    target_server: Annotated[
        c.Ldif.ServerTypes,
        u.Field(
            exclude=True,
            description="Target server type used for the conversion.",
        ),
    ]

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
                source=self.source_server.value,
                target=self.target_server.value,
                model_instance=item,
            )
            .flat_map(ensure_entry)
        )
