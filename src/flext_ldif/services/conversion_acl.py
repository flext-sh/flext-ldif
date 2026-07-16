"""ACL-specific conversion helpers for server-to-server translation."""

from __future__ import annotations

from abc import ABC, abstractmethod

from flext_ldif import FlextLdifModels, c, m, p, r, s, t, u
from flext_ldif.services.conversion_acl_preserve import (
    FlextLdifConversionAclPreserveMixin,
)

_LdifEntry = FlextLdifModels.Ldif.Entry
_LdifDN = FlextLdifModels.Ldif.DN
_LdifAttributes = FlextLdifModels.Ldif.Attributes


class FlextLdifConversionAclMixin(FlextLdifConversionAclPreserveMixin, s, ABC):
    """ACL-model conversion orchestration (preservation via the parent mixin)."""

    @abstractmethod
    def _convert_entry(
        self,
        source_server: p.Ldif.ServerServer,
        target_server: p.Ldif.ServerServer,
        entry: p.Ldif.Entry,
    ) -> p.Result[t.Ldif.ConvertedModel]:
        """Convert an entry through the concrete conversion facade."""

    def _convert_acl(
        self,
        source_server: p.Ldif.ServerServer,
        target_server: p.Ldif.ServerServer,
        acl: m.Ldif.Acl,
    ) -> p.Result[t.Ldif.ConvertedModel]:
        """Convert Acl model via Entry RFC + Metadata pipeline."""
        try:
            return self._convert_acl_core(source_server, target_server, acl)
        except c.Ldif.EXC_LDIF_PARSE as e:
            self.logger.exception("Failed to convert ACL model", error=str(e))
            return r[t.Ldif.ConvertedModel].fail_op("Acl conversion", e)

    def _convert_acl_core(
        self,
        source_server: p.Ldif.ServerServer,
        target_server: p.Ldif.ServerServer,
        acl: m.Ldif.Acl,
    ) -> p.Result[t.Ldif.ConvertedModel]:
        """Convert ACL model through an RFC entry bridge."""
        source_acl = acl.model_copy(deep=True)
        source_server_type: c.Ldif.ServerTypes | None = u.try_(
            lambda: (
                u.Ldif.normalize_server_type(source_server.server_type)
                if source_server.server_type
                else None
            ),
        ).map_or(None)
        rfc_entry = self._build_acl_conversion_entry(source_acl, source_server_type)
        target_server_type: c.Ldif.ServerTypes | None = u.try_(
            lambda: (
                u.Ldif.normalize_server_type(target_server.server_type)
                if target_server.server_type != c.IDENTIFIER_UNKNOWN
                else None
            ),
        ).map_or(None)
        return (
            self
            ._convert_entry(source_server, target_server, rfc_entry)
            .map_error(lambda error: error or "Acl conversion returned no entry")
            .flat_map(
                lambda converted_entry: self._entry_to_acl(
                    target_server,
                    converted_entry,
                ),
            )
            .flat_map(
                lambda converted_acl: r[t.Ldif.ConvertedModel].ok(
                    self._preserve_acl_metadata(
                        source_acl,
                        converted_acl,
                        source_server_type=source_server_type,
                        target_server_type=target_server_type,
                    ).model_copy(
                        update={"server_type": target_server_type},
                        deep=True,
                    ),
                ),
            )
        )

    @staticmethod
    def _build_acl_conversion_entry(
        acl: m.Ldif.Acl,
        source_server_type: c.Ldif.ServerTypes | None,
    ) -> p.Ldif.Entry:
        """Build the RFC entry carrier used for ACL conversion."""
        entry_metadata = u.Ldif.server_metadata_for(source_server_type)
        entry_metadata.acls = [acl.raw_acl] if acl.raw_acl else list[str]()
        entry_result = _LdifEntry.create(
            dn=_LdifDN(
                value="cn=acl-conversion,dc=example,dc=com",
                metadata={},
            ),
            attributes=_LdifAttributes(
                attributes={},
                attribute_metadata={},
                metadata=None,
            ),
            metadata=entry_metadata,
        )
        entry: p.Ldif.Entry = entry_result.unwrap()
        return entry

    @staticmethod
    def _entry_to_acl(
        target_server: p.Ldif.ServerServer,
        converted_entry: t.Ldif.ConvertedModel,
    ) -> p.Result[p.Ldif.Acl]:
        """Extract and parse the converted ACL from an entry carrier."""
        if not isinstance(converted_entry, m.Ldif.Entry):
            return r[p.Ldif.Acl].fail(
                "Entry conversion returned unexpected type: "
                f"{type(converted_entry).__name__}",
            )
        if converted_entry.metadata is None or not converted_entry.metadata.acls:
            return r[p.Ldif.Acl].fail(
                "Converted entry has no ACLs in metadata.acls",
            )
        return (
            r[p.Ldif.Acl]
            .from_result(
                target_server.acl_server.parse_server(
                    converted_entry.metadata.acls[0],
                ),
            )
            .flat_map(
                lambda parsed_acl: r[p.Ldif.Acl].ok(parsed_acl),
            )
        )


__all__: list[str] = ["FlextLdifConversionAclMixin"]
