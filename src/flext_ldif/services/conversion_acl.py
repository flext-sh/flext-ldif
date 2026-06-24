"""ACL-specific conversion helpers for server-to-server translation."""

from __future__ import annotations

from abc import abstractmethod

from flext_ldif import (
    FlextLdifConversionAclPreserveMixin,
    c,
    m,
    p,
    r,
    s,
    t,
    u,
)


class FlextLdifConversionAclMixin(FlextLdifConversionAclPreserveMixin, s):
    """ACL-model conversion orchestration (preservation via the parent mixin)."""

    @abstractmethod
    def _convert_entry(
        self,
        source_server: p.Ldif.ServerServer,
        target_server: p.Ldif.ServerServer,
        entry: m.Ldif.Entry,
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
            acl = acl.model_copy(deep=True)
            entry_dn = m.Ldif.DN(
                value="cn=acl-conversion,dc=example,dc=com",
                metadata=m.Ldif.EntryMetadata(),
            )
            entry_attributes = m.Ldif.Attributes(
                attributes={},
                attribute_metadata={},
                metadata=None,
            )
            source_server_type: c.Ldif.ServerTypes | None = u.try_(
                lambda: (
                    u.Ldif.normalize_server_type(source_server.server_type)
                    if source_server.server_type
                    else None
                ),
            ).map_or(None)
            entry_metadata = m.Ldif.ServerMetadata.create_for(
                source_server_type,
                extensions=None,
            )
            entry_metadata.acls = [acl.raw_acl] if acl.raw_acl else list[str]()
            rfc_entry = m.Ldif.Entry.create(
                dn=entry_dn,
                attributes=entry_attributes,
                metadata=entry_metadata,
            ).unwrap()
            target_server_type: c.Ldif.ServerTypes | None = u.try_(
                lambda: (
                    u.Ldif.normalize_server_type(target_server.server_type)
                    if target_server.server_type != c.IDENTIFIER_UNKNOWN
                    else None
                ),
            ).map_or(None)
            converted_entry_result = self._convert_entry(
                source_server,
                target_server,
                rfc_entry,
            )

            def _entry_to_acl(
                converted_entry: t.Ldif.ConvertedModel,
            ) -> p.Result[m.Ldif.Acl]:
                if not isinstance(converted_entry, m.Ldif.Entry):
                    return r[m.Ldif.Acl].fail(
                        "Entry conversion returned unexpected type: "
                        f"{type(converted_entry).__name__}",
                    )
                if (
                    converted_entry.metadata is None
                    or not converted_entry.metadata.acls
                ):
                    return r[m.Ldif.Acl].fail(
                        "Converted entry has no ACLs in metadata.acls",
                    )
                return (
                    r[m.Ldif.Acl]
                    .from_result(
                        target_server.acl_server.parse_server(
                            converted_entry.metadata.acls[0],
                        ),
                    )
                    .flat_map(
                        lambda parsed_acl: (
                            r[m.Ldif.Acl].ok(parsed_acl)
                            if isinstance(parsed_acl, m.Ldif.Acl)
                            else r[m.Ldif.Acl].fail(
                                "ACL conversion returned unexpected parsed type: "
                                f"{type(parsed_acl).__name__}",
                            )
                        ),
                    )
                )

            return (
                converted_entry_result
                .map_error(
                    lambda error: error or "Acl conversion returned no entry",
                )
                .flat_map(_entry_to_acl)
                .flat_map(
                    lambda converted_acl: r[t.Ldif.ConvertedModel].ok(
                        self._preserve_acl_metadata(
                            acl,
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
        except c.Ldif.EXC_LDIF_PARSE as e:
            self.logger.exception("Failed to convert ACL model", error=str(e))
            return r[t.Ldif.ConvertedModel].fail_op("Acl conversion", e)


__all__: list[str] = ["FlextLdifConversionAclMixin"]
