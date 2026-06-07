"""Direct Entry-model conversion concern for server-to-server translation.

Holds the concrete ``_convert_entry`` (satisfying the AclMixin abstract) plus
the conversion state it owns (``dn_registry``, ``base_dn``). Inherits the
metadata / support / schema mixins it depends on so its cross-concern calls
resolve without fragile abstract-method choreography; the order keeps the
support ``_resolve_schema_server`` ahead of the schema stub.
"""

from __future__ import annotations

from typing import Annotated, override

from flext_ldif import (
    FlextLdifConversionMetadataMixin,
    FlextLdifConversionSchemaMixin,
    FlextLdifConversionSupportMixin,
    c,
    m,
    p,
    r,
    s,
    t,
    u,
)
from flext_ldif.servers._oid.acl_pipeline import FlextLdifServersOidAclPipeline


class FlextLdifConversionEntryMixin(
    FlextLdifConversionMetadataMixin,
    FlextLdifConversionSupportMixin,
    FlextLdifConversionSchemaMixin,
    s,
):
    """Concrete Entry-model conversion + the conversion state it owns."""

    dn_registry: m.Ldif.DnRegistry = u.Field(
        default_factory=m.Ldif.DnRegistry,
        description="DN registry for tracking distinguished names during conversion",
    )
    base_dn: Annotated[
        str | None,
        u.Field(
            default=None,
            description=(
                "Migration base DN; when set, OID→OUD ACL conversion filters "
                "out-of-scope bind DNs and high-level-container anyone rules"
            ),
        ),
    ] = None

    @override
    def _convert_entry(
        self,
        source_server: p.Ldif.ServerServer,
        target_server: p.Ldif.ServerServer,
        entry: m.Ldif.Entry,
    ) -> p.Result[t.Ldif.ConvertedModel]:
        """Convert Entry model directly without serialization."""
        try:
            entry_dn = str(entry.dn) if entry.dn else ""
            valid: bool = u.Ldif.validate_dn(entry_dn)
            if not valid:
                return r[t.Ldif.ConvertedModel].fail(
                    f"Entry DN failed RFC 4514 validation: {entry_dn}",
                )
            _ = self.dn_registry.register_dn(entry_dn)
            converted_entry = entry.model_copy(deep=True)
            target_server_type_raw = target_server.server_type
            if target_server_type_raw != c.IDENTIFIER_UNKNOWN:
                target_server_type_str = u.Ldif.normalize_server_type(
                    target_server_type_raw,
                )
            else:
                target_server_type_str = c.Ldif.ServerTypes.RFC
            validated_server_type = u.Ldif.normalize_server_type(
                str(target_server_type_str),
            )
            metadata_for_analysis: (
                m.Ldif.ServerMetadata | m.Ldif.DynamicMetadata | None
            ) = (
                entry.metadata
                if isinstance(
                    entry.metadata,
                    (m.Ldif.ServerMetadata, m.Ldif.DynamicMetadata),
                )
                else None
            )
            conversion_analysis = self._analyze_metadata_for_conversion(
                metadata_for_analysis,
                validated_server_type,
            )
            source_server_name = source_server.server_type
            source_type_norm = source_server_name.lower()
            target_type_norm = str(target_server_type_str).lower()
            converted_entry = self._update_entry_metadata(
                converted_entry,
                validated_server_type,
                str(conversion_analysis) if conversion_analysis else None,
                source_server_name,
            )
            if source_type_norm != target_type_norm:
                schema_entry_result = self._convert_schema_entry_attributes(
                    source_server,
                    target_server,
                    converted_entry,
                )
                if schema_entry_result.failure:
                    return r[t.Ldif.ConvertedModel].fail(
                        schema_entry_result.error
                        or "Failed to convert schema attributes in entry",
                    )
                converted_entry = schema_entry_result.value
            transformed_attributes = u.Ldif.transform_entry_attributes_between_oid_rfc(
                converted_entry,
                source_type_norm,
                target_type_norm,
            )
            if transformed_attributes is not None:
                converted_entry = converted_entry.model_copy(
                    update={
                        "attributes": m.Ldif.Attributes.model_validate(
                            {
                                "attributes": transformed_attributes,
                                "attribute_metadata": {},
                                "metadata": None,
                            },
                        ),
                    },
                )
            acl_conversion = FlextLdifServersOidAclPipeline.convert_entry_acls(
                converted_entry,
                source_type_norm,
                target_type_norm,
                base_dn=self.base_dn or "",
            )
            if acl_conversion.failure:
                return r[t.Ldif.ConvertedModel].fail(
                    acl_conversion.error or "Failed to convert OID ACLs to OUD aci",
                )
            converted_entry = acl_conversion.value
            transformed_dn = u.Ldif.transform_schema_dn_between_oid_rfc(
                converted_entry,
                source_type_norm,
                target_type_norm,
            )
            if transformed_dn is not None:
                converted_entry = converted_entry.model_copy(
                    update={
                        "dn": m.Ldif.DN(
                            value=transformed_dn,
                            metadata=m.Ldif.EntryMetadata(),
                        ),
                    },
                )
            return r[t.Ldif.ConvertedModel].ok(converted_entry)
        except c.Ldif.EXC_LDIF_PARSE as e:
            self.logger.exception("Failed to convert Entry model", error=str(e))
            return r[t.Ldif.ConvertedModel].fail_op("Entry conversion", e)


__all__: list[str] = ["FlextLdifConversionEntryMixin"]
