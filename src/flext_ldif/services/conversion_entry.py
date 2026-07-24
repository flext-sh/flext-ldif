"""Direct Entry-model conversion concern for server-to-server translation.

Holds the concrete ``_convert_entry`` (satisfying the AclMixin abstract) plus
the conversion state it owns (``dn_registry``, ``base_dn``). Inherits the
metadata / support / schema mixins it depends on so its cross-concern calls
resolve without fragile abstract-method choreography; the order keeps the
support ``_resolve_schema_server`` ahead of the schema stub.
"""

from __future__ import annotations

from typing import Annotated, override

from flext_ldif import c, m, p, r, s, t, u
from flext_ldif.servers._oid.acl_pipeline import FlextLdifServersOidAclPipeline
from flext_ldif.services.conversion_metadata import FlextLdifConversionMetadataMixin
from flext_ldif.services.conversion_schema_entry import (
    FlextLdifConversionSchemaEntryMixin,
)
from flext_ldif.services.conversion_support import FlextLdifConversionSupportMixin


class FlextLdifConversionEntryMixin(
    FlextLdifConversionMetadataMixin,
    FlextLdifConversionSupportMixin,
    FlextLdifConversionSchemaEntryMixin,
    s,
):
    """Concrete Entry-model conversion + the conversion state it owns."""

    dn_registry: p.Ldif.DnRegistry = u.Field(
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
        entry: p.Ldif.Entry,
    ) -> p.Result[t.Ldif.ConvertedModel]:
        """Convert Entry model directly without serialization."""
        try:
            return self._convert_entry_core(source_server, target_server, entry)
        except c.Ldif.EXC_LDIF_PARSE as e:
            self.logger.exception("Failed to convert Entry model", error=str(e))
            return r[t.Ldif.ConvertedModel].fail_op("Entry conversion", e)

    def _convert_entry_core(
        self,
        source_server: p.Ldif.ServerServer,
        target_server: p.Ldif.ServerServer,
        entry: p.Ldif.Entry,
    ) -> p.Result[t.Ldif.ConvertedModel]:
        """Convert an entry model between server dialects."""
        entry_dn = str(entry.dn) if entry.dn else ""
        valid: bool = u.Ldif.validate_dn(entry_dn)
        if not valid:
            return r[t.Ldif.ConvertedModel].fail(
                f"Entry DN failed RFC 4514 validation: {entry_dn}"
            )
        _ = self.dn_registry.register_dn(entry_dn)
        target_server_type = self._resolve_target_server_type(target_server)
        validated_server_type = u.Ldif.normalize_server_type(str(target_server_type))
        source_server_name = source_server.server_type
        source_type_norm = source_server_name.lower()
        target_type_norm = str(target_server_type).lower()
        converted_entry = self._prepare_converted_entry(
            entry, validated_server_type, source_server_name
        )
        if source_type_norm != target_type_norm:
            schema_entry_result = self._convert_schema_entry_attributes(
                source_server, target_server, converted_entry
            )
            if schema_entry_result.failure:
                return r[t.Ldif.ConvertedModel].fail(
                    schema_entry_result.error
                    or "Failed to convert schema attributes in entry"
                )
            converted_entry = schema_entry_result.value
        return self._convert_entry_payload(
            converted_entry, source_type_norm, target_type_norm
        )

    @staticmethod
    def _resolve_target_server_type(
        target_server: p.Ldif.ServerServer,
    ) -> c.Ldif.ServerTypes:
        """Resolve the target server type for entry conversion."""
        if target_server.server_type != c.IDENTIFIER_UNKNOWN:
            return c.Ldif.ServerTypes(
                u.Ldif.normalize_server_type(target_server.server_type)
            )
        return c.Ldif.ServerTypes.RFC

    def _prepare_converted_entry(
        self,
        entry: p.Ldif.Entry,
        validated_server_type: c.Ldif.ServerTypes,
        source_server_name: str,
    ) -> p.Ldif.Entry:
        """Copy entry and attach conversion metadata."""
        metadata_for_analysis: p.Ldif.ServerMetadata | t.MutableJsonMapping | None = (
            entry.metadata
            if isinstance(entry.metadata, (m.Ldif.ServerMetadata, dict))
            else None
        )
        conversion_analysis = self._analyze_metadata_for_conversion(
            metadata_for_analysis, validated_server_type
        )
        updated_entry: p.Ldif.Entry = self._update_entry_metadata(
            entry.model_copy(deep=True),
            validated_server_type,
            str(conversion_analysis) if conversion_analysis else None,
            source_server_name,
        )
        return updated_entry

    def _convert_entry_payload(
        self,
        converted_entry: p.Ldif.Entry,
        source_type_norm: str,
        target_type_norm: str,
    ) -> p.Result[t.Ldif.ConvertedModel]:
        """Transform entry attributes, ACLs, and schema DN."""
        transformed_attributes = u.Ldif.transform_entry_attributes_between_oid_rfc(
            converted_entry, source_type_norm, target_type_norm
        )
        if transformed_attributes is not None:
            converted_entry = converted_entry.model_copy(
                update={
                    "attributes": m.Ldif.Attributes.model_validate({
                        "attributes": transformed_attributes,
                        "attribute_metadata": {},
                        "metadata": None,
                    })
                }
            )
        acl_conversion = FlextLdifServersOidAclPipeline.convert_entry_acls(
            converted_entry,
            source_type_norm,
            target_type_norm,
            base_dn=self.base_dn or "",
        )
        if acl_conversion.failure:
            return r[t.Ldif.ConvertedModel].fail(
                acl_conversion.error or "Failed to convert OID ACLs to OUD aci"
            )
        converted_entry = self._transform_entry_dn(
            acl_conversion.value, source_type_norm, target_type_norm
        )
        return r[t.Ldif.ConvertedModel].ok(converted_entry)

    @staticmethod
    def _transform_entry_dn(
        converted_entry: p.Ldif.Entry, source_type_norm: str, target_type_norm: str
    ) -> p.Ldif.Entry:
        """Transform schema DN when moving between OID and RFC dialects."""
        transformed_dn = u.Ldif.transform_schema_dn_between_oid_rfc(
            converted_entry, source_type_norm, target_type_norm
        )
        if transformed_dn is None:
            return converted_entry
        updated_entry: p.Ldif.Entry = converted_entry.model_copy(
            update={"dn": m.Ldif.DN(value=transformed_dn, metadata={})}
        )
        return updated_entry


__all__: list[str] = ["FlextLdifConversionEntryMixin"]
