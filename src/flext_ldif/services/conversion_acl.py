"""ACL-specific conversion helpers for server-to-server translation."""

from __future__ import annotations

import struct
from abc import ABC, abstractmethod

from flext_ldif import c, m, p, r, t, u

logger = u.fetch_logger(__name__)


class FlextLdifConversionAclMixin(ABC):
    """ACL-specific conversion helpers shared by the conversion facade."""

    @abstractmethod
    def _convert_entry(
        self,
        source_server: p.Ldif.ServerServer,
        target_server: p.Ldif.ServerServer,
        entry: m.Ldif.Entry,
    ) -> r[t.Ldif.ConvertedModel]:
        """Convert an entry through the concrete conversion facade."""

    def _convert_acl(
        self,
        source_server: p.Ldif.ServerServer,
        target_server: p.Ldif.ServerServer,
        acl: m.Ldif.Acl,
    ) -> r[t.Ldif.ConvertedModel]:
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
            source_server_type: str | None = u.try_(
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
            target_server_type: str | None = u.try_(
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
            converted_acl_result = r[m.Ldif.Acl].fail(
                "Converted entry has no ACLs in metadata.acls",
            )
            if converted_entry_result.failure:
                converted_acl_result = r[m.Ldif.Acl].fail(
                    converted_entry_result.error or "Acl conversion returned no entry",
                )
            else:
                converted_entry = converted_entry_result.value
                if not isinstance(converted_entry, m.Ldif.Entry):
                    converted_acl_result = r[m.Ldif.Acl].fail(
                        "Entry conversion returned unexpected type: "
                        f"{type(converted_entry).__name__}",
                    )
                elif (
                    converted_entry.metadata is None
                    or not converted_entry.metadata.acls
                ):
                    converted_acl_result = r[m.Ldif.Acl].fail(
                        "Converted entry has no ACLs in metadata.acls",
                    )
                else:
                    converted_acl_result = (
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
            return converted_acl_result.flat_map(
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
        except (
            ValueError,
            KeyError,
            AttributeError,
            UnicodeDecodeError,
            struct.error,
        ) as e:
            logger.exception("Failed to convert ACL model", error=str(e))
            return r[t.Ldif.ConvertedModel].fail_op("Acl conversion", e)

    def _get_extensions_dict(
        self,
        acl: m.Ldif.Acl,
    ) -> t.Ldif.MutableMetadataInputMapping:
        """Extract extensions dict from ACL metadata."""

        def to_general_value(
            value: t.JsonPayload | None,
        ) -> t.JsonValue:
            normalized_local: t.JsonValue = u.normalize_to_json_value(
                value if value is not None else "",
            )
            return normalized_local

        metadata = acl.metadata
        if metadata is None or not metadata:
            return {}
        return {
            key: to_general_value(value)
            for key, value in metadata.extensions.to_dict().items()
        }

    def _preserve_acl_metadata(
        self,
        original_acl: m.Ldif.Acl,
        converted_acl: m.Ldif.Acl,
        source_server_type: str | None = None,
        target_server_type: str | None = None,
    ) -> m.Ldif.Acl:
        """Preserve permissions and metadata from original ACL."""
        converted_permissions = converted_acl.permissions
        converted_has_permissions = converted_permissions is not None and any(
            (
                converted_permissions.read,
                converted_permissions.write,
                converted_permissions.add,
                converted_permissions.delete,
                converted_permissions.search,
                converted_permissions.compare,
                converted_permissions.self_write,
                converted_permissions.proxy,
                converted_permissions.browse,
                converted_permissions.auth,
                converted_permissions.all,
            ),
        )
        original_permissions = original_acl.permissions
        orig_perms_dict: t.MutableBoolMapping = (
            original_permissions.model_dump(
                exclude_defaults=True,
                exclude_unset=True,
            )
            if original_permissions
            else {}
        )
        if orig_perms_dict:
            logger.debug(
                "ACL permission preservation",
                source_server_type=source_server_type or "",
                target_server_type=target_server_type or "",
                original_permissions=str(orig_perms_dict),
            )
            permission_settings = m.Ldif.PermissionMappingConfig.model_validate({
                "original_acl": original_acl,
                "converted_acl": converted_acl,
                "orig_perms_dict": orig_perms_dict,
                "source_server_type": source_server_type,
                "target_server_type": target_server_type,
                "converted_has_permissions": converted_has_permissions,
            })
            normalized_source = u.try_(
                lambda: u.Ldif.normalize_server_type(
                    permission_settings.source_server_type or c.IDENTIFIER_UNKNOWN,
                ),
            ).map_or(None)
            normalized_target = u.try_(
                lambda: u.Ldif.normalize_server_type(
                    permission_settings.target_server_type or c.IDENTIFIER_UNKNOWN,
                ),
            ).map_or(None)
            server_pair = (
                (normalized_source, normalized_target)
                if normalized_source is not None and normalized_target is not None
                else None
            )
            permission_mapping = {
                None: None,
                (
                    c.Ldif.ServerTypes.OID,
                    c.Ldif.ServerTypes.OUD,
                ): ("oid_to_oud", u.Ldif.map_oid_to_oud_permissions),
                (
                    c.Ldif.ServerTypes.OUD,
                    c.Ldif.ServerTypes.OID,
                ): ("oud_to_oid", u.Ldif.map_oud_to_oid_permissions),
            }.get(server_pair)
            mapping_type = "none"
            replacement_permissions: m.Ldif.AclPermissions | None = None
            match permission_mapping:
                case (mapping_type, permission_mapper):
                    mapped_perms = permission_mapper(
                        permission_settings.orig_perms_dict,
                    )
                    normalized_perms = u.Ldif.build_mapped_permissions_dict(
                        mapped_perms,
                        {
                            key: u.Ldif.normalize_permission_key(key)
                            for key in c.Ldif.ACL_PERMISSION_KEYS
                        },
                    )
                    clean_permissions: t.MutableBoolMapping = {
                        key: value
                        for key, value in normalized_perms.items()
                        if value is not None
                    }
                    replacement_permissions = m.Ldif.AclPermissions.model_validate(
                        clean_permissions,
                    )
                case None if (
                    not permission_settings.converted_has_permissions
                    and original_permissions is not None
                ):
                    mapping_type = "preserve_original"
                    replacement_permissions = original_permissions.model_copy(
                        deep=True,
                    )
                case None:
                    mapping_type = "none"
                    replacement_permissions = None
            resolved_permissions = (
                permission_settings.converted_acl.permissions
                if replacement_permissions is None
                else replacement_permissions
            )
            converted_acl = permission_settings.converted_acl.model_copy(
                update={"permissions": resolved_permissions},
                deep=True,
            )
            logger.debug(
                "ACL t.MappingKV decision",
                mapping_type=mapping_type,
                normalized_source=str(normalized_source),
                normalized_target=str(normalized_target),
            )
        acl_step1 = (
            converted_acl.model_copy(
                update={"metadata": original_acl.metadata.model_copy(deep=True)},
                deep=True,
            )
            if original_acl.metadata and not converted_acl.metadata
            else converted_acl
        )
        original_extensions = self._get_extensions_dict(original_acl)
        if acl_step1.metadata is None:
            return acl_step1
        merged_ext_raw = {
            **original_extensions,
            **self._get_extensions_dict(acl_step1),
        }
        updated_metadata = acl_step1.metadata.model_copy(
            update={"extensions": m.Ldif.DynamicMetadata.from_dict(merged_ext_raw)},
            deep=True,
        )
        return acl_step1.model_copy(
            update={"metadata": updated_metadata},
            deep=True,
        )


__all__: list[str] = ["FlextLdifConversionAclMixin"]
