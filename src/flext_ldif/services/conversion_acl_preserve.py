"""ACL preservation concern — keep original ACL permissions + metadata.

Holds ``_preserve_acl_metadata`` (permission remap by server pair + extension
merge) and ``_get_extensions_dict``, the preservation half of ACL conversion;
``FlextLdifConversionAclMixin`` inherits it. Self-contained (only ``self.logger``).
"""

from __future__ import annotations

from flext_ldif import c, m, s, t, u


class FlextLdifConversionAclPreserveMixin(s):
    """ACL permission + metadata preservation helpers."""

    def _get_extensions_dict(
        self, acl: m.Ldif.Acl
    ) -> t.Ldif.MutableMetadataInputMapping:
        """Extract extensions dict from ACL metadata."""

        def to_general_value(value: t.JsonPayload | None) -> t.JsonValue:
            normalized_local: t.JsonValue = u.normalize_to_json_value(
                value if value is not None else ""
            )
            return normalized_local

        metadata = acl.metadata
        if metadata is None or not metadata:
            return {}
        # mro-wgwh.5 (agent: kimi-coder) — extensions is a plain mapping now.
        return {
            key: to_general_value(value) for key, value in metadata.extensions.items()
        }

    def _preserve_acl_metadata(
        self,
        original_acl: m.Ldif.Acl,
        converted_acl: m.Ldif.Acl,
        source_server_type: c.Ldif.ServerTypes | None = None,
        target_server_type: c.Ldif.ServerTypes | None = None,
    ) -> m.Ldif.Acl:
        """Preserve permissions and metadata from original ACL."""
        converted_permissions = converted_acl.permissions
        converted_has_permissions = converted_permissions is not None and any((
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
        ))
        original_permissions = original_acl.permissions
        orig_perms_dict: t.MutableBoolMapping = (
            original_permissions.model_dump(exclude_defaults=True, exclude_unset=True)
            if original_permissions
            else {}
        )
        if orig_perms_dict:
            self.logger.debug(
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
            server_pair = (
                (
                    permission_settings.source_server_type,
                    permission_settings.target_server_type,
                )
                if permission_settings.source_server_type is not None
                and permission_settings.target_server_type is not None
                else None
            )
            permission_mapping = {
                None: None,
                (c.Ldif.ServerTypes.OID, c.Ldif.ServerTypes.OUD): (
                    "oid_to_oud",
                    u.Ldif.map_oid_to_oud_permissions,
                ),
                (c.Ldif.ServerTypes.OUD, c.Ldif.ServerTypes.OID): (
                    "oud_to_oid",
                    u.Ldif.map_oud_to_oid_permissions,
                ),
            }.get(server_pair)
            mapping_type = "none"
            replacement_permissions: m.Ldif.AclPermissions | None = None
            match permission_mapping:
                case (mapping_type, permission_mapper):
                    mapped_perms = permission_mapper(
                        permission_settings.orig_perms_dict
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
                        clean_permissions
                    )
                case None if (
                    not permission_settings.converted_has_permissions
                    and original_permissions is not None
                ):
                    mapping_type = "preserve_original"
                    replacement_permissions = original_permissions.model_copy(deep=True)
                case None:
                    mapping_type = "none"
                    replacement_permissions = None
            resolved_permissions = (
                permission_settings.converted_acl.permissions
                if replacement_permissions is None
                else replacement_permissions
            )
            converted_acl = permission_settings.converted_acl.model_copy(
                update={"permissions": resolved_permissions}, deep=True
            )
            self.logger.debug(
                "ACL t.MappingKV decision",
                mapping_type=mapping_type,
                normalized_source=str(permission_settings.source_server_type),
                normalized_target=str(permission_settings.target_server_type),
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
        merged_ext_raw = {**original_extensions, **self._get_extensions_dict(acl_step1)}
        updated_metadata = acl_step1.metadata.model_copy(
            update={"extensions": merged_ext_raw}, deep=True
        )
        preserved_acl: m.Ldif.Acl = acl_step1.model_copy(
            update={"metadata": updated_metadata}, deep=True
        )
        return preserved_acl


__all__: list[str] = ["FlextLdifConversionAclPreserveMixin"]
