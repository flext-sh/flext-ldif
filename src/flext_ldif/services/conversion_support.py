"""Support-check helpers for server-to-server conversion."""

from __future__ import annotations

from flext_ldif import c, p, r, s, t


class FlextLdifConversionSupportMixin(s):
    """Support-check helpers shared by the conversion facade."""

    @staticmethod
    def _get_schema_from_attribute(
        server: p.Ldif.ServerServer,
    ) -> p.Ldif.SchemaServer:
        return server.schema_server

    def _resolve_server(
        self,
        server_or_type: str | p.Ldif.ServerReference | p.Ldif.ServerServer,
    ) -> p.Ldif.ServerServer:
        """Resolve server server instance from string type or return instance."""
        if isinstance(server_or_type, str):
            server_type_str: str = server_or_type
            resolved_result = self.server.resolve_base_server(
                server_type_str,
            )
            if resolved_result.failure:
                error_msg = (
                    f"Unknown server type: {server_or_type}: {resolved_result.error}"
                )
                raise ValueError(error_msg)
            resolved: p.Ldif.ServerServer = resolved_result.unwrap()
            return resolved
        if isinstance(server_or_type, p.Ldif.ServerServer):
            return server_or_type
        resolved_from_ref = self.server.resolve_base_server(
            server_or_type.server_type,
        )
        if resolved_from_ref.failure:
            error_msg = (
                f"Unknown server type: {server_or_type.server_type}: "
                f"{resolved_from_ref.error}"
            )
            raise ValueError(error_msg)
        resolved_server: p.Ldif.ServerServer = resolved_from_ref.unwrap()
        return resolved_server

    def _resolve_schema_server(
        self,
        server_or_type: str | p.Ldif.ServerReference | p.Ldif.ServerServer,
        *,
        role: str,
    ) -> p.Result[p.Ldif.SchemaServer]:
        server = self._resolve_server(server_or_type)
        try:
            schema = type(self)._get_schema_from_attribute(server)
            return r[p.Ldif.SchemaServer].ok(schema)
        except TypeError as e:
            return r[p.Ldif.SchemaServer].fail(f"{role} server error: {e}")

    def resolve_supported_conversions(
        self,
        server: p.Ldif.ServerReference | str,
    ) -> t.MutableBoolMapping:
        """Check which data types a server supports for conversion."""
        attribute_key = c.Ldif.SchemaItemKind.ATTRIBUTE.value
        objectclass_key = c.Ldif.SchemaItemKind.OBJECTCLASS.value
        support: t.MutableIntMapping = {
            attribute_key: 0,
            objectclass_key: 0,
            "acl": 0,
            "entry": 0,
        }
        concrete_server = self.server.resolve_base_server(
            server if isinstance(server, str) else server.server_type,
        ).map_or(None)
        if concrete_server is None:
            return {
                attribute_key: False,
                c.Ldif.DictKeys.OBJECTCLASS: False,
                objectclass_key: False,
                "acl": False,
                "entry": False,
            }
        support = self._check_schema_support(concrete_server, support)
        support = self._check_acl_support(concrete_server, support)
        support = self._check_entry_support(concrete_server, support)
        return {
            attribute_key: bool(support.get(attribute_key, 0)),
            c.Ldif.DictKeys.OBJECTCLASS: bool(support.get(objectclass_key, 0)),
            objectclass_key: bool(support.get(objectclass_key, 0)),
            "acl": bool(support.get("acl", 0)),
            "entry": bool(support.get("entry", 0)),
        }

    def _check_acl_support(
        self,
        server: p.Ldif.ServerServer,
        support: t.MutableIntMapping,
    ) -> t.MutableIntMapping:
        """Check ACL support."""
        acl = server.acl_server
        test_acl_def = 'targetattr="*" (version 3.0; acl "test"; allow (read) userdn="ldap:///self";)'
        acl_result = acl.parse_server(test_acl_def)
        if acl_result.map_or(None) is not None:
            support["acl"] = 1
        return support

    def _check_attribute_support(
        self,
        server_schema: p.Ldif.SchemaServer,
        test_attr_def: str,
        support: t.MutableIntMapping,
    ) -> t.MutableIntMapping:
        """Check attribute support for schema server."""
        attribute_result = server_schema.parse_attribute(test_attr_def)
        if attribute_result.success:
            support[c.Ldif.SchemaItemKind.ATTRIBUTE.value] = 1
        return support

    def _check_entry_support(
        self,
        server: p.Ldif.ServerServer,
        support: t.MutableIntMapping,
    ) -> t.MutableIntMapping:
        """Check Entry support via the canonical entry server public surface."""
        if server.entry_server.parse_entry("cn=test,dc=example,dc=com", {}).success:
            support["entry"] = 1
        return support

    def _check_objectclass_support(
        self,
        server_schema: p.Ldif.SchemaServer,
        test_oc_def: str,
        support: t.MutableIntMapping,
    ) -> t.MutableIntMapping:
        """Check objectClass support for schema server."""
        objectclass_result = server_schema.parse_objectclass(test_oc_def)
        if objectclass_result.success:
            support[c.Ldif.SchemaItemKind.OBJECTCLASS.value] = 1
        return support

    def _check_schema_support(
        self,
        server: p.Ldif.ServerServer,
        support: t.MutableIntMapping,
    ) -> t.MutableIntMapping:
        """Check schema (attribute and objectClass) support."""
        server_schema = type(self)._get_schema_from_attribute(server)
        test_attr_def = "( 2.16.840.1.113894.1.1.1 NAME 'orclTest' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        test_oc_def = (
            "( 2.16.840.1.113894.1.2.1 NAME 'orclTest' SUP top STRUCTURAL MUST cn )"
        )
        support = self._check_attribute_support(server_schema, test_attr_def, support)
        return self._check_objectclass_support(server_schema, test_oc_def, support)


__all__: list[str] = ["FlextLdifConversionSupportMixin"]
