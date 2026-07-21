"""Apache Directory Server servers implementation."""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar, override

from flext_ldif import c, m, p, r, t, u
from flext_ldif.servers.rfc import FlextLdifServersRfc

if TYPE_CHECKING:
    from collections.abc import MutableMapping


class FlextLdifServersApache(FlextLdifServersRfc):
    """Apache Directory Server servers implementation."""

    class Constants(FlextLdifServersRfc.Constants):
        """Standardized constants for Apache Directory Server server."""

        SERVER_TYPE: ClassVar[str] = "apache"
        PRIORITY: ClassVar[int] = 15
        CANONICAL_NAME: ClassVar[str] = "apache"
        ALIASES: ClassVar[frozenset[str]] = frozenset(["apache", "apache_directory"])
        CAN_NORMALIZE_FROM: ClassVar[frozenset[str]] = frozenset(["apache"])
        CAN_DENORMALIZE_TO: ClassVar[frozenset[str]] = frozenset(["apache", "rfc"])
        ACL_FORMAT: ClassVar[str] = "aci"
        ACL_ATTRIBUTE_NAME: ClassVar[str] = "aci"
        DETECTION_OID_PATTERN: ClassVar[str] = "1\\.3\\.6\\.1\\.4\\.1\\.18060\\."
        DETECTION_ATTRIBUTE_PREFIXES: ClassVar[frozenset[str]] = frozenset([
            "ads-",
            "apacheds",
        ])
        SCHEMA_ATTRIBUTE_NAME_REGEX: ClassVar[str] = "NAME\\s+\\(?\\s*'([^']+)'"
        DETECTION_OBJECTCLASS_NAMES: ClassVar[frozenset[str]] = frozenset([
            "ads-directoryservice",
            "ads-base",
            "ads-server",
            "ads-partition",
            "ads-interceptor",
        ])
        ATTRIBUTE_PATTERN_SETTINGS: ClassVar[p.Ldif.ServerPatternsConfig] = (
            m.Ldif.ServerPatternsConfig(
                oid_pattern=DETECTION_OID_PATTERN,
                attr_prefixes=DETECTION_ATTRIBUTE_PREFIXES,
                name_regex=SCHEMA_ATTRIBUTE_NAME_REGEX,
                use_prefix_match=True,
                match_definition_text=True,
            )
        )
        OBJECTCLASS_PATTERN_SETTINGS: ClassVar[p.Ldif.ServerPatternsConfig] = (
            m.Ldif.ServerPatternsConfig(
                oid_pattern=DETECTION_OID_PATTERN,
                attr_names=DETECTION_OBJECTCLASS_NAMES,
                name_regex=SCHEMA_ATTRIBUTE_NAME_REGEX,
            )
        )
        DETECTION_DN_MARKERS: ClassVar[frozenset[str]] = frozenset([
            "ou=settings",
            "ou=services",
            "ou=system",
            "ou=partitions",
        ])
        DETECTION_PATTERN: ClassVar[str] = "\\b(apacheDS|apache-.*)\\b"
        DETECTION_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset([
            "ads-directoryservice",
            "ads-base",
            "ads-server",
            "ads-partition",
            "ads-interceptor",
        ])
        DETECTION_WEIGHT: ClassVar[int] = 6
        ACL_ACI_ATTRIBUTE_NAMES: ClassVar[frozenset[str]] = frozenset([
            "ads-aci",
            "aci",
        ])
        ACL_CLAUSE_PATTERN: ClassVar[str] = "\\([^()]+\\)"
        ACL_VERSION_PATTERN: ClassVar[str] = "\\(version"
        ACL_NAME_PREFIX: ClassVar[str] = "apache-"
        ACL_SUBJECT_TYPE_ANONYMOUS: ClassVar[str] = "anonymous"
        ACL_SUBJECT_VALUE_WILDCARD: ClassVar[str] = "*"
        DN_CONFIG_ENTRY_MARKER: ClassVar[str] = "ou=settings"

    class Schema(FlextLdifServersRfc.Schema):
        """Schema servers for Apache Directory Server (ApacheDS)."""

        @override
        def can_handle_attribute(
            self,
            # NOTE (multi-agent, mro-0ftd.3.7.2): protocol param to match base.
            attr_definition: str | p.Ldif.SchemaAttribute,
        ) -> bool:
            """Detect ApacheDS attribute definitions using centralized constants."""
            matches: bool = u.Ldif.matches_server_patterns(
                value=attr_definition,
                settings=FlextLdifServersApache.Constants.ATTRIBUTE_PATTERN_SETTINGS,
            )
            return matches

        @override
        def can_handle_objectclass(
            self,
            oc_definition: str | p.Ldif.SchemaObjectClass,
        ) -> bool:
            """Detect ApacheDS objectClass definitions using centralized constants."""
            matches: bool = u.Ldif.matches_server_patterns(
                value=oc_definition,
                settings=FlextLdifServersApache.Constants.OBJECTCLASS_PATTERN_SETTINGS,
            )
            return matches

        @override
        def _hook_post_parse_objectclass(
            self,
            # NOTE (multi-agent, mro-0ftd.3.7.2): protocol payload (§3.2).
            oc: p.Ldif.SchemaObjectClass,
        ) -> p.Result[p.Ldif.SchemaObjectClass]:
            """Normalize Apache objectClass data after RFC parsing."""
            # NOTE (multi-agent, mro-0ftd.3.7.2): helpers return the immutable
            # model_copy transition (no in-place mutation) — assign it.
            oc = u.Ldif.fix_missing_sup(oc)
            oc = u.Ldif.fix_kind_mismatch(oc)
            return super()._hook_post_parse_objectclass(oc)

    class Acl(FlextLdifServersRfc.Acl):
        """Apache Directory Server ACI server."""

        @override
        def can_handle(self, acl_line: str | p.Ldif.Acl) -> bool:
            """Check if this is an ApacheDS ACI."""
            return self.can_handle_acl(acl_line)

        @override
        def can_handle_acl(self, acl_line: str | p.Ldif.Acl) -> bool:
            """Detect ApacheDS ACI lines."""
            if isinstance(acl_line, str):
                normalized = acl_line.strip()
            else:
                raw_acl = getattr(acl_line, "raw_acl", None)
                if not isinstance(raw_acl, str):
                    return False
                normalized = raw_acl.strip()
            if not normalized:
                return False
            attr_name, _, _ = normalized.partition(":")
            if (
                attr_name.strip().lower()
                in FlextLdifServersApache.Constants.ACL_ACI_ATTRIBUTE_NAMES
            ):
                return True
            return normalized.lower().startswith(
                FlextLdifServersApache.Constants.ACL_VERSION_PATTERN,
            )

        @override
        def _write_acl(self, acl_data: p.Ldif.Acl) -> p.Result[str]:
            """Write ACL data to Apache Directory Server ACI format."""
            parent_result = super()._write_acl(acl_data)
            if parent_result.success:
                acl_str = parent_result.value
                if acl_str and (not acl_str.strip().startswith(("aci:", "ads-aci:"))):
                    return r[str].ok(f"aci: {acl_str}")
                return r[str].from_result(parent_result)
            return r[str].from_result(parent_result)

    class Entry(FlextLdifServersRfc.Entry):
        """Entry servers for Apache Directory Server."""

        @override
        def can_handle(
            self,
            entry_dn: str,
            attributes: t.MutableStrSequenceMapping,
        ) -> bool:
            """Check if this server can handle the entry."""
            _ = entry_dn
            _ = attributes
            return True

        def _parse_entry(
            self,
            entry_dn: str,
            entry_attrs: MutableMapping[str, t.MutableSequenceOf[str | bytes]],
        ) -> p.Result[p.Ldif.Entry]:
            """Parse raw LDIF entry data into Entry model."""
            str_attrs: t.MutableStrSequenceMapping = {
                k: [v.decode() if isinstance(v, bytes) else v for v in vals]
                for k, vals in entry_attrs.items()
            }
            base_result = super().parse_entry(entry_dn, str_attrs)
            if base_result.failure:
                return r[p.Ldif.Entry].from_result(base_result)
            entry = base_result.value
            try:
                return self._mark_apache_entry(entry)
            except c.EXC_BASIC_TYPE as exc:
                return r[p.Ldif.Entry].fail_op(
                    "Apache Directory Server entry parsing",
                    exc,
                )

        def _mark_apache_entry(
            self,
            # NOTE (multi-agent, mro-0ftd.3.7.2): protocol payload (§3.2); the
            # model is constructed only at r[p.Ldif.Entry].ok(...) boundary.
            entry: p.Ldif.Entry,
        ) -> p.Result[p.Ldif.Entry]:
            """Attach Apache Directory Server metadata to an entry."""
            if not entry.dn:
                return r[p.Ldif.Entry].ok(entry)
            # NOTE (multi-agent, mro-0ftd.3.7.2): narrow to the concrete mutable
            # ServerMetadata model (the runtime object IS the model); it is the
            # JsonPayload the Entry.model_copy update accepts.
            raw_metadata = entry.metadata
            metadata: p.Ldif.ServerMetadata = (
                raw_metadata
                if isinstance(raw_metadata, m.Ldif.ServerMetadata)
                else m.Ldif.ServerMetadata(
                    server_type=self._get_server_type(),
                )
            )
            dn_lower = entry.dn.value.lower()
            if not metadata.extensions:
                metadata.extensions = {}
            metadata.extensions[c.Ldif.ServerMetadataKeys.IS_CONFIG_ENTRY] = (
                FlextLdifServersApache.Constants.DN_CONFIG_ENTRY_MARKER in dn_lower
            )
            processed_entry = entry.model_copy(update={"metadata": metadata})
            return r[p.Ldif.Entry].ok(processed_entry)


__all__: list[str] = ["FlextLdifServersApache"]
