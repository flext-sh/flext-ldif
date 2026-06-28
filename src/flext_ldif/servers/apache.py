"""Apache Directory Server servers implementation."""

from __future__ import annotations

from collections.abc import (
    MutableMapping,
)
from typing import ClassVar, override

from flext_ldif import (
    FlextLdifServersRfc,
    c,
    m,
    p,
    r,
    t,
    u,
)


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
        ATTRIBUTE_PATTERN_SETTINGS: ClassVar[m.Ldif.ServerPatternsConfig] = (
            m.Ldif.ServerPatternsConfig(
                oid_pattern=DETECTION_OID_PATTERN,
                attr_prefixes=DETECTION_ATTRIBUTE_PREFIXES,
                name_regex=SCHEMA_ATTRIBUTE_NAME_REGEX,
                use_prefix_match=True,
                match_definition_text=True,
            )
        )
        OBJECTCLASS_PATTERN_SETTINGS: ClassVar[m.Ldif.ServerPatternsConfig] = (
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
            attr_definition: str | m.Ldif.SchemaAttribute,
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
            oc_definition: str | m.Ldif.SchemaObjectClass,
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
            oc: m.Ldif.SchemaObjectClass,
        ) -> p.Result[m.Ldif.SchemaObjectClass]:
            """Normalize Apache objectClass data after RFC parsing."""
            u.Ldif.fix_missing_sup(oc)
            u.Ldif.fix_kind_mismatch(oc)
            return super()._hook_post_parse_objectclass(oc)

    class Acl(FlextLdifServersRfc.Acl):
        """Apache Directory Server ACI server."""

        @override
        def can_handle(self, acl_line: str | m.Ldif.Acl) -> bool:
            """Check if this is an ApacheDS ACI."""
            return self.can_handle_acl(acl_line)

        @override
        def can_handle_acl(self, acl_line: str | m.Ldif.Acl) -> bool:
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
        def _write_acl(self, acl_data: m.Ldif.Acl) -> p.Result[str]:
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
        ) -> p.Result[m.Ldif.Entry]:
            """Parse raw LDIF entry data into Entry model."""
            str_attrs: t.MutableStrSequenceMapping = {
                k: [v.decode() if isinstance(v, bytes) else v for v in vals]
                for k, vals in entry_attrs.items()
            }
            base_result = super().parse_entry(entry_dn, str_attrs)
            if base_result.failure:
                return r[m.Ldif.Entry].from_result(base_result)
            entry = base_result.value
            try:
                return self._mark_apache_entry(entry)
            except c.EXC_BASIC_TYPE as exc:
                return r[m.Ldif.Entry].fail_op(
                    "Apache Directory Server entry parsing", exc
                )

        def _mark_apache_entry(
            self,
            entry: m.Ldif.Entry,
        ) -> p.Result[m.Ldif.Entry]:
            """Attach Apache Directory Server metadata to an entry."""
            if not entry.dn:
                return r[m.Ldif.Entry].ok(entry)
            metadata = entry.metadata or m.Ldif.ServerMetadata(
                server_type=self._get_server_type(),
            )
            dn_lower = entry.dn.value.lower()
            if not metadata.extensions:
                metadata.extensions = m.Ldif.DynamicMetadata()
            metadata.extensions[c.Ldif.ServerMetadataKeys.IS_CONFIG_ENTRY] = (
                FlextLdifServersApache.Constants.DN_CONFIG_ENTRY_MARKER in dn_lower
            )
            processed_entry = entry.model_copy(update={"metadata": metadata})
            return r[m.Ldif.Entry].ok(processed_entry)


__all__: list[str] = ["FlextLdifServersApache"]
