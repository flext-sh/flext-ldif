"""Apache Directory Server quirks implementation."""

from __future__ import annotations

import re
from typing import ClassVar

from flext_core import FlextResult

from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif.constants import c
from flext_ldif.models import m
from flext_ldif.servers.rfc import FlextLdifServersRfc
from flext_ldif.utilities import u


class FlextLdifServersApache(FlextLdifServersRfc):
    """Apache Directory Server quirks implementation."""

    class Constants(FlextLdifServersRfc.Constants):
        """Standardized constants for Apache Directory Server quirk."""

        SERVER_TYPE: ClassVar[str] = "apache"
        PRIORITY: ClassVar[int] = 15

        CANONICAL_NAME: ClassVar[str] = "apache"
        ALIASES: ClassVar[frozenset[str]] = frozenset(["apache", "apache_directory"])
        CAN_NORMALIZE_FROM: ClassVar[frozenset[str]] = frozenset(["apache"])
        CAN_DENORMALIZE_TO: ClassVar[frozenset[str]] = frozenset(
            [
                "apache",
                "rfc",
            ],
        )

        ACL_FORMAT: ClassVar[str] = "aci"
        ACL_ATTRIBUTE_NAME: ClassVar[str] = "aci"

        DETECTION_OID_PATTERN: ClassVar[str] = r"1\.3\.6\.1\.4\.1\.18060\."
        DETECTION_ATTRIBUTE_PREFIXES: ClassVar[frozenset[str]] = frozenset(
            [
                "ads-",
                "apacheds",
            ],
        )
        DETECTION_OBJECTCLASS_NAMES: ClassVar[frozenset[str]] = frozenset(
            [
                "ads-directoryservice",
                "ads-base",
                "ads-server",
                "ads-partition",
                "ads-interceptor",
            ],
        )
        DETECTION_DN_MARKERS: ClassVar[frozenset[str]] = frozenset(
            [
                "ou=config",
                "ou=services",
                "ou=system",
                "ou=partitions",
            ],
        )

        DETECTION_PATTERN: ClassVar[str] = r"\b(apacheDS|apache-.*)\b"
        DETECTION_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset(
            [
                "ads-directoryservice",
                "ads-base",
                "ads-server",
                "ads-partition",
                "ads-interceptor",
            ],
        )
        DETECTION_WEIGHT: ClassVar[int] = 6

        SCHEMA_ATTRIBUTE_NAME_REGEX: ClassVar[str] = r"NAME\s+\(?\s*'([^']+)'"

        ACL_ACI_ATTRIBUTE_NAMES: ClassVar[frozenset[str]] = frozenset(
            [
                "ads-aci",
                "aci",
            ],
        )
        ACL_CLAUSE_PATTERN: ClassVar[str] = r"\([^()]+\)"
        ACL_VERSION_PATTERN: ClassVar[str] = r"\(version"
        ACL_NAME_PREFIX: ClassVar[str] = "apache-"

        ACL_SUBJECT_TYPE_ANONYMOUS: ClassVar[str] = "anonymous"
        ACL_SUBJECT_VALUE_WILDCARD: ClassVar[str] = "*"

        DN_CONFIG_ENTRY_MARKER: ClassVar[str] = "ou=config"

    class Schema(FlextLdifServersRfc.Schema):
        """Schema quirks for Apache Directory Server (ApacheDS)."""

        def can_handle_attribute(
            self,
            attr_definition: str | m.Ldif.SchemaAttribute,
        ) -> bool:
            """Detect ApacheDS attribute definitions using centralized constants."""
            if isinstance(attr_definition, m.Ldif.SchemaAttribute):
                return u.Ldif.Server.matches_server_patterns(
                    value=attr_definition,
                    oid_pattern=FlextLdifServersApache.Constants.DETECTION_OID_PATTERN,
                    detection_names=FlextLdifServersApache.Constants.DETECTION_ATTRIBUTE_PREFIXES,
                    use_prefix_match=True,
                )

            attr_lower = attr_definition.lower()
            if re.search(
                FlextLdifServersApache.Constants.DETECTION_OID_PATTERN,
                attr_definition,
            ):
                return True
            name_matches = re.findall(
                FlextLdifServersApache.Constants.SCHEMA_ATTRIBUTE_NAME_REGEX,
                attr_definition,
                re.IGNORECASE,
            )
            if any(
                name.lower().startswith(
                    tuple(
                        FlextLdifServersApache.Constants.DETECTION_ATTRIBUTE_PREFIXES,
                    ),
                )
                for name in name_matches
            ):
                return True
            prefixes = FlextLdifServersApache.Constants.DETECTION_ATTRIBUTE_PREFIXES
            return any(prefix in attr_lower for prefix in prefixes)

        def can_handle_objectclass(
            self,
            oc_definition: str | m.Ldif.SchemaObjectClass,
        ) -> bool:
            """Detect ApacheDS objectClass definitions using centralized constants."""
            if isinstance(oc_definition, m.Ldif.SchemaObjectClass):
                return u.Ldif.Server.matches_server_patterns(
                    value=oc_definition,
                    oid_pattern=FlextLdifServersApache.Constants.DETECTION_OID_PATTERN,
                    detection_names=FlextLdifServersApache.Constants.DETECTION_OBJECTCLASS_NAMES,
                )

            if re.search(
                FlextLdifServersApache.Constants.DETECTION_OID_PATTERN,
                oc_definition,
            ):
                return True
            name_matches = re.findall(
                FlextLdifServersApache.Constants.SCHEMA_ATTRIBUTE_NAME_REGEX,
                oc_definition,
                re.IGNORECASE,
            )
            return any(
                name.lower()
                in FlextLdifServersApache.Constants.DETECTION_OBJECTCLASS_NAMES
                for name in name_matches
            )

        def _parse_attribute(
            self,
            attr_definition: str,
        ) -> FlextResult[m.Ldif.SchemaAttribute]:
            """Parse attribute definition and add Apache metadata."""
            result = super()._parse_attribute(attr_definition)
            if result.is_success:
                attr_data = result.value
                metadata = m.Ldif.QuirkMetadata.create_for(
                    "apache",
                )
                return FlextResult[m.Ldif.SchemaAttribute].ok(
                    attr_data.model_copy(update={"metadata": metadata}),
                )
            return result

        def _parse_objectclass(
            self,
            oc_definition: str,
        ) -> FlextResult[m.Ldif.SchemaObjectClass]:
            """Parse objectClass definition and add Apache metadata."""
            result = super()._parse_objectclass(oc_definition)
            if result.is_success:
                oc_data = result.value

                u.Ldif.ObjectClass.fix_missing_sup(oc_data)
                u.Ldif.ObjectClass.fix_kind_mismatch(oc_data)
                metadata = m.Ldif.QuirkMetadata.create_for(
                    self._get_server_type(),
                )
                return FlextResult[m.Ldif.SchemaObjectClass].ok(
                    oc_data.model_copy(update={"metadata": metadata}),
                )
            return result

    class Acl(FlextLdifServersRfc.Acl):
        """Apache Directory Server ACI quirk."""

        def can_handle(self, acl_line: str | m.Ldif.Acl) -> bool:
            """Check if this is an ApacheDS ACI."""
            return self.can_handle_acl(acl_line)

        def can_handle_acl(self, acl_line: str | m.Ldif.Acl) -> bool:
            """Detect ApacheDS ACI lines."""
            if isinstance(acl_line, str):
                if not acl_line or not acl_line.strip():
                    return False
                normalized = acl_line.strip()
                attr_name, _, _ = normalized.partition(":")
                if (
                    attr_name.strip().lower()
                    in FlextLdifServersApache.Constants.ACL_ACI_ATTRIBUTE_NAMES
                ):
                    return True
                return normalized.lower().startswith(
                    FlextLdifServersApache.Constants.ACL_VERSION_PATTERN,
                )
            if isinstance(acl_line, m.Ldif.Acl):
                if not acl_line.raw_acl:
                    return False
                normalized = acl_line.raw_acl.strip()
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
            return False

        def _write_acl(self, acl_data: FlextLdifModelsDomains.Acl) -> FlextResult[str]:
            """Write ACL data to Apache Directory Server ACI format."""
            parent_result = super()._write_acl(acl_data)
            if parent_result.is_success:
                acl_str = parent_result.value

                if acl_str and not acl_str.strip().startswith(("aci:", "ads-aci:")):
                    return FlextResult[str].ok(f"aci: {acl_str}")
                return parent_result

            return parent_result

    class Entry(FlextLdifServersRfc.Entry):
        """Entry quirks for Apache Directory Server."""

        def can_handle(
            self,
            entry_dn: str,
            attributes: dict[str, list[str]],
        ) -> bool:
            """Check if this quirk can handle the entry."""
            _ = entry_dn
            _ = attributes
            return True

        def _parse_entry(
            self,
            entry_dn: str,
            entry_attrs: dict[str, list[str | bytes]],
        ) -> FlextResult[m.Ldif.Entry]:
            """Parse raw LDIF entry data into Entry model."""
            str_attrs: dict[str, list[str]] = {
                k: [v.decode() if isinstance(v, bytes) else v for v in vals]
                for k, vals in entry_attrs.items()
            }
            base_result = super().parse_entry(entry_dn, str_attrs)
            if base_result.is_failure:
                return base_result

            entry = base_result.value

            try:
                if not entry.dn:
                    return FlextResult[m.Ldif.Entry].ok(entry)

                metadata = entry.metadata or m.Ldif.QuirkMetadata(
                    quirk_type=self._get_server_type(),
                )
                dn_lower = entry.dn.value.lower()
                if not metadata.extensions:
                    metadata.extensions = m.Ldif.DynamicMetadata()
                metadata.extensions[c.Ldif.Domain.QuirkMetadataKeys.IS_CONFIG_ENTRY] = (
                    FlextLdifServersApache.Constants.DN_CONFIG_ENTRY_MARKER in dn_lower
                )

                processed_entry = entry.model_copy(update={"metadata": metadata})

                return FlextResult[m.Ldif.Entry].ok(processed_entry)

            except (ValueError, TypeError, AttributeError) as exc:
                return FlextResult[m.Ldif.Entry].fail(
                    f"Apache Directory Server entry parsing failed: {exc}",
                )


__all__ = ["FlextLdifServersApache"]
