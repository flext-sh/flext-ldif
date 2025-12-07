"""Apache Directory Server quirks implementation."""

from __future__ import annotations

# Copyright (c) 2025 FLEXT Team. All rights reserved.
# SPDX-License-Identifier: MIT
import re
from typing import ClassVar, override

from flext_core import FlextResult

from flext_ldif.constants import c
from flext_ldif.models import m
from flext_ldif.servers.rfc import FlextLdifServersRfc
from flext_ldif.typings import t

# Lazy import to avoid circular dependency - use _get_utilities() function


def _get_utilities() -> type[object]:
    """Lazy import of FlextLdifUtilities to avoid circular dependency.

    Returns:
        FlextLdifUtilities class type

    """
    from flext_ldif.utilities import FlextLdifUtilities  # noqa: PLC0415

    return FlextLdifUtilities


class FlextLdifServersApache(FlextLdifServersRfc):
    """Apache Directory Server quirks implementation.

    Extends RFC base with Apache-specific detection for attributes, objectClasses,
    and entries. All parsing/conversion inherited from RFC - only detection and
    metadata handling overridden. Uses u for shared validation
    logic across servers.
    """

    # =========================================================================
    class Constants(FlextLdifServersRfc.Constants):
        """Standardized constants for Apache Directory Server quirk."""

        # Server identity and priority (defined at Constants level)
        SERVER_TYPE: ClassVar[c.Ldif.LiteralTypes.ServerTypeLiteral] = "apache"
        PRIORITY: ClassVar[int] = 15

        # Server identification

        # Auto-discovery constants
        CANONICAL_NAME: ClassVar[str] = "apache_directory"
        ALIASES: ClassVar[frozenset[str]] = frozenset(["apache", "apache_directory"])
        CAN_NORMALIZE_FROM: ClassVar[frozenset[str]] = frozenset(["apache_directory"])
        CAN_DENORMALIZE_TO: ClassVar[frozenset[str]] = frozenset(
            [
                "apache_directory",
                "rfc",
            ],
        )

        # Apache Directory Server ACL format constants
        ACL_FORMAT: ClassVar[str] = "aci"  # Apache DS uses standard ACI
        ACL_ATTRIBUTE_NAME: ClassVar[str] = "aci"  # ACL attribute name

        # Detection constants (server-specific)
        # Migrated from c.LdapServerDetection
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

        # Server detection pattern and weight (for server detector service)
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

        # Schema attribute parsing patterns
        SCHEMA_ATTRIBUTE_NAME_REGEX: ClassVar[str] = r"NAME\s+\(?\s*'([^']+)'"

        # ACL-specific constants (migrated from nested Acl class)
        ACL_ACI_ATTRIBUTE_NAMES: ClassVar[frozenset[str]] = frozenset(
            [
                "ads-aci",
                "aci",  # Apache DS uses standard ACI
            ],
        )
        ACL_CLAUSE_PATTERN: ClassVar[str] = r"\([^()]+\)"
        ACL_VERSION_PATTERN: ClassVar[str] = r"\(version"
        ACL_NAME_PREFIX: ClassVar[str] = "apache-"
        # Note: PERMISSION_COMPARE is already defined above in line 72

        # ACL parsing constants (migrated from _parse_acl method)
        ACL_SUBJECT_TYPE_ANONYMOUS: ClassVar[str] = "anonymous"
        ACL_SUBJECT_VALUE_WILDCARD: ClassVar[str] = "*"

        # Entry detection constants (migrated from Entry class)
        DN_CONFIG_ENTRY_MARKER: ClassVar[str] = "ou=config"

        # === ACL AND ENCODING CONSTANTS (Centralized) ===
        # Use centralized StrEnums from FlextLdifConstants directly
        # No duplicate nested StrEnums - use c.AclPermission,
        # c.AclAction, and c.Encoding directly

    # =========================================================================
    # Server identification - accessed via Constants via properties in base.py
    # =========================================================================
    # NOTE: server_type and priority are accessed via properties in base.py
    # which read from Constants.SERVER_TYPE and Constants.PRIORITY
    # NOTE: __getattr__ delegation is inherited from FlextLdifServersBase

    class Schema(FlextLdifServersRfc.Schema):
        """Schema quirks for Apache Directory Server (ApacheDS).

        Detects and tags Apache-specific schema attributes and objectClasses.
        Inherits all parsing and conversion from RFC base.
        """

        def can_handle_attribute(
            self,
            attr_definition: str | m.Ldif.SchemaAttribute,
        ) -> bool:
            """Detect ApacheDS attribute definitions using centralized constants."""
            if isinstance(attr_definition, m.Ldif.SchemaAttribute):
                u = _get_utilities()
                return u.Server.matches_server_patterns(  # type: ignore[attr-defined]
                    value=attr_definition,
                    oid_pattern=FlextLdifServersApache.Constants.DETECTION_OID_PATTERN,
                    detection_names=FlextLdifServersApache.Constants.DETECTION_ATTRIBUTE_PREFIXES,
                    use_prefix_match=True,
                )
            # For string definitions, extract NAME and check prefix match
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
                u = _get_utilities()
                return u.Server.matches_server_patterns(  # type: ignore[attr-defined]
                    value=oc_definition,
                    oid_pattern=FlextLdifServersApache.Constants.DETECTION_OID_PATTERN,
                    detection_names=FlextLdifServersApache.Constants.DETECTION_OBJECTCLASS_NAMES,
                )
            # For string definitions, extract NAME and check exact match
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
            """Parse attribute definition and add Apache metadata.

            Args:
                attr_definition: Attribute definition string

            Returns:
                FlextResult with SchemaAttribute marked with Apache metadata

            """
            result = super()._parse_attribute(attr_definition)
            if result.is_success:
                attr_data = result.unwrap()
                metadata = m.QuirkMetadata.create_for(
                    "apache_directory",
                )
                return FlextResult[m.Ldif.SchemaAttribute].ok(
                    attr_data.model_copy(update={"metadata": metadata}),
                )
            return result

        def _parse_objectclass(
            self,
            oc_definition: str,
        ) -> FlextResult[m.Ldif.SchemaObjectClass]:
            """Parse objectClass definition and add Apache metadata.

            Args:
                oc_definition: ObjectClass definition string

            Returns:
                FlextResult with SchemaObjectClass marked with Apache metadata

            """
            result = super()._parse_objectclass(oc_definition)
            if result.is_success:
                oc_data = result.unwrap()
                # Fix common ObjectClass issues (RFC 4512 compliance)
                u = _get_utilities()
                u.ObjectClass.fix_missing_sup(  # type: ignore[attr-defined]
                    oc_data,
                    _server_type=self._get_server_type(),
                )
                u.ObjectClass.fix_kind_mismatch(  # type: ignore[attr-defined]
                    oc_data,
                    _server_type=self._get_server_type(),
                )
                metadata = m.QuirkMetadata.create_for(
                    self._get_server_type(),
                )
                return FlextResult[m.Ldif.SchemaObjectClass].ok(
                    oc_data.model_copy(update={"metadata": metadata}),
                )
            return result

        # Nested Acl and Entry classes for test API compatibility

    class Acl(FlextLdifServersRfc.Acl):
        """Apache Directory Server ACI quirk.

        Handles ApacheDS ACI (Access Control Instruction) format.
        """

        def can_handle(self, acl_line: t.Ldif.AclOrString) -> bool:
            """Check if this is an ApacheDS ACI.

            Override RFC's always-true behavior to check Apache-specific markers.

            Args:
                acl_line: ACL line string or Acl model

            Returns:
                True if this is ApacheDS ACI format

            """
            return self.can_handle_acl(acl_line)

        def can_handle_acl(self, acl_line: t.Ldif.AclOrString) -> bool:
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

        def _write_acl(self, acl_data: m.Ldif.Acl) -> FlextResult[str]:
            """Write ACL data to Apache Directory Server ACI format.

            Apache Directory Server ACLs use ACI format with 'aci:' prefix.

            Args:
                acl_data: Acl model to write

            Returns:
                FlextResult with Apache ACI string

            """
            # Try parent's write method first (RFC format)
            parent_result = super()._write_acl(acl_data)
            if parent_result.is_success:
                acl_str = parent_result.unwrap()
                # Ensure Apache ACI prefix is present
                if acl_str and not acl_str.strip().startswith(("aci:", "ads-aci:")):
                    # Add aci: prefix for Apache
                    return FlextResult[str].ok(f"aci: {acl_str}")
                return parent_result

            # RFC write failed - return parent error
            return parent_result

    class Entry(FlextLdifServersRfc.Entry):
        """Entry quirks for Apache Directory Server.

        Handles ApacheDS-specific entry detection and processing.
        Inherits entry handling from RFC base - no override needed.
        """

        @override
        def _parse_entry(
            self,
            entry_dn: str,
            entry_attrs: dict[str, list[str | bytes]],
        ) -> FlextResult[m.Ldif.Entry]:
            """Parse raw LDIF entry data into Entry model.

            Applies Apache-specific transformations.

            Args:
                entry_dn: Raw DN string from LDIF parser
                entry_attrs: Raw attributes mapping from LDIF parser

            Returns:
                FlextResult with parsed Entry model with Apache-specific metadata

            """
            # Business Rule: Apache Entry quirks extend RFC base parsing with server-specific
            # transformations. All entry parsing follows RFC 2849 foundation, with Apache-specific
            # enhancements applied after successful RFC parsing.
            # Implication: Apache quirks maintain RFC compliance while adding server-specific
            # metadata and transformations. This ensures compatibility with standard LDIF tools
            # while enabling Apache-specific optimizations.
            base_result = super()._parse_entry(entry_dn, entry_attrs)
            if base_result.is_failure:
                return base_result

            entry = base_result.unwrap()

            try:
                # Check if entry has DN
                if not entry.dn:
                    return FlextResult[m.Ldif.Entry].ok(entry)

                # Store metadata in extensions
                metadata = entry.metadata or m.QuirkMetadata(
                    quirk_type=self._get_server_type(),
                )
                dn_lower = entry.dn.value.lower()
                if not metadata.extensions:
                    metadata.extensions = m.DynamicMetadata()
                metadata.extensions[c.Ldif.QuirkMetadataKeys.IS_CONFIG_ENTRY] = (
                    FlextLdifServersApache.Constants.DN_CONFIG_ENTRY_MARKER in dn_lower
                )

                processed_entry = entry.model_copy(update={"metadata": metadata})

                return FlextResult[m.Ldif.Entry].ok(processed_entry)

            except (ValueError, TypeError, AttributeError) as exc:
                return FlextResult[m.Ldif.Entry].fail(
                    f"Apache Directory Server entry parsing failed: {exc}",
                )


__all__ = ["FlextLdifServersApache"]
