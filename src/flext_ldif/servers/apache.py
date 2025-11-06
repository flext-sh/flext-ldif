"""Apache Directory Server quirks implementation."""

from __future__ import annotations

import re
from collections.abc import Mapping
from enum import StrEnum
from typing import ClassVar

from flext_core import FlextResult

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.servers.rfc import FlextLdifServersRfc
from flext_ldif.typings import FlextLdifTypes
from flext_ldif.utilities import FlextLdifUtilities


class FlextLdifServersApache(FlextLdifServersRfc):
    """Apache Directory Server quirks implementation.

    Extends RFC base with Apache-specific detection for attributes, objectClasses,
    and entries. All parsing/conversion inherited from RFC - only detection and
    metadata handling overridden. Uses FlextLdifUtilities for shared validation
    logic across servers.
    """

    # === STANDARDIZED CONSTANTS FOR AUTO-DISCOVERY ===
    class Constants(FlextLdifServersRfc.Constants):
        """Standardized constants for Apache Directory Server quirk."""

        # Server identification
        SERVER_TYPE: ClassVar[str] = FlextLdifConstants.ServerTypes.APACHE

        # Auto-discovery constants
        CANONICAL_NAME: ClassVar[str] = "apache_directory"
        ALIASES: ClassVar[frozenset[str]] = frozenset(["apache_directory", "apache"])
        PRIORITY: ClassVar[int] = 15
        CAN_NORMALIZE_FROM: ClassVar[frozenset[str]] = frozenset(["apache_directory"])
        CAN_DENORMALIZE_TO: ClassVar[frozenset[str]] = frozenset([
            "apache_directory",
            "rfc",
        ])

        # Apache Directory Server ACL format constants
        ACL_FORMAT: ClassVar[str] = "aci"  # Apache DS uses standard ACI
        ACL_ATTRIBUTE_NAME: ClassVar[str] = "aci"  # ACL attribute name

        # NOTE: Apache inherits RFC baseline for:
        # - OPERATIONAL_ATTRIBUTES (RFC standard set)
        # - PRESERVE_ON_MIGRATION (createTimestamp, modifyTimestamp)
        # - SUPPORTED_PERMISSIONS (read, write, add, delete, search, compare)
        # - ATTRIBUTE_ALIASES (empty, no aliases)
        # - ATTRIBUTE_FIELDS (empty, no special fields)
        # - OBJECTCLASS_REQUIREMENTS (RFC standard requirements)

        # Detection constants (server-specific)
        # Migrated from FlextLdifConstants.LdapServerDetection
        DETECTION_OID_PATTERN: ClassVar[str] = r"1\.3\.6\.1\.4\.1\.18060\."
        DETECTION_ATTRIBUTE_PREFIXES: ClassVar[frozenset[str]] = frozenset([
            "ads-",
            "apacheds",
        ])
        DETECTION_OBJECTCLASS_NAMES: ClassVar[frozenset[str]] = frozenset([
            "ads-directoryservice",
            "ads-base",
            "ads-server",
            "ads-partition",
            "ads-interceptor",
        ])
        DETECTION_DN_MARKERS: ClassVar[frozenset[str]] = frozenset([
            "ou=config",
            "ou=services",
            "ou=system",
            "ou=partitions",
        ])

        # Server detection pattern and weight (for server detector service)
        DETECTION_PATTERN: ClassVar[str] = r"\b(apacheDS|apache-.*)\b"
        DETECTION_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset([
            "ads-directoryservice",
            "ads-base",
            "ads-server",
            "ads-partition",
            "ads-interceptor",
        ])
        DETECTION_WEIGHT: ClassVar[int] = 6

        # Schema attribute parsing patterns
        SCHEMA_ATTRIBUTE_NAME_REGEX: ClassVar[str] = r"NAME\s+\(?\s*'([^']+)'"

        # ACL-specific constants (migrated from nested Acl class)
        ACL_ACI_ATTRIBUTE_NAMES: ClassVar[frozenset[str]] = frozenset([
            "ads-aci",
            "aci",  # Apache DS uses standard ACI
        ])
        ACL_CLAUSE_PATTERN: ClassVar[str] = r"\([^()]+\)"
        ACL_VERSION_PATTERN: ClassVar[str] = r"\(version"
        ACL_NAME_PREFIX: ClassVar[str] = "apache-"
        # Note: PERMISSION_COMPARE is already defined above in line 72

        # ACL parsing constants (migrated from _parse_acl method)
        ACL_SUBJECT_TYPE_ANONYMOUS: ClassVar[str] = "anonymous"
        ACL_SUBJECT_VALUE_WILDCARD: ClassVar[str] = "*"

        # Entry detection constants (migrated from Entry class)
        DN_CONFIG_ENTRY_MARKER: ClassVar[str] = "ou=config"

        # === NESTED STRENUM DEFINITIONS ===
        # StrEnum definitions for type-safe permission, action, and encoding handling

        class AclPermission(StrEnum):
            """Apache Directory Server-specific ACL permissions."""

            READ = "read"
            WRITE = "write"
            ADD = "add"
            DELETE = "delete"
            SEARCH = "search"
            AUTH = "auth"
            ALL = "all"
            NONE = "none"

        class AclAction(StrEnum):
            """Apache Directory Server ACL action types."""

            ALLOW = "allow"
            DENY = "deny"

        class Encoding(StrEnum):
            """Apache Directory Server-supported encodings."""

            UTF_8 = "utf-8"
            UTF_16 = "utf-16"
            ASCII = "ascii"
            LATIN_1 = "latin-1"

    # =========================================================================
    # Server identification - accessed via Constants via properties in base.py
    # =========================================================================
    # NOTE: server_type and priority are accessed via properties in base.py
    # which read from Constants.SERVER_TYPE and Constants.PRIORITY

    def __getattr__(self, name: str) -> object:
        """Delegate method calls to nested Schema, Acl, or Entry instances.

        This enables calling schema/acl/entry methods directly on the main
        server instance.

        Args:
            name: Method or attribute name to look up

        Returns:
            Method or attribute from nested instance

        Raises:
            AttributeError: If attribute not found in any nested instance

        """
        # Try schema methods first (most common)
        if hasattr(self.schema, name):
            return getattr(self.schema, name)
        # Try acl methods
        if hasattr(self.acl, name):
            return getattr(self.acl, name)
        # Try entry methods
        if hasattr(self.entry, name):
            return getattr(self.entry, name)
        # Not found in any nested instance
        msg = f"'{type(self).__name__}' object has no attribute '{name}'"
        raise AttributeError(msg)

    class Schema(FlextLdifServersRfc.Schema):
        """Schema quirks for Apache Directory Server (ApacheDS).

        Detects and tags Apache-specific schema attributes and objectClasses.
        Inherits all parsing and conversion from RFC base.
        """

        def can_handle_attribute(
            self,
            attr_definition: str | FlextLdifModels.SchemaAttribute,
        ) -> bool:
            """Detect ApacheDS attribute definitions using centralized constants."""
            # Handle both string and model inputs
            if isinstance(attr_definition, str):
                attr_lower = attr_definition.lower()

                # Check OID pattern from constants (use DETECTION_OID_PATTERN)
                if re.search(
                    FlextLdifServersApache.Constants.DETECTION_OID_PATTERN,
                    attr_definition,
                ):
                    return True

                # Check attribute name prefixes (use DETECTION_ATTRIBUTE_PREFIXES)
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
            if isinstance(attr_definition, FlextLdifModels.SchemaAttribute):
                # Check OID pattern from constants (use DETECTION_OID_PATTERN)
                if re.search(
                    FlextLdifServersApache.Constants.DETECTION_OID_PATTERN,
                    attr_definition.oid,
                ):
                    return True

                # Check attribute name prefixes (use DETECTION_ATTRIBUTE_PREFIXES)
                attr_name_lower = attr_definition.name.lower()
                prefixes = FlextLdifServersApache.Constants.DETECTION_ATTRIBUTE_PREFIXES
                return any(attr_name_lower.startswith(prefix) for prefix in prefixes)
            return False

        def can_handle_objectclass(
            self,
            oc_definition: str | FlextLdifModels.SchemaObjectClass,
        ) -> bool:
            """Detect ApacheDS objectClass definitions using centralized constants."""
            if isinstance(oc_definition, str):
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
            if isinstance(oc_definition, FlextLdifModels.SchemaObjectClass):
                # Check OID pattern from constants (use DETECTION_OID_PATTERN)
                if re.search(
                    FlextLdifServersApache.Constants.DETECTION_OID_PATTERN,
                    oc_definition.oid,
                ):
                    return True

                # Check objectClass name (use DETECTION_OBJECTCLASS_NAMES)
                oc_name_lower = oc_definition.name.lower()
                return (
                    oc_name_lower
                    in FlextLdifServersApache.Constants.DETECTION_OBJECTCLASS_NAMES
                )
            return False

        def _parse_attribute(
            self,
            attr_definition: str,
        ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
            """Parse attribute definition and add Apache metadata.

            Args:
                attr_definition: Attribute definition string

            Returns:
                FlextResult with SchemaAttribute marked with Apache metadata

            """
            result = super()._parse_attribute(attr_definition)
            if result.is_success:
                attr_data = result.unwrap()
                metadata = FlextLdifModels.QuirkMetadata.create_for(
                    "apache_directory",
                )
                return FlextResult[FlextLdifModels.SchemaAttribute].ok(
                    attr_data.model_copy(update={"metadata": metadata}),
                )
            return result

        def _parse_objectclass(
            self,
            oc_definition: str,
        ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
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
                FlextLdifUtilities.ObjectClass.fix_missing_sup(
                    oc_data,
                    _server_type=FlextLdifServersApache.Constants.SERVER_TYPE,
                )
                FlextLdifUtilities.ObjectClass.fix_kind_mismatch(
                    oc_data,
                    _server_type=FlextLdifServersApache.Constants.SERVER_TYPE,
                )
                metadata = FlextLdifModels.QuirkMetadata.create_for(
                    "apache_directory",
                )
                return FlextResult[FlextLdifModels.SchemaObjectClass].ok(
                    oc_data.model_copy(update={"metadata": metadata}),
                )
            return result

        # Nested Acl and Entry classes for test API compatibility

    class Acl(FlextLdifServersRfc.Acl):
        """Apache Directory Server ACI quirk.

        Handles ApacheDS ACI (Access Control Instruction) format.
        """

        def can_handle(self, acl_line: FlextLdifTypes.Models.AclOrString) -> bool:
            """Check if this is an ApacheDS ACI.

            Override RFC's always-true behavior to check Apache-specific markers.

            Args:
                acl_line: ACL line string or Acl model

            Returns:
                True if this is ApacheDS ACI format

            """
            return self.can_handle_acl(acl_line)

        def can_handle_acl(self, acl_line: FlextLdifTypes.Models.AclOrString) -> bool:
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
            if isinstance(acl_line, FlextLdifModels.Acl):
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

        def _parse_acl(self, acl_line: str) -> FlextResult[FlextLdifModels.Acl]:
            """Parse ApacheDS ACI definition.

            Override RFC implementation with Apache-specific parsing.

            Args:
                acl_line: ACL definition line

            Returns:
                FlextResult with parsed Acl model

            """
            # Always try parent's _parse_acl first (RFC format)
            parent_result = super()._parse_acl(acl_line)
            if parent_result.is_success:
                # RFC parser succeeded - enhance with Apache-specific name
                acl_model = parent_result.unwrap()
                if not acl_model.name:
                    # Extract attribute name from ACL line for default name
                    attr_name, _ = self._splitacl_line(acl_line)
                    acl_model.name = (
                        f"{FlextLdifServersApache.Constants.ACL_NAME_PREFIX}{attr_name}"
                    )
                return FlextResult[FlextLdifModels.Acl].ok(acl_model)

            # RFC parser failed - use Apache-specific parsing
            try:
                attr_name, _content = self._splitacl_line(acl_line)

                # Create proper Acl model
                acl_model = FlextLdifModels.Acl(
                    name=f"{FlextLdifServersApache.Constants.ACL_NAME_PREFIX}{attr_name}",
                    target=FlextLdifModels.AclTarget(
                        target_dn=FlextLdifConstants.Acl.ACL_TARGET_DN_WILDCARD
                        if hasattr(FlextLdifConstants.Acl, "ACL_TARGET_DN_WILDCARD")
                        else "*",
                        attributes=[attr_name] if attr_name else [],
                    ),
                    subject=FlextLdifModels.AclSubject(
                        subject_type=FlextLdifServersApache.Constants.ACL_SUBJECT_TYPE_ANONYMOUS,
                        subject_value=FlextLdifServersApache.Constants.ACL_SUBJECT_VALUE_WILDCARD,
                    ),
                    permissions=FlextLdifModels.AclPermissions(),
                    raw_acl=acl_line,
                    metadata=FlextLdifModels.QuirkMetadata(
                        quirk_type=FlextLdifServersApache.Constants.SERVER_TYPE,
                        original_format=acl_line.strip(),
                        extensions={},
                    ),
                )

                return FlextResult[FlextLdifModels.Acl].ok(acl_model)

            except (ValueError, TypeError, AttributeError) as exc:
                return FlextResult[FlextLdifModels.Acl].fail(
                    f"Apache Directory Server ACL parsing failed: {exc}",
                )

        def _write_acl(self, acl_data: FlextLdifModels.Acl) -> FlextResult[str]:
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

        @staticmethod
        def _splitacl_line(acl_line: str) -> tuple[str, str]:
            """Split an ACL line into attribute name and payload."""
            attr_name, _, remainder = acl_line.partition(":")
            return attr_name.strip(), remainder.strip()

    class Entry(FlextLdifServersRfc.Entry):
        """Entry quirks for Apache Directory Server.

        Handles ApacheDS-specific entry detection and processing.
        Inherits entry handling from RFC base - no override needed.
        """

        def _parse_entry(
            self,
            entry_dn: str,
            entry_attrs: Mapping[str, object],
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Parse raw LDIF entry data into Entry model.

            Applies Apache-specific transformations.

            Args:
                entry_dn: Raw DN string from LDIF parser
                entry_attrs: Raw attributes mapping from LDIF parser

            Returns:
                FlextResult with parsed Entry model with Apache-specific metadata

            """
            # Always try parent's _parse_entry first (RFC format)
            base_result = super()._parse_entry(entry_dn, entry_attrs)
            if base_result.is_failure:
                return base_result

            entry = base_result.unwrap()

            try:
                # Store metadata in extensions
                metadata = entry.metadata or FlextLdifModels.QuirkMetadata(
                    quirk_type=FlextLdifServersApache.Constants.SERVER_TYPE,
                )
                dn_lower = entry.dn.value.lower()
                if not metadata.extensions:
                    metadata.extensions = {}
                metadata.extensions[
                    FlextLdifConstants.QuirkMetadataKeys.IS_CONFIG_ENTRY
                ] = FlextLdifServersApache.Constants.DN_CONFIG_ENTRY_MARKER in dn_lower

                processed_entry = entry.model_copy(update={"metadata": metadata})

                return FlextResult[FlextLdifModels.Entry].ok(processed_entry)

            except (ValueError, TypeError, AttributeError) as exc:
                return FlextResult[FlextLdifModels.Entry].fail(
                    f"Apache Directory Server entry parsing failed: {exc}",
                )


__all__ = ["FlextLdifServersApache"]
