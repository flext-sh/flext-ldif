"""Apache Directory Server quirks implementation."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import ClassVar

from flext_core import FlextResult

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.servers.rfc import FlextLdifServersRfc
from flext_ldif.utilities import FlextLdifUtilities


class FlextLdifServersApache(FlextLdifServersRfc):
    """Apache Directory Server quirks implementation.

    Extends RFC base with Apache-specific detection for attributes, objectClasses, and entries.
    All parsing/conversion inherited from RFC - only detection and metadata handling overridden.
    Uses FlextLdifUtilities for shared validation logic across servers.
    """

    # =========================================================================
    # Class-level attributes for server identification
    # =========================================================================
    server_type: ClassVar[str] = FlextLdifConstants.ServerTypes.APACHE
    priority: ClassVar[int] = 15

    # =========================================================================
    # Standardized constants (nested class inheriting from RFC.Constants)
    # =========================================================================
    class Constants(FlextLdifServersRfc.Constants):
        """Standardized constants for Apache Directory Server quirk."""

        # Metadata constants
        CANONICAL_NAME: ClassVar[str] = "apache_directory"
        ALIASES: ClassVar[frozenset[str]] = frozenset(["apache_directory", "apache"])
        CAN_NORMALIZE_FROM: ClassVar[frozenset[str]] = frozenset(["apache_directory"])
        CAN_DENORMALIZE_TO: ClassVar[frozenset[str]] = frozenset(["apache_directory", "rfc"])

        # Detection constants (server-specific)
        OID_PATTERN: Final[str] = r"1\.3\.6\.1\.4\.1\.18060\."
        ATTRIBUTE_PREFIXES: Final[frozenset[str]] = frozenset([
            "ads-",
            "apacheds",
        ])
        OBJECTCLASS_NAMES: Final[frozenset[str]] = frozenset([
            "ads-directoryservice",
            "ads-base",
            "ads-server",
            "ads-partition",
            "ads-interceptor",
        ])
        DN_MARKERS: Final[frozenset[str]] = frozenset([
            "ou=config",
            "ou=services",
            "ou=system",
            "ou=partitions",
        ])

    def __getattr__(self, name: str) -> object:
        """Delegate method calls to nested Schema, Acl, or Entry instances.

        This enables calling schema/acl/entry methods directly on the main server instance.

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

        def _can_handle_attribute(
            self, attr_definition: str | FlextLdifModels.SchemaAttribute
        ) -> bool:
            """Detect ApacheDS attribute definitions using centralized constants."""
            # Handle both string and model inputs
            if isinstance(attr_definition, str):
                attr_lower = attr_definition.lower()

                # Check OID pattern from constants
                if re.search(
                    FlextLdifServersApache.Constants.OID_PATTERN,
                    attr_definition,
                ):
                    return True

                # Check attribute name prefixes
                name_matches = re.findall(
                    r"NAME\s+\(?\s*'([^']+)'",
                    attr_definition,
                    re.IGNORECASE,
                )
                if any(
                    name.lower().startswith(
                        tuple(
                            FlextLdifServersApache.Constants.ATTRIBUTE_PREFIXES
                        )
                    )
                    for name in name_matches
                ):
                    return True

                return any(
                    prefix in attr_lower
                    for prefix in FlextLdifServersApache.Constants.ATTRIBUTE_PREFIXES
                )
            if isinstance(attr_definition, FlextLdifModels.SchemaAttribute):
                # Check OID pattern from constants
                if re.search(
                    FlextLdifServersApache.Constants.OID_PATTERN,
                    attr_definition.oid,
                ):
                    return True

                # Check attribute name prefixes
                attr_name_lower = attr_definition.name.lower()
                return any(
                    attr_name_lower.startswith(prefix)
                    for prefix in FlextLdifServersApache.Constants.ATTRIBUTE_PREFIXES
                )
            return False

        def _can_handle_objectclass(
            self, oc_definition: str | FlextLdifModels.SchemaObjectClass
        ) -> bool:
            """Detect ApacheDS objectClass definitions using centralized constants."""
            if isinstance(oc_definition, str):
                if re.search(
                    self.Constants.OID_PATTERN,
                    oc_definition,
                ):
                    return True

                name_matches = re.findall(
                    r"NAME\s+\(?\s*'([^']+)'",
                    oc_definition,
                    re.IGNORECASE,
                )
                return any(
                    name.lower()
                    in self.Constants.OBJECTCLASS_NAMES
                    for name in name_matches
                )
            if isinstance(oc_definition, FlextLdifModels.SchemaObjectClass):
                # Check OID pattern from constants
                if re.search(
                    self.Constants.OID_PATTERN,
                    oc_definition.oid,
                ):
                    return True

                # Check objectClass name
                oc_name_lower = oc_definition.name.lower()
                return (
                    oc_name_lower
                    in self.Constants.OBJECTCLASS_NAMES
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
                metadata = FlextLdifModels.QuirkMetadata.create_for_quirk(
                    "apache_directory"
                )
                return FlextResult[FlextLdifModels.SchemaAttribute].ok(
                    attr_data.model_copy(update={"metadata": metadata})
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
                    oc_data, server_type=FlextLdifConstants.LdapServers.APACHE_DIRECTORY
                )
                FlextLdifUtilities.ObjectClass.fix_kind_mismatch(
                    oc_data, server_type=FlextLdifConstants.LdapServers.APACHE_DIRECTORY
                )
                metadata = FlextLdifModels.QuirkMetadata.create_for_quirk(
                    "apache_directory"
                )
                return FlextResult[FlextLdifModels.SchemaObjectClass].ok(
                    oc_data.model_copy(update={"metadata": metadata})
                )
            return result

        # Nested Acl and Entry classes for test API compatibility
    class Acl(FlextLdifServersRfc.Acl):
        """Apache Directory Server ACI quirk.

        Handles ApacheDS ACI (Access Control Instruction) format.
        """

        ACI_ATTRIBUTE_NAMES: ClassVar[frozenset[str]] = frozenset([
            "ads-aci",
            FlextLdifConstants.AclAttributes.ACI,
        ])
        CLAUSE_PATTERN: ClassVar[re.Pattern[str]] = re.compile(r"\([^()]+\)")

        def _can_handle_acl(
            self, acl_line: str | FlextLdifModels.Acl
        ) -> bool:
            """Detect ApacheDS ACI lines."""
            if isinstance(acl_line, str):
                normalized = acl_line.strip() if acl_line else ""
                if not normalized:
                    return False
                attr_name, _, _ = normalized.partition(":")
                if attr_name.strip().lower() in self.ACI_ATTRIBUTE_NAMES:
                    return True
                return normalized.lower().startswith("(version")
            if isinstance(acl_line, FlextLdifModels.Acl):
                if not acl_line.raw_acl:
                    return False
                normalized = acl_line.raw_acl.strip()
                if not normalized:
                    return False

                attr_name, _, _ = normalized.partition(":")
                if attr_name.strip().lower() in self.ACI_ATTRIBUTE_NAMES:
                    return True

                return normalized.lower().startswith("(version")
            return False

        def _parse_acl(self, acl_line: str) -> FlextResult[FlextLdifModels.Acl]:
            """Parse ApacheDS ACI definition."""
            try:
                attr_name, _content = self._splitacl_line(acl_line)

                # Create proper Acl model
                acl_model = FlextLdifModels.Acl(
                    name=f"apache-{attr_name}",
                    target=FlextLdifModels.AclTarget(
                        target_dn="*",
                        attributes=[attr_name] if attr_name else [],
                    ),
                    subject=FlextLdifModels.AclSubject(
                        subject_type=FlextLdifConstants.AclSubjectTypes.ANONYMOUS,
                        subject_value="*",
                    ),
                    permissions=FlextLdifModels.AclPermissions(),
                    server_type=FlextLdifConstants.LdapServers.APACHE_DIRECTORY,
                    raw_acl=acl_line,
                )

                return FlextResult[FlextLdifModels.Acl].ok(acl_model)

            except (ValueError, TypeError, AttributeError) as exc:
                return FlextResult[FlextLdifModels.Acl].fail(
                    f"Apache Directory Server ACL parsing failed: {exc}",
                )

        def _write_acl(self, acl_data: FlextLdifModels.Acl) -> FlextResult[str]:
            """Write ACL data to RFC-compliant string format.

            Apache Directory Server ACLs use ACI format.
            """
            try:
                acl_attribute = getattr(
                    acl_data,
                    FlextLdifConstants.AclKeys.ACL_ATTRIBUTE,
                    FlextLdifConstants.AclKeys.ACI,
                )
                data_raw = getattr(acl_data, "data", {})
                data: dict[str, object] = data_raw if isinstance(data_raw, dict) else {}
                content = data.get("content", "")
                clauses_raw = data.get("clauses", [])
                clauses: list[str] = (
                    clauses_raw if isinstance(clauses_raw, list) else []
                )

                if content:
                    acl_str = f"{acl_attribute}: {content}"
                elif clauses:
                    acl_str = f"{acl_attribute}: {' '.join(clauses)}"
                else:
                    acl_str = f"{acl_attribute}:"

                return FlextResult[str].ok(acl_str)
            except (ValueError, TypeError, AttributeError) as exc:
                return FlextResult[str].fail(
                    f"Apache Directory Server ACL write failed: {exc}",
                )

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

        def parse_entry(
            self,
            entry_dn: str,
            entry_attrs: Mapping[str, object],
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Parse raw LDIF entry data into Entry model with Apache-specific transformations.

            Args:
                entry_dn: Raw DN string from LDIF parser
                entry_attrs: Raw attributes mapping from LDIF parser

            Returns:
                FlextResult with parsed Entry model with Apache-specific metadata

            """
            # First call parent parse_entry to get base Entry model
            base_result = super().parse_entry(entry_dn, entry_attrs)
            if base_result.is_failure:
                return base_result

            entry = base_result.unwrap()

            try:
                # Store metadata in extensions
                metadata = entry.metadata or FlextLdifModels.QuirkMetadata(
                    quirk_type=FlextLdifConstants.LdapServers.APACHE_DIRECTORY
                )
                dn_lower = entry.dn.value.lower()
                if not metadata.extensions:
                    metadata.extensions = {}
                metadata.extensions[FlextLdifConstants.QuirkMetadataKeys.IS_CONFIG_ENTRY] = (
                    "ou=config" in dn_lower
                )

                processed_entry = entry.model_copy(update={"metadata": metadata})

                return FlextResult[FlextLdifModels.Entry].ok(processed_entry)

            except (ValueError, TypeError, AttributeError) as exc:
                return FlextResult[FlextLdifModels.Entry].fail(
                    f"Apache Directory Server entry parsing failed: {exc}",
                )


__all__ = ["FlextLdifServersApache"]
