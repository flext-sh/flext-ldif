"""IBM Tivoli Directory Server quirks implementation."""

from __future__ import annotations

import base64
import re
from collections.abc import Mapping
from typing import ClassVar, Final, cast

from flext_core import FlextResult

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.servers.rfc import FlextLdifServersRfc
from flext_ldif.utilities import FlextLdifUtilities


class FlextLdifServersTivoli(FlextLdifServersRfc):
    """Schema quirks for IBM Tivoli Directory Server."""

    # === STANDARDIZED CONSTANTS FOR AUTO-DISCOVERY ===
    class Constants(FlextLdifServersRfc.Constants):
        """Standardized constants for IBM Tivoli Directory Server quirk."""

        SERVER_TYPE: ClassVar[str] = FlextLdifConstants.ServerTypes.IBM_TIVOLI
        CANONICAL_NAME: ClassVar[str] = "ibm_tivoli"
        ALIASES: ClassVar[frozenset[str]] = frozenset(["ibm_tivoli", "tivoli"])
        PRIORITY: ClassVar[int] = 30
        CAN_NORMALIZE_FROM: ClassVar[frozenset[str]] = frozenset(["ibm_tivoli"])
        CAN_DENORMALIZE_TO: ClassVar[frozenset[str]] = frozenset(["ibm_tivoli", "rfc"])

        # IBM Tivoli ACL format constants
        ACL_FORMAT: ClassVar[str] = "aci"  # Tivoli uses standard ACI
        ACL_ATTRIBUTE_NAME: ClassVar[str] = "aci"  # ACL attribute name

        # IBM Tivoli operational attributes (server-specific)
        OPERATIONAL_ATTRIBUTES: Final[frozenset[str]] = frozenset([
            "ibm-entryUUID",
            "ibm-entryChecksum",
        ])

        # Detection constants (server-specific) - migrated from FlextLdifConstants.LdapServerDetection
        DETECTION_OID_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
            r"\b1\.3\.18\.",
            re.IGNORECASE,
        )
        DETECTION_ATTRIBUTE_PREFIXES: Final[frozenset[str]] = frozenset([
            "ibm-",
            "ids-",
        ])
        DETECTION_OBJECTCLASS_NAMES: Final[frozenset[str]] = frozenset([
            "ibmuser",
            "ibmuniversaldirectoryuser",
            "ibmuniversaldirectorygroup",
            "ibm-slapdaccesscontrolsubentry",
            "ibm-ldapserver",
            "ibm-filterentry",
        ])
        DETECTION_DN_MARKERS: Final[frozenset[str]] = frozenset([
            "o=ibm,c=us",
            "o=example,c=us",
            "cn=REDACTED_LDAP_BIND_PASSWORD",
        ])

        # IBM Tivoli specific attributes (migrated from FlextLdifConstants)
        IBM_TIVOLI_SPECIFIC: Final[frozenset[str]] = frozenset([
            "ibm-entryuuid",
            "ibm-entrychecksum",
            "ibm-passwordchangedtime",
            "ibm-passwordexpirationtime",
            "ibm-passwordallowchangedate",
            "ibm-creationName",
            "ibm-modifyName",
        ])

        # ACL-specific constants (migrated from nested Acl class)
        ACL_ATTRIBUTE_NAMES: Final[frozenset[str]] = frozenset([
            "ibm-slapdaccesscontrol",
            "ibm-slapdgroupacl",
        ])
        ACL_DEFAULT_NAME: Final[str] = "Tivoli ACL"  # Default ACL name for Tivoli DS

    # =========================================================================
    # Class-level attributes for server identification (from Constants)
    # =========================================================================
    server_type: ClassVar[str] = Constants.SERVER_TYPE
    priority: ClassVar[int] = Constants.PRIORITY

    def __init__(self) -> None:
        """Initialize IBM Tivoli Directory Server quirks."""
        super().__init__()
        # Use object.__setattr__ to bypass Pydantic validation for dynamic attributes
        # Nested classes no longer require server_type and priority parameters
        object.__setattr__(self, "schema", self.Schema())
        object.__setattr__(self, "acl", self.Acl())
        object.__setattr__(self, "entry", self.Entry())

    class Schema(FlextLdifServersRfc.Schema):
        """IBM Tivoli Directory Server schema quirks implementation."""

        # INHERITED METHODS (from FlextLdifServersRfc.Schema)
        # These methods are inherited from RFC base class:
        # - _parse_attribute(): Uses RFC parser
        # - _parse_objectclass(): Uses RFC parser
        # - convert_attribute_from_rfc(): RFC conversion
        # - convert_objectclass_from_rfc(): RFC conversion
        # - _write_attribute(): RFC writer
        # - _write_objectclass(): RFC writer
        # - should_filter_out_attribute(): Returns False (no filtering)
        # - should_filter_out_objectclass(): Returns False (no filtering)
        #
        # Only _can_handle_* methods are overridden with Tivoli-specific logic.
        #

        def _can_handle_attribute(
            self, attr_definition: str | FlextLdifModels.SchemaAttribute
        ) -> bool:
            """Detect Tivoli-specific attributes."""
            if isinstance(attr_definition, str):
                if FlextLdifServersTivoli.Constants.DETECTION_OID_PATTERN.search(
                    attr_definition
                ):
                    return True
                attr_lower = attr_definition.lower()
                return any(
                    prefix in attr_lower
                    for prefix in FlextLdifServersTivoli.Constants.DETECTION_ATTRIBUTE_PREFIXES
                )
            if isinstance(attr_definition, FlextLdifModels.SchemaAttribute):
                if FlextLdifServersTivoli.Constants.DETECTION_OID_PATTERN.search(
                    attr_definition.oid
                ):
                    return True
                attr_name_lower = attr_definition.name.lower()
                return any(
                    attr_name_lower.startswith(prefix)
                    for prefix in FlextLdifServersTivoli.Constants.DETECTION_ATTRIBUTE_PREFIXES
                )
            return False

        def _can_handle_objectclass(
            self, oc_definition: str | FlextLdifModels.SchemaObjectClass
        ) -> bool:
            """Detect Tivoli objectClass definitions."""
            if isinstance(oc_definition, str):
                if FlextLdifServersTivoli.Constants.DETECTION_OID_PATTERN.search(
                    oc_definition
                ):
                    return True
                oc_lower = oc_definition.lower()
                return any(
                    oc_name in oc_lower
                    for oc_name in FlextLdifServersTivoli.Constants.DETECTION_OBJECTCLASS_NAMES
                )
            if isinstance(oc_definition, FlextLdifModels.SchemaObjectClass):
                if FlextLdifServersTivoli.Constants.DETECTION_OID_PATTERN.search(
                    oc_definition.oid
                ):
                    return True
                oc_name_lower = oc_definition.name.lower()
                return (
                    oc_name_lower
                    in FlextLdifServersTivoli.Constants.DETECTION_OBJECTCLASS_NAMES
                )
            return False

        def _parse_attribute(
            self,
            attr_definition: str,
        ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
            """Parse attribute definition and add Tivoli metadata.

            Args:
                attr_definition: Attribute definition string

            Returns:
                FlextResult with SchemaAttribute marked with Tivoli metadata

            """
            result = super()._parse_attribute(attr_definition)
            if result.is_success:
                attr_data = result.unwrap()
                metadata = FlextLdifModels.QuirkMetadata.create_for_quirk("ibm_tivoli")
                return FlextResult[FlextLdifModels.SchemaAttribute].ok(
                    attr_data.model_copy(update={"metadata": metadata})
                )
            return result

        def _parse_objectclass(
            self,
            oc_definition: str,
        ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
            """Parse objectClass definition and add Tivoli metadata.

            Args:
                oc_definition: ObjectClass definition string

            Returns:
                FlextResult with SchemaObjectClass marked with Tivoli metadata

            """
            result = super()._parse_objectclass(oc_definition)
            if result.is_success:
                oc_data = result.unwrap()
                metadata = FlextLdifModels.QuirkMetadata.create_for_quirk("ibm_tivoli")
                return FlextResult[FlextLdifModels.SchemaObjectClass].ok(
                    oc_data.model_copy(update={"metadata": metadata})
                )
            return result

        def convert_attribute_from_rfc(
            self,
            rfc_data: FlextLdifModels.SchemaAttribute,
        ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
            """Convert RFC attribute to Tivoli format with metadata.

            Args:
                rfc_data: RFC-compliant SchemaAttribute

            Returns:
                FlextResult with SchemaAttribute marked with Tivoli metadata

            """
            metadata = FlextLdifModels.QuirkMetadata.create_for_quirk("ibm_tivoli")
            result_data = rfc_data.model_copy(update={"metadata": metadata})
            return FlextResult[FlextLdifModels.SchemaAttribute].ok(result_data)

        def convert_objectclass_from_rfc(
            self,
            rfc_data: FlextLdifModels.SchemaObjectClass,
        ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
            """Convert RFC objectClass to Tivoli format with metadata.

            Args:
                rfc_data: RFC-compliant SchemaObjectClass

            Returns:
                FlextResult with SchemaObjectClass marked with Tivoli metadata

            """
            return FlextLdifUtilities.Schema.set_server_type(
                rfc_data, FlextLdifServersTivoli.Constants.SERVER_TYPE
            )

        # Nested class references for Schema - allows Schema().Entry() pattern
        # These are references to the outer class definitions for proper architecture

    class Acl(FlextLdifServersRfc.Acl):
        """IBM Tivoli DS ACL quirk."""

        def _can_handle_acl(self, acl_line: str | FlextLdifModels.Acl) -> bool:
            """Detect Tivoli DS ACL values."""
            if isinstance(acl_line, str):
                normalized = acl_line.strip() if acl_line else ""
                if not normalized:
                    return False
                attr_name, _, _ = normalized.partition(":")
                return (
                    attr_name.strip().lower()
                    in FlextLdifServersTivoli.Constants.ACL_ATTRIBUTE_NAMES
                )
            if isinstance(acl_line, FlextLdifModels.Acl):
                if not acl_line.raw_acl:
                    return False
                normalized = acl_line.raw_acl.strip()
                if not normalized:
                    return False
                attr_name, _, _ = normalized.partition(":")
                return (
                    attr_name.strip().lower()
                    in FlextLdifServersTivoli.Constants.ACL_ATTRIBUTE_NAMES
                )
            return False

        def _parse_acl(self, acl_line: str) -> FlextResult[FlextLdifModels.Acl]:
            """Parse Tivoli DS ACL definition."""
            try:
                _, content = self._splitacl_line(acl_line)

                # Extract access type from brace content
                access_match = re.search(r'access\s+"(\w+)"', content, re.IGNORECASE)
                access_type = (
                    access_match.group(1)
                    if access_match
                    else FlextLdifConstants.PermissionNames.READ
                )

                # Build Acl model with minimal parsing
                acl = FlextLdifModels.Acl(
                    name=FlextLdifServersTivoli.Constants.ACL_DEFAULT_NAME,
                    target=FlextLdifModels.AclTarget(
                        target_dn="",
                        attributes=[],
                    ),
                    subject=FlextLdifModels.AclSubject(
                        subject_type="",
                        subject_value="",
                    ),
                    permissions=FlextLdifModels.AclPermissions(
                        read=(
                            access_type.lower()
                            == FlextLdifConstants.PermissionNames.READ
                        ),
                        write=(
                            access_type.lower()
                            == FlextLdifConstants.PermissionNames.WRITE
                        ),
                    ),
                    server_type=cast(
                        "FlextLdifConstants.LiteralTypes.ServerType",
                        FlextLdifServersTivoli.Constants.SERVER_TYPE,
                    ),
                    raw_acl=acl_line,
                )
                return FlextResult[FlextLdifModels.Acl].ok(acl)

            except (ValueError, TypeError, AttributeError) as exc:
                return FlextResult[FlextLdifModels.Acl].fail(
                    f"IBM Tivoli DS ACL parsing failed: {exc}",
                )

        def _write_acl(self, acl_data: FlextLdifModels.Acl) -> FlextResult[str]:
            """Write ACL data to RFC-compliant string format.

            IBM Tivoli DS ACLs use "#" delimited segments:
            scope#trustee#rights#...
            """
            try:
                # Use Tivoli-specific attribute name
                # Use first ACL attribute name from Constants as default
                acl_attribute = next(
                    iter(FlextLdifServersTivoli.Constants.ACL_ATTRIBUTE_NAMES),
                    "ibm-slapdaccesscontrol",
                )

                # Check for raw_acl first (original ACL string)
                if acl_data.raw_acl:
                    return FlextResult[str].ok(acl_data.raw_acl)

                # Build from model fields
                parts: list[str] = []

                # Add scope (target DN)
                if acl_data.target and acl_data.target.target_dn:
                    parts.append(acl_data.target.target_dn)

                # Add trustee (subject value)
                if acl_data.subject and acl_data.subject.subject_value:
                    parts.append(acl_data.subject.subject_value)

                # Add rights (permissions) as individual strings
                if acl_data.permissions:
                    perms = acl_data.permissions
                    if perms.read:
                        parts.append(FlextLdifConstants.PermissionNames.READ)
                    if perms.write:
                        parts.append(FlextLdifConstants.PermissionNames.WRITE)
                    if perms.add:
                        parts.append(FlextLdifConstants.PermissionNames.ADD)
                    if perms.delete:
                        parts.append(FlextLdifConstants.PermissionNames.DELETE)
                    if perms.search:
                        parts.append(FlextLdifConstants.PermissionNames.SEARCH)
                    if perms.compare:
                        parts.append(FlextLdifConstants.PermissionNames.COMPARE)

                # Build ACL string
                acl_content = "#".join(parts) if parts else ""
                acl_str = (
                    f"{acl_attribute}: {acl_content}"
                    if acl_content
                    else f"{acl_attribute}:"
                )

                return FlextResult[str].ok(acl_str)
            except (ValueError, TypeError, AttributeError) as exc:
                return FlextResult[str].fail(f"IBM Tivoli DS ACL write failed: {exc}")

        @staticmethod
        def _splitacl_line(acl_line: str) -> tuple[str, str]:
            """Split an ACL line into attribute name and payload."""
            attr_name, _, remainder = acl_line.partition(":")
            return attr_name.strip(), remainder.strip()

    class Entry(FlextLdifServersRfc.Entry):
        """IBM Tivoli DS entry quirk."""

        # Entry detection uses Constants.DETECTION_DN_MARKERS and Constants.DETECTION_ATTRIBUTE_PREFIXES

        # OVERRIDDEN METHODS (from FlextLdifServersBase.Entry)
        # These methods override the base class with Tivoli DS-specific logic:
        # - _can_handle_entry(): Detects Tivoli DS entries by DN/attributes
        # - process_entry(): Normalizes Tivoli DS entries with metadata
        # - convert_entry_to_rfc(): Converts Tivoli DS entries to RFC format

        def normalize_dn(self, entry_dn: str) -> str:
            """Normalize DN for Tivoli DS.

            Uses utility DN normalization (RFC 4514 compliant).
            Falls back to lowercase if normalization fails (Tivoli specific).
            """
            normalized = FlextLdifUtilities.DN.norm(entry_dn)
            return normalized or entry_dn.lower()

        def normalize_attribute_name(self, attr_name: str) -> str:
            """Normalize attribute name for Tivoli DS."""
            return attr_name.lower()

        def _can_handle_entry(
            self,
            entry_dn: str,
            attributes: Mapping[str, object],
        ) -> bool:
            """Detect Tivoli DS-specific entries."""
            if not entry_dn:
                return False
            dn_lower = entry_dn.lower()
            if any(
                marker in dn_lower
                for marker in FlextLdifServersTivoli.Constants.DETECTION_DN_MARKERS
            ):
                return True

            normalized_attrs = {
                name.lower(): value for name, value in attributes.items()
            }
            if any(
                marker in normalized_attrs
                for marker in FlextLdifServersTivoli.Constants.DETECTION_ATTRIBUTE_PREFIXES
            ):
                return True

            object_classes_raw = attributes.get(
                FlextLdifConstants.DictKeys.OBJECTCLASS,
                [],
            )
            object_classes = (
                object_classes_raw
                if isinstance(object_classes_raw, list)
                else [object_classes_raw]
            )
            return bool(
                any(
                    str(oc).lower()
                    in FlextLdifServersTivoli.Constants.DETECTION_OBJECTCLASS_NAMES
                    for oc in object_classes
                ),
            )

        def convert_entry_to_rfc(
            self,
            entry_data: FlextLdifModels.Entry,
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Strip IBM Tivoli DS metadata before RFC processing."""
            try:
                # Work directly with LdifAttributes
                attributes = entry_data.attributes.attributes.copy()
                # Remove Tivoli-specific metadata, preserve everything else
                attributes.pop(FlextLdifConstants.QuirkMetadataKeys.SERVER_TYPE, None)
                attributes.pop(
                    FlextLdifConstants.QuirkMetadataKeys.IS_CONFIG_ENTRY, None
                )

                # Create new LdifAttributes directly from the dict
                new_attrs = FlextLdifModels.LdifAttributes(attributes=attributes)

                rfc_entry = entry_data.model_copy(
                    update={"attributes": new_attrs},
                )

                return FlextResult[FlextLdifModels.Entry].ok(rfc_entry)

            except (ValueError, TypeError, AttributeError) as exc:
                return FlextResult[FlextLdifModels.Entry].fail(
                    f"IBM Tivoli DS entry→RFC conversion failed: {exc}",
                )

        def convert_entry_from_rfc(
            self,
            entry_data: FlextLdifModels.Entry,
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Convert RFC entry to Tivoli DS-specific format."""
            try:
                # Work directly with Entry model
                entry_dn = entry_data.dn.value
                attributes = entry_data.attributes.attributes.copy()

                # Normalize DN for Tivoli DS
                normalized_dn = self.normalize_dn(entry_dn)

                # Normalize attribute names - work directly with dict[str, list[str]]
                tivoli_attrs: dict[str, list[str]] = {}
                for key, value in attributes.items():
                    normalized_name = self.normalize_attribute_name(key)
                    tivoli_attrs[normalized_name] = value

                # Create new LdifAttributes directly
                new_attrs = FlextLdifModels.LdifAttributes(attributes=tivoli_attrs)
                new_dn = FlextLdifModels.DistinguishedName(value=normalized_dn)

                tivoli_entry = entry_data.model_copy(
                    update={"dn": new_dn, "attributes": new_attrs},
                )

                return FlextResult[FlextLdifModels.Entry].ok(tivoli_entry)

            except (ValueError, TypeError, AttributeError) as exc:
                return FlextResult[FlextLdifModels.Entry].fail(
                    f"RFC→IBM Tivoli DS entry conversion failed: {exc}",
                )

        def process_entry(
            self,
            entry: FlextLdifModels.Entry,
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Normalise IBM Tivoli DS entries and attach metadata."""
            try:
                entry_dn = entry.dn.value
                attributes = entry.attributes.attributes.copy()
                dn_lower = entry_dn.lower()

                # Get objectClasses directly from attributes (already list[str])
                object_classes = attributes.get(
                    FlextLdifConstants.DictKeys.OBJECTCLASS,
                    [],
                )

                # Process attributes - work directly with dict[str, list[str]]
                # Copy all existing attributes first
                processed_attributes = attributes.copy()

                # Process binary values if any (convert bytes to base64 strings)
                for attr_name, attr_values in processed_attributes.items():
                    processed_values: list[str] = []
                    for value in attr_values:
                        if isinstance(value, bytes):
                            processed_values.append(
                                base64.b64encode(value).decode("utf-8")
                            )
                        else:
                            processed_values.append(str(value))
                    processed_attributes[attr_name] = processed_values

                # Add/update metadata attributes
                processed_attributes[
                    FlextLdifConstants.QuirkMetadataKeys.SERVER_TYPE
                ] = [FlextLdifServersTivoli.Constants.SERVER_TYPE]
                # Check if entry is config entry using Constants markers
                is_config = any(
                    marker in dn_lower
                    for marker in FlextLdifServersTivoli.Constants.DETECTION_DN_MARKERS
                )
                processed_attributes[
                    FlextLdifConstants.QuirkMetadataKeys.IS_CONFIG_ENTRY
                ] = [str(is_config)]
                # Update objectClass (already in list format)
                processed_attributes[FlextLdifConstants.DictKeys.OBJECTCLASS] = (
                    object_classes
                )

                # Create new LdifAttributes directly
                new_attrs = FlextLdifModels.LdifAttributes(
                    attributes=processed_attributes
                )

                processed_entry = entry.model_copy(
                    update={"attributes": new_attrs},
                )

                return FlextResult[FlextLdifModels.Entry].ok(processed_entry)

            except (ValueError, TypeError, AttributeError) as exc:
                return FlextResult[FlextLdifModels.Entry].fail(
                    f"IBM Tivoli DS entry processing failed: {exc}",
                )


__all__ = ["FlextLdifServersTivoli"]
