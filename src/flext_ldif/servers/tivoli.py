"""IBM Tivoli Directory Server quirks implementation.

# Copyright (c) 2025 FLEXT Team. All rights reserved.
# SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import base64
import re
from typing import ClassVar

from flext_core import r

from flext_ldif._utilities.acl import FlextLdifUtilitiesACL
from flext_ldif.constants import c
from flext_ldif.models import m
from flext_ldif.servers._rfc import FlextLdifServersRfcAcl
from flext_ldif.servers.rfc import FlextLdifServersRfc
from flext_ldif.utilities import u


class FlextLdifServersTivoli(FlextLdifServersRfc):
    """Schema quirks for IBM Tivoli Directory Server."""

    # =========================================================================
    class Constants(FlextLdifServersRfc.Constants):
        """Standardized constants for IBM Tivoli Directory Server quirk."""

        # Server identity and priority (defined at Constants level)
        SERVER_TYPE: ClassVar[str] = "ibm_tivoli"
        PRIORITY: ClassVar[int] = 30

        CANONICAL_NAME: ClassVar[str] = "ibm_tivoli"
        ALIASES: ClassVar[frozenset[str]] = frozenset(["tivoli", "ibm_tivoli"])
        CAN_NORMALIZE_FROM: ClassVar[frozenset[str]] = frozenset(["ibm_tivoli"])
        CAN_DENORMALIZE_TO: ClassVar[frozenset[str]] = frozenset(["ibm_tivoli", "rfc"])

        # IBM Tivoli ACL format constants
        ACL_FORMAT: ClassVar[str] = "aci"  # Tivoli uses standard ACI
        ACL_ATTRIBUTE_NAME: ClassVar[str] = "aci"  # ACL attribute name

        # IBM Tivoli operational attributes (server-specific)
        # Migrated from c.OperationalAttributeMappings
        OPERATIONAL_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset(
            [
                "createTimestamp",
                "modifyTimestamp",
                "creatorsName",
                "modifiersName",
                "ibm-entryUUID",
                "ibm-entryChecksum",
            ],
        )

        # NOTE: PRESERVE_ON_MIGRATION inherited from RFC.Constants (createTimestamp, modifyTimestamp)
        # NOTE: SUPPORTED_PERMISSIONS inherited from RFC.Constants (read, write, add, delete, search, compare)
        # NOTE: ATTRIBUTE_ALIASES inherited from RFC.Constants (empty dict)
        # NOTE: PERMISSION_* names inherited from RFC.Constants

        # Detection constants (server-specific) - migrated from c.LdapServerDetection
        # Note: DETECTION_OID_PATTERN as string pattern (not compiled) for base class compatibility
        DETECTION_OID_PATTERN: ClassVar[str] = r"\b1\.3\.18\."
        DETECTION_OID_PATTERN_COMPILED: ClassVar[re.Pattern[str]] = re.compile(
            r"\b1\.3\.18\.",
            re.IGNORECASE,
        )
        DETECTION_ATTRIBUTE_PREFIXES: ClassVar[frozenset[str]] = frozenset(
            [
                "ibm-",
                "ids-",
            ],
        )

        # Server detection patterns and weights (migrated from c.ServerDetection)
        DETECTION_PATTERN_STR: ClassVar[str] = r"\b(ibm|tivoli|ldapdb)\b"
        DETECTION_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
            DETECTION_PATTERN_STR,
            re.IGNORECASE,
        )
        DETECTION_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset(
            [
                "ibm-entryuuid",
                "ibm-entrychecksum",
                "ibm-slapdaccesscontrol",
                "ibm-slapdgroupacl",
            ],
        )
        DETECTION_WEIGHT: ClassVar[int] = 6
        DETECTION_OBJECTCLASS_NAMES: ClassVar[frozenset[str]] = frozenset(
            [
                "ibmuser",
                "ibmuniversaldirectoryuser",
                "ibmuniversaldirectorygroup",
                "ibm-slapdaccesscontrolsubentry",
                "ibm-ldapserver",
                "ibm-filterentry",
            ],
        )
        DETECTION_DN_MARKERS: ClassVar[frozenset[str]] = frozenset(
            [
                "o=ibm",
                "o=example",
                "cn=REDACTED_LDAP_BIND_PASSWORD",
                "cn=configuration",
                "cn=ibm",
            ],
        )

        # IBM Tivoli specific attributes (migrated from FlextLdifConstants)
        IBM_TIVOLI_SPECIFIC: ClassVar[frozenset[str]] = frozenset(
            [
                "ibm-entryuuid",
                "ibm-entrychecksum",
                "ibm-passwordchangedtime",
                "ibm-passwordexpirationtime",
                "ibm-passwordallowchangedate",
                "ibm-creationName",
                "ibm-modifyName",
            ],
        )

        # NOTE: Tivoli inherits RFC baseline for:
        # - ATTRIBUTE_FIELDS, OBJECTCLASS_REQUIREMENTS, ATTRIBUTE_ALIASES

        # ACL-specific constants (migrated from nested Acl class)
        ACL_ATTRIBUTE_NAMES: ClassVar[frozenset[str]] = frozenset(
            [
                "ibm-slapdaccesscontrol",
                "ibm-slapdgroupacl",
            ],
        )
        # Non-Tivoli ACL format markers (for rejection)
        ACL_NON_TIVOLI_MARKERS: ClassVar[frozenset[str]] = frozenset(
            [
                "aci:",
                "version 3.0",
                "allow(",
            ],
        )
        ACL_DEFAULT_NAME: ClassVar[str] = "Tivoli ACL"  # Default ACL name for Tivoli DS

        # ACL parsing patterns (migrated from _parse_acl method)
        ACL_ACCESS_PATTERN: ClassVar[str] = r'access\s+"(\w+)"'

        # ACL default values (migrated from _parse_acl method)
        ACL_DEFAULT_TARGET_DN: ClassVar[str] = ""
        ACL_DEFAULT_SUBJECT_TYPE: ClassVar[
            c.Ldif.LiteralTypes.AclSubjectTypeLiteral
        ] = "all"  # Default to "all" for generic ACL access
        ACL_DEFAULT_SUBJECT_VALUE: ClassVar[str] = ""

        # ACL attribute name constants (migrated from _write_acl method)
        ACL_PRIMARY_ATTRIBUTE_NAME: ClassVar[str] = "ibm-slapdaccesscontrol"

        # ACL separator for Tivoli format (migrated from _write_acl method)
        ACL_SEPARATOR: ClassVar[str] = "#"

        # === ACL AND ENCODING CONSTANTS (Centralized) ===
        # Use centralized StrEnums from FlextLdifConstants directly
        # No duplicate nested StrEnums - use c.Ldif.AclPermission,
        # c.Ldif.AclAction, and c.Ldif.Encoding directly

    # =========================================================================
    # Server identification - accessed via Constants via properties in base.py
    # =========================================================================
    # NOTE: server_type and priority are accessed via properties in base.py
    # which read from Constants.SERVER_TYPE and Constants.PRIORITY

    class Schema(FlextLdifServersRfc.Schema):
        """IBM Tivoli Directory Server schema quirks implementation."""

        # INHERITED METHODS (from FlextLdifServersRfc.Schema)
        # These methods are inherited from RFC base class:
        # - _parse_attribute(): Uses RFC parser
        # - _parse_objectclass(): Uses RFC parser
        # - _write_attribute(): RFC writer
        # - _write_objectclass(): RFC writer
        # - should_filter_out_attribute(): Returns False (no filtering)
        # - should_filter_out_objectclass(): Returns False (no filtering)
        #
        # Only can_handle_* methods are overridden with Tivoli-specific logic.
        #

        def can_handle_attribute(
            self,
            attr_definition: str | m.Ldif.SchemaAttribute,
        ) -> bool:
            """Detect Tivoli-specific attributes."""
            if isinstance(attr_definition, m.Ldif.SchemaAttribute):
                return u.Ldif.Server.matches_server_patterns(
                    value=attr_definition,
                    oid_pattern=FlextLdifServersTivoli.Constants.DETECTION_OID_PATTERN,
                    detection_names=FlextLdifServersTivoli.Constants.DETECTION_ATTRIBUTE_PREFIXES,
                    use_prefix_match=True,
                )
            # For string definitions
            if FlextLdifServersTivoli.Constants.DETECTION_OID_PATTERN_COMPILED.search(
                attr_definition,
            ):
                return True
            attr_lower = attr_definition.lower()
            return any(
                prefix in attr_lower
                for prefix in FlextLdifServersTivoli.Constants.DETECTION_ATTRIBUTE_PREFIXES
            )

        def can_handle_objectclass(
            self,
            oc_definition: str | m.Ldif.SchemaObjectClass,
        ) -> bool:
            """Detect Tivoli objectClass definitions."""
            if isinstance(oc_definition, m.Ldif.SchemaObjectClass):
                return u.Ldif.Server.matches_server_patterns(
                    value=oc_definition,
                    oid_pattern=FlextLdifServersTivoli.Constants.DETECTION_OID_PATTERN,
                    detection_names=FlextLdifServersTivoli.Constants.DETECTION_OBJECTCLASS_NAMES,
                )
            # For string definitions
            if FlextLdifServersTivoli.Constants.DETECTION_OID_PATTERN_COMPILED.search(
                oc_definition,
            ):
                return True
            oc_lower = oc_definition.lower()
            return any(
                oc_name in oc_lower
                for oc_name in FlextLdifServersTivoli.Constants.DETECTION_OBJECTCLASS_NAMES
            )

        def _parse_attribute(
            self,
            attr_definition: str,
        ) -> r[m.Ldif.SchemaAttribute]:
            """Parse attribute definition and add Tivoli metadata.

            Args:
                attr_definition: Attribute definition string

            Returns:
                r with SchemaAttribute marked with Tivoli metadata

            """
            result = super()._parse_attribute(attr_definition)
            if result.is_success:
                attr_data = result.value
                metadata = m.Ldif.QuirkMetadata.create_for("ibm_tivoli")
                return r[m.Ldif.SchemaAttribute].ok(
                    attr_data.model_copy(
                        update={"metadata": metadata},
                    ),
                )
            return result

        def _parse_objectclass(
            self,
            oc_definition: str,
        ) -> r[m.Ldif.SchemaObjectClass]:
            """Parse objectClass definition and add Tivoli metadata.

            Args:
                oc_definition: ObjectClass definition string

            Returns:
                r with SchemaObjectClass marked with Tivoli metadata

            """
            result = super()._parse_objectclass(oc_definition)
            if result.is_success:
                oc_data = result.value
                metadata = m.Ldif.QuirkMetadata.create_for("ibm_tivoli")
                return r[m.Ldif.SchemaObjectClass].ok(
                    oc_data.model_copy(
                        update={"metadata": metadata},
                    ),
                )
            return result

    class Acl(FlextLdifServersRfcAcl):  # type: ignore[override]
        """IBM Tivoli Directory Server ACL quirks implementation."""

        def can_handle(self, acl_line: str | m.Ldif.Acl) -> bool:
            """Check if this ACL is a Tivoli DS ACL."""
            if isinstance(acl_line, str):
                return self.can_handle_acl(acl_line)
            if isinstance(acl_line, m.Ldif.Acl):
                if not acl_line.raw_acl:
                    return False
                return self.can_handle_acl(acl_line.raw_acl)
            return False

        def can_handle_acl(self, acl_line: str | m.Ldif.Acl) -> bool:
            """Detect Tivoli DS ACL values."""
            if isinstance(acl_line, str):
                normalized = acl_line.strip() if acl_line else ""
                if not normalized:
                    return False
                # Reject non-Tivoli ACL formats (ACI, version 3.0, etc.)
                normalized_lower = normalized.lower()
                for marker in FlextLdifServersTivoli.Constants.ACL_NON_TIVOLI_MARKERS:
                    if marker in normalized_lower:
                        return False
                attr_name, _, _ = normalized.partition(":")
                attr_name_lower = attr_name.strip().lower()
                if not attr_name_lower:
                    return False
                return (
                    attr_name_lower
                    in FlextLdifServersTivoli.Constants.ACL_ATTRIBUTE_NAMES
                )
            if isinstance(acl_line, m.Ldif.Acl):
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

        def _parse_acl(self, acl_line: str) -> r[m.Ldif.Acl]:
            """Parse Tivoli DS ACL definition."""
            try:
                attr_name, content = FlextLdifUtilitiesACL.split_acl_line(acl_line)
                _ = attr_name  # Unused but required for tuple unpacking

                # Extract access type from brace content
                access_match = re.search(
                    FlextLdifServersTivoli.Constants.ACL_ACCESS_PATTERN,
                    content,
                    re.IGNORECASE,
                )
                access_type = (
                    access_match.group(1)
                    if access_match
                    else FlextLdifServersTivoli.Constants.PERMISSION_READ
                )

                # Build Acl model with minimal parsing
                acl = m.Ldif.Acl(
                    name=FlextLdifServersTivoli.Constants.ACL_DEFAULT_NAME,
                    target=m.Ldif.AclTarget(
                        target_dn=FlextLdifServersTivoli.Constants.ACL_DEFAULT_TARGET_DN,
                        attributes=[],
                    ),
                    subject=m.Ldif.AclSubject(
                        subject_type=FlextLdifServersTivoli.Constants.ACL_DEFAULT_SUBJECT_TYPE,
                        subject_value=FlextLdifServersTivoli.Constants.ACL_DEFAULT_SUBJECT_VALUE,
                    ),
                    permissions=m.Ldif.AclPermissions(
                        read=(
                            access_type.lower()
                            == FlextLdifServersTivoli.Constants.PERMISSION_READ
                        ),
                        write=(
                            access_type.lower()
                            == FlextLdifServersTivoli.Constants.PERMISSION_WRITE
                        ),
                    ),
                    server_type=self._get_server_type(),
                    raw_acl=acl_line,
                )
                return r[m.Ldif.Acl].ok(acl)

            except (ValueError, TypeError, AttributeError) as exc:
                return r[m.Ldif.Acl].fail(
                    f"IBM Tivoli DS ACL parsing failed: {exc}",
                )

        def _write_acl(self, acl_data: m.Ldif.Acl) -> r[str]:
            """Write ACL data to RFC-compliant string format.

            IBM Tivoli DS ACLs use "#" delimited segments:
            scope#trustee#rights#...
            """
            try:
                # Use Tivoli-specific attribute name
                # Default to primary ACL attribute name from Constants
                # Use primary ACL attribute name directly - no fallback
                acl_attribute = (
                    FlextLdifServersTivoli.Constants.ACL_PRIMARY_ATTRIBUTE_NAME
                )

                # Check for raw_acl first (original ACL string)
                if acl_data.raw_acl:
                    return r[str].ok(acl_data.raw_acl)

                # Build from model fields
                parts: list[str] = []

                # Add scope (target DN)
                if acl_data.target and acl_data.target.target_dn:
                    parts.append(acl_data.target.target_dn)

                # Add trustee (subject value)
                if acl_data.subject and acl_data.subject.subject_value:
                    parts.append(acl_data.subject.subject_value)

                # Add rights - collect active permissions from permissions dict
                # Map canonical permission names to Tivoli format
                permission_map = {
                    "read": FlextLdifServersTivoli.Constants.PERMISSION_READ,
                    "write": FlextLdifServersTivoli.Constants.PERMISSION_WRITE,
                    "add": FlextLdifServersTivoli.Constants.PERMISSION_ADD,
                    "delete": FlextLdifServersTivoli.Constants.PERMISSION_DELETE,
                    "search": FlextLdifServersTivoli.Constants.PERMISSION_SEARCH,
                    "compare": FlextLdifServersTivoli.Constants.PERMISSION_COMPARE,
                }
                active_perms: list[str] = []
                if acl_data.permissions:
                    # AclPermissions is a Pydantic model, convert to dict for iteration
                    perms_dict = acl_data.permissions.model_dump()
                    for perm_name, perm_value in perms_dict.items():
                        # Only include permissions that are True (allowed)
                        if perm_value is True and perm_name in permission_map:
                            active_perms.append(permission_map[perm_name])
                parts.extend(active_perms)

                # Build ACL string
                acl_content = (
                    FlextLdifServersTivoli.Constants.ACL_SEPARATOR.join(parts)
                    if parts
                    else ""
                )
                acl_str = (
                    f"{acl_attribute}: {acl_content}"
                    if acl_content
                    else f"{acl_attribute}:"
                )

                return r[str].ok(acl_str)
            except (ValueError, TypeError, AttributeError) as exc:
                return r[str].fail(f"IBM Tivoli DS ACL write failed: {exc}")

    class Entry(FlextLdifServersRfc.Entry):
        """IBM Tivoli DS entry quirk."""

        # Entry detection uses Constants.DETECTION_DN_MARKERS and Constants.DETECTION_ATTRIBUTE_PREFIXES

        # OVERRIDDEN METHODS (from FlextLdifServersBase.Entry)
        # These methods override the base class with Tivoli DS-specific logic:
        # - can_handle(): Detects Tivoli DS entries by DN/attributes
        # - process_entry(): Normalizes Tivoli DS entries with metadata

        def normalize_dn(self, entry_dn: str) -> str:
            """Normalize DN for Tivoli DS.

            Uses utility DN normalization (RFC 4514 compliant).
            Falls back to lowercase if normalization fails (Tivoli specific).
            """
            norm_result = u.Ldif.DN.norm(entry_dn)
            if norm_result.is_success:
                return norm_result.value
            # Fallback to lowercase if normalization fails (Tivoli specific)
            return entry_dn.lower()

        def normalize_attribute_name(self, attr_name: str) -> str:
            """Normalize attribute name for Tivoli DS."""
            return attr_name.lower()

        def can_handle(
            self,
            entry_dn: str,
            attributes: dict[str, list[str]],
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

            # Check for Tivoli-specific attribute prefixes
            normalized_attrs = {
                name.lower(): value for name, value in attributes.items()
            }
            if any(
                attr_name.startswith(prefix)
                for attr_name in normalized_attrs
                for prefix in FlextLdifServersTivoli.Constants.DETECTION_ATTRIBUTE_PREFIXES
            ):
                return True

            object_classes_raw: list[str] = u.mapper().get(
                attributes,
                c.Ldif.DictKeys.OBJECTCLASS,
                default=[],
            )
            if isinstance(object_classes_raw, list):
                object_classes: list[str] = object_classes_raw
            elif isinstance(object_classes_raw, tuple):
                object_classes = list(object_classes_raw)
            else:
                object_classes = [str(object_classes_raw)]
            return bool(
                any(
                    str(oc).lower()
                    in FlextLdifServersTivoli.Constants.DETECTION_OBJECTCLASS_NAMES
                    for oc in object_classes
                ),
            )

        def process_entry(
            self,
            entry: m.Ldif.Entry,
        ) -> r[m.Ldif.Entry]:
            """Normalise IBM Tivoli DS entries and attach metadata."""
            try:
                # Check if entry has DN and attributes - fast fail if missing
                if not entry.dn:
                    return r[m.Ldif.Entry].fail(
                        "Entry DN is required for Tivoli DS normalization",
                    )
                if not entry.attributes:
                    return r[m.Ldif.Entry].fail(
                        "Entry attributes are required for Tivoli DS normalization",
                    )

                entry_dn = entry.dn.value
                attributes = entry.attributes.attributes.copy()
                dn_lower = entry_dn.lower()

                # Get objectClasses directly from attributes (already list[str])
                object_classes: list[str] = u.mapper().get(
                    attributes,
                    c.Ldif.DictKeys.OBJECTCLASS,
                    default=[],
                )

                # Process attributes - work directly with dict[str, list[str]]
                # Copy all existing attributes first
                processed_attributes = attributes.copy()

                # Process binary values if any (convert bytes to base64 strings)
                for attr_name, attr_values in processed_attributes.items():
                    processed_values: list[str] = []
                    value: bytes | str
                    for value in attr_values:
                        # Explicitly handle both bytes and str types
                        str_value: str
                        if isinstance(value, bytes):
                            str_value = base64.b64encode(value).decode("utf-8")
                        else:
                            str_value = str(value)
                        processed_values.append(str_value)
                    processed_attributes[attr_name] = processed_values

                # Add/update metadata attributes
                processed_attributes[c.Ldif.Domain.QuirkMetadataKeys.SERVER_TYPE] = [
                    self._get_server_type(),
                ]
                # Check if entry is config entry using Constants markers
                is_config = any(
                    marker in dn_lower
                    for marker in FlextLdifServersTivoli.Constants.DETECTION_DN_MARKERS
                )
                processed_attributes[
                    c.Ldif.Domain.QuirkMetadataKeys.IS_CONFIG_ENTRY
                ] = [
                    str(is_config),
                ]
                # Update objectClass (already in list format)
                processed_attributes[c.Ldif.DictKeys.OBJECTCLASS] = object_classes

                # Create new Attributes directly
                new_attrs = m.Ldif.Attributes(
                    attributes=processed_attributes,
                )

                processed_entry = entry.model_copy(
                    update={"attributes": new_attrs},
                )

                return r[m.Ldif.Entry].ok(processed_entry)

            except (ValueError, TypeError, AttributeError) as exc:
                return r[m.Ldif.Entry].fail(
                    f"IBM Tivoli DS entry processing failed: {exc}",
                )


__all__ = ["FlextLdifServersTivoli"]
