"""Oracle Internet Directory (OID) Quirks.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Implements Oracle OID-specific extensions as quirks on top of RFC-compliant
base parsers. This wraps existing OID parser logic as composable quirks.

OID-specific features:
- Oracle OID attribute types (2.16.840.1.113894.* namespace)
- Oracle orclaci and orclentrylevelaci ACLs
- Oracle-specific schema attributes
- Oracle operational attributes
"""

from __future__ import annotations

import json
from functools import reduce

from flext_core import FlextLogger, FlextResult

from flext_ldif._models.metadata import FlextLdifModelsMetadata
from flext_ldif._utilities.acl import FlextLdifUtilitiesACL
from flext_ldif._utilities.dn import FlextLdifUtilitiesDN
from flext_ldif._utilities.entry import FlextLdifUtilitiesEntry
from flext_ldif._utilities.metadata import FlextLdifUtilitiesMetadata
from flext_ldif.constants import c
from flext_ldif.models import m
from flext_ldif.servers._oid.constants import FlextLdifServersOidConstants
from flext_ldif.servers.rfc import FlextLdifServersRfc
from flext_ldif.typings import t
from flext_ldif.utilities import u

logger = FlextLogger(__name__)


class FlextLdifServersOidEntry(FlextLdifServersRfc.Entry):
    r"""Oracle Internet Directory (OID) Entry implementation.

    OID vs RFC Entry Differences
    ============================
    Oracle OID exports entries in a format that deviates from RFC 2849/4517
    in several ways. This class normalizes OID-specific formats to
    RFC-compliant structures during parsing (Phase 1), and denormalizes
    back to OID format when writing (Phase 2).

    1. BOOLEAN ATTRIBUTE FORMAT
    ---------------------------
    RFC 4517 Section 3.3.3 (Boolean):
        Boolean = "TRUE" / "FALSE"

    OID Proprietary Format (Oracle Fusion Middleware):
        Boolean = "0" / "1"
        - "0" = FALSE
        - "1" = TRUE

    OID Boolean Attributes (Constants.BOOLEAN_ATTRIBUTES):
        - orclIsEnabled: Account enabled flag
        - orclSAMLEnable: SAML authentication enabled
        - orclSSLEnable: SSL/TLS enabled
        - orclIsVisible: Entry visibility
        - orclPasswordVerify: Password verification
        - orclAccountLocked: Account lockout status
        - orclPwdMustChange: Force password change

    Transformation Example:
        Input (OID LDIF):
            orclIsEnabled: 1
            orclAccountLocked: 0

        Output (RFC-normalized):
            orclIsEnabled: TRUE
            orclAccountLocked: FALSE

    2. ACL ATTRIBUTE NAMES
    ----------------------
    RFC 4876 / Draft-ietf-ldapext-aci (Standard ACI):
        aci: (target) (version X.X; acl "name"; action;)

    OID Proprietary Names (Oracle Internet Directory):
        orclaci: access to <target> by <subject> (<perms>)
        orclentrylevelaci: access to <target> by <subject> (<perms>)

    Transformation (Parsing):
        orclaci → aci
        orclentrylevelaci → aci

    Both OID ACL attributes are normalized to RFC "aci" during parsing.
    Original names are preserved in metadata for round-trip support.

    3. SCHEMA DN NORMALIZATION
    --------------------------
    RFC 4512 Section 4.2 (Subschema Subentry):
        Recommended DN: cn=schema (or cn=Subschema)

    OID Proprietary Schema DN:
        cn=subschemasubentry

    Transformation:
        cn=subschemasubentry → cn=schema

    This enables cross-server schema comparison and migration.

    4. OID-SPECIFIC OPERATIONAL ATTRIBUTES
    --------------------------------------
    OID adds proprietary operational attributes not in RFC 4512:
        - orclguid: Oracle-generated GUID (128-bit)
        - orclnormdn: Normalized DN (internal use)
        - orclaci: Access control list (subtree scope)
        - orclentrylevelaci: Entry-level ACL (no inheritance)
        - orclmodifiersname: Last modifier DN
        - orclmodifytimestamp: Modification timestamp (OID format)
        - orclcreatorsname: Creator DN
        - orclcreatetimestamp: Creation timestamp (OID format)

    These are preserved during parsing but flagged as operational
    in metadata for filtering during migration.

    5. RFC COMPLIANCE VALIDATION
    ----------------------------
    OID allows configurations that violate RFC 4512:

    a) Multiple Structural ObjectClasses:
        RFC 4512 Section 2.4.1:
            "An entry's objectClasses form a hierarchy..."
            "Exactly one structural objectClass chain must exist"

        OID allows (non-RFC):
            objectClass: person
            objectClass: organizationalUnit
            (Two structural classes = RFC violation)

        This class detects and flags such violations in metadata.

    b) Invalid Attributes for ObjectClass:
        RFC 4519 defines allowed attributes per objectClass.

        OID allows (non-RFC):
            objectClass: domain
            cn: Example    (cn not allowed by RFC 4519 domain)

        Such conflicts are detected and stored in metadata.

    6. DN CLEANING AND NORMALIZATION
    --------------------------------
    OID DNs may contain non-RFC characters or spacing:
        Input:  "cn= John Doe , ou=People,dc=example,dc=com"
        Output: "cn=John Doe,ou=People,dc=example,dc=com"

    Cleaning operations (via u.Ldif.DN):
        - Remove extra whitespace around RDN separators
        - Normalize attribute name casing (CN → cn)
        - Remove trailing separators

    7. METADATA TRACKING (ROUND-TRIP SUPPORT)
    -----------------------------------------
    All transformations are tracked in Entry.metadata for perfect
    round-trip support (OID → RFC → OID):

    metadata.extensions:
        - original_attributes_complete: Raw attributes before conversion
        - boolean_conversions: {attr: {original: [...], converted: [...]}}
        - oid_converted_attrs: List of converted attribute names
        - attribute_name_conversions: {orclaci: aci, ...}

    metadata.original_format_details:
        - original_dn: Raw DN before cleaning
        - original_dn_line: Raw "dn:" line from LDIF
        - original_attr_lines: Raw attribute lines from LDIF
        - boolean_format: "0/1"
        - server_type: "oid"

    Example LDIF Input (OID)
    ========================
    dn: cn=REDACTED_LDAP_BIND_PASSWORD,ou=People,dc=example,dc=com
    objectClass: person
    objectClass: organizationalPerson
    objectClass: orcluser
    cn: REDACTED_LDAP_BIND_PASSWORD
    sn: Administrator
    orclIsEnabled: 1
    orclAccountLocked: 0
    orclaci: access to entry by self (write)
    orclguid: 1234567890ABCDEF

    Example Parsed Entry (RFC-normalized)
    =====================================
    Entry(
        dn=DN(value="cn=REDACTED_LDAP_BIND_PASSWORD,ou=People,dc=example,dc=com"),
        attributes=Attributes(
            attributes={
                "objectClass": ["person", "organizationalPerson", "orcluser"],
                "cn": ["REDACTED_LDAP_BIND_PASSWORD"],
                "sn": ["Administrator"],
                "orclIsEnabled": ["TRUE"],      # Converted from "1"
                "orclAccountLocked": ["FALSE"], # Converted from "0"
                "aci": ["access to entry by self (write)"],  # Renamed
                "orclguid": ["1234567890ABCDEF"],
            }
        ),
        metadata=QuirkMetadata(
            server_type="oid",
            extensions={
                "conversion_boolean_conversions": {
                    "orclIsEnabled": {"conversion_original_value": ["1"], "conversion_converted_value": ["TRUE"]},
                    "orclAccountLocked": {"conversion_original_value": ["0"], "conversion_converted_value": ["FALSE"]},
                },
                c.Ldif.MetadataKeys.CONVERSION_ATTRIBUTE_NAME_CONVERSIONS: {"orclaci": "aci"},
                ...
            }
        )
    )

    Oracle Documentation References
    ================================
    - Oracle Fusion Middleware Administrator's Guide for Oracle Internet Directory:
      https://docs.oracle.com/cd/E29127_01/doc.111170/e28967/toc.htm
    - Oracle Directory Services LDIF Export Guide:
      https://docs.oracle.com/cd/E28280_01/REDACTED_LDAP_BIND_PASSWORD.1111/e10029/export_ldif.htm
    - Oracle Internet Directory Attribute Reference:
      https://docs.oracle.com/cd/E28280_01/REDACTED_LDAP_BIND_PASSWORD.1111/e10029/oid_schema_elements.htm

    """

    def _hook_transform_entry_raw(
        self,
        dn: str,
        attrs: dict[str, list[str | bytes]],
    ) -> FlextResult[tuple[str, dict[str, list[str | bytes]]]]:
        """Transform OID-specific DN and attributes before RFC parsing.

        OID-Specific Transformations:
        1. Schema DN: cn=subschemasubentry → cn=schema (RFC standard)
        2. DN cleaning: Normalize whitespace and RDN separators

        This hook enables OID entries to be parsed using RFC's generic
        _parse_entry without requiring a full method override.

        Args:
            dn: Original OID distinguished name
            attrs: Original OID attributes dictionary

        Returns:
            FlextResult with tuple of (normalized_dn, attrs)

        """
        # Clean DN using utility
        cleaned_dn, _ = FlextLdifUtilitiesDN.clean_dn_with_statistics(dn)

        # Normalize OID schema DN to RFC format
        # OID uses "cn=subschemasubentry", RFC uses "cn=schema"
        normalized_dn = cleaned_dn
        if cleaned_dn.lower() == FlextLdifServersOidConstants.SCHEMA_DN_QUIRK.lower():
            normalized_dn = FlextLdifServersRfc.Constants.SCHEMA_DN
            logger.debug(
                "OID→RFC transform: Normalizing schema DN",
                original_dn=cleaned_dn,
                normalized_dn=normalized_dn,
            )

        return FlextResult.ok((normalized_dn, attrs))

    def _normalize_attribute_name(self, attr_name: str) -> str:
        """Normalize OID attribute names to RFC-canonical format.

        Converts Oracle OID-specific attribute names to RFC standard equivalents.
        This transformation happens during the PARSING phase (Phase 1) to create
        RFC-canonical entries that can be processed uniformly by downstream logic.

        Transformations:
        - orclaci → aci: OID access control list to RFC ACI
        - orclentrylevelaci → aci: OID entry-level ACL to RFC ACI

        All other attributes are delegated to the RFC base implementation for
        standard normalization (e.g., objectclass → objectClass).

        Args:
            attr_name: Raw attribute name from LDIF

        Returns:
            RFC-canonical attribute name

        """
        # Python 3.13 match/case: Optimize ACL attribute normalization (DRY)
        match attr_name.lower():
            case attr_lower if attr_lower in {
                FlextLdifServersOidConstants.ORCLACI.lower(),
                FlextLdifServersOidConstants.ORCLENTRYLEVELACI.lower(),
            }:
                # Oracle OID ACL attributes → RFC standard ACI
                return FlextLdifServersRfc.Constants.ACL_ATTRIBUTE_NAME
            case _:
                # Delegate to RFC for standard normalization (objectclass, etc.)
                return super()._normalize_attribute_name(attr_name)

    def _convert_boolean_attributes_to_rfc(
        self,
        entry_attributes: dict[str, list[str]],
    ) -> tuple[
        dict[str, list[str]],
        set[str],
        dict[str, dict[str, str | list[str]]],
    ]:
        """Convert OID boolean attribute values to RFC format.

        OID uses "0"/"1" for boolean values, RFC4517 requires "TRUE"/"FALSE".
        Uses utilities.py for conversion (DRY principle).

        Args:
            entry_attributes: Entry attributes mapping

        Returns:
            Tuple: (converted_attrs, converted_set, boolean_conversions)

        """
        boolean_attributes = FlextLdifServersOidConstants.BOOLEAN_ATTRIBUTES
        boolean_attr_names = {attr.lower() for attr in boolean_attributes}

        # Use utilities.py for conversion (OID→RFC: "0/1" → "TRUE/FALSE")

        converted_attrs_for_util: dict[str, list[str]] = dict(
            entry_attributes.items(),
        )
        # Use constants for boolean format strings (DRY: avoid hardcoding)
        # Format strings must match _convert_single_boolean_value expectations:
        # - source_format "0/1" or "TRUE/FALSE"
        # - target_format "0/1" or "TRUE/FALSE"
        source_format = f"{FlextLdifServersOidConstants.ZERO_OID}/{FlextLdifServersOidConstants.ONE_OID}"
        target_format = "TRUE/FALSE"
        converted_attributes = FlextLdifUtilitiesEntry.convert_boolean_attributes(
            converted_attrs_for_util,
            boolean_attr_names,
            source_format=source_format,
            target_format=target_format,
        )

        # Track conversions for metadata
        converted_attrs: set[str] = set()
        boolean_conversions: dict[str, dict[str, str | list[str]]] = {}

        for attr_name, attr_values in u.mapper().to_dict(entry_attributes).items():
            if attr_name.lower() in boolean_attr_names:
                original_values = list(attr_values)
                # When default is provided, mapper().get returns the value directly
                converted_values = u.mapper().get(
                    converted_attributes, attr_name, default=original_values
                )

                if converted_values != original_values:
                    converted_attrs.add(attr_name)
                    # Track conversion for perfect round-trip
                    # Use constants for format strings (DRY: avoid hardcoding)
                    # Format: "TRUE_VALUE/FALSE_VALUE" (matches utility expectations)
                    original_format_str = f"{FlextLdifServersOidConstants.ONE_OID}/{FlextLdifServersOidConstants.ZERO_OID}"
                    converted_format_str = (
                        f"{c.BooleanFormats.TRUE_RFC}/{c.BooleanFormats.FALSE_RFC}"
                    )
                    # Use standardized nested metadata keys (DRY: avoid hardcoding)
                    mk_conv = c.Ldif.MetadataKeys
                    boolean_conversions[attr_name] = {
                        mk_conv.CONVERSION_ORIGINAL_VALUE: original_values,
                        mk_conv.CONVERSION_CONVERTED_VALUE: converted_values,
                        "conversion_type": "boolean_oid_to_rfc",
                        c.Ldif.MetadataKeys.ORIGINAL_FORMAT: original_format_str,
                        "converted_format": converted_format_str,
                    }
                    logger.debug(
                        "Converted boolean attribute OID→RFC",
                        attribute_name=attr_name,
                    )

        return converted_attributes, converted_attrs, boolean_conversions

    def _detect_entry_acl_transformations(
        self,
        entry_attrs: dict[str, list[str]],
        converted_attributes: dict[str, list[str]],
    ) -> dict[str, m.Ldif.AttributeTransformation]:
        """Detect ACL attribute transformations (orclaci→aci).

        Args:
            entry_attrs: Original raw attributes from LDIF
            converted_attributes: Converted attributes mapping

        Returns:
            Dictionary of ACL transformations

        """
        # Python 3.13: Dict comprehension for original_attr_names mapping
        original_attr_names: dict[str, str] = {
            normalized.lower(): str(raw_attr_name)
            for raw_attr_name in entry_attrs
            if (
                normalized := self._normalize_attribute_name(str(raw_attr_name))
            ).lower()
            != str(raw_attr_name).lower()
        }

        # Python 3.13: Dict comprehension for ACL transformations
        acl_transformations: dict[str, m.Ldif.AttributeTransformation] = {
            original_name: m.Ldif.AttributeTransformation(
                original_name=original_name,
                target_name=attr_name,
                original_values=attr_values,
                target_values=attr_values,
                transformation_type="renamed",
                reason=f"OID ACL ({original_name}) → RFC 2256 (aci)",
            )
            for attr_name, attr_values in converted_attributes.items()
            if attr_name.lower() in original_attr_names
            and (original_name := original_attr_names[attr_name.lower()]).lower()
            in {"orclaci", "orclentrylevelaci"}
        }

        return acl_transformations

    def _detect_rfc_violations(
        self,
        converted_attributes: dict[str, list[str]],
    ) -> tuple[list[str], list[dict[str, str | list[str]]]]:
        """Detect RFC compliance violations in entry.

        Args:
            converted_attributes: Entry attributes

        Returns:
            Tuple of (rfc_violations, attribute_conflicts)

        """
        # When default is provided, mapper().get returns the value directly
        object_classes = u.mapper().get(converted_attributes, "objectClass", default=[])
        object_classes_lower = {oc.lower() for oc in object_classes}

        # Python 3.13: Set operations and list comprehensions
        structural_classes = {
            "domain",
            "organization",
            "organizationalunit",
            "person",
            "groupofuniquenames",
            "groupofnames",
            "orclsubscriber",
            "orclgroup",
            "customsistemas",
            "customuser",
        }
        found_structural = object_classes_lower & structural_classes

        structural_str = ", ".join(sorted(found_structural))
        rfc_violations: list[str] = (
            [f"Multiple structural objectClasses: {structural_str}"]
            if len(found_structural) > 1
            else []
        )

        # Python 3.13: List comprehension for attribute conflicts
        domain_invalid_attrs = {
            "cn",
            "uniquemember",
            "member",
            "orclsubscriberfullname",
            "orclversion",
            "orclgroupcreatedate",
        }
        attribute_conflicts: list[dict[str, str | list[str]]] = [
            {
                "attribute": attr_name,
                "values": converted_attributes[attr_name],
                "reason": f"'{attr_name}' not allowed by RFC 4519 domain",
                "conflicting_objectclass": "domain",
            }
            for attr_name in converted_attributes
            if "domain" in object_classes_lower
            and attr_name.lower() in domain_invalid_attrs
        ]

        return rfc_violations, attribute_conflicts

    def normalize_schema_strings_inline(
        self,
        entry: m.Ldif.Entry,
    ) -> m.Ldif.Entry:
        """Normalize schema attribute strings (attributetypes, objectclasses).

        Applies OID-specific normalizations to schema definition strings stored
        as attribute values. Fixes typos and normalizes matching rules in schema
        entries before they are parsed into SchemaAttribute/SchemaObjectClass.

        Normalizations applied:
        - Matching rule typos: caseIgnoreSubStringsMatch → caseIgnoreSubstringsMatch
        - Other OID proprietary → RFC 4517 standard mappings

        Args:
            entry: Entry with potential schema attributes to normalize

        Returns:
            Entry with normalized schema attribute strings

        """
        if not entry.attributes:
            return entry

        # Schema attribute names (case-insensitive)
        # Use SCHEMA_FILTERABLE_FIELDS which already contains lowercase names
        schema_attrs = FlextLdifServersOidConstants.SCHEMA_FILTERABLE_FIELDS

        # Check if entry has schema attributes (Python 3.13: early return)
        if not any(
            attr_name.lower() in schema_attrs
            for attr_name in entry.attributes.attributes
        ):
            return entry

        # Get matching rule replacements from constants (DRY: Python 3.13)
        replacements = FlextLdifServersOidConstants.MATCHING_RULE_TO_RFC

        # Normalize schema attribute values (DRY: Python 3.13 optimized)
        # Python 3.13: Dict comprehension with conditional
        new_attributes: dict[str, list[str]] = {
            attr_name: (
                [
                    reduce(
                        lambda val, pair: val.replace(pair[0], pair[1]),
                        replacements.items(),
                        value,
                    )
                    for value in attr_values
                ]
                if attr_name.lower() in schema_attrs
                else attr_values
            )
            for attr_name, attr_values in u.mapper()
            .to_dict(entry.attributes.attributes)
            .items()
        }

        # Only create new entry if attributes changed
        if new_attributes == entry.attributes.attributes:
            return entry

        # Pydantic 2: model_copy accepts dict[str, object] for partial updates
        update_dict: dict[str, object] = {
            "attributes": m.Ldif.Attributes(attributes=new_attributes),
        }
        return entry.model_copy(update=update_dict)

    # ===== PHASE 2: DENORMALIZATION VIA HOOK OVERRIDE =====
    # ARCHITECTURE: Override RFC's _restore_entry_from_metadata() hook
    # to apply OID-specific denormalization. Keeps code in RFC base class,
    # OID only provides OID-specific behavior via override.

    def _restore_single_attribute(
        self,
        attr_name: str,
        attr_values: list[str],
        original_attrs: dict[str, list[str]] | None,
    ) -> tuple[str, list[str]]:
        """Restore attribute from metadata or apply denormalization.

        Attempts to find original attribute name/values from metadata. If not found,
        applies OID denormalization rule (aci → orclaci).

        Args:
            attr_name: Current (normalized) attribute name
            attr_values: Current attribute values
            original_attrs: Original attributes dict from metadata (optional)

        Returns:
            Tuple of (restored_attr_name, restored_attr_values)

        """
        # Try to find original attribute in metadata
        if original_attrs and isinstance(original_attrs, dict):
            for orig_name, orig_values in u.mapper().to_dict(original_attrs).items():
                if self._normalize_attribute_name(str(orig_name)) == attr_name:
                    # Found original - restore it
                    if isinstance(orig_values, (list, tuple)):
                        # Type narrowing: isinstance guarantees it's iterable
                        restored_values = [str(v) for v in orig_values]
                    else:
                        restored_values = [str(orig_values)]
                    return str(orig_name), restored_values

        # Not in metadata - apply denormalization rule
        denorm_name = (
            FlextLdifServersOidConstants.ORCLACI
            if attr_name.lower()
            == FlextLdifServersRfc.Constants.ACL_ATTRIBUTE_NAME.lower()
            else attr_name
        )
        return denorm_name, attr_values

    def _denormalize_oid_attributes_for_output(
        self,
        attrs: dict[str, list[str]],
        metadata: m.Ldif.QuirkMetadata | None,
    ) -> dict[str, list[str]]:
        """Denormalize RFC attributes to OID format.

        Restores original attribute names from metadata if available,
        otherwise applies OID denormalization rules (e.g., aci → orclaci).

        Uses c.Ldif.MetadataKeys.ORIGINAL_ATTRIBUTES_COMPLETE
        for metadata key standardization.
        """
        mk = c.Ldif.MetadataKeys
        original_attrs_raw = (
            metadata.extensions.get(mk.ORIGINAL_ATTRIBUTES_COMPLETE)
            if metadata and metadata.extensions
            else None
        )
        # Business Rule: original_attrs must be dict[str, list[str]] | None
        # Implication: Remote auditing requires structured attribute data
        # Type narrowing: convert MetadataAttributeValue to dict[str, list[str]]
        original_attrs: dict[str, list[str]] | None = None
        if original_attrs_raw is not None and isinstance(original_attrs_raw, dict):
            # Convert dict values to list[str] format
            original_attrs = {
                k: v if isinstance(v, list) else [str(v)]
                for k, v in u.mapper().to_dict(original_attrs_raw).items()
                if isinstance(k, str)
            }
        denormalized: dict[str, list[str]] = {}
        for attr_name, attr_values in u.mapper().to_dict(attrs).items():
            restored_name, restored_values = self._restore_single_attribute(
                attr_name,
                attr_values,
                original_attrs,
            )
            denormalized[restored_name] = restored_values
        return denormalized

    def _extract_boolean_conversions_from_metadata(
        self,
        entry_data: m.Ldif.Entry,
    ) -> dict[str, dict[str, str | list[str]]]:
        """Extract boolean conversions from entry metadata.

        Extracts from nested structure: CONVERTED_ATTRIBUTES[CONVERSION_BOOLEAN_CONVERSIONS].

        Args:
            entry_data: Entry model with metadata

        Returns:
            Dictionary of boolean conversions by attribute name

        """
        mk = c.Ldif.MetadataKeys
        boolean_conversions: dict[str, dict[str, str | list[str]]] = {}

        if not (entry_data.metadata and entry_data.metadata.extensions):
            return boolean_conversions

        converted_attrs_data = (
            entry_data.metadata.extensions.get(mk.CONVERTED_ATTRIBUTES)
            if entry_data.metadata and entry_data.metadata.extensions
            else None
        )
        # Extract from nested structure: CONVERTED_ATTRIBUTES[CONVERSION_BOOLEAN_CONVERSIONS]
        if isinstance(converted_attrs_data, dict):
            # When default is provided, mapper().get returns the value directly
            boolean_conversions_obj = u.mapper().get(
                converted_attrs_data, mk.CONVERSION_BOOLEAN_CONVERSIONS, default={}
            )
            # Type-safe extraction: rebuild with proper typing
            if isinstance(boolean_conversions_obj, dict):
                for key, value in u.mapper().to_dict(boolean_conversions_obj).items():
                    if isinstance(key, str) and isinstance(value, dict):
                        # Narrow value type to dict[str, str | list[str]]
                        boolean_conversions[key] = {
                            k: v for k, v in value.items() if isinstance(v, str | list)
                        }

        return boolean_conversions

    def _restore_boolean_attribute_from_metadata(
        self,
        attr_name: str,
        conv_data: dict[str, list[str] | str],
        restored_attrs: dict[str, list[str]],
    ) -> bool:
        """Restore single boolean attribute from conversion metadata.

        Args:
            attr_name: Attribute name to restore
            conv_data: Conversion metadata for the attribute
            restored_attrs: Dictionary to update with restored value

        Returns:
            True if restoration was successful, False otherwise

        """
        mk = c.Ldif.MetadataKeys

        converted_val_list = conv_data.get(mk.CONVERSION_CONVERTED_VALUE, [])
        if not converted_val_list:
            return False

        # Map RFC boolean (TRUE/FALSE) → OID format (1/0)
        rfc_value = converted_val_list[0] if converted_val_list else ""
        oid_value = FlextLdifServersOidConstants.RFC_TO_OID.get(
            rfc_value,
            rfc_value,  # Fallback to RFC value if not in map
        )
        restored_attrs[attr_name] = [oid_value]
        logger.debug(
            "Restored OID boolean format from metadata",
            attribute_name=attr_name,
            rfc_value=rfc_value,
            oid_value=oid_value,
            operation="_restore_boolean_values_to_oid",
        )
        return True

    def _convert_rfc_boolean_to_oid(self, value: str) -> tuple[str, bool]:
        """Convert single RFC boolean value to OID format.

        Args:
            value: RFC boolean value (TRUE/FALSE) or other value

        Returns:
            Tuple of (converted_value, was_converted)

        """
        if value == "TRUE":
            return FlextLdifServersOidConstants.ONE_OID, True
        if value == "FALSE":
            return FlextLdifServersOidConstants.ZERO_OID, True
        return value, False

    def _convert_boolean_values_to_oid(
        self,
        attr_name: str,
        current_values: list[str],
        restored_attrs: dict[str, list[str]],
    ) -> None:
        """Convert RFC boolean values to OID format for an attribute.

        Modifies restored_attrs in place if conversion is needed.

        Args:
            attr_name: Attribute name
            current_values: Current values to convert
            restored_attrs: Dict to update with converted values

        """
        new_values: list[str] = []
        changed = False
        for val in current_values:
            converted, was_converted = self._convert_rfc_boolean_to_oid(str(val))
            new_values.append(converted)
            if was_converted:
                changed = True
        if changed:
            restored_attrs[attr_name] = new_values

    def _restore_boolean_values_to_oid(
        self,
        entry_data: m.Ldif.Entry,
    ) -> m.Ldif.Entry:
        """Restore OID boolean format from RFC format (RFC → OID: TRUE/FALSE → 0/1).

        Overrides RFC's _restore_boolean_values() to convert RFC 4517 boolean format
        ("TRUE"/"FALSE") back to OID format ("1"/"0") during write.

        Uses FlextLdifServersOidConstants for boolean format constants.
        Uses u.Entry for conversion (DRY principle).

        Args:
            entry_data: Entry model with RFC-formatted boolean attributes

        Returns:
            Entry with OID-formatted boolean attributes if conversions exist

        """
        if not entry_data.attributes:
            return entry_data

        # Extract boolean conversions from metadata
        boolean_conversions = self._extract_boolean_conversions_from_metadata(
            entry_data,
        )

        # Boolean attribute names for matching
        boolean_attr_names = {
            attr.lower() for attr in FlextLdifServersOidConstants.BOOLEAN_ATTRIBUTES
        }

        # Restore boolean attributes
        restored_attrs = dict(entry_data.attributes.attributes)
        for attr_name in list(restored_attrs.keys()):
            if attr_name.lower() not in boolean_attr_names:
                continue

            # 1. Try to restore from metadata (priority)
            conv_data = boolean_conversions.get(attr_name, {})
            if isinstance(conv_data, dict) and conv_data:
                self._restore_boolean_attribute_from_metadata(
                    attr_name,
                    conv_data,
                    restored_attrs,
                )
                continue

            # 2. Enforce conversion if no metadata (RFC -> OID enforcement)
            self._convert_boolean_values_to_oid(
                attr_name,
                restored_attrs[attr_name],
                restored_attrs,
            )

        if restored_attrs == entry_data.attributes.attributes:
            return entry_data

        # Return entry with restored attributes
        # Business Rule: Attributes.metadata must be EntryMetadata | None
        # Implication: Remote auditing requires proper metadata structure
        # Type narrowing: ensure metadata is EntryMetadata | None, not dict
        entry_metadata: FlextLdifModelsMetadata.EntryMetadata | None = None
        if entry_data.attributes and entry_data.attributes.metadata:
            # entry_data.attributes.metadata is already EntryMetadata | None
            entry_metadata = entry_data.attributes.metadata
        # Pydantic 2: model_copy accepts dict[str, object] for partial updates
        update_dict: dict[str, object] = {
            "attributes": m.Ldif.Attributes(
                attributes=restored_attrs,
                attribute_metadata=(
                    entry_data.attributes.attribute_metadata
                    if entry_data.attributes
                    else {}
                ),
                metadata=entry_metadata,
            ),
        }
        return entry_data.model_copy(update=update_dict)

    def _restore_entry_from_metadata(
        self,
        entry_data: m.Ldif.Entry,
    ) -> m.Ldif.Entry:
        """Restore OID-specific formats from metadata (RFC → OID denormalization).

        Overrides RFC's _restore_entry_from_metadata() to apply OID-specific
        denormalization during write phase. Restores:
        - Boolean format: "TRUE"/"FALSE" → "0"/"1" (RFC 4517 → OID)
        - ACL attribute names: aci → orclaci (RFC → OID)
        - Schema DN: cn=schema → cn=subschemasubentry (RFC → OID)

        This hook is called by RFC._write_entry() before formatting the entry
        for LDIF output. Enables perfect round-trip OID→RFC→OID conversion.

        Uses c.Ldif.MetadataKeys for standardized metadata keys.

        Args:
            entry_data: RFC-normalized Entry model to restore

        Returns:
            Entry with OID-specific formats restored from metadata

        """
        # Restore OID-specific boolean format from metadata
        # Entry is already RFC-normalized, only OID-specific format restoration needed
        return self._restore_boolean_values_to_oid(entry_data)

    # =====================================================================
    # METADATA BUILDER HELPERS (DRY refactoring)
    # =====================================================================

    # REMOVED: _build_conversion_metadata, _build_dn_metadata, etc.
    # CONSOLIDATED into u.Metadata (DRY: 118→1 call)

    def _extract_original_extensions(
        self,
        original_entry: m.Ldif.Entry,
    ) -> dict[str, str | int | bool | list[str]]:
        """Extract compatible extensions from original entry metadata."""
        original_extensions: dict[str, str | int | bool | list[str]] = {}
        if not (original_entry.metadata and original_entry.metadata.extensions):
            return original_extensions
        ext = original_entry.metadata.extensions
        if not hasattr(ext, "items"):
            return original_extensions
        for k, v in ext.items():
            if isinstance(v, (str, int, bool)):
                original_extensions[k] = v
            elif isinstance(v, list):
                if all(isinstance(item, str) for item in v):
                    # Type compatibility: v is list[str], but pyright sees it as list[ScalarValue]
                    # Convert explicitly to list[str] for type safety
                    original_extensions[k] = [str(item) for item in v]
                elif all(
                    isinstance(item, (str, int, float, bool, type(None))) for item in v
                ):
                    # Convert ScalarValue list to list[str] for type compatibility
                    original_extensions[k] = [
                        str(item) for item in v if item is not None
                    ]
        return original_extensions

    def _build_json_serialized_metadata(
        self,
        rfc_violations: list[str],
        attribute_conflicts: list[dict[str, str]],
        boolean_conversions: dict[str, dict[str, str | list[str]]],
        converted_attributes: dict[str, list[str]],
        original_entry: m.Ldif.Entry,
    ) -> tuple[str | None, str | None, str | None, str | None, str | None]:
        """Serialize complex metadata to JSON strings for MetadataAttributeValue."""
        rfc_violations_str = json.dumps(rfc_violations) if rfc_violations else None
        attribute_conflicts_str = (
            json.dumps(attribute_conflicts) if attribute_conflicts else None
        )
        boolean_conversions_str = (
            json.dumps(boolean_conversions) if boolean_conversions else None
        )
        converted_attributes_str = (
            json.dumps(converted_attributes) if converted_attributes else None
        )
        original_entry_str = (
            json.dumps(original_entry.model_dump()) if original_entry else None
        )
        return (
            rfc_violations_str,
            attribute_conflicts_str,
            boolean_conversions_str,
            converted_attributes_str,
            original_entry_str,
        )

    def _create_entry_result_with_metadata(
        self,
        _entry: m.Ldif.Entry,  # Unused: kept for signature
        cleaned_dn: str,
        original_dn: str,
        _dn_stats: m.Ldif.DNStatistics,
        converted_attrs: set[str],
        boolean_conversions: dict[str, dict[str, str | list[str]]],
        acl_transformations: dict[str, m.Ldif.AttributeTransformation],
        rfc_violations: list[str],
        attribute_conflicts: list[dict[str, str]],
        converted_attributes: dict[str, list[str]],
        original_entry: m.Ldif.Entry,
    ) -> FlextResult[m.Ldif.Entry]:
        """Create entry result with complete metadata.

        CONSOLIDATED: Uses u.Metadata utilities for DRY code.
        Previous helper methods (_build_*) replaced by utility calls.

        """
        # Get original attributes once
        original_attrs = (
            original_entry.attributes.attributes if original_entry.attributes else {}
        )

        # INLINE: _build_conversion_metadata (18 lines → 2 lines)
        # Use constants for metadata keys (DRY: avoid hardcoding)
        mk = c.Ldif.MetadataKeys
        conversion_metadata: dict[str, list[str]] = (
            {mk.CONVERSION_CONVERTED_ATTRIBUTE_NAMES: list(converted_attrs)}
            if converted_attrs
            else {}
        )

        # INLINE: _build_dn_metadata (27 lines → 3 lines)
        # Use constants for metadata keys (DRY: avoid hardcoding)
        mk = c.Ldif.MetadataKeys
        dn_metadata: dict[str, str | bool] = (
            {
                mk.ORIGINAL_DN_COMPLETE: original_dn,
                mk.ORIGINAL_DN_LINE_COMPLETE: cleaned_dn,  # cleaned_dn is the processed DN
                mk.HAS_DIFFERENCES: True,  # DN was cleaned/modified
            }
            if original_dn != cleaned_dn
            else {}
        )

        # UTILITY: build_rfc_compliance_metadata (93 lines → 1 call)
        # Serialize complex types to JSON strings using helper method
        (
            rfc_violations_str,
            attribute_conflicts_str,
            boolean_conversions_str,
            converted_attributes_str,
            original_entry_str,
        ) = self._build_json_serialized_metadata(
            rfc_violations,
            attribute_conflicts,
            boolean_conversions,
            converted_attributes,
            original_entry,
        )
        rfc_compliance_metadata = (
            FlextLdifUtilitiesMetadata.build_rfc_compliance_metadata(
                "oid",  # quirk_type - required first positional argument
                rfc_violations=rfc_violations_str,
                attribute_conflicts=attribute_conflicts_str,
                boolean_conversions=boolean_conversions_str,
                converted_attributes=converted_attributes_str,
                original_entry=original_entry_str,
                entry_dn=cleaned_dn,
            )
        )

        # UTILITY: build_entry_metadata_extensions (58 lines → 10 lines)
        # Convert complex types to ScalarValue (str) for build_entry_metadata_extensions
        original_attributes_str: str | None = (
            json.dumps(original_attrs) if original_attrs else None
        )
        processed_attributes_str: str | None = (
            json.dumps(converted_attributes) if converted_attributes else None
        )
        # MetadataKeys is a class, not an instance - convert class attributes to dict
        metadata_keys_dict = {
            k: v
            for k, v in c.Ldif.MetadataKeys.__dict__.items()
            if not k.startswith("_") and isinstance(v, str)
        }
        metadata_keys_str: str | None = (
            json.dumps(metadata_keys_dict) if metadata_keys_dict else None
        )
        operational_attributes_str: str | None = (
            json.dumps(list(FlextLdifServersOidConstants.OPERATIONAL_ATTRIBUTES))
            if FlextLdifServersOidConstants.OPERATIONAL_ATTRIBUTES
            else None
        )
        generic_metadata = FlextLdifUtilitiesMetadata.build_entry_metadata_extensions(
            "oid",  # quirk_type - required first positional argument
            entry_dn=original_dn,
            original_attributes=original_attributes_str,
            processed_attributes=processed_attributes_str,
            server_type="oid",
            metadata_keys=metadata_keys_str,
            operational_attributes=operational_attributes_str,
        )
        # OID-specific: conversions, target DN, format message
        mk = c.Ldif.MetadataKeys
        # Store boolean conversions and attribute name conversions
        # Use typed structure for ConvertedAttributesData
        attr_name_conversions: dict[str, str] = (
            {
                FlextLdifServersOidConstants.ORCLACI: FlextLdifServersRfc.Constants.ACL_ATTRIBUTE_NAME,
            }
            if (
                FlextLdifServersRfc.Constants.ACL_ATTRIBUTE_NAME in converted_attributes
                and FlextLdifServersOidConstants.ORCLACI in original_attrs
            )
            else {}
        )
        converted_attrs_data: dict[
            str, dict[str, dict[str, str | list[str]]] | dict[str, str]
        ] = {
            c.Ldif.MetadataKeys.CONVERSION_BOOLEAN_CONVERSIONS: boolean_conversions,
            c.Ldif.MetadataKeys.CONVERSION_ATTRIBUTE_NAME_CONVERSIONS: attr_name_conversions,
        }
        # Business Rule: DynamicMetadata accepts MetadataAttributeValue
        # Implication: Complex nested dicts must be converted to compatible format
        # Convert ConvertedAttributesData to JSON string for MetadataAttributeValue compatibility
        converted_attrs_data_str: str = json.dumps(converted_attrs_data)
        generic_metadata[mk.CONVERTED_ATTRIBUTES] = converted_attrs_data_str
        generic_metadata[c.Ldif.MetadataKeys.ENTRY_TARGET_DN_CASE] = cleaned_dn
        generic_metadata[c.Ldif.MetadataKeys.ENTRY_ORIGINAL_FORMAT] = (
            f"OID Entry with {len(converted_attrs)} boolean conversions"
        )

        # Extract compatible extensions from original entry using helper
        original_extensions = self._extract_original_extensions(original_entry)

        # Build extensions dict using dict constructor + update for PERF403 compliance
        # Business Rule: DynamicMetadata accepts MetadataAttributeValue
        # Implication: All values must be compatible with MetadataAttributeValue
        # Type annotation ensures MetadataValue compatibility
        # Type narrowing: conversion_metadata values are list[str] which is compatible with MetadataAttributeValue
        extensions_data: dict[str, t.MetadataAttributeValue] = dict(conversion_metadata)
        # Type narrowing: dn_metadata values are str | bool which are compatible with MetadataAttributeValue
        extensions_data.update(dn_metadata)
        # Type narrowing: rfc_compliance_metadata values are str which is compatible with MetadataAttributeValue
        extensions_data.update(rfc_compliance_metadata)
        # Type narrowing: generic_metadata values are str which is compatible with MetadataAttributeValue
        extensions_data.update(generic_metadata)
        # Type narrowing: original_extensions values are str | int | bool | list[str] which are compatible with MetadataAttributeValue
        extensions_data.update(original_extensions)
        extensions_data[c.Ldif.MetadataKeys.ORIGINAL_DN_COMPLETE] = str(
            original_entry.dn,
        )

        # Create metadata using domain class (create_for returns validated instance)
        metadata = m.Ldif.QuirkMetadata.create_for(
            self._get_server_type(),
            extensions=extensions_data,
        )

        # INLINE: _track_boolean_conversions_in_metadata (47 lines → 10 lines)
        # Use standardized nested metadata keys (DRY: avoid hardcoding)
        for attr_name, conv_data in boolean_conversions.items():
            original_vals = conv_data.get(mk.CONVERSION_ORIGINAL_VALUE, [])
            converted_vals = conv_data.get(mk.CONVERSION_CONVERTED_VALUE, [])
            if original_vals and converted_vals:
                FlextLdifUtilitiesMetadata.track_boolean_conversion(
                    metadata=metadata,
                    attr_name=attr_name,
                    original_value=original_vals[0]
                    if len(original_vals) == 1
                    else str(original_vals),
                    converted_value=converted_vals[0]
                    if len(converted_vals) == 1
                    else str(converted_vals),
                    format_direction="OID->RFC",
                )

        # UTILITY: build_original_format_details (70 lines → 1 call)
        # Extract original lines from RFC parser metadata
        orig_dn_line: str | None = None
        orig_attr_lines: list[str] = []
        if original_entry.metadata and original_entry.metadata.original_format_details:
            format_details = original_entry.metadata.original_format_details
            raw_dn_line = getattr(format_details, "original_dn_line", None)
            orig_dn_line = str(raw_dn_line) if raw_dn_line is not None else None
            raw_lines = getattr(format_details, "original_attr_lines", [])
            if isinstance(raw_lines, (list, tuple)):
                orig_attr_lines = [str(line) for line in list(raw_lines)]

        # Convert complex types to ScalarValue (str) for build_original_format_details
        # Use different variable names to avoid conflicts with earlier definitions
        converted_attrs_format_str: str | None = (
            json.dumps(list(converted_attrs)) if converted_attrs else None
        )
        boolean_conversions_format_str: str | None = (
            json.dumps(boolean_conversions) if boolean_conversions else None
        )
        converted_attributes_format_str: str | None = (
            json.dumps(converted_attributes) if converted_attributes else None
        )
        original_attributes_format_str: str | None = (
            json.dumps(original_attrs) if original_attrs else None
        )
        original_attr_lines_str: str | None = (
            json.dumps(orig_attr_lines) if orig_attr_lines else None
        )
        metadata.original_format_details = (
            FlextLdifUtilitiesMetadata.build_original_format_details(
                "oid",  # quirk_type - required first positional argument
                original_dn=original_dn,
                cleaned_dn=cleaned_dn,
                converted_attrs=converted_attrs_format_str,
                boolean_conversions=boolean_conversions_format_str,
                converted_attributes=converted_attributes_format_str,
                original_attributes=original_attributes_format_str,
                server_type="oid",
                original_dn_line=orig_dn_line,
                original_attr_lines=original_attr_lines_str,
            )
        )

        # Track schema quirk if schema DN was normalized
        if (
            original_dn != cleaned_dn
            and original_dn.lower()
            == FlextLdifServersOidConstants.SCHEMA_DN_QUIRK.lower()
        ):
            # Business Rule: schema_transformations is stored in metadata.extensions as a list
            # Implication: Use DynamicMetadata.__setitem__ API for Pydantic 2 extra fields
            # DynamicMetadata has extra="allow", so we can add fields dynamically
            if "schema_transformations" not in metadata.extensions:
                metadata.extensions["schema_transformations"] = []
            # Type guard: Ensure schema_transformations is a list before appending
            schema_transformations = metadata.extensions.get("schema_transformations")
            if isinstance(schema_transformations, list):
                schema_transformations.append("schema_dn_normalization")
            else:
                # Initialize if not a list (shouldn't happen, but defensive)
                metadata.extensions["schema_transformations"] = [
                    "schema_dn_normalization",
                ]

        # Add ACL transformations
        if acl_transformations:
            metadata.attribute_transformations.update(acl_transformations)

        # Create final Entry
        ldif_attrs = m.Ldif.Attributes(attributes=converted_attributes)
        return FlextResult[m.Ldif.Entry].ok(
            m.Ldif.Entry(
                dn=m.Ldif.DN(value=cleaned_dn),
                attributes=ldif_attrs,
                metadata=metadata,
            ),
        )

    # ===== _parse_entry HELPER METHODS (DRY refactoring) =====
    # REMOVED: _analyze_oid_entry_differences (63 lines → utility)
    # Now uses: u.Entry.analyze_differences()
    # REMOVED: _store_oid_minimal_differences (68 lines → utility)
    # Now uses: u.Metadata.store_minimal_differences()

    def _hook_post_parse_entry(
        self,
        entry: m.Ldif.Entry,
    ) -> FlextResult[m.Ldif.Entry]:
        r"""Hook: Transform parsed entry using OID-specific enhancements.

        OID vs RFC Transformations Applied
        ==================================
        This hook extends RFC's `_hook_post_parse_entry()` to apply
        OID-specific normalizations during Phase 1 (parsing).

        Step 1: Boolean Attribute Conversion
        ------------------------------------
        RFC 4517 Section 3.3.3:
            Boolean = "TRUE" / "FALSE"

        OID Format:
            Boolean = "0" / "1"

        Transformation:
            "0" → "FALSE"
            "1" → "TRUE"

        Applies to attributes in Constants.BOOLEAN_ATTRIBUTES:
            orclIsEnabled, orclAccountLocked, orclPwdMustChange, etc.

        Step 2: Attribute Name Normalization
        ------------------------------------
        RFC 4876 (ACI):
            aci: <acl-definition>

        OID Proprietary:
            orclaci: <acl-definition>
            orclentrylevelaci: <acl-definition>

        Transformation:
            orclaci → aci
            orclentrylevelaci → aci

        Metadata Tracking
        -----------------
        All transformations are stored in `entry.metadata.extensions`:
            - oid_converted_attrs: List of converted boolean attributes
            - oid_boolean_conversions: Dict mapping attr → {original, converted}

        This metadata enables perfect round-trip support in Phase 2 (writing).

        Args:
            entry: RFC-parsed Entry model (from RFC._parse_entry)

        Returns:
            FlextResult with transformed Entry model

        """
        try:
            if not entry.attributes or not entry.dn:
                return FlextResult.ok(entry)

            # Step 1: Convert boolean attributes OID → RFC
            logger.debug(
                "_hook_post_parse_entry attributes",
                attributes=list(entry.attributes.attributes.keys()),
            )
            converted_attributes, converted_attrs, boolean_conversions = (
                self._convert_boolean_attributes_to_rfc(entry.attributes.attributes)
            )
            logger.debug("converted_attrs: %s", converted_attrs)
            logger.debug("boolean_conversions: %s", boolean_conversions)

            # Step 2: Normalize attribute names OID → RFC (orclaci → aci)
            normalized_attributes: dict[str, list[str]] = {}
            for attr_name, attr_values in converted_attributes.items():
                normalized_name = self._normalize_attribute_name(attr_name)
                normalized_attributes[normalized_name] = attr_values

            # Update entry attributes with transformed values
            entry.attributes.attributes = normalized_attributes

            # Store transformation metadata for later use in _parse_entry()
            mk = c.Ldif.MetadataKeys
            if entry.metadata:
                if not entry.metadata.extensions:
                    entry.metadata.extensions = (
                        FlextLdifModelsMetadata.DynamicMetadata()
                    )
                # Build properly typed ConvertedAttributesData structure
                converted_attrs_list: list[str] = list(converted_attrs)
                if boolean_conversions:
                    # Build full structure with boolean conversions
                    # Business Rule: DynamicMetadata accepts MetadataAttributeValue
                    # Implication: Complex types must be converted to compatible format
                    conv_data: dict[
                        str, dict[str, dict[str, str | list[str]]] | list[str]
                    ] = {
                        mk.CONVERSION_CONVERTED_ATTRIBUTE_NAMES: converted_attrs_list,
                        mk.CONVERSION_BOOLEAN_CONVERSIONS: boolean_conversions,
                    }
                    # Convert ConvertedAttributesData to JSON string for MetadataAttributeValue compatibility
                    conv_data_str: str = json.dumps(conv_data)
                    entry.metadata.extensions[mk.CONVERTED_ATTRIBUTES] = conv_data_str
                else:
                    # Just store the list of converted attribute names
                    entry.metadata.extensions[mk.CONVERTED_ATTRIBUTES] = (
                        converted_attrs_list
                    )

            return FlextResult.ok(entry)
        except Exception as e:
            logger.exception("OID post-parse entry hook failed")
            return FlextResult.fail(f"OID post-parse entry hook failed: {e}")

    def _extract_acl_metadata_from_string(
        self,
        acl_value: str,
        current_extensions: dict[str, t.MetadataAttributeValue],
    ) -> None:
        """Extract OID-specific ACL metadata from ACL string.

        Extracts bindmode, deny_group_override, append_to_all, bind_ip_filter,
        and constrain_to_added_object from the ACL string using regex patterns.
        """
        bindmode = FlextLdifUtilitiesACL.extract_component(
            acl_value,
            FlextLdifServersOidConstants.ACL_BINDMODE_PATTERN,
            group=1,
        )
        if bindmode:
            current_extensions[c.Ldif.MetadataKeys.ACL_BINDMODE] = bindmode

        if FlextLdifUtilitiesACL.extract_component(
            acl_value,
            FlextLdifServersOidConstants.ACL_DENY_GROUP_OVERRIDE_PATTERN,
        ):
            current_extensions[c.Ldif.MetadataKeys.ACL_DENY_GROUP_OVERRIDE] = True

        if FlextLdifUtilitiesACL.extract_component(
            acl_value,
            FlextLdifServersOidConstants.ACL_APPEND_TO_ALL_PATTERN,
        ):
            current_extensions[c.Ldif.MetadataKeys.ACL_APPEND_TO_ALL] = True

        bind_ip_filter = FlextLdifUtilitiesACL.extract_component(
            acl_value,
            FlextLdifServersOidConstants.ACL_BIND_IP_FILTER_PATTERN,
            group=1,
        )
        if bind_ip_filter:
            current_extensions[c.Ldif.MetadataKeys.ACL_BIND_IP_FILTER] = bind_ip_filter

        constrain_to_added = FlextLdifUtilitiesACL.extract_component(
            acl_value,
            FlextLdifServersOidConstants.ACL_CONSTRAIN_TO_ADDED_PATTERN,
            group=1,
        )
        if constrain_to_added:
            current_extensions[c.Ldif.MetadataKeys.ACL_CONSTRAIN_TO_ADDED_OBJECT] = (
                constrain_to_added
            )

    def _merge_parsed_acl_extensions(
        self,
        acl_quirk: object,
        acl_value: str,
        current_extensions: dict[str, t.MetadataAttributeValue],
    ) -> None:
        """Parse ACL and merge additional extensions from parsed model."""
        # Use public parse() method instead of private _parse_acl
        if not hasattr(acl_quirk, "parse"):
            return
        try:
            # Type narrowing: acl_quirk has parse method after hasattr check
            # Use getattr to satisfy pyright - hasattr check already passed
            parse_method = getattr(acl_quirk, "parse", None)
            if parse_method is None or not callable(parse_method):
                return
            acl_result_raw = parse_method(acl_value)
            # Type narrowing: acl_result is FlextResult after callable check
            if not isinstance(acl_result_raw, FlextResult):
                return
            acl_result = acl_result_raw
            if not acl_result.is_success:
                return
            acl_model = acl_result.value
            if not (acl_model.metadata and acl_model.metadata.extensions):
                return
            acl_extensions = (
                acl_model.metadata.extensions.model_dump()
                if hasattr(acl_model.metadata.extensions, "model_dump")
                else dict(acl_model.metadata.extensions)
            )
            # Map pattern names to MetadataKeys
            key_mapping = {
                "bindmode": c.Ldif.MetadataKeys.ACL_BINDMODE,
                "deny_group_override": c.Ldif.MetadataKeys.ACL_DENY_GROUP_OVERRIDE,
            }
            for key, value in acl_extensions.items():
                mapped_key = key_mapping.get(key)
                if mapped_key and not current_extensions.get(mapped_key):
                    current_extensions[mapped_key] = value
        except Exception:
            logger.debug("Failed to parse ACL extension metadata", exc_info=True)

    def _process_orclaci_values(
        self,
        orclaci_values: list[str] | str | None,
        current_extensions: dict[str, t.MetadataAttributeValue],
    ) -> None:
        """Process orclaci values and extract ACL metadata."""
        if not orclaci_values:
            return

        parent = self._get_parent_quirk_safe()
        if parent is None:
            return
        acl_quirk = getattr(parent, "_acl_quirk", None)
        if not acl_quirk:
            return

        acl_list = (
            list(orclaci_values)
            if isinstance(orclaci_values, (list, tuple))
            else [str(orclaci_values)]
        )

        for acl_value in acl_list:
            if not isinstance(acl_value, str):
                continue
            self._extract_acl_metadata_from_string(acl_value, current_extensions)
            self._merge_parsed_acl_extensions(acl_quirk, acl_value, current_extensions)

    def _hook_finalize_entry_parse(
        self,
        entry: m.Ldif.Entry,
        original_dn: str,
        original_attrs: dict[str, list[str]],
    ) -> FlextResult[m.Ldif.Entry]:
        """Finalize OID entry with ACL and RFC violation metadata.

        This hook adds OID-specific metadata without duplicating the
        difference analysis already performed by RFC base class.

        OID-Specific Additions:
        - ACL transformations (orclaci → aci renames detected)
        - RFC violations (multiple structural objectClasses, etc.)
        - Attribute conflicts for invalid combinations

        The RFC base class already handles:
        - Difference analysis (DN and attribute changes)
        - Minimal differences storage
        - Original format preservation

        Args:
            entry: Parsed entry from RFC with all hooks applied
            original_dn: Original DN before transformation
            original_attrs: Original attributes for comparison

        Returns:
            FlextResult with entry containing OID-specific metadata

        """
        _ = original_dn  # Used for logging if needed

        if not entry.attributes:
            return FlextResult.ok(entry)

        normalized_attrs = entry.attributes.attributes

        # Ensure metadata exists
        if not entry.metadata:
            entry.metadata = m.Ldif.QuirkMetadata.create_for(
                "oid",
                extensions=FlextLdifModelsMetadata.DynamicMetadata(),
            )

        # Get current extensions
        current_extensions: dict[str, t.MetadataAttributeValue] = (
            dict(entry.metadata.extensions) if entry.metadata.extensions else {}
        )

        # Process ACLs to extract their extensions (bindmode, deny_group_override, etc.)
        # Use original_attrs to get ACL attributes (before any transformations)
        orclaci_raw = original_attrs.get("orclaci") if original_attrs else None
        if not orclaci_raw:
            # Fallback to entry.attributes if not in original_attrs
            orclaci_raw = normalized_attrs.get("orclaci") if normalized_attrs else None
        # Type narrow to expected format for _process_orclaci_values
        orclaci_values: list[str] | str | None = None
        if isinstance(orclaci_raw, str):
            orclaci_values = orclaci_raw
        elif isinstance(orclaci_raw, list):
            orclaci_values = [str(v) for v in orclaci_raw]
        # Delegate ACL processing to helper method to reduce nesting
        self._process_orclaci_values(orclaci_values, current_extensions)

        # OID-specific: Detect ACL attribute transformations
        acl_transformations = self._detect_entry_acl_transformations(
            original_attrs,
            normalized_attrs,
        )

        # OID-specific: Detect RFC compliance violations
        rfc_violations, attribute_conflicts = self._detect_rfc_violations(
            normalized_attrs,
        )

        # Add OID-specific metadata to extensions
        # Business Rule: DynamicMetadata accepts MetadataAttributeValue
        # Implication: Complex types must be converted to compatible format
        # Serialize complex types to JSON strings for MetadataValue compatibility
        if acl_transformations:
            # AttributeTransformation.model_dump() → dict[str, str | list[str]]
            # Convert to JSON string for MetadataAttributeValue compatibility
            acl_transformations_dict = {
                name: trans.model_dump() for name, trans in acl_transformations.items()
            }
            current_extensions["acl_transformations"] = json.dumps(
                acl_transformations_dict,
            )
        if rfc_violations:
            # list[str] is compatible with Sequence[ScalarValue] in MetadataAttributeValue
            # But to be safe, convert to JSON string
            current_extensions["rfc_violations"] = json.dumps(rfc_violations)
        if attribute_conflicts:
            # list[dict[str, str]] needs conversion to MetadataAttributeValue
            # Convert to JSON string
            current_extensions["attribute_conflicts"] = json.dumps(attribute_conflicts)

        # Update entry metadata with all extensions (ACL extensions + OID-specific metadata)
        if current_extensions != (entry.metadata.extensions if entry.metadata else {}):
            # Pydantic 2: model_copy accepts dict[str, object] for partial updates
            update_dict: dict[str, object] = {
                "extensions": FlextLdifModelsMetadata.DynamicMetadata(
                    **current_extensions
                )
                if current_extensions
                else FlextLdifModelsMetadata.DynamicMetadata(),
            }
            entry.metadata = entry.metadata.model_copy(update=update_dict)

            logger.debug(
                "OID finalize: Added server-specific metadata",
                acl_count=len(acl_transformations),
                violations_count=len(rfc_violations),
                conflicts_count=len(attribute_conflicts),
            )

        return FlextResult.ok(entry)

    def _get_current_attrs_with_acl_equivalence(
        self,
        entry_data: m.Ldif.Entry,
    ) -> set[str]:
        """Get current attribute names with OID ACL equivalence.

        OID-specific: Considers aci and orclaci as equivalent for ACL attributes.

        Args:
            entry_data: Entry data

        Returns:
            Set of lowercase attribute names with ACL equivalence applied

        """
        current_attrs: set[str] = set()
        if entry_data.attributes and entry_data.attributes.attributes:
            current_attrs = {
                attr_name.lower() for attr_name in entry_data.attributes.attributes
            }
            # OID-specific: Add orclaci if aci exists, and vice versa
            if "aci" in current_attrs:
                current_attrs.add("orclaci")
            if "orclaci" in current_attrs:
                current_attrs.add("aci")
        return current_attrs

    def _should_skip_original_line(
        self,
        original_line: str,
        current_attrs: set[str],
        write_options: FlextLdifModelsSettings.WriteFormatOptions | None,
        *,
        write_empty_values: bool,
    ) -> bool:
        """Check if original line should be skipped during restoration.

        Args:
            original_line: Original attribute line
            current_attrs: Set of current attribute names (lowercase)
            write_options: Write format options
            write_empty_values: Whether to write empty values (unused in OID override)

        Returns:
            True if line should be skipped

        """
        _ = write_empty_values  # Conform to parent signature
        # Skip DN line
        if original_line.lower().startswith("dn:"):
            return True
        # Skip comments unless write_metadata_as_comments is True
        if original_line.strip().startswith("#"):
            include_comments = write_options and getattr(
                write_options,
                "write_metadata_as_comments",
                False,
            )
            if not include_comments:
                return True
        # Only restore lines for attributes that still exist
        if ":" in original_line:
            attr_name_part = original_line.split(":", 1)[0].strip().lower()
            attr_name_part = attr_name_part.removesuffix(":").removeprefix("<")
            if current_attrs and attr_name_part not in current_attrs:
                return True
        return False

    def _convert_line_boolean_to_oid(self, original_line: str) -> str:
        """Convert RFC boolean values in line to OID format.

        Args:
            original_line: Original attribute line

        Returns:
            Line with boolean values converted to OID format

        """
        if ":" not in original_line:
            return original_line
        parts = original_line.split(":", 1)
        attr_lower = parts[0].strip().lower()
        if attr_lower not in FlextLdifServersOidConstants.BOOLEAN_ATTRIBUTES:
            return original_line
        value_part = parts[1].strip() if len(parts) > 1 else ""
        if value_part == "TRUE":
            return f"{parts[0]}: {FlextLdifServersOidConstants.ONE_OID}"
        if value_part == "FALSE":
            return f"{parts[0]}: {FlextLdifServersOidConstants.ZERO_OID}"
        return original_line

    def _convert_line_acl_to_oid(self, original_line: str) -> str:
        """Convert RFC ACL attribute name (aci) to OID format (orclaci).

        Args:
            original_line: Original attribute line

        Returns:
            Line with ACL attribute name converted to OID format

        """
        if ":" not in original_line:
            return original_line
        parts = original_line.split(":", 1)
        attr_lower = parts[0].strip().lower()

        # Convert aci to orclaci
        if attr_lower == "aci":
            logger.debug("Converting aci to orclaci", line=original_line)
            # Preserve spacing after colon if possible, or default to single space
            value_part = parts[1]
            return f"orclaci:{value_part}"

        return original_line

    def _write_original_attr_lines(
        self,
        ldif_lines: list[str],
        entry_data: m.Ldif.Entry,
        original_attr_lines_complete: list[str],
        write_options: FlextLdifModelsSettings.WriteFormatOptions | None,
    ) -> set[str]:
        """Write original attribute lines preserving exact formatting.

        OID-specific: Considers aci and orclaci as equivalent for ACL attributes.

        Args:
            ldif_lines: Output lines list
            entry_data: Entry data
            original_attr_lines_complete: Original attribute lines
            write_options: Write format options

        Returns:
            Set of attribute names (as they appear in Entry.attributes) that were written.
            For ACL attributes, returns both 'aci' and 'orclaci' when either is written.

        """
        written_attrs: set[str] = set()
        current_attrs = self._get_current_attrs_with_acl_equivalence(entry_data)

        for original_line in original_attr_lines_complete:
            if self._should_skip_original_line(
                original_line,
                current_attrs,
                write_options,
                write_empty_values=True,  # OID preserves empty values
            ):
                continue

            # Extract attribute name from original line for tracking
            if ":" in original_line:
                original_attr_name = original_line.split(":", 1)[0].strip().lower()
                written_attrs.add(original_attr_name)
                # ACL equivalence: if aci written, also mark orclaci as written (and vice versa)
                if original_attr_name == "aci":
                    written_attrs.add("orclaci")
                elif original_attr_name == "orclaci":
                    written_attrs.add("aci")

            # Apply boolean conversion (RFC -> OID)
            line_to_write = self._convert_line_boolean_to_oid(original_line)

            # Apply ACL conversion (RFC -> OID)
            line_to_write = self._convert_line_acl_to_oid(line_to_write)

            ldif_lines.append(line_to_write)

        logger.debug(
            "Restored original attribute lines from metadata",
            entry_dn=entry_data.dn.value[:50] if entry_data.dn else None,
            original_lines_count=len(original_attr_lines_complete),
            written_attrs=list(written_attrs),
        )
        return written_attrs
