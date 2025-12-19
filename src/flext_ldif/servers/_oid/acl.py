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
import re
from dataclasses import dataclass
from typing import ClassVar, Literal, cast

from flext_core import FlextLogger, FlextResult, u

from flext_ldif._models.metadata import FlextLdifModelsMetadata
from flext_ldif._utilities.acl import FlextLdifUtilitiesACL
from flext_ldif._utilities.metadata import FlextLdifUtilitiesMetadata
from flext_ldif.constants import c
from flext_ldif.models import m
from flext_ldif.servers._oid.constants import FlextLdifServersOidConstants
from flext_ldif.servers._rfc import (
    FlextLdifServersRfcAcl,
)
from flext_ldif.servers.rfc import FlextLdifServersRfc
from flext_ldif.typings import t

# Removed alias - use c.Ldif.MetadataKeys directly (no redundant aliases in higher layers)

logger = FlextLogger(__name__)


# Type alias for OID Constants to avoid circular imports
# FlextLdifServersOid is defined in oid.py which imports this module
_OidConstants = FlextLdifServersOidConstants


class FlextLdifServersOidAcl(FlextLdifServersRfcAcl):
    r"""Oracle Internet Directory (OID) ACL implementation.

    OID vs RFC ACL Differences
    ==========================
    Oracle OID uses a proprietary ACL format (orclaci/orclentrylevelaci)
    that differs significantly from RFC 4876 (LDAP Access Control Model).
    This class parses OID ACLs and normalizes them to a common model.

    1. ACL ATTRIBUTE NAMES
    ----------------------
    RFC 4876 Standard:
        aci: access to ... by ...

    OID Proprietary:
        orclaci: access to Union[entry, attr]=(...) by subject (permissions)
        orclentrylevelaci: (same format, entry-level scope)

    2. ACL FORMAT STRUCTURE
    -----------------------
    OID ACL Syntax (from Oracle Fusion Middleware documentation):

        orclaci: access to <target> by <subject> (<permissions>)
        orclentrylevelaci: access to <target> by <subject> (<permissions>)

    Target Types:
        - entry: Entire entry
        - attr=(*): All attributes
        - attr=(cn,sn,mail): Specific attributes

    Subject Types:
        - *: Everyone (anonymous)
        - self: The entry itself
        - "dn": Specific user DN (quoted)
        - group="dn": Group DN
        - dnattr=(attrname): DN from attribute
        - guidattr=(attrname): GUID from attribute
        - groupattr=(attrname): Group from attribute

    3. OID-SPECIFIC PERMISSIONS
    ---------------------------
    Standard permissions (RFC-like):
        read, write, add, delete, search, compare

    OID extensions:
        browse: Combination of read + search
        auth: Authentication permission
        selfwrite: Self-modification permission
        proxy: Proxy access permission
        all: All permissions combined

    Negative permissions (deny specific rights):
        noread, nowrite, noadd, nodelete, nosearch, nocompare,
        nobrowse, noselfwrite

    4. ENTRY-LEVEL vs SUBTREE ACL
    -----------------------------
    OID distinguishes between:
        - orclaci: Applies to subtree (inherited)
        - orclentrylevelaci: Applies only to entry (not inherited)

    5. ACL PARSING PATTERNS
    -----------------------
    Constants.ACL_TYPE_PATTERN:
        r"^(Union[orclaci, orclentrylevelaci]):"

    Constants.ACL_TARGET_PATTERN:
        r"access to (Union[entry, attr]=\\(([^)]+)\\))"

    Constants.ACL_SUBJECT_PATTERN:
        r"by\\s+(group=\"[^\"]+\"|...)"

    Constants.ACL_PERMISSIONS_PATTERN:
        r"\\(([^)]+)\\)(?:\\s*$)"

    Example LDIF Input (OID)
    ========================
    dn: ou=People,dc=example,dc=com
    orclaci: access to entry by group="cn=Admins" (browse,add,delete)
    orclaci: access to attr=(*) by * (read,search)
    orclaci: access to attr=(userpassword) by self (write)
    orclentrylevelaci: access to entry by * (browse)

    Example Parsed Model
    ====================
    Acl(
        target_type='entry',
        target_attrs=None,
        subject_type='group_dn',
        subject='cn=Admins,dc=example,dc=com',
        permissions=['browse', 'add', 'delete'],
        scope='subtree',  # from orclaci
        metadata={"original_format": "...", "acl_source_server": "oid"}
    )

    Acl(
        target_type='attr',
        target_attrs=['userpassword'],
        subject_type='self',
        subject='self',
        permissions=['write', 'compare'],
        scope='subtree',
        metadata={...}
    )

    References
    ----------
    - RFC 4876: A Configuration Profile Schema for LDAP Access Control
    - Oracle Fusion Middleware Administrator's Guide for OID
    - Oracle Directory Server Enterprise Edition Reference, Chapter "Access Control"

    """

    # ACL attribute name is obtained from Constants.ACL_ATTRIBUTE_NAME
    # No instance variable needed - use Constants directly

    # =====================================================================
    # PROTOCOL IMPLEMENTATION: p.ServerAclProtocol
    # =====================================================================

    # RFC Foundation - Standard LDAP attributes (all servers start here)
    RFC_ACL_ATTRIBUTES: ClassVar[list[str]] = [
        "aci",  # Standard LDAP (RFC 4876)
        "acl",  # Alternative format
        "olcAccess",  # OpenLDAP
        "aclRights",  # Generic rights
        "aclEntry",  # ACL entry
    ]

    # OID-specific extensions
    OID_ACL_ATTRIBUTES: ClassVar[list[str]] = [
        "orclaci",  # OID-specific ACI
        "orclentrylevelaci",  # OID entry-level ACI
        "orclContainerLevelACL",  # OID container ACL
    ]

    def get_acl_attributes(self) -> list[str]:
        """Get RFC + OID extensions.

        Returns:
            List of ACL attribute names (RFC foundation + OID-specific)

        """
        return self.RFC_ACL_ATTRIBUTES + self.OID_ACL_ATTRIBUTES

    # is_acl_attribute inherited from base class (uses set for O(1) lookup)

    # OVERRIDDEN METHODS (from FlextLdifServersBase.Acl)
    # These methods override the base class with Oracle OID-specific logic:
    # - can_handle_acl(): Detects orclaci/orclentrylevelaci formats
    # - parse_acl(): Normalizes Oracle OID ACL to RFC-compliant internal model
    # - write_acl(): Serializes RFC-compliant model to OID ACL format
    # - get_acl_attribute_name(): Returns "orclaci" (OID-specific, overridden)

    # =====================================================================
    # METADATA CONFIGURATION
    # =====================================================================
    # Dataclass to consolidate _build_oid_acl_metadata parameters
    # Reduces 15 individual parameters to single config object
    @dataclass(frozen=True)
    class OidAclMetadataConfig:
        """Configuration for building OID ACL metadata.

        Consolidates 15 parameters into single dataclass for reduced complexity
        and improved parameter passing (Parameter Object pattern).

        Attributes:
            acl_line: Original ACL line
            oid_subject_type: OID subject type (user, group, dn_attr, etc.)
            rfc_subject_type: RFC-normalized subject type
            oid_subject_value: Original subject value
            target_dn: Target DN
            perms_dict: Permissions dictionary
            target_attrs: Target attributes (optional)
            acl_filter: OID filter expression (optional)
            acl_constraint: OID added_object_constraint (optional)
            bindmode: OID BINDMODE - auth/encryption (optional)
            deny_group_override: OID DenyGroupOverride flag (optional)
            append_to_all: OID AppendToAll flag (optional)
            bind_ip_filter: OID BINDIPFILTER expression (optional)
            constrain_to_added_object: OID constraintonaddedobject filter (optional)

        """

        acl_line: str
        oid_subject_type: str
        rfc_subject_type: str
        oid_subject_value: str
        target_dn: str
        perms_dict: dict[str, bool]
        target_attrs: list[str] | None = None
        acl_filter: str | None = None
        acl_constraint: str | None = None
        bindmode: str | None = None
        deny_group_override: bool | None = None
        append_to_all: bool | None = None
        bind_ip_filter: str | None = None
        constrain_to_added_object: str | None = None

    # OVERRIDDEN METHODS (from FlextLdifServersBase.Acl)
    # These methods override the base class with Oracle OID-specific logic:
    # - can_handle_acl(): Detects orclaci/orclentrylevelaci formats
    # - parse_acl(): Normalizes Oracle OID ACL to RFC-compliant internal model
    # - write_acl(): Serializes RFC-compliant model to OID ACL format
    # - get_acl_attribute_name(): Returns "orclaci" (OID-specific, overridden)

    def can_handle_acl(self, acl_line: str | m.Ldif.Acl) -> bool:
        """Check if this is an Oracle OID ACL.

        Detects Oracle OID ACL by checking for Oracle-specific ACL syntax patterns:
        - "access to <target> by <subject>" (Oracle OID ACL format)
        - "orclaci:" (LDIF attribute prefix)
        - "orclentrylevelaci:" (LDIF attribute prefix)

        OID ACL: access to [Union[entry, attr]] by <subject> (<perms>)

        Args:
            acl_line: Raw ACL line from LDIF or Acl model

        Returns:
            True if this is Oracle OID ACL format

        """
        if isinstance(acl_line, m.Ldif.Acl):
            # Check metadata for OID server type
            if acl_line.metadata and acl_line.metadata.quirk_type:
                return acl_line.metadata.quirk_type == self._get_server_type()
            return False
        if not acl_line:
            return False
        # Type narrowing: after checking for Acl, remaining is str
        # acl_line is str at this point (Union[str, Acl], and Acl was already checked)
        acl_line_str: str = str(acl_line)
        acl_line_lower = acl_line_str.strip().lower()

        # Check for LDIF attribute prefix (when parsing from LDIF file)
        if acl_line_lower.startswith(
            (
                f"{FlextLdifServersOidConstants.ORCLACI}:",
                f"{FlextLdifServersOidConstants.ORCLENTRYLEVELACI}:",
            ),
        ):
            return True

        # Check for Oracle OID ACL content pattern (RFC 4876 compliant syntax)
        # Oracle format: "access to <target> by <subject> : <permissions>"
        return acl_line_lower.startswith("access to ")

    def _update_acl_with_oid_metadata(
        self,
        acl_data: m.Ldif.Acl,
        _acl_line: str,  # Unused but required by interface
    ) -> m.Ldif.Acl:
        """Update ACL with OID server type and metadata."""
        server_type = FlextLdifServersOidConstants.SERVER_TYPE
        updated_metadata = (
            acl_data.metadata.model_copy(update={"quirk_type": server_type})
            if acl_data.metadata
            else m.Ldif.QuirkMetadata.create_for(
                server_type,
                extensions=FlextLdifModelsMetadata.DynamicMetadata(),
            )
        )
        # Use specific type for model_copy update
        update_dict: dict[str, object] = {
            "server_type": server_type,
            "metadata": updated_metadata,
        }
        return acl_data.model_copy(update=update_dict)

    def _parse_acl(self, acl_line: str) -> FlextResult[m.Ldif.Acl]:
        r"""Parse Oracle OID ACL string to RFC-compliant internal model.

        OID vs RFC ACL Parsing
        ======================
        This method extends RFC's `_parse_acl()` to handle OID-specific
        ACL formats while maintaining RFC compatibility.

        Parsing Strategy
        ----------------
        1. Try RFC parent parser first (handles standard ACIs)
        2. If OID-specific format detected, enhance with OID metadata
        3. Fall back to OID-specific parser for proprietary formats

        OID ACL Format (Input)
        ----------------------
        orclaci: access to <target> by <subject> (<permissions>)
        orclentrylevelaci: access to <target> by <subject> (<permissions>)

        Example Input:
            orclaci: access to entry by group="cn=Admins" (browse)
            orclaci: access to attr=(userpassword) by self (write)
            orclentrylevelaci: access to entry by * (browse)

        OID-Specific Features Parsed
        ----------------------------
        1. ACL Type Detection:
           - orclaci: Subtree scope (inherited)
           - orclentrylevelaci: Entry-level scope (not inherited)

        2. Target Extraction:
           - entry: Entire entry
           - attr=(*): All attributes
           - attr=(cn,sn,mail): Specific attributes

        3. Subject Detection:
           - *: Anonymous (everyone)
           - self: The entry itself
           - "dn": Specific user DN (quoted)
           - group="dn": Group membership
           - dnattr=(attr): DN from entry attribute
           - guidattr=(attr): GUID from entry attribute
           - groupattr=(attr): Group from entry attribute

        4. Permission Parsing:
           - Standard: browse, read, write, add, delete, search, compare
           - Extended: auth, selfwrite, proxy, all
           - Negations: noread, nowrite, noadd, nodelete, nosearch

        5. Filter Extraction:
           - filter=(objectClass=person)
           - Complex nested filters supported

        6. Constraint Extraction:
           - added_object_constraint=(objectClass=...)

        Output Model (RFC-normalized)
        -----------------------------
        Acl(
            permissions={'browse': True, 'add': True, 'delete': True},
            target='entry',
            target_attrs=None,
            subject='group',
            subject_dn='cn=Admins,dc=example,dc=com',
            scope='subtree',
            metadata=m.Ldif.QuirkMetadata(
                server_type='oid',
                extensions={
                    "original_format": "orclaci: access to entry by...",
                    'acl_type': 'orclaci',
                    ...
                }
            )
        )

        Args:
            acl_line: Oracle OID ACL definition line from LDIF

        Returns:
            FlextResult with RFC-normalized Acl model

        """
        # Always try parent's _parse_acl first (RFC format)
        parent_result = super()._parse_acl(acl_line)

        # If parent validation failed (empty string, etc.), return error immediately
        if parent_result.is_failure:
            return parent_result

        # Check if this is an OID ACL and parent parser populated it correctly
        if (
            parent_result.is_success
            and (acl_data := parent_result.value)
            and self.can_handle_acl(acl_line)
            and any(
                getattr(acl_data, field) is not None
                for field in ("permissions", "target", "subject")
            )
        ):
            # Parent parser populated the model, use it with OID server_type
            updated_acl = self._update_acl_with_oid_metadata(acl_data, acl_line)
            return FlextResult[m.Ldif.Acl].ok(updated_acl)

        # Not an OID ACL - use parent result or fall through
        if (
            parent_result.is_success
            and (acl_data := parent_result.value)
            and not self.can_handle_acl(acl_line)
        ):
            return FlextResult[m.Ldif.Acl].ok(acl_data)

        # RFC parser failed - use OID-specific parsing
        return self._parse_oid_specific_acl(acl_line)

    # =====================================================================
    # OID-SPECIFIC ACL PARSING/FORMATTING METHODS
    # These methods contain OID server knowledge and MUST stay in this class
    # =====================================================================

    @staticmethod
    def _extract_oid_target(content: str) -> tuple[str | None, list[str]]:
        """Extract target DN and attributes from OID ACL.

        Args:
            content: OID ACL content string

        Returns:
            Tuple of (target_dn, attribute_list)

        """
        target_dn: str | None = None
        attributes: list[str] = []
        patterns = _OidConstants

        # Extract target DN using constant pattern
        target_match = re.search(
            patterns.ACL_TARGET_DN_EXTRACT,
            content,
            re.IGNORECASE,
        )
        if target_match:
            target_dn = target_match.group(1)

        # Extract target attributes using OID-specific pattern (attr=(...) format)
        # Try OID format first (attr=(cn,sn,mail))
        attr_match = re.search(
            patterns.ACL_TARGET_ATTR_OID_EXTRACT,
            content,
            re.IGNORECASE,
        )
        if attr_match:
            attr_str = attr_match.group(1)
            attributes = [a.strip() for a in attr_str.split(",")]

        return target_dn, attributes

    @staticmethod
    def _detect_oid_subject(content: str) -> str | None:
        """Detect OID ACL subject type by matching ACL_SUBJECT_PATTERNS.

        Args:
            content: OID ACL content string

        Returns:
            Subject type ("self", "user_dn", "group_dn", "dn_attr", "guid_attr", "group_attr") or None

        """
        if not content:
            return None

        const = _OidConstants

        # Check for subject type by matching ACL_SUBJECT_PATTERNS keys
        # This identifies what kind of subject is present in the OID ACL
        for pattern_key, (_, subject_type, _) in (
            u.mapper().to_dict(const.ACL_SUBJECT_PATTERNS).items()
        ):
            # Check if the pattern key (literal substring) is present in content
            if pattern_key.lower() in content.lower():
                return subject_type

        return None

    @staticmethod
    def _parse_oid_permissions(content: str) -> dict[str, bool]:
        """Parse OID ACL permissions clause.

        Extracts OID permissions from ACL string and normalizes them using
        ACL_PERMISSION_MAPPING. Handles compound permissions (e.g., browse→read+search)
        and permission negation (e.g., nowrite→no_write).

        Args:
            content: OID ACL content string (e.g., "access to ... (read,write)")

        Returns:
            Permissions dict: normalized name → True (allow) / False (deny)
            E.g., {"read": True, "search": True, "browse": False}

        """
        permissions: dict[str, bool] = {}
        const = _OidConstants

        # Use OID-specific pattern to extract permissions from parentheses
        # OID format: (read,write) or (read,write,self_write)
        perm_match = re.search(const.ACL_PERMS_EXTRACT_OID, content, re.IGNORECASE)
        if perm_match:
            perms_str = perm_match.group(1)
            # Split by comma for OID format (not space-separated like RFC)
            raw_perms = [p.strip() for p in perms_str.split(",")]

            # Process each permission
            for raw_perm in raw_perms:
                if not raw_perm:
                    continue

                # Check for negative permission prefix
                is_negative = raw_perm.lower().startswith("no")
                perm_name = raw_perm

                # Normalize using ACL_PERMISSION_MAPPING
                if perm_name.lower() in const.ACL_PERMISSION_MAPPING:
                    # Get normalized permission names from mapping
                    mapped_names = const.ACL_PERMISSION_MAPPING[perm_name.lower()]
                    for mapped_name in mapped_names:
                        # Compound permissions map to multiple entries
                        # (e.g., browse → [read, search])
                        permissions[mapped_name] = not is_negative
                else:
                    # Unknown permission - store as-is
                    # This preserves any server-specific extensions
                    permissions[perm_name.lower()] = not is_negative

        return permissions

    @staticmethod
    def _format_oid_target(target_dn: str, attributes: list[str]) -> str:
        r"""Format OID ACL target clause.

        Generates OID orclaci format: "entry" or "attr=(...)"
        NOT RFC format: "target=\"*\" targetattr=\"...\""

        Args:
            target_dn: Target DN string ("entry", "*", etc.)
            attributes: List of target attributes

        Returns:
            Formatted OID target clause (e.g. "entry" or "attr=(cn,mail)")

        """
        # Handle entry-level targets
        if not attributes or target_dn == "entry":
            return "entry"
        # Handle all-attributes target
        if len(attributes) == 1 and attributes[0] == "*":
            return "attr=(*)"
        # Handle specific attributes
        attrs_str = ",".join(attributes)
        return f"attr=({attrs_str})"

    @staticmethod
    def clean_subject_value(subject_value: str) -> str:
        """Clean OID subject value by removing ldap:/// prefix and parser suffixes.

        Args:
            subject_value: Subject value with possible prefixes/suffixes

        Returns:
            Cleaned subject value

        """
        clean_value = subject_value

        # Strip ldap:/// prefix if present (comes from internal RFC storage)
        if clean_value.startswith("ldap:///"):
            clean_value = clean_value[8:]  # Remove "ldap:///" prefix
            # Also remove LDAP URL query parameters (e.g., ?scope=base, ?scope=sub)
            if "?" in clean_value:
                clean_value = clean_value.split("?")[0]

        # Strip parser-added suffixes (#GROUPDN, #LDAPURL, #USERDN)
        if "#" in clean_value:
            # Remove any suffix after # that matches known parser suffixes
            suffixes_to_strip = {"#GROUPDN", "#LDAPURL", "#USERDN"}
            for suffix in suffixes_to_strip:
                if clean_value.endswith(suffix):
                    clean_value = clean_value[: -len(suffix)]
                    break

        return clean_value

    @staticmethod
    def _format_oid_subject(subject_type: str, subject_value: str) -> str:
        r"""Format OID ACL subject clause in orclaci format.

        Generates OID orclaci format: "self", "*", "group=\"DN\"", "dnattr=(attr)", etc.
        NOT RFC format: "subject=\"userdn=*\""

        Args:
            subject_type: Subject type ("self", "anonymous", "group_dn", "dn_attr", etc.)
            subject_value: Subject value (DN, attribute name, etc., may have ldap:/// prefix or #SUFFIX from internal storage)

        Returns:
            Formatted OID subject clause (e.g. "self", "*", "group=\"cn=REDACTED_LDAP_BIND_PASSWORDs,dc=example,dc=com\"")

        """
        clean_value = FlextLdifServersOidAcl.clean_subject_value(subject_value)

        match subject_type.lower():
            case "self":
                return "self"
            case "anonymous" | "*":
                return "*"
            case "group_dn" | "group":
                # OID format: by group="DN"
                return f'group="{clean_value}"'
            case "user_dn" | "user":
                # OID format: by "DN"
                return f'"{clean_value}"'
            case "dn_attr":
                # OID format: by dnattr=(attribute)
                return f"dnattr=({clean_value})"
            case "guid_attr":
                # OID format: by guidattr=(attribute)
                return f"guidattr=({clean_value})"
            case "group_attr":
                # OID format: by groupattr=(attribute)
                return f"groupattr=({clean_value})"
            case _:
                # Default to user_dn style
                return f'"{clean_value}"' if clean_value else "*"

    @staticmethod
    def _format_oid_permissions(
        permissions: t.Ldif.MetadataDictMutable,
    ) -> str:
        """Format OID ACL permissions clause.

        OID uses simple comma-separated format: (write,compare,browse)
        NOT RFC format with allow/deny keywords.

        Args:
            permissions: Permissions dictionary (name -> True/False)

        Returns:
            Formatted OID permissions clause (e.g., "(write,compare)")

        """
        # Permission name mapping for OID format output
        # Maps internal names (with underscores) to OID format names
        permission_names = {
            "read": "read",
            "write": "write",
            "add": "add",
            "delete": "delete",
            "search": "search",
            "compare": "compare",
            "self_write": "selfwrite",
            "proxy": "proxy",
            "browse": "browse",
            "auth": "auth",
            "all": "all",
            "no_write": "nowrite",
            "no_add": "noadd",
            "no_delete": "nodelete",
            "no_browse": "nobrowse",
            "no_self_write": "noselfwrite",
        }

        # Collect only allowed permissions, mapping to OID format
        allowed_perms: list[str] = []
        for perm, allowed in u.mapper().to_dict(permissions).items():
            if allowed:
                # Map internal name to OID format name
                # mapper().get() returns the value directly, not a FlextResult
                oid_perm_name = u.mapper().get(permission_names, perm, default=perm)
                allowed_perms.append(oid_perm_name)

        # Generate simple OID format: (perm1,perm2,perm3)
        if allowed_perms:
            return f"({','.join(allowed_perms)})"
        # Default if no permissions allowed - this shouldn't normally happen
        return "(none)"

    def _build_metadata_extensions(
        self,
        metadata: (
            m.Ldif.QuirkMetadata
            | dict[
                str,
                str
                | int
                | float
                | bool
                | list[str]
                | dict[str, str | list[str]]
                | None,
            ]
            | None
        ),
    ) -> list[str]:
        """Build OID ACL extension clauses from metadata.

        Consolidates formatting of OID-specific metadata extensions:
        - Generic: filter, added_object_constraint
        - OID-specific: bindmode, DenyGroupOverride, AppendToAll, etc.

        Args:
            metadata: ACL metadata with extensions (domain or public model)

        Returns:
            List of formatted extension clauses

        """
        if not metadata:
            return []

        meta_extensions = self._extract_extensions_dict(metadata)
        if not meta_extensions:
            return []

        return self._format_extensions(meta_extensions)

    def _extract_extensions_dict(
        self,
        metadata: (
            m.Ldif.QuirkMetadata
            | dict[
                str,
                str
                | int
                | float
                | bool
                | list[str]
                | dict[str, str | list[str]]
                | None,
            ]
        ),
    ) -> dict[str, str | int | float | bool | list[str] | None]:
        """Extract extensions dict from metadata, converting types if needed.

        Args:
            metadata: Metadata in any acceptable format

        Returns:
            Dictionary of extensions or empty dict if none found

        """
        # Ensure metadata is m.Ldif.QuirkMetadata (public facade)
        if not isinstance(metadata, m.Ldif.QuirkMetadata):
            if hasattr(metadata, "model_dump"):
                metadata_dict = metadata.model_dump()
                metadata = m.Ldif.QuirkMetadata.model_validate(metadata_dict)
            elif isinstance(metadata, dict):
                metadata = m.Ldif.QuirkMetadata.model_validate(metadata)
            else:
                return {}

        return getattr(metadata, "extensions", None) or {}

    def _format_extensions(
        self,
        meta_extensions: dict[str, str | int | float | bool | list[str] | None],
    ) -> list[str]:
        """Format extension values based on metadata key type.

        Args:
            meta_extensions: Metadata extensions dictionary

        Returns:
            List of formatted extension clause strings

        """
        extensions: list[str] = []
        # MetadataKeys removed - use direct string keys

        # Generic extensions
        # u.mapper().get() returns T | None directly, not FlextResult
        acl_filter = u.mapper().get(meta_extensions, c.Ldif.MetadataKeys.ACL_FILTER)
        if acl_filter:
            extensions.append(f"filter={acl_filter}")

        acl_constraint = u.mapper().get(
            meta_extensions, c.Ldif.MetadataKeys.ACL_CONSTRAINT
        )
        if acl_constraint:
            extensions.append(f"added_object_constraint=({acl_constraint})")

        # Valued OID-specific extensions
        bindmode = u.mapper().get(meta_extensions, c.Ldif.MetadataKeys.ACL_BINDMODE)
        if bindmode:
            extensions.append(f"bindmode=({bindmode})")

        bind_ip_filter = u.mapper().get(
            meta_extensions, c.Ldif.MetadataKeys.ACL_BIND_IP_FILTER
        )
        if bind_ip_filter:
            extensions.append(f"bindipfilter=({bind_ip_filter})")

        constrain_to_added = u.mapper().get(
            meta_extensions, c.Ldif.MetadataKeys.ACL_CONSTRAIN_TO_ADDED_OBJECT
        )
        if constrain_to_added:
            extensions.append(f"constraintonaddedobject=({constrain_to_added})")

        # Boolean OID-specific extensions
        deny_group_override = u.mapper().get(
            meta_extensions, c.Ldif.MetadataKeys.ACL_DENY_GROUP_OVERRIDE
        )
        if deny_group_override:
            extensions.append("DenyGroupOverride")

        append_to_all = u.mapper().get(
            meta_extensions, c.Ldif.MetadataKeys.ACL_APPEND_TO_ALL
        )
        if append_to_all:
            extensions.append("AppendToAll")

        return extensions

    @staticmethod
    def _normalize_to_dict(
        value: (
            m.Ldif.AclSubject
            | m.Ldif.QuirkMetadata
            | dict[str, str | int | bool]
            | str
            | None
        ),
    ) -> dict[str, str | int | bool]:
        """Normalize value to dict for model validation.

        Args:
            value: Pydantic model, dict, or string

        Returns:
            Dictionary representation of value

        """
        # Business Rule: Convert value to dict format for ACL subject serialization.
        # Value can be dict, Pydantic model (with model_dump), or primitive type.
        # Implication: Type narrowing ensures we only call model_dump() on Pydantic models.
        if isinstance(value, dict):
            return value
        # Type narrowing: Check if value is a Pydantic model before calling model_dump()
        # Business Rule: Only Pydantic models have model_dump() method.
        # Implication: Use isinstance check or hasattr + callable check for type safety.
        if (
            value is not None
            and not isinstance(value, (str, int, float, bool))
            and hasattr(value, "model_dump")
            and callable(getattr(value, "model_dump", None))
        ):
            return value.model_dump()
        return {"subject_type": str(value)} if value else {}

    @staticmethod
    def _normalize_permissions_to_dict(
        permissions: (m.Ldif.AclPermissions | dict[str, bool] | None),
    ) -> dict[str, bool]:
        """Normalize permissions to dict for formatting.

        Args:
            permissions: Permissions model, dict, or None

        Returns:
            Dictionary representation of permissions

        """
        if not permissions:
            return {}
        if isinstance(permissions, dict):
            # Convert dict to normalized format
            # mapper().get() returns the value directly, not a FlextResult
            return {
                "read": bool(u.mapper().get(permissions, "read", default=False)),
                "write": bool(u.mapper().get(permissions, "write", default=False)),
                "add": bool(u.mapper().get(permissions, "add", default=False)),
                "delete": bool(u.mapper().get(permissions, "delete", default=False)),
                "search": bool(permissions.get("search", False)),
                "compare": bool(permissions.get("compare", False)),
                "self_write": bool(permissions.get("self_write", False)),
                "proxy": bool(permissions.get("proxy", False)),
                "browse": bool(permissions.get("browse", False)),
                "auth": bool(permissions.get("auth", False)),
                "all": bool(permissions.get("all", False)),
            }
        if isinstance(permissions, dict):
            raw_perms = permissions
            return {
                "read": bool(raw_perms.get("read")),
                "write": bool(raw_perms.get("write")),
                "add": bool(raw_perms.get("add")),
                "delete": bool(raw_perms.get("delete")),
                "search": bool(raw_perms.get("search")),
                "compare": bool(raw_perms.get("compare")),
                "self_write": bool(raw_perms.get("self_write")),
                "proxy": bool(raw_perms.get("proxy")),
                "browse": bool(raw_perms.get("browse")),
                "auth": bool(raw_perms.get("auth")),
                "all": bool(raw_perms.get("all")),
            }
        if hasattr(permissions, "model_dump") and callable(
            getattr(permissions, "model_dump", None),
        ):
            raw_perms = permissions.model_dump()
            return {
                "read": bool(raw_perms.get("read", False)),
                "write": bool(raw_perms.get("write", False)),
                "add": bool(raw_perms.get("add", False)),
                "delete": bool(raw_perms.get("delete", False)),
                "search": bool(raw_perms.get("search", False)),
                "compare": bool(raw_perms.get("compare", False)),
                "self_write": bool(raw_perms.get("self_write", False)),
                "proxy": bool(raw_perms.get("proxy", False)),
                "browse": bool(raw_perms.get("browse", False)),
                "auth": bool(raw_perms.get("auth", False)),
                "all": bool(raw_perms.get("all", False)),
            }
        return {}

    def _prepare_subject_value_with_suffix(
        self,
        subject_value: str,
        oid_subject_type: str,
    ) -> str:
        """Prepare subject value with OID-specific suffix if needed.

        Args:
            subject_value: Original subject value
            oid_subject_type: OID subject type

        Returns:
            Subject value with suffix if applicable

        """
        if (
            oid_subject_type in {"dn_attr", "guid_attr", "group_attr"}
            and "#" not in subject_value
        ):
            type_suffix = {
                "dn_attr": "LDAPURL",
                "guid_attr": "USERDN",
                "group_attr": "GROUPDN",
            }
            return f"{subject_value}#{type_suffix[oid_subject_type]}"
        return subject_value

    def _prepare_subject_and_permissions_for_write(
        self,
        acl_subject: (m.Ldif.AclSubject | dict[str, str | int | bool]),
        acl_permissions: (m.Ldif.AclPermissions | dict[str, bool] | None),
        metadata: (
            m.Ldif.QuirkMetadata
            | dict[
                str,
                str
                | int
                | float
                | bool
                | list[str]
                | dict[str, str | list[str]]
                | None,
            ]
            | None
        ),
    ) -> tuple[str, str]:
        """Prepare OID subject and permissions clauses for ACL write.

        Consolidates subject mapping, suffix handling, permissions formatting.

        Args:
            acl_subject: RFC-compliant subject (domain or public model)
            acl_permissions: Permissions model, dict, or None
            metadata: ACL metadata for source subject type (domain or public)

        Returns:
            Tuple of (subject_clause, permissions_clause)

        """
        # Convert to public models using helper
        subject_dict = self._normalize_to_dict(acl_subject)
        subject_public = m.Ldif.AclSubject.model_validate(subject_dict)

        # Normalize metadata - preserve extensions dict for source_subject_type lookup
        # Business Rule: metadata can be domain or facade, but we need facade
        metadata_public: m.Ldif.QuirkMetadata | None = None
        if metadata:
            # Business Rule: Preserve full metadata including extensions dict
            # The extensions dict contains source_subject_type needed for ACL writing
            if isinstance(metadata, m.Ldif.QuirkMetadata):
                # Already public facade, use as-is
                metadata_public = metadata
            elif hasattr(metadata, "model_dump"):
                # Domain model, convert to facade
                metadata_dict_raw = metadata.model_dump()
                metadata_public = m.Ldif.QuirkMetadata.model_validate(metadata_dict_raw)
            elif isinstance(metadata, dict):
                # Validate dict directly - preserve all fields including extensions
                metadata_public = m.Ldif.QuirkMetadata.model_validate(metadata)
            else:
                metadata_dict = self._normalize_to_dict(metadata)
                metadata_public = m.Ldif.QuirkMetadata.model_validate(
                    metadata_dict,
                )

        # Map RFC subject to OID subject type
        oid_subject_type = self._map_rfc_subject_to_oid(
            subject_public,
            metadata_public,
        )

        # Prepare subject value with suffix if needed
        subject_value = self._prepare_subject_value_with_suffix(
            subject_public.subject_value,
            oid_subject_type,
        )

        # Format subject clause
        subject_clause = self._format_oid_subject(
            oid_subject_type,
            subject_value,
        )

        # Convert and format permissions
        permissions_dict = self._normalize_permissions_to_dict(acl_permissions)
        # Convert dict[str, bool] to MetadataDictMutable for _format_oid_permissions
        permissions_metadata: t.Ldif.MetadataDictMutable = cast(
            "t.Ldif.MetadataDictMutable",
            permissions_dict,
        )
        permissions_clause = self._format_oid_permissions(permissions_metadata)

        return subject_clause, permissions_clause

    def _map_oid_subject_to_rfc(
        self,
        oid_subject_type: str,
        oid_subject_value: str,
    ) -> tuple[str, str]:
        """Map OID subject types to RFC subject types."""
        if oid_subject_type == "self":
            return "self", "ldap:///self"
        if oid_subject_type == "group_dn":
            # Map group_dn to "group" subject type
            return "group", oid_subject_value
        if oid_subject_type == "user_dn":
            # Map user_dn to "dn" subject type
            return "dn", oid_subject_value
        if oid_subject_type in {"dn_attr", "guid_attr", "group_attr"}:
            # Map attribute-based types to "dn" with the attribute value
            return "dn", oid_subject_value
        if oid_subject_type == "*" or oid_subject_value == "*":
            return "anonymous", "*"
        # Default fallback: use "dn" for unknown types
        return "dn", oid_subject_value

    def _build_oid_acl_metadata(
        self,
        config: FlextLdifServersOidAcl.OidAclMetadataConfig,
    ) -> dict[str, str | int | bool]:
        """Build metadata extensions for OID ACL with Oracle-specific features.

        Delegates to u.Metadata.build_acl_metadata_complete()
        for unified ACL metadata construction.

        Args:
            config: OidAclMetadataConfig with all ACL metadata parameters

        Returns:
            Metadata extensions dict for zero-data-loss preservation

        """
        # Convert complex types to ScalarValue (str) for build_acl_metadata_complete
        # which only accepts ScalarValue (str | int | float | bool | datetime | None)
        target_attrs_str: str | None = (
            json.dumps(config.target_attrs) if config.target_attrs else None
        )
        permissions_str: str | None = (
            json.dumps(config.perms_dict) if config.perms_dict else None
        )

        metadata_dict = FlextLdifUtilitiesMetadata.build_acl_metadata_complete(
            "oid",  # quirk_type - required first positional argument
            acl_line=config.acl_line,
            server_type="oid",
            subject_type=config.oid_subject_type,
            subject_value=config.oid_subject_value,
            target_dn=config.target_dn,
            target_attrs=target_attrs_str,
            permissions=permissions_str,
            target_subject_type=config.rfc_subject_type,
            acl_filter=config.acl_filter,
            acl_constraint=config.acl_constraint,
            bindmode=config.bindmode,
            deny_group_override=config.deny_group_override is True,
            append_to_all=config.append_to_all is True,
            bind_ip_filter=config.bind_ip_filter,
            constrain_to_added_object=config.constrain_to_added_object,
            target_key=FlextLdifServersOidConstants.OID_ACL_SOURCE_TARGET,
        )
        # Store original OID subject type as source_subject_type for conversion
        if config.oid_subject_type:
            metadata_dict["acl_source_subject_type"] = config.oid_subject_type
        return metadata_dict

    def _parse_oid_specific_acl(
        self,
        acl_line: str,
    ) -> FlextResult[m.Ldif.Acl]:
        """Parse OID-specific ACL format when RFC parser fails."""
        # OID ACL format: orclaci: access to [Union[entry, attr]=(...)]
        #   [by subject (permissions)] [filter=(...)] [added_object_constraint=()]
        try:
            # Extract target using OID-specific method
            target_dn, target_attrs = self._extract_oid_target(acl_line)
            # Default to "entry" if no explicit target DN specified
            if not target_dn:
                target_dn = "entry"

            # Detect subject using OID-specific method
            oid_subject_type = self._detect_oid_subject(acl_line)
            # Extract subject value using DRY utility (OUD pattern)
            oid_subject_value: str | None = None
            if oid_subject_type:
                for (
                    regex,
                    subj_type,
                    _,
                ) in FlextLdifServersOidConstants.ACL_SUBJECT_PATTERNS.values():
                    if subj_type == oid_subject_type and regex:
                        oid_subject_value = FlextLdifUtilitiesACL.extract_component(
                            acl_line,
                            regex,
                            group=1,
                        )
                        if oid_subject_value:
                            break
                oid_subject_value = oid_subject_value or "*"
            else:
                oid_subject_type = "self"
                oid_subject_value = "self"

            # Map OID subject types to RFC subject types
            rfc_subject_type, rfc_subject_value = self._map_oid_subject_to_rfc(
                oid_subject_type,
                oid_subject_value,
            )

            # Parse permissions using OID-specific method
            perms_dict = self._parse_oid_permissions(acl_line)

            # Extract filter and constraint using DRY utility (OUD pattern)
            acl_filter = FlextLdifUtilitiesACL.extract_component(
                acl_line,
                FlextLdifServersOidConstants.ACL_FILTER_PATTERN,
                group=1,
            )
            acl_constraint = FlextLdifUtilitiesACL.extract_component(
                acl_line,
                FlextLdifServersOidConstants.ACL_CONSTRAINT_PATTERN,
                group=1,
            )

            # Extract OID-specific extensions using DRY utility
            bindmode = FlextLdifUtilitiesACL.extract_component(
                acl_line,
                FlextLdifServersOidConstants.ACL_BINDMODE_PATTERN,
                group=1,
            )
            deny_group_override = (
                FlextLdifUtilitiesACL.extract_component(
                    acl_line,
                    FlextLdifServersOidConstants.ACL_DENY_GROUP_OVERRIDE_PATTERN,
                )
                is not None
            )
            append_to_all = (
                FlextLdifUtilitiesACL.extract_component(
                    acl_line,
                    FlextLdifServersOidConstants.ACL_APPEND_TO_ALL_PATTERN,
                )
                is not None
            )
            bind_ip_filter = FlextLdifUtilitiesACL.extract_component(
                acl_line,
                FlextLdifServersOidConstants.ACL_BIND_IP_FILTER_PATTERN,
                group=1,
            )
            constrain_to_added_object = FlextLdifUtilitiesACL.extract_component(
                acl_line,
                FlextLdifServersOidConstants.ACL_CONSTRAIN_TO_ADDED_PATTERN,
                group=1,
            )

            # Build metadata extensions using config object
            config = self.OidAclMetadataConfig(
                acl_line=acl_line,
                oid_subject_type=oid_subject_type,
                rfc_subject_type=rfc_subject_type,
                oid_subject_value=oid_subject_value,
                perms_dict=perms_dict,
                target_dn=target_dn,
                target_attrs=target_attrs,
                acl_filter=acl_filter,
                acl_constraint=acl_constraint,
                bindmode=bindmode,
                deny_group_override=deny_group_override,
                append_to_all=append_to_all,
                bind_ip_filter=bind_ip_filter,
                constrain_to_added_object=constrain_to_added_object,
            )
            extensions = self._build_oid_acl_metadata(config)

            # Create ACL model with parsed data (Python 3.13: cleaner dict creation)
            # Use RFC name (aci) for Entry model (OID → RFC conversion)
            # Use literal directly for type safety
            server_type: str = "oid"

            # Architecture: Filter permissions to RFC-compliant only
            # Server-specific permissions (like OID's "none") are preserved in metadata.extensions
            # via build_acl_metadata_complete(permissions=config.perms_dict) above
            rfc_compliant_perms = m.Ldif.AclPermissions.get_rfc_compliant_permissions(
                perms_dict,
            )

            # Ensure rfc_subject_type is a valid Literal type for AclSubject
            # _map_oid_subject_to_rfc returns tuple[str, str], but subject_type must be Literal
            subject_type_literal: Literal[
                "user",
                "group",
                "role",
                "self",
                "all",
                "public",
                "anonymous",
                "authenticated",
                "dn",
                "user_dn",
                "userdn",
                "sddl",
            ] = cast(
                "Literal['user', 'group', 'role', 'self', 'all', 'public', 'anonymous', 'authenticated', 'dn', 'user_dn', 'userdn', 'sddl']",
                rfc_subject_type,
            )

            # Convert extensions to DynamicMetadata format
            # extensions is dict[str, str | int | bool] from build_acl_metadata_complete
            # QuirkMetadata.extensions accepts DynamicMetadata | dict[str, MetadataAttributeValue] | None
            # Create DynamicMetadata instance from dict
            extensions_metadata = FlextLdifModelsMetadata.DynamicMetadata(**extensions)

            acl_model = m.Ldif.Acl(
                name=FlextLdifServersRfc.Constants.ACL_ATTRIBUTE_NAME,
                target=m.Ldif.AclTarget(
                    target_dn=target_dn,
                    attributes=target_attrs or [],
                ),
                subject=m.Ldif.AclSubject(
                    subject_type=subject_type_literal,
                    subject_value=rfc_subject_value,
                ),
                permissions=m.Ldif.AclPermissions(**rfc_compliant_perms),
                server_type=server_type,
                metadata=m.Ldif.QuirkMetadata(
                    quirk_type=server_type,
                    extensions=extensions_metadata,
                ),
                raw_acl=acl_line,
            )
            return FlextResult[m.Ldif.Acl].ok(acl_model)
        except Exception as e:
            # Python 3.13: Walrus operator for cleaner code
            max_len = FlextLdifServersOidConstants.MAX_LOG_LINE_LENGTH
            acl_preview = acl_line[:max_len] if len(acl_line) > max_len else acl_line
            logger.debug(
                "OID ACL parse failed",
                error=str(e),
                error_type=type(e).__name__,
                acl_line=acl_preview,
                acl_line_length=len(acl_line),
            )
            # Return error result
            return FlextResult[m.Ldif.Acl].fail(
                f"OID ACL parsing failed: {e}",
            )

    # REMOVED: _get_oid_patterns (36 lines dead code - never called)
    # Constants.ACL_*_PATTERN are used directly where needed

    def convert_rfc_acl_to_aci(
        self,
        rfc_acl_attrs: dict[str, list[str]],
        target_server: str = "oid",
    ) -> FlextResult[dict[str, list[str]]]:
        """Convert RFC ACL format to Oracle OID orclaci format.

        Returns RFC format unchanged (RFC ACLs are compatible with OID).

        Args:
            rfc_acl_attrs: ACL attributes in RFC format
            target_server: Target server type (unused, maintained for API compatibility)

        Returns:
            FlextResult with RFC ACL attributes (unchanged, compatible with OID)

        """
        _ = target_server  # Unused, required for parent class interface
        return FlextResult.ok(rfc_acl_attrs)

    def _write_acl(
        self,
        acl_data: m.Ldif.Acl,
        _format_option: str | None = None,
    ) -> FlextResult[str]:
        r"""Write ACL to OID orclaci format (Phase 2: Denormalization).

        OID vs RFC ACL Writing
        ======================
        This method converts RFC-normalized Acl models back to Oracle OID
        orclaci format for LDIF output.

        Output Format (OID)
        -------------------
        orclaci: access to <target> by <subject> (<permissions>)

        Writing Strategy
        ----------------
        1. If raw_acl in OID format exists, use it directly (round-trip)
        2. Otherwise, build OID format from RFC-normalized model:
           a) Add ACL type prefix (orclaci:)
           b) Format target clause
           c) Format subject clause
           d) Format permissions clause
           e) Add metadata extensions

        Input Model (RFC-normalized)
        ----------------------------
        Acl(
            permissions={'browse': True, 'add': True},
            target=AclTarget(target_dn='entry', attributes=None),
            subject=AclSubject(type='group', dn='cn=Admins,...'),
            scope='subtree',
            metadata=m.Ldif.QuirkMetadata(server_type='oid', ...)
        )

        Output (OID Format)
        -------------------
        orclaci: access to entry by group="cn=Admins,dc=example,dc=com" (browse,add)

        Format Components
        -----------------
        1. ACL Type: orclaci: | orclentrylevelaci:
        2. Access To: "access to"
        3. Target:
           - entry → "entry"
           - attr=(*) → "attr=(*)"
           - attr=(cn,sn) → "attr=(cn,sn)"
        4. By: "by"
        5. Subject:
           - * → "*"
           - self → "self"
           - user DN → "\"cn=user,...\""
           - group → "group=\"cn=group,...\""
        6. Permissions: "(browse,add,delete)"

        Metadata Restoration
        --------------------
        If metadata.extensions contains original OID format details,
        they are used to reconstruct the exact original format:
        - acl_type: orclaci vs orclentrylevelaci
        - original_permissions: Original permission order
        - filter: Original filter expression
        - constraint: Original constraint expression

        Args:
            acl_data: RFC-normalized Acl model to write
            _format_option: Formatting option (unused, OID uses standard format)

        Returns:
            FlextResult with OID orclaci formatted string

        """
        # If raw_acl is available and already in OID format, use it
        if acl_data.raw_acl and acl_data.raw_acl.startswith(
            FlextLdifServersOidConstants.ORCLACI + ":",
        ):
            return FlextResult[str].ok(acl_data.raw_acl)

        # Build orclaci format using consolidated helpers
        acl_parts = [
            FlextLdifServersOidConstants.ORCLACI + ":",
            FlextLdifServersOidConstants.ACL_ACCESS_TO,
        ]

        # Add target if available
        if acl_data.target:
            target_public = m.Ldif.AclTarget.model_validate(
                acl_data.target.model_dump(),
            )
            acl_parts.append(
                self._format_oid_target(
                    target_public.target_dn,
                    target_public.attributes or [],
                ),
            )

        # Format subject and permissions if available (consolidated in helper)
        if acl_data.subject:
            # Ensure all arguments are m.* (public facade) types
            # Business Rule: acl_data fields can be domain or facade, but methods need facade
            subject_public = (
                m.Ldif.AclSubject.model_validate(acl_data.subject.model_dump())
                if not isinstance(acl_data.subject, m.Ldif.AclSubject)
                else acl_data.subject
            )
            # Ensure permissions is always m.Ldif.AclPermissions | None (public facade)
            if acl_data.permissions:
                if isinstance(acl_data.permissions, m.Ldif.AclPermissions):
                    permissions_public = acl_data.permissions
                else:
                    permissions_dict = acl_data.permissions.model_dump()
                    permissions_public = m.Ldif.AclPermissions.model_validate(
                        permissions_dict,
                    )
            else:
                permissions_public = None
            # Ensure metadata is always m.Ldif.QuirkMetadata | None (public facade)
            if acl_data.metadata:
                if isinstance(acl_data.metadata, m.Ldif.QuirkMetadata):
                    metadata_public = acl_data.metadata
                else:
                    metadata_dict = acl_data.metadata.model_dump()
                    metadata_public = m.Ldif.QuirkMetadata.model_validate(metadata_dict)
            else:
                metadata_public = None
            subject_clause, permissions_clause = (
                self._prepare_subject_and_permissions_for_write(
                    subject_public,
                    permissions_public,
                    metadata_public,
                )
            )
            acl_parts.extend(
                [
                    FlextLdifServersOidConstants.ACL_BY,
                    subject_clause,
                    permissions_clause,
                ],
            )

        # Add metadata extensions (consolidated in helper)
        # Ensure metadata is m.Ldif.QuirkMetadata (public facade)
        if acl_data.metadata:
            if isinstance(acl_data.metadata, m.Ldif.QuirkMetadata):
                metadata_public = acl_data.metadata
            else:
                metadata_dict = acl_data.metadata.model_dump()
                metadata_public = m.Ldif.QuirkMetadata.model_validate(metadata_dict)
        else:
            metadata_public = None
        acl_parts.extend(self._build_metadata_extensions(metadata_public))

        # Join parts (both formats use same join - DRY)
        orclaci_str = " ".join(acl_parts)
        return FlextResult[str].ok(orclaci_str)

    def _get_source_subject_type(
        self,
        metadata: m.Ldif.QuirkMetadata | None,
    ) -> str | None:
        """Get source subject type from metadata."""
        if not metadata or not metadata.extensions:
            return None

        # MetadataKeys removed - use direct string keys
        source_subject_type_raw = metadata.extensions.get(
            c.Ldif.MetadataKeys.ACL_SOURCE_SUBJECT_TYPE,
        )
        if source_subject_type_raw is None or isinstance(
            source_subject_type_raw,
            str,
        ):
            return source_subject_type_raw
        msg = f"Expected Optional[str], got {type(source_subject_type_raw)}"
        raise TypeError(msg)

    def _map_bind_rules_to_oid(
        self,
        rfc_subject_value: str,
        source_subject_type: str | None,
    ) -> str:
        """Map bind_rules/group to OID subject type."""
        # Check for attribute-based subject types from source metadata
        if source_subject_type in {"dn_attr", "guid_attr", "group_attr"}:
            return source_subject_type
        # Determine if it's group_dn or user_dn based on value
        if source_subject_type in {"group_dn", "user_dn"}:
            return source_subject_type
        # OUD uses "group" as subject_type for groupdn - map to group_dn for OID
        if source_subject_type == "group":
            return "group_dn"
        if (
            "group=" in rfc_subject_value.lower()
            or "groupdn" in rfc_subject_value.lower()
        ):
            return "group_dn"
        # Detect group DN by checking if DN path contains "cn=groups"
        # (e.g., cn=REDACTED_LDAP_BIND_PASSWORDs,cn=groups,dc=example,dc=com indicates a group)
        if "cn=groups" in rfc_subject_value.lower():
            return "group_dn"
        return "user_dn"

    def _map_rfc_subject_to_oid(
        self,
        rfc_subject: m.Ldif.AclSubject,
        metadata: m.Ldif.QuirkMetadata | None,
    ) -> str:
        """Map RFC subject type to OID subject type for writing.

        Args:
            rfc_subject: RFC-compliant subject model
            metadata: ACL metadata with original OID subject type

        Returns:
            OID subject type for writing

        """
        rfc_subject_type = rfc_subject.subject_type
        rfc_subject_value = rfc_subject.subject_value

        # Read source subject type from GENERIC metadata
        source_subject_type = self._get_source_subject_type(metadata)

        # If source_subject_type is an attribute-based type, use it directly
        if source_subject_type in {"dn_attr", "guid_attr", "group_attr"}:
            return source_subject_type

        # Map RFC → OID for write (using match/case for clarity)
        match rfc_subject_type:
            case "self":
                return "self"
            case "anonymous":
                return "*"
            case rfc_type if rfc_subject_value == "*":
                return "*"
            case rfc_type if rfc_type in {
                "dn_attr",
                "guid_attr",
                "group_attr",
                "group_dn",
                "user_dn",
            }:
                # Return attribute-based types as-is
                return rfc_type
            case "bind_rules" | "group":
                # Map bind_rules/group to OID-specific type
                return self._map_bind_rules_to_oid(
                    rfc_subject_value,
                    source_subject_type,
                )
            case "dn":
                # If RFC type is "dn" but source_subject_type is attribute-based, use source
                if source_subject_type in {"dn_attr", "guid_attr", "group_attr"}:
                    return source_subject_type
                return "user_dn"
            case _:
                # Default fallback
                return source_subject_type or "user_dn"
