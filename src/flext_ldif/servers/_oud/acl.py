"""Oracle Unified Directory (OUD) Quirks.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Provides OUD-specific quirks for schema, ACL, and entry processing.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, ClassVar, cast

from flext_core import FlextLogger, FlextResult

from flext_ldif.constants import c
from flext_ldif.models import m
from flext_ldif.protocols import FlextLdifProtocols
from flext_ldif.servers._base.acl import FlextLdifServersBaseSchemaAcl
from flext_ldif.servers._oud.constants import FlextLdifServersOudConstants
from flext_ldif.servers.rfc import FlextLdifServersRfc
from flext_ldif.typings import t
from flext_ldif.utilities import u

# Aliases for simplified usage
p = FlextLdifProtocols

if TYPE_CHECKING:
    from flext_ldif.services.acl import FlextLdifAcl

logger = FlextLogger(__name__)


class FlextLdifServersOudAcl(FlextLdifServersRfc.Acl):
    """Oracle OUD ACL Implementation (RFC 4876 ACI Format).

    Extends RFC baseline with Oracle OUD-specific Access Control Instruction (ACI) format.
    OUD implements RFC 4876 with significant vendor extensions.

    RFC vs OUD ACI Differences
    ==========================

    **RFC Baseline** (RFC 4876):

    - Basic ACI structure: ``(target)(version;acl "name";permission subject;)``
    - Limited permissions: read, write, add, delete, search, compare
    - Basic bind rules: userdn, groupdn

    **OUD Extensions** (Oracle Docs):

    1. **Extended Permissions** (Oracle-specific):

       - ``selfwrite``: Add/delete own DN from DN-valued attributes (group membership)
       - ``proxy``: Access resources with another entry's rights (impersonation)
       - ``import``: Import entries from another server during modRDN
       - ``export``: Export entries to another server during modRDN
       - ``all``: Grants read, write, search, delete, compare, selfwrite (NOT proxy/import/export)

    2. **Extended Targets** (Oracle-specific):

       - ``targetscope``: base|onelevel|subtree|subordinate (limits ACI scope)
       - ``targattrfilters``: Attribute value filtering ``add=attr:(filter);delete=attr:(filter)``
       - ``targetcontrol``: LDAP control OIDs for extended operations
       - ``extop``: Extended operation OIDs (StartTLS, Password Modify, etc.)

    3. **Extended Bind Rules** (Oracle-specific):

       - ``ip="192.168.1.0/24"``: Source IP address/CIDR filtering
       - ``dns="*.example.com"``: DNS domain-based restrictions
       - ``timeofday="0800-1700"``: Time-of-day restrictions (24h format HHMM-HHMM)
       - ``dayofweek="Mon,Tue,Wed"``: Day-of-week restrictions
       - ``authmethod="simple|ssl|sasl"``: Authentication method requirements
       - ``ssf="40"``: Security Strength Factor (minimum encryption key size)
       - ``roledn``: Role-based access control

    4. **Special Subjects** (Oracle-specific):

       - ``userdn="ldap:///self"``: The authenticated user themselves
       - ``userdn="ldap:///anyone"``: Any user (including anonymous)
       - ``userdn="ldap:///all"``: All authenticated users

    5. **Multi-line ACI Format** (Oracle-specific):

       OUD supports multi-line ACIs with continuation (leading whitespace)::

           aci: (targetattr="*")(version 3.0; acl "Multi-permission";
                allow (read,search,write,selfwrite,compare)
                groupdn="ldap:///cn=Group1,dc=example,dc=com";
                allow (read,search,compare) userdn="ldap:///anyone";)

    ACI Syntax Reference
    --------------------

    Complete OUD ACI format::

        aci: (target)(version 3.0;acl "name";permissionBindRules;)

    Where:
    - ``target``: Optional. Entry scope ``(target="ldap:///dn")``
    - ``targetattr``: Optional. Attributes ``(targetattr="cn || sn")`` or ``(targetattr="*")``
    - ``targetfilter``: Optional. LDAP filter ``(targetfilter="(objectClass=person)")``
    - ``version 3.0``: Required. Fixed version string
    - ``acl "name"``: Required. Human-readable ACL name
    - ``permission``: Required. ``allow|deny (rights)``
    - ``bindRules``: Required. Subject specification

    Real Examples (from fixtures)
    -----------------------------

    **Single Group Permission**::

        aci: (targetattr="*")(version 3.0; acl "OracleContext accessible by Admins";
             allow (all) groupdn="ldap:///cn=OracleContextAdmins,cn=groups,dc=example,dc=com";)

    **Attribute Exclusion** (``!=`` syntax)::

        aci: (targetattr!="userpassword||authpassword||aci")
             (version 3.0; acl "Anonymous read"; allow (read,search,compare)
             userdn="ldap:///anyone";)

    **Multiple Permissions per ACI**::

        aci: (targetattr="*")(version 3.0; acl "DAS Group Access";
             allow (read,search,write,selfwrite,compare)
             groupdn="ldap:///cn=OracleDASUserPriv,cn=Groups,cn=OracleContext";
             allow (read,search,compare) userdn="ldap:///anyone";)

    Official Documentation
    ----------------------

    - ACI Syntax: https://docs.oracle.com/cd/E22289_01/html/821-1277/aci-syntax.html
    - Access Control Model: https://docs.oracle.com/en/middleware/idm/unified-directory/12.2.1.3/oudag/understanding-access-control-model-oracle-unified-directory.html

    Example Usage
    -------------

    ::

        quirk = FlextLdifServersOudAcl()
        if quirk.can_handle(acl_line):
            result = quirk.parse(acl_line)
            if result.is_success:
                acl_model = result.unwrap()
                # Access OUD-specific fields via metadata.extensions

    """

    # =====================================================================
    # PROTOCOL IMPLEMENTATION: FlextLdifProtocols.ServerAclProtocol
    # =====================================================================

    # RFC Foundation - Standard LDAP attributes (all servers start here)
    RFC_ACL_ATTRIBUTES: ClassVar[list[str]] = [
        "aci",  # Standard LDAP (RFC 4876)
        "acl",  # Alternative format
        "olcAccess",  # OpenLDAP
        "aclRights",  # Generic rights
        "aclEntry",  # ACL entry
    ]

    # OUD-specific ACL extensions
    # Oracle ACI compatibility (alternative ACL format support)
    OUD_ACL_ATTRIBUTES: ClassVar[list[str]] = [
        "ds-privilege-name",  # OUD privilege system - native OUD attribute
    ]

    def get_acl_attributes(self) -> list[str]:
        """Get RFC + OUD extensions.

        Returns:
            List of ACL attribute names (RFC foundation + OUD-specific)

        """
        return self.RFC_ACL_ATTRIBUTES + self.OUD_ACL_ATTRIBUTES

    # is_acl_attribute inherited from base class (uses set for O(1) lookup)

    # OVERRIDDEN METHODS (from FlextLdifServersBase.Acl)
    # These methods override the base class with Oracle OUD-specific logic:
    # - can_handle(): Detects OUD ACL formats
    # - parse(): Normalizes Oracle OUD ACL to RFC-compliant internal model
    # - write(): Serializes RFC-compliant model to OUD ACI format
    # - get_attribute_name(): Returns "aci" (OUD-specific, overridden)

    # Oracle OUD server configuration defaults

    def __init__(
        self,
        acl_service: FlextLdifAcl | None = None,
        _parent_quirk: p.Quirks.ParentQuirkProtocol | None = None,
        **kwargs: str | float | bool | None,
    ) -> None:
        """Initialize OUD ACL quirk.

        Args:
            acl_service: Injected FlextLdifAcl service (optional)
            _parent_quirk: Reference to parent quirk (optional, must satisfy ParentQuirkProtocol)
            **kwargs: Additional arguments passed to parent

        """
        # Business Rule: Filter _parent_quirk from kwargs to avoid type errors
        # Implication: _parent_quirk is handled separately, not via Pydantic fields
        # Business Rule: Only pass GeneralValueType (str | float | bool | None) to super().__init__
        # Implication: Filter kwargs to ensure type safety (int is not GeneralValueType, only str/float/bool/None)
        filtered_kwargs: dict[str, str | float | bool | None] = {
            k: v
            for k, v in kwargs.items()
            if k != "_parent_quirk" and isinstance(v, (str, float, bool, type(None)))
        }
        # Business Rule: Acl.__init__ accepts acl_service and _parent_quirk
        # Cast acl_service to HasParseMethodProtocol for type compatibility
        from typing import cast

        acl_service_typed: p.Services.HasParseMethodProtocol | None = (
            cast("p.Services.HasParseMethodProtocol", acl_service)
            if acl_service is not None
            else None
        )
        # Call base class __init__ directly to avoid mypy inference issues through nested class
        # Business Rule: _parent_quirk must satisfy ParentQuirkProtocol
        parent_quirk_typed: p.Quirks.ParentQuirkProtocol | None = (
            cast("p.Quirks.ParentQuirkProtocol", _parent_quirk)
            if _parent_quirk is not None
            else None
        )
        FlextLdifServersBaseSchemaAcl.__init__(
            self,
            acl_service=acl_service_typed,
            _parent_quirk=parent_quirk_typed,
            **filtered_kwargs,
        )
        # NOTE: Hook registration was removed - AclConverter was moved to services/acl.py
        # Use FlextLdifAcl instead for ACL conversion operations

    # NOTE: Obsolete method removed - hook registration pattern changed
    # AclConverter was moved to services/acl.py as FlextLdifAcl
    # Use FlextLdifAcl for ACL format conversions (RFC → server-specific format)

    def can_handle(self, acl_line: t.AclOrString) -> bool:
        """Check if this is an Oracle OUD ACL (public method).

        Args:
            acl_line: ACL line string or Acl model to check.

        Returns:
            True if this is Oracle OUD ACL format

        """
        # Type narrowing: t.AclOrString is str | m.Acl, compatible with can_handle_acl signature
        # Use cast to ensure type checker knows it's compatible
        return self.can_handle_acl(cast("str | m.Acl", acl_line))

    def can_handle_acl(self, acl_line: str | m.Acl) -> bool:
        """Check if this is an Oracle OUD ACL line (implements abstract method from base.py).

        RFC vs OUD Behavior Differences
        ================================

        **RFC Baseline** (in rfc.py):
        - Returns ``True`` for ALL ACL lines (catch-all fallback)
        - Does not inspect ACL format or content
        - RFC is the universal fallback when no server-specific handler matches

        **OUD Override** (this method):
        - Returns ``True`` ONLY for OUD-specific ACL formats
        - Detects ACL format by inspecting content patterns
        - Allows RFC fallback for non-OUD formats

        Detects Oracle OUD ACL by checking if the line starts with:

        - ``aci:`` - RFC 4876 compliant ACI attribute prefix
        - ``targetattr=`` - Inline ACI format (attribute target)
        - ``targetscope=`` - Inline ACI format (scope target)
        - ``version 3.0`` - ACI version marker (OUD uses version 3.0)
        - ``ds-cfg-`` - OUD configuration ACL (server config attributes)

        Also handles ``ds-privilege-name`` format: Simple privilege names without
        parentheses or equals signs (e.g., "config-read", "password-reset").

        Args:
            acl_line: Raw ACL line string or Acl model from LDIF

        Returns:
            True if this is Oracle OUD ACL format

        References:
            - RFC 4876: Access Control Instruction (ACI) Format
            - Oracle OUD 14.1.2: https://docs.oracle.com/en/middleware/idm/unified-directory/14.1.2/oudag/understanding-access-control-model-oracle-unified-directory.html

        """
        # Handle Acl model: check metadata quirk type or attribute name
        if not isinstance(acl_line, str):
            # Type narrowing: acl_line is m.Acl
            if isinstance(acl_line, m.Acl):
                # Check metadata quirk type
                if (
                    acl_line.metadata
                    and hasattr(acl_line.metadata, "quirk_type")
                    and acl_line.metadata.quirk_type
                ):
                    return str(acl_line.metadata.quirk_type) == self._get_server_type()
                # Check name attribute
                if hasattr(acl_line, "name") and acl_line.name:
                    return u.Schema.normalize_attribute_name(
                        acl_line.name,
                    ) == u.Schema.normalize_attribute_name(
                        FlextLdifServersOudConstants.ACL_ATTRIBUTE_NAME,
                    )
            return False

        # Handle string: empty string check (type narrowed after Acl check above)
        if not isinstance(acl_line, str) or not (normalized := acl_line.strip()):
            return False

        # Check for OUD ACL patterns using constants
        normalized_lower = normalized.lower()
        oud_prefixes = [
            FlextLdifServersOudConstants.ACL_ACI_PREFIX,
            FlextLdifServersOudConstants.ACL_TARGETATTR_PREFIX,
            FlextLdifServersOudConstants.ACL_TARGETSCOPE_PREFIX,
            FlextLdifServersOudConstants.ACL_DEFAULT_VERSION,
        ]

        # RFC 4876 ACI format OR OUD config ACL
        # Type narrowing: normalized is str after isinstance check
        if (
            any(normalized.startswith(prefix) for prefix in oud_prefixes)
            or "ds-cfg-" in normalized_lower
        ):
            return True

        # ds-privilege-name format: simple privilege names without prohibited patterns
        return not any(
            pattern in normalized_lower for pattern in ["access to", "(", ")", "=", ":"]
        )

    def _parse_acl(self, acl_line: str) -> FlextResult[m.Acl]:
        """Parse Oracle OUD ACL string to RFC-compliant internal model.

        RFC vs OUD Behavior Differences
        ================================

        **RFC Baseline** (in rfc.py):
        - Simple passthrough: stores raw ACL line in ``raw_acl`` field
        - No parsing of ACL structure (target, permissions, subject)
        - Model fields (name, target, permissions, subject) remain None

        **OUD Override** (this method):
        - Full parsing of OUD ACI format into structured model
        - Extracts and populates: name, target, permissions, subject
        - Handles OUD-specific extensions: timeofday, dayofweek, ip, dns, ssf, authmethod
        - Stores OUD-specific data in metadata.extensions

        Supported OUD ACL Formats
        -------------------------

        1. **RFC 4876 ACI format** (primary OUD format)::

            aci: (targetattr="cn || sn")(version 3.0; acl "Allow Read"; allow (read) userdn="ldap:///self";)

        2. **ds-privilege-name format** (OUD REDACTED_LDAP_BIND_PASSWORDistrative privileges)::

            config - read
            password - reset
            bypass - acl

        OUD ACI Syntax (RFC 4876 + Oracle Extensions)
        ---------------------------------------------

        ::

            aci: (target)(version 3.0;acl "name";permissionBindRules;)

        **Target Types**:
        - ``target`` - Entry DN scope (e.g., ``target="ldap:///ou=people,dc=example,dc=com"``)
        - ``targetattr`` - Attribute filter (e.g., ``targetattr="cn || sn || mail"``)
        - ``targetfilter`` - LDAP filter (e.g., ``targetfilter="(objectClass=person)"``)
        - ``targetscope`` - Scope (base|onelevel|subtree|subordinate)
        - ``targattrfilters`` - Attribute filters for add/delete operations
        - ``targetcontrol`` - Control OID restrictions
        - ``extop`` - Extended operation OID restrictions

        **Permissions**: read, write, add, delete, search, compare, selfwrite, proxy,
        import, export, all

        **Bind Rules**:
        - ``userdn`` - User DN match (ldap:///self, ldap:///anyone, ldap:///all)
        - ``groupdn`` - Group membership
        - ``roledn`` - Role-based access (OUD uses groups, not roles)
        - ``userattr`` - Value matching between user and target attributes
        - ``ip`` - IP address/CIDR range
        - ``dns`` - DNS domain pattern
        - ``timeofday`` - Time restriction (HHMM-HHMM)
        - ``dayofweek`` - Day restriction (Mon,Tue,Wed,...)
        - ``authmethod`` - Authentication method (simple|ssl|sasl)
        - ``ssf`` - Security strength factor

        Note: OUD does NOT parse Oracle Internet Directory (OID) formats directly.
        If receiving OID data, it must be pre-converted via RFC Entry Model first.

        Args:
            acl_line: ACL definition line (ACI format or ds-privilege-name)

        Returns:
            FlextResult with OUD ACL Pydantic model

        References:
            - RFC 4876: Access Control Instruction (ACI) Format
            - Oracle OUD ACI Syntax: https://docs.oracle.com/cd/E22289_01/html/821-1277/aci-syntax.html

        """
        # Type guard: ensure acl_line is a string
        if not isinstance(acl_line, str):
            return FlextResult[m.Acl].fail(
                f"ACL line must be a string, got {type(acl_line).__name__}",
            )
        normalized = acl_line.strip()

        # Detect format: RFC 4876 ACI or ds-privilege-name
        # OUD ONLY handles OUD-native formats - Alternative format data comes pre-converted via RFC Entry Model
        if normalized.startswith(FlextLdifServersOudConstants.ACL_ACI_PREFIX):
            # RFC 4876 ACI format (OUD native format)
            return self._parse_aci_format(acl_line)

        # Try RFC parser first for other non-ACI formats
        # This handles cases where RFC Entry Model data needs to be parsed
        rfc_result = super()._parse_acl(acl_line)
        if rfc_result.is_success:
            # RFC parser succeeded - check if it has a valid name
            # If name is empty and line doesn't look like RFC format, try ds-privilege-name
            acl_model = rfc_result.unwrap()
            if acl_model.name or normalized.startswith("aci:"):
                # RFC parser returned valid result with name or recognized format
                return rfc_result

        # If RFC parser fails or returned empty name, try ds-privilege-name format
        # OUD-specific simple privilege names (config-read, password-reset, etc.)
        return self._parse_ds_privilege_name(normalized)

    def _parse_aci_format(self, acl_line: str) -> FlextResult[m.Acl]:
        """Parse RFC 4876 ACI format using utility with OUD-specific config.

        RFC vs OUD Behavior Differences
        ================================

        **RFC Baseline**:
        - No dedicated ACI parser (RFC stores raw ACL in passthrough mode)
        - RFC 4876 defines the ACI format but not all servers implement it

        **OUD Implementation** (this method):
        - Full RFC 4876 ACI parser with Oracle OUD extensions
        - Parses target types, version, name, permissions, bind rules
        - Handles OUD-specific multi-group patterns (timeofday, ssf with operators)
        - Stores parsed components in structured model fields

        ACI Format Parsed
        -----------------

        ::

            aci: (targetattr="*")(version 3.0; acl "ACL Name"; allow (read,search) userdn="ldap:///self";)

        **Parsed Components**:

        1. **Target clause**: ``(targetattr="*")`` → ``target.attributes``
        2. **Version**: ``version 3.0`` → validated (OUD uses version 3.0)
        3. **ACL name**: ``acl "ACL Name"`` → ``name``
        4. **Permission**: ``allow (read,search)`` → ``permissions.read``, ``permissions.search``
        5. **Bind rules**: ``userdn="ldap:///self"`` → ``subject.subject_type``, ``subject.subject_value``

        **OUD-Specific Extensions in metadata.extensions**:

        - ``bind_timeofday`` - Time-based access control (e.g., ">=0800" AND "<=1700")
        - ``ssf`` - Security strength factor (e.g., ">=128")
        - ``bind_ip`` - IP-based restrictions
        - ``bind_dns`` - DNS-based restrictions
        - ``bind_dayofweek`` - Day-of-week restrictions
        - ``bind_authmethod`` - Authentication method restrictions

        Implementation Pattern
        ----------------------

        **Constants Used** (from ``FlextLdifServersOudConstants``):

        - ``ACL_TIMEOFDAY_PATTERN`` - Regex for timeofday bind rule extraction
        - ``ACL_SSF_PATTERN`` - Regex for SSF bind rule extraction
        - ``ACL_ACI_PREFIX`` - Prefix to identify ACI format ("aci:")

        **MetadataKeys** (stored in ``metadata.extensions``):

        - Extensions follow ``c.MetadataKeys.ACL_*`` pattern
        - OUD-specific: bind_timeofday, ssf, bind_ip, bind_dns, bind_dayofweek

        **Utilities Used**:

        - ``u.ACL.parse_aci()`` - Core ACI parsing
        - ``FlextLdifServersOudConstants.get_parser_config()`` - OUD parser config

        **RFC Override**: This method extends RFC behavior (RFC has no ACI parser).

        Args:
            acl_line: ACL definition line with 'aci:' prefix

        Returns:
            FlextResult with OUD ACL Pydantic model

        References:
            - RFC 4876: Access Control Instruction (ACI) Format
            - Oracle OUD ACI Syntax: https://docs.oracle.com/cd/E22289_01/html/821-1277/aci-syntax.html

        """
        config_raw = FlextLdifServersOudConstants.get_parser_config()
        # Ensure config is m.AciParserConfig (public facade)
        # Business Rule: get_parser_config returns FlextLdifModelsConfig.AciParserConfig
        # but parse_aci expects m.AciParserConfig
        config_dict = config_raw.model_dump()
        config = m.AciParserConfig.model_validate(config_dict)
        result = u.ACL.parse_aci(acl_line, config)

        if not result.is_success:
            return result

        # Post-process for OUD-specific multi-group patterns (timeofday, ssf)
        acl = result.unwrap()
        aci_content = acl_line.split(":", 1)[1].strip() if ":" in acl_line else ""
        # Preserve all extensions from parse_aci (including targattrfilters, targetcontrol, etc.)
        extensions = (
            dict(acl.metadata.extensions)
            if acl.metadata and acl.metadata.extensions
            else {}
        )

        # Handle bind_timeofday (captures operator + value)
        # Uses c.MetadataKeys.ACL_BIND_TIMEOFDAY for consistency
        timeofday_match = re.search(
            FlextLdifServersOudConstants.ACL_TIMEOFDAY_PATTERN,
            aci_content,
        )
        if timeofday_match:
            extensions[c.MetadataKeys.ACL_BIND_TIMEOFDAY] = (
                f"{timeofday_match.group(1)}{timeofday_match.group(2)}"
            )

        # Handle SSF (captures operator + value)
        # Uses c.MetadataKeys.ACL_SSF for consistency
        ssf_match = re.search(
            FlextLdifServersOudConstants.ACL_SSF_PATTERN,
            aci_content,
        )
        if ssf_match:
            extensions[c.MetadataKeys.ACL_SSF] = (
                f"{ssf_match.group(1)}{ssf_match.group(2)}"
            )

        # Always update metadata to ensure extensions are preserved
        # (even if timeofday/ssf weren't found, we need to preserve parse_aci extensions)
        # Business Rule: config.server_type must be valid ServerTypeLiteral
        # Implication: Type narrowing required - config is AciParserConfig with server_type field
        server_type_value = config.server_type if config else "oud"
        new_metadata = m.QuirkMetadata.create_for(
            server_type_value,
            extensions=extensions,
        )
        # Use dict[str, Any] for model_copy update to avoid type checker strictness
        update_dict: dict[str, Any] = {"metadata": new_metadata}
        acl = acl.model_copy(update=update_dict)

        return FlextResult[m.Acl].ok(acl)

    def _parse_ds_privilege_name(
        self,
        privilege_name: str,
    ) -> FlextResult[m.Acl]:
        """Parse OUD ds-privilege-name format (simple privilege names).

        RFC vs OUD Behavior Differences
        ================================

        **RFC Baseline**:
        - No concept of ds-privilege-name (this is OUD-specific)
        - RFC would store this as raw ACL passthrough

        **OUD Implementation** (this method):
        - Parses OUD-specific REDACTED_LDAP_BIND_PASSWORDistrative privilege names
        - Creates minimal ACL model with privilege stored in metadata
        - Used for OUD server configuration and REDACTED_LDAP_BIND_PASSWORDistrative access control

        OUD ds-privilege-name Format
        ----------------------------

        Oracle OUD uses simple privilege names (not full ACI format) for
        REDACTED_LDAP_BIND_PASSWORDistrative access control. These are typically found in the
        ``ds-privilege-name`` attribute on user entries.

        **Common Privilege Names**:

        - ``bypass-acl`` - Bypass all ACL checks (SECURITY CRITICAL)
        - ``modify-acl`` - Modify access control rules
        - ``proxied-auth`` - Use LDAP Proxied Authorization Control
        - ``config-read`` - Read server configuration
        - ``config-write`` - Write server configuration
        - ``config-delete`` - Delete configuration objects
        - ``password-reset`` - Reset user passwords
        - ``password-change`` - Change own password
        - ``bypass-lockdown`` - Bypass lockdown mode
        - ``ldif-import`` - Import LDIF data
        - ``ldif-export`` - Export LDIF data
        - ``backend-backup`` - Backup backend data
        - ``backend-restore`` - Restore backend data
        - ``server-shutdown`` - Shutdown server
        - ``server-restart`` - Restart server
        - ``disconnect-client`` - Disconnect LDAP clients
        - ``cancel-request`` - Cancel in-progress requests
        - ``unindexed-search`` - Perform unindexed searches
        - ``subentry-write`` - Write subentries (ACIs, etc.)

        **Security Note**: Never combine ``bypass-acl`` with ``proxied-auth``
        as this allows proxied users to bypass ACI evaluation.

        Model Mapping
        -------------

        - ``name`` → privilege_name (e.g., "config-read")
        - ``target`` → None (no target in ds-privilege-name)
        - ``subject`` → None (no subject in ds-privilege-name)
        - ``permissions`` → None (implicit based on privilege)
        - ``metadata.extensions[DS_PRIVILEGE_NAME_KEY]`` → privilege_name
        - ``metadata.extensions[FORMAT_TYPE_KEY]`` → FORMAT_TYPE_DS_PRIVILEGE

        Implementation Pattern
        ----------------------

        **Constants Used** (from ``FlextLdifServersOudConstants``):

        - ``SERVER_TYPE`` - Server identifier ("oud")
        - ``DS_PRIVILEGE_NAME_KEY`` - Metadata key for privilege name
        - ``FORMAT_TYPE_KEY`` - Metadata key for format type
        - ``FORMAT_TYPE_DS_PRIVILEGE`` - Format type value ("ds-privilege-name")

        **MetadataKeys** (stored in ``metadata.extensions``):

        - Uses OUD-specific Constants keys (not generic c.MetadataKeys)

        **Model Factory**:

        - Uses ``m.Acl()`` directly with minimal fields
        - Uses ``m.QuirkMetadata()`` for server-specific metadata

        **RFC Override**: This is OUD-only (RFC has no ds-privilege-name concept).

        Args:
            privilege_name: Simple privilege name (e.g., "config-read")

        Returns:
            FlextResult with OUD ACL Pydantic model

        References:
            - Oracle OUD Administrative Privileges: https://docs.oracle.com/en/middleware/idm/unified-directory/12.2.1.3/oudag/understanding-access-control-model-oracle-unified-directory.html

        """
        try:
            # Build minimal ACL model for ds-privilege-name
            # This format doesn't have traditional target/subject/permissions
            acl_model = m.Acl(
                name=privilege_name,  # Use privilege name as ACL name
                target=None,  # No target in ds-privilege-name format
                subject=None,  # No subject in ds-privilege-name format
                permissions=None,  # No traditional read/write/add permissions
                server_type=FlextLdifServersOudConstants.SERVER_TYPE,  # OUD server type from Constants
                raw_line=privilege_name,  # Original line
                raw_acl=privilege_name,  # Raw ACL string
                validation_violations=[],  # No validation issues
                metadata=m.QuirkMetadata(
                    quirk_type=FlextLdifServersOudConstants.SERVER_TYPE,  # OUD quirk type from Constants
                    extensions=m.DynamicMetadata(**{
                        # Use Constants for metadata keys instead of hardcoded strings
                        FlextLdifServersOudConstants.DS_PRIVILEGE_NAME_KEY: privilege_name,
                        FlextLdifServersOudConstants.FORMAT_TYPE_KEY: (
                            FlextLdifServersOudConstants.FORMAT_TYPE_DS_PRIVILEGE
                        ),
                    }),
                ),
            )

            return FlextResult[m.Acl].ok(acl_model)

        except Exception as e:
            logger.exception(
                "Failed to parse OUD ds-privilege-name",
            )
            return FlextResult[m.Acl].fail(
                f"Failed to parse OUD ds-privilege-name: {e}",
            )

    def _should_use_raw_acl(self, acl_data: m.Acl) -> bool:
        """Check if raw_acl should be used as-is.

        Args:
            acl_data: ACL model instance

        Returns:
            True if raw_acl should be used (only if already in proper OUD format)

        """
        if not acl_data.raw_acl:
            return False

        # Use raw_acl ONLY if already in OUD format (aci: prefix)
        # All other formats (OID, etc.) must be converted
        # Type narrowing: raw_acl is str | None, checked above
        raw_acl_str = acl_data.raw_acl if isinstance(acl_data.raw_acl, str) else ""
        return raw_acl_str.startswith(
            FlextLdifServersOudConstants.ACL_ACI_PREFIX,
        )

    def _build_aci_target(self, acl_data: m.Acl) -> str:
        """Build ACI target clause from ACL model.

        RFC vs OUD Behavior Differences
        ================================

        **RFC Baseline**:
        - No target clause building (RFC uses raw passthrough)
        - No structured target serialization

        **OUD Implementation** (this method):
        - Builds ``(targetattr="...")`` from ``target.attributes``
        - Uses ``||`` separator for multiple attributes (OUD-specific format)
        - Falls back to metadata if model fields are empty

        OUD Target Clause Format
        ------------------------

        ::

            (targetattr="cn || sn || mail")
            (target="ldap:///ou=people,dc=example,dc=com")

        **Attribute Separator**: OUD uses ``||`` (double pipe) to separate
        multiple target attributes, unlike some servers that use commas.

        Args:
            acl_data: ACL model containing target information

        Returns:
            Formatted target clause string (e.g., '(targetattr="cn || sn")')

        References:
            - Oracle OUD ACI Target Keywords: https://docs.oracle.com/cd/E22289_01/html/821-1277/aci-syntax.html#aci-target-keywords

        """
        # Extract target from model or metadata
        # Type narrowing: acl_data is m.Acl
        target = acl_data.target
        if not target and acl_data.metadata:
            # Type narrowing: acl_data.metadata is m.QuirkMetadata
            # Business Rule: extensions is m.DynamicMetadata which has dict-like interface
            extensions = acl_data.metadata.extensions
            target_dict = (
                extensions.get("acl_target_target")
                if extensions and hasattr(extensions, "get")
                else None
            )
            # Business Rule: target_dict may be GeneralValueType or MetadataAttributeValue.
            # We need MetadataDictMutable (dict[str, MetadataAttributeValue]) for type safety.
            # Implication: Convert and validate types explicitly.
            target_data: dict[str, Any] = {}
            if isinstance(target_dict, dict):
                # Business Rule: Filter values to ensure MetadataAttributeValue compatibility.
                # GeneralValueType may include nested Mappings, but MetadataDictMutable doesn't.
                # Implication: Convert values to MetadataAttributeValue-compatible types.
                # Type narrowing: Filter to only ScalarValue or Sequence[ScalarValue] types.
                target_data = {
                    k: v
                    for k, v in target_dict.items()
                    if not isinstance(v, Mapping)  # Exclude nested mappings
                    and isinstance(v, (str, int, float, bool, type(None), list))
                }
            # Business Rule: Extract attributes and target_dn from target_data.
            # Values are MetadataAttributeValue, so we need type narrowing for list[str].
            # Implication: Validate types before using in AclTarget constructor.
            if target_data:
                attrs_raw = target_data.get("attributes")
                dn_raw = target_data.get("target_dn")
                # Type narrowing: Convert to expected types for AclTarget
                attrs: list[str] = (
                    list(attrs_raw)
                    if isinstance(attrs_raw, list)
                    and all(isinstance(item, str) for item in attrs_raw)
                    else []
                )
                dn: str = str(dn_raw) if isinstance(dn_raw, str) else "*"
                target = m.AclTarget(
                    target_dn=dn,
                    attributes=attrs,
                )

        # CONSOLIDATED: Use utility for formatting
        return u.ACL.build_aci_target_clause(
            target_attributes=target.attributes if target else None,
            target_dn=target.target_dn if target else None,
            separator=" || ",
        )

    def _build_aci_permissions(
        self,
        acl_data: m.Acl,
    ) -> FlextResult[str]:
        """Build ACI permissions clause from ACL model.

        RFC vs OUD Behavior Differences
        ================================

        **RFC Baseline**:
        - No permission clause building (RFC uses raw passthrough)
        - No structured permission serialization

        **OUD Implementation** (this method):
        - Builds ``allow (perm1,perm2)`` from ``permissions.*`` booleans
        - Filters to OUD-supported permissions only
        - Stores unsupported permissions in metadata for tracking
        - Handles ``selfwrite`` to ``write`` promotion via metadata bridge

        OUD Permissions Format
        ----------------------

        ::

            allow(read, search, compare)
            deny(write, delete)

        **OUD-Supported Permissions** (RFC 4876 + Oracle extensions):

        - ``read`` - Read entry attributes
        - ``write`` - Modify entry attributes
        - ``add`` - Add new entries
        - ``delete`` - Delete entries
        - ``search`` - Search for entries
        - ``compare`` - Compare attribute values
        - ``selfwrite`` - Add/delete own DN from DN-valued attributes (OUD extension)
        - ``proxy`` - Access entries as another user (OUD extension)

        **Special "all" Permission**: In OUD, ``all`` grants all permissions
        except ``proxy``, ``import``, and ``export``.

        **Unsupported Permissions**: Vendor-specific permissions from source
        servers (e.g., OID's ``browse``, ``obliterate``) are stored in metadata
        but not included in the ACI output.

        Args:
            acl_data: ACL model instance

        Returns:
            FlextResult with formatted permissions string (e.g., 'allow (read,search)')

        References:
            - Oracle OUD ACI Permissions: https://docs.oracle.com/cd/E22289_01/html/821-1277/aci-syntax.html#aci-permissions

        """
        # Get permissions from model field or metadata
        perms = acl_data.permissions

        if not perms and acl_data.metadata:
            # Reconstruct permissions from ACL_TARGET_PERMISSIONS metadata
            # This is set during conversion from source server (e.g., OID→OUD)
            # Type narrowing: acl_data.metadata is m.QuirkMetadata
            extensions = acl_data.metadata.extensions
            target_perms_dict_raw = (
                extensions.get("acl_target_permissions")
                if extensions and hasattr(extensions, "get")
                else None
            )
            if not target_perms_dict_raw:
                # Fallback: try old key name
                target_perms_dict_raw = (
                    extensions.get("target_permissions")
                    if extensions and hasattr(extensions, "get")
                    else None
                )
            target_perms_dict = target_perms_dict_raw
            # Business Rule: target_perms_dict may be GeneralValueType or MetadataAttributeValue.
            # We need MetadataDictMutable (dict[str, MetadataAttributeValue]) for type safety.
            # Implication: Convert and validate types explicitly.
            if target_perms_dict and isinstance(target_perms_dict, dict):
                # Type narrowing: ensure dict has correct types
                # Filter to only MetadataAttributeValue-compatible types

                perms_data = cast(
                    "t.MetadataDictMutable",
                    {
                        k: v
                        for k, v in (
                            target_perms_dict.items()
                            if isinstance(target_perms_dict, dict)
                            else []
                        )
                        if not isinstance(v, Mapping)  # Exclude nested mappings
                        and isinstance(v, (str, int, float, bool, type(None), list))
                    },
                )
            else:
                perms_data = {}
            # Extract boolean fields with type guards - only use fields that exist in AclPermissions
            if perms_data:
                perms = m.AclPermissions(
                    read=bool(perms_data.get("read")),
                    write=bool(perms_data.get("write")),
                    add=bool(perms_data.get("add")),
                    delete=bool(perms_data.get("delete")),
                    search=bool(perms_data.get("search")),
                    compare=bool(perms_data.get("compare")),
                    self_write=bool(
                        perms_data.get("self_write") or perms_data.get("selfwrite"),
                    ),
                    proxy=bool(perms_data.get("proxy")),
                )
            else:
                perms = None

        if not perms:
            return FlextResult[str].fail("ACL model has no permissions object")

        # Extract permission names from boolean fields directly
        ops: list[str] = [
            field_name
            for field_name in (
                "read",
                "write",
                "add",
                "delete",
                "search",
                "compare",
                "self_write",
                "proxy",
            )
            if getattr(perms, field_name, False)
        ]

        # Normalize permission names: self_write → selfwrite to match SUPPORTED_PERMISSIONS
        permission_normalization = {
            "self_write": "selfwrite",
        }
        normalized_ops = [permission_normalization.get(op, op) for op in ops]

        # Filter to only OUD-supported rights using utility
        filtered_ops = u.ACL.filter_supported_permissions(
            normalized_ops,
            FlextLdifServersOudConstants.SUPPORTED_PERMISSIONS,
        )

        # Check metadata bridge for self_write promotion
        # Type narrowing: acl_data.metadata is m.QuirkMetadata | None
        extensions = acl_data.metadata.extensions if acl_data.metadata else None
        if (
            extensions
            and hasattr(extensions, "get")
            and extensions.get("self_write_to_write")
            and FlextLdifServersOudConstants.PERMISSION_SELF_WRITE in ops
            and "write" not in filtered_ops
        ):
            filtered_ops.append("write")

        if not filtered_ops:
            return FlextResult[str].fail(
                f"ACL model has no OUD-supported permissions (all were unsupported vendor-specific permissions like {FlextLdifServersOudConstants.PERMISSION_SELF_WRITE}, stored in metadata)",
            )

        ops_str = ",".join(filtered_ops)
        return FlextResult[str].ok(
            f"{FlextLdifServersOudConstants.ACL_ALLOW_PREFIX}{ops_str})",
        )

    def _extract_and_resolve_acl_subject(
        self,
        acl_data: m.Acl,
    ) -> tuple[str | None, str, str]:
        """Extract metadata and resolve subject type and value in one pass.

        Returns:
            Tuple of (base_dn, subject_type_for_format, subject_value_str)

        """
        # Extract metadata with type guards in compact form
        # Type narrowing: acl_data is m.Acl
        ext = acl_data.metadata.extensions if acl_data.metadata else None
        base_dn = (
            (
                base_dn_val
                if isinstance(base_dn_val := ext.get("base_dn"), str)
                else None
            )
            if ext
            else None
        )
        source_subject_type = (
            (
                sst
                if isinstance(
                    sst := ext.get(
                        c.MetadataKeys.ACL_SOURCE_SUBJECT_TYPE,
                    ),
                    str,
                )
                else None
            )
            if ext
            else None
        )

        # Determine subject type using single pass logic
        # Priority: source_subject_type (for attribute-based types) > acl_data.subject.subject_type > "self"
        # If source_subject_type is an attribute-based type, use it directly
        if source_subject_type in {"dn_attr", "guid_attr", "group_attr"}:
            subject_type = source_subject_type
        else:
            subject_type = (
                acl_data.subject.subject_type
                if acl_data.subject
                else source_subject_type
            ) or "self"

        # Map bind_rules to actual subject type using metadata
        if subject_type == "bind_rules":
            if source_subject_type in {"dn_attr", "guid_attr", "group_attr"}:
                subject_type = source_subject_type
            elif source_subject_type == "group_dn" or (
                acl_data.subject
                and acl_data.subject.subject_value
                and any(
                    kw in acl_data.subject.subject_value.lower()
                    for kw in ("group=", "groupdn")
                )
            ):
                subject_type = "group"

        # Resolve subject value from ACL data or stored metadata
        subject_value = (
            acl_data.subject.subject_value if acl_data.subject else None
        ) or (
            sv
            if ext
            and isinstance(
                sv := ext.get(
                    c.MetadataKeys.ACL_ORIGINAL_SUBJECT_VALUE,
                ),
                str,
            )
            else None
        )

        # Default self values
        if not subject_value and subject_type == "self":
            subject_value = FlextLdifServersOudConstants.ACL_SELF_SUBJECT
        if not subject_value:
            subject_value = ""

        return base_dn, subject_type, subject_value

    def _build_aci_subject(self, acl_data: m.Acl) -> str:
        """Build ACI bind rules (subject) clause from ACL model.

        RFC vs OUD Behavior Differences
        ================================

        **RFC Baseline**:
        - No bind rules clause building (RFC uses raw passthrough)
        - No structured subject serialization

        **OUD Implementation** (this method):
        - Builds bind rules from ``subject.subject_type`` and ``subject.subject_value``
        - Maps subject types to OUD bind operators (userdn, groupdn, roledn)
        - Handles special "self" subject type with ``ldap:///self``
        - Handles attribute-based subject types (dn_attr, guid_attr, group_attr)
        - Filters base_dn from subject value to avoid redundancy

        OUD Bind Rules Format
        ---------------------

        ::

            userdn = "ldap:///self"
            userdn = "ldap:///cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"
            groupdn = "ldap:///cn=REDACTED_LDAP_BIND_PASSWORDs,ou=groups,dc=example,dc=com"
            roledn = "ldap:///cn=dir-REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"
            userattr = "attribute#USERDN"
            userattr = "attribute#GROUPDN"
            userattr = "attribute#LDAPURL"

        **Bind Rule Operators** (RFC 4876 + Oracle extensions):

        - ``userdn`` - User DN match (most common)
        - ``groupdn`` - Group membership check
        - ``roledn`` - Role-based access control (OUD extension)
        - ``userattr`` - Attribute-based subject matching with suffix specifier
        - ``ip`` - IP address/CIDR restriction (stored in metadata)
        - ``dns`` - DNS domain pattern (stored in metadata)
        - ``timeofday`` - Time restriction HHMM-HHMM (stored in metadata)
        - ``dayofweek`` - Day restriction (stored in metadata)
        - ``authmethod`` - Auth method restriction (stored in metadata)
        - ``ssf`` - Security strength factor (stored in metadata)

        **Special Subject Types**:

        - ``self`` → ``userdn="ldap:///self";`` (user accessing own entry)
        - ``anyone`` → ``userdn="ldap:///anyone";`` (anonymous access)
        - ``all`` → ``userdn="ldap:///all";`` (all authenticated users)
        - ``dn_attr`` → ``userattr="attribute#LDAPURL";`` (DN from attribute)
        - ``guid_attr`` → ``userattr="attribute#USERDN";`` (GUID from attribute)
        - ``group_attr`` → ``userattr="attribute#GROUPDN";`` (Group DN from attribute)

        Args:
            acl_data: ACL model containing subject information

        Returns:
            Formatted bind rules clause (e.g., 'userdn="ldap:///self";)')

        References:
            - Oracle OUD ACI Bind Rules: https://docs.oracle.com/cd/E22289_01/html/821-1277/aci-syntax.html#aci-bind-rules

        """
        # Extract and resolve in one pass
        base_dn, subject_type, subject_value = self._extract_and_resolve_acl_subject(
            acl_data,
        )

        # Default to self if no subject type
        if not subject_type or subject_type == "self":
            return f'userdn="{FlextLdifServersOudConstants.ACL_SELF_SUBJECT}";)'

        # Handle attribute-based subject types (from OID conversion)
        # These need userattr format with suffix specifier
        attr_suffix_map = {
            "dn_attr": "LDAPURL",
            "guid_attr": "USERDN",
            "group_attr": "GROUPDN",
        }

        if subject_type in attr_suffix_map:
            suffix = attr_suffix_map[subject_type]
            return f'userattr="{subject_value}#{suffix}";)'

        # Filter base_dn from subject value if present
        filtered_value = (
            subject_value[: -len(base_dn)].rstrip(",")
            if (base_dn and subject_value.endswith(base_dn))
            else subject_value
        )

        # Map subject type to bind operator and format
        bind_operator = {
            "user": "userdn",
            "group": "groupdn",
            "role": "roledn",
        }.get(
            subject_type,
            "userdn",
        )
        return u.ACL.format_aci_subject(
            subject_type,
            filtered_value,
            bind_operator,
        )

    def _write_acl(self, acl_data: m.Acl) -> FlextResult[str]:
        """Write RFC-compliant ACL model to OUD ACI string format (protected internal method).

        This is the server-specific ACL serialization implementation for Oracle Unified Directory (OUD).
        It implements RFC 4876 ACI (Access Control Instruction) format with OUD-specific extensions.

        RFC vs OUD Behavior Differences
        ================================

        **RFC Baseline** (in rfc.py ``_write_acl``):
        - Simple passthrough: returns ``raw_acl`` field unchanged
        - Falls back to ``name:`` format if raw_acl is empty
        - No structured serialization of ACL components

        **OUD Override** (this method):
        - Full RFC 4876 ACI serialization from structured model
        - Builds target clause from ``target.attributes``, ``target.target_dn``
        - Builds permissions from ``permissions.*`` boolean fields
        - Builds bind rules from ``subject.subject_type``, ``subject.subject_value``
        - Includes OUD-specific extensions from metadata
        - Generates conversion comments for cross-server migrations

        Output ACI Format
        -----------------

        ::

            aci: (targetattr="cn || sn")(version 3.0; acl "ACL Name"; allow (read,search) userdn="ldap:///self";)

        **ACI Components Built**:

        1. **Target clause** (from ``_build_aci_target``):
           - ``(targetattr="attr1 || attr2")`` from ``target.attributes``
           - ``(target="ldap:///dn")`` from ``target.target_dn``

        2. **Target extensions** (from metadata.extensions via Constants):
           - ``(targetscope="subtree")``
           - ``(targetfilter="(objectClass=person)")``
           - ``(targattrfilters="...")``
           - ``(targetcontrol="oid")``
           - ``(extop="oid")``

        3. **Version and name**:
           - ``(version 3.0; acl "Name";`` (always version 3.0 for OUD)

        4. **Permissions** (from ``_build_aci_permissions``):
           - ``allow (read,write,search)`` from ``permissions.*`` booleans
           - OUD-supported: read, write, add, delete, search, compare, selfwrite, proxy
           - Unsupported permissions stored in metadata for tracking

        5. **Bind rules** (from ``_build_aci_subject``):
           - ``userdn="ldap:///self"`` for self access
           - ``userdn="ldap:///cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"`` for user DN
           - ``groupdn="ldap:///cn=REDACTED_LDAP_BIND_PASSWORDs,ou=groups,dc=example,dc=com"`` for group
           - ``roledn="ldap:///cn=role,dc=example,dc=com"`` for role-based access
           - Additional bind rules from metadata: ip, dns, timeofday, dayofweek, authmethod, ssf

        **Cross-Server Migration Comments**:

        When converting from other servers (e.g., OID→OUD), comments are generated
        to track unsupported features::

            # Converted from: oid
            # Original ACL preserved in metadata for reference
            aci: (targetattr="*")(version 3.0; acl "Test"; allow (read) userdn="ldap:///self";)

        Args:
            acl_data: RFC-compliant ACL Pydantic model

        Returns:
            FlextResult with OUD ACI formatted string including conversion comments

        Example:
            >>> acl = m.Acl(
            ...     name="Allow Self Read",
            ...     target=m.AclTarget(attributes=["cn", "sn"]),
            ...     permissions=m.AclPermissions(read=True, search=True),
            ...     subject=m.AclSubject(subject_type="self"),
            ... )
            >>> result = oud_acl._write_acl(acl)
            >>> # Output: 'aci: (targetattr="cn || sn")(version 3.0; acl "Allow Self Read"; allow (read,search) userdn="ldap:///self";)'

        References:
            - RFC 4876: Access Control Instruction (ACI) Format
            - Oracle OUD ACI Syntax: https://docs.oracle.com/cd/E22289_01/html/821-1277/aci-syntax.html

        """
        try:
            # Use sc (server constants) for OUD-specific, keep c for main constants
            sc = FlextLdifServersOudConstants
            extensions: dict[str, t.MetadataAttributeValue] | None = (
                acl_data.metadata.extensions.model_dump()
                if acl_data.metadata and acl_data.metadata.extensions
                else None
            )

            # CONSOLIDATED: Conversion comments via utility (DRY)
            # Use c.MetadataKeys for standardized key names (from flext_ldif.constants)
            aci_output_lines = u.ACL.format_conversion_comments(
                extensions,
                c.MetadataKeys.CONVERTED_FROM_SERVER,
                c.MetadataKeys.CONVERSION_COMMENTS,
            )

            # Check if we should use raw_acl as-is
            if self._should_use_raw_acl(acl_data):
                aci_output_lines.append(acl_data.raw_acl)
                return FlextResult[str].ok("\n".join(aci_output_lines))

            # Build ACI parts
            aci_parts = [self._build_aci_target(acl_data)]

            # CONSOLIDATED: Target extensions via utility (DRY)
            aci_parts.extend(
                u.ACL.extract_target_extensions(
                    extensions,
                    sc.ACL_TARGET_EXTENSIONS_CONFIG,
                ),
            )

            # Version and ACL name
            acl_name = acl_data.name or sc.ACL_DEFAULT_NAME
            aci_parts.append(f'({sc.ACL_DEFAULT_VERSION}; acl "{acl_name}";')

            # Permissions
            perms_result = self._build_aci_permissions(acl_data)
            if perms_result.is_failure:
                return FlextResult[str].fail(perms_result.error or "Unknown error")

            # Subject
            subject_str = self._build_aci_subject(acl_data)
            if not subject_str:
                return FlextResult[str].fail("ACL subject DN was filtered out")

            # CONSOLIDATED: Bind rules via utility (DRY)
            bind_rules = u.ACL.extract_bind_rules_from_extensions(
                extensions,
                sc.ACL_BIND_RULES_CONFIG,
                tuple_length=sc.ACL_BIND_RULE_TUPLE_LENGTH,
            )
            if bind_rules:
                subject_str = subject_str.rstrip(";)")
                subject_str = f"{subject_str} and {' and '.join(bind_rules)};)"

            aci_parts.extend([perms_result.unwrap(), subject_str])

            # Build final ACI string
            aci_string = f"{sc.ACL_ACI_PREFIX} {' '.join(aci_parts)}"
            aci_output_lines.append(aci_string)

            return FlextResult[str].ok("\n".join(aci_output_lines))

        except Exception as e:
            logger.exception(
                "Failed to write ACL to OUD ACI format",
            )
            return FlextResult[str].fail(
                f"Failed to write ACL to OUD ACI format: {e}",
            )

    @staticmethod
    def _is_aci_start(line: str) -> bool:
        """Check if line starts an ACI definition.

        Args:
            line: Stripped line to check

        Returns:
            True if line starts with 'aci:' (case-insensitive)

        """
        return line.lower().startswith(
            FlextLdifServersOudConstants.ACL_ACI_PREFIX.lower(),
        )

    @staticmethod
    def _is_ds_cfg_acl(line: str) -> bool:
        """Check if line is a ds-cfg ACL format.

        Args:
            line: Stripped line to check

        Returns:
            True if line starts with 'ds-cfg-' (case-insensitive)

        """
        return line.lower().startswith(
            FlextLdifServersOudConstants.ACL_DS_CFG_PREFIX.lower(),
        )

    def _finalize_aci(
        self,
        current_aci: list[str],
        acls: list[m.Acl],
    ) -> None:
        """Parse and add accumulated ACI to ACL list.

        Args:
            current_aci: List of accumulated ACI lines
            acls: Target list to append parsed ACL

        """
        if current_aci:
            aci_text = "\n".join(current_aci)
            result = self.parse(aci_text)
            if result.is_success:
                acls.append(result.unwrap())


"""Oracle Unified Directory (OUD) Quirks.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Provides OUD-specific quirks for schema, ACL, and entry processing.
"""


from typing import TYPE_CHECKING

from flext_core import FlextLogger

from flext_ldif.protocols import FlextLdifProtocols
from flext_ldif.servers.rfc import FlextLdifServersRfc

# Aliases for simplified usage
p = FlextLdifProtocols

if TYPE_CHECKING:
    from flext_ldif.services.acl import FlextLdifAcl

logger = FlextLogger(__name__)
