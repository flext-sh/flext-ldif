"""Oracle Unified Directory (OUD) Servers.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Provides OUD-specific servers for schema, ACL, and entry processing.
"""

from __future__ import annotations

from collections.abc import (
    Mapping,
)
from typing import ClassVar, override

from flext_ldif import (
    FlextLdifServersBase,
    FlextLdifServersBaseEntry,
    FlextLdifServersOudConstants,
    FlextLdifServersRfc,
    c,
    m,
    p,
    r,
    t,
    u,
)
from flext_ldif.servers._oud.helpers import FlextLdifServersOudHelpersMixin

logger = u.fetch_logger(__name__)


class FlextLdifServersOudEntry(
    FlextLdifServersOudHelpersMixin,
    FlextLdifServersRfc.Entry,
):
    """Oracle OUD Entry Implementation (RFC 2849 + OUD Extensions).

    Extends RFC 2849 LDIF entry processing with Oracle OUD-specific features.

    RFC vs OUD Entry Differences
    ============================

    **RFC 2849 Baseline**:

    - Entry format: ``dn: <distinguished-name>`` followed by attributes
    - Attributes: ``<attribute-name>: <value>`` (colon-space-value)
    - Base64 encoding: ``<attribute-name>:: <base64-value>`` (double colon)
    - Multi-valued: Multiple lines with same attribute name
    - Continuation: Long lines wrapped with leading space
    - Changetype: add, delete, modify, modrdn

    **OUD Extensions** (Oracle-specific):

    1. **Operational Attributes** (OUD-specific prefixes):

       - ``ds-cfg-*``: Server configuration attributes
       - ``ds-sync-*``: Replication and synchronization state
       - ``ds-pwp-*``: Password policy attributes
       - ``ds-privilege-name``: Privilege assignments (root-dse-read, modify-acl, etc.)
       - ``createTimestamp``, ``modifyTimestamp``: Creation/modification time
       - ``creatorsName``, ``modifiersName``: Creator/modifier DN

    2. **DN Handling** (OUD-specific):

       - Case-insensitive comparison but case-preserving storage
       - Spaces after commas in DN allowed: ``cn=User, dc=example, dc=com``
       - Escaped characters: backslash-comma, backslash-plus, backslash-quote
       - DN normalization for comparison

    3. **Multi-line ACIs** (OUD-specific):

       - ACIs can span multiple lines with continuation (leading whitespace)
       - Multiple ACIs per entry (multi-valued ``aci`` attribute)
       - Complex ACIs with multiple bind rules

    4. **ObjectClass Handling** (OUD-specific):

       - Mixed case objectClass names accepted: ``groupOfUniqueNames`` = ``GROUPOFUNIQUENAMES``
       - Oracle-specific objectClasses: ``orclContext``, ``orclContainer``, ``orclGroup``
       - OUD supports both STRUCTURAL and AUXILIARY classes

    5. **Attribute Value Handling**:

       - Binary attributes auto-detected and base64 encoded
       - Multi-byte UTF-8 properly handled
       - Sensitive attributes (``userPassword``) handled specially

    Real Examples (from fixtures)
    -----------------------------

    **Basic Entry**::

        dn: cn=OracleContext,dc=example,dc=com
        cn: OracleContext
        objectclass: top
        objectclass: orclContext
        objectclass: orclContextAux82
        orclVersion: 90600

    **Entry with Multi-valued Attributes**::

        dn: cn=OracleDASGroupPriv, cn=Groups,cn=OracleContext
        objectclass: groupOfUniqueNames
        uniquemember: cn=orclREDACTED_LDAP_BIND_PASSWORD
        uniqueMember: cn=OracleDASAdminGroup, cn=Groups,cn=OracleContext
        displayname: DAS Group Privilege

    **Entry with Complex ACI** (multi-line)::

        dn: cn=Groups,cn=OracleContext
        aci: (targetattr="*")(version 3.0; acl "Multi-group access";
             allow (read,search,write,selfwrite,compare)
             groupdn="ldap:///cn=OracleDASUserPriv,cn=Groups,cn=OracleContext";
             allow (read,search,compare) userdn="ldap:///anyone";)

    Conversion Pipeline
    -------------------

    OUD has ZERO knowledge of OID (or other server) formats. All conversions
    go through RFC Entry Model as intermediate format::

        OID Entry → RFC Entry Model → OUD Entry
        OUD Entry → RFC Entry Model → OpenLDAP Entry

    This decoupling ensures servers don't need to know about each other.

    Official Documentation
    ----------------------

    - LDIF Format: https://docs.oracle.com/cd/E22289_01/html/821-1273/understanding-ldif-files.html
    - RFC 2849 (base): https://tools.ietf.org/html/rfc2849

    Example Usage
    -------------

    ::

        server = FlextLdifServersOudEntry()
        if server.can_handle_entry(entry):
            result = server.parse_entry(entry.dn.value, entry.attributes.attributes)
            if result.success:
                parsed_entry = result.value
                # Access OUD-specific operational attributes

    """

    def __init__(
        self,
        entry_service: p.Ldif.EntryServer | None = None,
        _parent_server: FlextLdifServersBase | None = None,
    ) -> None:
        """Initialize OUD entry server."""
        FlextLdifServersBaseEntry.__init__(
            self,
            entry_service,
            _parent_server=None,
        )
        if _parent_server is not None:
            object.__setattr__(self, "_parent_server", _parent_server)

    @override
    def can_handle(
        self,
        entry_dn: str,
        attributes: t.MutableStrSequenceMapping,
    ) -> bool:
        """Check if OUD should handle this entry using pattern matching.

        RFC vs OUD Behavior Differences
        ================================

        **RFC Baseline** (in rfc.py):
        - Returns ``True`` for ALL entries (catch-all fallback)
        - Does not inspect DN patterns or attribute names
        - RFC is the universal fallback when no server-specific handler matches

        **OUD Override** (this method):
        - Returns ``True`` ONLY for OUD-specific entries
        - Detects entries by DN patterns, attribute prefixes, and keywords
        - Allows RFC fallback for non-OUD entries

        OUD Detection Patterns
        ----------------------

        **DN Patterns** (from ``Constants.DN_DETECTION_PATTERNS``):
        - ``cn=OracleContext`` - Oracle context entries
        - ``dc=oracleContext`` - Oracle domain context
        - ``ou=OracleContext`` - Oracle org unit context

        **Attribute Prefixes** (from ``Constants.DETECTION_ATTRIBUTE_PREFIXES``):
        - ``ds-cfg-`` - OUD server configuration attributes
        - ``ds-sync-`` - OUD replication attributes
        - ``ds-pwp-`` - OUD password policy attributes
        - ``orcl`` - Oracle-specific attributes (orclVersion, orclContext, etc.)

        **Attribute Names** (from ``Constants.BOOLEAN_ATTRIBUTES``):
        - OUD-specific boolean operational attributes

        **Keyword Patterns** (from ``Constants.KEYWORD_PATTERNS``):
        - Oracle-specific values within attributes

        Implementation Pattern
        ----------------------

        **Constants Used** (from ``FlextLdifConstantsServersOud``):

        - ``DN_DETECTION_PATTERNS`` - DN patterns for OUD detection
        - ``DETECTION_ATTRIBUTE_PREFIXES`` - Attribute prefixes (ds-cfg-, orcl, etc.)
        - ``BOOLEAN_ATTRIBUTES`` - OUD-specific boolean attrs
        - ``KEYWORD_PATTERNS`` - Keyword detection patterns

        **Utilities Used**:

        - ``u.Ldif.matches_server_patterns()`` - Pattern matching

        **RFC Override**: Extends RFC (RFC returns True for all entries as fallback).

        Args:
            entry_dn: Entry DN string
            attributes: Entry attributes dictionary

        Returns:
            True if this server should handle the entry

        References:
            - Oracle OUD LDIF Format: https://docs.oracle.com/cd/E22289_01/html/821-1273/understanding-ldif-files.html

        """
        oud_constants = FlextLdifServersOudConstants
        patterns_config = m.Ldif.ServerPatternsConfig(
            dn_patterns=oud_constants.DN_DETECTION_PATTERNS,
            attr_prefixes=oud_constants.DETECTION_ATTRIBUTE_PREFIXES,
            attr_names=oud_constants.BOOLEAN_ATTRIBUTES,
            keyword_patterns=oud_constants.KEYWORD_PATTERNS,
        )
        return (
            u.Ldif.matches_entry_server_patterns(entry_dn, attributes, patterns_config)
            or "objectclass" in attributes
        )

    @override
    def parse_server(self, value: str) -> r[t.MutableSequenceOf[m.Ldif.Entry]]:
        """Parse LDIF content and apply OUD post-processing hooks."""
        parsed_result = super().parse_server(value)
        if parsed_result.failure:
            return parsed_result
        processed_entries: t.MutableSequenceOf[m.Ldif.Entry] = []
        for parsed_entry in parsed_result.value:
            post_parse_result = self._hook_post_parse_entry(parsed_entry)
            if post_parse_result.failure:
                return r[t.MutableSequenceOf[m.Ldif.Entry]].fail(
                    post_parse_result.error or "OUD post-parse failed",
                )
            entry_after_post: m.Ldif.Entry = post_parse_result.value
            original_dn = entry_after_post.dn.value if entry_after_post.dn else ""
            original_attrs: t.MutableStrSequenceMapping = (
                entry_after_post.attributes.attributes
                if entry_after_post.attributes
                and entry_after_post.attributes.attributes
                else {}
            )
            finalize_result = self._hook_finalize_entry_parse(
                entry_after_post,
                original_dn,
                original_attrs,
            )
            if finalize_result.failure:
                return r[t.MutableSequenceOf[m.Ldif.Entry]].fail(
                    finalize_result.error or "OUD finalize parse failed",
                )
            processed_entries.append(finalize_result.value)
        return r[t.MutableSequenceOf[m.Ldif.Entry]].ok(processed_entries)

    @override
    def parse_entry(
        self,
        entry_dn: str,
        entry_attrs: t.MutableStrSequenceMapping | m.Ldif.Entry,
    ) -> r[m.Ldif.Entry]:
        """Parse entry with OUD-specific metadata population.

        RFC vs OUD Behavior Differences
        ================================

        **RFC Baseline** (in rfc.py ``parse_entry``):
        - Creates Entry model with RFC defaults
        - Metadata has server_type='rfc'
        - No server-specific format tracking

        **OUD Override** (this method):
        - Calls RFC base parse_entry for Entry creation
        - Populates OUD-specific metadata for round-trip support
        - Tracks original DN, transform source, and attribute case

        Metadata Populated
        ------------------

        **original_format_details** (from ``c.Ldif.Rfc``):
        - ``_transform_source``: "oud" (server type identifier)
        - ``_dn_original``: Original DN before any normalization
        - ``_dn_was_base64``: Whether DN was base64 encoded

        **original_attribute_case** (for round-trip):
        - Maps normalized attribute names to original case
        - Example: {"objectclass": "objectClass"}

        Implementation Pattern
        ----------------------

        **Utilities Used**:
        - ``u.Ldif.build_entry_parse_metadata()`` - Metadata creation

        **RFC Override**: Extends RFC (RFC creates Entry, OUD adds metadata).

        Args:
            entry_dn: Entry distinguished name
            entry_attrs: Entry attributes mapping

        Returns:
            r[Entry] with OUD-specific metadata populated

        References:
            - Oracle OUD LDIF Format: https://docs.oracle.com/cd/E22289_01/html/821-1273/understanding-ldif-files.html

        """
        entry_attrs_dict: t.MutableStrSequenceMapping = {}
        if isinstance(entry_attrs, Mapping):
            for key, values in entry_attrs.items():
                entry_attrs_dict[key] = list(values)
        elif entry_attrs.attributes and entry_attrs.attributes.attributes:
            entry_attrs_dict = {
                k: list(vs) for k, vs in entry_attrs.attributes.attributes.items()
            }
        result = super().parse_entry(entry_dn, entry_attrs_dict)
        if result.failure:
            return result
        entry = result.value
        original_attribute_case: t.MutableStrMapping = {}
        if isinstance(entry_attrs, Mapping):
            for attr_name in entry_attrs:
                original_attribute_case[attr_name.lower()] = attr_name
        metadata_config = m.Ldif.EntryParseMetadataConfig.model_validate({
            "server_type": c.Ldif.ServerTypes.OUD,
            "original_entry_dn": entry_dn,
            "cleaned_dn": entry.dn.value if entry.dn else entry_dn,
            "original_dn_line": f"dn: {entry_dn}",
            "original_attr_lines": [],
            "dn_was_base64": False,
            "original_attribute_case": original_attribute_case,
        })
        metadata = u.Ldif.build_entry_parse_metadata(
            metadata_config,
        )
        entry.metadata = metadata
        return r[m.Ldif.Entry].ok(entry)

    _ACL_METADATA_KEY_MAPPING_CACHE: ClassVar[t.MappingKV[str, str] | None] = None

    def _hook_finalize_entry_parse(
        self,
        entry: m.Ldif.Entry,
        original_dn: str,
        original_attrs: t.AttributeMapping,
    ) -> r[m.Ldif.Entry]:
        """Hook: Process ACLs and propagate their extensions to entry metadata.

        This hook processes ACL attributes (aci) in the entry and extracts
        their metadata extensions (like targattrfilters, targetcontrol, etc.)
        and propagates them to the entry's metadata.extensions.

        Args:
            entry: Parsed entry from RFC with all hooks applied
            original_dn: Original DN before transformation
            original_attrs: Original attributes for ACL processing

        Returns:
            r with entry containing ACL metadata extensions

        """
        _ = original_dn
        aci_values = self._find_aci_values(entry, original_attrs)
        if not aci_values:
            return r[m.Ldif.Entry].ok(entry)
        if not entry.metadata:
            entry.metadata = m.Ldif.ServerMetadata.create_for(
                "oud",
                extensions=m.Ldif.DynamicMetadata(),
            )
        current_extensions: t.Ldif.MutableMetadataInputMapping = (
            dict(entry.metadata.extensions.to_dict())
            if entry.metadata and entry.metadata.extensions
            else {}
        )
        parent = self._get_parent_server_safe()
        acl_server = parent.acl_server if parent is not None else None
        if acl_server is None:
            return r[m.Ldif.Entry].ok(entry)
        self._process_aci_list_for_finalize(aci_values, acl_server, current_extensions)
        if current_extensions:
            existing_extensions = (
                dict(entry.metadata.extensions.to_dict())
                if entry.metadata and entry.metadata.extensions
                else {}
            )
            merged_extensions = {**existing_extensions, **current_extensions}
            if entry.metadata:
                entry.metadata = entry.metadata.model_copy(
                    update={
                        "extensions": m.Ldif.DynamicMetadata.from_dict(
                            merged_extensions,
                        ),
                    },
                )
        return r[m.Ldif.Entry].ok(entry)

    @override
    def _hook_post_parse_entry(self, entry: m.Ldif.Entry) -> r[m.Ldif.Entry]:
        """Hook: Validate OUD ACI macros after parsing Entry.

        RFC vs OUD Behavior Differences
        ================================

        **RFC Baseline** (in rfc.py ``_hook_post_parse_entry``):
        - Default implementation returns entry unchanged
        - No macro validation or processing
        - No entry post-processing hooks

        **OUD Override** (this method):
        - Validates OUD ACI macro syntax when present
        - Detects and validates macro patterns in ACIs
        - Preserves macros for OUD directory server expansion
        - Adds metadata notes when macros detected

        OUD ACI Macro Types
        -------------------

        **1. DN Substring Macro** ``($dn)``:
           - Used for substring matching/substitution
           - Example: ``userdn="ldap:///$($dn)"``

        **2. Hierarchical DN Macro** ``[$dn]``:
           - Used for hierarchical substitution
           - Example: ``userdn="ldap:///[$dn]"``

        **3. Attribute Value Macro** ``($attr.attrName)``:
           - Substitutes attribute value at runtime
           - Example: ``userdn="ldap:///($attr.manager)"``

        Validation Rules
        ----------------

        - Macros must be well-formed (balanced parentheses/brackets)
        - Attribute macros must reference valid attribute names
        - Macros are NOT expanded here (OUD server does that at runtime)

        Implementation Pattern
        ----------------------

        **Constants Used** (from ``FlextLdifConstantsServersOud``):

        - ``MAX_LOG_LINE_LENGTH`` - Truncation limit for log messages

        **MetadataKeys** (from ``c``):

        - ``ACI_LIST_PREVIEW_LIMIT`` - Max ACIs to log in preview

        **Hooks**:

        - This IS a hook method (``_hook_post_parse_entry``)
        - Calls ``_validate_aci_macros()`` for syntax validation

        **RFC Override**: Extends RFC (RFC returns entry unchanged).

        Args:
            entry: Entry parsed from OUD LDIF (in RFC canonical format)

        Returns:
            r[Entry] - validated entry, unchanged if valid

        References:
            - Oracle OUD ACI Macros: https://docs.oracle.com/cd/E22289_01/html/821-1277/aci-syntax.html

        """
        attrs_dict: t.MutableStrSequenceMapping = (
            entry.attributes.attributes if entry.attributes is not None else {}
        )
        aci_attrs = attrs_dict.get("aci")
        if aci_attrs and u.matches_type(aci_attrs, (list, tuple)):
            has_macros = False
            acl_metadata_extensions: t.Ldif.MutableMetadataInputMapping = {}
            for aci_value in aci_attrs:
                if u.matches_type(aci_value, str):
                    process_result = self._process_single_aci_value(
                        aci_value,
                        acl_metadata_extensions,
                    )
                    if process_result.failure:
                        return r[m.Ldif.Entry].fail(
                            process_result.error or "ACI processing failed",
                        )
                    if process_result.value:
                        has_macros = True
            if has_macros:
                aci_list = (
                    list(aci_attrs)
                    if u.matches_type(aci_attrs, (list, tuple))
                    else [str(aci_attrs)]
                )
                logger.debug(
                    "Entry contains OUD ACI macros - preserved for runtime expansion",
                    entry_dn=entry.dn.value if entry.dn else "",
                    aci_count=len(aci_list),
                )
            entry = self._merge_acl_metadata_to_entry(entry, acl_metadata_extensions)
        return r[m.Ldif.Entry].ok(entry)

    @override
    def _hook_pre_write_entry(self, entry: m.Ldif.Entry) -> r[m.Ldif.Entry]:
        """Hook: Pre-write entry validation (simplified).

        Entry is returned unchanged (RFC-valid format preserved).

        Args:
            entry: RFC Entry (already canonical)

        Returns:
            r[Entry] - entry unchanged

        """
        return r[m.Ldif.Entry].ok(entry)

    @override
    def _write_entry(self, entry_data: m.Ldif.Entry) -> r[str]:
        """Write Entry to LDIF with OUD-specific formatting + phase-aware ACL handling.

        RFC vs OUD Behavior Differences
        ================================

        **RFC Baseline** (in rfc.py ``_write_entry``):
        - Basic RFC 2849 compliant LDIF output
        - Writes ``dn: <value>`` line followed by attributes
        - Uses ``:`` for normal values, ``::`` for base64
        - Optional ``changetype: modify`` format for schema updates
        - Basic metadata restoration (DN, attributes)

        **OUD Override** (this method):
        - Full OUD-specific formatting with roundtrip preservation
        - Pre-write hook application for OUD-specific normalization
        - Phase-aware ACL handling (comment ACLs in non-ACL phases)
        - Original entry commenting (write source as commented LDIF)
        - DN normalization in ACL values (userdn, groupdn patterns)
        - Restores original OUD formatting from metadata

        OUD-Specific Features
        ---------------------

        **1. Pre-Write Normalization** (OUD requirement):
           - Applies _hook_pre_write_entry() for attribute normalization
           - Converts to OUD-expected camelCase (objectclass → objectClass)
           - Converts boolean values to TRUE/FALSE format

        **2. Roundtrip Preservation** (OUD requirement):
           - Restores original DN (spaces after commas)
           - Restores original attribute case (``objectClass`` vs ``objectclass``)
           - Preserves original attribute order
           - Uses metadata.extensions for stored original values

        **3. Phase-Aware ACL Handling** (OUD migration):
           - In phases 01/02/03: Comments out ACL attributes
           - In phase 04 (ACL): Writes ACL attributes normally
           - Prevents ACL application before entries exist

        **4. Original Entry Commenting** (OUD migration):
           - When ``write_original_entry_as_comment=True``
           - Writes source entry as commented LDIF block
           - Helps with migration debugging and auditing

        **5. ACL DN Normalization** (OUD ACI requirement):
           - Normalizes DNs in ACI values (userdn, groupdn)
           - Removes spaces after commas in DN references
           - Preserves case but normalizes whitespace

        Migration Phase Flow
        --------------------

        ::

            Phase 01 (Groups):    [ACL commented] → ``# aci: (target...)``
            Phase 02 (Users):     [ACL commented] → ``# aci: (target...)``
            Phase 03 (Contexts):  [ACL commented] → ``# aci: (target...)``
            Phase 04 (ACL):       [ACL active]    → ``aci: (target...)``

        Args:
            entry_data: Entry model to write (with complete metadata)

        Returns:
            r with LDIF string (with original formatting restored when possible)

        References:
            - Oracle OUD LDIF Format: https://docs.oracle.com/cd/E22289_01/html/821-1273/understanding-ldif-files.html
            - RFC 2849: LDIF Specification

        """
        hook_result = self._hook_pre_write_entry(entry_data)
        if hook_result.failure:
            return r[str].fail_op("Pre-write hook", hook_result.error)
        normalized_entry = hook_result.value
        entry_to_write = self._restore_entry_from_metadata(normalized_entry)
        write_options = self._extract_write_format_options(entry_to_write.metadata)
        ldif_parts: t.MutableSequenceOf[str] = []
        ldif_parts.extend(self._add_original_entry_comments(entry_data, write_options))
        entry_data = self._apply_phase_aware_acl_handling(entry_data, write_options)
        if FlextLdifServersOudConstants.ACL_NORMALIZE_DNS_IN_VALUES:
            entry_data = self._normalize_acl_dns(entry_data)
        return (
            super()
            ._write_entry(entry_data)
            .map(lambda ldif_text: u.Ldif.finalize_ldif_text([*ldif_parts, ldif_text]))
        )
