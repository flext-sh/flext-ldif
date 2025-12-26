"""Oracle Unified Directory (OUD) Quirks.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Provides OUD-specific quirks for schema, ACL, and entry processing.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping

from flext_core import FlextLogger, FlextResult

from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif._models.metadata import FlextLdifModelsMetadata
from flext_ldif._models.settings import FlextLdifModelsSettings
from flext_ldif._utilities.metadata import FlextLdifUtilitiesMetadata
from flext_ldif.constants import c
from flext_ldif.models import m
from flext_ldif.servers._base.entry import FlextLdifServersBaseEntry
from flext_ldif.servers._oud.acl import FlextLdifServersOudAcl
from flext_ldif.servers._oud.constants import FlextLdifServersOudConstants
from flext_ldif.servers.base import FlextLdifServersBase
from flext_ldif.servers.rfc import FlextLdifServersRfc
from flext_ldif.typings import t
from flext_ldif.utilities import u

logger = FlextLogger(__name__)


class FlextLdifServersOudEntry(FlextLdifServersRfc.Entry):
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

        quirk = FlextLdifServersOudEntry()
        if quirk.can_handle_entry(entry):
            result = quirk.parse_entry(entry.dn.value, entry.attributes.attributes)
            if result.is_success:
                parsed_entry = result.value
                # Access OUD-specific operational attributes

    """

    def __init__(
        self,
        entry_service: object | None = None,
        _parent_quirk: FlextLdifServersBase | None = None,
        **kwargs: str | float | bool | None,
    ) -> None:
        """Initialize OUD entry quirk.

        Args:
            entry_service: Injected entry service (optional, must satisfy HasParseMethodProtocol)
            _parent_quirk: Reference to parent FlextLdifServersBase (optional)
            **kwargs: Additional arguments passed to parent

        """
        # Business Rule: Filter _parent_quirk from kwargs to avoid type errors
        # Implication: _parent_quirk is handled separately, not via Pydantic fields
        # Business Rule: Only pass t.GeneralValueType (str | float | bool | None) to super().__init__
        # Implication: Filter kwargs to ensure type safety (int is not t.GeneralValueType, only str/float/bool/None)
        filtered_kwargs: dict[str, str | float | bool | None] = {
            k: v
            for k, v in kwargs.items()
            if k != "_parent_quirk" and isinstance(v, (str, float, bool, type(None)))
        }
        # Business Rule: Entry.__init__ accepts entry_service and _parent_quirk
        # Implication: Call parent __init__ directly, parent handles FlextService call
        # Use same pattern as FlextLdifServersRfcEntry - call base class directly
        # Cast entry_service to protocol type for type compatibility

        entry_service_typed: object | None = (
            entry_service if entry_service is not None else None
        )

        FlextLdifServersBaseEntry.__init__(
            self,
            entry_service_typed,  # Pass as positional arg (first parameter)
            _parent_quirk=None,  # Pass None, handle separately
            **filtered_kwargs,
        )
        # Store _parent_quirk after initialization using object.__setattr__
        if _parent_quirk is not None:
            object.__setattr__(self, "_parent_quirk", _parent_quirk)

    # OVERRIDDEN METHODS (from FlextLdifServersBase.Entry)
    # These methods override the base class with Oracle OUD-specific logic:
    # - can_handle(): Detects OUD entries by DN/attributes (PRIVATE)
    # - _parse_entry(): Normalizes OUD entries with metadata during parsing (PRIVATE)
    # - _write_entry(): Writes OUD entries with proper formatting (PRIVATE)

    def can_handle(
        self,
        entry_dn: str,
        attributes: dict[str, list[str]],
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

        **Constants Used** (from ``FlextLdifServersOudConstants``):

        - ``DN_DETECTION_PATTERNS`` - DN patterns for OUD detection
        - ``DETECTION_ATTRIBUTE_PREFIXES`` - Attribute prefixes (ds-cfg-, orcl, etc.)
        - ``BOOLEAN_ATTRIBUTES`` - OUD-specific boolean attrs
        - ``KEYWORD_PATTERNS`` - Keyword detection patterns

        **Utilities Used**:

        - ``u.Ldif.Entry.matches_server_patterns()`` - Pattern matching

        **RFC Override**: Extends RFC (RFC returns True for all entries as fallback).

        Args:
            entry_dn: Entry DN string
            attributes: Entry attributes dictionary

        Returns:
            True if this quirk should handle the entry

        References:
            - Oracle OUD LDIF Format: https://docs.oracle.com/cd/E22289_01/html/821-1273/understanding-ldif-files.html

        """
        oud_constants = FlextLdifServersOudConstants
        # Create ServerPatternsConfig from constants
        patterns_config = FlextLdifModelsSettings.ServerPatternsConfig(
            dn_patterns=oud_constants.DN_DETECTION_PATTERNS,
            attr_prefixes=oud_constants.DETECTION_ATTRIBUTE_PREFIXES,
            attr_names=oud_constants.BOOLEAN_ATTRIBUTES,
            keyword_patterns=oud_constants.KEYWORD_PATTERNS,
        )
        return (
            u.Ldif.Entry.matches_server_patterns(
                entry_dn,
                attributes,
                patterns_config,
            )
            or "objectclass" in attributes
        )

    # ===== _parse_entry - SIMPLIFIED VIA HOOK-BASED ARCHITECTURE =====
    # NOTE: _process_oud_attributes REMOVED - RFC base + hooks handles this
    # NOTE: _build_and_populate_roundtrip_metadata REMOVED - RFC base handles this
    # NOTE: _analyze_oud_entry_differences REMOVED - use u.Ldif.Entry.analyze_differences
    # NOTE: _store_oud_minimal_differences REMOVED - use FlextLdifUtilitiesMetadata.store_minimal_differences
    # NOTE: parse_entry now calls RFC base + populates OUD metadata (2025-01)

    def parse_entry(
        self,
        entry_dn: str,
        entry_attrs: (dict[str, list[str]] | m.Ldif.Entry),
    ) -> FlextResult[m.Ldif.Entry]:
        """Parse entry with OUD-specific metadata population.

        RFC vs OUD Behavior Differences
        ================================

        **RFC Baseline** (in rfc.py ``parse_entry``):
        - Creates Entry model with RFC defaults
        - Metadata has quirk_type='rfc'
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
        - ``FlextLdifUtilitiesMetadata.build_entry_parse_metadata()`` - Metadata creation

        **RFC Override**: Extends RFC (RFC creates Entry, OUD adds metadata).

        Args:
            entry_dn: Entry distinguished name
            entry_attrs: Entry attributes mapping

        Returns:
            FlextResult[Entry] with OUD-specific metadata populated

        References:
            - Oracle OUD LDIF Format: https://docs.oracle.com/cd/E22289_01/html/821-1273/understanding-ldif-files.html

        """
        # Business Rule: parse_entry expects dict[str, list[str]]
        # Implication: Convert entry_attrs to expected format
        # Type narrowing: convert Mapping to dict[str, list[str]]
        entry_attrs_dict: dict[str, list[str]] = {}
        if isinstance(entry_attrs, dict):
            for key, values in entry_attrs.items():
                if isinstance(values, list):
                    entry_attrs_dict[key] = [str(v) for v in values]
                elif isinstance(values, (str, bytes)):
                    entry_attrs_dict[key] = [str(values)]
                else:
                    entry_attrs_dict[key] = [str(values)]
        elif (
            isinstance(entry_attrs, m.Ldif.Entry)
            and entry_attrs.attributes
            and entry_attrs.attributes.attributes
        ):
            # If Entry model passed, extract attributes
            entry_attrs_dict = {
                k: [str(v) for v in (vs if isinstance(vs, list) else [vs])]
                for k, vs in entry_attrs.attributes.attributes.items()
            }
        # Call RFC base parse_entry for Entry creation
        result = super().parse_entry(entry_dn, entry_attrs_dict)
        if result.is_failure:
            return result

        entry = result.value

        # Build OUD-specific metadata
        original_attribute_case: dict[str, str] = {}
        if isinstance(entry_attrs, Mapping):
            for attr_name in entry_attrs:
                if isinstance(attr_name, str):
                    # Track original case for round-trip support
                    original_attribute_case[attr_name.lower()] = attr_name

        # Create OUD metadata using utility
        metadata_config = FlextLdifModelsSettings.EntryParseMetadataConfig(
            quirk_type="oud",
            original_entry_dn=entry_dn,
            cleaned_dn=entry.dn.value if entry.dn else entry_dn,
            original_dn_line=f"dn: {entry_dn}",
            original_attr_lines=[],
            dn_was_base64=False,
            original_attribute_case=original_attribute_case,
        )
        metadata = FlextLdifUtilitiesMetadata.build_entry_parse_metadata(
            metadata_config,
        )

        # Update entry with OUD metadata
        entry.metadata = metadata

        return FlextResult.ok(entry)

    def _is_schema_entry(self, entry: m.Ldif.Entry) -> bool:
        """Check if entry is a schema entry - delegate to utility."""
        # Convert domain model to facade model for utility compatibility
        facade_entry = m.Ldif.Entry.model_validate(entry.model_dump())
        return u.Ldif.Entry.is_schema_entry(facade_entry, strict=False)

    def _add_original_entry_comments(
        self,
        entry_data: m.Ldif.Entry,
        write_options: m.Ldif.WriteFormatOptions | None,
    ) -> list[str]:
        """Add original entry as commented LDIF block.

        RFC vs OUD Behavior Differences
        ================================

        **RFC Baseline**:
        - No original entry commenting support
        - Writes only the current entry format

        **OUD Override** (this method):
        - Writes original source entry as commented LDIF block
        - Helps debug migration issues by showing source format
        - Enables auditing of OID → OUD conversions

        Output Format
        -------------

        When enabled, output includes both original and converted entry::

            # ======================================================================
            # ORIGINAL Entry (alternative format) (commented)
            # ======================================================================
            # dn: cn=user, dc=example, dc=com
            # objectclass: person
            # cn: user
            #
            # ======================================================================
            # CONVERTED OUD Entry (active)
            # ======================================================================
            dn: cn=user,dc=example,dc=com
            objectClass: person
            cn: user

        Configuration
        -------------

        Controlled via ``WriteFormatOptions``:
        - ``write_original_entry_as_comment: True`` - Enable original entry comments
        - Original entry stored in ``metadata.write_options["_original_entry"]``

        Args:
            entry_data: Entry with metadata containing original entry
            write_options: Write options with write_original_entry_as_comment flag

        Returns:
            List of LDIF comment lines (empty if feature disabled)

        """
        if not (write_options and write_options.write_original_entry_as_comment):
            return []

        # RFC Compliance: Check metadata.write_options
        if not (entry_data.metadata and entry_data.metadata.write_options):
            return []

        # WriteOptions can be a Pydantic model or dict
        write_opts = entry_data.metadata.write_options
        if hasattr(write_opts, "model_dump"):
            write_opts_dict = write_opts.model_dump()
        elif isinstance(write_opts, dict):
            write_opts_dict = write_opts
        else:
            write_opts_dict = {}
        original_entry_obj = write_opts_dict.get("original_entry")
        if not (original_entry_obj and isinstance(original_entry_obj, m.Ldif.Entry)):
            return []

        ldif_parts: list[str] = []
        ldif_parts.extend(
            [
                "# " + "=" * 70,
                "# ORIGINAL Entry (alternative format) (commented)",
                "# " + "=" * 70,
            ],
        )

        original_result = self._write_entry_as_comment(original_entry_obj)
        if original_result.is_success:
            ldif_parts.append(original_result.value)

        ldif_parts.extend(
            [
                "",
                "# " + "=" * 70,
                "# CONVERTED OUD Entry (active)",
                "# " + "=" * 70,
            ],
        )

        return ldif_parts

    def _apply_phase_aware_acl_handling(
        self,
        entry_data: m.Ldif.Entry,
        write_options: m.Ldif.WriteFormatOptions | None,
    ) -> m.Ldif.Entry:
        """Apply phase-aware ACL attribute commenting.

        RFC vs OUD Behavior Differences
        ================================

        **RFC Baseline**:
        - No phase-aware ACL handling
        - ACL attributes written directly without modification

        **OUD Override** (this method):
        - Comments out ACL attributes during non-ACL migration phases
        - Enables phased migration: entries first, ACLs later
        - Prevents ACL application before referenced entries exist

        OUD Migration Phases
        --------------------

        **Phase-Aware ACL Strategy**:

        ::

            Phase 01 (Groups):    ACL attributes → commented (# aci: ...)
            Phase 02 (Users):     ACL attributes → commented (# aci: ...)
            Phase 03 (Contexts):  ACL attributes → commented (# aci: ...)
            Phase 04 (ACL):       ACL attributes → written normally (aci: ...)

        **Why Phase-Aware ACLs?**:
        - ACIs reference entries by DN (userdn, groupdn)
        - Referenced entries must exist before ACI can be applied
        - Applying ACIs too early causes errors

        Configuration
        -------------

        Controlled via ``WriteFormatOptions``:
        - ``comment_acl_in_non_acl_phases: True`` - Enable phase awareness
        - ``entry_category``: Current phase (``"group"``, ``"user"``, ``"acl"``)
        - ``acl_attribute_names``: List of ACL attribute names to comment

        Args:
            entry_data: Entry to process
            write_options: Write options with ACL phase settings

        Returns:
            Entry with ACL attributes commented if applicable

        """
        if not (write_options and write_options.comment_acl_in_non_acl_phases):
            return entry_data

        category = write_options.entry_category
        acl_attrs = write_options.acl_attribute_names

        if not (category and category != "acl" and acl_attrs):
            return entry_data

        # Comment out ACL attributes in non-ACL phases (01/02/03)
        # Use utility to comment ACL attributes - CRITICAL for client-a-oud-mig phase-aware handling
        # Convert to list if needed (acl_attrs can be frozenset, set, or list)
        acl_attrs_list = (
            list(acl_attrs)
            if isinstance(acl_attrs, (frozenset, set))
            else acl_attrs
            if isinstance(acl_attrs, list)
            else []
        )
        return self._comment_acl_attributes(entry_data, acl_attrs_list)

    @staticmethod
    def extract_and_remove_acl_attributes(
        attributes_dict: dict[str, list[str]],
        acl_attribute_names: list[str],
    ) -> tuple[dict[str, list[str]], dict[str, list[str]], set[str]]:
        """Extract ACL attributes and remove from active dict.

        Args:
            attributes_dict: Current attributes dictionary
            acl_attribute_names: Names of ACL attributes to process

        Returns:
            Tuple of (new_attributes_dict, commented_acl_values, hidden_attrs)

        """
        new_attrs: dict[str, list[str]] = dict(attributes_dict)
        commented_vals: dict[str, list[str]] = {}
        hidden_attrs = set()

        for acl_attr in acl_attribute_names:
            if acl_attr in new_attrs:
                acl_values = new_attrs[acl_attr]
                if isinstance(acl_values, list):
                    commented_vals[acl_attr] = list(acl_values)
                else:
                    commented_vals[acl_attr] = [str(acl_values)]

                del new_attrs[acl_attr]
                hidden_attrs.add(acl_attr.lower())

        return new_attrs, commented_vals, hidden_attrs

    @staticmethod
    def _create_write_options_with_hidden_attrs(
        write_opts: m.Ldif.WriteOptions | dict[str, object] | None,
        hidden_attrs: set[str],
    ) -> m.Ldif.WriteOptions:
        """Create WriteOptions with updated hidden attributes.

        Args:
            write_opts: Existing write options (model, dict, or None)
            hidden_attrs: Set of hidden attribute names to add

        Returns:
            New WriteOptions with merged hidden_attrs

        """
        if not write_opts:
            return m.Ldif.WriteOptions()

        # Extract existing hidden attrs
        hidden_attrs_raw = getattr(write_opts, "hidden_attrs", [])
        hidden_attrs_set = (
            set(hidden_attrs_raw)
            if isinstance(hidden_attrs_raw, (list, tuple, frozenset, set))
            else set()
        )
        hidden_attrs_set.update(hidden_attrs)

        # Handle Pydantic model with model_copy
        # Type narrowing: check if write_opts is a Pydantic model
        # Business Rule: Always use public m.Ldif.WriteOptions, not internal m.Ldif.WriteOptions
        if isinstance(write_opts, m.Ldif.WriteOptions):
            # Use dict[str, object] for model_copy update to satisfy strict type checker
            update_dict: dict[str, object] = {"hidden_attrs": list(hidden_attrs_set)}
            return write_opts.model_copy(update=update_dict)

        # Handle dict
        if isinstance(write_opts, dict):
            write_opts_dict: dict[str, object] = {
                "hidden_attrs": list(hidden_attrs_set),
            }
            for field in ["line_width", "indent", "sort_attributes"]:
                if field in write_opts:
                    write_opts_dict[field] = write_opts[field]
            return m.Ldif.WriteOptions.model_validate(write_opts_dict)

        # Handle Pydantic model with model_dump (WriteFormatOptions or internal WriteOptions)
        # Business Rule: Always convert to public FlextLdifModelsDomains.WriteOptions, not internal FlextLdifModelsDomains.WriteOptions
        if hasattr(write_opts, "model_dump"):
            write_opts_dict_raw = write_opts.model_dump()
            filtered_dict: dict[str, object] = {"hidden_attrs": list(hidden_attrs_set)}
            for field in ["line_width", "indent", "sort_attributes"]:
                if field in write_opts_dict_raw:
                    filtered_dict[field] = write_opts_dict_raw[field]
            return m.Ldif.WriteOptions.model_validate(filtered_dict)

        # Fallback: create new WriteOptions
        # Business Rule: Always return public m.Ldif.WriteOptions
        return m.Ldif.WriteOptions(hidden_attrs=list(hidden_attrs_set))

    @staticmethod
    def update_metadata_with_commented_acls(
        metadata: FlextLdifModelsDomains.QuirkMetadata,
        acl_attribute_names: list[str],
        commented_acl_values: dict[str, list[str]],
        hidden_attrs: set[str],
        entry_attributes_dict: dict[str, list[str]],
    ) -> FlextLdifModelsDomains.QuirkMetadata:
        """Update metadata with commented ACL information.

        Args:
            metadata: Existing metadata (must be m.Ldif.QuirkMetadata, not internal model)
            acl_attribute_names: List of ACL attribute names
            commented_acl_values: Dictionary of commented ACL values
            hidden_attrs: Set of hidden attribute names
            entry_attributes_dict: Original attributes dict for checking

        Returns:
            Updated metadata with ACL information

        """
        # Type narrowing: ensure metadata is usable as QuirkMetadata
        # Business Rule: Accept both internal and facade QuirkMetadata types
        metadata_typed: FlextLdifModelsDomains.QuirkMetadata = metadata
        current_extensions: dict[str, t.MetadataAttributeValue] = (
            dict(metadata_typed.extensions) if metadata_typed.extensions else {}
        )

        # Create new write options with hidden attrs using helper
        new_write_options = (
            FlextLdifServersOudEntry._create_write_options_with_hidden_attrs(
                metadata_typed.write_options,
                hidden_attrs,
            )
        )

        # Create new metadata instance with updated write_options
        # Use dict[str, object] for model_copy update to satisfy strict type checker
        update_dict: dict[str, object] = {"write_options": new_write_options}
        metadata_typed = metadata_typed.model_copy(update=update_dict)

        # Store commented ACL values
        if commented_acl_values:
            converted_attrs: list[str] = list(commented_acl_values.keys())
            current_extensions["converted_attributes"] = converted_attrs
            # Business Rule: extensions expects MetadataAttributeValue (ScalarValue)
            # Implication: Convert dict to JSON string for storage
            current_extensions["commented_attribute_values"] = json.dumps(
                commented_acl_values,
            )

        # Track in extensions - type narrow for list[str] using comprehension
        commented_attrs_raw = current_extensions.get("acl_commented_attributes", [])
        commented_attrs: list[str] = (
            [str(x) for x in commented_attrs_raw]
            if isinstance(commented_attrs_raw, list)
            else []
        )

        for acl_attr in acl_attribute_names:
            if acl_attr in entry_attributes_dict and acl_attr not in commented_attrs:
                commented_attrs.append(acl_attr)

        if commented_attrs:
            current_extensions["acl_commented_attributes"] = commented_attrs

        # Business Rule: metadata is frozen, must use model_copy to update both extensions and write_options
        # Implication: Combine both updates in a single model_copy call
        # Use dict[str, object] for model_copy update to satisfy strict type checker
        update_dict_final: dict[str, object] = {
            "extensions": current_extensions,
            "write_options": new_write_options,
        }
        return metadata_typed.model_copy(update=update_dict_final)

    @staticmethod
    def _comment_acl_attributes(
        entry_data: m.Ldif.Entry,
        acl_attribute_names: list[str],
    ) -> m.Ldif.Entry:
        """Comment out ACL attributes by removing them from attributes dict and storing in metadata.

        CRITICAL for client-a-oud-mig phase-aware ACL handling.
        Removes ACL attributes from active attributes dict and stores values in metadata
        for later comment generation with [TRANSFORMED] and [SKIP TO 04] tags.

        Args:
            entry_data: Entry with ACL attributes
            acl_attribute_names: List of ACL attribute names to comment

        Returns:
            Entry with ACL attributes removed from attributes dict and stored in metadata

        """
        if not entry_data.attributes or not acl_attribute_names:
            return entry_data

        # Ensure metadata exists
        existing_metadata = entry_data.metadata
        if not existing_metadata:
            existing_metadata = m.Ldif.QuirkMetadata.create_for("oud")

        # Extract and remove ACL attributes from active dict
        # Note: Using class-based call for staticmethod
        new_attributes_dict, commented_acl_values, hidden_attrs = (
            FlextLdifServersOudEntry.extract_and_remove_acl_attributes(
                entry_data.attributes.attributes,
                acl_attribute_names,
            )
        )

        # Update metadata with commented ACL information
        updated_metadata = FlextLdifServersOudEntry.update_metadata_with_commented_acls(
            existing_metadata,
            acl_attribute_names,
            commented_acl_values,
            hidden_attrs,
            entry_data.attributes.attributes,
        )

        # Return updated entry with new attributes dict (without ACLs)
        return entry_data.model_copy(
            update={
                "attributes": m.Ldif.Attributes(
                    attributes=new_attributes_dict,
                    attribute_metadata=entry_data.attributes.attribute_metadata,
                    metadata=entry_data.attributes.metadata,
                ),
                "metadata": updated_metadata,
            },
        )

    def _normalize_aci_value(
        self,
        aci_value: str,
        _base_dn: str | None,
        _dn_registry: m.Ldif.DnRegistry | None,
    ) -> tuple[str, bool]:
        """Normalize ACI value DNs (already RFC canonical, no changes needed)."""
        # ACI values are already normalized during RFC parsing
        return aci_value, False

    def _extract_acl_metadata(
        self,
        entry_data: m.Ldif.Entry,
    ) -> tuple[str | None, m.Ldif.DnRegistry | None]:
        """Extract base_dn and dn_registry from entry metadata for ACL processing.

        Args:
            entry_data: Entry with potential metadata

        Returns:
            Tuple of (base_dn, dn_registry)

        """
        base_dn: str | None = None
        dn_registry: m.Ldif.DnRegistry | None = None

        if entry_data.metadata and entry_data.metadata.write_options:
            # Try write_options first
            base_dn_value = getattr(
                entry_data.metadata.write_options,
                "base_dn",
                None,
            )
            if isinstance(base_dn_value, str):
                base_dn = base_dn_value

            # Get dn_registry from write_options
            dn_registry_value = getattr(
                entry_data.metadata.write_options,
                "dn_registry",
                None,
            )
            if isinstance(dn_registry_value, m.Ldif.DnRegistry):
                dn_registry = dn_registry_value

        # Try extensions if write_options doesn't have base_dn
        if base_dn is None and entry_data.metadata and entry_data.metadata.extensions:
            extensions = entry_data.metadata.extensions
            # DynamicMetadata has .get() method for extra field access
            base_dn_ext = extensions.get("base_dn")
            if isinstance(base_dn_ext, str):
                base_dn = base_dn_ext
            dn_registry_ext = extensions.get("dn_registry")
            if isinstance(dn_registry_ext, m.Ldif.DnRegistry):
                dn_registry = dn_registry_ext

        return base_dn, dn_registry

    def _normalize_acl_dns(
        self,
        entry_data: m.Ldif.Entry,
    ) -> m.Ldif.Entry:
        r"""Normalize and filter DNs in ACL attribute values (userdn/groupdn inside ACL strings).

        RFC vs OUD Behavior Differences
        ================================

        **RFC Baseline**:
        - No ACL DN normalization in RFC base
        - ACLs stored as raw strings without processing

        **OUD Override** (this method):
        - Normalizes DNs within ACI values (userdn, groupdn patterns)
        - Removes spaces after commas in embedded DNs
        - Optionally filters DNs by base_dn scope
        - Preserves DN case while normalizing whitespace

        ACI DN Normalization
        --------------------

        **Patterns Processed**:
        - ``userdn="ldap:///cn=user, dc=example, dc=com"`` → normalized DN
        - ``groupdn="ldap:///cn=group, dc=example, dc=com"`` → normalized DN
        - ``roledn="ldap:///cn=role, dc=example, dc=com"`` → normalized DN

        **Normalization Rules**:
        - Remove spaces after commas: ``cn=user, dc=example`` → ``cn=user,dc=example``
        - Preserve attribute case: ``CN=User`` stays as ``CN=User``
        - Handle escaped characters: ``cn=user\, name`` preserved

        **Base DN Filtering** (when configured):
        - Filter out ACIs referencing DNs outside base_dn scope
        - Helps migration by excluding irrelevant ACIs

        Args:
            entry_data: Entry with potential ACL attributes

        Returns:
            Entry with normalized/filtered ACL values

        """
        if not entry_data.attributes or not entry_data.attributes.attributes:
            return entry_data

        # Extract base_dn and dn_registry from metadata
        base_dn, dn_registry = self._extract_acl_metadata(entry_data)

        # Process aci attribute values
        attrs = entry_data.attributes.attributes
        if "aci" not in attrs:
            return entry_data

        aci_values = attrs["aci"]
        if not aci_values:
            return entry_data

        # Normalize each ACL value string
        normalized_aci_values: list[str] = []
        for aci in aci_values:
            aci_str = aci if isinstance(aci, str) else str(aci)
            normalized_aci, was_filtered = self._normalize_aci_value(
                aci_str,
                base_dn,
                dn_registry,
            )

            # Only add if no DN was filtered out (ACL is still valid)
            if not was_filtered and normalized_aci:
                normalized_aci_values.append(normalized_aci)

        # Update entry with normalized ACL values
        if normalized_aci_values != aci_values:
            new_attrs = dict(entry_data.attributes.attributes)
            new_attrs["aci"] = normalized_aci_values
            entry_data.attributes.attributes = new_attrs

        return entry_data

    def _restore_entry_from_metadata(
        self,
        entry_data: m.Ldif.Entry,
    ) -> m.Ldif.Entry:
        """Restore original DN and attributes using generic utilities.

        RFC vs OUD Behavior Differences
        ================================

        **RFC Baseline** (in rfc.py ``_restore_entry_from_metadata``):
        - Basic restoration of DN and attributes
        - Uses metadata.extensions for stored values
        - Simple case mapping restoration

        **OUD Override** (this method):
        - Full roundtrip restoration using OUD-specific metadata
        - Restores DN with original spacing (spaces after commas)
        - Restores attribute names with original case
        - Restores attribute values to original format

        Restoration Process
        -------------------

        **1. DN Restoration** (if differences detected):
           - Checks ``minimal_differences_dn.has_differences``
           - Uses ``original_dn_complete`` from extensions
           - Restores DN with original spacing quirks

        **2. Attribute Restoration** (if case mapping available):
           - Uses ``original_attribute_case`` mapping
           - Uses ``original_attributes_complete`` dictionary
           - Restores each attribute with original case

        Example Restoration
        -------------------

        ::

            # Original OID entry:
            objectclass: groupOfUniqueNames
            uniquemember: cn = user1

            # Normalized for OUD:
            objectClass: groupOfUniqueNames
            uniqueMember: cn = user1

            # Restored for roundtrip (with preserve_original=True):
            objectclass: groupOfUniqueNames
            uniquemember: cn = user1

        """
        if not (entry_data.metadata and entry_data.metadata.extensions):
            return entry_data
        ext = entry_data.metadata.extensions

        # Restore DN if differences detected
        # Uses c.Ldif.MetadataKeys for consistent key access
        mk = c.Ldif.MetadataKeys
        if (
            (original_dn := ext.get(mk.ORIGINAL_DN_COMPLETE))
            and isinstance(original_dn, str)
            and entry_data.dn
        ):
            dn_diff = ext.get(mk.MINIMAL_DIFFERENCES_DN, {})
            if isinstance(dn_diff, dict):
                has_diff = dn_diff.get(mk.HAS_DIFFERENCES, False)
                if has_diff:
                    entry_data = entry_data.model_copy(
                        update={
                            "dn": m.Ldif.DN(value=original_dn),
                        },
                    )

        # Restore attributes if case mapping available
        original_case_map = (
            entry_data.metadata.original_attribute_case if entry_data.metadata else None
        )
        if (
            entry_data.attributes
            and original_case_map
            and isinstance(original_case_map, dict)
            and (
                orig_attrs := ext.get(c.Ldif.MetadataKeys.ORIGINAL_ATTRIBUTES_COMPLETE)
            )
            and isinstance(orig_attrs, dict)
        ):
            # Business Rule: Restore original attribute case from metadata.
            # orig_case is str (from original_case_map.get()), but pyright may infer
            # it as MetadataAttributeValue. We use explicit type narrowing.
            # Implication: Ensure orig_case is always str for dict key access.
            restored: dict[str, list[str]] = {}
            for attr_name, attr_values in entry_data.attributes.attributes.items():
                # Business Rule: original_case_map.get() returns str (the original case).
                # Type narrowing: Ensure orig_case is str for type safety.
                orig_case_raw = original_case_map.get(
                    attr_name.lower(),
                    attr_name,
                )
                orig_case: str = str(orig_case_raw) if orig_case_raw else attr_name
                # Business Rule: orig_attrs is dict-like (DynamicMetadata), accessed via str keys.
                # Implication: Use str(orig_case) for type safety even though runtime is correct.
                if orig_case in orig_attrs:
                    val = orig_attrs[orig_case]
                    restored[orig_case] = (
                        [str(i) for i in val]
                        if isinstance(val, (list, tuple))
                        else [str(val)]
                    )
                else:
                    restored[orig_case] = (
                        [str(i) for i in attr_values]
                        if isinstance(attr_values, list)
                        else [str(attr_values)]
                    )

            if restored:
                entry_data = entry_data.model_copy(
                    update={
                        "attributes": m.Ldif.Attributes(
                            attributes=restored,
                            attribute_metadata=entry_data.attributes.attribute_metadata,
                            metadata=entry_data.attributes.metadata,
                        ),
                    },
                )

        return entry_data

    def _write_entry(
        self,
        entry_data: m.Ldif.Entry,
    ) -> FlextResult[str]:
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
            FlextResult with LDIF string (with original formatting restored when possible)

        References:
            - Oracle OUD LDIF Format: https://docs.oracle.com/cd/E22289_01/html/821-1273/understanding-ldif-files.html
            - RFC 2849: LDIF Specification

        """
        # Step 1: Apply pre-write hook for OUD-specific normalization (attribute case, boolean conversion)
        hook_result = self._hook_pre_write_entry(entry_data)
        if hook_result.is_failure:
            return FlextResult[str].fail(
                f"Pre-write hook failed: {hook_result.error}",
            )
        normalized_entry = hook_result.value

        # Step 2: Restore original formatting from metadata
        entry_to_write = self._restore_entry_from_metadata(normalized_entry)

        # Extract write options (uses utility)
        write_options = FlextLdifUtilitiesMetadata.extract_write_options(
            entry_to_write,
        )

        # Build LDIF output
        ldif_parts: list[str] = []
        ldif_parts.extend(
            self._add_original_entry_comments(entry_data, write_options),
        )

        # Apply phase-aware ACL handling
        entry_data = self._apply_phase_aware_acl_handling(entry_data, write_options)

        # Normalize DNs in ACL values if enabled
        if FlextLdifServersOudConstants.ACL_NORMALIZE_DNS_IN_VALUES:
            entry_data = self._normalize_acl_dns(entry_data)

        # Write entry in appropriate format and finalize using map pattern
        return (
            super()
            ._write_entry(entry_data)
            .map(
                lambda ldif_text: u.Ldif.Writer.finalize_ldif_text(
                    ldif_parts + [ldif_text]
                ),
            )
        )

    def _write_entry_as_comment(
        self,
        entry_data: m.Ldif.Entry,
    ) -> FlextResult[str]:
        """Write entry as commented LDIF (each line prefixed with '# ').

        Args:
            entry_data: Entry to write as comment

        Returns:
            FlextResult with commented LDIF string

        """
        # Use RFC write method and transform to commented LDIF using map pattern
        return (
            super()
            ._write_entry(entry_data)
            .map(
                lambda ldif_text: "\n".join(
                    f"# {line}" for line in ldif_text.split("\n")
                ),
            )
        )

    def _add_transformation_comments(
        self,
        comment_lines: list[str],
        entry: m.Ldif.Entry,
        format_options: m.Ldif.WriteFormatOptions | None = None,
    ) -> None:
        """Add transformation comments for attribute changes, including OUD-specific ACL handling.

        OUD Override of RFC's _add_transformation_comments to handle OID→OUD transformations:
        - [TRANSFORMED] for original ACL values (orclaci)
        - [SKIP TO 04] for new ACL values (aci) in phases 01-03

        Uses generic utilities with hooks/parameters for extensibility.
        Attributes are sorted using the same ordering logic as normal attributes.

        Args:
            comment_lines: List to append comments to
            entry: Entry with transformation metadata
            format_options: Write format options for attribute ordering

        """
        if not entry.metadata:
            return

        # Handle OUD-specific ACL comments for phases 01-03
        # Pass format_options to ensure ACL comments are sorted correctly
        acl_attr_names_to_skip = self._add_oud_acl_comments(
            comment_lines,
            entry,
            format_options,
        )

        # Process attribute_transformations (primary source)
        processed_attrs: set[str] = set()
        if entry.metadata.attribute_transformations:
            # Collect attribute names and sort them using the same logic as normal attributes
            attr_names = [
                attr_name
                for attr_name in entry.metadata.attribute_transformations
                if attr_name.lower() not in acl_attr_names_to_skip
            ]
            ordered_attr_names = self._determine_attribute_order(
                attr_names,
                format_options,
            )

            # Iterate over sorted attribute names instead of dictionary directly
            for attr_name in ordered_attr_names:
                transformation = entry.metadata.attribute_transformations[attr_name]
                transformation_type = transformation.transformation_type.upper()
                # Map types: MODIFIED → TRANSFORMED for comments
                comment_type = (
                    "TRANSFORMED"
                    if transformation_type in {"MODIFIED", "TRANSFORMED"}
                    else transformation_type
                )
                self._add_attribute_transformation_comments(
                    comment_lines,
                    attr_name,
                    transformation,
                    comment_type,
                )
                processed_attrs.add(attr_name.lower())

        # Also check removed_attributes field for legacy compatibility
        # This ensures all removed attributes are shown, even if not tracked as transformations
        if (
            format_options
            and format_options.write_removed_attributes_as_comments
            and entry.metadata.removed_attributes
        ):
            # removed_attributes is a DynamicMetadata, iterate over model_dump keys
            removed_attrs_dict = entry.metadata.removed_attributes.model_dump()
            removed_attr_names: list[str] = [
                str(attr_name)
                for attr_name in removed_attrs_dict
                if isinstance(attr_name, str)
                and attr_name.lower() not in acl_attr_names_to_skip
            ]
            ordered_removed_attrs = self._determine_attribute_order(
                removed_attr_names,
                format_options,
            )

            for attr_name in ordered_removed_attrs:
                # Skip if already processed as transformation or ACL
                if attr_name.lower() in processed_attrs:
                    continue

                removed_values = entry.metadata.removed_attributes[attr_name]
                if isinstance(removed_values, list):
                    comment_lines.extend(
                        f"# [REMOVED] {attr_name}: {value}" for value in removed_values
                    )
                else:
                    comment_lines.append(
                        f"# [REMOVED] {attr_name}: {removed_values}",
                    )

        if comment_lines:
            comment_lines.append("")  # Separator

    def _collect_acl_from_transformations(
        self,
        entry: m.Ldif.Entry,
        acl_comments_dict: dict[str, list[str]],
        acl_attr_names_to_skip: set[str],
    ) -> None:
        """Collect ACL comments from attribute_transformations with SKIP_TO_04."""
        if not entry.metadata or not entry.metadata.attribute_transformations:
            return

        acl_attr_set = {"aci", "orclaci", "orclentrylevelaci"}
        for (
            attr_name,
            transformation,
        ) in entry.metadata.attribute_transformations.items():
            is_skip_to_04 = (
                transformation.reason and "SKIP_TO_04" in transformation.reason.upper()
            )
            if is_skip_to_04 and attr_name.lower() in acl_attr_set:
                acl_attr_names_to_skip.add(attr_name.lower())
                if attr_name not in acl_comments_dict:
                    acl_comments_dict[attr_name] = []
                for acl_value in transformation.original_values:
                    acl_comments_dict[attr_name].extend([
                        f"# [REMOVED] {attr_name}: {acl_value}",
                        f"# [SKIP_TO_04] {attr_name}: {acl_value}",
                    ])

    @staticmethod
    def _normalize_acl_values(
        acl_values_raw: object,
    ) -> list[str] | str | m.Ldif.Acl:
        """Normalize ACL values to expected type for comment generation.

        Args:
            acl_values_raw: Raw ACL values (MetadataAttributeValue)

        Returns:
            Normalized values as list[str], str, or Acl model

        """
        if isinstance(acl_values_raw, str):
            return acl_values_raw
        if isinstance(acl_values_raw, list):
            return [str(v) for v in acl_values_raw]
        if isinstance(acl_values_raw, m.Ldif.Acl):
            return acl_values_raw
        return str(acl_values_raw)

    @staticmethod
    def _parse_commented_values(
        commented_raw: object,
    ) -> dict[str, object] | None:
        """Parse commented ACL values from raw storage format.

        Args:
            commented_raw: Raw value from extensions (JSON string or dict)

        Returns:
            Parsed dict or None if unparseable

        """
        if isinstance(commented_raw, str):
            # json.loads returns Any - validate with isinstance
            result = json.loads(commented_raw)
            if isinstance(result, dict):
                return result
            return None
        if isinstance(commented_raw, dict):
            return commented_raw
        return None

    def _collect_acl_from_extensions(
        self,
        entry: m.Ldif.Entry,
        acl_comments_dict: dict[str, list[str]],
        acl_attr_names_to_skip: set[str],
    ) -> None:
        """Collect ACL comments from extensions.commented_attribute_values."""
        if not entry.metadata or not entry.metadata.extensions:
            return

        commented_acl_values_raw = entry.metadata.extensions.get(
            "commented_attribute_values",
        )
        if not commented_acl_values_raw:
            return

        commented_acl_values = self._parse_commented_values(commented_acl_values_raw)
        if not commented_acl_values:
            return

        original_acl_attr = self._get_original_acl_attr(entry)
        for acl_attr_name, acl_values_raw in commented_acl_values.items():
            if acl_attr_name.lower() in acl_attr_names_to_skip:
                continue
            acl_attr_names_to_skip.add(acl_attr_name.lower())
            sort_key = original_acl_attr or acl_attr_name
            if sort_key not in acl_comments_dict:
                acl_comments_dict[sort_key] = []
            acl_values = self._normalize_acl_values(acl_values_raw)
            self._add_acl_value_comments(
                acl_comments_dict[sort_key],
                original_acl_attr,
                acl_attr_name,
                acl_values,
            )

    def _add_acl_value_comments(
        self,
        comments: list[str],
        original_attr: str,
        attr_name: str,
        acl_values: list[str] | str | m.Ldif.Acl,
    ) -> None:
        """Add TRANSFORMED and SKIP_TO_04 comments for ACL values."""
        if isinstance(acl_values, list):
            for acl_value in acl_values:
                comments.extend([
                    f"# [TRANSFORMED] {original_attr}: {acl_value}",
                    f"# [SKIP_TO_04] {attr_name}: {acl_value}",
                ])
        else:
            acl_val_str = str(acl_values)
            comments.extend([
                f"# [TRANSFORMED] {original_attr}: {acl_val_str}",
                f"# [SKIP_TO_04] {attr_name}: {acl_val_str}",
            ])

    def _add_oud_acl_comments(
        self,
        comment_lines: list[str],
        entry: m.Ldif.Entry,
        format_options: m.Ldif.WriteFormatOptions | None = None,
    ) -> set[str]:
        """Add OUD-specific ACL comments for phases 01-03.

        Checks both attribute_transformations and extensions.commented_attribute_values.
        Returns set of ACL attribute names to skip in regular processing.

        """
        acl_attr_names_to_skip: set[str] = set()
        if not entry.metadata:
            return acl_attr_names_to_skip

        acl_comments_dict: dict[str, list[str]] = {}

        self._collect_acl_from_transformations(
            entry,
            acl_comments_dict,
            acl_attr_names_to_skip,
        )
        self._collect_acl_from_extensions(
            entry,
            acl_comments_dict,
            acl_attr_names_to_skip,
        )

        if acl_comments_dict:
            acl_attr_names = list(acl_comments_dict.keys())
            ordered_acl_attrs = self._determine_attribute_order(
                acl_attr_names,
                format_options,
            )
            for attr_name in ordered_acl_attrs:
                if attr_name in acl_comments_dict:
                    comment_lines.extend(acl_comments_dict[attr_name])

        return acl_attr_names_to_skip

    def _get_original_acl_attr(self, entry: m.Ldif.Entry) -> str:
        """Get original ACL attribute name (orclaci) from transformations or metadata."""
        if entry.metadata and entry.metadata.attribute_transformations:
            for (
                attr_name,
                transformation,
            ) in entry.metadata.attribute_transformations.items():
                if (
                    attr_name.lower() in {"aci", "orclaci"}
                    and transformation.target_name
                    and transformation.target_name.lower() == "aci"
                ):
                    return attr_name

        # Try to find original ACL attribute name from metadata
        if entry.metadata and entry.metadata.extensions:
            acl_original_format = entry.metadata.extensions.get(
                "original_format",
            )
            if acl_original_format and "orclaci:" in str(acl_original_format):
                return "orclaci"

        # Default to "orclaci" if we can't determine the original name
        return "orclaci"

    def generate_entry_comments(
        self,
        entry: m.Ldif.Entry,
        format_options: m.Ldif.WriteFormatOptions | None = None,
    ) -> str:
        """Generate LDIF comments for transformations, including OUD-specific ACL handling.

        OUD Override of RFC's generate_entry_comments to add phase-aware ACL comments.
        Delegates to _add_transformation_comments() for OID→OUD specific handling.

        Args:
            entry: Entry to generate comments for
            format_options: Write format options controlling comment generation (optional)

        Returns:
            String containing comment lines (with trailing newline if non-empty)

        """
        # Return empty if no format_options provided
        if not format_options:
            return ""

        comment_lines: list[str] = []

        # Add transformation comments if enabled (includes OUD-specific ACL handling)
        if format_options.write_transformation_comments:
            self._add_transformation_comments(comment_lines, entry, format_options)

        # Add rejection reason comments if enabled
        if format_options.write_rejection_reasons:
            self._add_rejection_reason_comments(comment_lines, entry)

        return "\n".join(comment_lines) + "\n" if comment_lines else ""

    def _normalize_aci_value_simple(self, value: object) -> list[str] | str | None:
        """Normalize ACI value to list[str] | str | None."""
        if isinstance(value, list):
            return [str(v) for v in value]
        if isinstance(value, str):
            return value
        if value is None:
            return None
        return str(value)

    def _find_aci_in_dict(
        self,
        attrs: Mapping[str, object] | None,
    ) -> list[str] | str | None:
        """Find ACI value in dictionary (case-insensitive)."""
        if not attrs:
            return None
        for key, value in attrs.items():
            if key.lower() == "aci":
                return self._normalize_aci_value_simple(value)
        return None

    def _find_aci_values(
        self,
        entry: m.Ldif.Entry,
        original_attrs: t.Ldif.CommonDict.AttributeDictGeneric,
    ) -> list[str] | str | None:
        """Find ACI values from entry or original_attrs."""
        # Try direct key access first
        aci_values = self._normalize_aci_value_simple(
            original_attrs.get("aci") if original_attrs else None,
        )

        # Try entry attributes if not found
        if not aci_values and entry.attributes and entry.attributes.attributes:
            aci_values = self._normalize_aci_value_simple(
                entry.attributes.attributes.get("aci"),
            )

        # Try case-insensitive search if still not found
        if not aci_values:
            aci_values = self._find_aci_in_dict(original_attrs)
            if not aci_values and entry.attributes and entry.attributes.attributes:
                aci_values = self._find_aci_in_dict(entry.attributes.attributes)

        return aci_values

    def _process_parsed_acl_extensions(
        self,
        acl_extensions: dict[str, t.MetadataAttributeValue],
        current_extensions: dict[str, t.MetadataAttributeValue],
    ) -> None:
        """Process parsed ACL extensions and add to current extensions."""
        mk = c.Ldif.MetadataKeys
        key_mapping: dict[str, str] = {
            "targattrfilters": mk.ACL_TARGETATTR_FILTERS,
            "targetcontrol": mk.ACL_TARGET_CONTROL,
            "extop": mk.ACL_EXTOP,
            "ip": mk.ACL_BIND_IP_FILTER,  # Use BIND_IP_FILTER instead
            "dns": mk.ACL_TARGETSCOPE,  # Use available constant
            "dayofweek": mk.ACL_NUMBERING,  # Fallback
            "timeofday": mk.ACL_BINDMODE,  # Fallback
            "authmethod": mk.ACL_SOURCE_PERMISSIONS,  # Fallback
            "ssf": mk.ACL_SSFS,  # Use SSFS
            mk.ACL_TARGETATTR_FILTERS: mk.ACL_TARGETATTR_FILTERS,
            mk.ACL_TARGET_CONTROL: mk.ACL_TARGET_CONTROL,
            mk.ACL_EXTOP: mk.ACL_EXTOP,
            mk.ACL_BIND_IP_FILTER: mk.ACL_BIND_IP_FILTER,
            mk.ACL_TARGETSCOPE: mk.ACL_TARGETSCOPE,
            mk.ACL_NUMBERING: mk.ACL_NUMBERING,
            mk.ACL_BINDMODE: mk.ACL_BINDMODE,
            mk.ACL_SOURCE_PERMISSIONS: mk.ACL_SOURCE_PERMISSIONS,
            mk.ACL_SSFS: mk.ACL_SSFS,
        }
        known_keys = {
            mk.ACL_TARGETATTR_FILTERS,
            mk.ACL_TARGET_CONTROL,
            mk.ACL_EXTOP,
            mk.ACL_BIND_IP_FILTER,
            mk.ACL_TARGETSCOPE,
            mk.ACL_NUMBERING,
            mk.ACL_BINDMODE,
            mk.ACL_SOURCE_PERMISSIONS,
            mk.ACL_SSFS,
        }
        for key, value in acl_extensions.items():
            key_lower = key.lower()
            mapped_key = key_mapping.get(key) or key_mapping.get(key_lower)
            if mapped_key is None and key in known_keys:
                mapped_key = key
            final_key = mapped_key or key
            # Type narrowing: ensure value is compatible with MetadataAttributeValue
            # MetadataAttributeValue = ScalarValue | Sequence[ScalarValue] | Mapping[str, ScalarValue]
            # where ScalarValue = str | int | float | bool | datetime | None
            if isinstance(value, (str, int, float, bool, type(None))):
                current_extensions[final_key] = value
            elif isinstance(value, (list, tuple)):
                # Convert to list[str] if all items are strings, otherwise convert to list[ScalarValue]
                value_list: list[t.ScalarValue] = [
                    item
                    if isinstance(item, (str, int, float, bool, type(None)))
                    else str(item)
                    for item in value
                ]
                current_extensions[final_key] = value_list
            elif isinstance(value, dict):
                # Convert dict values to ScalarValue
                value_dict: dict[str, t.ScalarValue] = {
                    k: v
                    if isinstance(v, (str, int, float, bool, type(None)))
                    else str(v)
                    for k, v in value.items()
                }
                current_extensions[final_key] = value_dict
            else:
                # Convert other types to str
                current_extensions[final_key] = str(value)

    def _process_aci_list_for_finalize(
        self,
        aci_values: list[str] | str,
        acl_quirk: FlextLdifServersOudAcl,
        current_extensions: dict[str, t.MetadataAttributeValue],
    ) -> None:
        """Process list of ACI values and extract metadata."""
        aci_list = (
            list(aci_values)
            if isinstance(aci_values, (list, tuple))
            else [str(aci_values)]
        )
        for aci_value in aci_list:
            if not isinstance(aci_value, str):
                continue
            normalized_aci = aci_value.strip()
            if not normalized_aci.startswith("aci:"):
                normalized_aci = f"aci: {normalized_aci}"
            # Parse ACL using OUD ACL quirk's parse() method (public API)
            acl_result = acl_quirk.parse(normalized_aci)
            if acl_result.is_success:
                acl_model = acl_result.value
                if acl_model.metadata and acl_model.metadata.extensions:
                    acl_ext_raw = (
                        acl_model.metadata.extensions.model_dump()
                        if hasattr(acl_model.metadata.extensions, "model_dump")
                        else dict(acl_model.metadata.extensions)
                    )
                    # Type narrow for proper type checking
                    acl_extensions: dict[str, t.MetadataAttributeValue] = dict(
                        acl_ext_raw,
                    )
                    self._process_parsed_acl_extensions(
                        acl_extensions,
                        current_extensions,
                    )

    def _merge_acl_metadata_to_entry(
        self,
        entry: m.Ldif.Entry,
        acl_metadata_extensions: dict[str, t.MetadataAttributeValue],
    ) -> m.Ldif.Entry:
        """Merge ACL metadata extensions into entry metadata."""
        if not acl_metadata_extensions:
            return entry

        if entry.metadata:
            # Get current extensions as dict
            current_extensions: dict[str, t.MetadataAttributeValue]
            if isinstance(
                entry.metadata.extensions,
                FlextLdifModelsMetadata.DynamicMetadata,
            ):
                current_extensions_dict = entry.metadata.extensions.model_dump(
                    exclude_unset=True,
                )
                current_extensions = current_extensions_dict
            elif isinstance(entry.metadata.extensions, dict):
                # Type narrowing: dict is compatible with dict[str, t.MetadataAttributeValue]
                current_extensions = entry.metadata.extensions
            else:
                current_extensions = {}
            # Merge and create new entry
            current_extensions.update(acl_metadata_extensions)
            merged_extensions = FlextLdifModelsMetadata.DynamicMetadata.from_dict(
                current_extensions,
            )
            return entry.model_copy(
                update={
                    "metadata": entry.metadata.model_copy(
                        update={"extensions": merged_extensions},
                        deep=True,
                    ),
                },
                deep=True,
            )
        # Entry has no metadata, create it
        entry_metadata = m.Ldif.QuirkMetadata.create_for(
            "oud",
            extensions=FlextLdifModelsMetadata.DynamicMetadata.from_dict(
                acl_metadata_extensions,
            ),
        )
        return entry.model_copy(update={"metadata": entry_metadata}, deep=True)

    def _extract_acl_metadata_from_dynamic(
        self,
        acl_extensions: FlextLdifModelsMetadata.DynamicMetadata,
        acl_metadata_extensions: dict[str, t.MetadataAttributeValue],
    ) -> None:
        """Extract ACL metadata from DynamicMetadata extensions."""
        mk = c.Ldif.MetadataKeys
        # Map source keys to destination MetadataKeys
        key_mapping: dict[str, str] = {
            "extop": mk.ACL_EXTOP,
            "ip": mk.ACL_BIND_IP_FILTER,
            "dns": mk.ACL_BIND_DNS,
            "dayofweek": mk.ACL_BIND_DAYOFWEEK,
            "timeofday": mk.ACL_BIND_TIMEOFDAY,
            "authmethod": "acl:vendor:bind_authmethod",
            "ssf": "acl:vendor:bind_ssf",
            "targetcontrol": "targetcontrol",
            "targetscope": "targetscope",
            "targattrfilters": mk.ACL_TARGETATTR_FILTERS,
        }
        for src_key, dest_key in key_mapping.items():
            value_raw = acl_extensions.get(src_key)
            if value_raw is not None:
                # Type narrowing: ensure value is compatible with MetadataAttributeValue
                if isinstance(value_raw, (str, int, float, bool, type(None))):
                    acl_metadata_extensions[dest_key] = value_raw
                elif isinstance(value_raw, (list, tuple)):
                    value_list: list[t.ScalarValue] = [
                        item
                        if isinstance(item, (str, int, float, bool, type(None)))
                        else str(item)
                        for item in value_raw
                    ]
                    acl_metadata_extensions[dest_key] = value_list
                elif isinstance(value_raw, dict):
                    value_dict: dict[str, t.ScalarValue] = {
                        k: v
                        if isinstance(v, (str, int, float, bool, type(None)))
                        else str(v)
                        for k, v in value_raw.items()
                    }
                    acl_metadata_extensions[dest_key] = value_dict
                else:
                    acl_metadata_extensions[dest_key] = str(value_raw)

    def _extract_acl_metadata_from_dict(
        self,
        acl_extensions: dict[str, t.MetadataAttributeValue],
        acl_metadata_extensions: dict[str, t.MetadataAttributeValue],
    ) -> None:
        """Extract ACL metadata from dict extensions."""
        mk = c.Ldif.MetadataKeys
        key_mapping: dict[str, str] = {
            "extop": mk.ACL_EXTOP,
            "ip": mk.ACL_BIND_IP_FILTER,
            "dns": mk.ACL_BIND_DNS,
            "dayofweek": mk.ACL_BIND_DAYOFWEEK,
            "timeofday": mk.ACL_BIND_TIMEOFDAY,
            "authmethod": "acl:vendor:bind_authmethod",
            "ssf": "acl:vendor:bind_ssf",
            "targetcontrol": "targetcontrol",
            "targetscope": "targetscope",
            "targattrfilters": mk.ACL_TARGETATTR_FILTERS,
        }
        for src_key, dest_key in key_mapping.items():
            value_raw = acl_extensions.get(src_key)
            if value_raw is not None:
                # Type narrowing: ensure value is compatible with MetadataAttributeValue
                # DynamicMetadata.get() returns t.MetadataAttributeValue, but mypy needs help
                if isinstance(value_raw, (str, int, float, bool, type(None))):
                    acl_metadata_extensions[dest_key] = value_raw
                elif isinstance(value_raw, (list, tuple)):
                    value_list: list[t.ScalarValue] = [
                        item
                        if isinstance(item, (str, int, float, bool, type(None)))
                        else str(item)
                        for item in value_raw
                    ]
                    acl_metadata_extensions[dest_key] = value_list
                elif isinstance(value_raw, dict):
                    value_dict: dict[str, t.ScalarValue] = {
                        k: v
                        if isinstance(v, (str, int, float, bool, type(None)))
                        else str(v)
                        for k, v in value_raw.items()
                    }
                    acl_metadata_extensions[dest_key] = value_dict
                else:
                    acl_metadata_extensions[dest_key] = str(value_raw)

    def _process_single_aci_value(
        self,
        aci_value: str,
        acl_metadata_extensions: dict[str, t.MetadataAttributeValue],
    ) -> FlextResult[bool]:
        """Process single ACI value, extract metadata, return has_macros flag."""
        has_macros = bool(re.search(r"\(\$dn\)|\[\$dn\]|\(\$attr\.", aci_value))

        # Validate macro rules
        validation_result = self._validate_aci_macros(aci_value)
        if validation_result.is_failure:
            return FlextResult[bool].fail(
                f"ACI macro validation failed: {validation_result.error}",
            )

        # Parse ACL to extract metadata
        acl_quirk = FlextLdifServersOudAcl()
        parse_result = acl_quirk.parse(aci_value)
        if parse_result.is_success:
            parsed_acl = parse_result.value
            if parsed_acl.metadata and parsed_acl.metadata.extensions:
                acl_extensions = parsed_acl.metadata.extensions
                if isinstance(acl_extensions, FlextLdifModelsMetadata.DynamicMetadata):
                    self._extract_acl_metadata_from_dynamic(
                        acl_extensions,
                        acl_metadata_extensions,
                    )
                elif isinstance(acl_extensions, dict):
                    self._extract_acl_metadata_from_dict(
                        acl_extensions,
                        acl_metadata_extensions,
                    )

        return FlextResult.ok(has_macros)

    def _hook_post_parse_entry(
        self,
        entry: m.Ldif.Entry,
    ) -> FlextResult[m.Ldif.Entry]:
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

        **Constants Used** (from ``FlextLdifServersOudConstants``):

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
            FlextResult[Entry] - validated entry, unchanged if valid

        References:
            - Oracle OUD ACI Macros: https://docs.oracle.com/cd/E22289_01/html/821-1277/aci-syntax.html

        """
        # Extract attributes dict with None check for type safety
        attrs_dict = entry.attributes.attributes if entry.attributes is not None else {}

        # Validate ACI macros if present and extract ACL metadata
        aci_attrs = attrs_dict.get("aci")
        if aci_attrs and isinstance(aci_attrs, (list, tuple)):
            has_macros = False
            acl_metadata_extensions: dict[str, t.MetadataAttributeValue] = {}

            for aci_value in aci_attrs:
                if isinstance(aci_value, str):
                    # Process single ACI using helper method (reduces nesting)
                    process_result = self._process_single_aci_value(
                        aci_value,
                        acl_metadata_extensions,
                    )
                    if process_result.is_failure:
                        return FlextResult[m.Ldif.Entry].fail(
                            process_result.error or "ACI processing failed",
                        )
                    if process_result.value:
                        has_macros = True

            # Log if macros were found (metadata is immutable - just log)
            if has_macros:
                max_len = FlextLdifServersOudConstants.MAX_LOG_LINE_LENGTH
                aci_list = (
                    list(aci_attrs)
                    if isinstance(aci_attrs, (list, tuple))
                    else [str(aci_attrs)]
                )
                logger.debug(
                    "Entry contains OUD ACI macros - preserved for runtime expansion",
                    entry_dn=entry.dn.value if entry.dn else None,
                    aci_count=len(aci_list),
                    aci_preview=[
                        s[:max_len] for s in aci_list[:10] if isinstance(s, str)
                    ],
                )

            # Transfer ACL metadata to entry using helper method
            entry = self._merge_acl_metadata_to_entry(entry, acl_metadata_extensions)

        # Entry is RFC-canonical - return unchanged
        return FlextResult[m.Ldif.Entry].ok(entry)

    def _validate_aci_macros(self, _aci_value: str) -> FlextResult[bool]:
        """Validate OUD ACI macro consistency rules (no-op)."""
        # ACI syntax is validated at parse time
        return FlextResult[bool].ok(True)

    @staticmethod
    def _hook_pre_write_entry_static(
        entry: m.Ldif.Entry,
        validate_aci_macros: Callable[[str], FlextResult[bool]],
        correct_rfc_syntax_in_attributes: Callable[
            [t.Ldif.CommonDict.AttributeDict],
            FlextResult[t.Ldif.CommonDict.AttributeDict],
        ],
    ) -> FlextResult[m.Ldif.Entry]:
        """Hook: Validate and CORRECT RFC syntax issues before writing Entry - static helper.

        This hook ensures that Entry data with RFC-valid syntax is properly
        formatted for OUD LDIF output. It does NOT alter data structure
        (attributes, objectClasses, etc.) - only corrects syntax/formatting.

        Args:
            entry: RFC Entry (already canonical, with aci: attributes)
            validate_aci_macros: Function to validate ACI macros
            correct_rfc_syntax_in_attributes: Function to correct RFC syntax

        Returns:
            FlextResult[Entry] - entry with corrected syntax, fail() if syntax errors

        """
        # INLINED: _extract_attributes_dict (only used once)
        attrs_dict_raw = entry.attributes.attributes if entry.attributes else {}
        attrs_dict: t.Ldif.CommonDict.AttributeDict = dict(
            attrs_dict_raw.items(),
        )
        aci_validation_error = FlextLdifServersOudEntry.validate_aci_macros_in_entry(
            attrs_dict,
            validate_aci_macros,
        )
        if aci_validation_error:
            return FlextResult[m.Ldif.Entry].fail(aci_validation_error)

        return FlextLdifServersOudEntry.correct_syntax_and_return_entry(
            entry,
            attrs_dict,
            correct_rfc_syntax_in_attributes,
        )

    @staticmethod
    def validate_aci_macros_in_entry(
        attrs_dict: t.Ldif.CommonDict.AttributeDict,
        validate_aci_macros: Callable[[str], FlextResult[bool]],
    ) -> str | None:
        """Validate ACI macros if present. Returns error message or None if valid."""
        aci_attrs = attrs_dict.get("aci")
        if aci_attrs and isinstance(aci_attrs, (list, tuple)):
            for aci_value in aci_attrs:
                if isinstance(aci_value, str):
                    validation_result = validate_aci_macros(aci_value)
                    if validation_result.is_failure:
                        return f"ACI macro validation failed: {validation_result.error}"
        return None

    @staticmethod
    def correct_syntax_and_return_entry(
        entry: m.Ldif.Entry,
        attrs_dict: t.Ldif.CommonDict.AttributeDict,
        correct_rfc_syntax_in_attributes: Callable[
            [t.Ldif.CommonDict.AttributeDict],
            FlextResult[t.Ldif.CommonDict.AttributeDict],
        ],
    ) -> FlextResult[m.Ldif.Entry]:
        """Correct RFC syntax issues and return entry."""
        corrected_result = correct_rfc_syntax_in_attributes(attrs_dict)
        if corrected_result.is_failure:
            return FlextResult[m.Ldif.Entry].fail(
                corrected_result.error or "Unknown error",
            )

        corrected_data = corrected_result.value
        # Business Rule: apply_syntax_corrections expects specific types
        # Implication: Convert corrected_data and syntax_corrections to expected formats
        # Type compatibility: corrected_data is AttributeDict (dict[str, list[str]])
        # Use dict() to create a mutable copy with proper type inference
        corrected_data_typed: dict[
            str,
            str | int | float | bool | list[str] | dict[str, str | list[str]] | None,
        ] = dict(corrected_data)
        # Business Rule: apply_syntax_corrections expects list[str] or dict[str, str], not None.
        # Implication: Type narrowing ensures syntax_corrections_typed is not None before calling.
        # Type narrowing: Convert to expected types for apply_syntax_corrections.
        # Business Rule: syntax_corrections_raw may be None, list, dict, or other types.
        # Implication: Explicit type narrowing with isinstance checks ensures type safety.
        # Extract syntax_corrections with explicit type narrowing
        syntax_corrections_raw = corrected_data_typed.get("syntax_corrections")
        syntax_corrections_typed: list[str] | dict[str, str] | None = None
        if isinstance(syntax_corrections_raw, list):
            # Type narrowing: syntax_corrections_raw is list, convert to list[str]
            syntax_corrections_typed = [str(v) for v in syntax_corrections_raw]
        elif isinstance(syntax_corrections_raw, dict):
            # Type narrowing: syntax_corrections_raw is dict, convert to dict[str, str]
            # Business Rule: Use explicit iteration to help type checker understand types.
            # Implication: Type checker may infer Never for dict.items() in some contexts.
            # Additional type narrowing: ensure dict type before iteration
            syntax_corrections_dict: dict[str, str] = {}
            # Business Rule: syntax_corrections_raw is dict[str, ...] from corrected_data_typed.
            # Implication: Values may be str | int | float | bool | list[str] | dict[str, str | list[str]] | None.
            # We convert all values to str for dict[str, str] compatibility.
            if isinstance(syntax_corrections_raw, dict):
                for k, v in syntax_corrections_raw.items():
                    syntax_corrections_dict[str(k)] = str(v) if v is not None else ""
            syntax_corrections_typed = syntax_corrections_dict
        # Business Rule: Only call apply_syntax_corrections if syntax_corrections_typed is not None.
        # Type narrowing: Check for None before calling to ensure type safety.
        if syntax_corrections_typed is not None:
            return FlextLdifServersOudEntry.apply_syntax_corrections(
                entry,
                corrected_data_typed,
                syntax_corrections_typed,
            )

        return FlextResult[m.Ldif.Entry].ok(entry)

    @staticmethod
    def apply_syntax_corrections(
        entry: m.Ldif.Entry,
        corrected_data: dict[
            str,
            str | int | float | bool | list[str] | dict[str, str | list[str]] | None,
        ],
        syntax_corrections: list[str] | dict[str, str] | None,
    ) -> FlextResult[m.Ldif.Entry]:
        """Apply syntax corrections to entry."""
        corrected_attrs_raw = corrected_data.get("corrected_attributes")
        # Type narrowing: corrected_attrs should be dict[str, str | list[str]] | None
        if not isinstance(corrected_attrs_raw, dict):
            return FlextResult[m.Ldif.Entry].ok(entry)

        attrs_for_model: dict[str, list[str]] = {}
        for raw_key, raw_value in corrected_attrs_raw.items():
            # Type narrowing: ensure key is string
            if not isinstance(raw_key, str):
                continue
            # Type narrowing: handle different value types
            if isinstance(raw_value, list):
                attrs_for_model[raw_key] = [str(item) for item in raw_value]
            elif isinstance(raw_value, str):
                attrs_for_model[raw_key] = [raw_value]
            elif isinstance(raw_value, tuple):
                attrs_for_model[raw_key] = [str(item) for item in raw_value]

        corrected_ldif_attrs = m.Ldif.Attributes(
            attributes=attrs_for_model,
        )
        corrected_entry = entry.model_copy(
            update={"attributes": corrected_ldif_attrs},
        )

        logger.debug(
            "OUD quirks: Applied syntax corrections before writing (structure preserved)",
            entry_dn=entry.dn.value if entry.dn else None,
            corrections_count=len(syntax_corrections)
            if isinstance(syntax_corrections, (list, tuple))
            else 0,
            corrections=syntax_corrections,
            corrected_attributes=list(attrs_for_model.keys()),
        )
        return FlextResult[m.Ldif.Entry].ok(corrected_entry)

    def _hook_finalize_entry_parse(
        self,
        entry: m.Ldif.Entry,
        original_dn: str,
        original_attrs: t.Ldif.CommonDict.AttributeDictGeneric,
    ) -> FlextResult[m.Ldif.Entry]:
        """Hook: Process ACLs and propagate their extensions to entry metadata.

        This hook processes ACL attributes (aci) in the entry and extracts
        their metadata extensions (like targattrfilters, targetcontrol, etc.)
        and propagates them to the entry's metadata.extensions.

        Args:
            entry: Parsed entry from RFC with all hooks applied
            original_dn: Original DN before transformation
            original_attrs: Original attributes for ACL processing

        Returns:
            FlextResult with entry containing ACL metadata extensions

        """
        _ = original_dn  # Used for logging if needed

        # Use helper to find ACI values
        aci_values = self._find_aci_values(entry, original_attrs)
        if not aci_values:
            return FlextResult.ok(entry)

        # Ensure metadata exists
        if not entry.metadata:
            entry.metadata = m.Ldif.QuirkMetadata.create_for(
                "oud",
                extensions=FlextLdifModelsMetadata.DynamicMetadata(),
            )

        # Get current extensions
        current_extensions: dict[str, t.MetadataAttributeValue] = (
            dict(entry.metadata.extensions) if entry.metadata.extensions else {}
        )

        # Get ACL quirk from parent server (uses helper from base class)
        parent = self._get_parent_quirk_safe()
        if parent is None:
            return FlextResult.ok(entry)

        # Access ACL quirk via parent's _acl_quirk attribute
        acl_quirk_raw = getattr(parent, "_acl_quirk", None)
        if not acl_quirk_raw:
            return FlextResult.ok(entry)

        # Type narrow for proper type checking
        if not isinstance(acl_quirk_raw, FlextLdifServersOudAcl):
            return FlextResult.ok(entry)
        acl_quirk: FlextLdifServersOudAcl = acl_quirk_raw

        # Process ACLs using helper method
        self._process_aci_list_for_finalize(aci_values, acl_quirk, current_extensions)

        # Update entry metadata with ACL extensions
        # Always merge extensions if we have any ACL extensions to add
        # Check if we actually added new ACL extensions (not just existing ones)
        if current_extensions:
            # Merge with existing extensions if metadata exists
            existing_extensions = (
                dict(entry.metadata.extensions)
                if entry.metadata and entry.metadata.extensions
                else {}
            )
            # Merge current_extensions into existing_extensions (current takes precedence)
            merged_extensions = {**existing_extensions, **current_extensions}
            # Always update metadata if we have extensions (even if they're the same)
            entry.metadata = entry.metadata.model_copy(
                update={
                    "extensions": FlextLdifModelsMetadata.DynamicMetadata.from_dict(
                        merged_extensions,
                    ),
                },
            )

        return FlextResult.ok(entry)

    def _hook_pre_write_entry(
        self,
        entry: m.Ldif.Entry,
    ) -> FlextResult[m.Ldif.Entry]:
        """Hook: Pre-write entry validation (simplified).

        Entry is returned unchanged (RFC-valid format preserved).

        Args:
            entry: RFC Entry (already canonical)

        Returns:
            FlextResult[Entry] - entry unchanged

        """
        # Entry is RFC-canonical and already validated
        return FlextResult[m.Ldif.Entry].ok(entry)

    def _finalize_and_parse_entry(
        self,
        entry_dict: dict[str, t.GeneralValueType],
        entries_list: list[m.Ldif.Entry],
    ) -> None:
        """Finalize entry dict and parse into entries list.

        Args:
            entry_dict: Entry dictionary with DN and attributes
            entries_list: Target list to append parsed Entry models

        """
        if "dn" not in entry_dict:
            return

        dn = str(entry_dict.pop("dn"))
        original_entry_dict = dict(entry_dict)

        # Convert entry_dict to proper type for parse_entry (str only, decode bytes)
        entry_attrs: dict[str, list[str]] = {}
        for k, v in entry_dict.items():
            if isinstance(v, list):
                entry_attrs[str(k)] = [
                    item.decode("utf-8") if isinstance(item, bytes) else str(item)
                    for item in v
                ]
            elif isinstance(v, bytes):
                entry_attrs[str(k)] = [v.decode("utf-8")]
            elif isinstance(v, str):
                entry_attrs[str(k)] = [v]
            else:
                entry_attrs[str(k)] = [str(v)]

        result = self.parse_entry(dn, entry_attrs)
        if result.is_success:
            entry = result.value
            original_dn = dn
            parsed_dn = entry.dn.value if entry.dn else None
            parsed_attrs = entry.attributes.attributes if entry.attributes else {}

            # CONSOLIDATED: Use utilities for difference analysis and storage (DRY)
            # Type annotation uses str | bytes to match analyze_differences signature
            converted_attrs: dict[str, list[str | bytes]] = {
                k: list(v) if isinstance(v, list) else [str(v)]
                for k, v in parsed_attrs.items()
            }
            dn_differences, attribute_differences, original_attrs_complete, _ = (
                u.Ldif.Entry.analyze_differences(
                    entry_attrs=original_entry_dict,
                    converted_attrs=converted_attrs,
                    original_dn=original_dn,
                    cleaned_dn=parsed_dn or original_dn,
                )
            )

            # Ensure metadata exists
            if not entry.metadata:
                entry.metadata = m.Ldif.QuirkMetadata.create_for(
                    "oud",
                    extensions=FlextLdifModelsMetadata.DynamicMetadata(),
                )

            # CONSOLIDATED: Store via utility (DRY)
            # Business Rule: store_minimal_differences expects ScalarValue for _extra
            # Implication: Convert complex dicts to JSON strings for storage
            FlextLdifUtilitiesMetadata.store_minimal_differences(
                metadata=entry.metadata,
                dn_differences=json.dumps(dn_differences),
                attribute_differences=json.dumps(attribute_differences),
                original_dn=original_dn or "",
                parsed_dn=parsed_dn or "",
                original_attributes_complete=json.dumps(original_attrs_complete),
            )

            logger.debug(
                "OUD entry parsed with minimal differences",
                entry_dn=original_dn[:50] if original_dn else None,
            )

            entries_list.append(entry)

    def _determine_attribute_order(
        self,
        attr_names: list[str],
        format_options: m.Ldif.WriteFormatOptions | None,
    ) -> list[str]:
        """Determine attribute order based on format options.

        Args:
            attr_names: List of attribute names to order
            format_options: Write format options with sort_attributes flag (may be None)

        Returns:
            Ordered list of attribute names (sorted or original order)

        """
        if format_options and format_options.sort_attributes:
            return sorted(attr_names, key=str.lower)
        return attr_names

    def _add_attribute_transformation_comments(
        self,
        comment_lines: list[str],
        attr_name: str,
        _transformation: FlextLdifModelsDomains.AttributeTransformation,
        comment_type: str,
    ) -> None:
        """Add comment for attribute transformation.

        Args:
            comment_lines: List to append comments to
            attr_name: Name of transformed attribute
            _transformation: Transformation metadata (reserved for future use)
            comment_type: Type of transformation (MODIFIED, TRANSFORMED, etc.)

        """
        comment_lines.append(
            f"# [{comment_type}] {attr_name}: transformation applied",
        )

    def _add_rejection_reason_comments(
        self,
        comment_lines: list[str],
        entry: m.Ldif.Entry,
    ) -> None:
        """Add comments with rejection reason if entry was rejected.

        Args:
            comment_lines: List to append comments to
            entry: Entry model with potential rejection metadata

        """
        if (
            entry.metadata
            and entry.metadata.extensions
            and isinstance(entry.metadata.extensions, dict)
        ):
            rejection_reason = entry.metadata.extensions.get("rejection_reason")
            if rejection_reason:
                comment_lines.append(f"# [REJECTION] {rejection_reason}")
