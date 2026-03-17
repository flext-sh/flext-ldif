"""Oracle Unified Directory (OUD) Quirks.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Provides OUD-specific quirks for schema, ACL, and entry processing.
"""

from __future__ import annotations

import builtins
import re
from collections.abc import Callable, Mapping
from typing import override

from flext_core import FlextLogger, r, u as core_u

from flext_ldif import c, m, p, t, u
from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif._models.metadata import FlextLdifModelsMetadata
from flext_ldif._utilities.metadata import FlextLdifUtilitiesMetadata
from flext_ldif.servers._base.entry import FlextLdifServersBaseEntry
from flext_ldif.servers._oud.acl import FlextLdifServersOudAcl
from flext_ldif.servers._oud.constants import FlextLdifServersOudConstants
from flext_ldif.servers.base import FlextLdifServersBase
from flext_ldif.servers.rfc import FlextLdifServersRfc

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
        entry_service: p.Ldif.EntryQuirk | None = None,
        _parent_quirk: FlextLdifServersBase | None = None,
        **kwargs: str | float | bool | None,
    ) -> None:
        """Initialize OUD entry quirk.

        Args:
            entry_service: Injected entry service (optional, must satisfy HasParseMethod)
            _parent_quirk: Reference to parent FlextLdifServersBase (optional)
            **kwargs: Additional arguments passed to parent

        """
        {
            k: v
            for k, v in kwargs.items()
            if k != "_parent_quirk"
            and core_u.is_type(v, (str, float, bool, type(None)))
        }
        entry_service_typed: p.Ldif.EntryQuirk | None = (
            entry_service if entry_service is not None else None
        )
        FlextLdifServersBaseEntry.__init__(
            self, entry_service_typed, _parent_quirk=None
        )
        if _parent_quirk is not None:
            object.__setattr__(self, "_parent_quirk", _parent_quirk)

    @staticmethod
    def _comment_acl_attributes(
        entry_data: m.Ldif.Entry, acl_attribute_names: list[str]
    ) -> m.Ldif.Entry:
        """Comment out ACL attributes by removing them from attributes dict and storing in metadata.

        CRITICAL for flext-oud-mig phase-aware ACL handling.
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
        existing_metadata = entry_data.metadata
        if not existing_metadata:
            existing_metadata = m.Ldif.QuirkMetadata.create_for("oud")
        else:
            existing_metadata = m.Ldif.QuirkMetadata.model_validate(
                existing_metadata.model_dump()
            )
        new_attributes_dict, commented_acl_values, hidden_attrs = (
            FlextLdifServersOudEntry.extract_and_remove_acl_attributes(
                entry_data.attributes.attributes, acl_attribute_names
            )
        )
        updated_metadata = FlextLdifServersOudEntry.update_metadata_with_commented_acls(
            existing_metadata,
            acl_attribute_names,
            commented_acl_values,
            hidden_attrs,
            entry_data.attributes.attributes,
        )
        return entry_data.model_copy(
            update={
                "attributes": m.Ldif.Attributes(
                    attributes=dict(new_attributes_dict),
                    attribute_metadata=entry_data.attributes.attribute_metadata,
                    metadata=entry_data.attributes.metadata,
                ),
                "metadata": updated_metadata,
            }
        )

    @staticmethod
    def _create_write_options_with_hidden_attrs(
        write_opts: FlextLdifModelsDomains.WriteOptions
        | Mapping[str, builtins.object]
        | None,
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
        hidden_attrs_raw = getattr(write_opts, "hidden_attrs", [])
        hidden_attrs_set: set[str] = set()
        if core_u.is_type(hidden_attrs_raw, (list, tuple, frozenset, set)):
            hidden_attrs_set = {str(item) for item in hidden_attrs_raw}
        hidden_attrs_set.update(hidden_attrs)
        if isinstance(write_opts, FlextLdifModelsDomains.WriteOptions):
            write_opts_data: dict[str, builtins.object] = write_opts.model_dump()
            write_opts_data["hidden_attrs"] = list(hidden_attrs_set)
            return m.Ldif.WriteOptions.model_validate(write_opts_data)
        write_opts_dict: dict[str, builtins.object] = {
            "hidden_attrs": list(hidden_attrs_set)
        }
        format_value = write_opts.get("format")
        if isinstance(format_value, str):
            write_opts_dict["format"] = format_value
        base_dn_value = write_opts.get("base_dn")
        if isinstance(base_dn_value, str):
            write_opts_dict["base_dn"] = base_dn_value
        sort_entries_value = write_opts.get("sort_entries")
        if isinstance(sort_entries_value, bool):
            write_opts_dict["sort_entries"] = sort_entries_value
        else:
            sort_attributes_value = write_opts.get("sort_attributes")
            if isinstance(sort_attributes_value, bool):
                write_opts_dict["sort_entries"] = sort_attributes_value
        include_comments_value = write_opts.get("include_comments")
        if isinstance(include_comments_value, bool):
            write_opts_dict["include_comments"] = include_comments_value
        else:
            write_metadata_as_comments = write_opts.get("write_metadata_as_comments")
            if isinstance(write_metadata_as_comments, bool):
                write_opts_dict["include_comments"] = write_metadata_as_comments
        base64_encode_binary_value = write_opts.get("base64_encode_binary")
        if isinstance(base64_encode_binary_value, bool):
            write_opts_dict["base64_encode_binary"] = base64_encode_binary_value
        return m.Ldif.WriteOptions.model_validate(write_opts_dict)

    @staticmethod
    def _hook_pre_write_entry_static(
        entry: m.Ldif.Entry,
        validate_aci_macros: Callable[[str], r[bool]],
        correct_rfc_syntax_in_attributes: Callable[
            [t.Ldif.CommonDict.AttributeDict],
            r[t.Ldif.CommonDict.AttributeDict],
        ],
    ) -> r[m.Ldif.Entry]:
        """Hook: Validate and CORRECT RFC syntax issues before writing Entry - static helper.

        This hook ensures that Entry data with RFC-valid syntax is properly
        formatted for OUD LDIF output. It does NOT alter data structure
        (attributes, objectClasses, etc.) - only corrects syntax/formatting.

        Args:
            entry: RFC Entry (already canonical, with aci: attributes)
            validate_aci_macros: Function to validate ACI macros
            correct_rfc_syntax_in_attributes: Function to correct RFC syntax

        Returns:
            r[Entry] - entry with corrected syntax, fail() if syntax errors

        """
        attrs_dict_raw = entry.attributes.attributes if entry.attributes else {}
        attrs_dict: t.Ldif.CommonDict.AttributeDict = dict(attrs_dict_raw.items())
        aci_validation_error = FlextLdifServersOudEntry.validate_aci_macros_in_entry(
            attrs_dict, validate_aci_macros
        )
        if aci_validation_error:
            return r[m.Ldif.Entry].fail(aci_validation_error)
        return FlextLdifServersOudEntry.correct_syntax_and_return_entry(
            entry, attrs_dict, correct_rfc_syntax_in_attributes
        )

    @staticmethod
    def _normalize_acl_values(
        acl_values_raw: builtins.object,
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
        commented_raw: builtins.object,
    ) -> dict[str, builtins.object] | None:
        """Parse commented ACL values from raw storage format.

        Args:
            commented_raw: Raw value from extensions (JSON string or dict)

        Returns:
            Parsed dict or None if unparseable

        """
        parsed: builtins.object
        if isinstance(commented_raw, str):
            parsed = m.Ldif.DynamicMetadata.model_validate_json(commented_raw)
        else:
            parsed = commented_raw
        if not isinstance(parsed, Mapping):
            return None
        normalized: dict[str, builtins.object] = {}
        for raw_key, raw_value in parsed.items():
            normalized[raw_key] = (
                FlextLdifModelsMetadata.DynamicMetadata.coerce_metadata_value(raw_value)
            )
        return normalized

    @staticmethod
    def apply_syntax_corrections(
        entry: m.Ldif.Entry,
        corrected_data: Mapping[
            str, t.Scalar | list[str] | Mapping[str, str | list[str]] | None
        ],
        syntax_corrections: list[str] | Mapping[str, str] | None,
    ) -> r[m.Ldif.Entry]:
        """Apply syntax corrections to entry."""
        corrected_attrs_raw = corrected_data.get("corrected_attributes")
        if not isinstance(corrected_attrs_raw, Mapping):
            return r[m.Ldif.Entry].ok(entry)
        attrs_for_model: dict[str, list[str]] = {}
        for raw_key, raw_value in corrected_attrs_raw.items():
            if isinstance(raw_value, list):
                attrs_for_model[raw_key] = [str(item) for item in raw_value]
            else:
                attrs_for_model[raw_key] = [str(raw_value)]
        corrected_ldif_attrs = m.Ldif.Attributes(attributes=attrs_for_model)
        corrected_entry = entry.model_copy(update={"attributes": corrected_ldif_attrs})
        logger.debug(
            "OUD quirks: Applied syntax corrections before writing (structure preserved)",
            entry_dn=entry.dn.value if entry.dn else "",
            corrections_count=len(syntax_corrections) if syntax_corrections else 0,
        )
        return r[m.Ldif.Entry].ok(corrected_entry)

    @staticmethod
    def correct_syntax_and_return_entry(
        entry: m.Ldif.Entry,
        attrs_dict: t.Ldif.CommonDict.AttributeDict,
        correct_rfc_syntax_in_attributes: Callable[
            [t.Ldif.CommonDict.AttributeDict],
            r[t.Ldif.CommonDict.AttributeDict],
        ],
    ) -> r[m.Ldif.Entry]:
        """Correct RFC syntax issues and return entry."""
        corrected_result = correct_rfc_syntax_in_attributes(attrs_dict)
        if corrected_result.is_failure:
            return r[m.Ldif.Entry].fail(corrected_result.error or "Unknown error")
        corrected_data = corrected_result.value
        corrected_data_typed: dict[
            str, t.Scalar | list[str] | dict[str, str | list[str]] | None
        ] = dict(corrected_data)
        syntax_corrections_raw = corrected_data_typed.get("syntax_corrections")
        syntax_corrections_typed: list[str] | dict[str, str] | None = None
        if isinstance(syntax_corrections_raw, list):
            syntax_corrections_typed = [str(v) for v in syntax_corrections_raw]
        elif isinstance(syntax_corrections_raw, Mapping):
            syntax_corrections_dict: dict[str, str] = {}
            for k, v in syntax_corrections_raw.items():
                syntax_corrections_dict[str(k)] = str(v)
            syntax_corrections_typed = syntax_corrections_dict
        if syntax_corrections_typed is not None:
            return FlextLdifServersOudEntry.apply_syntax_corrections(
                entry, corrected_data_typed, syntax_corrections_typed
            )
        return r[m.Ldif.Entry].ok(entry)

    @staticmethod
    def extract_and_remove_acl_attributes(
        attributes_dict: Mapping[str, list[str]], acl_attribute_names: list[str]
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
        hidden_attrs: set[str] = set()
        for acl_attr in acl_attribute_names:
            if acl_attr in new_attrs:
                acl_values = new_attrs[acl_attr]
                if core_u.is_type(acl_values, list):
                    commented_vals[acl_attr] = list(acl_values)
                else:
                    commented_vals[acl_attr] = [str(acl_values)]
                del new_attrs[acl_attr]
                hidden_attrs.add(acl_attr.lower())
        return (new_attrs, commented_vals, hidden_attrs)

    @staticmethod
    def update_metadata_with_commented_acls(
        metadata: m.Ldif.QuirkMetadata,
        acl_attribute_names: list[str],
        commented_acl_values: Mapping[str, list[str]],
        hidden_attrs: set[str],
        entry_attributes_dict: Mapping[str, list[str]],
    ) -> m.Ldif.QuirkMetadata:
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
        metadata_typed: m.Ldif.QuirkMetadata = metadata
        current_extensions: dict[str, builtins.object] = (
            dict(metadata_typed.extensions) if metadata_typed.extensions else {}
        )
        new_write_options = (
            FlextLdifServersOudEntry._create_write_options_with_hidden_attrs(
                metadata_typed.write_options, hidden_attrs
            )
        )
        update_dict: dict[str, builtins.object] = {"write_options": new_write_options}
        metadata_typed = metadata_typed.model_copy(update=update_dict)
        if commented_acl_values:
            converted_attrs_list: list[str] = list(commented_acl_values.keys())
            converted_attrs_typed: builtins.object = list(converted_attrs_list)
            current_extensions["converted_attributes"] = converted_attrs_typed
            current_extensions["commented_attribute_values"] = (
                m.Ldif.DynamicMetadata.from_dict(commented_acl_values).model_dump_json()
            )
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
            commented_attrs_typed: builtins.object = list(commented_attrs)
            current_extensions["acl_commented_attributes"] = commented_attrs_typed
        update_dict_final: dict[str, builtins.object] = {
            "extensions": current_extensions,
            "write_options": new_write_options,
        }
        return metadata_typed.model_copy(update=update_dict_final)

    @staticmethod
    def validate_aci_macros_in_entry(
        attrs_dict: t.Ldif.CommonDict.AttributeDict,
        validate_aci_macros: Callable[[str], r[bool]],
    ) -> str | None:
        """Validate ACI macros if present. Returns error message or None if valid."""
        aci_attrs = attrs_dict.get("aci")
        if aci_attrs and core_u.is_type(aci_attrs, (list, tuple)):
            for aci_value in aci_attrs:
                if core_u.is_type(aci_value, str):
                    validation_result = validate_aci_macros(aci_value)
                    if validation_result.is_failure:
                        return f"ACI macro validation failed: {validation_result.error}"
        return None

    @override
    def can_handle(self, entry_dn: str, attributes: Mapping[str, list[str]]) -> bool:
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

        - ``u.Ldif.matches_server_patterns()`` - Pattern matching

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
        patterns_config = m.Ldif.ServerPatternsConfig(
            dn_patterns=oud_constants.DN_DETECTION_PATTERNS,
            attr_prefixes=oud_constants.DETECTION_ATTRIBUTE_PREFIXES,
            attr_names=oud_constants.BOOLEAN_ATTRIBUTES,
            keyword_patterns=oud_constants.KEYWORD_PATTERNS,
        )
        return (
            u.Ldif.matches_server_patterns(entry_dn, attributes, patterns_config)
            or "objectclass" in attributes
        )

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
        if not format_options:
            return ""
        comment_lines: list[str] = []
        if format_options.write_transformation_comments:
            self._add_transformation_comments(comment_lines, entry, format_options)
        if format_options.write_rejection_reasons:
            self._add_rejection_reason_comments(comment_lines, entry)
        return "\n".join(comment_lines) + "\n" if comment_lines else ""

    @override
    def parse(self, ldif_content: str) -> r[list[m.Ldif.Entry]]:
        """Parse LDIF content and apply OUD post-processing hooks."""
        parsed_result = super().parse(ldif_content)
        if parsed_result.is_failure:
            return parsed_result
        processed_entries: list[m.Ldif.Entry] = []
        for parsed_entry in parsed_result.value:
            post_parse_result = self._hook_post_parse_entry(parsed_entry)
            if post_parse_result.is_failure:
                return r[list[m.Ldif.Entry]].fail(
                    post_parse_result.error or "OUD post-parse failed"
                )
            entry_after_post: m.Ldif.Entry = post_parse_result.value
            original_dn = entry_after_post.dn.value if entry_after_post.dn else ""
            original_attrs = (
                entry_after_post.attributes.attributes
                if entry_after_post.attributes
                and entry_after_post.attributes.attributes
                else {}
            )
            finalize_result = self._hook_finalize_entry_parse(
                entry_after_post, original_dn, original_attrs
            )
            if finalize_result.is_failure:
                return r[list[m.Ldif.Entry]].fail(
                    finalize_result.error or "OUD finalize parse failed"
                )
            processed_entries.append(finalize_result.value)
        return r[list[m.Ldif.Entry]].ok(processed_entries)

    @override
    def parse_entry(
        self, entry_dn: str, entry_attrs: Mapping[str, list[str]] | m.Ldif.Entry
    ) -> r[m.Ldif.Entry]:
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
            r[Entry] with OUD-specific metadata populated

        References:
            - Oracle OUD LDIF Format: https://docs.oracle.com/cd/E22289_01/html/821-1273/understanding-ldif-files.html

        """
        entry_attrs_dict: dict[str, list[str]] = {}
        if isinstance(entry_attrs, Mapping):
            for key, values in entry_attrs.items():
                entry_attrs_dict[str(key)] = [str(v) for v in values]
        elif entry_attrs.attributes and entry_attrs.attributes.attributes:
            entry_attrs_dict = {
                k: [str(v) for v in vs]
                for k, vs in entry_attrs.attributes.attributes.items()
            }
        result = super().parse_entry(entry_dn, entry_attrs_dict)
        if result.is_failure:
            return result
        entry = result.value
        original_attribute_case: dict[str, str] = {}
        if isinstance(entry_attrs, Mapping):
            for attr_name in entry_attrs:
                original_attribute_case[attr_name.lower()] = attr_name
        metadata_config = m.Ldif.EntryParseMetadataConfig(
            quirk_type="oud",
            original_entry_dn=entry_dn,
            cleaned_dn=entry.dn.value if entry.dn else entry_dn,
            original_dn_line=f"dn: {entry_dn}",
            original_attr_lines=[],
            dn_was_base64=False,
            original_attribute_case=original_attribute_case,
        )
        metadata = FlextLdifUtilitiesMetadata.build_entry_parse_metadata(
            metadata_config
        )
        entry.metadata = metadata
        return r[m.Ldif.Entry].ok(entry)

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
        comment_lines.append(f"# [{comment_type}] {attr_name}: transformation applied")

    def _add_original_entry_comments(
        self, entry_data: m.Ldif.Entry, write_options: m.Ldif.WriteFormatOptions | None
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
        if not (entry_data.metadata and entry_data.metadata.write_options):
            return []
        write_opts = entry_data.metadata.write_options
        write_opts_data = write_opts.model_dump(exclude_none=True)
        original_entry_raw = write_opts_data.get("original_entry")
        original_entry_obj: m.Ldif.Entry | None = None
        if isinstance(original_entry_raw, Mapping):
            original_entry_obj = m.Ldif.Entry.model_validate(original_entry_raw)
        if original_entry_obj is None:
            return []
        ldif_parts: list[str] = []
        ldif_parts.extend([
            "# " + "=" * 70,
            "# ORIGINAL Entry (alternative format) (commented)",
            "# " + "=" * 70,
        ])
        original_result = self._write_entry_as_comment(original_entry_obj)
        if original_result.is_success:
            ldif_parts.append(original_result.value)
        ldif_parts.extend([
            "",
            "# " + "=" * 70,
            "# CONVERTED OUD Entry (active)",
            "# " + "=" * 70,
        ])
        return ldif_parts

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
            entry, acl_comments_dict, acl_attr_names_to_skip
        )
        self._collect_acl_from_extensions(
            entry, acl_comments_dict, acl_attr_names_to_skip
        )
        if acl_comments_dict:
            acl_attr_names = list(acl_comments_dict.keys())
            ordered_acl_attrs = self._determine_attribute_order(
                acl_attr_names, format_options
            )
            for attr_name in ordered_acl_attrs:
                if attr_name in acl_comments_dict:
                    comment_lines.extend(acl_comments_dict[attr_name])
        return acl_attr_names_to_skip

    def _add_rejection_reason_comments(
        self, comment_lines: list[str], entry: m.Ldif.Entry
    ) -> None:
        """Add comments with rejection reason if entry was rejected.

        Args:
            comment_lines: List to append comments to
            entry: Entry model with potential rejection metadata

        """
        if (
            entry.metadata
            and entry.metadata.extensions
            and core_u.is_type(entry.metadata.extensions, dict)
        ):
            rejection_reason = entry.metadata.extensions.get("rejection_reason")
            if rejection_reason:
                comment_lines.append(f"# [REJECTION] {rejection_reason}")

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
        acl_attr_names_to_skip = self._add_oud_acl_comments(
            comment_lines, entry, format_options
        )
        processed_attrs: set[str] = set()
        if entry.metadata.attribute_transformations:
            attr_names = [
                attr_name
                for attr_name in entry.metadata.attribute_transformations
                if attr_name.lower() not in acl_attr_names_to_skip
            ]
            ordered_attr_names = self._determine_attribute_order(
                attr_names, format_options
            )
            for attr_name in ordered_attr_names:
                transformation = entry.metadata.attribute_transformations[attr_name]
                transformation_type = transformation.transformation_type.upper()
                comment_type = (
                    "TRANSFORMED"
                    if transformation_type in {"MODIFIED", "TRANSFORMED"}
                    else transformation_type
                )
                self._add_attribute_transformation_comments(
                    comment_lines, attr_name, transformation, comment_type
                )
                processed_attrs.add(attr_name.lower())
        if (
            format_options
            and format_options.write_removed_attributes_as_comments
            and entry.metadata.removed_attributes
        ):
            removed_attrs_dict = entry.metadata.removed_attributes.to_dict()
            removed_attr_names: list[str] = [
                str(attr_name)
                for attr_name in removed_attrs_dict
                if core_u.is_type(attr_name, str)
                and attr_name.lower() not in acl_attr_names_to_skip
            ]
            ordered_removed_attrs = self._determine_attribute_order(
                removed_attr_names, format_options
            )
            for attr_name in ordered_removed_attrs:
                if attr_name.lower() in processed_attrs:
                    continue
                removed_values = entry.metadata.removed_attributes[attr_name]
                if isinstance(removed_values, list):
                    comment_lines.extend(
                        f"# [REMOVED] {attr_name}: {value}" for value in removed_values
                    )
                else:
                    comment_lines.append(f"# [REMOVED] {attr_name}: {removed_values}")
        if comment_lines:
            comment_lines.append("")

    def _apply_phase_aware_acl_handling(
        self, entry_data: m.Ldif.Entry, write_options: m.Ldif.WriteFormatOptions | None
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
        acl_attrs_list = list(acl_attrs)
        return self._comment_acl_attributes(entry_data, acl_attrs_list)

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
            "commented_attribute_values"
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

    def _determine_attribute_order(
        self, attr_names: list[str], format_options: m.Ldif.WriteFormatOptions | None
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

    def _extract_acl_metadata(
        self, entry_data: m.Ldif.Entry
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
            base_dn_value = getattr(entry_data.metadata.write_options, "base_dn", None)
            if isinstance(base_dn_value, str):
                base_dn = base_dn_value
            dn_registry_value = getattr(
                entry_data.metadata.write_options, "dn_registry", None
            )
            if isinstance(dn_registry_value, m.Ldif.DnRegistry):
                dn_registry = dn_registry_value
        if base_dn is None and entry_data.metadata and entry_data.metadata.extensions:
            extensions = entry_data.metadata.extensions
            base_dn_ext = extensions.get("base_dn")
            if isinstance(base_dn_ext, str):
                base_dn = base_dn_ext
            dn_registry_ext = extensions.get("dn_registry")
            if isinstance(dn_registry_ext, m.Ldif.DnRegistry):
                dn_registry = dn_registry_ext
        return (base_dn, dn_registry)

    def _extract_acl_metadata_from_dict(
        self,
        acl_extensions: Mapping[str, builtins.object],
        acl_metadata_extensions: dict[str, builtins.object],
    ) -> None:
        """Extract ACL metadata from dict extensions."""
        mk = c.Ldif.MetadataKeys
        key_mapping: dict[str, str] = {
            "extop": mk.ACL_EXTOP,
            "ip": mk.ACL_BIND_IP_FILTER,
            "bind_ip": mk.ACL_BIND_IP_FILTER,
            "dns": mk.ACL_BIND_DNS,
            "bind_dns": mk.ACL_BIND_DNS,
            "dayofweek": mk.ACL_BIND_DAYOFWEEK,
            "bind_dayofweek": mk.ACL_BIND_DAYOFWEEK,
            "timeofday": mk.ACL_BIND_TIMEOFDAY,
            "bind_timeofday": mk.ACL_BIND_TIMEOFDAY,
            "authmethod": mk.ACL_AUTHMETHOD,
            "ssf": mk.ACL_SSF,
            "targetcontrol": "targetcontrol",
            "targetscope": "targetscope",
            "targattrfilters": mk.ACL_TARGETATTR_FILTERS,
        }
        for src_key, dest_key in key_mapping.items():
            value_raw = acl_extensions.get(src_key)
            if value_raw is not None:
                if value_raw is None or u.is_primitive(value_raw):
                    acl_metadata_extensions[dest_key] = value_raw
                elif isinstance(value_raw, (list, tuple)):
                    value_list: list[t.Ldif.Scalar] = [
                        item if item is None or u.is_primitive(item) else str(item)
                        for item in value_raw
                    ]
                    acl_metadata_extensions[dest_key] = value_list
                elif isinstance(value_raw, Mapping):
                    value_dict_2: dict[str, t.Scalar] = {}
                    for k, v in value_raw.items():
                        key = str(k)
                        value_dict_2[key] = v if u.is_primitive(v) else str(v)
                    acl_metadata_extensions[dest_key] = dict(value_dict_2)
                else:
                    acl_metadata_extensions[dest_key] = str(value_raw)

    def _extract_acl_metadata_from_dynamic(
        self,
        acl_extensions: FlextLdifModelsMetadata.DynamicMetadata,
        acl_metadata_extensions: dict[str, builtins.object],
    ) -> None:
        """Extract ACL metadata from DynamicMetadata extensions."""
        mk = c.Ldif.MetadataKeys
        key_mapping: dict[str, str] = {
            "extop": mk.ACL_EXTOP,
            "ip": mk.ACL_BIND_IP_FILTER,
            "bind_ip": mk.ACL_BIND_IP_FILTER,
            "dns": mk.ACL_BIND_DNS,
            "bind_dns": mk.ACL_BIND_DNS,
            "dayofweek": mk.ACL_BIND_DAYOFWEEK,
            "bind_dayofweek": mk.ACL_BIND_DAYOFWEEK,
            "timeofday": mk.ACL_BIND_TIMEOFDAY,
            "bind_timeofday": mk.ACL_BIND_TIMEOFDAY,
            "authmethod": mk.ACL_AUTHMETHOD,
            "ssf": mk.ACL_SSF,
            "targetcontrol": "targetcontrol",
            "targetscope": "targetscope",
            "targattrfilters": mk.ACL_TARGETATTR_FILTERS,
        }
        for src_key, dest_key in key_mapping.items():
            value_raw = acl_extensions.get(src_key)
            if value_raw is None:
                continue
            if u.is_primitive(value_raw):
                scalar_value: t.Scalar = value_raw
                acl_metadata_extensions[dest_key] = scalar_value
            elif isinstance(value_raw, (list, tuple)):
                value_list: list[t.Ldif.Scalar] = [
                    item if item is None or u.is_primitive(item) else str(item)
                    for item in value_raw
                ]
                acl_metadata_extensions[dest_key] = value_list
            elif isinstance(value_raw, Mapping):
                value_dict_1: dict[str, t.Scalar] = {}
                for k, v in value_raw.items():
                    key = str(k)
                    if u.is_primitive(v):
                        value_dict_1[key] = v
                    else:
                        value_dict_1[key] = str(v)
                value_dict_typed_1: builtins.object = dict(value_dict_1)
                acl_metadata_extensions[dest_key] = value_dict_typed_1
            else:
                acl_metadata_extensions[dest_key] = str(value_raw)

    def _finalize_and_parse_entry(
        self, entry_dict: dict[str, builtins.object], entries_list: list[m.Ldif.Entry]
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
        entry_attrs: dict[str, list[str]] = {}
        for k, v in entry_dict.items():
            if isinstance(v, list):
                values: list[str] = []
                for item in v:
                    if isinstance(item, bytes):
                        values.append(item.decode("utf-8"))
                    else:
                        values.append(str(item))
                entry_attrs[str(k)] = values
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
            parsed_attrs: dict[str, list[str]] = (
                dict(entry.attributes.attributes) if entry.attributes else {}
            )
            converted_attrs: dict[str, list[str | bytes]] = {
                k: list(v) for k, v in parsed_attrs.items()
            }
            entry_attrs_for_diff: dict[
                str, t.Scalar | list[str] | Mapping[str, str] | None
            ] = {}
            for raw_key, raw_value in original_entry_dict.items():
                key_str = str(raw_key)
                if isinstance(raw_value, bytes):
                    entry_attrs_for_diff[key_str] = raw_value.decode("utf-8")
                elif raw_value is None or u.is_primitive(raw_value):
                    entry_attrs_for_diff[key_str] = raw_value
                elif isinstance(raw_value, list):
                    entry_attrs_for_diff[key_str] = [str(item) for item in raw_value]
                elif isinstance(raw_value, Mapping):
                    entry_attrs_for_diff[key_str] = {
                        str(k): str(v) for k, v in raw_value.items()
                    }
                else:
                    entry_attrs_for_diff[key_str] = str(raw_value)
            dn_differences, attribute_differences, original_attrs_complete, _ = (
                u.Ldif.analyze_differences(
                    entry_attrs=entry_attrs_for_diff,
                    converted_attrs=converted_attrs,
                    original_dn=original_dn,
                    cleaned_dn=parsed_dn or original_dn,
                )
            )
            if not entry.metadata:
                entry.metadata = m.Ldif.QuirkMetadata.create_for(
                    "oud", extensions=FlextLdifModelsMetadata.DynamicMetadata()
                )
            FlextLdifUtilitiesMetadata.store_minimal_differences(
                metadata=entry.metadata,
                dn_differences=m.Ldif.DynamicMetadata.from_dict(
                    dn_differences
                ).model_dump_json(),
                attribute_differences=m.Ldif.DynamicMetadata.from_dict(
                    attribute_differences
                ).model_dump_json(),
                original_dn=original_dn or "",
                parsed_dn=parsed_dn or "",
                original_attributes_complete=m.Ldif.DynamicMetadata.from_dict(
                    original_attrs_complete
                ).model_dump_json(),
            )
            logger.debug(
                "OUD entry parsed with minimal differences",
                entry_dn=original_dn[:50] if original_dn else "",
            )
            entries_list.append(entry)

    def _find_aci_in_dict(
        self, attrs: Mapping[str, builtins.object] | None
    ) -> list[str] | str | None:
        """Find ACI value in dictionary (case-insensitive)."""
        if not attrs:
            return None
        for key, value in attrs.items():
            if key.lower() == "aci":
                if value is None:
                    return None
                if isinstance(value, str):
                    return value
                return str(value)
        return None

    def _find_aci_values(
        self,
        entry: m.Ldif.Entry,
        original_attrs: t.Ldif.CommonDict.AttributeDictGeneric,
    ) -> list[str] | str | None:
        """Find ACI values from entry or original_attrs."""
        aci_values: list[str] | str | None = None
        if original_attrs:
            original_aci = original_attrs.get("aci")
            if isinstance(original_aci, list):
                aci_input: builtins.object = [str(v) for v in original_aci]
                aci_values = self._normalize_aci_value_simple(aci_input)
            elif isinstance(original_aci, str):
                aci_values = self._normalize_aci_value_simple(original_aci)
        if not aci_values and entry.attributes and entry.attributes.attributes:
            entry_aci = entry.attributes.attributes.get("aci")
            if isinstance(entry_aci, list):
                entry_aci_input: builtins.object = [str(v) for v in entry_aci]
                aci_values = self._normalize_aci_value_simple(entry_aci_input)
        if not aci_values:
            aci_values = self._find_aci_in_dict(original_attrs)
            if not aci_values and entry.attributes and entry.attributes.attributes:
                aci_values = self._find_aci_in_dict(entry.attributes.attributes)
        if not aci_values and entry.metadata and entry.metadata.extensions:
            commented_raw = entry.metadata.extensions.get("commented_attribute_values")
            if commented_raw is not None:
                commented_values = self._parse_commented_values(commented_raw)
                if commented_values:
                    for key, value in commented_values.items():
                        if key.lower() == "aci":
                            aci_values = self._normalize_aci_value_simple(value)
                            if aci_values:
                                break
        return aci_values

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
                    and (transformation.target_name.lower() == "aci")
                ):
                    return attr_name
        if entry.metadata and entry.metadata.extensions:
            acl_original_format = entry.metadata.extensions.get("original_format")
            if acl_original_format and "orclaci:" in str(acl_original_format):
                return "orclaci"
        return "orclaci"

    def _hook_finalize_entry_parse(
        self,
        entry: m.Ldif.Entry,
        original_dn: str,
        original_attrs: t.Ldif.CommonDict.AttributeDictGeneric,
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
            entry.metadata = m.Ldif.QuirkMetadata.create_for(
                "oud", extensions=FlextLdifModelsMetadata.DynamicMetadata()
            )
        current_extensions: dict[str, builtins.object] = (
            dict(entry.metadata.extensions.to_dict())
            if entry.metadata and entry.metadata.extensions
            else {}
        )
        parent = self._get_parent_quirk_safe()
        if parent is None:
            return r[m.Ldif.Entry].ok(entry)
        acl_quirk_raw = getattr(parent, "_acl_quirk", None)
        if not acl_quirk_raw:
            return r[m.Ldif.Entry].ok(entry)
        if not core_u.is_type(acl_quirk_raw, FlextLdifServersOudAcl):
            return r[m.Ldif.Entry].ok(entry)
        acl_quirk: FlextLdifServersOudAcl = acl_quirk_raw
        self._process_aci_list_for_finalize(aci_values, acl_quirk, current_extensions)
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
                        "extensions": FlextLdifModelsMetadata.DynamicMetadata.from_dict(
                            merged_extensions
                        )
                    }
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
            r[Entry] - validated entry, unchanged if valid

        References:
            - Oracle OUD ACI Macros: https://docs.oracle.com/cd/E22289_01/html/821-1277/aci-syntax.html

        """
        attrs_dict = entry.attributes.attributes if entry.attributes is not None else {}
        aci_attrs = attrs_dict.get("aci")
        if aci_attrs and core_u.is_type(aci_attrs, (list, tuple)):
            has_macros = False
            acl_metadata_extensions: dict[str, builtins.object] = {}
            for aci_value in aci_attrs:
                if core_u.is_type(aci_value, str):
                    process_result = self._process_single_aci_value(
                        aci_value, acl_metadata_extensions
                    )
                    if process_result.is_failure:
                        return r[m.Ldif.Entry].fail(
                            process_result.error or "ACI processing failed"
                        )
                    if process_result.value:
                        has_macros = True
            if has_macros:
                aci_list = (
                    list(aci_attrs)
                    if core_u.is_type(aci_attrs, (list, tuple))
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

    def _is_schema_entry(self, entry: m.Ldif.Entry) -> bool:
        """Check if entry is a schema entry - delegate to utility."""
        facade_entry = entry
        return u.Ldif.is_schema_entry(facade_entry, strict=False)

    def _merge_acl_metadata_to_entry(
        self,
        entry: m.Ldif.Entry,
        acl_metadata_extensions: Mapping[str, builtins.object],
    ) -> m.Ldif.Entry:
        """Merge ACL metadata extensions into entry metadata."""
        if not acl_metadata_extensions:
            return entry
        if entry.metadata:
            current_extensions: dict[str, builtins.object] = (
                dict(entry.metadata.extensions.to_dict())
                if entry.metadata.extensions
                else {}
            )
            current_extensions.update(acl_metadata_extensions)
            merged_extensions = FlextLdifModelsMetadata.DynamicMetadata.from_dict(
                current_extensions
            )
            return entry.model_copy(
                update={
                    "metadata": entry.metadata.model_copy(
                        update={"extensions": merged_extensions}, deep=True
                    )
                },
                deep=True,
            )
        entry_metadata = m.Ldif.QuirkMetadata.create_for(
            "oud",
            extensions=FlextLdifModelsMetadata.DynamicMetadata.from_dict(
                acl_metadata_extensions
            ),
        )
        return entry.model_copy(update={"metadata": entry_metadata}, deep=True)

    def _normalize_aci_value(
        self,
        aci_value: str,
        _base_dn: str | None,
        _dn_registry: m.Ldif.DnRegistry | None,
    ) -> tuple[str, bool]:
        """Normalize ACI value DNs (already RFC canonical, no changes needed)."""
        return (aci_value, False)

    def _normalize_aci_value_simple(
        self, value: builtins.object
    ) -> list[str] | str | None:
        """Normalize ACI value to list[str] | str | None."""
        if isinstance(value, list):
            return [str(v) for v in value]
        if isinstance(value, str):
            return value
        return str(value)

    def _normalize_acl_dns(self, entry_data: m.Ldif.Entry) -> m.Ldif.Entry:
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
        - Handle escaped characters: ``cn=user\\, name`` preserved

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
        base_dn, dn_registry = self._extract_acl_metadata(entry_data)
        attrs = entry_data.attributes.attributes
        if "aci" not in attrs:
            return entry_data
        aci_values = attrs["aci"]
        if not aci_values:
            return entry_data
        normalized_aci_values: list[str] = []
        for aci in aci_values:
            aci_str = aci if core_u.is_type(aci, str) else str(aci)
            normalized_aci, was_filtered = self._normalize_aci_value(
                aci_str, base_dn, dn_registry
            )
            if not was_filtered and normalized_aci:
                normalized_aci_values.append(normalized_aci)
        if normalized_aci_values != aci_values:
            new_attrs = dict(entry_data.attributes.attributes)
            new_attrs["aci"] = normalized_aci_values
            entry_data.attributes.attributes = new_attrs
        return entry_data

    def _process_aci_list_for_finalize(
        self,
        aci_values: list[str] | str,
        acl_quirk: FlextLdifServersOudAcl,
        current_extensions: dict[str, builtins.object],
    ) -> None:
        """Process list of ACI values and extract metadata."""
        aci_list = list(aci_values) if isinstance(aci_values, list) else [aci_values]
        for aci_value in aci_list:
            normalized_aci = aci_value.strip()
            if not normalized_aci.startswith("aci:"):
                normalized_aci = f"aci: {normalized_aci}"
            acl_result = acl_quirk.parse(normalized_aci)
            if acl_result.is_success:
                acl_model = acl_result.value
                if acl_model.metadata and acl_model.metadata.extensions:
                    acl_ext_raw = acl_model.metadata.extensions.to_dict()
                    acl_extensions: dict[str, builtins.object] = {}
                    for raw_key, raw_value in acl_ext_raw.items():
                        key = str(raw_key)
                        acl_extensions[key] = (
                            FlextLdifModelsMetadata.DynamicMetadata.coerce_metadata_value(
                                raw_value
                            )
                        )
                    self._process_parsed_acl_extensions(
                        acl_extensions, current_extensions
                    )

    def _process_parsed_acl_extensions(
        self,
        acl_extensions: Mapping[str, builtins.object],
        current_extensions: dict[str, builtins.object],
    ) -> None:
        """Process parsed ACL extensions and add to current extensions."""
        mk = c.Ldif.MetadataKeys
        key_mapping: dict[str, str] = {
            "targattrfilters": mk.ACL_TARGETATTR_FILTERS,
            "targetcontrol": mk.ACL_TARGET_CONTROL,
            "extop": mk.ACL_EXTOP,
            "ip": mk.ACL_BIND_IP_FILTER,
            "dns": mk.ACL_TARGETSCOPE,
            "dayofweek": mk.ACL_NUMBERING,
            "timeofday": mk.ACL_BINDMODE,
            "authmethod": mk.ACL_SOURCE_PERMISSIONS,
            "ssf": mk.ACL_SSFS,
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
            if value is None or u.is_primitive(value):
                current_extensions[final_key] = value
            elif isinstance(value, (list, tuple)):
                value_list: list[t.Ldif.Scalar] = [
                    item if item is None or u.is_primitive(item) else str(item)
                    for item in value
                ]
                current_extensions[final_key] = value_list
            elif isinstance(value, Mapping):
                value_dict_inner: dict[str, t.Scalar] = {}
                for k, v in value.items():
                    key = str(k)
                    if u.is_primitive(v):
                        value_dict_inner[key] = v
                    else:
                        value_dict_inner[key] = str(v)
                value_dict_typed: builtins.object = dict(value_dict_inner)
                current_extensions[final_key] = value_dict_typed
            else:
                current_extensions[final_key] = str(value)

    def _process_single_aci_value(
        self, aci_value: str, acl_metadata_extensions: dict[str, builtins.object]
    ) -> r[bool]:
        """Process single ACI value, extract metadata, return has_macros flag."""
        has_macros = bool(re.search(r"\(\$dn\)|\[\$dn\]|\(\$attr\.", aci_value))
        validation_result = self._validate_aci_macros(aci_value)
        if validation_result.is_failure:
            return r[bool].fail(
                f"ACI macro validation failed: {validation_result.error}"
            )
        normalized_aci = aci_value.strip()
        if not normalized_aci.startswith("aci:"):
            normalized_aci = f"aci: {normalized_aci}"
        acl_quirk = FlextLdifServersOudAcl()
        parse_result = acl_quirk.parse(normalized_aci)
        if parse_result.is_success:
            parsed_acl = parse_result.value
            if parsed_acl.metadata and parsed_acl.metadata.extensions:
                acl_extensions = parsed_acl.metadata.extensions
                if core_u.is_type(
                    acl_extensions, FlextLdifModelsMetadata.DynamicMetadata
                ):
                    self._extract_acl_metadata_from_dynamic(
                        acl_extensions, acl_metadata_extensions
                    )
                elif isinstance(acl_extensions, Mapping):
                    acl_extensions_dict: dict[str, builtins.object] = {
                        str(
                            k
                        ): FlextLdifModelsMetadata.DynamicMetadata.coerce_metadata_value(
                            v
                        )
                        for k, v in acl_extensions.items()
                    }
                    self._extract_acl_metadata_from_dict(
                        acl_extensions_dict, acl_metadata_extensions
                    )
        return r[bool].ok(has_macros)

    def _restore_entry_from_metadata(self, entry_data: m.Ldif.Entry) -> m.Ldif.Entry:
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
        mk = c.Ldif.MetadataKeys
        original_dn_value = ext.get(mk.ORIGINAL_DN_COMPLETE)
        if isinstance(original_dn_value, str) and entry_data.dn:
            dn_diff_raw = ext.get(mk.MINIMAL_DIFFERENCES_DN, {})
            if isinstance(dn_diff_raw, Mapping):
                has_diff = bool(dn_diff_raw.get(mk.HAS_DIFFERENCES, False))
                if has_diff:
                    entry_data = entry_data.model_copy(
                        update={"dn": m.Ldif.DN(value=original_dn_value)}
                    )
        original_case_map_raw = (
            entry_data.metadata.original_attribute_case if entry_data.metadata else None
        )
        original_attributes_raw = ext.get(
            c.Ldif.MetadataKeys.ORIGINAL_ATTRIBUTES_COMPLETE
        )
        if (
            entry_data.attributes
            and isinstance(original_case_map_raw, Mapping)
            and isinstance(original_attributes_raw, Mapping)
        ):
            restored: dict[str, list[str]] = {}
            for attr_name, attr_values in entry_data.attributes.attributes.items():
                orig_case_raw = original_case_map_raw.get(attr_name.lower(), attr_name)
                orig_case: str = (
                    orig_case_raw if isinstance(orig_case_raw, str) else attr_name
                )
                if orig_case in original_attributes_raw:
                    val = original_attributes_raw[orig_case]
                    restored[orig_case] = (
                        [str(i) for i in val]
                        if isinstance(val, (list, tuple))
                        else [str(val)]
                    )
                else:
                    restored[orig_case] = (
                        [str(i) for i in attr_values]
                        if attr_values
                        else [str(attr_values)]
                    )
            if restored:
                entry_data = entry_data.model_copy(
                    update={
                        "attributes": m.Ldif.Attributes(
                            attributes=restored,
                            attribute_metadata=entry_data.attributes.attribute_metadata,
                            metadata=entry_data.attributes.metadata,
                        )
                    }
                )
        return entry_data

    def _validate_aci_macros(self, _aci_value: str) -> r[bool]:
        """Validate OUD ACI macro consistency rules (no-op)."""
        return r[bool].ok(True)

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
        if hook_result.is_failure:
            return r[str].fail(f"Pre-write hook failed: {hook_result.error}")
        normalized_entry = hook_result.value
        entry_to_write = self._restore_entry_from_metadata(normalized_entry)
        write_options_raw = FlextLdifUtilitiesMetadata.extract_write_options(
            entry_to_write
        )
        write_options = (
            m.Ldif.WriteFormatOptions.model_validate(write_options_raw.model_dump())
            if write_options_raw is not None
            else None
        )
        ldif_parts: list[str] = []
        ldif_parts.extend(self._add_original_entry_comments(entry_data, write_options))
        entry_data = self._apply_phase_aware_acl_handling(entry_data, write_options)
        if FlextLdifServersOudConstants.ACL_NORMALIZE_DNS_IN_VALUES:
            entry_data = self._normalize_acl_dns(entry_data)
        return (
            super()
            ._write_entry(entry_data)
            .map(lambda ldif_text: u.Ldif.finalize_ldif_text(ldif_parts + [ldif_text]))
        )

    def _write_entry_as_comment(self, entry_data: m.Ldif.Entry) -> r[str]:
        """Write entry as commented LDIF (each line prefixed with '# ').

        Args:
            entry_data: Entry to write as comment

        Returns:
            r with commented LDIF string

        """
        return (
            super()
            ._write_entry(entry_data)
            .map(
                lambda ldif_text: "\n".join(
                    f"# {line}" for line in ldif_text.split("\n")
                )
            )
        )
