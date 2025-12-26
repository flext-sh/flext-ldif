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

from flext_core import FlextLogger, r

from flext_ldif._models.metadata import FlextLdifModelsMetadata
from flext_ldif.constants import c
from flext_ldif.models import m
from flext_ldif.servers._base.schema import FlextLdifServersBaseSchema
from flext_ldif.servers._oid.constants import FlextLdifServersOidConstants
from flext_ldif.servers.rfc import FlextLdifServersRfc
from flext_ldif.utilities import u

# Removed alias - use c.Ldif.MetadataKeys directly (no redundant aliases in higher layers)

logger = FlextLogger(__name__)

# Type alias for OID Constants to avoid circular imports
# FlextLdifServersOid is defined in oid.py which imports this module
_OidConstants = FlextLdifServersOidConstants


class FlextLdifServersOidSchema(
    FlextLdifServersRfc.Schema,
):
    """Oracle Internet Directory (OID) schema quirks implementation.

    OID vs RFC Differences
    ======================
    Oracle OID exports schema in a format that deviates from RFC 4512 in
    several ways. This class normalizes OID-specific formats to RFC-compliant
    structures during parsing, and denormalizes back to OID format when writing.

    1. MATCHING RULE CASE SENSITIVITY
    ---------------------------------
    OID Bug: Uses 'caseIgnoreSubStringsMatch' (capital S) instead of
    RFC 4517 compliant 'caseIgnoreSubstringsMatch' (lowercase s).

    - OID exports:   EQUALITY caseIgnoreSubStringsMatch
    - RFC standard:  SUBSTR caseIgnoreSubstringsMatch (note: SUBSTR not EQUALITY)

    This quirk normalizes:
    - 'caseIgnoreSubStringsMatch' → 'caseIgnoreSubstringsMatch'
    - Moves from EQUALITY to SUBSTR field (per RFC 4517 Section 4.2.2)

    See: Oracle Fusion Middleware Admin Guide, Chapter "Schema Management"

    2. SYNTAX OID QUIRKS
    --------------------
    OID uses proprietary syntax OIDs that must be mapped to RFC 4517:

    - OID ACI List Syntax (1.3.6.1.4.1.1466.115.121.1.1)
      → RFC Directory String (1.3.6.1.4.1.1466.115.121.1.15)

    3. ORACLE-SPECIFIC ATTRIBUTES
    -----------------------------
    OID defines proprietary attributes in the 2.16.840.1.113894.* namespace:

    - orclGUID: Oracle GUID (maps to RFC entryUUID conceptually)
    - orclPassword: Oracle password storage
    - orclaci: Oracle Access Control Information
    - orclentrylevelaci: Entry-level ACI

    See: Oracle Fusion Middleware Reference for OID Schema

    4. OBJECTCLASS SUP QUIRKS
    -------------------------
    OID allows multiple SUP values in objectClass definitions, which is
    technically RFC-compliant but less common. Format normalization handles:

    - SUP ( top person ) → list ['top', 'person']
    - SUP top → list ['top']

    5. AUXILLARY TYPO
    -----------------
    OID exports sometimes contain typo 'AUXILLARY' instead of 'AUXILIARY'.
    This quirk normalizes the typo during parsing.

    6. BOOLEAN ATTRIBUTE FORMAT
    ---------------------------
    OID uses '0'/'1' for boolean attributes instead of RFC 4517 'TRUE'/'FALSE':

    - orcldasenableproductlogo: 1 → TRUE
    - pwdlockout: 0 → FALSE

    Detection Pattern
    =================
    OID schemas are detected by:
    - OID namespace: 2.16.840.1.113894.*
    - Attribute prefix: orcl*
    - ObjectClasses: orclContext, orclContainer, etc.

    References
    ----------
    - RFC 4512: LDAP Directory Information Models (Schema)
    - RFC 4517: LDAP Syntaxes and Matching Rules
    - Oracle Fusion Middleware Administrator's Guide for OID
    - Oracle Fusion Middleware Reference for OID Schema Objects

    """

    def __init__(
        self,
        schema_service: object | None = None,
        _parent_quirk: FlextLdifServersRfc | None = None,
        **kwargs: str | float | bool | None,
    ) -> None:
        """Initialize OID schema quirk.

        server_type and priority are obtained from parent class Constants.
        They are not passed as parameters anymore.

        Args:
            schema_service: Injected schema service with parse method (optional)
            _parent_quirk: Reference to parent FlextLdifServersRfc (optional)
            **kwargs: Passed to parent (must not include _parent_quirk or _schema_service)

        """
        # Business Rule: _schema_service is NOT a t.GeneralValueType, so it cannot be
        # passed to FlextService.__init__ which expects only t.GeneralValueType kwargs.
        # Implication: _schema_service must be stored directly on the instance after
        # super().__init__() using object.__setattr__.
        # Filter _schema_service and _parent_quirk from kwargs to avoid duplicate arguments
        # Business Rule: Only pass t.GeneralValueType (str | float | bool | None) to super().__init__
        # Implication: Filter kwargs to ensure type safety
        filtered_kwargs: dict[str, str | float | bool | None] = {
            k: v
            for k, v in kwargs.items()
            if k not in ("_parent_quirk", "_schema_service")
            and isinstance(v, (str, float, bool, type(None)))
        }
        # Business Rule: Call parent Schema.__init__ which accepts _schema_service and _parent_quirk
        # Cast schema_service to HasParseMethodProtocol for type compatibility

        schema_service_typed: object | None = (
            schema_service if schema_service is not None else None
        )
        # Call base class __init__ directly to avoid mypy inference issues through nested class
        FlextLdifServersBaseSchema.__init__(
            self,
            _schema_service=schema_service_typed,
            _parent_quirk=None,
            **filtered_kwargs,
        )
        # Store _parent_quirk after initialization using object.__setattr__
        if _parent_quirk is not None:
            object.__setattr__(self, "_parent_quirk", _parent_quirk)

    # Schema parsing and conversion methods
    # OVERRIDDEN METHODS (from FlextLdifServersBase.Schema)
    # These methods override base class with Oracle OID-specific logic:
    # - _parse_attribute(): OID schema parsing with OID replacements
    # - _parse_objectclass(): OID schema parsing with OID replacements
    # - _write_attribute(): RFC writer with OID error handling
    # - _write_objectclass(): RFC writer with OID error handling
    # - should_filter_out_attribute(): Returns False (accept all)
    # - should_filter_out_objectclass(): Returns False (accept all)
    # - create_metadata(): Creates OID-specific metadata

    def _hook_post_parse_attribute(
        self,
        attr: m.Ldif.SchemaAttribute,
    ) -> r[m.Ldif.SchemaAttribute]:
        """Hook: Transform parsed attribute using OID-specific normalizations.

        Called by RFC._parse_attribute() after RFC 4512 baseline parsing.
        Applies OID → RFC transformations to normalize Oracle-specific
        schema formats to RFC-compliant structures.

        OID-Specific Transformations Applied
        ====================================

        Step 1: Syntax OID Cleanup
        --------------------------
        Remove quotes from syntax OID values. OID sometimes exports:
            SYNTAX '1.3.6.1.4.1.1466.115.121.1.15'
        RFC 4512 requires unquoted:
            SYNTAX 1.3.6.1.4.1.1466.115.121.1.15

        Step 2: Matching Rule Normalization
        -----------------------------------
        Fix OID's case sensitivity bug and incorrect field placement:

        Input (OID export):
            EQUALITY caseIgnoreSubStringsMatch  (wrong: capital S, wrong field)

        Output (RFC 4517 compliant):
            EQUALITY caseIgnoreMatch
            SUBSTR caseIgnoreSubstringsMatch  (lowercase s, correct)

        Uses Constants.MATCHING_RULE_TO_RFC mapping:
            'caseIgnoreSubStringsMatch' → 'caseIgnoreSubstringsMatch'
            'accessDirectiveMatch' → 'caseIgnoreMatch'

        Step 3: Syntax OID Replacement
        ------------------------------
        Map OID proprietary syntax OIDs to RFC 4517 standard:

        Uses Constants.SYNTAX_OID_TO_RFC mapping:
            '1.3.6.1.4.1.1466.115.121.1.1' (OID ACI List)
            → '1.3.6.1.4.1.1466.115.121.1.15' (RFC Directory String)

        Step 4: SUBSTR Field Correction
        -------------------------------
        Move caseIgnoreSubstringsMatch from EQUALITY to SUBSTR field
        per RFC 4517 Section 4.2.2 (Substring Matching Rules).

        Example LDIF Input (OID)
        ========================
        attributetypes: ( 2.16.840.1.113894.1.1.5 NAME 'orclDbType'
          EQUALITY caseIgnoreSubStringsMatch
          SYNTAX '1.3.6.1.4.1.1466.115.121.1.15{128}' )

        Example Output (RFC Normalized)
        ===============================
        SchemaAttribute(
            oid='2.16.840.1.113894.1.1.5',
            name='orclDbType',
            equality='caseIgnoreMatch',
            substr='caseIgnoreSubstringsMatch',
            syntax='1.3.6.1.4.1.1466.115.121.1.15',
            length=128
        )

        Args:
            attr: Parsed attribute from RFC baseline parser

        Returns:
            r with OID-normalized SchemaAttribute

        """
        try:
            # Step 1: Clean syntax OID (remove quotes, no replacements)
            if attr.syntax:
                attr.syntax = u.Ldif.Schema.normalize_syntax_oid(
                    str(attr.syntax),
                )

            # Step 2: Normalize matching rules using Constants
            normalized_equality, normalized_substr = (
                u.Ldif.Schema.normalize_matching_rules(
                    attr.equality,
                    attr.substr,
                    replacements=_OidConstants.MATCHING_RULE_TO_RFC,
                    normalized_substr_values=_OidConstants.MATCHING_RULE_TO_RFC,
                )
            )
            if normalized_equality != attr.equality:
                attr.equality = normalized_equality
            if normalized_substr != attr.substr:
                attr.substr = normalized_substr
            # Normalize ordering field if present
            if attr.ordering:
                normalized_ordering = _OidConstants.MATCHING_RULE_TO_RFC.get(
                    attr.ordering,
                )
                if normalized_ordering:
                    attr.ordering = normalized_ordering

            # Step 3: Apply syntax OID→RFC replacements
            if attr.syntax:
                attr.syntax = u.Ldif.Schema.normalize_syntax_oid(
                    str(attr.syntax),
                    replacements=_OidConstants.SYNTAX_OID_TO_RFC,
                )

            # Step 4: Transform caseIgnoreSubstringsMatch (EQUALITY → SUBSTR)
            attr = self._transform_case_ignore_substrings(attr)

            return r[str].ok(attr)

        except Exception as e:
            logger.exception(
                "OID post-parse attribute hook failed",
            )
            return r[str].fail(
                f"OID post-parse attribute hook failed: {e}",
            )

    def _hook_post_parse_objectclass(
        self,
        oc: m.Ldif.SchemaObjectClass,
    ) -> r[m.Ldif.SchemaObjectClass]:
        """Hook: Transform parsed objectClass using OID-specific normalizations.

        Called by RFC._parse_objectclass() after RFC 4512 baseline parsing.
        Applies OID → RFC transformations to normalize Oracle-specific
        objectClass definitions.

        OID-Specific Transformations Applied
        ====================================

        Step 1: SUP Normalization
        -------------------------
        OID exports SUP in various formats that need normalization:

        Input formats (OID):
            SUP top                    → ['top']
            SUP ( top person )         → ['top', 'person']
            SUP 'top'                  → ['top']

        Output (RFC normalized list):
            sup=['top', 'person']

        Multiple SUP is RFC-compliant (RFC 4512 Section 4.1.1) but less common.

        Step 2: AUXILLARY Typo Fix
        --------------------------
        OID sometimes exports typo 'AUXILLARY' instead of 'AUXILIARY':

        Input (OID with typo):
            objectClasses: ( ... AUXILLARY ... )

        Output (RFC corrected):
            kind='AUXILIARY'

        Step 3: Attribute Name Case Normalization
        -----------------------------------------
        OID exports MUST/MAY attributes with inconsistent case:

        Input (OID lowercase):
            MUST ( middlename $ mail )

        Output (RFC CamelCase):
            must=['middleName', 'mail']

        Uses Constants.ATTR_NAME_CASE_MAP for corrections:
            'middlename' → 'middleName' (per RFC 4519)

        Example LDIF Input (OID)
        ========================
        objectClasses: ( 2.16.840.1.113894.1.0.5
          NAME 'orclUserV2'
          SUP ( top person inetOrgPerson )
          AUXILLARY
          MUST ( middlename )
          MAY ( orclPassword ) )

        Example Output (RFC Normalized)
        ===============================
        SchemaObjectClass(
            oid='2.16.840.1.113894.1.0.5',
            name='orclUserV2',
            sup=['top', 'person', 'inetOrgPerson'],
            kind='AUXILIARY',
            must=['middleName'],
            may=['orclPassword']
        )

        Args:
            oc: Parsed objectClass from RFC baseline parser

        Returns:
            r with OID-normalized SchemaObjectClass

        """
        try:
            # Get original format for transformations
            # MetadataKeys removed - use direct string keys
            key = c.Ldif.MetadataKeys.SCHEMA_ORIGINAL_FORMAT
            original_format_str = (
                str(oc.metadata.extensions.get(key, ""))
                if oc.metadata and oc.metadata.extensions
                else ""
            )

            # Normalize SUP and AUXILIARY
            updated_sup = self._normalize_sup_from_model(oc)
            if updated_sup is None and original_format_str:
                updated_sup = self._normalize_sup_from_original_format(
                    original_format_str,
                )

            updated_kind = self._normalize_auxiliary_typo(
                oc,
                original_format_str,
            )

            # Normalize attribute names in MUST and MAY (OID → RFC case correction)
            normalized_must = self._normalize_attribute_names(oc.must)
            normalized_may = self._normalize_attribute_names(oc.may)

            # Apply transformations if needed
            update_dict: dict[str, str | list[str] | None] = {
                k: v
                for k, v in {
                    "sup": updated_sup,
                    "kind": updated_kind,
                    "must": normalized_must if normalized_must != oc.must else None,
                    "may": normalized_may if normalized_may != oc.may else None,
                }.items()
                if v
            }

            if update_dict:
                oc = oc.model_copy(update=update_dict)

            return r[str].ok(oc)

        except Exception as e:
            logger.exception(
                "OID post-parse objectclass hook failed",
            )
            return r[str].fail(
                f"OID post-parse objectclass hook failed: {e}",
            )

    def _transform_case_ignore_substrings(
        self,
        attr_data: m.Ldif.SchemaAttribute,
    ) -> m.Ldif.SchemaAttribute:
        """Transform caseIgnoreSubstringsMatch from EQUALITY to SUBSTR.

        RFC 4517 compliance: caseIgnoreSubstringsMatch must be SUBSTR, not EQUALITY.
        Transform during parse so the model is correct from the start (OID → RFC).

        Args:
            attr_data: Attribute data to transform

        Returns:
            Transformed attribute data

        """
        # Use utilities to normalize matching rules
        # (moves SUBSTR from EQUALITY to SUBSTR)
        normalized_equality, normalized_substr = u.Ldif.Schema.normalize_matching_rules(
            attr_data.equality,
            attr_data.substr,
            substr_rules_in_equality={
                "caseIgnoreSubstringsMatch": "caseIgnoreMatch",
                "caseIgnoreSubStringsMatch": "caseIgnoreMatch",
            },
        )

        # Only transform if values changed
        if (
            normalized_equality != attr_data.equality
            or normalized_substr != attr_data.substr
        ):
            logger.debug(
                "Moved caseIgnoreSubstringsMatch from EQUALITY to SUBSTR",
                attribute_name=attr_data.name,
                original_equality=attr_data.equality,
                normalized_substr=normalized_substr,
            )

            # Preserve original_format before transformation
            original_format: str | None = None
            # MetadataKeys removed - use direct string keys
            key = c.Ldif.MetadataKeys.SCHEMA_ORIGINAL_FORMAT
            if (
                attr_data.metadata
                and attr_data.metadata.extensions
                and key in attr_data.metadata.extensions
            ):
                original_format_raw = attr_data.metadata.extensions.get(
                    c.Ldif.MetadataKeys.SCHEMA_ORIGINAL_FORMAT,
                )
                if original_format_raw is None or isinstance(
                    original_format_raw,
                    str,
                ):
                    original_format = original_format_raw
                else:
                    msg = f"Expected Optional[str], got {type(original_format_raw)}"
                    raise TypeError(msg)

            # Create new model with transformed values
            transformed = attr_data.model_copy(
                update={
                    "equality": normalized_equality,
                    "substr": normalized_substr,
                },
            )

            # Restore original_format in metadata after transformation
            if original_format and transformed.metadata:
                transformed.metadata.extensions[
                    c.Ldif.MetadataKeys.SCHEMA_ORIGINAL_FORMAT
                ] = original_format

            return transformed

        return attr_data

    def _capture_attribute_values(
        self,
        attr_data: m.Ldif.SchemaAttribute,
    ) -> dict[str, str | None]:
        """Capture attribute values for metadata tracking.

        Used both before and after transformations to track source/target state.
        """
        return {
            "syntax_oid": str(attr_data.syntax) if attr_data.syntax else None,
            "equality": attr_data.equality,
            "substr": attr_data.substr,
            "ordering": attr_data.ordering,
            "name": attr_data.name,
        }

    # REMOVED: _add_source_metadata (34 lines dead code - never called)
    # SOURCE metadata is populated in _parse_attribute via source_values capture

    def _add_target_metadata(
        self,
        attr_data: m.Ldif.SchemaAttribute,
        target_values: dict[str, str | None],
    ) -> None:
        """Add target metadata to attribute."""
        # MetadataKeys removed - use direct string keys
        if not attr_data.metadata:
            return

        # Preserve TARGET (after transformation)
        if target_values["syntax_oid"]:
            attr_data.metadata.extensions[
                c.Ldif.MetadataKeys.SCHEMA_TARGET_SYNTAX_OID
            ] = target_values["syntax_oid"]
        if target_values["name"]:
            attr_data.metadata.extensions[
                c.Ldif.MetadataKeys.SCHEMA_TARGET_ATTRIBUTE_NAME
            ] = target_values["name"]

        # Preserve TARGET matching rules (after transformation)
        target_rules = {}
        if target_values["equality"]:
            target_rules["equality"] = target_values["equality"]
        if target_values["substr"]:
            target_rules["substr"] = target_values["substr"]
        if target_values["ordering"]:
            target_rules["ordering"] = target_values["ordering"]
        if target_rules:
            attr_data.metadata.extensions[
                c.Ldif.MetadataKeys.SCHEMA_TARGET_MATCHING_RULES
            ] = target_rules

        # Timestamp
        attr_data.metadata.extensions[c.Ldif.Format.META_TRANSFORMATION_TIMESTAMP] = (
            u.Generators.generate_iso_timestamp()
        )

    def _parse_attribute(
        self,
        attr_definition: str,
    ) -> r[m.Ldif.SchemaAttribute]:
        r"""Parse Oracle OID attribute definition (Phase 1: Normalization).

        OID vs RFC Attribute Parsing
        ============================
        This method extends RFC's `_parse_attribute()` to handle OID-specific
        schema attribute formats while normalizing to RFC 4512 structures.

        Parsing Pipeline
        ----------------
        1. Call RFC base parser with lenient mode
        2. RFC parser calls `_hook_post_parse_attribute()` hook
        3. Hook applies OID→RFC transformations:
           - Fix matching rule typo (SubStrings → Substrings)
           - Normalize syntax OIDs (OID → RFC 4517)
        4. Add OID-specific metadata for round-trip support
        5. Capture target values for bidirectional conversion

        OID-Specific Input Handling
        ---------------------------
        a) SYNTAX with Quotes:
           OID exports: SYNTAX '1.3.6.1.4.1.1466.115.121.1.15'
           RFC 4512:    SYNTAX 1.3.6.1.4.1.1466.115.121.1.15

        b) Case-Insensitive Matching:
           OID uses case-insensitive NAME matching
           RFC 4512 is case-sensitive

        c) Matching Rule Typos:
           OID: SUBSTR caseIgnoreSubStringsMatch (uppercase S)
           RFC: SUBSTR caseIgnoreSubstringsMatch (lowercase s)

        Example Input (OID)
        -------------------
        ( 2.16.840.1.113894.1.1.123
          NAME 'orclPassword'
          SYNTAX '1.3.6.1.4.1.1466.115.121.1.40'{128}
          EQUALITY octetStringMatch
          SINGLE-VALUE
          X-ORIGIN 'Oracle' )

        Example Output (RFC-normalized)
        -------------------------------
        SchemaAttribute(
            oid='2.16.840.1.113894.1.1.123',
            names=['orclPassword'],
            syntax='1.3.6.1.4.1.1466.115.121.1.40',  # Quotes removed
            syntax_length=128,
            equality='octetStringMatch',
            single_value=True,
            x_origin=['Oracle'],
            metadata=m.Ldif.QuirkMetadata(
                quirk_type='oid',
                extensions=FlextLdifModelsMetadata.DynamicMetadata(
                    **{
                        c.Ldif.MetadataKeys.SCHEMA_ORIGINAL_FORMAT: '( 2.16.840.1.113894... )',
                        c.Ldif.MetadataKeys.SCHEMA_ORIGINAL_STRING_COMPLETE: '...',
                        c.Ldif.MetadataKeys.SCHEMA_SOURCE_SERVER: 'oid',
                    }
                )
            )
        )

        Metadata for Round-Trip
        -----------------------
        Uses c.Ldif.MetadataKeys:
        - SCHEMA_ORIGINAL_FORMAT: Stripped definition string
        - SCHEMA_ORIGINAL_STRING_COMPLETE: Complete with all formatting
        - SCHEMA_SOURCE_SERVER: "oid"
        - META_TRANSFORMATION_TIMESTAMP: ISO timestamp

        Args:
            attr_definition: AttributeType definition string
                            (without "attributetypes:" prefix)

        Returns:
            r with RFC-normalized SchemaAttribute

        """
        try:
            # Parse RFC baseline - hook _hook_post_parse_attribute() applies
            # OID-specific transformations (matching rules, syntax normalization)
            result = super()._parse_attribute(attr_definition)

            if not result.is_success:
                return result

            # Unwrap parsed attribute (already has OID transformations via hook)
            attr_data = result.value

            # Preserve TARGET values AFTER transformations (applied by hook)
            target_values = self._capture_attribute_values(attr_data)

            # Ensure metadata is preserved with GENERIC metadata (NO *_OID_* keys!)
            if not attr_data.metadata:
                attr_data.metadata = self.create_metadata(attr_definition.strip())

            # Add GENERIC metadata keys for 100% bidirectional conversion
            if attr_data.metadata:
                # MetadataKeys removed - use direct string keys
                attr_data.metadata.extensions[
                    c.Ldif.MetadataKeys.SCHEMA_ORIGINAL_FORMAT
                ] = attr_definition.strip()
                attr_data.metadata.extensions[
                    c.Ldif.MetadataKeys.SCHEMA_ORIGINAL_STRING_COMPLETE
                ] = attr_definition  # Complete with ALL formatting
                attr_data.metadata.extensions[
                    c.Ldif.MetadataKeys.SCHEMA_SOURCE_SERVER
                ] = "oid"  # OID parsed this

                # Preserve ALL schema formatting details for zero data loss
                # Convert internal QuirkMetadata to public QuirkMetadata if needed
                metadata_public = m.Ldif.QuirkMetadata.model_validate(
                    attr_data.metadata.model_dump(),
                )
                u.Ldif.Metadata.preserve_schema_formatting(
                    metadata_public,
                    attr_definition,
                )

                # Add target metadata (transformations applied by hook)
                self._add_target_metadata(attr_data, target_values)

            return r[m.Ldif.SchemaAttribute].ok(attr_data)

        except Exception as e:
            logger.exception(
                "OID attribute parsing failed",
            )
            return r[m.Ldif.SchemaAttribute].fail(
                f"OID attribute parsing failed: {e}",
            )

    def _write_attribute(
        self,
        attr_data: m.Ldif.SchemaAttribute,
    ) -> r[str]:
        r"""Write Oracle OID attribute definition (Phase 2: Denormalization).

        OID vs RFC Attribute Writing
        ============================
        This method converts RFC-normalized SchemaAttribute models back to
        Oracle OID format for LDIF output.

        Architecture Principle
        ----------------------
        - Parser: OID LDIF → RFC Models (normalization)
        - Writer: RFC Models → OID LDIF (denormalization)

        The OID writer ALWAYS denormalizes to OID format, regardless of
        the source server. For OID→OUD conversion, use RFC writer instead.

        Denormalization Pipeline
        ------------------------
        1. Copy model to avoid mutation
        2. Restore SOURCE values from metadata if available
        3. If no SOURCE metadata, apply RFC→OID mappings:
           a) Matching rules: caseIgnoreSubstringsMatch → caseIgnoreSubStringsMatch
           b) Syntax OIDs: RFC → OID proprietary
        4. Call RFC base writer with denormalized values

        Denormalization Rules
        ---------------------
        a) Matching Rules (Constants.MATCHING_RULE_RFC_TO_OID):
           RFC:  caseIgnoreSubstringsMatch (lowercase s)
           OID:  caseIgnoreSubStringsMatch (uppercase S)

        b) Syntax OIDs (Constants.SYNTAX_RFC_TO_OID):
           RFC:  1.3.6.1.4.1.1466.115.121.1.15 (Directory String)
           OID:  1.3.6.1.4.1.1466.115.121.1.1 (OID ACI List)

        Metadata Usage for Perfect Round-Trip
        -------------------------------------
        If metadata.extensions contains SOURCE values:
        - SCHEMA_SOURCE_MATCHING_RULES: {equality, substr, ordering}
        - SCHEMA_SOURCE_SYNTAX_OID: Original OID syntax

        These are used to restore exact original format.

        Example Input (RFC-normalized)
        ------------------------------
        SchemaAttribute(
            oid='2.16.840.1.113894.1.1.123',
            names=['orclTest'],
            syntax='1.3.6.1.4.1.1466.115.121.1.15',
            substr='caseIgnoreSubstringsMatch',  # RFC format
            metadata=m.Ldif.QuirkMetadata(
                extensions=FlextLdifModelsMetadata.DynamicMetadata(
                    **{
                        c.Ldif.MetadataKeys.SCHEMA_SOURCE_MATCHING_RULES: {
                            'substr': 'caseIgnoreSubStringsMatch'
                        },
                    }
                )
            )
        )

        Example Output (OID Format)
        ---------------------------
        ( 2.16.840.1.113894.1.1.123
          NAME 'orclTest'
          SYNTAX 1.3.6.1.4.1.1466.115.121.1.1
          SUBSTR caseIgnoreSubStringsMatch )

        Args:
            attr_data: RFC-normalized SchemaAttribute model to write

        Returns:
            r with OID-formatted attribute definition string

        """
        # Create a copy to avoid mutating the original
        attr_copy = attr_data.model_copy(deep=True)

        # MetadataKeys removed - use direct string keys

        # ✅ STRICT RULE: OID Writer SEMPRE denormaliza RFC → OID LDIF
        # Does not matter where it came from (OID, OUD, OpenLDAP, etc.)
        # Se estamos escrevendo OID LDIF, SEMPRE aplicamos conversões OID!

        # Tentar restaurar valores SOURCE do metadata (para 100% fidelidade)
        source_rules = None
        source_syntax = None
        if attr_copy.metadata and attr_copy.metadata.extensions:
            source_rules = attr_copy.metadata.extensions.get(
                c.Ldif.MetadataKeys.SCHEMA_SOURCE_MATCHING_RULES,
            )
            source_syntax = attr_copy.metadata.extensions.get(
                c.Ldif.MetadataKeys.SCHEMA_SOURCE_SYNTAX_OID,
            )

        # 1. Denormalizar matching rules: RFC → OID
        if source_rules and isinstance(source_rules, dict):
            # Preferir valores SOURCE do metadata (se vieram de OID originalmente)
            oid_equality = source_rules.get("equality", attr_copy.equality)
            oid_substr = source_rules.get("substr", attr_copy.substr)
            oid_ordering = source_rules.get("ordering", attr_copy.ordering)
        else:
            # Denormalizar valores atuais RFC → OID
            oid_equality, oid_substr = u.Ldif.Schema.normalize_matching_rules(
                attr_copy.equality,
                attr_copy.substr,
                replacements=_OidConstants.MATCHING_RULE_RFC_TO_OID,
                normalized_substr_values=_OidConstants.MATCHING_RULE_RFC_TO_OID,
            )
            oid_ordering = attr_copy.ordering
            if attr_copy.ordering:
                mapped = _OidConstants.MATCHING_RULE_RFC_TO_OID.get(
                    attr_copy.ordering,
                )
                if mapped:
                    oid_ordering = mapped

        # 2. Denormalizar syntax OID: RFC → OID
        # Business Rule: OID syntax must be string for denormalization
        # Implication: Remote auditing tracks syntax conversions as strings
        # Type narrowing: convert source_syntax (MetadataAttributeValue) to str | None
        oid_syntax: str | None = None
        if source_syntax:
            # Preferir syntax SOURCE do metadata (se veio de OID originalmente)
            # Convert MetadataAttributeValue to string
            oid_syntax = str(source_syntax) if source_syntax else None
        else:
            # Denormalizar syntax atual RFC → OID
            oid_syntax = str(attr_copy.syntax) if attr_copy.syntax else None
        if oid_syntax:
            mapped = FlextLdifServersOidConstants.SYNTAX_RFC_TO_OID.get(
                str(attr_copy.syntax),
            )
            if mapped:
                oid_syntax = mapped

        # Remove original_format from metadata (not used for writing)
        oid_metadata = attr_copy.metadata
        if attr_copy.metadata and attr_copy.metadata.extensions:
            # Use constant for metadata key (DRY: avoid hardcoding)
            keys_to_remove = {c.Ldif.MetadataKeys.SCHEMA_ORIGINAL_FORMAT}
            new_extensions = {
                k: v
                for k, v in attr_copy.metadata.extensions.items()
                if k not in keys_to_remove
            }
            # Use specific type for model_copy update
            update_dict: dict[str, object] = {
                "extensions": FlextLdifModelsMetadata.DynamicMetadata.from_dict(
                    new_extensions
                ),
            }
            oid_metadata = attr_copy.metadata.model_copy(update=update_dict)

        # Apply transformations with model_copy
        # Use specific type for model_copy update
        matchers_dict: dict[str, object] = {
            "equality": oid_equality,
            "substr": oid_substr,
            "ordering": oid_ordering,
            "syntax": oid_syntax,
            "metadata": oid_metadata,
        }
        attr_copy = attr_copy.model_copy(update=matchers_dict)

        # Call parent RFC writer with OID-denormalized attribute
        return super()._write_attribute(attr_copy)

    def _normalize_sup_from_model(
        self,
        oc_data: m.Ldif.SchemaObjectClass,
    ) -> str | (list[str] | None):
        """Normalize SUP from objectClass model.

        Fixes: SUP ( top ) → SUP top, SUP 'top' → SUP top

        Args:
            oc_data: ObjectClass data to check

        Returns:
            Normalized SUP value or None if no fix needed

        """
        if not oc_data.sup:
            return None

        # Python 3.13: Match/case for cleaner pattern matching
        # Set of SUP values that need normalization
        sup_normalize_set = {"( top )", "(top)", "'top'", '"top"'}

        match oc_data.sup:
            case sup_str if (sup_clean := str(sup_str).strip()) in sup_normalize_set:
                logger.debug(
                    "OID→RFC transform: SUP normalization",
                    objectclass_name=oc_data.name,
                    objectclass_oid=oc_data.oid,
                    original_sup=sup_clean,
                    normalized_sup="top",
                )
                return "top"
            case [sup_item] if (
                sup_clean := str(sup_item).strip()
            ) in sup_normalize_set:
                logger.debug(
                    "OID→RFC transform: SUP normalization (list)",
                    objectclass_name=oc_data.name,
                    objectclass_oid=oc_data.oid,
                    original_sup=sup_clean,
                    normalized_sup="top",
                )
                return "top"
            case _:
                return None

    def _normalize_sup_from_original_format(
        self,
        original_format_str: str,
    ) -> str | None:
        """Normalize SUP from original_format string.

        Args:
            original_format_str: Original format string to check

        Returns:
            Normalized SUP value or None if no fix needed

        """
        # Python 3.13: match/case for pattern matching (DRY: use set for patterns)
        sup_patterns = ("SUP 'top'", "SUP ( top )", "SUP (top)")
        match original_format_str:
            case s if any(pattern in s for pattern in sup_patterns):
                logger.debug(
                    "OID→RFC transform: SUP normalization (from original_format)",
                    original_format_preview=s[
                        : FlextLdifServersOidConstants.MAX_LOG_LINE_LENGTH
                    ],
                )
                return "top"
            case _:
                return None

    def _normalize_auxiliary_typo(
        self,
        oc_data: m.Ldif.SchemaObjectClass,
        original_format_str: str,
    ) -> str | None:
        """Normalize AUXILLARY typo to AUXILIARY.

        Args:
            oc_data: ObjectClass data to check
            original_format_str: Original format string to check

        Returns:
            Normalized kind value or None if no fix needed

        """
        # Python 3.13: match/case for cleaner pattern matching
        kind = getattr(oc_data, "kind", None)
        match (kind, original_format_str):
            case (k, _) if k and k.upper() == "AUXILLARY":
                logger.debug(
                    "OID→RFC transform: AUXILLARY → AUXILIARY",
                    objectclass_name=oc_data.name,
                    objectclass_oid=oc_data.oid,
                    original_kind=k,
                    normalized_kind="AUXILIARY",
                )
                return "AUXILIARY"
            case (_, fmt) if fmt and "AUXILLARY" in fmt:
                logger.debug(
                    "OID→RFC: AUXILLARY → AUXILIARY (original_format)",
                    objectclass_name=getattr(oc_data, "name", None),
                    objectclass_oid=getattr(oc_data, "oid", None),
                    original_format_preview=fmt[
                        : FlextLdifServersOidConstants.MAX_LOG_LINE_LENGTH
                    ],
                )
                return "AUXILIARY"
            case _:
                return None

    def _normalize_attribute_names(
        self,
        attr_list: list[str] | None,
    ) -> list[str] | None:
        """Normalize attribute names using OID case mappings.

        OID exports objectClass MAY/MUST with lowercase attribute names,
        but attributeType definitions use CamelCase. This normalizes
        to RFC-correct case during parsing (OID → RFC transformation).

        Args:
            attr_list: List of attribute names from OID (may contain lowercase)

        Returns:
            List with normalized attribute names (RFC-correct case)
            None if input was None

        """
        if not attr_list:
            return attr_list

        # List comprehension with case normalization
        case_map = FlextLdifServersOidConstants.ATTR_NAME_CASE_MAP
        return [case_map.get(attr_name.lower(), attr_name) for attr_name in attr_list]

    def _parse_objectclass(
        self,
        oc_definition: str,
    ) -> r[m.Ldif.SchemaObjectClass]:
        """Parse Oracle OID objectClass definition.

        Uses RFC 4512 compliant baseline parser with lenient mode for OID quirks,
        then applies OID-specific enhancements.

        Args:
            oc_definition: ObjectClass definition string
                        (without "objectclasses:" prefix)

        Returns:
            r with parsed OID objectClass data with metadata

        """
        try:
            # Call parent RFC parser for objectClass parsing
            result = super()._parse_objectclass(oc_definition)

            if not result.is_success:
                return result

            # Unwrap parsed objectClass from RFC baseline
            oc_data = result.value

            # Apply OID-specific enhancements on top of RFC baseline
            # Hook _hook_post_parse_objectclass() called by RFC
            # Transforms: SUP/AUXILIARY, attribute name normalization

            # Ensure metadata is preserved with OID-specific information
            # MetadataKeys removed - use direct string keys
            key = c.Ldif.MetadataKeys.SCHEMA_ORIGINAL_FORMAT
            if not oc_data.metadata:
                oc_data.metadata = self.create_metadata(oc_definition.strip())
            elif not oc_data.metadata.extensions.get(key):
                oc_data.metadata.extensions[key] = oc_definition.strip()

            # Attach timestamp metadata
            if oc_data.metadata:
                oc_data.metadata.extensions[
                    c.Ldif.Format.META_TRANSFORMATION_TIMESTAMP
                ] = u.Generators.generate_iso_timestamp()

            return r[m.Ldif.SchemaObjectClass].ok(oc_data)

        except Exception as e:
            logger.exception(
                "OID objectClass parsing failed",
            )
            return r[m.Ldif.SchemaObjectClass].fail(
                f"OID objectClass parsing failed: {e}",
            )

    def _transform_attribute_for_write(
        self,
        attr_data: m.Ldif.SchemaAttribute,
    ) -> m.Ldif.SchemaAttribute:
        """Apply OID-specific attribute transformations before writing.

        IMPORTANT: Writer denormalization (RFC → OID) happens in _write_attribute.
        This hook should NOT re-normalize matching rules back to RFC.
        Only apply NAME normalization here.

        Args:
            attr_data: SchemaAttribute to transform (denormalized)

        Returns:
            Transformed SchemaAttribute with NAME fixes only

        """
        # Apply AttributeFixer transformations to NAME (use utilities.py)
        fixed_name = u.Ldif.Schema.normalize_name(attr_data.name) or attr_data.name

        # DO NOT re-normalize matching rules here!
        # Writer denormalization (RFC → OID) was already applied in _write_attribute
        # Re-normalizing here would undo the denormalization
        fixed_equality = attr_data.equality
        fixed_substr = attr_data.substr

        # Apply invalid SUBSTR rule replacements using utility
        original_substr = fixed_substr
        fixed_substr = u.Ldif.Schema.replace_invalid_substr_rule(
            fixed_substr,
            FlextLdifServersOidConstants.INVALID_SUBSTR_RULES,
        )
        if fixed_substr != original_substr:
            logger.debug(
                "Replaced invalid SUBSTR rule",
                attribute_name=attr_data.name,
                attribute_oid=attr_data.oid,
                original_substr=original_substr,
                replacement_substr=fixed_substr,
            )

        # Check if this is a boolean attribute using utility
        is_boolean = u.Ldif.Schema.is_boolean_attribute(
            fixed_name,
            set(FlextLdifServersOidConstants.BOOLEAN_ATTRIBUTES),
        )
        if is_boolean:
            logger.debug(
                "Identified boolean attribute",
                attribute_name=fixed_name,
                attribute_oid=attr_data.oid,
            )

        # Extract x_origin from metadata.extensions (Python 3.13: match/case)
        x_origin_value: str | None = None
        if attr_data.metadata and attr_data.metadata.extensions:
            match attr_data.metadata.extensions.get("x_origin"):
                case origin if isinstance(origin, str):
                    x_origin_value = origin
                case None:
                    pass  # Already None
                case x_origin_raw:
                    # Fast-fail: x_origin must be str or None
                    logger.warning(
                        "x_origin extension is not a string, ignoring",
                        extra={
                            "x_origin_type": type(x_origin_raw).__name__,
                            "x_origin_value": str(x_origin_raw)[:100],
                            "attribute_name": attr_data.name,
                            "attribute_oid": attr_data.oid,
                        },
                    )

        return m.Ldif.SchemaAttribute(
            oid=attr_data.oid,
            name=fixed_name,
            desc=attr_data.desc,
            sup=attr_data.sup,
            equality=fixed_equality,
            ordering=attr_data.ordering,
            substr=fixed_substr,
            syntax=attr_data.syntax,
            length=attr_data.length,
            usage=attr_data.usage,
            single_value=attr_data.single_value,
            no_user_modification=attr_data.no_user_modification,
            metadata=attr_data.metadata,
            x_origin=x_origin_value,
            x_file_ref=attr_data.x_file_ref,
            x_name=attr_data.x_name,
            x_alias=attr_data.x_alias,
            x_oid=attr_data.x_oid,
        )

    # REMOVED: _post_write_objectclass (36 lines dead code - never called)
    # Typo fix is handled in _normalize_auxiliary_typo during parsing

    def extract_schemas_from_ldif(
        self,
        ldif_content: str,
        *,  # keyword-only parameter
        validate_dependencies: bool = False,
    ) -> r[
        dict[
            str,
            list[m.Ldif.SchemaAttribute] | list[m.Ldif.SchemaObjectClass],
        ]
    ]:
        """Extract and parse all schema definitions from LDIF content.

        OID-specific implementation: Uses base template method without dependency
        validation (OID has relaxed schema validation compared to RFC strict mode).

        Args:
            ldif_content: Raw LDIF content containing schema definitions
            validate_dependencies: Whether to validate attribute dependencies
                (default False for OID as it has simpler schema)

        Returns:
            FlextResult containing extracted attributes and objectclasses
            as a dictionary with ATTRIBUTES and OBJECTCLASS lists.

        """
        return super().extract_schemas_from_ldif(
            ldif_content,
            validate_dependencies=validate_dependencies,
        )


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
