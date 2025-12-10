"""Oracle Unified Directory (OUD) Quirks.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Provides OUD-specific quirks for schema, ACL, and entry processing.
"""

from __future__ import annotations

from flext_core import FlextLogger, FlextResult, FlextService, FlextUtilities as u

from flext_ldif._utilities.schema import FlextLdifUtilitiesSchema
from flext_ldif.constants import c
from flext_ldif.models import m
from flext_ldif.servers._oud.constants import FlextLdifServersOudConstants
from flext_ldif.servers.rfc import FlextLdifServersRfc

logger = FlextLogger(__name__)


class FlextLdifServersOudSchema(FlextLdifServersRfc.Schema):
    """Oracle OUD Schema Implementation (RFC 4512 + OUD Extensions).

    Extends RFC 4512 schema parsing with Oracle OUD-specific features.

    RFC vs OUD Schema Differences
    =============================

    **RFC 4512 Baseline**:

    - ``attributeTypes``: OID, NAME, DESC, EQUALITY, ORDERING, SUBSTR, SYNTAX, SINGLE-VALUE, USAGE
    - ``objectClasses``: OID, NAME, DESC, SUP, STRUCTURAL/AUXILIARY/ABSTRACT, MUST, MAY
    - OIDs must be strictly numeric (e.g., ``2.5.4.3``)

    **OUD Extensions** (Oracle-specific):

    1. **Extended OID Formats**:

       - Non-numeric OIDs: ``X-oid`` suffix (e.g., ``custom-cn-oid``)
       - Oracle namespace: ``1.3.6.1.4.1.26027.*`` (OUD-specific)
       - Legacy OID: ``9.9.9.9.*`` (Oracle extended)

    2. **X-* Extensions** (Oracle-specific):

       - ``X-ORIGIN 'source'``: Origin of the attribute (e.g., ``'RFC 4519'``, ``'Oracle OUD'``)
       - ``X-SCHEMA-FILE 'file.ldif'``: File where schema is defined
       - ``X-PATTERN 'regex'``: Validation pattern for attribute values
       - ``X-ENUM 'value1' 'value2'``: Enumerated allowed values
       - ``X-SUBST 'type'``: Substring matching rule
       - ``X-APPROX 'type'``: Approximate matching rule

    3. **Operational Attributes** (OUD-specific):

       - ``ds-cfg-*``: Configuration attributes
       - ``ds-sync-*``: Replication synchronization
       - ``ds-pwp-*``: Password policy
       - ``orclaci``: Oracle ACI (different from ``aci``)

    4. **DN Case Handling**:

       - OUD preserves DN case (case-insensitive comparison, case-preserving storage)
       - DN components normalized to canonical form
       - Spaces after commas normalized

    Real Examples (from fixtures)
    -----------------------------

    **AttributeType with X-ORIGIN**::

        attributeTypes: ( 0.9.2342.19200300.100.1.1 NAME ( 'uid' 'userid' )
            EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch
            SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} X-ORIGIN 'RFC 4519' )

    **ObjectClass with SUP**::

        objectClasses: ( 0.9.2342.19200300.100.4.5 NAME 'account' SUP top
            STRUCTURAL MUST uid MAY ( description $ seeAlso $ l $ o $ ou $ host )
            X-ORIGIN 'RFC 4524' )

    **Oracle-specific Schema**::

        attributeTypes: ( 1.3.6.1.4.1.26027.1.1.1 NAME 'ds-cfg-enabled'
            EQUALITY booleanMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.7
            SINGLE-VALUE X-ORIGIN 'Oracle Unified Directory' )

    Official Documentation
    ----------------------

    - Schema Management: https://docs.oracle.com/en/middleware/idm/unified-directory/14.1.2/oudag/managing-directory-schema.html
    - RFC 4512 (base): https://tools.ietf.org/html/rfc4512

    Example Usage
    -------------

    ::

        quirk = FlextLdifServersOud()
        if quirk.schema.can_handle_attribute(attr_def):
            result = quirk.schema.parse(attr_def)
            if result.is_success:
                parsed_attr = result.value
                # X-ORIGIN available in parsed_attr.x_origin

    """

    def __init__(
        self,
        schema_service: object | None = None,
        **kwargs: str | float | bool | None,
    ) -> None:
        """Initialize OUD schema quirk.

        OUD extends RFC baseline with Oracle-specific enhancements.

        Args:
            schema_service: Injected FlextLdifSchema service (optional)
            **kwargs: Additional arguments passed to parent

        """
        # Business Rule: Filter _parent_quirk from kwargs to avoid type errors
        # Implication: _parent_quirk is handled separately, not via Pydantic fields
        # Business Rule: _schema_service is NOT a GeneralValueType, so it cannot be
        # passed to FlextService.__init__ which expects only GeneralValueType kwargs.
        # Implication: _schema_service must be passed explicitly to Schema.__init__
        # Business Rule: Only pass GeneralValueType (str | float | bool | None) to super().__init__
        # Implication: Filter kwargs to ensure type safety (int is not GeneralValueType, only str/float/bool/None)
        filtered_kwargs: dict[str, str | float | bool | None] = {
            k: v
            for k, v in kwargs.items()
            if k not in ("_parent_quirk", "_schema_service")
            and isinstance(v, (str, float, bool, type(None)))
        }
        # Business Rule: _schema_service is NOT a GeneralValueType, so it cannot be
        # passed to FlextService.__init__ which expects only GeneralValueType kwargs.
        # Implication: _schema_service must be stored directly on the instance after
        # super().__init__() using object.__setattr__.
        # Call parent RFC.Schema.__init__ without _schema_service (it's not GeneralValueType)
        # Use explicit FlextService.__init__ call to avoid type checker confusion

        FlextService.__init__(self, **filtered_kwargs)
        # Store _schema_service after initialization (not a Pydantic field)
        if schema_service is not None:
            object.__setattr__(self, "_schema_service", schema_service)
        # Note: _parent_quirk is handled separately if needed

    def _validate_attribute_oid(
        self,
        oid: str,
    ) -> FlextResult[bool]:
        """Validate attribute OID format for OUD.

        Args:
            oid: OID string to validate

        Returns:
            FlextResult with boolean indicating validity

        """
        oid_validation_result = u.OID.validate_format(oid)
        if oid_validation_result.is_failure:
            return FlextResult[bool].fail(
                f"OID validation failed: {oid_validation_result.error}",
            )

        is_valid_basic_oid = oid_validation_result.value

        # OUD allows OID format extensions: numeric OID or ending with -oid suffix
        is_valid_oud_oid = is_valid_basic_oid
        if not is_valid_oud_oid and oid.endswith("-oid"):
            # Check if base OID (without -oid suffix) is valid
            base_oid = oid[:-4]
            base_validation = u.OID.validate_format(base_oid)
            if base_validation.is_success:
                is_valid_oud_oid = base_validation.value

        if not is_valid_oud_oid:
            return FlextResult[bool].fail(
                f"Invalid OUD OID format: {oid} (must be numeric RFC OID or end with -oid suffix)",
            )

        return FlextResult[bool].ok(is_valid_oud_oid)

    def _collect_attribute_extensions(
        self,
        attr: m.Ldif.SchemaAttribute,
    ) -> list[str]:
        """Collect OUD X-* extensions from attribute.

        Args:
            attr: Parsed SchemaAttribute

        Returns:
            List of detected X-* extension names

        """
        extensions = []
        if attr.x_origin:
            extensions.append("X-ORIGIN")
        if attr.x_file_ref:
            extensions.append("X-FILE-REF")
        if attr.x_name:
            extensions.append("X-NAME")
        if attr.x_alias:
            extensions.append("X-ALIAS")
        if attr.x_oid:
            extensions.append("X-OID")
        return extensions

    def _hook_post_parse_attribute(
        self,
        attr: m.Ldif.SchemaAttribute,
    ) -> FlextResult[m.Ldif.SchemaAttribute]:
        """Hook: Validate OUD-specific attribute features after RFC parsing.

        RFC vs OUD Behavior Differences
        ================================

        **RFC Baseline** (in rfc.py):
        - No post-parse hook (passes attribute through unchanged)
        - Standard RFC 4512 attribute parsing only
        - No OID format extensions

        **OUD Override** (this method):
        - Validates OUD-specific OID format extensions
        - Detects and logs OUD X-* extension usage
        - Applies OUD-specific validation rules

        OUD Schema Extensions (beyond RFC 4512)
        ---------------------------------------

        **OID Format Extensions**:
        - RFC requires numeric OIDs (e.g., ``1.3.6.1.4.1.26027.1.1.42``)
        - OUD allows non-numeric suffix (e.g., ``1.3.6.1-oid``)

        **X-* Extensions** (Oracle-specific metadata):

        - ``X-ORIGIN`` - Source/origin of the attribute definition::

            X-ORIGIN 'Oracle Unified Directory Server'

        - ``X-SCHEMA-FILE`` - Schema file where attribute is defined::

            X-SCHEMA-FILE '99-user.ldif'

        - ``X-PATTERN`` - Regular expression pattern for value validation::

            X-PATTERN '^[a-zA-Z0-9]+$'

        - ``X-ENUM`` - Enumerated allowed values::

            X - ENUM("value1value2value3")

        - ``X-NAME`` - Alternative name for the attribute
        - ``X-ALIAS`` - Alias names for the attribute
        - ``X-OID`` - Alternative OID reference
        - ``X-FILE-REF`` - External file reference

        Validation Rules
        ----------------

        1. OIDs must be numeric or end with ``-oid`` suffix
        2. X-* extensions must be well-formed (structure check)
        3. SYNTAX must reference valid OID (format check)

        Args:
            attr: Parsed SchemaAttribute from RFC parser

        Returns:
            FlextResult[SchemaAttribute] - validated and metadata-enriched attribute

        References:
            - RFC 4512: LDAP Directory Information Models (Schema)
            - Oracle OUD Schema Management: https://docs.oracle.com/en/middleware/idm/unified-directory/14.1.2/oudag/managing-directory-schema.html

        """
        if not attr or not attr.oid:
            return FlextResult[m.Ldif.SchemaAttribute].ok(attr)

        oid = str(attr.oid)

        # Validate OID format
        oid_validation = self._validate_attribute_oid(oid)
        if oid_validation.is_failure:
            return FlextResult[m.Ldif.SchemaAttribute].fail(
                oid_validation.error or "OID validation failed",
            )

        is_valid_oud_oid = oid_validation.value

        # Store OID validation metadata in attribute metadata for tracking
        existing_metadata = attr.metadata
        if not existing_metadata:
            existing_metadata = m.Ldif.QuirkMetadata.create_for("oud")

        # Get existing extensions or create new dict
        current_extensions = (
            dict(existing_metadata.extensions) if existing_metadata.extensions else {}
        )

        # Track OID validation status using standardized MetadataKeys
        current_extensions[c.Ldif.MetadataKeys.SYNTAX_OID_VALID] = is_valid_oud_oid

        # Track if OID uses OUD extension format (-oid suffix)
        if oid.endswith("-oid"):
            current_extensions["oid_format_extension"] = True

        # Update attribute with metadata including extensions
        attr = attr.model_copy(
            update={
                "metadata": existing_metadata.model_copy(
                    update={"extensions": current_extensions},
                ),
            },
        )

        # Log if OUD-specific X-* extensions detected
        oud_extensions = self._collect_attribute_extensions(attr)
        if oud_extensions:
            logger.debug(
                "Attribute has OUD X-* extensions",
                attribute_name=attr.name,
                attribute_oid=attr.oid,
                extensions=oud_extensions,
                extension_count=len(oud_extensions),
            )

        return FlextResult[m.Ldif.SchemaAttribute].ok(attr)

    def _validate_objectclass_sup(
        self,
        oc: m.Ldif.SchemaObjectClass,
    ) -> FlextResult[bool]:
        """Validate objectClass SUP constraint for OUD.

        Args:
            oc: SchemaObjectClass to validate

        Returns:
            FlextResult indicating validation success or failure

        """
        sup = oc.sup
        if sup:
            sup_str = str(sup)
            # Check for multiple SUPs (RFC uses $ as separator)
            if "$" in sup_str:
                return FlextResult[bool].fail(
                    f"OUD objectClass '{oc.name}' has multiple SUPs: "
                    f"{sup_str}. "
                    "OUD only allows single SUP (use AUXILIARY classes "
                    "for additional features).",
                )
        return FlextResult[bool].ok(True)

    def _validate_objectclass_oid_and_sup(
        self,
        oc: m.Ldif.SchemaObjectClass,
    ) -> FlextResult[m.Ldif.SchemaObjectClass]:
        """Validate ObjectClass OID and SUP OID formats.

        Args:
            oc: SchemaObjectClass to validate

        Returns:
            FlextResult with validated objectClass or error

        """
        # Validate ObjectClass OID format
        if oc and oc.oid:
            oid_str = str(oc.oid)
            oid_validation = self._validate_attribute_oid(oid_str)
            if oid_validation.is_failure:
                return FlextResult[m.Ldif.SchemaObjectClass].fail(
                    f"ObjectClass OID validation failed: {oid_validation.error}",
                )

            is_valid_oud_oid = oid_validation.value

            # Track OID validation in metadata
            existing_oc_metadata = oc.metadata
            if not existing_oc_metadata:
                existing_oc_metadata = m.Ldif.QuirkMetadata.create_for(
                    "oud",
                )

            oc_extensions = (
                dict(existing_oc_metadata.extensions)
                if existing_oc_metadata.extensions
                else {}
            )

            oc_extensions[c.Ldif.MetadataKeys.SYNTAX_OID_VALID] = is_valid_oud_oid

            if oid_str.endswith("-oid"):
                oc_extensions["oid_format_extension"] = True

            oc = oc.model_copy(
                update={
                    "metadata": existing_oc_metadata.model_copy(
                        update={"extensions": oc_extensions},
                    ),
                },
            )

        # Validate SUP OID if it's an OID format
        sup = oc.sup
        if sup:
            sup_str = str(sup)
            if sup_str and "." in sup_str and sup_str[0].isdigit():
                sup_validation = self._validate_attribute_oid(sup_str)
                if sup_validation.is_failure:
                    return FlextResult[m.Ldif.SchemaObjectClass].fail(
                        f"ObjectClass SUP OID validation failed: {sup_validation.error}",
                    )

        return FlextResult[m.Ldif.SchemaObjectClass].ok(oc)

    def _hook_post_parse_objectclass(
        self,
        oc: m.Ldif.SchemaObjectClass,
    ) -> FlextResult[m.Ldif.SchemaObjectClass]:
        """Hook: Validate OUD-specific objectClass features after RFC parsing.

        RFC vs OUD Behavior Differences
        ================================

        **RFC Baseline** (in rfc.py):
        - No post-parse hook (passes objectClass through unchanged)
        - Allows multiple superiors (SUP class1 $ class2)
        - Standard RFC 4512 objectClass parsing only

        **OUD Override** (this method):
        - Enforces OUD SingleSUP constraint
        - Validates OUD-specific objectClass rules
        - Logs validation results for debugging

        OUD ObjectClass Constraints
        ---------------------------

        **SingleSUP Constraint** (OUD-specific restriction):

        - **RFC 4512 allows**: ``SUP person $ inetOrgPerson`` (multiple superiors)
        - **OUD requires**: ``SUP person`` (single superior only)

        This is because OUD uses a stricter inheritance model. To add
        functionality from multiple classes, use AUXILIARY classes::

            # RFC allows (OUD rejects):
            objectClasses: ( 1.2.3.4 NAME 'myClass'
              SUP person $ organizationalPerson
              STRUCTURAL ... )

            # OUD requires:
            objectClasses: ( 1.2.3.4 NAME 'myClass'
              SUP person
              AUXILIARY ( organizationalPerson )
              STRUCTURAL ... )

        **X-* Extensions** (Oracle-specific metadata):

        - ``X-ORIGIN`` - Source/origin of the objectClass definition
        - ``X-SCHEMA-FILE`` - Schema file where objectClass is defined
        - ``X-ENUM`` - Enumerated allowed values for attributes
        - ``X-PATTERN`` - Validation patterns

        **No Multiple Structural Chains**:

        OUD enforces that each entry can only have one structural objectClass
        chain. This is validated at schema load time, not during parsing.

        Validation Rules
        ----------------

        1. SUP must be single (not multiple separated by ``$``)
        2. X-* extensions must be well-formed
        3. MUST/MAY attributes validated in ``validate_objectclass_dependencies``

        Args:
            oc: Parsed SchemaObjectClass from RFC parser

        Returns:
            FlextResult[SchemaObjectClass] - validated objectClass

        References:
            - RFC 4512: LDAP Directory Information Models (Schema)
            - Oracle OUD Schema Management: https://docs.oracle.com/en/middleware/idm/unified-directory/14.1.2/oudag/managing-directory-schema.html

        """
        if not oc:
            return FlextResult[m.Ldif.SchemaObjectClass].fail(
                "ObjectClass is None or empty",
            )

        # Validate SingleSUP constraint (OUD restriction)
        sup_validation = self._validate_objectclass_sup(oc)
        if sup_validation.is_failure:
            return FlextResult[m.Ldif.SchemaObjectClass].fail(
                sup_validation.error or "SUP validation failed",
            )

        # Validate ObjectClass OID and SUP OID formats
        oid_and_sup_validation = self._validate_objectclass_oid_and_sup(oc)
        if oid_and_sup_validation.is_failure:
            return FlextResult[m.Ldif.SchemaObjectClass].fail(
                oid_and_sup_validation.error or "OID validation failed",
            )

        oc = oid_and_sup_validation.value

        # Log validation success
        logger.debug(
            "ObjectClass validated: SingleSUP constraint OK",
            objectclass_name=oc.name,
            objectclass_oid=oc.oid,
            sup_value=oc.sup,
        )

        return FlextResult[m.Ldif.SchemaObjectClass].ok(oc)

    def _apply_attribute_matching_rule_transforms(
        self,
        attr_data: m.Ldif.SchemaAttribute,
    ) -> tuple[str | None, str | None]:
        """Apply OUD-specific matching rule transformations.

        Args:
            attr_data: SchemaAttribute with original matching rules

        Returns:
            Tuple of (fixed_equality, fixed_substr)

        """
        fixed_equality = attr_data.equality
        fixed_substr = attr_data.substr

        # OUD QUIRK: caseIgnoreSubstringsMatch must be SUBSTR, not EQUALITY
        if fixed_equality == "caseIgnoreSubstringsMatch":
            logger.warning(
                "Moved caseIgnoreSubstringsMatch from EQUALITY to SUBSTR",
                attribute_name=attr_data.name,
            )
            fixed_substr = "caseIgnoreSubstringsMatch"
            fixed_equality = None

        # OUD QUIRK: Remove redundant EQUALITY when SUBSTR is caseIgnoreSubstringsMatch
        if (
            fixed_substr == "caseIgnoreSubstringsMatch"
            and fixed_equality == "caseIgnoreMatch"
        ):
            logger.warning(
                "OUD QUIRK: FOUND REDUNDANT EQUALITY+SUBSTR - Removing redundant EQUALITY",
                attribute_name=attr_data.name,
                attribute_oid=attr_data.oid,
                original_equality=fixed_equality,
                original_substr=fixed_substr,
                new_equality=None,
                new_substr="caseIgnoreSubstringsMatch",
                redundant_equality="caseIgnoreMatch",
            )
            fixed_equality = None

        # Apply invalid SUBSTR rule replacements
        original_substr = fixed_substr
        fixed_substr = FlextLdifUtilitiesSchema.replace_invalid_substr_rule(
            fixed_substr,
            FlextLdifServersOudConstants.INVALID_SUBSTR_RULES,
        )
        if fixed_substr != original_substr:
            logger.warning(
                "Replaced invalid SUBSTR rule",
                attribute_name=attr_data.name,
                attribute_oid=attr_data.oid,
                original_substr=original_substr,
                replacement_substr=fixed_substr,
            )

        return fixed_equality, fixed_substr

    def _apply_attribute_oid_metadata(
        self,
        attr: m.Ldif.SchemaAttribute,
    ) -> m.Ldif.SchemaAttribute:
        """Apply OID validation and tracking metadata to attribute.

        Args:
            attr: SchemaAttribute to update with OID metadata

        Returns:
            Updated attribute with OID validation metadata

        """
        if not attr or not attr.oid:
            return attr

        oid_str = str(attr.oid)
        oid_validation = self._validate_attribute_oid(oid_str)
        if oid_validation.is_failure:
            return attr  # Return unchanged if validation fails

        is_valid_oud_oid = oid_validation.value

        # Track OID validation in metadata
        existing_metadata = attr.metadata
        if not existing_metadata:
            existing_metadata = m.Ldif.QuirkMetadata.create_for("oud")

        current_extensions = (
            dict(existing_metadata.extensions) if existing_metadata.extensions else {}
        )

        current_extensions[c.Ldif.MetadataKeys.SYNTAX_OID_VALID] = is_valid_oud_oid

        if oid_str.endswith("-oid"):
            current_extensions["oid_format_extension"] = True

        return attr.model_copy(
            update={
                "metadata": existing_metadata.model_copy(
                    update={"extensions": current_extensions},
                ),
            },
        )

    def _transform_attribute_for_write(
        self,
        attr_data: m.Ldif.SchemaAttribute,
    ) -> m.Ldif.SchemaAttribute:
        """Apply OUD-specific attribute transformations before writing.

        RFC vs OUD Behavior Differences
        ================================

        **RFC Baseline** (in rfc.py ``_transform_attribute_for_write``):
        - Returns attribute unchanged (no transformation)
        - No matching rule validation or correction

        **OUD Override** (this method):
        - Validates and corrects matching rule assignments
        - Applies OUD-specific EQUALITY/SUBSTR rule fixes
        - Handles invalid SUBSTR rule replacements
        - Tracks boolean attributes for special handling

        OUD Matching Rule Quirks
        ------------------------

        **QUIRK 1: caseIgnoreSubstringsMatch in EQUALITY**

        Some source servers (e.g., OID) incorrectly place ``caseIgnoreSubstringsMatch``
        in the EQUALITY position. OUD requires it in SUBSTR::

            # Source (invalid for OUD):
            EQUALITY caseIgnoreSubstringsMatch SUBSTR caseIgnoreSubstringsMatch

            # Transformed (OUD-compatible):
            SUBSTR caseIgnoreSubstringsMatch

        **QUIRK 2: Redundant EQUALITY + SUBSTR**

        OUD rejects redundant ``caseIgnoreMatch`` EQUALITY when ``caseIgnoreSubstringsMatch``
        SUBSTR is present. This affects 135+ attributes exported from OID::

            # Source (rejected by OUD):
            EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch

            # Transformed (accepted by OUD):
            SUBSTR caseIgnoreSubstringsMatch

        **QUIRK 3: Invalid SUBSTR Rules**

        Some SUBSTR rules are not supported by OUD and must be replaced
        or removed. See ``Constants.INVALID_SUBSTR_RULES`` for mappings.

        **Boolean Attribute Tracking**

        Boolean attributes (defined in ``Constants.BOOLEAN_ATTRIBUTES``) are
        tracked for special handling during schema write operations.

        Args:
            attr_data: Parsed SchemaAttribute model

        Returns:
            Transformed SchemaAttribute with OUD-specific fixes applied

        References:
            - Oracle OUD Schema Management: https://docs.oracle.com/en/middleware/idm/unified-directory/14.1.2/oudag/managing-directory-schema.html

        """
        # Apply matching rule transformations
        fixed_equality, fixed_substr = self._apply_attribute_matching_rule_transforms(
            attr_data,
        )

        # Check if this is a boolean attribute for special handling
        is_boolean = FlextLdifUtilitiesSchema.is_boolean_attribute(
            attr_data.name,
            set(FlextLdifServersOudConstants.BOOLEAN_ATTRIBUTES),
        )
        if is_boolean:
            logger.debug(
                "Identified boolean attribute",
                attribute_name=attr_data.name,
                attribute_oid=attr_data.oid,
            )

        # Update attribute with transformed matching rules
        updated_attr = attr_data.model_copy(
            update={
                "equality": fixed_equality,
                "substr": fixed_substr,
            },
        )

        # Apply OID validation metadata
        return self._apply_attribute_oid_metadata(updated_attr)

    def extract_schemas_from_ldif(
        self,
        ldif_content: str,
        *,
        validate_dependencies: bool = True,  # OUD defaults to True (needs validation)
    ) -> FlextResult[
        dict[
            str,
            list[m.Ldif.SchemaAttribute]
            | list[m.Ldif.SchemaObjectClass],
        ]
    ]:
        """Extract and parse all schema definitions from LDIF content.

        OUD-specific implementation: Uses base template method with dependency
        validation enabled by default. The template method handles attribute
        extraction, available_attributes set building, and objectClass extraction.

        Strategy pattern: OUD requires dependency validation to ensure all
        attributes referenced in objectClass MUST/MAY lists are available.

        Filters only Oracle internal objectClasses that OUD already provides built-in.
        All custom objectClasses pass through, including those with unresolved
        dependencies (OUD will validate at startup).

        Args:
            ldif_content: Raw LDIF content containing schema definitions
            validate_dependencies: Enable dependency validation (default: True for OUD)

        Returns:
            FlextResult with dict containing schema data
            (ATTRIBUTES and objectclasses lists)

        """
        # Use base template method with OUD's dependency validation
        # This replaces 66 lines of duplicated code with a 3-line call
        return super().extract_schemas_from_ldif(
            ldif_content,
            validate_dependencies=validate_dependencies,
        )
