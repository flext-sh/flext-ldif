"""RFC 4512 Compliant Server Quirks - Base LDAP Schema/ACL/Entry Implementation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Provides RFC-compliant baseline implementations for LDAP directory operations.
All server-specific quirks (OID, OUD, OpenLDAP, etc.) extend this RFC base.

Architecture:
    - RFC baseline: Strict RFC 2849/4512 compliance
    - Server quirks: Extend RFC with server-specific enhancements
    - No cross-server dependencies: Each server is isolated
    - Generic conversions: All via RFC intermediate format

References:
    - RFC 2849: LDIF Format Specification
    - RFC 4512: LDAP Directory Information Models

"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Self, cast, overload

from flext_core import (
    FlextLogger,
    FlextResult,
    FlextTypes,
)

# Metadata access via m.Ldif namespace from models import
from flext_ldif._utilities.metadata import FlextLdifUtilitiesMetadata
from flext_ldif._utilities.object_class import FlextLdifUtilitiesObjectClass
from flext_ldif._utilities.schema import FlextLdifUtilitiesSchema
from flext_ldif.constants import c
from flext_ldif.models import m
from flext_ldif.servers._base.schema import FlextLdifServersBaseSchema
from flext_ldif.servers.base import FlextLdifServersBase
from flext_ldif.typings import t

logger = FlextLogger(__name__)


class FlextLdifServersRfcSchema(FlextLdifServersBase.Schema):
    """RFC 4512 Compliant Schema Quirk - STRICT Implementation.

    RFC 4512 ABNF Grammar (Section 4.1):
    ====================================

    AttributeTypeDescription (Section 4.1.2):
    -----------------------------------------
    AttributeTypeDescription = LPAREN WSP
        numericoid                    ; object identifier
        [ SP "NAME" SP qdescrs ]      ; short names (e.g., 'cn', 'mail')
        [ SP "DESC" SP qdstring ]     ; description
        [ SP "OBSOLETE" ]             ; not active
        [ SP "SUP" SP oid ]           ; supertype
        [ SP "EQUALITY" SP oid ]      ; equality matching rule
        [ SP "ORDERING" SP oid ]      ; ordering matching rule
        [ SP "SUBSTR" SP oid ]        ; substring matching rule
        [ SP "SYNTAX" SP noidlen ]    ; value syntax (OID{len})
        [ SP "SINGLE-VALUE" ]         ; single-value constraint
        [ SP "COLLECTIVE" ]           ; collective attribute
        [ SP "NO-USER-MODIFICATION" ] ; not user modifiable
        [ SP "USAGE" SP usage ]       ; usage classification
        extensions WSP RPAREN

    ObjectClassDescription (Section 4.1.1):
    ---------------------------------------
    ObjectClassDescription = LPAREN WSP
        numericoid                 ; object identifier
        [ SP "NAME" SP qdescrs ]   ; short names
        [ SP "DESC" SP qdstring ]  ; description
        [ SP "OBSOLETE" ]          ; not active
        [ SP "SUP" SP oids ]       ; superior classes
        [ SP kind ]                ; ABSTRACT / STRUCTURAL / AUXILIARY
        [ SP "MUST" SP oids ]      ; required attributes
        [ SP "MAY" SP oids ]       ; allowed attributes
        extensions WSP RPAREN

    Common Productions:
    -------------------
    numericoid = number 1*( DOT number )
    oid = descr / numericoid
    oids = oid / ( LPAREN WSP oidlist WSP RPAREN )
    qdescrs = qdescr / ( LPAREN WSP qdescrlist WSP RPAREN )
    qdescr = SQUOTE descr SQUOTE
    noidlen = numericoid [ LCURLY len RCURLY ]
    usage = "userApplications" / "directoryOperation" /
            "distributedOperation" / "dSAOperation"
    kind = "ABSTRACT" / "STRUCTURAL" / "AUXILIARY"

    Valid Usage Values (c.Ldif.SchemaUsage enum):
    - userApplications     (default for user attributes)
    - directoryOperation   (operational attributes)
    - distributedOperation (distributed across DSAs)
    - dSAOperation         (DSA-specific attributes)

    Valid ObjectClass Kinds (c.Ldif.Rfc.SCHEMA_KINDS):
    - ABSTRACT    (cannot be instantiated directly)
    - STRUCTURAL  (can be instantiated, single per entry)
    - AUXILIARY   (can be added to entries with structural)
    """

    def __init__(
        self,
        schema_service: object | None = None,
        parent_quirk: object | None = None,
        **kwargs: FlextTypes.GeneralValueType,
    ) -> None:
        """Initialize RFC schema quirk service.

        Args:
            schema_service: Injected FlextLdifSchema service (optional)
            parent_quirk: Reference to parent quirk (optional)
            **kwargs: Passed to parent class

        """
        # Pass schema_service to parent explicitly
        # Base class stores as self._schema_service
        # Note: _parent_quirk is stored via object.__setattr__ after initialization
        # to avoid Pydantic validation errors (it's not a Pydantic field)
        # Business Rule: Filter parent_quirk and _schema_service from kwargs to avoid type errors
        # Implication: parent_quirk and _schema_service are handled separately, not via Pydantic fields
        filtered_kwargs: dict[str, FlextTypes.GeneralValueType] = {
            k: v
            for k, v in kwargs.items()
            if k not in {"_parent_quirk", "parent_quirk", "_schema_service"}
        }
        # Business Rule: Call parent Schema.__init__ which accepts _schema_service and _parent_quirk
        # Note: parent_quirk is filtered from kwargs and handled separately after __init__
        # schema_service is already properly typed by the constructor
        schema_service_typed: object = schema_service

        # Call base class __init__ directly to avoid mypy inference issues through nested class
        FlextLdifServersBaseSchema.__init__(
            self,
            _schema_service=schema_service_typed,
            _parent_quirk=None,
            **filtered_kwargs,
        )
        # Store _parent_quirk after initialization using object.__setattr__
        if parent_quirk is not None:
            object.__setattr__(self, "_parent_quirk", parent_quirk)

    def can_handle_attribute(
        self,
        attr_definition: str | m.Ldif.SchemaAttribute,
    ) -> bool:
        """Check if RFC quirk can handle attribute definitions (abstract impl).

        Accepts raw string or SchemaAttribute model.
        """
        _ = (self, attr_definition)
        return True

    def can_handle_objectclass(
        self,
        oc_definition: str | m.Ldif.SchemaObjectClass,
    ) -> bool:
        """Check if RFC quirk can handle objectClass definitions (abstract impl).

        Accepts raw string or SchemaObjectClass model.
        """
        _ = (self, oc_definition)
        return True

    def should_filter_out_attribute(
        self,
        _attribute: m.Ldif.SchemaAttribute,
    ) -> bool:
        """RFC quirk does not filter attributes.

        Args:
            _attribute: SchemaAttribute model (unused)

        Returns:
            False

        """
        _ = self
        return False

    def should_filter_out_objectclass(
        self,
        _objectclass: m.Ldif.SchemaObjectClass,
    ) -> bool:
        """RFC quirk does not filter objectClasses.

        Args:
            _objectclass: SchemaObjectClass model (unused)

        Returns:
            False

        """
        _ = (self, _objectclass)
        return False

    # ===== HELPER METHODS FOR RFC SCHEMA PARSING =====

    @staticmethod
    def _build_attribute_metadata(
        attr_definition: str,
        syntax: str | None,
        syntax_validation_error: str | None,
        attribute_oid: str | None = None,
        equality_oid: str | None = None,
        ordering_oid: str | None = None,
        substr_oid: str | None = None,
        sup_oid: str | None = None,
        _server_type: str | None = None,
    ) -> m.Ldif.QuirkMetadata | None:
        """Build metadata for attribute including extensions and OID validation.

        Delegates to base implementation with RFC server type.

        Args:
            attr_definition: Original attribute definition
            syntax: Syntax OID (optional)
            syntax_validation_error: Validation error for syntax OID if any
            attribute_oid: Attribute OID (optional, for validation tracking)
            equality_oid: Equality matching rule OID (optional)
            ordering_oid: Ordering matching rule OID (optional)
            substr_oid: Substring matching rule OID (optional)
            sup_oid: SUP OID (optional)
            _server_type: Server type identifier (unused, always RFC)

        Returns:
            QuirkMetadata or None

        """
        # Use passed server_type or default to RFC
        server_type_to_use = _server_type or "rfc"
        return FlextLdifServersBase.Schema.build_attribute_metadata(
            attr_definition,
            syntax,
            syntax_validation_error,
            attribute_oid=attribute_oid,
            equality_oid=equality_oid,
            ordering_oid=ordering_oid,
            substr_oid=substr_oid,
            sup_oid=sup_oid,
            server_type=server_type_to_use,
        )

    # ===== RFC 4512 PARSING METHODS =====

    def _parse_attribute(
        self,
        attr_definition: str,
    ) -> FlextResult[m.Ldif.SchemaAttribute]:
        """Parse RFC 4512 attribute definition using generalized parser.

        Args:
            attr_definition: RFC 4512 attribute definition string

        Returns:
            FlextResult with parsed SchemaAttribute model

        """
        # Get server type (fast-fail if not available)
        self._get_server_type()

        # Wrap method to match ParsePartsHook protocol
        # ParsePartsHook expects dict[str, str | bool | None]
        def parse_parts_hook(
            definition: str,
        ) -> dict[str, str | bool | None]:
            # Use FlextLdifUtilitiesSchema.parse_attribute which returns FlextResult
            # Extract only the fields needed by ParsePartsHook
            parse_result = FlextLdifUtilitiesSchema.parse_attribute(definition)
            if parse_result.is_failure:
                # Return empty dict on failure (maintains existing behavior)
                return {}
            parsed = parse_result.value
            # Type narrowing: cast to expected type
            return cast("dict[str, str | bool | None]", parsed)

        # Use FlextLdifUtilitiesSchema.parse_attribute directly
        # (FlextLdifUtilities.Ldif.Parsers.Attribute.parse was removed to break circular imports)
        parse_result_temp = FlextLdifUtilitiesSchema.parse_attribute(attr_definition)
        if parse_result_temp.is_failure:
            return parse_result_temp

        parse_result_raw = parse_result_temp.value
        # Type narrowing: parse_attribute returns dict, convert to SchemaAttribute
        parse_result: FlextResult[m.Ldif.SchemaAttribute] = FlextResult[
            m.Ldif.SchemaAttribute
        ].ok(m.Ldif.SchemaAttribute.model_validate(parse_result_raw))

        # Invoke post-parse hook for server-specific customization
        if parse_result.is_failure:
            return parse_result

        return self._hook_post_parse_attribute(parse_result.value)

    def _parse_attribute_core(
        self,
        attr_definition: str,
    ) -> FlextResult[m.Ldif.SchemaAttribute]:
        """Core RFC 4512 attribute parsing per Section 4.1.2.

        RFC 4512 ABNF (AttributeTypeDescription):
        =========================================
        AttributeTypeDescription = LPAREN WSP
            numericoid                    ; object identifier
            [ SP "NAME" SP qdescrs ]      ; short names
            [ SP "DESC" SP qdstring ]     ; description
            [ SP "OBSOLETE" ]             ; not active
            [ SP "SUP" SP oid ]           ; supertype
            [ SP "EQUALITY" SP oid ]      ; equality matching rule
            [ SP "ORDERING" SP oid ]      ; ordering matching rule
            [ SP "SUBSTR" SP oid ]        ; substring matching rule
            [ SP "SYNTAX" SP noidlen ]    ; value syntax
            [ SP "SINGLE-VALUE" ]         ; single-value constraint
            [ SP "COLLECTIVE" ]           ; collective attribute
            [ SP "NO-USER-MODIFICATION" ] ; not user modifiable
            [ SP "USAGE" SP usage ]       ; usage classification
            extensions WSP RPAREN

        Delegates parsing to FlextLdifUtilitiesSchema.parse_attribute()
        for SRP compliance and code reuse.

        Args:
            attr_definition: RFC 4512 attribute definition string

        Returns:
            FlextResult with parsed SchemaAttribute model

        """
        try:
            # Delegate parsing to centralized utility (SRP)
            parsed_result = self.parse_attribute(attr_definition)
            if parsed_result.is_failure:
                return parsed_result
            parsed = (
                parsed_result.value.model_dump()
                if hasattr(parsed_result.value, "model_dump")
                else {}
            )

            # Extract syntax validation error from parsed result
            syntax_validation_error: str | None = None
            syntax_validation = parsed.get("syntax_validation")
            if syntax_validation and isinstance(syntax_validation, dict):
                error_value = syntax_validation.get(
                    c.Ldif.MetadataKeys.SYNTAX_VALIDATION_ERROR,
                )
                if isinstance(error_value, str):
                    syntax_validation_error = error_value

            # Type-safe extraction with narrowing for _build_attribute_metadata call
            # Track all OIDs: attribute, syntax, matching rules
            # (equality, ordering, substr), and SUP
            syntax_val = parsed.get("syntax")
            syntax_for_meta: str | None = (
                syntax_val if isinstance(syntax_val, str | type(None)) else None
            )

            oid_val = parsed.get("oid")
            oid_for_meta: str | None = (
                oid_val if isinstance(oid_val, str | type(None)) else None
            )

            eq_val = parsed.get("equality")
            eq_for_meta: str | None = (
                eq_val if isinstance(eq_val, str | type(None)) else None
            )

            ord_val = parsed.get("ordering")
            ord_for_meta: str | None = (
                ord_val if isinstance(ord_val, str | type(None)) else None
            )

            sub_val = parsed.get("substr")
            sub_for_meta: str | None = (
                sub_val if isinstance(sub_val, str | type(None)) else None
            )

            sup_val = parsed.get("sup")
            sup_for_meta: str | None = (
                sup_val if isinstance(sup_val, str | type(None)) else None
            )

            # Get server type from the actual server class (not hardcoded "rfc")
            server_type_value = self._get_server_type()
            metadata = self._build_attribute_metadata(
                attr_definition,
                syntax_for_meta,
                syntax_validation_error,
                attribute_oid=oid_for_meta,
                equality_oid=eq_for_meta,
                ordering_oid=ord_for_meta,
                substr_oid=sub_for_meta,
                sup_oid=sup_for_meta,
                _server_type=server_type_value,
            )

            # Type-safe extraction with narrowing
            oid_value = parsed["oid"]
            oid: str = oid_value if isinstance(oid_value, str) else str(oid_value or "")

            name_value = parsed["name"]
            name: str = (
                name_value
                if isinstance(name_value, str)
                else (str(name_value) if name_value else "")
            )

            desc_value = parsed["desc"]
            desc: str | None = (
                desc_value
                if isinstance(desc_value, str)
                else (
                    str(desc_value) if desc_value and desc_value is not True else None
                )
            )

            syntax_value = parsed["syntax"]
            syntax: str | None = (
                syntax_value
                if isinstance(syntax_value, str)
                else (
                    str(syntax_value)
                    if syntax_value and syntax_value is not True
                    else None
                )
            )

            length_value = parsed["length"]
            if isinstance(length_value, int):
                length: int | None = length_value
            elif isinstance(length_value, str) and length_value:
                length = int(length_value)
            else:
                length = None

            equality_value = parsed["equality"]
            equality: str | None = (
                equality_value
                if isinstance(equality_value, str)
                else (
                    str(equality_value)
                    if equality_value and equality_value is not True
                    else None
                )
            )

            ordering_value = parsed["ordering"]
            ordering: str | None = (
                ordering_value
                if isinstance(ordering_value, str)
                else (
                    str(ordering_value)
                    if ordering_value and ordering_value is not True
                    else None
                )
            )

            substr_value = parsed["substr"]
            substr: str | None = (
                substr_value
                if isinstance(substr_value, str)
                else (
                    str(substr_value)
                    if substr_value and substr_value is not True
                    else None
                )
            )

            single_value_value = parsed["single_value"]
            single_value: bool = (
                isinstance(single_value_value, bool) and single_value_value
            )

            no_user_mod_value = parsed["no_user_modification"]
            no_user_modification: bool = (
                isinstance(no_user_mod_value, bool) and no_user_mod_value
            )

            sup_value = parsed["sup"]
            sup: str | None = (
                sup_value
                if isinstance(sup_value, str)
                else (str(sup_value) if sup_value and sup_value is not True else None)
            )

            usage_value = parsed["usage"]
            usage: str | None = (
                usage_value
                if isinstance(usage_value, str)
                else (
                    str(usage_value)
                    if usage_value and usage_value is not True
                    else None
                )
            )

            attribute = m.Ldif.SchemaAttribute(
                oid=oid,
                name=name,
                desc=desc,
                syntax=syntax,
                length=length,
                equality=equality,
                ordering=ordering,
                substr=substr,
                single_value=single_value,
                no_user_modification=no_user_modification,
                sup=sup,
                usage=usage,
                metadata=metadata,
                x_origin=None,
                x_file_ref=None,
                x_name=None,
                x_alias=None,
                x_oid=None,
            )

            return FlextResult[m.Ldif.SchemaAttribute].ok(attribute)

        except (ValueError, TypeError, AttributeError) as e:
            logger.exception("RFC attribute parsing exception")
            return FlextResult[m.Ldif.SchemaAttribute].fail(
                f"RFC attribute parsing failed: {e}",
            )

    def _parse_objectclass(
        self,
        oc_definition: str,
    ) -> FlextResult[m.Ldif.SchemaObjectClass]:
        """Parse RFC 4512 objectClass definition using generalized parser.

        Args:
            oc_definition: ObjectClass definition string

        Returns:
            FlextResult with parsed SchemaObjectClass model

        """
        # Get server type (fast-fail if not available)
        server_type = self._get_server_type()

        # Wrap method to match ParseCoreHook protocol
        def parse_parts_hook(
            definition: str,
        ) -> dict[str, str | list[str] | None]:
            # Use FlextLdifUtilitiesSchema.parse_objectclass which returns dict directly
            # Extract only the fields needed by ParsePartsHook
            parsed = FlextLdifUtilitiesSchema.parse_objectclass(definition)
            # Type narrowing: cast to expected type
            return cast("dict[str, str | list[str] | None]", parsed)

        # DSL: Use config-based parse signature
        # ObjectClass.parse accepts config=None with **kwargs
        parse_result: FlextResult[m.Ldif.SchemaObjectClass] = (
            FlextLdifUtilitiesObjectClass.parse(
                definition=oc_definition,
                server_type=server_type,
                parse_parts_hook=parse_parts_hook,
            )
        )

        # Invoke post-parse hook for server-specific customization
        if parse_result.is_failure:
            return parse_result

        return self._hook_post_parse_objectclass(parse_result.value)

    def _validate_oid_list(
        self,
        oids: list[str] | None,
        oid_type: str,
        metadata_extensions: dict[str, list[str] | str | bool | None],
    ) -> None:
        """Validate OID list and track in metadata."""
        if not oids or not isinstance(oids, (list, tuple)):
            return
        for idx, oid in enumerate(oids):
            if oid and isinstance(oid, str):
                FlextLdifServersBase.Schema.validate_and_track_oid(
                    metadata_extensions,
                    oid,
                    f"objectClass {oid_type}[{idx}]",
                )

    def _build_objectclass_metadata(
        self,
        oc_definition: str,
        metadata_extensions: dict[str, list[str] | str | bool | None],
    ) -> m.Ldif.QuirkMetadata:
        """Build objectClass metadata with extensions."""
        server_type: str = "rfc"
        metadata = m.Ldif.QuirkMetadata(
            quirk_type=server_type,
            extensions=m.Ldif.DynamicMetadata(**metadata_extensions)
            if metadata_extensions
            else m.Ldif.DynamicMetadata(),
        )
        FlextLdifUtilitiesMetadata.preserve_schema_formatting(
            metadata,
            oc_definition,
        )
        return metadata

    def _parse_objectclass_core(
        self,
        oc_definition: str,
    ) -> FlextResult[m.Ldif.SchemaObjectClass]:
        """Core RFC 4512 objectClass parsing per Section 4.1.1.

        Delegates parsing to FlextLdifUtilitiesSchema.parse_objectclass()
        for SRP compliance and code reuse.

        """
        try:
            parsed = FlextLdifUtilitiesSchema.parse_objectclass(oc_definition)

            metadata_extensions_raw = parsed["metadata_extensions"]
            metadata_extensions_raw_dict: dict[
                str,
                str | int | float | bool | datetime | list[str] | None,
            ] = (
                metadata_extensions_raw
                if isinstance(metadata_extensions_raw, dict)
                else {}
            )
            # Convert to expected type for methods that require it
            metadata_extensions: dict[str, list[str] | str | bool | None] = {}
            for key, value in metadata_extensions_raw_dict.items():
                if isinstance(value, (str, bool, list)) or value is None:
                    metadata_extensions[key] = value
                elif isinstance(value, (int, float)):
                    metadata_extensions[key] = str(value)
                elif isinstance(value, datetime):
                    metadata_extensions[key] = value.isoformat()
                else:
                    metadata_extensions[key] = str(value)
            metadata_extensions[c.Ldif.MetadataKeys.ORIGINAL_FORMAT] = (
                oc_definition.strip()
            )
            metadata_extensions[c.Ldif.MetadataKeys.SCHEMA_ORIGINAL_STRING_COMPLETE] = (
                oc_definition
            )

            objectclass_oid = parsed.get("oid")
            if objectclass_oid is None or isinstance(objectclass_oid, str):
                FlextLdifServersBase.Schema.validate_and_track_oid(
                    metadata_extensions,
                    objectclass_oid,
                    "objectClass",
                )

            objectclass_sup_oid = parsed.get("sup")
            if objectclass_sup_oid is None or isinstance(objectclass_sup_oid, str):
                FlextLdifServersBase.Schema.validate_and_track_oid(
                    metadata_extensions,
                    objectclass_sup_oid,
                    "objectClass SUP",
                )

            # Narrow must and may lists before passing to _validate_oid_list
            must_val = parsed.get("must")
            must_list: list[str] | None = (
                must_val if isinstance(must_val, list) else None
            )
            self._validate_oid_list(must_list, "MUST", metadata_extensions)

            may_val = parsed.get("may")
            may_list: list[str] | None = may_val if isinstance(may_val, list) else None
            self._validate_oid_list(may_list, "MAY", metadata_extensions)

            metadata = self._build_objectclass_metadata(
                oc_definition,
                metadata_extensions,
            )

            # Type-safe extraction with narrowing for SchemaObjectClass
            oc_oid_value = parsed["oid"]
            oc_oid: str = (
                oc_oid_value
                if isinstance(oc_oid_value, str)
                else str(oc_oid_value or "")
            )

            oc_name_value = parsed["name"]
            oc_name: str = (
                oc_name_value
                if isinstance(oc_name_value, str)
                else (str(oc_name_value) if oc_name_value else "")
            )

            oc_desc_value = parsed["desc"]
            oc_desc: str | None = (
                oc_desc_value
                if isinstance(oc_desc_value, str)
                else (
                    str(oc_desc_value)
                    if oc_desc_value and oc_desc_value is not True
                    else None
                )
            )

            oc_sup_value = parsed["sup"]
            if isinstance(oc_sup_value, str):
                oc_sup: str | list[str] | None = oc_sup_value
            elif isinstance(oc_sup_value, list):
                oc_sup = oc_sup_value
            else:
                oc_sup = None

            oc_kind_value = parsed["kind"]
            oc_kind: str = (
                oc_kind_value
                if isinstance(oc_kind_value, str)
                else str(oc_kind_value or "STRUCTURAL")
            )

            oc_must_value = parsed["must"]
            oc_must: list[str] | None = (
                oc_must_value if isinstance(oc_must_value, list) else None
            )

            oc_may_value = parsed["may"]
            oc_may: list[str] | None = (
                oc_may_value if isinstance(oc_may_value, list) else None
            )

            objectclass = m.Ldif.SchemaObjectClass(
                oid=oc_oid,
                name=oc_name,
                desc=oc_desc,
                sup=oc_sup,
                kind=oc_kind,
                must=oc_must,
                may=oc_may,
                metadata=metadata,
            )

            return FlextResult[m.Ldif.SchemaObjectClass].ok(objectclass)

        except (ValueError, TypeError, AttributeError) as e:
            logger.exception("RFC objectClass parsing exception")
            return FlextResult[m.Ldif.SchemaObjectClass].fail(
                f"RFC objectClass parsing failed: {e}",
            )

    # Schema conversion methods eliminated - use universal parse/write pipeline

    def _transform_objectclass_for_write(
        self,
        oc_data: m.Ldif.SchemaObjectClass,
    ) -> m.Ldif.SchemaObjectClass:
        """Hook for subclasses to transform objectClass before writing."""
        return oc_data

    def _post_write_objectclass(self, written_str: str) -> str:
        """Hook for subclasses to transform written objectClass string."""
        return written_str

    def _transform_attribute_for_write(
        self,
        attr_data: m.Ldif.SchemaAttribute,
    ) -> m.Ldif.SchemaAttribute:
        """Hook for subclasses to transform attribute before writing."""
        return attr_data

    def _post_write_attribute(self, written_str: str) -> str:
        """Hook for subclasses to transform written attribute string."""
        return written_str

    def _build_attribute_parts(
        # Import here to avoid circular import
        # Import here to avoid circular import
        self,
        attr_data: m.Ldif.SchemaAttribute,
    ) -> list[str]:
        """Build RFC attribute definition parts.

        Delegates to FlextLdifUtilitiesSchema.build_attribute_parts_with_metadata()
        for SRP compliance. Restores original formatting from metadata when
        available for zero data loss (perfect round-trip).

        Args:
            attr_data: SchemaAttribute model to serialize

        Returns:
            List of RFC-compliant attribute definition parts

        """
        return FlextLdifUtilitiesSchema.build_attribute_parts_with_metadata(
            attr_data,
            restore_original=True,
        )

    def _build_objectclass_parts(
        # Import here to avoid circular import
        # Import here to avoid circular import
        self,
        oc_data: m.Ldif.SchemaObjectClass,
    ) -> list[str]:
        """Build RFC objectClass definition parts.

        Delegates to FlextLdifUtilitiesSchema.build_objectclass_parts_with_metadata()
        for SRP compliance. Restores original formatting from metadata when
        available for zero data loss (perfect round-trip).

        Args:
            oc_data: SchemaObjectClass model to serialize

        Returns:
            List of RFC-compliant objectClass definition parts

        """
        return FlextLdifUtilitiesSchema.build_objectclass_parts_with_metadata(
            oc_data,
            restore_original=True,
        )

    def _ensure_x_origin(
        self,
        output_str: str,
        metadata: m.Ldif.QuirkMetadata | None,
    ) -> str:
        """Ensure X-ORIGIN extension is present if in metadata.

        Inserts X-ORIGIN before closing paren if not already present.
        Consolidated helper for both attribute and objectClass writing.
        """
        if not metadata or not metadata.extensions:
            return output_str
        x_origin_raw = metadata.extensions.get(
            c.Ldif.MetadataKeys.X_ORIGIN,
        )
        if not isinstance(x_origin_raw, str):
            return output_str
        if ")" not in output_str or "X-ORIGIN" in output_str:
            return output_str
        x_origin_str = f" X-ORIGIN '{x_origin_raw}'"
        return output_str.rstrip(")") + x_origin_str + ")"

    def _write_schema_item(
        self,
        data: m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass,
    ) -> FlextResult[str]:
        """Write schema item (attribute or objectClass) to RFC-compliant format.

        Auto-detects type using isinstance for proper type narrowing.

        Args:
            data: Schema item (attribute or objectClass)

        Returns:
            FlextResult with RFC-compliant string

        """
        try:
            # Use isinstance for proper type narrowing
            if isinstance(data, m.Ldif.SchemaAttribute):
                attr_transformed = self._transform_attribute_for_write(data)
                if not attr_transformed.oid:
                    return FlextResult[str].fail(
                        "RFC attribute writing failed: missing OID",
                    )
                parts = self._build_attribute_parts(attr_transformed)
                written_str = " ".join(parts)
                transformed_str = self._post_write_attribute(written_str)

                # Restore original case from metadata (attribute only)
                if attr_transformed.metadata:
                    fmt = attr_transformed.metadata.schema_format_details
                    if fmt:
                        attr_case = getattr(
                            fmt,
                            "attribute_case",
                            c.Ldif.SchemaFields.ATTRIBUTE_TYPES,
                        )
                        attr_types_lower = c.Ldif.SchemaFields.ATTRIBUTE_TYPES.lower()
                        if attr_types_lower in transformed_str.lower():
                            transformed_str = re.sub(
                                rf"{attr_types_lower}:",
                                f"{attr_case}:",
                                transformed_str,
                                flags=re.IGNORECASE,
                            )
                return FlextResult[str].ok(
                    self._ensure_x_origin(
                        transformed_str,
                        attr_transformed.metadata,
                    ),
                )

            # data is SchemaObjectClass
            oc_transformed = self._transform_objectclass_for_write(data)
            if not oc_transformed.oid:
                return FlextResult[str].fail(
                    "RFC objectclass writing failed: missing OID",
                )
            parts = self._build_objectclass_parts(oc_transformed)
            written_str = " ".join(parts)
            transformed_str = self._post_write_objectclass(written_str)

            return FlextResult[str].ok(
                self._ensure_x_origin(
                    transformed_str,
                    oc_transformed.metadata,
                ),
            )

        except (ValueError, TypeError, AttributeError) as e:
            item_type = (
                "attribute"
                if isinstance(data, m.Ldif.SchemaAttribute)
                else "objectclass"
            )
            logger.exception(
                "RFC %s writing exception",
                item_type,
                exception=e,
            )
            return FlextResult[str].fail(f"RFC {item_type} writing failed: {e}")

    def _write_attribute(
        self,
        attr_data: m.Ldif.SchemaAttribute,
    ) -> FlextResult[str]:
        """Write attribute to RFC-compliant string format (internal)."""
        if not isinstance(attr_data, m.Ldif.SchemaAttribute):
            return FlextResult[str].fail(
                f"Invalid attribute type: expected SchemaAttribute, "
                f"got {type(attr_data).__name__}",
            )
        return self._write_schema_item(attr_data)

    def _write_objectclass(
        self,
        oc_data: m.Ldif.SchemaObjectClass,
    ) -> FlextResult[str]:
        """Write objectClass to RFC-compliant string format (internal)."""
        if not isinstance(oc_data, m.Ldif.SchemaObjectClass):
            return FlextResult[str].fail(
                f"Invalid objectClass type: expected SchemaObjectClass, "
                f"got {type(oc_data).__name__}",
            )
        return self._write_schema_item(oc_data)

    # parse(), write(), _route_parse() are now in base.py
    # This class only provides RFC-specific implementations of:
    # - _parse_attribute(), _parse_objectclass()
    # - _write_attribute(), _write_objectclass()
    # - can_handle_attribute(), can_handle_objectclass()

    @overload
    def __call__(
        self,
        attr_definition: str,
        *,
        oc_definition: None = None,
        attr_model: None = None,
        oc_model: None = None,
        operation: str | None = None,
    ) -> object: ...

    @overload
    def __call__(
        self,
        *,
        attr_definition: None = None,
        oc_definition: str,
        attr_model: None = None,
        oc_model: None = None,
        operation: str | None = None,
    ) -> object: ...

    @overload
    def __call__(
        self,
        *,
        attr_definition: None = None,
        oc_definition: None = None,
        attr_model: m.Ldif.SchemaAttribute,
        oc_model: None = None,
        operation: str | None = None,
    ) -> str: ...

    @overload
    def __call__(
        self,
        *,
        attr_definition: None = None,
        oc_definition: None = None,
        attr_model: None = None,
        oc_model: m.Ldif.SchemaObjectClass,
        operation: str | None = None,
    ) -> str: ...

    @overload
    def __call__(
        self,
        attr_definition: str | None = None,
        oc_definition: str | None = None,
        attr_model: m.Ldif.SchemaAttribute | None = None,
        oc_model: m.Ldif.SchemaObjectClass | None = None,
        operation: str | None = None,
    ) -> t.Ldif.SchemaModelOrString: ...

    def __call__(
        self,
        attr_definition: str | None = None,
        oc_definition: str | None = None,
        attr_model: m.Ldif.SchemaAttribute | None = None,
        oc_model: m.Ldif.SchemaObjectClass | None = None,
        operation: str | None = None,
    ) -> t.Ldif.SchemaModelOrString:
        """Callable interface - automatic polymorphic processor.

        Pass definition string for parsing or model for writing.
        Returns concrete model instances (SchemaAttribute/SchemaObjectClass)
        or strings, which satisfy the Protocol contracts.
        """
        # Schema.execute() expects a single 'data' parameter, not separate parameters
        # For __call__, we need to handle multiple parameters differently
        # If attr_definition is provided, use it; otherwise use oc_definition
        # If attr_model is provided, use it; otherwise use oc_model
        data: str | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | None = None
        if attr_definition is not None:
            data = attr_definition
        elif oc_definition is not None:
            data = oc_definition
        elif attr_model is not None:
            data = attr_model
        elif oc_model is not None:
            data = oc_model

        result = self.execute(data=data, operation=operation)
        unwrapped = result.value
        # Type narrowing: unwrapped is SchemaAttribute | SchemaObjectClass | str
        # Cast to satisfy protocol return type
        return cast("t.Ldif.SchemaModelOrString", unwrapped)

    def __new__(
        cls,
        schema_service: object | None = None,
        parent_quirk: object | None = None,
        **kwargs: t.Ldif.FlexibleKwargsMutable,
    ) -> Self:
        """Override __new__ to support auto-execute and processor instantiation."""
        # Use object.__new__ to avoid calling parent's __new__ which also checks auto_execute
        # This prevents recursion when child class has auto_execute=True
        instance = object.__new__(cls)
        # Remove auto-execute kwargs before passing to __init__
        # Filter out auto-execute kwargs AND _parent_quirk (internal, not for Pydantic)
        # Also filter parent_quirk to avoid passing it twice
        filtered_kwargs = {
            "attr_definition",
            "oc_definition",
            "attr_model",
            "oc_model",
            "operation",
            "_parent_quirk",  # Internal attribute, not for Pydantic
            "parent_quirk",  # Filter to avoid passing twice
        }
        _ = {k: v for k, v in kwargs.items() if k not in filtered_kwargs}  # Unused
        # Use explicit parent_quirk parameter or fallback to kwargs (_parent_quirk)
        # Business Rule: parent_quirk must satisfy ParentQuirkProtocol
        parent_quirk_raw = (
            parent_quirk if parent_quirk is not None else kwargs.get("_parent_quirk")
        )

        parent_quirk_value: object | None = (
            parent_quirk_raw if parent_quirk_raw is not None else None
        )
        # Initialize instance using proper type - Schema.__init__ accepts schema_service
        # Type narrowing: instance is Self (Schema subclass)
        # Guard clause: should always pass for valid Schema subclasses
        if not isinstance(instance, FlextLdifServersRfcSchema):
            # Unreachable for valid Schema subclasses, but needed for type safety
            error_msg = f"Invalid instance type: {type(instance)}"
            raise TypeError(error_msg)
        schema_instance: Self = instance  # Now properly narrowed
        # Initialize using super() to avoid mypy error about accessing __init__ on instance
        # Call __init__ without kwargs - pyrefly cannot verify type compatibility
        super(FlextLdifServersBase.Schema, schema_instance).__init__()
        # Store _schema_service after initialization (not a Pydantic field)
        if schema_service is not None:
            object.__setattr__(schema_instance, "_schema_service", schema_service)
        # Store _parent_quirk after initialization using object.__setattr__
        if parent_quirk_value is not None:
            object.__setattr__(schema_instance, "_parent_quirk", parent_quirk_value)

        if cls.auto_execute:
            # Type-safe extraction of kwargs with isinstance checks
            attr_def_raw = kwargs.get("attr_definition")
            attr_def: str | None = (
                attr_def_raw if isinstance(attr_def_raw, str) else None
            )
            oc_def_raw = kwargs.get("oc_definition")
            oc_def: str | None = oc_def_raw if isinstance(oc_def_raw, str) else None
            attr_mod_raw = kwargs.get("attr_model")
            attr_mod: m.Ldif.SchemaAttribute | None = (
                attr_mod_raw
                if isinstance(attr_mod_raw, m.Ldif.SchemaAttribute)
                else None
            )
            oc_mod_raw = kwargs.get("oc_model")
            oc_mod: m.Ldif.SchemaObjectClass | None = (
                oc_mod_raw if isinstance(oc_mod_raw, m.Ldif.SchemaObjectClass) else None
            )
            op_raw = kwargs.get("operation")
            op: str | None = (
                "parse" if isinstance(op_raw, str) and op_raw == "parse" else None
            )
            # Schema.execute() expects a single 'data' parameter
            data: str | m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | None = None
            if attr_def is not None:
                data = attr_def
            elif oc_def is not None:
                data = oc_def
            elif attr_mod is not None:
                data = attr_mod
            elif oc_mod is not None:
                data = oc_mod
            # Type narrowing: instance is Self (Schema subclass)
            # Use schema_instance from above
            result = schema_instance.execute(data=data, operation=op)
            # Unwrap and return the result of auto-execute
            unwrapped = result.value
            if isinstance(unwrapped, cls):
                return unwrapped
            return instance

        return instance

    def create_metadata(
        self,
        original_format: str,
        extensions: t.Ldif.MetadataDictMutable | None = None,
    ) -> m.Ldif.QuirkMetadata:
        """Create quirk metadata with consistent server-specific extensions.

        Helper method to consolidate metadata creation across server quirks.
        Reduces code duplication in server-specific parse_attribute/parse_objectclass methods.

        Args:
            original_format: Original text format of the parsed element
            extensions: Optional dict of server-specific extensions/metadata

        Returns:
            m.Ldif.QuirkMetadata with quirk_type from Constants of parent server class

        Note:
            server_type is retrieved from Constants of the parent server class dynamically.
            This ensures all nested classes (Schema, Acl, Entry) use the same Constants
            from their parent server class (e.g., FlextLdifServersRfc.Constants,
            FlextLdifServersOid.Constants).

        """
        # Find parent server class that has Constants
        # Iterate through MRO to find the server class (not nested Schema/Acl/Entry)
        server_type_value: str = "generic"
        for cls in type(self).__mro__:
            # Check if this class has a Constants nested class
            if hasattr(cls, "Constants") and hasattr(cls.Constants, "SERVER_TYPE"):
                server_type_value = cls.Constants.SERVER_TYPE.value
                break

        # Build extensions with original_format
        all_extensions: t.Ldif.MetadataDictMutable = {
            c.Ldif.MetadataKeys.ACL_ORIGINAL_FORMAT: original_format,
        }
        if extensions:
            all_extensions.update(extensions)

        return m.Ldif.QuirkMetadata(
            quirk_type=server_type_value,
            extensions=m.Ldif.DynamicMetadata(**all_extensions)
            if all_extensions
            else m.Ldif.DynamicMetadata(),
        )

    def extract_schemas_from_ldif(
        self,
        ldif_content: str,
        *,
        validate_dependencies: bool = False,
    ) -> FlextResult[
        dict[
            str,
            list[m.Ldif.SchemaAttribute] | list[m.Ldif.SchemaObjectClass],
        ]
    ]:
        """Extract schema definitions from LDIF using u.

        Args:
            ldif_content: Raw LDIF content with schema definitions
            validate_dependencies: If True, validate attrs before objectClass extraction

        Returns:
            FlextResult with ATTRIBUTES and OBJECTCLASS lists

        """
        try:
            # PHASE 1: Extract all attributeTypes using FlextLdifUtilities
            attributes_parsed = FlextLdifUtilitiesSchema.extract_attributes_from_lines(
                ldif_content,
                self.parse_attribute,
            )

            # PHASE 2: Build available attributes set (if validation requested)
            if validate_dependencies:
                available_attrs = (
                    FlextLdifUtilitiesSchema.build_available_attributes_set(
                        attributes_parsed,
                    )
                )

                # Call server-specific validation hook
                validation_result = self._hook_validate_attributes(
                    attributes_parsed,
                    available_attrs,
                )
                if not validation_result.is_success:
                    return FlextResult[
                        dict[
                            str,
                            list[m.Ldif.SchemaAttribute]
                            | list[m.Ldif.SchemaObjectClass],
                        ]
                    ].fail(
                        f"Attribute validation failed: {validation_result.error}",
                    )

            # PHASE 3: Extract objectClasses using FlextLdifUtilities
            objectclasses_parsed = (
                FlextLdifUtilitiesSchema.extract_objectclasses_from_lines(
                    ldif_content,
                    self.parse_objectclass,
                )
            )

            # Return combined result
            # Use c.Ldif.DictKeys for type-safe dictionary keys
            schema_dict: dict[
                str,
                list[m.Ldif.SchemaAttribute] | list[m.Ldif.SchemaObjectClass],
            ] = {
                c.Ldif.DictKeys.ATTRIBUTES: attributes_parsed,
                c.Ldif.DictKeys.OBJECTCLASS: objectclasses_parsed,
            }
            return FlextResult[
                dict[
                    str,
                    list[m.Ldif.SchemaAttribute] | list[m.Ldif.SchemaObjectClass],
                ]
            ].ok(schema_dict)

        except Exception as e:
            logger.exception(
                "Schema extraction failed",
            )
            return FlextResult[
                dict[
                    str,
                    list[m.Ldif.SchemaAttribute] | list[m.Ldif.SchemaObjectClass],
                ]
            ].fail(
                f"Schema extraction failed: {e}",
            )
