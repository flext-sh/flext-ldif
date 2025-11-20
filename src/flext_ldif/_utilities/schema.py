"""Extracted nested class from FlextLdifUtilities.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import copy
import re
from collections.abc import Callable
from typing import TypedDict, cast

from flext_core import FlextLogger, FlextResult, FlextRuntime

from flext_ldif._utilities.oid import FlextLdifUtilitiesOID
from flext_ldif._utilities.parser import FlextLdifUtilitiesParser
from flext_ldif._utilities.writer import FlextLdifUtilitiesWriter
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels

logger = FlextLogger(__name__)


# TypedDicts for parse methods return types (replaces dict[str, Any])
class ParsedAttributeDict(TypedDict, total=False):
    """Type-safe dictionary structure for parsed attribute definitions."""

    oid: str
    name: str | None
    desc: str | None
    syntax: str | None
    length: int | None
    equality: str | None
    ordering: str | None
    substr: str | None
    single_value: bool
    no_user_modification: bool
    sup: str | None
    usage: str | None
    metadata_extensions: dict[str, object]
    syntax_validation: dict[str, object] | None


class ParsedObjectClassDict(TypedDict, total=False):
    """Type-safe dictionary structure for parsed objectClass definitions."""

    oid: str
    name: str | None
    desc: str | None
    sup: str | None
    kind: str
    must: list[str] | None
    may: list[str] | None
    metadata_extensions: dict[str, object]


class FlextLdifUtilitiesSchema:
    """Generic attribute definition normalization utilities."""

    @staticmethod
    def normalize_name(
        name_value: str | None,
        suffixes_to_remove: list[str] | None = None,
        char_replacements: dict[str, str] | None = None,
    ) -> str | None:
        """Normalize attribute NAME field."""
        if not name_value or not isinstance(name_value, str):
            return name_value

        result = name_value
        if suffixes_to_remove is None:
            suffixes_to_remove = [";binary"]
        if char_replacements is None:
            char_replacements = {"_": "-"}

        for suffix in suffixes_to_remove:
            if suffix in result:
                result = result.replace(suffix, "")

        for old, new in char_replacements.items():
            if old in result:
                result = result.replace(old, new)

        return result if result != name_value else name_value

    @staticmethod
    def normalize_matching_rules(
        equality: str | None,
        substr: str | None = None,
        *,
        replacements: dict[str, str] | None = None,
        substr_rules_in_equality: dict[str, str] | None = None,
        normalized_substr_values: dict[str, str] | None = None,
    ) -> tuple[str | None, str | None]:
        """Normalize EQUALITY and SUBSTR matching rules.

        Handles:
        1. SUBSTR rule incorrectly in EQUALITY field → move to SUBSTR
        2. Apply server-specific matching rule replacements
        3. Normalize case variants (caseIgnoreSubStringsMatch → caseIgnoreSubstringsMatch)

        Args:
            equality: Current EQUALITY rule
            substr: Current SUBSTR rule
            replacements: Dict of custom replacements {old: new}
            substr_rules_in_equality: Map of SUBSTR rules found in EQUALITY → correct EQUALITY
            normalized_substr_values: Map of SUBSTR variants → normalized SUBSTR

        Returns:
            Tuple of (normalized_equality, normalized_substr)

        """
        result_equality = equality
        result_substr = substr

        # Fix SUBSTR rules incorrectly used in EQUALITY field
        # When a SUBSTR rule is found in EQUALITY, move it to SUBSTR and set EQUALITY to default
        if (
            substr_rules_in_equality
            and equality
            and equality in substr_rules_in_equality
        ):
            # Move the SUBSTR rule from EQUALITY to SUBSTR
            # The original equality value (e.g., "caseIgnoreSubstringsMatch") goes to substr
            result_substr = equality  # The original equality value is a SUBSTR rule
            # Set EQUALITY to the mapped correct EQUALITY rule
            result_equality = substr_rules_in_equality[
                equality
            ]  # e.g., "caseIgnoreMatch"

        # Normalize SUBSTR case variants
        if (
            result_substr
            and normalized_substr_values
            and result_substr in normalized_substr_values
        ):
            result_substr = normalized_substr_values[result_substr]

        # Apply server-specific matching rule replacements
        if replacements and result_equality and result_equality in replacements:
            result_equality = replacements[result_equality]

        return result_equality, result_substr

    @staticmethod
    def normalize_syntax_oid(
        syntax: str | None,
        *,
        replacements: dict[str, str] | None = None,
    ) -> str | None:
        """Normalize SYNTAX OID field.

        Transformations:
        - Remove quotes (Oracle OID uses 'OID', RFC uses OID)
        - Apply server-specific syntax OID replacements

        Args:
            syntax: Original SYNTAX OID
            replacements: Dict of syntax OID replacements {old: new}

        Returns:
            Normalized syntax OID

        """
        if not syntax:
            return syntax

        result = syntax

        # Remove quotes if present (Oracle OID: '1.2.3', RFC: 1.2.3)
        if result.startswith("'") and result.endswith("'"):
            result = result[1:-1]

        # Apply server-specific syntax OID replacements
        if replacements and result in replacements:
            result = replacements[result]

        return result

    @staticmethod
    def _apply_field_transformation(
        transformed: object,
        field_name: str,
        transform_fn: object,
    ) -> FlextResult[object]:
        """Apply single field transformation with monadic error handling."""
        if not callable(transform_fn):
            return FlextResult.ok(transformed)

        try:
            old_value = getattr(transformed, field_name, None)
            new_value = transform_fn(old_value)

            # Handle both direct values and FlextResult returns
            if isinstance(new_value, FlextResult):
                if new_value.is_failure:
                    return FlextResult.fail(
                        f"Transformation of '{field_name}' failed: {new_value.error}",
                    )
                setattr(transformed, field_name, new_value.unwrap())
            else:
                setattr(transformed, field_name, new_value)

            return FlextResult.ok(transformed)
        except Exception as e:
            logger.exception(
                "Schema field transformation failed",
                field_name=field_name,
            )
            return FlextResult.fail(f"Transformation of '{field_name}' error: {e}")

    @staticmethod
    def _return_result(
        transformed: object,
        _original_type: FlextLdifModels.SchemaAttribute
        | FlextLdifModels.SchemaObjectClass,
    ) -> FlextResult[
        FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass
    ]:
        """Wrap transformation result with proper type.

        Args:
            transformed: The transformed schema object
            _original_type: Original type (unused, kept for API compatibility)

        """
        if isinstance(transformed, FlextLdifModels.SchemaAttribute):
            return FlextResult.ok(transformed)
        if isinstance(transformed, FlextLdifModels.SchemaObjectClass):
            return FlextResult.ok(transformed)
        # Fallback for unknown types
        return FlextResult.fail(
            f"Unknown schema object type: {type(transformed).__name__}",
        )

    @staticmethod
    def _create_schema_copy(
        schema_obj: FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass,
    ) -> FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass:
        """Create a copy of the schema object."""
        if hasattr(schema_obj, "model_copy"):
            return schema_obj.model_copy()
        return copy.copy(schema_obj)

    @staticmethod
    def _validate_transformation_result(
        unwrapped: object,
        schema_obj: FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass,
    ) -> FlextResult[
        FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass
    ]:
        """Validate that transformation result matches input type."""
        if isinstance(schema_obj, FlextLdifModels.SchemaAttribute):
            if isinstance(unwrapped, FlextLdifModels.SchemaAttribute):
                return FlextResult.ok(unwrapped)
            return FlextResult.fail(
                "Field transformation returned unexpected type for SchemaAttribute",
            )
        if isinstance(schema_obj, FlextLdifModels.SchemaObjectClass):
            if isinstance(unwrapped, FlextLdifModels.SchemaObjectClass):
                return FlextResult.ok(unwrapped)
            return FlextResult.fail(
                "Field transformation returned unexpected type for SchemaObjectClass",
            )
        return FlextResult.fail(
            f"Unknown schema object type: {type(schema_obj).__name__}"
        )

    @staticmethod
    def _apply_field_transforms(
        transformed: FlextLdifModels.SchemaAttribute
        | FlextLdifModels.SchemaObjectClass,
        field_transforms: dict[
            str, Callable[[object], object] | str | list[str] | None
        ],
        schema_obj: FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass,
    ) -> FlextResult[
        FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass
    ]:
        """Apply all field transformations."""
        # Declare variable with explicit type to help type checker
        current: FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass = (
            transformed
        )

        for field_name, transform_fn in field_transforms.items():
            if not hasattr(current, field_name):
                continue

            result = FlextLdifUtilitiesSchema._apply_field_transformation(
                current,
                field_name,
                transform_fn,
            )
            if result.is_failure:
                return FlextResult.fail(
                    result.error or "Field transformation failed",
                )

            unwrapped = result.unwrap()
            validation_result = (
                FlextLdifUtilitiesSchema._validate_transformation_result(
                    unwrapped,
                    schema_obj,
                )
            )
            if validation_result.is_failure:
                return validation_result
            unwrapped_validated = validation_result.unwrap()
            # Type narrowing: validate and narrow type explicitly
            if isinstance(
                unwrapped_validated,
                (FlextLdifModels.SchemaAttribute, FlextLdifModels.SchemaObjectClass),
            ):
                current = unwrapped_validated
            else:
                return FlextResult.fail(
                    f"Unexpected type after transformation: {type(unwrapped_validated).__name__}",
                )

        # Type narrowing: current is now guaranteed to be SchemaAttribute | SchemaObjectClass
        # Validate type to help type checker understand the type
        if not isinstance(
            current,
            (FlextLdifModels.SchemaAttribute, FlextLdifModels.SchemaObjectClass),
        ):
            return FlextResult.fail(
                f"Type narrowing failed: {type(current).__name__}",
            )
        return FlextResult[
            FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass
        ].ok(current)

    @staticmethod
    def apply_transformations(
        schema_obj: FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass,
        *,
        field_transforms: (
            dict[
                str,
                Callable[
                    [object],
                    object,
                ]
                | str
                | list[str]
                | None,
            ]
            | None
        ) = None,
    ) -> FlextResult[
        FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass
    ]:
        """Apply transformation pipeline to schema object.

        Generic transformation pipeline accepting optional transformer callables.

        Args:
            schema_obj: SchemaAttribute or SchemaObjectClass (type annotation guarantees non-None)
            field_transforms: Dict of {field_name: transform_callable}

        Returns:
            FlextResult with transformed schema object

        """
        # Type annotation guarantees schema_obj is not None - no defensive check needed

        try:
            transformed = FlextLdifUtilitiesSchema._create_schema_copy(schema_obj)

            # Apply transformations with monadic chaining
            if field_transforms:
                transform_result = FlextLdifUtilitiesSchema._apply_field_transforms(
                    transformed,
                    field_transforms,
                    schema_obj,
                )
                if transform_result.is_failure:
                    return transform_result
                transformed = transform_result.unwrap()

            # Return with proper type based on input
            return FlextLdifUtilitiesSchema._return_result(transformed, schema_obj)
        except Exception as e:
            logger.exception(
                "Transformation pipeline error",
            )
            return FlextResult.fail(f"Transformation pipeline error: {e}")

    @staticmethod
    def set_server_type(
        model_instance: FlextLdifModels.SchemaAttribute
        | FlextLdifModels.SchemaObjectClass,
        server_type: str,
    ) -> FlextResult[
        FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass
    ]:
        """Copy schema model and set server_type in metadata.

        Common pattern used by quirks when converting from RFC format.

        Args:
            model_instance: RFC-compliant schema model
            server_type: Server type identifier (e.g., "oid", "oud")

        Returns:
            FlextResult with model copy containing server_type in metadata

        """
        if not model_instance:
            return FlextResult.ok(model_instance)

        try:
            # Create copy
            if hasattr(model_instance, "model_copy"):
                result = model_instance.model_copy(deep=True)
            else:
                result = copy.deepcopy(model_instance)

            # Set server_type in metadata
            if (
                hasattr(result, "metadata")
                and result.metadata is not None
                and hasattr(result.metadata, "server_type")
            ):
                result.metadata.extensions["server_type"] = server_type

            return FlextResult.ok(result)
        except Exception as e:
            logger.exception(
                "Failed to set server type",
            )
            return FlextResult.fail(f"Failed to set server type: {e}")

    @staticmethod
    def _extract_schema_items_from_lines(
        ldif_content: str,
        parse_callback: Callable[
            [str],
            FlextResult[
                FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass
            ],
        ]
        | Callable[[str], FlextResult[FlextLdifModels.SchemaAttribute]]
        | Callable[[str], FlextResult[FlextLdifModels.SchemaObjectClass]],
        line_prefix: str,
    ) -> list[FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass]:
        """Generic extraction of schema items from LDIF content lines.

        Consolidated logic for extracting both attributes and objectClasses.
        Iterates through LDIF lines, identifies definitions by prefix
        (case-insensitive), and parses them using the provided callback.

        Args:
            ldif_content: Raw LDIF content containing schema definitions
            parse_callback: Parser function to call for each definition
            line_prefix: Prefix to match (e.g., "attributetypes:", "objectclasses:")

        Returns:
            List of successfully parsed schema items

        """
        items: list[
            FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass
        ] = []

        for raw_line in ldif_content.split("\n"):
            line = raw_line.strip()

            # Case-insensitive prefix match
            if line.lower().startswith(line_prefix.lower()):
                item_def = line.split(":", 1)[1].strip()
                result = parse_callback(item_def)
                if hasattr(result, "is_success") and result.is_success:
                    unwrapped = result.unwrap()
                    # Type narrowing: unwrapped is guaranteed to be SchemaAttribute | SchemaObjectClass
                    if isinstance(
                        unwrapped,
                        (
                            FlextLdifModels.SchemaAttribute,
                            FlextLdifModels.SchemaObjectClass,
                        ),
                    ):
                        items.append(unwrapped)

        return items

    @staticmethod
    def extract_attributes_from_lines(
        ldif_content: str,
        parse_callback: Callable[[str], FlextResult[FlextLdifModels.SchemaAttribute]],
    ) -> list[FlextLdifModels.SchemaAttribute]:
        """Extract and parse all attributeTypes from LDIF content lines.

        Delegates to generic extraction method.

        Args:
            ldif_content: Raw LDIF content containing schema definitions
            parse_callback: Parser function to call for each attribute definition

        Returns:
            List of successfully parsed attribute models

        """
        items = FlextLdifUtilitiesSchema._extract_schema_items_from_lines(
            ldif_content,
            parse_callback,
            "attributetypes:",
        )
        # Type narrowing: filter to only SchemaAttribute instances
        return [
            item for item in items if isinstance(item, FlextLdifModels.SchemaAttribute)
        ]

    @staticmethod
    def extract_objectclasses_from_lines(
        ldif_content: str,
        parse_callback: Callable[[str], FlextResult[FlextLdifModels.SchemaObjectClass]],
    ) -> list[FlextLdifModels.SchemaObjectClass]:
        """Extract and parse all objectClasses from LDIF content lines.

        Delegates to generic extraction method.

        Args:
            ldif_content: Raw LDIF content containing schema definitions
            parse_callback: Parser function to call for each objectClass definition

        Returns:
            List of successfully parsed objectClass models

        """
        items = FlextLdifUtilitiesSchema._extract_schema_items_from_lines(
            ldif_content,
            parse_callback,
            "objectclasses:",
        )
        # Type narrowing: filter to only SchemaObjectClass instances
        return [
            item
            for item in items
            if isinstance(item, FlextLdifModels.SchemaObjectClass)
        ]

    @staticmethod
    def build_available_attributes_set(
        attributes: list[FlextLdifModels.SchemaAttribute],
    ) -> set[str]:
        """Build set of available attribute names (lowercase) for dependency validation.

        Used during schema extraction to build a set of all available attribute names
        that can be referenced by objectClass definitions (in MUST/MAY lists).

        This is commonly used by OUD, OID, and other servers that need to validate
        objectClass dependencies during schema extraction.

        Args:
            attributes: List of parsed SchemaAttribute models

        Returns:
            Set of lowercase attribute names

        Example:
            >>> attrs = [SchemaAttribute(name="cn"), SchemaAttribute(name="sn")]
            >>> available = FlextLdifUtilitiesSchema.build_available_attributes_set(
            ...     attrs
            ... )
            >>> "cn" in available
            True
            >>> "uid" in available
            False

        """
        available: set[str] = set()

        for attr_data in attributes:
            # Validate it's a SchemaAttribute with a name
            if not isinstance(attr_data, FlextLdifModels.SchemaAttribute):
                continue

            if not hasattr(attr_data, "name") or attr_data.name is None:
                continue

            # Add lowercase name to set
            attr_name = str(attr_data.name).lower()
            available.add(attr_name)

        return available

    @staticmethod
    def build_metadata(
        definition: str,
        additional_extensions: dict[str, object] | None = None,
    ) -> dict[str, object]:
        """Build metadata extensions dictionary for schema definitions.

        Generic method to build metadata from schema definition string.
        Extracts extensions and adds original format and additional extensions.

        Args:
            definition: Original schema definition string
            additional_extensions: Additional extension key-value pairs

        Returns:
            Dictionary of metadata extensions (empty if none)

        """
        # Use Parser to extract extensions
        extensions = FlextLdifUtilitiesParser.extract_extensions(definition)

        # Store original format for round-trip fidelity
        extensions[FlextLdifConstants.MetadataKeys.ORIGINAL_FORMAT] = definition.strip()

        # Add any additional extensions
        if additional_extensions:
            extensions.update(additional_extensions)

        return extensions

    @staticmethod
    def parse_attribute(
        attr_definition: str,
        *,
        _case_insensitive: bool = False,
        _allow_syntax_quotes: bool = False,
        validate_syntax: bool = True,
    ) -> ParsedAttributeDict:
        """Parse RFC 4512 attribute definition into structured data.

        Generic parsing method that extracts all fields from attribute definition.
        Used by server quirks to get base parsing logic without duplication.

        Args:
            attr_definition: RFC 4512 attribute definition string
            _case_insensitive: If True, use case-insensitive NAME matching (unused)
            _allow_syntax_quotes: If True, allow optional quotes in SYNTAX (unused)
            validate_syntax: If True, validate syntax OID format

        Returns:
            Dictionary with parsed fields:
            - oid: str (required)
            - name: str | None
            - desc: str | None
            - syntax: str | None
            - length: int | None
            - equality: str | None
            - ordering: str | None
            - substr: str | None
            - single_value: bool
            - no_user_modification: bool
            - sup: str | None
            - usage: str | None
            - metadata_extensions: dict[str, object]
            - syntax_validation: dict[str, object] | None

        Raises:
            ValueError: If OID is missing or invalid

        """
        # Extract OID (required)
        oid = FlextLdifUtilitiesParser.extract_oid(attr_definition)
        if not oid:
            msg = "RFC attribute parsing failed: missing an OID"
            raise ValueError(msg)

        # Extract NAME (optional) - use utilities with OID as fallback
        name = FlextLdifUtilitiesParser.extract_optional_field(
            attr_definition,
            FlextLdifConstants.LdifPatterns.SCHEMA_NAME,
            default=oid,
        )

        # Extract DESC (optional)
        desc = FlextLdifUtilitiesParser.extract_optional_field(
            attr_definition,
            FlextLdifConstants.LdifPatterns.SCHEMA_DESC,
        )

        # Extract SYNTAX (optional) with optional length constraint
        syntax_match = re.search(
            FlextLdifConstants.LdifPatterns.SCHEMA_SYNTAX_LENGTH,
            attr_definition,
        )
        syntax = syntax_match.group(1) if syntax_match else None
        length = (
            int(syntax_match.group(2))
            if syntax_match and syntax_match.group(2)
            else None
        )

        # Validate syntax OID (if requested)
        syntax_extensions: dict[str, object] = {}
        syntax_validation: dict[str, object] | None = None
        if validate_syntax and syntax and syntax.strip():
            validate_result = FlextLdifUtilitiesOID.validate_format(syntax)
            if validate_result.is_failure:
                syntax_extensions[
                    FlextLdifConstants.MetadataKeys.SYNTAX_VALIDATION_ERROR
                ] = f"Syntax OID validation failed: {validate_result.error}"
            elif not validate_result.unwrap():
                syntax_extensions[
                    FlextLdifConstants.MetadataKeys.SYNTAX_VALIDATION_ERROR
                ] = (
                    f"Invalid syntax OID format: {syntax} "
                    f"(must be numeric dot-separated format)"
                )
            syntax_extensions[FlextLdifConstants.MetadataKeys.SYNTAX_OID_VALID] = (
                FlextLdifConstants.MetadataKeys.SYNTAX_VALIDATION_ERROR
                not in syntax_extensions
            )
            syntax_validation = syntax_extensions.copy()

        # Extract matching rules (optional)
        equality = FlextLdifUtilitiesParser.extract_optional_field(
            attr_definition,
            FlextLdifConstants.LdifPatterns.SCHEMA_EQUALITY,
        )
        substr = FlextLdifUtilitiesParser.extract_optional_field(
            attr_definition,
            FlextLdifConstants.LdifPatterns.SCHEMA_SUBSTR,
        )
        ordering = FlextLdifUtilitiesParser.extract_optional_field(
            attr_definition,
            FlextLdifConstants.LdifPatterns.SCHEMA_ORDERING,
        )

        # Extract flags (boolean)
        single_value = FlextLdifUtilitiesParser.extract_boolean_flag(
            attr_definition,
            FlextLdifConstants.LdifPatterns.SCHEMA_SINGLE_VALUE,
        )

        no_user_modification = False
        if _case_insensitive:  # Lenient mode (OID)
            no_user_modification = FlextLdifUtilitiesParser.extract_boolean_flag(
                attr_definition,
                FlextLdifConstants.LdifPatterns.SCHEMA_NO_USER_MODIFICATION,
            )

        # Extract SUP and USAGE (optional)
        sup = FlextLdifUtilitiesParser.extract_optional_field(
            attr_definition,
            FlextLdifConstants.LdifPatterns.SCHEMA_SUP,
        )
        usage = FlextLdifUtilitiesParser.extract_optional_field(
            attr_definition,
            FlextLdifConstants.LdifPatterns.SCHEMA_USAGE,
        )

        # Build metadata using utilities
        extensions = FlextLdifUtilitiesSchema.build_metadata(
            attr_definition,
            additional_extensions=syntax_extensions if syntax_validation else None,
        )

        return {
            "oid": oid,
            "name": name,
            "desc": desc,
            "syntax": syntax,
            "length": length,
            "equality": equality,
            "ordering": ordering,
            "substr": substr,
            "single_value": single_value,
            "no_user_modification": no_user_modification,
            "sup": sup,
            "usage": usage,
            "metadata_extensions": extensions,
            "syntax_validation": syntax_validation,
        }

    @staticmethod
    def parse_objectclass(
        oc_definition: str,
        *,
        _case_insensitive: bool = False,
    ) -> ParsedObjectClassDict:
        """Parse RFC 4512 objectClass definition into structured data.

        Generic parsing method that extracts all fields from objectClass definition.
        Used by server quirks to get base parsing logic without duplication.

        Args:
            oc_definition: RFC 4512 objectClass definition string
            _case_insensitive: If True, use case-insensitive NAME matching (unused)

        Returns:
            Dictionary with parsed fields:
            - oid: str (required)
            - name: str | None
            - desc: str | None
            - sup: str | None
            - kind: str (STRUCTURAL, AUXILIARY, or ABSTRACT)
            - must: list[str] | None
            - may: list[str] | None
            - metadata_extensions: dict[str, object]

        Raises:
            ValueError: If OID is missing or invalid

        """
        # Extract OID (required)
        oid = FlextLdifUtilitiesParser.extract_oid(oc_definition)
        if not oid:
            msg = "RFC objectClass parsing failed: missing an OID"
            raise ValueError(msg)

        # Extract NAME (optional) - use utilities with OID as fallback
        name = FlextLdifUtilitiesParser.extract_optional_field(
            oc_definition,
            FlextLdifConstants.LdifPatterns.SCHEMA_NAME,
            default=oid,
        )

        # Extract DESC (optional)
        desc = FlextLdifUtilitiesParser.extract_optional_field(
            oc_definition,
            FlextLdifConstants.LdifPatterns.SCHEMA_DESC,
        )

        # Extract SUP (optional) - superior objectClass(es)
        sup = None
        sup_match = re.search(
            FlextLdifConstants.LdifPatterns.SCHEMA_OBJECTCLASS_SUP,
            oc_definition,
        )
        if sup_match:
            sup_value = sup_match.group(1) or sup_match.group(2)
            sup_value = sup_value.strip()
            # Handle multiple superior classes - use first one
            sup = next(
                (s.strip() for s in sup_value.split("$")),
                sup_value,
            )

        # Determine kind (STRUCTURAL, AUXILIARY, ABSTRACT)
        # RFC 4512: Default to STRUCTURAL if KIND is not specified
        kind_match = re.search(
            FlextLdifConstants.LdifPatterns.SCHEMA_OBJECTCLASS_KIND,
            oc_definition,
            re.IGNORECASE,
        )
        kind = (
            kind_match.group(1).upper()
            if kind_match
            else FlextLdifConstants.Schema.STRUCTURAL
        )

        # Extract MUST attributes (optional) - can be single or multiple
        must = None
        must_match = re.search(
            FlextLdifConstants.LdifPatterns.SCHEMA_OBJECTCLASS_MUST,
            oc_definition,
        )
        if must_match:
            must_value = (must_match.group(1) or must_match.group(2)).strip()
            must = [m.strip() for m in must_value.split("$")]

        # Extract MAY attributes (optional) - can be single or multiple
        may = None
        may_match = re.search(
            FlextLdifConstants.LdifPatterns.SCHEMA_OBJECTCLASS_MAY,
            oc_definition,
        )
        if may_match:
            may_value = (may_match.group(1) or may_match.group(2)).strip()
            may = [m.strip() for m in may_value.split("$")]

        # Build metadata using utilities
        extensions = FlextLdifUtilitiesSchema.build_metadata(
            oc_definition,
        )

        return {
            "oid": oid,
            "name": name,
            "desc": desc,
            "sup": sup,
            "kind": kind,
            "must": must,
            "may": may,
            "metadata_extensions": extensions,
        }

    @staticmethod
    def _build_attribute_parts_from_model(
        attr_data: FlextLdifModels.SchemaAttribute,
    ) -> list[str]:
        """Build RFC 4512 attribute definition parts (extracted to reduce complexity)."""
        # Import directly from _utilities submodule to avoid circular dependency

        parts: list[str] = [f"( {attr_data.oid}"]

        if attr_data.name:
            parts.append(f"NAME '{attr_data.name}'")

        if attr_data.desc:
            parts.append(f"DESC '{attr_data.desc}'")

        if attr_data.metadata and attr_data.metadata.extensions.get(
            FlextLdifConstants.MetadataKeys.OBSOLETE,
        ):
            parts.append("OBSOLETE")

        if attr_data.sup:
            parts.append(f"SUP {attr_data.sup}")

        FlextLdifUtilitiesWriter.add_attribute_matching_rules(attr_data, parts)
        FlextLdifUtilitiesWriter.add_attribute_syntax(attr_data, parts)
        FlextLdifUtilitiesWriter.add_attribute_flags(attr_data, parts)

        if attr_data.usage:
            parts.append(f"USAGE {attr_data.usage}")

        if attr_data.metadata and attr_data.metadata.extensions.get("x_origin"):
            parts.append(f"X-ORIGIN '{attr_data.metadata.extensions.get('x_origin')}'")

        parts.append(")")

        return parts

    @staticmethod
    def _write_schema_element(
        data: FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass,
        expected_type: type,
        type_name: str,
        parts_builder: Callable[..., list[str]],
    ) -> str:
        """Generic helper for writing schema elements (DRY pattern).

        Args:
            data: Schema model (attribute or objectclass)
            expected_type: Expected type for validation
            type_name: Name for error messages
            parts_builder: Function to build parts list

        Returns:
            RFC 4512 formatted string

        Raises:
            TypeError: If data is wrong type
            ValueError: If OID is missing

        """
        if not isinstance(data, expected_type):
            msg = f"{type_name} must be {expected_type.__name__} model"
            raise TypeError(msg)

        if not data.oid:
            msg = f"RFC {type_name} writing failed: missing OID"
            raise ValueError(msg)

        parts = parts_builder(data)
        return " ".join(parts)

    @staticmethod
    def write_attribute(
        attr_data: FlextLdifModels.SchemaAttribute,
    ) -> str:
        """Write RFC 4512 attribute definition string from SchemaAttribute model.

        Generic writing method that builds RFC-compliant attribute definition string.
        Used by server quirks to get base writing logic without duplication.

        Args:
            attr_data: SchemaAttribute model (oid required)

        Returns:
            RFC 4512 formatted string

        Raises:
            ValueError: If OID is missing

        """
        return FlextLdifUtilitiesSchema._write_schema_element(
            attr_data,
            FlextLdifModels.SchemaAttribute,
            "attr_data",
            FlextLdifUtilitiesSchema._build_attribute_parts_from_model,
        )

    @staticmethod
    def _add_objectclass_sup(
        oc_data: FlextLdifModels.SchemaObjectClass,
        parts: list[str],
    ) -> None:
        """Add SUP to objectclass parts list."""
        if oc_data.sup:
            if FlextRuntime.is_list_like(oc_data.sup):
                sup_list_str = cast("list[str]", oc_data.sup)
                if len(sup_list_str) == 1:
                    parts.append(f"SUP {sup_list_str[0]}")
                else:
                    sup_str = " $ ".join(sup_list_str)
                    parts.append(f"SUP ( {sup_str} )")
            else:
                parts.append(f"SUP {oc_data.sup}")

    @staticmethod
    def _add_objectclass_must_may(
        oc_data: FlextLdifModels.SchemaObjectClass,
        parts: list[str],
    ) -> None:
        """Add MUST and MAY to objectclass parts list."""
        if oc_data.must:
            if FlextRuntime.is_list_like(oc_data.must):
                must_list_str = cast("list[str]", oc_data.must)
                if len(must_list_str) == 1:
                    parts.append(f"MUST {must_list_str[0]}")
                else:
                    must_str = " $ ".join(must_list_str)
                    parts.append(f"MUST ( {must_str} )")
            else:
                parts.append(f"MUST {oc_data.must}")

        if oc_data.may:
            if FlextRuntime.is_list_like(oc_data.may):
                may_list_str = cast("list[str]", oc_data.may)
                if len(may_list_str) == 1:
                    parts.append(f"MAY {may_list_str[0]}")
                else:
                    may_str = " $ ".join(may_list_str)
                    parts.append(f"MAY ( {may_str} )")
            else:
                parts.append(f"MAY {oc_data.may}")

    @staticmethod
    def _build_objectclass_parts_from_model(
        oc_data: FlextLdifModels.SchemaObjectClass,
    ) -> list[str]:
        """Build RFC 4512 objectClass definition parts (extracted to reduce complexity)."""
        parts: list[str] = [f"( {oc_data.oid}"]

        if oc_data.name:
            parts.append(f"NAME '{oc_data.name}'")

        if oc_data.desc:
            parts.append(f"DESC '{oc_data.desc}'")

        if oc_data.metadata and oc_data.metadata.extensions.get(
            FlextLdifConstants.MetadataKeys.OBSOLETE,
        ):
            parts.append("OBSOLETE")

        FlextLdifUtilitiesSchema._add_objectclass_sup(oc_data, parts)

        kind = oc_data.kind or FlextLdifConstants.Schema.STRUCTURAL
        parts.append(str(kind))

        FlextLdifUtilitiesSchema._add_objectclass_must_may(oc_data, parts)

        if oc_data.metadata and oc_data.metadata.extensions.get("x_origin"):
            parts.append(f"X-ORIGIN '{oc_data.metadata.extensions.get('x_origin')}'")

        parts.append(")")

        return parts

    @staticmethod
    def write_objectclass(
        oc_data: FlextLdifModels.SchemaObjectClass,
    ) -> str:
        """Write RFC 4512 objectClass definition string from SchemaObjectClass model.

        Generic writing method that builds RFC-compliant objectClass definition string.
        Used by server quirks to get base writing logic without duplication.

        Args:
            oc_data: SchemaObjectClass model (oid required)

        Returns:
            RFC 4512 formatted string

        Raises:
            ValueError: If OID is missing

        """
        return FlextLdifUtilitiesSchema._write_schema_element(
            oc_data,
            FlextLdifModels.SchemaObjectClass,
            "oc_data",
            FlextLdifUtilitiesSchema._build_objectclass_parts_from_model,
        )

    @staticmethod
    def normalize_attribute_name(
        attribute_name: str | None,
        *,
        case_sensitive: bool = False,
    ) -> str | None:
        """Normalize attribute name for case-insensitive comparisons.

        Centralizes attribute name normalization used throughout server quirks
        to reduce code duplication of `.lower()` calls.

        Args:
            attribute_name: Original attribute name
            case_sensitive: If True, preserve case; if False, convert to lowercase

        Returns:
            Normalized attribute name or None if input is None

        Example:
            >>> FlextLdifUtilitiesSchema.normalize_attribute_name("CN")
            "cn"

            >>> FlextLdifUtilitiesSchema.normalize_attribute_name("givenName")
            "givenname"

            >>> FlextLdifUtilitiesSchema.normalize_attribute_name(
            ...     "CN", case_sensitive=True
            ... )
            "CN"

        """
        if not attribute_name or not isinstance(attribute_name, str):
            return attribute_name

        return attribute_name if case_sensitive else attribute_name.lower()

    @staticmethod
    def is_boolean_attribute(
        attribute_name: str | None,
        boolean_attributes: set[str],
    ) -> bool:
        """Check if attribute is in boolean attributes set (case-insensitive).

        Centralizes boolean attribute checking to reduce duplication of
        set comprehensions like `{attr.lower() for attr in list}`.

        Args:
            attribute_name: Attribute name to check
            boolean_attributes: Set of boolean attribute names (will be normalized)

        Returns:
            True if attribute is in boolean set, False otherwise

        Example:
            >>> bool_attrs = {"boolean", "enabled", "active"}
            >>> FlextLdifUtilitiesSchema.is_boolean_attribute("Enabled", bool_attrs)
            True

            >>> FlextLdifUtilitiesSchema.is_boolean_attribute("description", bool_attrs)
            False

        """
        if not attribute_name or not boolean_attributes:
            return False

        # Normalize input attribute name
        normalized_input = FlextLdifUtilitiesSchema.normalize_attribute_name(
            attribute_name,
        )

        # Normalize all items in the boolean attributes set for comparison
        normalized_set = {
            FlextLdifUtilitiesSchema.normalize_attribute_name(attr)
            for attr in boolean_attributes
        }

        return normalized_input in normalized_set

    @staticmethod
    def is_attribute_in_list(
        attribute_name: str | None,
        attribute_list: list[str] | set[str] | None,
    ) -> bool:
        """Check if attribute exists in list or set (case-insensitive).

        Centralizes case-insensitive attribute list checking to reduce
        duplication of `.lower()` comparisons in loops. Works with both
        lists and sets for flexible usage.

        Args:
            attribute_name: Attribute name to check
            attribute_list: List or set of attribute names to search

        Returns:
            True if attribute is in list/set, False otherwise

        Example:
            >>> attrs = ["cn", "mail", "objectClass"]
            >>> FlextLdifUtilitiesSchema.is_attribute_in_list("CN", attrs)
            True

            >>> attrs_set = {"cn", "mail", "objectClass"}
            >>> FlextLdifUtilitiesSchema.is_attribute_in_list("CN", attrs_set)
            True

            >>> FlextLdifUtilitiesSchema.is_attribute_in_list("description", attrs)
            False

        """
        if not attribute_name or not attribute_list:
            return False

        # Normalize input attribute name
        normalized_input = FlextLdifUtilitiesSchema.normalize_attribute_name(
            attribute_name,
        )

        # Check against normalized list/set items
        return any(
            FlextLdifUtilitiesSchema.normalize_attribute_name(attr) == normalized_input
            for attr in attribute_list
        )


__all__ = [
    "FlextLdifUtilitiesSchema",
]
