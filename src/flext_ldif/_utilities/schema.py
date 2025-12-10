"""Extracted nested class from FlextLdifUtilities.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import copy
import re
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime
from typing import cast

from flext_core import FlextLogger, FlextResult, FlextRuntime, FlextTypes

from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif._utilities.oid import FlextLdifUtilitiesOID
from flext_ldif._utilities.parser import FlextLdifUtilitiesParser
from flext_ldif._utilities.writer import FlextLdifUtilitiesWriter
from flext_ldif.constants import c
from flext_ldif.protocols import p
from flext_ldif.typings import t

# REMOVED: Type aliases redundantes - use m.* diretamente (já importado com runtime alias)
# SchemaAttribute: TypeAlias = FlextLdifModelsDomains.SchemaAttribute  # Use FlextLdifModelsDomains.SchemaAttribute directly
# SchemaObjectClass: TypeAlias = FlextLdifModelsDomains.SchemaObjectClass  # Use FlextLdifModelsDomains.SchemaObjectClass directly

logger = FlextLogger(__name__)


# TypedDicts moved to typings.py - import from there


def _convert_sequence_to_str_list(seq: Sequence[object]) -> list[str]:
    """Helper to convert Sequence to list[str] - avoids type narrowing issues in type checkers."""
    return [str(item) for item in seq]


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
    def validate_syntax_oid(syntax: str | None) -> str | None:
        r"""Validate syntax OID format.

        Generic validation for syntax OID fields used across server implementations.
        Checks that OID syntax conforms to standard OID format (numeric dot notation).

        Args:
            syntax: Syntax OID to validate

        Returns:
            Error message if validation fails, None otherwise

        """
        if syntax is None or not syntax.strip():
            return None

        validate_result = FlextLdifUtilitiesOID.validate_format(syntax)
        if validate_result.is_failure:
            return f"Syntax OID validation failed: {validate_result.error}"
        if not validate_result.unwrap():
            return f"Invalid syntax OID format: {syntax}"

        return None

    @staticmethod
    def detect_schema_type(
        definition: (
            str
            | FlextLdifModelsDomains.SchemaAttribute
            | FlextLdifModelsDomains.SchemaObjectClass
        ),
    ) -> str:
        r"""Detect schema type (attribute or objectclass) for automatic routing.

        Generic utility used by multiple server implementations to automatically
        classify schema definitions. Detects based on model type first, then
        uses RFC 4512 keyword patterns for string detection.

        Args:
            definition: Schema definition string or model.

        Returns:
            "attribute" or "objectclass".

        """
        if isinstance(definition, FlextLdifModelsDomains.SchemaAttribute):
            return "attribute"
        if isinstance(definition, FlextLdifModelsDomains.SchemaObjectClass):
            return "objectclass"
        # Try to detect from string content (definition is str at this point)
        definition_str = str(definition)
        definition_lower = definition_str.lower()

        # Check for objectClass-specific keywords (RFC 4512)
        # ObjectClasses have: STRUCTURAL, AUXILIARY, ABSTRACT, MUST, MAY
        # (Note: SUP is valid for both attributes and objectClasses, so excluded)
        # Attributes have: EQUALITY, SUBSTR, ORDERING, SYNTAX, USAGE, SINGLE-VALUE, NO-USER-MODIFICATION
        objectclass_only_keywords = [
            " structural",
            " auxiliary",
            " abstract",
            " must (",
            " may (",
        ]
        for keyword in objectclass_only_keywords:
            if keyword in definition_lower:
                return "objectclass"

        # Check for attribute-specific keywords (more accurate detection)
        # These keywords ONLY appear in attribute definitions
        attribute_only_keywords = [
            " equality ",
            " substr ",
            " ordering ",
            " syntax ",
            " usage ",
            " single-value",
            " no-user-modification",
        ]
        for keyword in attribute_only_keywords:
            if keyword in definition_lower:
                return "attribute"

        # Legacy check for explicit objectclass keyword
        if "objectclass" in definition_lower or "oclass" in definition_lower:
            return "objectclass"

        # Default to attribute if ambiguous
        return "attribute"

    @staticmethod
    def _apply_field_transformation(
        transformed: FlextLdifModelsDomains.SchemaAttribute
        | FlextLdifModelsDomains.SchemaObjectClass,
        field_name: str,
        transform_fn: Callable[
            [FlextTypes.GeneralValueType],
            FlextTypes.GeneralValueType | FlextResult[FlextTypes.GeneralValueType],
        ],
    ) -> FlextResult[
        FlextLdifModelsDomains.SchemaAttribute
        | FlextLdifModelsDomains.SchemaObjectClass
    ]:
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
        transformed: FlextLdifModelsDomains.SchemaAttribute
        | FlextLdifModelsDomains.SchemaObjectClass,
        _original_type: FlextLdifModelsDomains.SchemaAttribute
        | FlextLdifModelsDomains.SchemaObjectClass,
    ) -> FlextResult[
        FlextLdifModelsDomains.SchemaAttribute
        | FlextLdifModelsDomains.SchemaObjectClass
    ]:
        """Wrap transformation result with proper type.

        Args:
            transformed: The transformed schema object
            _original_type: Original type (unused, kept for API compatibility)

        """
        if isinstance(transformed, FlextLdifModelsDomains.SchemaAttribute):
            return FlextResult.ok(transformed)
        if isinstance(transformed, FlextLdifModelsDomains.SchemaObjectClass):
            return FlextResult.ok(transformed)
        # Fallback for unknown types
        return FlextResult.fail(
            f"Unknown schema object type: {type(transformed).__name__}",
        )

    @staticmethod
    def _create_schema_copy(
        schema_obj: FlextLdifModelsDomains.SchemaAttribute
        | FlextLdifModelsDomains.SchemaObjectClass,
    ) -> (
        FlextLdifModelsDomains.SchemaAttribute
        | FlextLdifModelsDomains.SchemaObjectClass
    ):
        """Create a copy of the schema object."""
        if hasattr(schema_obj, "model_copy"):
            return schema_obj.model_copy()
        return copy.copy(schema_obj)

    @staticmethod
    def _validate_transformation_result(
        unwrapped: FlextLdifModelsDomains.SchemaAttribute
        | FlextLdifModelsDomains.SchemaObjectClass,
        schema_obj: FlextLdifModelsDomains.SchemaAttribute
        | FlextLdifModelsDomains.SchemaObjectClass,
    ) -> FlextResult[
        FlextLdifModelsDomains.SchemaAttribute
        | FlextLdifModelsDomains.SchemaObjectClass
    ]:
        """Validate that transformation result matches input type."""
        if isinstance(schema_obj, FlextLdifModelsDomains.SchemaAttribute):
            if isinstance(unwrapped, FlextLdifModelsDomains.SchemaAttribute):
                return FlextResult.ok(unwrapped)
            return FlextResult.fail(
                "Field transformation returned unexpected type for SchemaAttribute",
            )
        if isinstance(schema_obj, FlextLdifModelsDomains.SchemaObjectClass):
            if isinstance(unwrapped, FlextLdifModelsDomains.SchemaObjectClass):
                return FlextResult.ok(unwrapped)
            return FlextResult.fail(
                "Field transformation returned unexpected type for SchemaObjectClass",
            )
        return FlextResult.fail(
            f"Unknown schema object type: {type(schema_obj).__name__}",
        )

    @staticmethod
    def _apply_field_transforms(
        transformed: FlextLdifModelsDomains.SchemaAttribute
        | FlextLdifModelsDomains.SchemaObjectClass,
        field_transforms: dict[
            str,
            Callable[
                [FlextTypes.GeneralValueType],
                FlextTypes.GeneralValueType | FlextResult[FlextTypes.GeneralValueType],
            ]
            | str
            | list[str]
            | None,
        ],
        schema_obj: FlextLdifModelsDomains.SchemaAttribute
        | FlextLdifModelsDomains.SchemaObjectClass,
    ) -> FlextResult[
        FlextLdifModelsDomains.SchemaAttribute
        | FlextLdifModelsDomains.SchemaObjectClass
    ]:
        """Apply all field transformations."""
        # Declare variable with explicit type to help type checker
        current: (
            FlextLdifModelsDomains.SchemaAttribute
            | FlextLdifModelsDomains.SchemaObjectClass
        ) = transformed

        for field_name, transform_fn in field_transforms.items():
            if not hasattr(current, field_name):
                continue

            # Type narrowing: transform_fn may be str | list[str] | None, handle accordingly
            if isinstance(transform_fn, (str, list)) or transform_fn is None:
                # Skip non-callable transforms
                continue
            # After isinstance check, transform_fn is Callable
            transform_callable: Callable[
                [FlextTypes.GeneralValueType],
                FlextTypes.GeneralValueType | FlextResult[FlextTypes.GeneralValueType],
            ] = transform_fn
            result = FlextLdifUtilitiesSchema._apply_field_transformation(
                current,
                field_name,
                transform_callable,
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
                (
                    FlextLdifModelsDomains.SchemaAttribute,
                    FlextLdifModelsDomains.SchemaObjectClass,
                ),
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
            (
                FlextLdifModelsDomains.SchemaAttribute,
                FlextLdifModelsDomains.SchemaObjectClass,
            ),
        ):
            return FlextResult.fail(
                f"Type narrowing failed: {type(current).__name__}",
            )
        return FlextResult[
            FlextLdifModelsDomains.SchemaAttribute
            | FlextLdifModelsDomains.SchemaObjectClass
        ].ok(current)

    @staticmethod
    def apply_transformations(
        schema_obj: FlextLdifModelsDomains.SchemaAttribute
        | FlextLdifModelsDomains.SchemaObjectClass,
        *,
        field_transforms: (
            dict[
                str,
                Callable[
                    [FlextTypes.GeneralValueType],
                    FlextTypes.GeneralValueType
                    | FlextResult[FlextTypes.GeneralValueType],
                ]
                | str
                | list[str]
                | None,
            ]
            | None
        ) = None,
    ) -> FlextResult[
        FlextLdifModelsDomains.SchemaAttribute
        | FlextLdifModelsDomains.SchemaObjectClass
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
        model_instance: FlextLdifModelsDomains.SchemaAttribute
        | FlextLdifModelsDomains.SchemaObjectClass,
        server_type: str,
    ) -> FlextResult[
        FlextLdifModelsDomains.SchemaAttribute
        | FlextLdifModelsDomains.SchemaObjectClass
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
                FlextLdifModelsDomains.SchemaAttribute
                | FlextLdifModelsDomains.SchemaObjectClass
            ],
        ]
        | Callable[[str], FlextResult[FlextLdifModelsDomains.SchemaAttribute]]
        | Callable[[str], FlextResult[FlextLdifModelsDomains.SchemaObjectClass]],
        line_prefix: str,
    ) -> list[
        FlextLdifModelsDomains.SchemaAttribute
        | FlextLdifModelsDomains.SchemaObjectClass
    ]:
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
            FlextLdifModelsDomains.SchemaAttribute
            | FlextLdifModelsDomains.SchemaObjectClass
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
                            FlextLdifModelsDomains.SchemaAttribute,
                            FlextLdifModelsDomains.SchemaObjectClass,
                        ),
                    ):
                        items.append(unwrapped)

        return items

    @staticmethod
    def extract_attributes_from_lines(
        ldif_content: str,
        parse_callback: Callable[
            [str], FlextResult[FlextLdifModelsDomains.SchemaAttribute]
        ],
    ) -> list[FlextLdifModelsDomains.SchemaAttribute]:
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
            item
            for item in items
            if isinstance(item, FlextLdifModelsDomains.SchemaAttribute)
        ]

    @staticmethod
    def extract_objectclasses_from_lines(
        ldif_content: str,
        parse_callback: Callable[
            [str], FlextResult[FlextLdifModelsDomains.SchemaObjectClass]
        ],
    ) -> list[FlextLdifModelsDomains.SchemaObjectClass]:
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
            if isinstance(item, FlextLdifModelsDomains.SchemaObjectClass)
        ]

    @staticmethod
    def build_available_attributes_set(
        attributes: list[FlextLdifModelsDomains.SchemaAttribute],
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
            if not isinstance(attr_data, FlextLdifModelsDomains.SchemaAttribute):
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
        additional_extensions: dict[str, t.MetadataAttributeValue] | None = None,
    ) -> dict[str, t.MetadataAttributeValue]:
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
        extensions_raw = FlextLdifUtilitiesParser.extract_extensions(definition)
        # ExtensionsDict is dict[str, str | list[str] | bool | None]
        # Convert to dict[str, MetadataAttributeValue] for compatibility
        extensions: dict[str, t.MetadataAttributeValue] = dict(extensions_raw.items())

        # Store original format for round-trip fidelity
        extensions[c.Ldif.MetadataKeys.ORIGINAL_FORMAT] = definition.strip()

        # Add any additional extensions
        if additional_extensions:
            extensions.update(additional_extensions)

        return extensions

    @staticmethod
    def _extract_attribute_basic_fields(
        attr_definition: str,
    ) -> tuple[str, str, str | None]:
        """Extract OID, NAME, and DESC from attribute definition."""
        oid = FlextLdifUtilitiesParser.extract_oid(attr_definition)
        if not oid:
            msg = "RFC attribute parsing failed: missing an OID"
            raise ValueError(msg)

        name_raw = FlextLdifUtilitiesParser.extract_optional_field(
            attr_definition,
            c.Ldif.LdifPatterns.SCHEMA_NAME,
            default=oid,
        )
        # Type narrowing: when default is provided, result is never None
        name: str = name_raw if name_raw is not None else oid

        desc = FlextLdifUtilitiesParser.extract_optional_field(
            attr_definition,
            c.Ldif.LdifPatterns.SCHEMA_DESC,
        )

        return oid, name, desc

    @staticmethod
    def _extract_attribute_syntax(
        attr_definition: str,
    ) -> tuple[str | None, int | None]:
        """Extract SYNTAX and length from attribute definition."""
        syntax_match = re.search(
            c.Ldif.LdifPatterns.SCHEMA_SYNTAX_LENGTH,
            attr_definition,
        )
        syntax = syntax_match.group(1) if syntax_match else None
        length = (
            int(syntax_match.group(2))
            if syntax_match and syntax_match.group(2)
            else None
        )
        return syntax, length

    @staticmethod
    def _validate_attribute_syntax(
        syntax: str | None,
    ) -> dict[str, t.MetadataAttributeValue] | None:
        """Validate syntax OID and return validation result."""
        if not syntax or not syntax.strip():
            return None

        syntax_extensions: dict[str, bool | list[str] | str | None] = {}
        validate_result = FlextLdifUtilitiesOID.validate_format(syntax)
        if validate_result.is_failure:
            syntax_extensions[c.Ldif.MetadataKeys.SYNTAX_VALIDATION_ERROR] = (
                f"Syntax OID validation failed: {validate_result.error}"
            )
        elif not validate_result.unwrap():
            syntax_extensions[c.Ldif.MetadataKeys.SYNTAX_VALIDATION_ERROR] = (
                f"Invalid syntax OID format: {syntax} "
                f"(must be numeric dot-separated format)"
            )
        syntax_extensions[c.Ldif.MetadataKeys.SYNTAX_OID_VALID] = (
            c.Ldif.MetadataKeys.SYNTAX_VALIDATION_ERROR not in syntax_extensions
        )
        return dict(syntax_extensions.items())

    @staticmethod
    def _extract_attribute_matching_rules(
        attr_definition: str,
    ) -> tuple[str | None, str | None, str | None]:
        """Extract matching rules (equality, substr, ordering) from attribute definition."""
        equality = FlextLdifUtilitiesParser.extract_optional_field(
            attr_definition,
            c.Ldif.LdifPatterns.SCHEMA_EQUALITY,
        )
        substr = FlextLdifUtilitiesParser.extract_optional_field(
            attr_definition,
            c.Ldif.LdifPatterns.SCHEMA_SUBSTR,
        )
        ordering = FlextLdifUtilitiesParser.extract_optional_field(
            attr_definition,
            c.Ldif.LdifPatterns.SCHEMA_ORDERING,
        )
        return equality, substr, ordering

    @staticmethod
    def _extract_attribute_flags(
        attr_definition: str,
    ) -> tuple[bool, bool]:
        """Extract boolean flags (single_value, no_user_modification) from attribute definition."""
        single_value = FlextLdifUtilitiesParser.extract_boolean_flag(
            attr_definition,
            c.Ldif.LdifPatterns.SCHEMA_SINGLE_VALUE,
        )
        no_user_modification = FlextLdifUtilitiesParser.extract_boolean_flag(
            attr_definition,
            c.Ldif.LdifPatterns.SCHEMA_NO_USER_MODIFICATION,
        )
        return single_value, no_user_modification

    @staticmethod
    def _extract_attribute_sup_usage(
        attr_definition: str,
    ) -> tuple[str | None, str | None]:
        """Extract SUP and USAGE from attribute definition."""
        sup = FlextLdifUtilitiesParser.extract_optional_field(
            attr_definition,
            c.Ldif.LdifPatterns.SCHEMA_SUP,
        )
        usage = FlextLdifUtilitiesParser.extract_optional_field(
            attr_definition,
            c.Ldif.LdifPatterns.SCHEMA_USAGE,
        )
        return sup, usage

    @staticmethod
    def _convert_metadata_for_attribute(
        value: t.MetadataAttributeValue,
    ) -> t.ScalarValue | list[str] | dict[str, t.ScalarValue | list[str]]:
        """Convert MetadataAttributeValue for ParsedAttributeDict."""
        if isinstance(value, (str, int, float, bool, type(None))):
            return value
        if isinstance(value, datetime):
            return value.isoformat()
        if isinstance(value, Sequence) and not isinstance(value, str):
            return _convert_sequence_to_str_list(value)
        if isinstance(value, Mapping):
            converted_nested: dict[str, t.ScalarValue | list[str]] = {}
            mapping_value: Mapping[str, t.MetadataAttributeValue] = value
            for k, v_raw in mapping_value.items():
                k_str = str(k)
                if isinstance(v_raw, (str, int, float, bool, type(None))):
                    converted_nested[k_str] = v_raw
                elif isinstance(v_raw, datetime):
                    converted_nested[k_str] = v_raw.isoformat()
                elif isinstance(v_raw, Sequence) and not isinstance(v_raw, str):
                    converted_nested[k_str] = _convert_sequence_to_str_list(v_raw)
                elif isinstance(v_raw, Mapping):
                    converted_nested[k_str] = str(dict(v_raw.items()))
                else:
                    converted_nested[k_str] = str(v_raw)
            return converted_nested
        return str(value)

    @staticmethod
    def parse_attribute(
        attr_definition: str,
        *,
        validate_syntax: bool = True,
    ) -> t.Ldif.ModelMetadata.ParsedAttributeDict:
        """Parse RFC 4512 attribute definition into structured data.

        Generic parsing method that extracts all fields from attribute definition.
        Used by server quirks to get base parsing logic without duplication.

        Args:
            attr_definition: RFC 4512 attribute definition string
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
            - metadata_extensions: dict[str, t.MetadataAttributeValue]
            - syntax_validation: dict[str, t.MetadataAttributeValue] | None

        Raises:
            ValueError: If OID is missing or invalid

        """
        # Extract basic fields
        oid, name, desc = FlextLdifUtilitiesSchema._extract_attribute_basic_fields(
            attr_definition,
        )

        # Extract syntax and length
        syntax, length = FlextLdifUtilitiesSchema._extract_attribute_syntax(
            attr_definition,
        )

        # Validate syntax if requested
        syntax_validation_result: dict[str, t.MetadataAttributeValue] | None = None
        if validate_syntax:
            syntax_validation_result = (
                FlextLdifUtilitiesSchema._validate_attribute_syntax(syntax)
            )

        # Extract matching rules
        equality, substr, ordering = (
            FlextLdifUtilitiesSchema._extract_attribute_matching_rules(attr_definition)
        )

        # Extract flags
        single_value, no_user_modification = (
            FlextLdifUtilitiesSchema._extract_attribute_flags(attr_definition)
        )

        # Extract SUP and USAGE
        sup, usage = FlextLdifUtilitiesSchema._extract_attribute_sup_usage(
            attr_definition,
        )

        # Build metadata
        additional_extensions_converted: dict[str, t.MetadataAttributeValue] | None = (
            syntax_validation_result
        )

        extensions_raw = FlextLdifUtilitiesSchema.build_metadata(
            attr_definition,
            additional_extensions=additional_extensions_converted,
        )

        # Convert extensions
        extensions_converted: dict[
            str,
            t.ScalarValue | list[str] | dict[str, t.ScalarValue | list[str]],
        ] = {
            k: FlextLdifUtilitiesSchema._convert_metadata_for_attribute(v)
            for k, v in extensions_raw.items()
        }

        # Convert syntax validation
        syntax_validation_converted: (
            dict[str, t.ScalarValue | list[str] | dict[str, t.ScalarValue | list[str]]]
            | None
        ) = None
        if syntax_validation_result is not None:
            syntax_validation_converted = {
                k: FlextLdifUtilitiesSchema._convert_metadata_for_attribute(v)
                for k, v in syntax_validation_result.items()
            }

        # Build parsed attribute dict
        # NOTE: Types are runtime-compatible, pyrefly sees recursion in nested dict conversion
        # Cast to ensure type compatibility - convert_metadata_value ensures max 2-level nesting
        parsed_dict: t.Ldif.ModelMetadata.ParsedAttributeDict = cast(
            "t.Ldif.ModelMetadata.ParsedAttributeDict",
            {
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
                "metadata_extensions": extensions_converted,
                "syntax_validation": syntax_validation_converted,
            },
        )
        return parsed_dict

    @staticmethod
    def _extract_objectclass_basic_fields(
        oc_definition: str,
    ) -> tuple[str, str, str | None]:
        """Extract OID, NAME, and DESC from objectClass definition."""
        oid = FlextLdifUtilitiesParser.extract_oid(oc_definition)
        if not oid:
            msg = "RFC objectClass parsing failed: missing an OID"
            raise ValueError(msg)

        name_raw = FlextLdifUtilitiesParser.extract_optional_field(
            oc_definition,
            c.Ldif.LdifPatterns.SCHEMA_NAME,
            default=oid,
        )
        # Type narrowing: when default is provided, result is never None
        name: str = name_raw if name_raw is not None else oid

        desc = FlextLdifUtilitiesParser.extract_optional_field(
            oc_definition,
            c.Ldif.LdifPatterns.SCHEMA_DESC,
        )

        return oid, name, desc

    @staticmethod
    def _extract_objectclass_sup(
        oc_definition: str,
    ) -> str | None:
        """Extract SUP from objectClass definition."""
        sup_match = re.search(
            c.Ldif.LdifPatterns.SCHEMA_OBJECTCLASS_SUP,
            oc_definition,
        )
        if not sup_match:
            return None

        sup_value = sup_match.group(1) or sup_match.group(2)
        sup_value = sup_value.strip()
        return next(
            (s.strip() for s in sup_value.split("$")),
            sup_value,
        )

    @staticmethod
    def _extract_objectclass_kind(
        oc_definition: str,
    ) -> str:
        """Extract KIND from objectClass definition."""
        kind_match = re.search(
            c.Ldif.LdifPatterns.SCHEMA_OBJECTCLASS_KIND,
            oc_definition,
            re.IGNORECASE,
        )
        return (
            kind_match.group(1).upper()
            if kind_match
            else c.Ldif.SchemaKind.STRUCTURAL.value
        )

    @staticmethod
    def _extract_objectclass_must_may(
        oc_definition: str,
    ) -> tuple[list[str] | None, list[str] | None]:
        """Extract MUST and MAY attributes from objectClass definition."""
        must = None
        must_match = re.search(
            c.Ldif.LdifPatterns.SCHEMA_OBJECTCLASS_MUST,
            oc_definition,
        )
        if must_match:
            must_value = (must_match.group(1) or must_match.group(2)).strip()
            must = [m.strip() for m in must_value.split("$")]

        may = None
        may_match = re.search(
            c.Ldif.LdifPatterns.SCHEMA_OBJECTCLASS_MAY,
            oc_definition,
        )
        if may_match:
            may_value = (may_match.group(1) or may_match.group(2)).strip()
            may = [m.strip() for m in may_value.split("$")]

        return must, may

    @staticmethod
    def _convert_metadata_for_objectclass(
        value: t.MetadataAttributeValue,
    ) -> t.ScalarValue | list[str] | dict[str, t.ScalarValue | list[str]]:
        """Convert MetadataAttributeValue for ParsedObjectClassDict."""
        if isinstance(value, (str, int, float, bool, type(None))):
            return value
        if isinstance(value, datetime):
            return value.isoformat()
        if isinstance(value, Sequence) and not isinstance(value, str):
            return _convert_sequence_to_str_list(value)
        if isinstance(value, Mapping):
            converted_nested: dict[str, t.ScalarValue | list[str]] = {}
            mapping_value: Mapping[str, t.MetadataAttributeValue] = value
            for k, v_raw in mapping_value.items():
                k_str = str(k)
                if isinstance(v_raw, (str, int, float, bool, type(None))):
                    converted_nested[k_str] = v_raw
                elif isinstance(v_raw, datetime):
                    converted_nested[k_str] = v_raw.isoformat()
                elif isinstance(v_raw, Sequence) and not isinstance(v_raw, str):
                    converted_nested[k_str] = _convert_sequence_to_str_list(v_raw)
                elif isinstance(v_raw, Mapping):
                    converted_nested[k_str] = str(dict(v_raw.items()))
                else:
                    converted_nested[k_str] = str(v_raw)
            return converted_nested
        return str(value)

    @staticmethod
    def parse_objectclass(
        oc_definition: str,
    ) -> t.Ldif.ModelMetadata.ParsedObjectClassDict:
        """Parse RFC 4512 objectClass definition into structured data.

        Generic parsing method that extracts all fields from objectClass definition.
        Used by server quirks to get base parsing logic without duplication.

        Args:
            oc_definition: RFC 4512 objectClass definition string

        Returns:
            Dictionary with parsed fields:
            - oid: str (required)
            - name: str | None
            - desc: str | None
            - sup: str | None
            - kind: str (STRUCTURAL, AUXILIARY, or ABSTRACT)
            - must: list[str] | None
            - may: list[str] | None
            - metadata_extensions: dict[str, t.MetadataAttributeValue]

        Raises:
            ValueError: If OID is missing or invalid

        """
        # Extract basic fields
        oid, name, desc = FlextLdifUtilitiesSchema._extract_objectclass_basic_fields(
            oc_definition,
        )

        # Extract SUP
        sup = FlextLdifUtilitiesSchema._extract_objectclass_sup(oc_definition)

        # Extract KIND
        kind = FlextLdifUtilitiesSchema._extract_objectclass_kind(oc_definition)

        # Extract MUST and MAY
        must, may = FlextLdifUtilitiesSchema._extract_objectclass_must_may(
            oc_definition,
        )

        # Build metadata
        extensions_raw = FlextLdifUtilitiesSchema.build_metadata(oc_definition)

        # Convert extensions
        extensions_converted: dict[
            str,
            t.ScalarValue | list[str] | dict[str, t.ScalarValue | list[str]],
        ] = {
            k: FlextLdifUtilitiesSchema._convert_metadata_for_objectclass(v)
            for k, v in extensions_raw.items()
        }

        # Build parsed objectClass dict
        # NOTE: Types are runtime-compatible, pyrefly sees recursion in nested dict conversion
        # Cast to ensure type compatibility - _convert_metadata_for_objectclass ensures max 2-level nesting
        parsed_dict: t.Ldif.ModelMetadata.ParsedObjectClassDict = cast(
            "t.Ldif.ModelMetadata.ParsedObjectClassDict",
            {
                "oid": oid,
                "name": name,
                "desc": desc,
                "sup": sup,
                "kind": kind,
                "must": must,
                "may": may,
                "metadata_extensions": extensions_converted,
            },
        )
        return parsed_dict

    @staticmethod
    def _try_restore_original_format(
        attr_data: FlextLdifModelsDomains.SchemaAttribute,
    ) -> list[str] | None:
        """Try to restore original format from metadata for perfect round-trip.

        Args:
            attr_data: FlextLdifModelsDomains.SchemaAttribute model with potential metadata

        Returns:
            List with original format if available, None otherwise

        """
        if not (
            attr_data.metadata
            and attr_data.metadata.schema_format_details
            and getattr(
                attr_data.metadata.schema_format_details,
                "original_string_complete",
                None,
            )
        ):
            return None

        original = str(
            getattr(
                attr_data.metadata.schema_format_details,
                "original_string_complete",
                "",
            ),
        )
        if not original:
            return None

        # Extract definition part (remove prefix, handle nested parens)
        definition_match = re.search(r"\(.*\)", original, re.DOTALL)
        return [definition_match.group(0)] if definition_match else None

    @staticmethod
    def _build_name_part(
        attr_data: FlextLdifModelsDomains.SchemaAttribute
        | FlextLdifModelsDomains.SchemaObjectClass,
        *,
        restore_format: bool = False,
    ) -> str | None:
        """Build NAME part with optional format restoration.

        Args:
            attr_data: FlextLdifModelsDomains.SchemaAttribute model
            restore_format: If True, restore multiple names format from metadata

        Returns:
            NAME part string or None if no name

        """
        if not attr_data.name:
            return None

        if not restore_format or not attr_data.metadata:
            return f"NAME '{attr_data.name}'"

        schema_details = attr_data.metadata.schema_format_details
        if not schema_details:
            return f"NAME '{attr_data.name}'"
        name_format = getattr(schema_details, "name_format", "single")
        name_values_ = getattr(schema_details, "name_values", [])
        name_values: list[str] = (
            [str(v) for v in name_values_] if isinstance(name_values_, list) else []
        )

        if name_format == "multiple" and name_values:
            names_str = " ".join(f"'{n}'" for n in name_values)
            return f"NAME ( {names_str} )"

        return f"NAME '{attr_data.name}'"

    @staticmethod
    def _build_obsolete_part(
        attr_data: FlextLdifModelsDomains.SchemaAttribute
        | FlextLdifModelsDomains.SchemaObjectClass,
        parts: list[str],
        field_order: list[str] | None,
        *,
        restore_position: bool = False,
    ) -> None:
        """Build OBSOLETE part with optional position restoration.

        Args:
            attr_data: FlextLdifModelsDomains.SchemaAttribute model
            parts: Parts list to modify
            field_order: Field order from metadata (if available)
            restore_position: If True, restore original position

        """
        has_obsolete = False
        if attr_data.metadata:
            schema_details = attr_data.metadata.schema_format_details
            has_obsolete = bool(
                getattr(schema_details, "obsolete_presence", False)
                if schema_details
                else False,
            )
            if not has_obsolete:
                has_obsolete = bool(
                    attr_data.metadata.extensions.get(
                        c.Ldif.MetadataKeys.OBSOLETE,
                    ),
                )

        if not has_obsolete:
            return

        if restore_position and field_order and "OBSOLETE" in field_order:
            obs_pos = field_order.index("OBSOLETE")
            parts.insert(min(obs_pos, len(parts)), "OBSOLETE")
        else:
            parts.append("OBSOLETE")

    @staticmethod
    def _build_x_origin_part(
        attr_data: FlextLdifModelsDomains.SchemaAttribute
        | FlextLdifModelsDomains.SchemaObjectClass,
        *,
        restore_format: bool = False,
    ) -> str | None:
        """Build X-ORIGIN part with optional format restoration.

        Args:
            attr_data: FlextLdifModelsDomains.SchemaAttribute model
            restore_format: If True, use metadata value if available

        Returns:
            X-ORIGIN part string or None

        """
        if not attr_data.metadata:
            return None

        schema_details = attr_data.metadata.schema_format_details
        x_origin_value = None

        if (
            restore_format
            and schema_details
            and getattr(schema_details, "x_origin_presence", None)
            and getattr(schema_details, "x_origin_value", None)
        ):
            x_origin_value = getattr(schema_details, "x_origin_value", None)

        if not x_origin_value:
            x_origin_value = attr_data.metadata.extensions.get("x_origin")

        return f"X-ORIGIN '{x_origin_value}'" if x_origin_value else None

    @staticmethod
    def _get_field_order(
        attr_data: FlextLdifModelsDomains.SchemaAttribute,
    ) -> list[str] | None:
        """Extract field order from metadata if available.

        Args:
            attr_data: FlextLdifModelsDomains.SchemaAttribute model

        Returns:
            Field order list or None

        """
        if not attr_data.metadata or not attr_data.metadata.schema_format_details:
            return None

        field_order_ = getattr(
            attr_data.metadata.schema_format_details,
            "field_order",
            None,
        )
        if field_order_ and isinstance(field_order_, list):
            return [str(item) for item in field_order_]
        return None

    @staticmethod
    def _apply_trailing_spaces(
        attr_data: FlextLdifModelsDomains.SchemaAttribute
        | FlextLdifModelsDomains.SchemaObjectClass,
        parts: list[str],
    ) -> None:
        """Apply trailing spaces from metadata if available.

        Args:
            attr_data: FlextLdifModelsDomains.SchemaAttribute model
            parts: Parts list to modify (modifies last element)

        """
        if not attr_data.metadata or not attr_data.metadata.schema_format_details:
            return

        trailing = getattr(
            attr_data.metadata.schema_format_details,
            "trailing_spaces",
            "",
        )
        if trailing and parts:
            parts[-1] += str(trailing)

    @staticmethod
    def _build_attribute_parts_from_model(
        attr_data: p.Ldif.SchemaAttributeProtocol,
    ) -> list[str]:
        """Build RFC 4512 attribute definition parts (simple version)."""
        parts: list[str] = [f"( {attr_data.oid}"]

        if attr_data.name:
            parts.append(f"NAME '{attr_data.name}'")

        if attr_data.desc:
            parts.append(f"DESC '{attr_data.desc}'")

        if attr_data.metadata and attr_data.metadata.extensions.get(
            c.Ldif.MetadataKeys.OBSOLETE,
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
    def build_attribute_parts_with_metadata(
        attr_data: p.Ldif.SchemaAttributeProtocol
        | FlextLdifModelsDomains.SchemaAttribute,
        *,
        restore_original: bool = True,
    ) -> list[str]:
        """Build RFC 4512 attribute parts with full metadata restoration.

        Generalized version that supports perfect round-trip by restoring
        original format, NAME format, OBSOLETE position, X-ORIGIN, and
        trailing spaces from metadata when available.

        Args:
            attr_data: SchemaAttribute model (accepts both facade and domain models)
            restore_original: If True, try to restore original format first

        Returns:
            List of RFC-compliant attribute definition parts

        """
        # Try original format restoration first (perfect round-trip)
        if restore_original:
            original_parts = FlextLdifUtilitiesSchema._try_restore_original_format(
                attr_data,
            )
            if original_parts:
                return original_parts

        # Build RFC-compliant parts with metadata restoration
        parts: list[str] = [f"( {attr_data.oid}"]
        field_order = FlextLdifUtilitiesSchema._get_field_order(attr_data)

        # NAME with format restoration
        name_part = FlextLdifUtilitiesSchema._build_name_part(
            attr_data,
            restore_format=True,
        )
        if name_part:
            parts.append(name_part)

        # DESC and SUP (simple fields)
        if attr_data.desc:
            parts.append(f"DESC '{attr_data.desc}'")
        if attr_data.sup:
            parts.append(f"SUP {attr_data.sup}")
        if attr_data.usage:
            parts.append(f"USAGE {attr_data.usage}")

        # OBSOLETE with position restoration
        FlextLdifUtilitiesSchema._build_obsolete_part(
            attr_data,
            parts,
            field_order,
            restore_position=True,
        )

        # Matching rules, syntax, flags
        FlextLdifUtilitiesWriter.add_attribute_matching_rules(attr_data, parts)
        FlextLdifUtilitiesWriter.add_attribute_syntax(attr_data, parts)
        FlextLdifUtilitiesWriter.add_attribute_flags(attr_data, parts)

        # X-ORIGIN with restoration
        x_origin_part = FlextLdifUtilitiesSchema._build_x_origin_part(
            attr_data,
            restore_format=True,
        )
        if x_origin_part:
            parts.append(x_origin_part)

        parts.append(")")

        # Trailing spaces restoration
        FlextLdifUtilitiesSchema._apply_trailing_spaces(attr_data, parts)

        return parts

    @staticmethod
    def _format_attribute_list(
        attr_list: str | list[str] | None,
        prefix: str,
    ) -> str | None:
        """Format attribute list (MUST/MAY) for objectClass definition.

        Args:
            attr_list: Attribute list (single value or list)
            prefix: Prefix string (MUST or MAY)

        Returns:
            Formatted string or None if empty

        """
        if not attr_list:
            return None

        if FlextRuntime.is_list_like(attr_list) and isinstance(attr_list, list):
            attr_strs = [str(item) for item in attr_list]
            if len(attr_strs) == 1:
                return f"{prefix} {attr_strs[0]}"
            return f"{prefix} ( {' $ '.join(attr_strs)} )"

        return f"{prefix} {attr_list}"

    @staticmethod
    def _format_sup_list(
        sup_value: str | list[str] | None,
    ) -> str | None:
        """Format SUP (superior) list for objectClass definition.

        Args:
            sup_value: SUP value (single value or list)

        Returns:
            Formatted string or None if empty

        """
        if not sup_value:
            return None

        if FlextRuntime.is_list_like(sup_value) and isinstance(sup_value, list):
            sup_strs = [str(item) for item in sup_value]
            return f"SUP ( {' $ '.join(sup_strs)} )"

        return f"SUP {sup_value}"

    @staticmethod
    def _try_restore_objectclass_original_format(
        oc_data: FlextLdifModelsDomains.SchemaObjectClass,
        *,
        restore_original: bool = True,
    ) -> list[str] | None:
        """Try to restore original format from metadata for objectClass.

        Args:
            oc_data: FlextLdifModelsDomains.SchemaObjectClass model
            restore_original: Whether to attempt restoration

        Returns:
            Original format parts if found, None otherwise

        """
        if not restore_original or not oc_data.metadata:
            return None

        schema_details = oc_data.metadata.schema_format_details
        if not schema_details:
            return None

        original = str(getattr(schema_details, "original_string_complete", ""))
        if not original:
            return None

        definition_match = re.search(r"\(.*\)", original, re.DOTALL)
        if definition_match:
            return [definition_match.group(0)]

        return None

    @staticmethod
    def build_objectclass_parts_with_metadata(
        oc_data: FlextLdifModelsDomains.SchemaObjectClass,
        *,
        restore_original: bool = True,
    ) -> list[str]:
        """Build RFC 4512 objectClass parts with full metadata restoration.

        Generalized version that supports perfect round-trip by restoring
        original format, NAME format, OBSOLETE position, SUP format, and
        X-ORIGIN from metadata when available.

        Args:
            oc_data: FlextLdifModelsDomains.SchemaObjectClass model
            restore_original: If True, try to restore original format first

        Returns:
            List of RFC-compliant objectClass definition parts

        """
        # Try original format restoration first (perfect round-trip)
        original_parts = (
            FlextLdifUtilitiesSchema._try_restore_objectclass_original_format(
                oc_data,
                restore_original=restore_original,
            )
        )
        if original_parts:
            return original_parts

        # Build RFC-compliant parts with metadata restoration
        parts: list[str] = [f"( {oc_data.oid}"]

        # NAME with format restoration
        name_part = FlextLdifUtilitiesSchema._build_name_part(
            oc_data,
            restore_format=True,
        )
        if name_part:
            parts.append(name_part)

        # DESC (simple field)
        if oc_data.desc:
            parts.append(f"DESC '{oc_data.desc}'")

        # OBSOLETE with position restoration
        field_order = None
        if oc_data.metadata and oc_data.metadata.schema_format_details:
            field_order_ = getattr(
                oc_data.metadata.schema_format_details,
                "field_order",
                None,
            )
            if field_order_ and isinstance(field_order_, list):
                field_order = [str(item) for item in field_order_]

        FlextLdifUtilitiesSchema._build_obsolete_part(
            oc_data,
            parts,
            field_order,
            restore_position=True,
        )

        # SUP - handle single or multiple
        sup_part = FlextLdifUtilitiesSchema._format_sup_list(oc_data.sup)
        if sup_part:
            parts.append(sup_part)

        # KIND (structural, auxiliary, abstract)
        kind = oc_data.kind or c.Ldif.SchemaKind.STRUCTURAL.value
        parts.append(str(kind))

        # MUST and MAY attributes (using helper)
        must_part = FlextLdifUtilitiesSchema._format_attribute_list(
            oc_data.must,
            "MUST",
        )
        if must_part:
            parts.append(must_part)

        may_part = FlextLdifUtilitiesSchema._format_attribute_list(oc_data.may, "MAY")
        if may_part:
            parts.append(may_part)

        # X-ORIGIN with restoration
        x_origin_part = FlextLdifUtilitiesSchema._build_x_origin_part(
            oc_data,
            restore_format=True,
        )
        if x_origin_part:
            parts.append(x_origin_part)

        parts.append(")")

        # Trailing spaces restoration
        FlextLdifUtilitiesSchema._apply_trailing_spaces(oc_data, parts)

        return parts

    @staticmethod
    def _write_schema_element(
        data: FlextLdifModelsDomains.SchemaAttribute
        | FlextLdifModelsDomains.SchemaObjectClass,
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
        attr_data: FlextLdifModelsDomains.SchemaAttribute,
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
            FlextLdifModelsDomains.SchemaAttribute,
            "attr_data",
            FlextLdifUtilitiesSchema._build_attribute_parts_from_model,
        )

    @staticmethod
    def _add_objectclass_sup(
        oc_data: FlextLdifModelsDomains.SchemaObjectClass,
        parts: list[str],
    ) -> None:
        """Add SUP to objectclass parts list."""
        if oc_data.sup:
            if FlextRuntime.is_list_like(oc_data.sup):
                if not isinstance(oc_data.sup, list):
                    msg = f"Expected list, got {type(oc_data.sup)}"
                    raise TypeError(msg)
                sup_list_str: list[str] = [str(item) for item in oc_data.sup]
                if len(sup_list_str) == 1:
                    parts.append(f"SUP {sup_list_str[0]}")
                else:
                    sup_str = " $ ".join(sup_list_str)
                    parts.append(f"SUP ( {sup_str} )")
            else:
                parts.append(f"SUP {oc_data.sup}")

    @staticmethod
    def _add_objectclass_must_may(
        oc_data: FlextLdifModelsDomains.SchemaObjectClass,
        parts: list[str],
    ) -> None:
        """Add MUST and MAY to objectclass parts list."""
        if oc_data.must:
            if FlextRuntime.is_list_like(oc_data.must):
                if not isinstance(oc_data.must, list):
                    msg = f"Expected list, got {type(oc_data.must)}"
                    raise TypeError(msg)
                must_list_str: list[str] = [str(item) for item in oc_data.must]
                if len(must_list_str) == 1:
                    parts.append(f"MUST {must_list_str[0]}")
                else:
                    must_str = " $ ".join(must_list_str)
                    parts.append(f"MUST ( {must_str} )")
            else:
                parts.append(f"MUST {oc_data.must}")

        if oc_data.may:
            if FlextRuntime.is_list_like(oc_data.may):
                if not isinstance(oc_data.may, list):
                    msg = f"Expected list, got {type(oc_data.may)}"
                    raise TypeError(msg)
                may_list_str: list[str] = [str(item) for item in oc_data.may]
                if len(may_list_str) == 1:
                    parts.append(f"MAY {may_list_str[0]}")
                else:
                    may_str = " $ ".join(may_list_str)
                    parts.append(f"MAY ( {may_str} )")
            else:
                parts.append(f"MAY {oc_data.may}")

    @staticmethod
    def _build_objectclass_parts_from_model(
        oc_data: FlextLdifModelsDomains.SchemaObjectClass,
    ) -> list[str]:
        """Build RFC 4512 objectClass definition parts (extracted to reduce complexity)."""
        parts: list[str] = [f"( {oc_data.oid}"]

        if oc_data.name:
            parts.append(f"NAME '{oc_data.name}'")

        if oc_data.desc:
            parts.append(f"DESC '{oc_data.desc}'")

        if oc_data.metadata and oc_data.metadata.extensions.get(
            c.Ldif.MetadataKeys.OBSOLETE,
        ):
            parts.append("OBSOLETE")

        FlextLdifUtilitiesSchema._add_objectclass_sup(oc_data, parts)

        kind = oc_data.kind or c.Ldif.SchemaKind.STRUCTURAL.value
        parts.append(str(kind))

        FlextLdifUtilitiesSchema._add_objectclass_must_may(oc_data, parts)

        if oc_data.metadata and oc_data.metadata.extensions.get("x_origin"):
            parts.append(f"X-ORIGIN '{oc_data.metadata.extensions.get('x_origin')}'")

        parts.append(")")

        return parts

    @staticmethod
    def write_objectclass(
        oc_data: FlextLdifModelsDomains.SchemaObjectClass,
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
            FlextLdifModelsDomains.SchemaObjectClass,
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

    @staticmethod
    def find_missing_attributes(
        attr_list: list[str] | str | None,
        available_attributes: set[str],
    ) -> list[str]:
        """Find attributes missing from available set.

        Generic helper for validating MUST/MAY attribute dependencies.

        Args:
            attr_list: List of attribute names or single name
            available_attributes: Set of available attributes

        Returns:
            List of missing attribute names

        """
        if not attr_list:
            return []

        # Normalize to list of strings
        if isinstance(attr_list, str):
            attrs = [attr_list]
        elif isinstance(attr_list, list):
            attrs = [str(a) for a in attr_list]
        else:
            return []

        return [
            a
            for a in attrs
            if not FlextLdifUtilitiesSchema.is_attribute_in_list(
                a,
                available_attributes,
            )
        ]

    @staticmethod
    def validate_objectclass_dependencies(
        oc_name: str | None,
        oc_oid: str | None,
        must_attrs: list[str] | str | None,
        may_attrs: list[str] | str | None,
        available_attributes: set[str],
    ) -> tuple[bool, list[str]]:
        """Validate objectclass attribute dependencies.

        Checks if all MUST and MAY attributes exist in available set.

        Args:
            oc_name: ObjectClass name
            oc_oid: ObjectClass OID
            must_attrs: Required attributes list
            may_attrs: Optional attributes list
            available_attributes: Set of available attribute names

        Returns:
            Tuple of (is_valid, missing_attributes)

        """
        if not oc_name or not oc_oid:
            return False, []

        missing: list[str] = []
        missing.extend(
            FlextLdifUtilitiesSchema.find_missing_attributes(
                must_attrs,
                available_attributes,
            ),
        )
        missing.extend(
            FlextLdifUtilitiesSchema.find_missing_attributes(
                may_attrs,
                available_attributes,
            ),
        )
        return len(missing) == 0, missing

    @staticmethod
    def replace_invalid_substr_rule(
        substr: str | None,
        invalid_rules: Mapping[str, str | None],
    ) -> str | None:
        """Replace invalid SUBSTR rule with valid replacement.

        Centralizes invalid SUBSTR rule replacement logic used by multiple
        server implementations (OID, OUD, etc.).

        Args:
            substr: Current SUBSTR rule value
            invalid_rules: Mapping of invalid rules to replacements.
                           If value is None, rule is removed (returns None).
                           If value is str, rule is replaced with that value.

        Returns:
            Replacement SUBSTR rule, or original if not in invalid_rules

        Example:
            >>> invalid = {
            ...     "caseExactSubstringsMatch": "caseIgnoreSubstringsMatch",
            ...     "unsupportedRule": None,
            ... }  # None = remove
            >>> FlextLdifUtilitiesSchema.replace_invalid_substr_rule(
            ...     "caseExactSubstringsMatch", invalid
            ... )
            'caseIgnoreSubstringsMatch'
            >>> FlextLdifUtilitiesSchema.replace_invalid_substr_rule(
            ...     "unsupportedRule", invalid
            ... )
            None

        """
        if not substr or not invalid_rules:
            return substr

        if substr in invalid_rules:
            return invalid_rules[substr]

        return substr


__all__ = [
    "FlextLdifUtilitiesSchema",
]
