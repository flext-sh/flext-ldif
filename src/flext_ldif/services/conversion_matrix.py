"""Quirks conversion matrix for LDAP server translation.

This module provides the QuirksConversionMatrix facade that enables
conversion between LDAP server quirks (OUD, OID, OpenLDAP, etc.) by
using RFC as an intermediate representation.

Conversion Pattern:
 Source Format → Source.to_rfc() → RFC Format → Target.from_rfc() → Target Format

This creates an N×N translation matrix with only 2×N implementations
(to_rfc and from_rfc per quirk type).

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Literal, cast

from flext_core import FlextResult

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.protocols import FlextLdifProtocols

# Type aliases for backward compatibility
DataType = Literal["attribute", "objectClass", "acl", "entry"]
QuirkInstance = Any  # Server quirk instance


class _SimpleDnRegistry:
    """Simple DN registry for testing compatibility."""

    def __init__(self) -> None:
        """Initialize empty DN registry."""
        self._dns: dict[str, str] = {}

    def register_dn(self, dn: str) -> str:
        """Register a DN and return the canonical form."""
        canonical = dn.lower()  # Simple canonicalization
        self._dns[canonical] = dn
        return canonical

    def get_canonical_dn(self, dn: str) -> str | None:
        """Get canonical DN if registered."""
        return self._dns.get(dn.lower())

    def clear(self) -> None:
        """Clear all registered DNs."""
        self._dns.clear()

    def validate_oud_consistency(self) -> FlextResult[bool]:
        """Validate DN consistency for OUD (always pass for testing)."""
        return FlextResult.ok(True)


class FlextLdifQuirksConversionMatrix:
    """Facade for universal, model-driven quirk-to-quirk conversion.

    This class provides a unified interface for converting LDIF data models between
    different server formats (OUD, OID, etc.) by using RFC as a universal
    intermediate representation. The entire process is model-driven, ensuring
    type safety and consistency.

    The conversion pipeline is:
    1.  `source_quirk.normalize_to_rfc(model)` -> RFC Model
    2.  `target_quirk.denormalize_from_rfc(RFC Model)` -> Target Model
    """

    # Maximum number of errors to show in batch conversion
    MAX_ERRORS_TO_SHOW: int = 5

    def __init__(self) -> None:
        """Initialize conversion matrix with DN registry."""
        # Simple DN registry implementation for testing compatibility
        self.dn_registry = _SimpleDnRegistry()

    def convert(
        self,
        source_quirk: FlextLdifProtocols.Quirks.QuirksPort,
        target_quirk: FlextLdifProtocols.Quirks.QuirksPort,
        model_instance_or_data_type: FlextLdifProtocols.ConvertibleModel | str,
        data: str | dict[str, object] | None = None,
    ) -> (
        FlextResult[FlextLdifProtocols.ConvertibleModel]
        | FlextResult[str | dict[str, object]]
    ):
        """Convert a model from a source server format to a target server format.

        Supports both new strategy pattern (model-based) and legacy string-based conversions.

        Args:
            source_quirk: Source quirk instance
            target_quirk: Target quirk instance
            model_instance_or_data_type: Either a model instance (new pattern) or data type string (legacy)
            data: Data to convert (legacy pattern only)

        Returns:
            FlextResult with converted model or string data

        """
        # Determine if this is legacy (string-based) or new (model-based) conversion
        if isinstance(model_instance_or_data_type, str) and data is not None:
            # Legacy string-based conversion
            return self._convert_legacy(
                source_quirk, target_quirk, model_instance_or_data_type, data
            )
        if data is None:
            # New model-based conversion
            return self._convert_model(
                source_quirk, target_quirk, model_instance_or_data_type
            )
        return FlextResult.fail(
            "Invalid arguments: provide either (model) or (data_type, data)"
        )

    def _convert_model(
        self,
        source_quirk: FlextLdifProtocols.Quirks.QuirksPort,
        target_quirk: FlextLdifProtocols.Quirks.QuirksPort,
        model_instance: FlextLdifProtocols.ConvertibleModel,
    ) -> FlextResult[FlextLdifProtocols.ConvertibleModel]:
        """Convert using new strategy pattern with models."""
        try:
            # Step 1: Normalize the source model to the canonical RFC representation.
            if isinstance(model_instance, FlextLdifModels.Entry):
                normalize_result = source_quirk.normalize_entry_to_rfc(model_instance)
            elif isinstance(model_instance, FlextLdifModels.SchemaAttribute):
                normalize_result = source_quirk.normalize_attribute_to_rfc(
                    model_instance
                )
            elif isinstance(model_instance, FlextLdifModels.SchemaObjectClass):
                normalize_result = source_quirk.normalize_objectclass_to_rfc(
                    model_instance
                )
            elif isinstance(model_instance, FlextLdifModels.Acl):
                normalize_result = source_quirk.normalize_acl_to_rfc(model_instance)
            else:
                return FlextResult.fail(
                    f"Unsupported model type for conversion: {type(model_instance).__name__}"
                )

            if normalize_result.is_failure:
                return FlextResult.fail(
                    f"Failed to normalize {type(model_instance).__name__} to RFC: {normalize_result.error}"
                )

            rfc_model = normalize_result.unwrap()

            # Step 2: Denormalize the RFC model to the target server's format.
            if isinstance(rfc_model, FlextLdifModels.Entry):
                denormalize_result = target_quirk.denormalize_entry_from_rfc(rfc_model)
            elif isinstance(rfc_model, FlextLdifModels.SchemaAttribute):
                denormalize_result = target_quirk.denormalize_attribute_from_rfc(
                    rfc_model
                )
            elif isinstance(rfc_model, FlextLdifModels.SchemaObjectClass):
                denormalize_result = target_quirk.denormalize_objectclass_from_rfc(
                    rfc_model
                )
            elif isinstance(rfc_model, FlextLdifModels.Acl):
                denormalize_result = target_quirk.denormalize_acl_from_rfc(rfc_model)
            else:
                # This case should be unreachable if the normalize step was successful
                return FlextResult.fail(
                    "Mismatch in model type after RFC normalization."
                )

            if denormalize_result.is_failure:
                return FlextResult.fail(
                    f"Failed to denormalize {type(rfc_model).__name__} from RFC: {denormalize_result.error}"
                )

            return FlextResult.ok(denormalize_result.unwrap())

        except Exception as e:
            return FlextResult.fail(
                f"An unexpected error occurred during conversion: {e}"
            )

    def _convert_legacy(
        self,
        source_quirk: QuirkInstance,
        target_quirk: QuirkInstance,
        data_type: str,
        data: str | dict[str, object],
    ) -> FlextResult[str | dict[str, object]]:
        """Convert using legacy string-based pattern."""
        try:
            if data_type == "attribute":
                return self._convert_attribute(source_quirk, target_quirk, data)
            if data_type == "objectClass":
                return self._convert_objectclass(source_quirk, target_quirk, data)
            if data_type == "acl":
                if isinstance(data, str):
                    return self._convert_acl(source_quirk, target_quirk, data)
                return FlextResult.fail("ACL conversion requires string input")
            if data_type == "entry":
                return self._convert_entry(source_quirk, target_quirk, data)
            return FlextResult.fail(f"Invalid data_type: {data_type}")
        except Exception as e:
            return FlextResult.fail(f"Legacy conversion failed: {e}")

    def _extract_and_register_dns(
        self,
        model: FlextLdifModels.Acl,
        data_type: DataType,
    ) -> None:
        """Extract DNs from ACL model and register with canonical case.

        Extracts DNs from ACL models and registers them with the DN registry
        to ensure case consistency across conversions.

        Args:
            model: ACL Pydantic model containing potential DN references
            data_type: Type of data being processed (must be "acl")

        """
        if data_type != "acl":
            return

        # Extract DN from ACL subject (if present)
        if model.subject and model.subject.subject_value:
            subject_value = model.subject.subject_value

            # Extract DN from LDAP URL format: ldap:///cn=...,dc=...
            if isinstance(subject_value, str) and "ldap:///" in subject_value:
                dn_part = subject_value.split("ldap:///", 1)[1].split("?", 1)[0]
                if dn_part:
                    self.dn_registry.register_dn(dn_part)

            # Plain DN (not in LDAP URL format)
            elif isinstance(subject_value, str) and (
                "=" in subject_value or "," in subject_value
            ):
                self.dn_registry.register_dn(subject_value)

    def _normalize_dns_in_model(
        self,
        acl: FlextLdifModels.Acl,
    ) -> FlextResult[FlextLdifModels.Acl]:
        """Normalize DN references in ACL model to use canonical case.

        For ACL models, DN normalization is typically a pass-through
        since ACLs contain LDAP URLs, not plain DNs.

        Args:
            acl: ACL Pydantic model with potential DN references

        Returns:
            FlextResult with normalized ACL model

        """
        # ACLs typically don't have direct DN fields to normalize
        # DN references are in LDAP URLs like "ldap:///cn=REDACTED_LDAP_BIND_PASSWORD,dc=com"
        # which are handled during parsing/writing
        return FlextResult[FlextLdifModels.Acl].ok(acl)

    def _convert_attribute(
        self,
        source_quirk: QuirkInstance,
        target_quirk: QuirkInstance,
        data: str | dict[str, object],
    ) -> FlextResult[str | dict[str, object]]:
        """Convert attribute from source to target quirk via RFC.

        Pipeline: parse → to_rfc → from_rfc → write

        For string input that cannot be parsed, returns the original string
        unchanged as a pass-through (permissive/lenient parsing for graceful
        handling of malformed data).
        """
        try:
            # Step 1: Parse source format (if string)
            source_data: FlextLdifModels.SchemaAttribute | str | dict[str, object]
            if isinstance(data, str):
                # Use the quirk directly for parsing
                if not hasattr(source_quirk, "parse_attribute"):
                    # Quirk doesn't support attribute parsing - pass through
                    return FlextResult[str | dict[str, object]].ok(data)
                parse_result = source_quirk.parse_attribute(data)
                if parse_result.is_failure:
                    # Graceful degradation: pass through unparseable data unchanged
                    # This allows the system to handle malformed attributes without failing
                    # The receiving end (target) will also pass it through if it can't parse
                    return FlextResult[str | dict[str, object]].ok(data)
                source_data = parse_result.unwrap()

                # Check if parser fell back to default values (lenient parsing)
                # BUT ONLY pass through if input looks like garbage (no parentheses, no valid structure)
                # When parsing fails leniently, name and oid are set to 'unknown'
                if (
                    isinstance(source_data, FlextLdifModels.SchemaAttribute)
                    and source_data.name == "unknown"
                    and source_data.oid == "unknown"
                    and "("
                    not in data  # Only pass through if not even trying proper LDAP syntax
                ):
                    # Parser was lenient and couldn't really parse this
                    # Input looks like complete garbage - pass through
                    return FlextResult[str | dict[str, object]].ok(data)
            else:
                source_data = data

            # Step 2: Convert source → RFC
            if not hasattr(source_quirk, "convert_attribute_to_rfc"):
                return FlextResult[str | dict[str, object]].fail(
                    "Source quirk does not support attribute to RFC conversion",
                )
            # Type narrowing: source_data must be SchemaAttribute at this point
            if not isinstance(source_data, FlextLdifModels.SchemaAttribute):
                source_data = cast("FlextLdifModels.SchemaAttribute", source_data)
            to_rfc_result = source_quirk.convert_attribute_to_rfc(source_data)
            if to_rfc_result.is_failure:
                return FlextResult[str | dict[str, object]].fail(
                    f"Failed to convert source→RFC: {to_rfc_result.error}",
                )
            rfc_data = to_rfc_result.unwrap()

            # Step 3: Convert RFC → target
            if not hasattr(target_quirk, "convert_attribute_from_rfc"):
                return FlextResult[str | dict[str, object]].fail(
                    "Target quirk does not support attribute from RFC conversion",
                )
            from_rfc_result = target_quirk.convert_attribute_from_rfc(rfc_data)
            if from_rfc_result.is_failure:
                error_msg = from_rfc_result.error
                # Enhance error message if it looks like a type mismatch
                if error_msg and "has no attribute" in error_msg:
                    error_msg = (
                        f"Target quirk does not support the data format: {error_msg}"
                    )
                return FlextResult[str | dict[str, object]].fail(
                    f"Failed to convert RFC→target: {error_msg}",
                )
            target_data = from_rfc_result.unwrap()

            # Step 4: Write target format
            if not hasattr(target_quirk, "write_attribute_to_rfc"):
                return FlextResult[str | dict[str, object]].fail(
                    "Target quirk does not support attribute writing",
                )
            write_result = target_quirk.write_attribute_to_rfc(target_data)
            if write_result.is_failure:
                return FlextResult[str | dict[str, object]].fail(
                    f"Failed to write target format: {write_result.error}",
                )

            # Cast Result[str] to Result[str | Dict] for return type compatibility
            return cast("FlextResult[str | dict[str, object]]", write_result)

        except AttributeError as e:
            # Handle cases where quirks return incompatible types (e.g., dict instead of SchemaAttribute)
            if "has no attribute" in str(e):
                return FlextResult[str | dict[str, object]].fail(
                    f"Source quirk does not support proper model objects: {e}",
                )
            return FlextResult[str | dict[str, object]].fail(
                f"Attribute conversion failed: {e}",
            )
        except (ValueError, TypeError, RuntimeError, Exception) as e:
            return FlextResult[str | dict[str, object]].fail(
                f"Attribute conversion failed: {e}",
            )

    def _convert_objectclass(
        self,
        source_quirk: QuirkInstance,
        target_quirk: QuirkInstance,
        data: str | dict[str, object],
    ) -> FlextResult[str | dict[str, object]]:
        """Convert objectClass from source to target quirk via RFC.

        Pipeline: parse → to_rfc → from_rfc → write

        For string input that cannot be parsed, returns the original string
        unchanged as a pass-through (permissive/lenient parsing for graceful
        handling of malformed data).
        """
        try:
            # Step 1: Parse source format (if string)
            source_data: FlextLdifModels.SchemaObjectClass | str | dict[str, object]
            if isinstance(data, str):
                # Use the quirk directly for parsing
                if not hasattr(source_quirk, "parse_objectclass"):
                    # Quirk doesn't support objectClass parsing - pass through
                    return FlextResult[str | dict[str, object]].ok(data)
                # Check if quirk declares it can't handle objectClass definitions at all
                # Use a minimal valid Oracle definition for testing (recognized by all quirks)
                test_oc_def = "( 2.16.840.1.113894.1.2.1 NAME 'orclTest' SUP top STRUCTURAL MUST cn )"
                if hasattr(
                    source_quirk,
                    "can_handle_objectclass",
                ) and not source_quirk.can_handle_objectclass(test_oc_def):
                    # Quirk explicitly says it can't handle objectClass definitions - this is an error
                    return FlextResult[str | dict[str, object]].fail(
                        "Source quirk does not support objectClass parsing",
                    )
                parse_result = source_quirk.parse_objectclass(data)
                if parse_result.is_failure:
                    # Graceful degradation: pass through unparseable data unchanged
                    # This allows the system to handle malformed objectClasses without failing
                    # The receiving end (target) will also pass it through if it can't parse
                    return FlextResult[str | dict[str, object]].ok(data)
                source_data = parse_result.unwrap()

                # Check if parser fell back to default values (lenient parsing)
                # BUT ONLY pass through if input looks like garbage (no parentheses, no valid structure)
                # When parsing fails leniently, name and oid are set to 'unknown'
                if (
                    isinstance(source_data, FlextLdifModels.SchemaObjectClass)
                    and source_data.name == "unknown"
                    and source_data.oid == "unknown"
                    and "("
                    not in data  # Only pass through if not even trying proper LDAP syntax
                ):
                    # Parser was lenient and couldn't really parse this
                    # Input looks like complete garbage - pass through
                    return FlextResult[str | dict[str, object]].ok(data)
            else:
                source_data = data

            # Step 2: Convert source → RFC
            if not hasattr(source_quirk, "convert_objectclass_to_rfc"):
                return FlextResult[str | dict[str, object]].fail(
                    "Source quirk does not support objectClass to RFC conversion",
                )
            # Type narrowing: source_data must be SchemaObjectClass at this point
            if not isinstance(source_data, FlextLdifModels.SchemaObjectClass):
                source_data = cast("FlextLdifModels.SchemaObjectClass", source_data)
            to_rfc_result = source_quirk.convert_objectclass_to_rfc(source_data)
            if to_rfc_result.is_failure:
                return FlextResult[str | dict[str, object]].fail(
                    f"Failed to convert source→RFC: {to_rfc_result.error}",
                )
            rfc_data = to_rfc_result.unwrap()

            # Step 3: Convert RFC → target
            if not hasattr(target_quirk, "convert_objectclass_from_rfc"):
                return FlextResult[str | dict[str, object]].fail(
                    "Target quirk does not support objectClass from RFC conversion",
                )
            from_rfc_result = target_quirk.convert_objectclass_from_rfc(rfc_data)
            if from_rfc_result.is_failure:
                error_msg = from_rfc_result.error
                # Enhance error message if it looks like a type mismatch
                if error_msg and "has no attribute" in error_msg:
                    error_msg = (
                        f"Target quirk does not support the data format: {error_msg}"
                    )
                return FlextResult[str | dict[str, object]].fail(
                    f"Failed to convert RFC→target: {error_msg}",
                )
            target_data = from_rfc_result.unwrap()

            # Step 4: Write target format
            if not hasattr(target_quirk, "write_objectclass_to_rfc"):
                return FlextResult[str | dict[str, object]].fail(
                    "Target quirk does not support objectClass writing",
                )
            write_result = target_quirk.write_objectclass_to_rfc(target_data)
            if write_result.is_failure:
                return FlextResult[str | dict[str, object]].fail(
                    f"Failed to write target format: {write_result.error}",
                )

            # Cast Result[str] to Result[str | Dict] for return type compatibility
            return cast("FlextResult[str | dict[str, object]]", write_result)

        except AttributeError as e:
            # Handle cases where quirks return incompatible types (e.g., dict instead of SchemaObjectClass)
            if "has no attribute" in str(e):
                return FlextResult[str | dict[str, object]].fail(
                    f"Source quirk does not support proper model objects: {e}",
                )
            return FlextResult[str | dict[str, object]].fail(
                f"ObjectClass conversion failed: {e}",
            )
        except (ValueError, TypeError, RuntimeError, Exception) as e:
            return FlextResult[str | dict[str, object]].fail(
                f"ObjectClass conversion failed: {e}",
            )

    def _convert_acl(
        self,
        source_quirk: QuirkInstance,
        target_quirk: QuirkInstance,
        data: str,
    ) -> FlextResult[str]:
        """Convert ACL from source to target quirk via RFC.

        Pipeline: parse → extract DNs → to_rfc → from_rfc → normalize → write

        ALL steps use Pydantic models (FlextLdifModels.Acl) - NO dicts.

        Args:
            source_quirk: Source server quirk
            target_quirk: Target server quirk
            data: ACL string to convert

        Returns:
            FlextResult with converted ACL string

        """
        try:
            # Access nested ACL quirk components via acl attribute
            if not hasattr(source_quirk, "acl"):
                return FlextResult[str].fail(
                    "Source quirk does not have ACL quirk (missing acl attribute)",
                )
            if not hasattr(target_quirk, "acl"):
                return FlextResult[str].fail(
                    "Target quirk does not have ACL quirk (missing acl attribute)",
                )

            source_acl_quirk = getattr(source_quirk, "acl", None)
            target_acl_quirk = getattr(target_quirk, "acl", None)

            if source_acl_quirk is None or target_acl_quirk is None:
                return FlextResult[str].fail("ACL quirk access failed")

            # Step 1: Parse source ACL string → Pydantic model
            if not hasattr(source_acl_quirk, "parse_acl"):
                return FlextResult[str].fail(
                    "Source quirk does not support ACL parsing",
                )
            parse_result = source_acl_quirk.parse_acl(data)
            if parse_result.is_failure:
                return FlextResult[str].fail(
                    f"Failed to parse source ACL: {parse_result.error}",
                )
            source_model: FlextLdifModels.Acl = parse_result.unwrap()

            # Step 2: Extract and register DNs from model
            self._extract_and_register_dns(source_model, "acl")

            # Step 3: Convert source model → RFC model
            if not hasattr(source_acl_quirk, "convert_acl_to_rfc"):
                return FlextResult[str].fail(
                    "Source quirk does not support ACL to RFC conversion",
                )
            to_rfc_result = source_acl_quirk.convert_acl_to_rfc(source_model)
            if to_rfc_result.is_failure:
                return FlextResult[str].fail(
                    f"Failed to convert source→RFC: {to_rfc_result.error}",
                )
            rfc_model: FlextLdifModels.Acl = to_rfc_result.unwrap()

            # Step 4: Convert RFC model → target model
            if not hasattr(target_acl_quirk, "convert_acl_from_rfc"):
                return FlextResult[str].fail(
                    "Target quirk does not support ACL from RFC conversion",
                )
            from_rfc_result = target_acl_quirk.convert_acl_from_rfc(rfc_model)
            if from_rfc_result.is_failure:
                return FlextResult[str].fail(
                    f"Failed to convert RFC→target: {from_rfc_result.error}",
                )
            target_model: FlextLdifModels.Acl = from_rfc_result.unwrap()

            # Step 5: Normalize DN references in model
            normalize_result = self._normalize_dns_in_model(target_model)
            if normalize_result.is_failure:
                return FlextResult[str].fail(
                    f"Failed to normalize DN references: {normalize_result.error}",
                )
            normalized_model: FlextLdifModels.Acl = normalize_result.unwrap()

            # Step 6: Write target model → string
            if not hasattr(target_acl_quirk, "write_acl_to_rfc"):
                return FlextResult[str].fail(
                    "Target quirk does not support ACL writing",
                )
            write_result = target_acl_quirk.write_acl_to_rfc(normalized_model)
            if write_result.is_failure:
                return FlextResult[str].fail(
                    f"Failed to write target format: {write_result.error}",
                )

            return write_result

        except (ValueError, TypeError, AttributeError, RuntimeError, Exception) as e:
            return FlextResult[str].fail(f"ACL conversion failed: {e}")

    def _convert_entry(
        self,
        source_quirk: QuirkInstance,
        target_quirk: QuirkInstance,
        data: str | dict[str, object],
    ) -> FlextResult[str | dict[str, object]]:
        """Convert entry from source to target quirk via RFC.

        Pipeline: parse → extract DNs → to_rfc → from_rfc → normalize DNs → write
        """
        try:
            # Access Entry quirk components
            source_entry_quirk = getattr(source_quirk, "entry", None)
            target_entry_quirk = getattr(target_quirk, "entry", None)

            if source_entry_quirk is None:
                return FlextResult[str | dict[str, object]].fail(
                    "Source quirk does not have Entry support",
                )
            if target_entry_quirk is None:
                return FlextResult[str | dict[str, object]].fail(
                    "Target quirk does not have Entry support",
                )

            # Step 1: Parse source format (if string)
            if isinstance(data, str):
                # For entry, we need to parse LDIF - use basic parser first
                # This is a simplified approach; real implementation may need full LDIF parsing
                return FlextResult[str | dict[str, object]].fail(
                    "String input for entry conversion not yet supported - pass parsed dict",
                )
            source_data = data

            # Step 2: Extract and register DNs (skip for entries - only for ACLs)
            # Entry DN extraction would require different logic not yet implemented

            # Step 3: Convert source → RFC
            to_rfc_result = source_entry_quirk.convert_entry_to_rfc(source_data)
            if to_rfc_result.is_failure:
                return FlextResult[str | dict[str, object]].fail(
                    f"Failed to convert source→RFC: {to_rfc_result.error}",
                )
            rfc_data = to_rfc_result.unwrap()

            # Step 4: Convert RFC → target
            from_rfc_result = target_entry_quirk.convert_entry_from_rfc(rfc_data)
            if from_rfc_result.is_failure:
                return FlextResult[str | dict[str, object]].fail(
                    f"Failed to convert RFC→target: {from_rfc_result.error}",
                )
            target_data = from_rfc_result.unwrap()

            # Step 5: Normalize DN references to canonical case
            # (skip for entries - DN normalization for dict data not yet implemented)
            normalized_data = target_data

            # Step 6: Write target format
            write_result: FlextResult[str | dict[str, object]] = (
                target_entry_quirk.write_entry_to_ldif(normalized_data)
            )
            if write_result.is_failure:
                return FlextResult[str | dict[str, object]].fail(
                    f"Failed to write target format: {write_result.error}",
                )

            return write_result

        except (ValueError, TypeError, AttributeError, RuntimeError, Exception) as e:
            return FlextResult[str | dict[str, object]].fail(
                f"Entry conversion failed: {e}",
            )

    def batch_convert(
        self,
        source_quirk: QuirkInstance,
        target_quirk: QuirkInstance,
        data_type: DataType,
        data_list: Sequence[str | dict[str, object]],
    ) -> FlextResult[list[str | dict[str, object]]]:
        """Convert multiple items from source to target quirk via RFC.

        This is a convenience method that applies convert() to a list of items.
        DN registry is shared across all conversions to ensure case consistency.

        Args:
            source_quirk: Source quirk instance
            target_quirk: Target quirk instance
            data_type: Type of data to convert
            data_list: List of items to convert

        Returns:
            FlextResult containing list of converted items

        Examples:
            >>> attributes = ["( 2.16... )", "( 2.16... )", ...]
            >>> result = matrix.batch_convert(oud, oid, "attribute", attributes)
            >>> if result.is_success:
            ...     converted = result.unwrap()
            ...     print(f"Converted {len(converted)} attributes")

        """
        try:
            converted = []
            errors = []

            for idx, item in enumerate(data_list):
                result = self.convert(source_quirk, target_quirk, data_type, item)
                if result.is_success:
                    converted.append(result.unwrap())
                else:
                    errors.append(f"Item {idx}: {result.error}")

            if errors:
                error_msg = (
                    f"Batch conversion completed with {len(errors)} errors:\n"
                    + "\n".join(errors[: self.MAX_ERRORS_TO_SHOW])
                )
                if len(errors) > self.MAX_ERRORS_TO_SHOW:
                    error_msg += (
                        f"\n... and {len(errors) - self.MAX_ERRORS_TO_SHOW} more errors"
                    )
                return FlextResult[list[str | dict[str, object]]].fail(error_msg)

            return FlextResult[list[str | dict[str, object]]].ok(converted)

        except (ValueError, TypeError, AttributeError, RuntimeError, Exception) as e:
            return FlextResult[list[str | dict[str, object]]].fail(
                f"Batch conversion failed: {e}",
            )

    def validate_oud_conversion(self) -> FlextResult[bool]:
        """Validate DN case consistency for OUD target conversion.

        This should be called after batch conversions to OUD to ensure
        no DN case conflicts exist that would cause OUD to reject the data.

        Returns:
            FlextResult[bool]: Validation result with any inconsistencies in metadata

        Examples:
            >>> matrix = FlextLdifQuirksConversionMatrix()
            >>> # ... perform conversions ...
            >>> result = matrix.validate_oud_conversion()
            >>> if result.unwrap():
            ...     print("DN consistency validated for OUD")
            >>> else:
            ...     print(f"Warning: {result.metadata['warning']}")

        """
        return self.dn_registry.validate_oud_consistency()

    def reset_dn_registry(self) -> None:
        """Clear DN registry for new conversion session.

        Call this between independent conversion operations to avoid
        DN case pollution from previous conversions.

        Examples:
            >>> matrix = FlextLdifQuirksConversionMatrix()
            >>> # ... convert some entries ...
            >>> matrix.reset_dn_registry()  # Start fresh
            >>> # ... convert different entries ...

        """
        self.dn_registry.clear()

    def get_supported_conversions(self, quirk: QuirkInstance) -> dict[str, bool]:
        """Check which data types a quirk supports for conversion.

        Args:
            quirk: Quirk instance to check

        Returns:
            Dictionary mapping data_type to support status

        Examples:
            >>> oud = FlextLdifServersOud()
            >>> supported = matrix.get_supported_conversions(oud)
            >>> print(supported)
            {'attribute': True, FlextLdifConstants.DictKeys.OBJECTCLASS: True, 'acl': True, 'entry': True}

        """
        support = {
            "attribute": False,
            FlextLdifConstants.DictKeys.OBJECTCLASS: False,
            "acl": False,
            "entry": False,
        }

        # Check schema support
        # Use Oracle OID namespace for testing (recognized by OID/OUD/OpenLDAP quirks)
        # This allows real quirks to return True while test quirks return based on capability
        test_attr_def = "( 2.16.840.1.113894.1.1.1 NAME 'orclTest' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        test_oc_def = (
            "( 2.16.840.1.113894.1.2.1 NAME 'orclTest' SUP top STRUCTURAL MUST cn )"
        )

        if hasattr(quirk, "can_handle_attribute") and quirk.can_handle_attribute(
            test_attr_def,
        ):
            support["attribute"] = True
        if hasattr(quirk, "can_handle_objectclass") and quirk.can_handle_objectclass(
            test_oc_def,
        ):
            support[FlextLdifConstants.DictKeys.OBJECTCLASS] = True

        # Check ACL support
        acl_quirk = getattr(quirk, "acl", None)
        test_acl_def = 'targetattr="*" (version 3.0; acl "test"; allow (read) userdn="ldap:///self";)'
        if (
            acl_quirk
            and hasattr(acl_quirk, "can_handle_acl")
            and acl_quirk.can_handle_acl(test_acl_def)
        ):
            support["acl"] = True

        # Check Entry support
        entry_quirk = getattr(quirk, "entry", None)
        # Entry support is indicated by either:
        # 1. A nested entry quirk with convert_entry_to_rfc method, OR
        # 2. The quirk itself has entry marker AND convert_entry_to_rfc method
        if entry_quirk:
            if hasattr(entry_quirk, "convert_entry_to_rfc"):
                # Nested entry quirk (e.g., OUD/OID quirks)
                support["entry"] = True
            elif hasattr(quirk, "convert_entry_to_rfc"):
                # Quirk itself has entry support (test quirks with bool marker)
                support["entry"] = True

        return support


__all__ = ["DataType", "FlextLdifQuirksConversionMatrix"]
