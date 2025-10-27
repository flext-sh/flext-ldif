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
from typing import Literal, cast

from flext_core import FlextResult

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.quirks.base import (
    BaseAclQuirk,
    BaseEntryQuirk,
    BaseSchemaQuirk,
)
from flext_ldif.quirks.dn_case_registry import FlextLdifDnCaseRegistry

DataType = Literal["attribute", "objectclass", "acl", "entry"]

# Type alias for polymorphic quirk instances that can handle multiple data types
# These are server-specific implementations (e.g., OUD, OID, OpenLDAP) that may support
# schema, ACL, and/or entry processing capabilities
QuirkInstance = BaseSchemaQuirk | BaseAclQuirk | BaseEntryQuirk


class FlextLdifQuirksConversionMatrix:
    """Facade for universal quirk-to-quirk conversion via RFC intermediate format.

    This class provides a unified interface for converting LDAP data between
    different server quirks (OUD, OID, OpenLDAP, etc.) using RFC standards
    as the universal intermediate representation.

    The conversion pipeline ensures DN case consistency through a registry:
    1. Parse source format
    2. Extract and register DNs with canonical case
    3. Convert source → RFC (with DN metadata)
    4. Convert RFC → target (normalizing DN references)
    5. Validate DN consistency for OUD targets

    Examples:
        >>> from flext_ldif.quirks.servers.oud_quirks import FlextLdifQuirksServersOud
        >>> from flext_ldif.quirks.servers.oid_quirks import FlextLdifQuirksServersOid
        >>>
        >>> matrix = FlextLdifQuirksConversionMatrix()
        >>> oud = FlextLdifQuirksServersOud()
        >>> oid = FlextLdifQuirksServersOid()
        >>>
        >>> # Convert OUD attribute to OID
        >>> oud_attr = "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' ... )"
        >>> result = matrix.convert(oud, oid, "attribute", oud_attr)
        >>> if result.is_success:
        ...     oid_attr = result.unwrap()

    Attributes:
        dn_registry: DN case registry for tracking canonical DN case

    """

    # Constants
    MAX_ERRORS_TO_SHOW = 5

    def __init__(self) -> None:
        """Initialize conversion matrix with DN case registry."""
        super().__init__()
        self.dn_registry = FlextLdifDnCaseRegistry()

    def convert(
        self,
        source_quirk: QuirkInstance,
        target_quirk: QuirkInstance,
        data_type: DataType,
        data: str | dict[str, object],
    ) -> FlextResult[str | dict[str, object]]:
        """Convert data from source quirk format to target quirk format via RFC.

        This method orchestrates the complete conversion pipeline:
        1. Parse source format (if string input)
        2. Extract and register DNs with canonical case
        3. Convert source → RFC (with DN metadata)
        4. Convert RFC → target
        5. Normalize DN references to canonical case
        6. Write target format (if string output requested)
        7. Validate DN consistency for OUD targets

        Args:
            source_quirk: Source quirk instance (e.g., OUD, OID)
            target_quirk: Target quirk instance (e.g., OUD, OID)
            data_type: Type of data - "attribute", FlextLdifConstants.DictKeys.OBJECTCLASS, "acl", or "entry"
            data: Data to convert (string or dict)

        Returns:
            FlextResult containing converted data in target quirk format

        Raises:
            ValueError: If data_type is invalid

        Examples:
            >>> # Convert OUD entry to OID
            >>> oud_entry_ldif = '''
            ... dn: cn=OracleContext,dc=example,dc=com
            ... objectClass: orclContext
            ... orclVersion: 90600
            ... '''
            >>> result = matrix.convert(oud, oid, "entry", oud_entry_ldif)

        """
        if data_type == "attribute":
            return self._convert_attribute(source_quirk, target_quirk, data)
        if data_type == FlextLdifConstants.DictKeys.OBJECTCLASS:
            return self._convert_objectclass(source_quirk, target_quirk, data)
        if data_type == "acl":
            # ACL conversion requires string input
            if not isinstance(data, str):
                return FlextResult[str | dict[str, object]].fail(
                    "ACL conversion requires string input, not dict"
                )
            acl_result = self._convert_acl(source_quirk, target_quirk, data)
            # Cast FlextResult[str] to FlextResult[str | dict[str, object]] for return type
            return cast("FlextResult[str | dict[str, object]]", acl_result)
        if data_type == "entry":
            return self._convert_entry(source_quirk, target_quirk, data)
        return FlextResult[str | dict[str, object]].fail(
            f"Invalid data_type '{data_type}'. Must be one of: attribute, objectclass, acl, entry"
        )

    def _extract_and_register_dns(
        self, model: FlextLdifModels.Acl, data_type: DataType
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
        self, acl: FlextLdifModels.Acl
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
        # DN references are in LDAP URLs like "ldap:///cn=admin,dc=com"
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
        """
        try:
            # Step 1: Parse source format (if string)
            if isinstance(data, str):
                # Use type casting since concrete implementations have these methods
                source_quirk_schema = cast("BaseSchemaQuirk", source_quirk)
                if not hasattr(source_quirk_schema, "parse_attribute"):
                    return FlextResult[str | dict[str, object]].fail(
                        "Source quirk does not support attribute parsing"
                    )
                parse_result = source_quirk_schema.parse_attribute(data)
                if parse_result.is_failure:
                    return FlextResult[str | dict[str, object]].fail(
                        f"Failed to parse source attribute: {parse_result.error}"
                    )
                source_data = parse_result.unwrap()
            else:
                source_data = data

            # Step 2: Convert source → RFC
            source_quirk_schema = cast("BaseSchemaQuirk", source_quirk)
            if not hasattr(source_quirk_schema, "convert_attribute_to_rfc"):
                return FlextResult[str | dict[str, object]].fail(
                    "Source quirk does not support attribute to RFC conversion"
                )
            # Type narrowing: source_data must be SchemaAttribute at this point
            if not isinstance(source_data, FlextLdifModels.SchemaAttribute):
                source_data = cast("FlextLdifModels.SchemaAttribute", source_data)
            to_rfc_result = source_quirk_schema.convert_attribute_to_rfc(source_data)
            if to_rfc_result.is_failure:
                return FlextResult[str | dict[str, object]].fail(
                    f"Failed to convert source→RFC: {to_rfc_result.error}"
                )
            rfc_data = to_rfc_result.unwrap()

            # Step 3: Convert RFC → target
            # Use type casting since concrete implementations have these methods
            target_quirk_schema = cast("BaseSchemaQuirk", target_quirk)
            if not hasattr(target_quirk_schema, "convert_attribute_from_rfc"):
                return FlextResult[str | dict[str, object]].fail(
                    "Target quirk does not support attribute from RFC conversion"
                )
            from_rfc_result = target_quirk_schema.convert_attribute_from_rfc(rfc_data)
            if from_rfc_result.is_failure:
                return FlextResult[str | dict[str, object]].fail(
                    f"Failed to convert RFC→target: {from_rfc_result.error}"
                )
            target_data = from_rfc_result.unwrap()

            # Step 4: Write target format
            if not hasattr(target_quirk_schema, "write_attribute_to_rfc"):
                return FlextResult[str | dict[str, object]].fail(
                    "Target quirk does not support attribute writing"
                )
            write_result = target_quirk_schema.write_attribute_to_rfc(target_data)
            if write_result.is_failure:
                return FlextResult[str | dict[str, object]].fail(
                    f"Failed to write target format: {write_result.error}"
                )

            # Cast Result[str] to Result[str | Dict] for return type compatibility
            return cast("FlextResult[str | dict[str, object]]", write_result)

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[str | dict[str, object]].fail(
                f"Attribute conversion failed: {e}"
            )

    def _convert_objectclass(
        self,
        source_quirk: QuirkInstance,
        target_quirk: QuirkInstance,
        data: str | dict[str, object],
    ) -> FlextResult[str | dict[str, object]]:
        """Convert objectClass from source to target quirk via RFC.

        Pipeline: parse → to_rfc → from_rfc → write
        """
        try:
            # Step 1: Parse source format (if string)
            if isinstance(data, str):
                # Use type casting since concrete implementations have these methods
                source_quirk_schema = cast("BaseSchemaQuirk", source_quirk)
                if not hasattr(source_quirk_schema, "parse_objectclass"):
                    return FlextResult[str | dict[str, object]].fail(
                        "Source quirk does not support objectClass parsing"
                    )
                # Check if quirk declares it can't handle objectClass definitions at all
                # Use a minimal valid Oracle definition for testing (recognized by all quirks)
                test_oc_def = "( 2.16.840.1.113894.1.2.1 NAME 'orclTest' SUP top STRUCTURAL MUST cn )"
                if hasattr(
                    source_quirk_schema, "can_handle_objectclass"
                ) and not source_quirk_schema.can_handle_objectclass(test_oc_def):
                    # Quirk indicates it can't handle objectClass definitions
                    return FlextResult[str | dict[str, object]].fail(
                        "Source quirk does not support objectClass parsing"
                    )
                parse_result = source_quirk_schema.parse_objectclass(data)
                if parse_result.is_failure:
                    return FlextResult[str | dict[str, object]].fail(
                        f"Failed to parse source objectClass: {parse_result.error}"
                    )
                source_data = parse_result.unwrap()
            else:
                source_data = data

            # Step 2: Convert source → RFC
            source_quirk_schema = cast("BaseSchemaQuirk", source_quirk)
            if not hasattr(source_quirk_schema, "convert_objectclass_to_rfc"):
                return FlextResult[str | dict[str, object]].fail(
                    "Source quirk does not support objectClass to RFC conversion"
                )
            # Type narrowing: source_data must be SchemaObjectClass at this point
            if not isinstance(source_data, FlextLdifModels.SchemaObjectClass):
                source_data = cast("FlextLdifModels.SchemaObjectClass", source_data)
            to_rfc_result = source_quirk_schema.convert_objectclass_to_rfc(source_data)
            if to_rfc_result.is_failure:
                return FlextResult[str | dict[str, object]].fail(
                    f"Failed to convert source→RFC: {to_rfc_result.error}"
                )
            rfc_data = to_rfc_result.unwrap()

            # Step 3: Convert RFC → target
            # Use type casting since concrete implementations have these methods
            target_quirk_schema = cast("BaseSchemaQuirk", target_quirk)
            if not hasattr(target_quirk_schema, "convert_objectclass_from_rfc"):
                return FlextResult[str | dict[str, object]].fail(
                    "Target quirk does not support objectClass from RFC conversion"
                )
            from_rfc_result = target_quirk_schema.convert_objectclass_from_rfc(rfc_data)
            if from_rfc_result.is_failure:
                return FlextResult[str | dict[str, object]].fail(
                    f"Failed to convert RFC→target: {from_rfc_result.error}"
                )
            target_data = from_rfc_result.unwrap()

            # Step 4: Write target format
            if not hasattr(target_quirk_schema, "write_objectclass_to_rfc"):
                return FlextResult[str | dict[str, object]].fail(
                    "Target quirk does not support objectClass writing"
                )
            write_result = target_quirk_schema.write_objectclass_to_rfc(target_data)
            if write_result.is_failure:
                return FlextResult[str | dict[str, object]].fail(
                    f"Failed to write target format: {write_result.error}"
                )

            # Cast Result[str] to Result[str | Dict] for return type compatibility
            return cast("FlextResult[str | dict[str, object]]", write_result)

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[str | dict[str, object]].fail(
                f"ObjectClass conversion failed: {e}"
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
                    "Source quirk does not have ACL quirk (missing acl attribute)"
                )
            if not hasattr(target_quirk, "acl"):
                return FlextResult[str].fail(
                    "Target quirk does not have ACL quirk (missing acl attribute)"
                )

            source_acl_quirk = source_quirk.acl
            target_acl_quirk = target_quirk.acl

            # Step 1: Parse source ACL string → Pydantic model
            if not hasattr(source_acl_quirk, "parse_acl"):
                return FlextResult[str].fail(
                    "Source quirk does not support ACL parsing"
                )
            parse_result = source_acl_quirk.parse_acl(data)
            if parse_result.is_failure:
                return FlextResult[str].fail(
                    f"Failed to parse source ACL: {parse_result.error}"
                )
            source_model: FlextLdifModels.Acl = parse_result.unwrap()

            # Step 2: Extract and register DNs from model
            self._extract_and_register_dns(source_model, "acl")

            # Step 3: Convert source model → RFC model
            if not hasattr(source_acl_quirk, "convert_acl_to_rfc"):
                return FlextResult[str].fail(
                    "Source quirk does not support ACL to RFC conversion"
                )
            to_rfc_result = source_acl_quirk.convert_acl_to_rfc(source_model)
            if to_rfc_result.is_failure:
                return FlextResult[str].fail(
                    f"Failed to convert source→RFC: {to_rfc_result.error}"
                )
            rfc_model: FlextLdifModels.Acl = to_rfc_result.unwrap()

            # Step 4: Convert RFC model → target model
            if not hasattr(target_acl_quirk, "convert_acl_from_rfc"):
                return FlextResult[str].fail(
                    "Target quirk does not support ACL from RFC conversion"
                )
            from_rfc_result = target_acl_quirk.convert_acl_from_rfc(rfc_model)
            if from_rfc_result.is_failure:
                return FlextResult[str].fail(
                    f"Failed to convert RFC→target: {from_rfc_result.error}"
                )
            target_model: FlextLdifModels.Acl = from_rfc_result.unwrap()

            # Step 5: Normalize DN references in model
            normalize_result = self._normalize_dns_in_model(target_model)
            if normalize_result.is_failure:
                return FlextResult[str].fail(
                    f"Failed to normalize DN references: {normalize_result.error}"
                )
            normalized_model: FlextLdifModels.Acl = normalize_result.unwrap()

            # Step 6: Write target model → string
            if not hasattr(target_acl_quirk, "write_acl_to_rfc"):
                return FlextResult[str].fail(
                    "Target quirk does not support ACL writing"
                )
            write_result = target_acl_quirk.write_acl_to_rfc(normalized_model)
            if write_result.is_failure:
                return FlextResult[str].fail(
                    f"Failed to write target format: {write_result.error}"
                )

            return write_result

        except (ValueError, TypeError, AttributeError) as e:
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
                    "Source quirk does not have Entry support"
                )
            if target_entry_quirk is None:
                return FlextResult[str | dict[str, object]].fail(
                    "Target quirk does not have Entry support"
                )

            # Step 1: Parse source format (if string)
            if isinstance(data, str):
                # For entry, we need to parse LDIF - use basic parser first
                # This is a simplified approach; real implementation may need full LDIF parsing
                return FlextResult[str | dict[str, object]].fail(
                    "String input for entry conversion not yet supported - pass parsed dict"
                )
            source_data = data

            # Step 2: Extract and register DNs (skip for entries - only for ACLs)
            # Entry DN extraction would require different logic not yet implemented

            # Step 3: Convert source → RFC
            to_rfc_result = source_entry_quirk.convert_entry_to_rfc(source_data)
            if to_rfc_result.is_failure:
                return FlextResult[str | dict[str, object]].fail(
                    f"Failed to convert source→RFC: {to_rfc_result.error}"
                )
            rfc_data = to_rfc_result.unwrap()

            # Step 4: Convert RFC → target
            from_rfc_result = target_entry_quirk.convert_entry_from_rfc(rfc_data)
            if from_rfc_result.is_failure:
                return FlextResult[str | dict[str, object]].fail(
                    f"Failed to convert RFC→target: {from_rfc_result.error}"
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
                    f"Failed to write target format: {write_result.error}"
                )

            return write_result

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[str | dict[str, object]].fail(
                f"Entry conversion failed: {e}"
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

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[list[str | dict[str, object]]].fail(
                f"Batch conversion failed: {e}"
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
            >>> oud = FlextLdifQuirksServersOud()
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
            test_attr_def
        ):
            support["attribute"] = True
        if hasattr(quirk, "can_handle_objectclass") and quirk.can_handle_objectclass(
            test_oc_def
        ):
            support[FlextLdifConstants.DictKeys.OBJECTCLASS] = True

        # Check ACL support
        acl_quirk = getattr(quirk, "acl", None)
        test_acl_def = 'targetattr="*" (version 3.0; acl "test"; allow (read) userdn="ldap:///self";)'
        if (
            acl_quirk
            and hasattr(quirk, "can_handle_acl")
            and quirk.can_handle_acl(test_acl_def)
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
