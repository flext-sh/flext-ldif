"""Quirks conversion matrix for LDAP server translation.

This module provides the QuirksConversionMatrix facade that enables
conversion between LDAP server quirks (OUD, OID, OpenLDAP, etc.) using
a universal Entry model as the pivot point.

Conversion Pattern:
 Source → Write to LDIF → Parse with Target → Entry Model

All server conversions work through the universal Entry model, which stores
server-specific metadata. This simplifies conversions to: write→parse pipeline.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import Sequence
from typing import cast, override

from flext_core import FlextResult, FlextService

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.protocols import FlextLdifProtocols
from flext_ldif.services.dn import FlextLdifDn
from flext_ldif.utilities import FlextLdifUtilities


class FlextLdifConversion(FlextService[FlextLdifModels.ConvertibleModel]):
    """Facade for universal, model-driven quirk-to-quirk conversion.

    This class provides a unified interface for converting LDIF data models between
    different server formats (OUD, OID, etc.) by using RFC as a universal
    intermediate representation. The entire process is model-driven, ensuring
    type safety and consistency.

    The conversion pipeline is:
    1.  `source.normalize_to_rfc(model)` -> RFC Model
    2.  `target.denormalize_from_rfc(RFC Model)` -> Target Model

    FlextService V2 Integration:
    - Inherits from FlextService[FlextLdifModels.ConvertibleModel]
    - Implements execute() method for health checks
    - Provides stateless conversion operations
    """

    # Maximum number of errors to show in batch conversion
    MAX_ERRORS_TO_SHOW: ClassVar[int] = 5

    def __init__(self) -> None:
        """Initialize the conversion facade with DN case registry."""
        super().__init__()
        object.__setattr__(self, "dn_registry", FlextLdifDn.Registry())  # type: ignore[attr-defined]

    @override
    def execute(self) -> FlextResult[dict[str, object]]:
        """Execute conversion service health check.

        Returns:
            FlextResult with conversion service status and capabilities

        """
        try:
            return FlextResult[dict[str, object]].ok({
                "service": "ConversionService",
                "status": "operational",
                "capabilities": [
                    "convert_entries",
                    "convert_attributes",
                    "convert_objectclasses",
                    "convert_acls",
                    "batch_convert",
                ],
                "dn_registry_active": True,
            })
        except Exception as e:
            return FlextResult[dict[str, object]].fail(
                f"Conversion service health check failed: {e}",
            )

    def convert(
        self,
        source: FlextLdifProtocols.Quirks.QuirksPort,
        target: FlextLdifProtocols.Quirks.QuirksPort,
        model_instance_or_data_type: FlextLdifModels.ConvertibleModel | str,
        data: str | dict[str, object] | None = None,
    ) -> (
        FlextResult[FlextLdifModels.ConvertibleModel]
        | FlextResult[str | dict[str, object]]
    ):
        """Convert a model from a source server format to a target server format.

        Supports both new strategy pattern (model-based) and legacy string-based conversions.

        Args:
            source: Source quirk instance
            target: Target quirk instance
            model_instance_or_data_type: Either a model instance (new pattern) or data type string (legacy)
            data: Data to convert (legacy pattern only)

        Returns:
            FlextResult with converted model or string data

        """
        # Determine if this is legacy (string-based) or new (model-based) conversion
        if isinstance(model_instance_or_data_type, str) and data is not None:
            # Legacy string-based conversion
            return self._convert_legacy(
                source,
                target,
                model_instance_or_data_type,
                data,
            )
        if data is None:
            # New model-based conversion
            return self._convert_model(source, target, model_instance_or_data_type)
        return FlextResult.fail(
            "Invalid arguments: provide either (model) or (data_type, data)",
        )

    def _convert_model(
        self,
        source: FlextLdifProtocols.Quirks.QuirksPort,
        target: FlextLdifProtocols.Quirks.QuirksPort,
        model_instance: FlextLdifModels.ConvertibleModel,
    ) -> FlextResult[FlextLdifModels.ConvertibleModel]:
        """Convert Entry model between source and target server formats with FlextLdifUtilities.

        Uses universal Entry model as pivot point via write→parse pipeline.
        Conversions are server-agnostic: write to LDIF, then parse with target quirk.

        This approach eliminates the need for normalize_to_rfc/denormalize_from_rfc
        and ensures all conversions go through the same parse/write codepath used
        in normal parsing and writing operations.
        """
        try:
            # Only Entry models can be converted (schema models are server-specific)
            if not isinstance(model_instance, FlextLdifModels.Entry):
                return FlextResult.fail(
                    f"Only Entry models can be converted between servers. "
                    f"Got: {type(model_instance).__name__}",
                )

            entry: FlextLdifModels.Entry = model_instance

            # Validate entry DN using FlextLdifUtilities.DN before conversion
            entry_dn = (
                str(FlextLdifUtilities.DN._get_dn_value(entry.dn)) if entry.dn else ""
            )
            if not FlextLdifUtilities.DN.validate(entry_dn):
                return FlextResult.fail(
                    f"Entry DN failed RFC 4514 validation: {entry_dn}",
                )

            # Register entry DN for case consistency during conversion
            self.dn_registry.register_dn(entry_dn)

            # Step 1: Write Entry from source server format to RFC LDIF string
            write_result = source.write_entry(entry)
            if write_result.is_failure:
                return FlextResult.fail(
                    f"Failed to write entry in source format: {write_result.error}",
                )

            ldif_string: str = write_result.unwrap()
            if not ldif_string or not ldif_string.strip():
                return FlextResult.fail("Write operation returned empty LDIF")

            # Step 2: Parse LDIF string with target server to get Entry in target format
            parse_result = target.parse(ldif_string)
            if parse_result.is_failure:
                return FlextResult.fail(
                    f"Failed to parse entry in target format: {parse_result.error}",
                )

            parsed_entries = parse_result.unwrap()
            if not parsed_entries:
                return FlextResult.fail("Parse operation returned empty entry list")

            # Return first parsed entry (conversion always produces one entry)
            return FlextResult.ok(parsed_entries[0])

        except Exception as e:
            return FlextResult.fail(f"Entry conversion failed: {e}")

    def _convert_legacy(
        self,
        source: object,
        target: object,
        data_type: str,
        data: str | dict[str, object],
    ) -> FlextResult[str | dict[str, object]]:
        """Convert using legacy string-based pattern."""
        try:
            if data_type == "attribute":
                return self._convert_attribute(source, target, data)
            if data_type == "objectClass":
                return self._convert_objectclass(source, target, data)
            if data_type == "acl":
                if isinstance(data, str):
                    return self._convert_acl(source, target, data)
                return FlextResult.fail("ACL conversion requires string input")
            if data_type == "entry":
                return self._convert_entry(source, target, data)
            return FlextResult.fail(f"Invalid data_type: {data_type}")
        except Exception as e:
            return FlextResult.fail(f"Legacy conversion failed: {e}")

    def _extract_and_register_dns(
        self,
        model: FlextLdifModels.Acl,
        data_type: str,
    ) -> None:
        """Extract DNs from ACL model and register with canonical case using FlextLdifUtilities.

        Extracts DNs from ACL models and registers them with the DN registry
        to ensure case consistency across conversions. Uses FlextLdifUtilities
        for RFC 4514 DN validation.

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
                # Validate DN using FlextLdifUtilities before registering
                if dn_part and FlextLdifUtilities.DN.validate(dn_part):
                    self.dn_registry.register_dn(dn_part)

            # Plain DN (not in LDAP URL format)
            elif isinstance(subject_value, str) and (
                "=" in subject_value or "," in subject_value
            ):
                # Validate DN using FlextLdifUtilities.DN before registering
                if FlextLdifUtilities.DN.validate(subject_value):
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
        # DN references are in LDAP URLs like "ldap:///cn=admin,dc=com"
        # which are handled during parsing/writing
        return FlextResult[FlextLdifModels.Acl].ok(acl)

    def _parse_source_attribute(
        self,
        source: object,
        data: str | dict[str, object],
    ) -> FlextResult[FlextLdifModels.SchemaAttribute | str | dict[str, object]]:
        """Parse source attribute data."""
        if not isinstance(data, str):
            return FlextResult.ok(data)

        if not hasattr(source.schema, "parse_attribute"):
            return FlextResult.ok(data)

        parse_result = source.schema.parse_attribute(data)
        if parse_result.is_failure:
            return FlextResult.ok(data)

        source_data = parse_result.unwrap()
        if (
            isinstance(source_data, FlextLdifModels.SchemaAttribute)
            and source_data.name == "unknown"
            and source_data.oid == "unknown"
            and "(" not in data
        ):
            return FlextResult.ok(data)

        return FlextResult.ok(source_data)

    def _normalize_attribute_to_rfc(
        self,
        source: object,
        source_data: FlextLdifModels.SchemaAttribute | str | dict[str, object],
    ) -> FlextResult:
        """Normalize attribute to RFC format.

        Since convert_* wrapper methods were removed, attributes are already
        in their final form after parsing with _parse_attribute.
        This is a pass-through for compatibility.
        """
        if isinstance(source_data, FlextLdifModels.SchemaAttribute):
            return FlextResult.ok(source_data)
        if isinstance(source_data, str):
            # Try to parse as RFC attribute
            if hasattr(source, "schema") and hasattr(source.schema, "parse_attribute"):
                parse_result = source.schema.parse_attribute(source_data)
                if parse_result.is_success:
                    return parse_result
            return FlextResult.ok(source_data)
        return FlextResult.ok(source_data)

    def _write_attribute_target(
        self,
        target: object,
        target_data: FlextLdifModels.SchemaAttribute | str | dict[str, object],
    ) -> FlextResult[str | dict[str, object]]:
        """Write attribute in target format."""
        if not hasattr(target, "schema") or not hasattr(
            target.schema,
            "write_attribute_to_rfc",
        ):
            return FlextResult.fail("Target quirk does not support attribute writing")

        write_result = target.schema.write_attribute_to_rfc(target_data)
        if write_result.is_failure:
            return FlextResult.fail(
                f"Failed to write target format: {write_result.error}",
            )

        return write_result

    def _convert_attribute(
        self,
        source: object,
        target: object,
        data: str | dict[str, object],
    ) -> FlextResult[str | dict[str, object]]:
        """Convert attribute from source to target quirk via write→parse pipeline.

        Pipeline: parse source → write as string → parse target

        Uses the same pattern as Entry conversion:
        1. Parse attribute with source quirk to get model
        2. Write attribute model to RFC string representation
        3. Parse RFC string with target quirk
        """
        try:
            # Step 1: Parse source attribute (if string input)
            if isinstance(data, str):
                if not hasattr(source, "schema") or not hasattr(
                    source.schema,
                    "parse_attribute",
                ):
                    return FlextResult.ok(data)  # Pass-through if no parser

                parse_result = source.schema.parse_attribute(data)
                if parse_result.is_failure:
                    return FlextResult.ok(data)  # Pass-through on parse error
                source_attr = parse_result.unwrap()
            else:
                source_attr = data

            # Step 2: Write attribute with source quirk to get RFC string
            if not hasattr(source, "schema") or not hasattr(
                source.schema,
                "write_attribute",
            ):
                return FlextResult.ok(source_attr)  # Return as-is if no writer

            write_result = source.schema.write_attribute(source_attr)
            if write_result.is_failure:
                return FlextResult.ok(source_attr)  # Return as-is on write error

            attr_string: str = write_result.unwrap()

            # Step 3: Parse RFC string with target quirk
            if not hasattr(target, "schema") or not hasattr(
                target.schema,
                "parse_attribute",
            ):
                return FlextResult.ok(attr_string)  # Return string if no parser

            parse_result = target.schema.parse_attribute(attr_string)
            if parse_result.is_failure:
                return FlextResult.ok(attr_string)  # Return string on parse error

            parsed_attr = parse_result.unwrap()

            # Step 4: Write target attribute to final format
            if not hasattr(target, "schema") or not hasattr(
                target.schema,
                "write_attribute",
            ):
                return FlextResult.ok(parsed_attr)  # Return model if no writer

            return cast(
                "FlextResult[str | dict[str, object]]",
                target.schema.write_attribute(parsed_attr),
            )

        except (AttributeError, ValueError, TypeError, RuntimeError, Exception) as e:
            return FlextResult.fail(f"Attribute conversion failed: {e}")

    def _parse_source_objectclass(
        self,
        source: object,
        data: str | dict[str, object],
    ) -> FlextResult[FlextLdifModels.SchemaObjectClass | str | dict[str, object]]:
        """Parse source objectClass data."""
        if not isinstance(data, str):
            return FlextResult.ok(data)

        if not hasattr(source, "parse_objectclass"):
            return FlextResult.ok(data)

        # Check if quirk can handle objectClass
        test_oc_def = (
            "( 2.16.840.1.113894.1.2.1 NAME 'orclTest' SUP top STRUCTURAL MUST cn )"
        )
        if hasattr(
            source.schema,
            "can_handle_objectclass",
        ) and not source.schema.can_handle_objectclass(test_oc_def):
            return FlextResult.fail("Source quirk does not support objectClass parsing")

        parse_result = source.schema.parse_objectclass(data)
        if parse_result.is_failure:
            return FlextResult.ok(data)

        source_data = parse_result.unwrap()
        if (
            isinstance(source_data, FlextLdifModels.SchemaObjectClass)
            and source_data.name == "unknown"
            and source_data.oid == "unknown"
            and "(" not in data
        ):
            return FlextResult.ok(data)

        return FlextResult.ok(source_data)

    def _normalize_objectclass_to_rfc(
        self,
        source: object,
        source_data: FlextLdifModels.SchemaObjectClass | str | dict[str, object],
    ) -> FlextResult:
        """Normalize objectClass to RFC format.

        Since convert_* wrapper methods were removed, objectClasses are already
        in their final form after parsing. This is a pass-through for compatibility.
        """
        if isinstance(source_data, FlextLdifModels.SchemaObjectClass):
            return FlextResult.ok(source_data)
        if isinstance(source_data, str):
            # Try to parse as RFC objectClass
            if hasattr(source, "parse_objectclass"):
                parse_result = source.parse_objectclass(source_data)
                if parse_result.is_success:
                    return parse_result
            return FlextResult.ok(source_data)
        return FlextResult.ok(source_data)

    def _write_objectclass_target(
        self,
        target: object,
        target_data: FlextLdifModels.SchemaObjectClass | str | dict[str, object],
    ) -> FlextResult[str | dict[str, object]]:
        """Write objectClass in target format."""
        if not hasattr(target, "schema") or not hasattr(
            target.schema,
            "write_objectclass_to_rfc",
        ):
            return FlextResult.fail("Target quirk does not support objectClass writing")

        write_result = target.schema.write_objectclass_to_rfc(target_data)
        if write_result.is_failure:
            return FlextResult.fail(
                f"Failed to write target format: {write_result.error}",
            )

        return write_result

    def _convert_objectclass(
        self,
        source: object,
        target: object,
        data: str | dict[str, object],
    ) -> FlextResult[str | dict[str, object]]:
        """Convert objectClass from source to target quirk via write→parse pipeline.

        Pipeline: parse source → write as string → parse target

        Uses the same pattern as Entry and Attribute conversion:
        1. Parse objectClass with source quirk to get model
        2. Write objectClass model to RFC string representation
        3. Parse RFC string with target quirk
        """
        try:
            # Step 1: Parse source objectClass (if string input)
            if isinstance(data, str):
                if not hasattr(source, "schema") or not hasattr(
                    source.schema,
                    "parse_objectclass",
                ):
                    return FlextResult.ok(data)  # Pass-through if no parser

                parse_result = source.schema.parse_objectclass(data)
                if parse_result.is_failure:
                    return FlextResult.ok(data)  # Pass-through on parse error
                source_oc = parse_result.unwrap()
            else:
                source_oc = data

            # Step 2: Write objectClass with source quirk to get RFC string
            if not hasattr(source, "schema") or not hasattr(
                source.schema,
                "write_objectclass",
            ):
                return FlextResult.ok(source_oc)  # Return as-is if no writer

            write_result = source.schema.write_objectclass(source_oc)
            if write_result.is_failure:
                return FlextResult.ok(source_oc)  # Return as-is on write error

            oc_string: str = write_result.unwrap()

            # Step 3: Parse RFC string with target quirk
            if not hasattr(target, "schema") or not hasattr(
                target.schema,
                "parse_objectclass",
            ):
                return FlextResult.ok(oc_string)  # Return string if no parser

            parse_result = target.schema.parse_objectclass(oc_string)
            if parse_result.is_failure:
                return FlextResult.ok(oc_string)  # Return string on parse error

            parsed_oc = parse_result.unwrap()

            # Step 4: Write target objectClass to final format
            if not hasattr(target, "schema") or not hasattr(
                target.schema,
                "write_objectclass",
            ):
                return FlextResult.ok(parsed_oc)  # Return model if no writer

            return cast(
                "FlextResult[str | dict[str, object]]",
                target.schema.write_objectclass(parsed_oc),
            )

        except (AttributeError, ValueError, TypeError, RuntimeError, Exception) as e:
            return FlextResult.fail(f"ObjectClass conversion failed: {e}")

    def _convert_acl(
        self,
        source: object,
        target: object,
        data: str,
    ) -> FlextResult[str]:
        """Convert ACL from source to target quirk.

        Pipeline: parse source ACL → Pydantic model → write target format

        ACL models (FlextLdifModels.Acl) are server-agnostic universal models,
        so no RFC intermediate conversion is needed - we can write directly.

        Args:
            source: Source server quirk
            target: Target server quirk
            data: ACL string to convert

        Returns:
            FlextResult with converted ACL string

        """
        try:
            # Access nested ACL quirk components via acl attribute
            if not hasattr(source, "acl"):
                return FlextResult[str].fail(
                    "Source quirk does not have ACL quirk (missing acl attribute)",
                )
            if not hasattr(target, "acl"):
                return FlextResult[str].fail(
                    "Target quirk does not have ACL quirk (missing acl attribute)",
                )

            source_acl = getattr(source, "acl", None)
            target_acl = getattr(target, "acl", None)

            if source_acl is None or target_acl is None:
                return FlextResult[str].fail("ACL quirk access failed")

            # Step 1: Parse source ACL string → Pydantic model (server-agnostic)
            if not hasattr(source_acl, "parse"):
                return FlextResult[str].fail(
                    "Source quirk does not support ACL parsing",
                )
            parse_result = source_acl.parse(data)
            if parse_result.is_failure:
                return FlextResult[str].fail(
                    f"Failed to parse source ACL: {parse_result.error}",
                )
            acl_model: FlextLdifModels.Acl = parse_result.unwrap()

            # Step 2: Extract and register DNs from model
            self._extract_and_register_dns(acl_model, "acl")

            # Step 3: Normalize DN references in model (currently a pass-through for ACLs)
            normalize_result = self._normalize_dns_in_model(acl_model)
            if normalize_result.is_failure:
                return FlextResult[str].fail(
                    f"Failed to normalize DN references: {normalize_result.error}",
                )
            normalized_model: FlextLdifModels.Acl = normalize_result.unwrap()

            # Step 4: Write ACL model in target server format
            if not hasattr(target_acl, "write"):
                return FlextResult[str].fail(
                    "Target quirk does not support ACL writing",
                )
            write_result = target_acl.write(normalized_model)
            if write_result.is_failure:
                return FlextResult[str].fail(
                    f"Failed to write target format: {write_result.error}",
                )

            return write_result

        except (ValueError, TypeError, AttributeError, RuntimeError, Exception) as e:
            return FlextResult[str].fail(f"ACL conversion failed: {e}")

    def _convert_entry(
        self,
    ) -> FlextResult[str | dict[str, object]]:
        """Convert entry from source to target quirk via RFC.

        DEPRECATED: Use model-based conversion with Entry objects instead.
        This legacy method relied on wrapper methods that are no longer available.

        The correct approach is:
        1. Parse entry with source server: source.parse_entry(ldif_string)
        2. Convert using write→parse pipeline: source.write_entry() → target.parse()
        """
        return FlextResult[str | dict[str, object]].fail(
            "Dict-based entry conversion is deprecated. "
            "Use Entry model conversion: convert(source, target, entry_model)",
        )

    def batch_convert(
        self,
        source: object,
        target: object,
        data_type: str,
        data_list: Sequence[str | dict[str, object]],
    ) -> FlextResult[list[str | dict[str, object]]]:
        """Convert multiple items from source to target quirk via RFC.

        This is a convenience method that applies convert() to a list of items.
        DN registry is shared across all conversions to ensure case consistency.

        Args:
            source: Source quirk instance
            target: Target quirk instance
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
                result = self.convert(source, target, data_type, item)
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
            >>> matrix = FlextLdifConversion()
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
            >>> matrix = FlextLdifConversion()
            >>> # ... convert some entries ...
            >>> matrix.reset_dn_registry()  # Start fresh
            >>> # ... convert different entries ...

        """
        self.dn_registry.clear()

    def get_supported_conversions(self, quirk: object) -> dict[str, bool]:
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

        # Check schema support via parse() public method
        # Use Oracle OID namespace for testing (recognized by OID/OUD/OpenLDAP quirks)
        test_attr_def = "( 2.16.840.1.113894.1.1.1 NAME 'orclTest' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        test_oc_def = (
            "( 2.16.840.1.113894.1.2.1 NAME 'orclTest' SUP top STRUCTURAL MUST cn )"
        )

        # Test attribute support via parse() - if parse succeeds, quirk supports attributes
        attr_result = quirk.schema.parse(test_attr_def)
        if attr_result.is_success:
            support["attribute"] = True

        # Test objectClass support via parse() - if parse succeeds, quirk supports objectClasses
        oc_result = quirk.schema.parse(test_oc_def)
        if oc_result.is_success:
            support[FlextLdifConstants.DictKeys.OBJECTCLASS] = True

        # Check ACL support
        acl = getattr(quirk, "acl", None)
        test_acl_def = 'targetattr="*" (version 3.0; acl "test"; allow (read) userdn="ldap:///self";)'
        if acl:
            acl_result = acl.parse(test_acl_def)
            if acl_result.is_success:
                support["acl"] = True

        # Check Entry support - indicated by presence of entry quirk with parse method
        entry = getattr(quirk, "entry", None)
        if entry and hasattr(entry, "parse"):
            support["entry"] = True

        return support


__all__ = ["FlextLdifConversion"]
