"""Quirks Conversion Matrix - Universal translation facade via RFC intermediate format.

This module provides the QuirksConversionMatrix facade that enables seamless
conversion between any two LDAP server quirks (OUD, OID, OpenLDAP, etc.) by
using RFC as a universal intermediate representation.

Conversion Pattern:
    Source Format → Source.to_rfc() → RFC Format → Target.from_rfc() → Target Format

This creates an N×N translation matrix with only 2×N implementations
(to_rfc and from_rfc per quirk type).

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Any, Literal

from flext_core.types import FlextResult
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.types import FlextLdifTypes


DataType = Literal["attribute", "objectclass", "acl", "entry"]


class QuirksConversionMatrix:
    """Facade for universal quirk-to-quirk conversion via RFC intermediate format.

    This class provides a unified interface for converting LDAP data between
    different server quirks (OUD, OID, OpenLDAP, etc.) using RFC standards
    as the universal intermediate representation.

    Examples:
        >>> from flext_ldif.quirks.servers.oud_quirks import FlextLdifQuirksServersOud
        >>> from flext_ldif.quirks.servers.oid_quirks import FlextLdifQuirksServersOid
        >>>
        >>> matrix = QuirksConversionMatrix()
        >>> oud = FlextLdifQuirksServersOud()
        >>> oid = FlextLdifQuirksServersOid()
        >>>
        >>> # Convert OUD attribute to OID
        >>> oud_attr = "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' ... )"
        >>> result = matrix.convert(oud, oid, "attribute", oud_attr)
        >>> if result.is_success:
        ...     oid_attr = result.unwrap()

    Attributes:
        None - Stateless facade
    """

    def convert(
        self,
        source_quirk: Any,
        target_quirk: Any,
        data_type: DataType,
        data: str | FlextLdifTypes.Dict,
    ) -> FlextResult[str | FlextLdifTypes.Dict]:
        """Convert data from source quirk format to target quirk format via RFC.

        This method orchestrates the complete conversion pipeline:
        1. Parse source format (if string input)
        2. Convert source → RFC
        3. Convert RFC → target
        4. Write target format (if string output requested)

        Args:
            source_quirk: Source quirk instance (e.g., OUD, OID)
            target_quirk: Target quirk instance (e.g., OUD, OID)
            data_type: Type of data - "attribute", "objectclass", "acl", or "entry"
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
        elif data_type == "objectclass":
            return self._convert_objectclass(source_quirk, target_quirk, data)
        elif data_type == "acl":
            return self._convert_acl(source_quirk, target_quirk, data)
        elif data_type == "entry":
            return self._convert_entry(source_quirk, target_quirk, data)
        else:
            return FlextResult[str | FlextLdifTypes.Dict].fail(
                f"Invalid data_type '{data_type}'. Must be one of: attribute, objectclass, acl, entry"
            )

    def _convert_attribute(
        self,
        source_quirk: Any,
        target_quirk: Any,
        data: str | FlextLdifTypes.Dict,
    ) -> FlextResult[str]:
        """Convert attribute from source to target quirk via RFC.

        Pipeline: parse → to_rfc → from_rfc → write
        """
        try:
            # Step 1: Parse source format (if string)
            if isinstance(data, str):
                parse_result = source_quirk.parse_attribute(data)
                if parse_result.is_failure:
                    return FlextResult[str].fail(
                        f"Failed to parse source attribute: {parse_result.error}"
                    )
                source_data = parse_result.unwrap()
            else:
                source_data = data

            # Step 2: Convert source → RFC
            to_rfc_result = source_quirk.convert_attribute_to_rfc(source_data)
            if to_rfc_result.is_failure:
                return FlextResult[str].fail(
                    f"Failed to convert source→RFC: {to_rfc_result.error}"
                )
            rfc_data = to_rfc_result.unwrap()

            # Step 3: Convert RFC → target
            from_rfc_result = target_quirk.convert_attribute_from_rfc(rfc_data)
            if from_rfc_result.is_failure:
                return FlextResult[str].fail(
                    f"Failed to convert RFC→target: {from_rfc_result.error}"
                )
            target_data = from_rfc_result.unwrap()

            # Step 4: Write target format
            write_result = target_quirk.write_attribute_to_rfc(target_data)
            if write_result.is_failure:
                return FlextResult[str].fail(
                    f"Failed to write target format: {write_result.error}"
                )

            return write_result

        except Exception as e:
            return FlextResult[str].fail(f"Attribute conversion failed: {e}")

    def _convert_objectclass(
        self,
        source_quirk: Any,
        target_quirk: Any,
        data: str | FlextLdifTypes.Dict,
    ) -> FlextResult[str]:
        """Convert objectClass from source to target quirk via RFC.

        Pipeline: parse → to_rfc → from_rfc → write
        """
        try:
            # Step 1: Parse source format (if string)
            if isinstance(data, str):
                parse_result = source_quirk.parse_objectclass(data)
                if parse_result.is_failure:
                    return FlextResult[str].fail(
                        f"Failed to parse source objectClass: {parse_result.error}"
                    )
                source_data = parse_result.unwrap()
            else:
                source_data = data

            # Step 2: Convert source → RFC
            to_rfc_result = source_quirk.convert_objectclass_to_rfc(source_data)
            if to_rfc_result.is_failure:
                return FlextResult[str].fail(
                    f"Failed to convert source→RFC: {to_rfc_result.error}"
                )
            rfc_data = to_rfc_result.unwrap()

            # Step 3: Convert RFC → target
            from_rfc_result = target_quirk.convert_objectclass_from_rfc(rfc_data)
            if from_rfc_result.is_failure:
                return FlextResult[str].fail(
                    f"Failed to convert RFC→target: {from_rfc_result.error}"
                )
            target_data = from_rfc_result.unwrap()

            # Step 4: Write target format
            write_result = target_quirk.write_objectclass_to_rfc(target_data)
            if write_result.is_failure:
                return FlextResult[str].fail(
                    f"Failed to write target format: {write_result.error}"
                )

            return write_result

        except Exception as e:
            return FlextResult[str].fail(f"ObjectClass conversion failed: {e}")

    def _convert_acl(
        self,
        source_quirk: Any,
        target_quirk: Any,
        data: str | FlextLdifTypes.Dict,
    ) -> FlextResult[str]:
        """Convert ACL from source to target quirk via RFC.

        Pipeline: parse → to_rfc → from_rfc → write
        """
        try:
            # Access ACL quirk components
            source_acl_quirk = getattr(source_quirk, "acl", None)
            target_acl_quirk = getattr(target_quirk, "acl", None)

            if source_acl_quirk is None:
                return FlextResult[str].fail("Source quirk does not have ACL support")
            if target_acl_quirk is None:
                return FlextResult[str].fail("Target quirk does not have ACL support")

            # Step 1: Parse source format (if string)
            if isinstance(data, str):
                parse_result = source_acl_quirk.parse_acl(data)
                if parse_result.is_failure:
                    return FlextResult[str].fail(
                        f"Failed to parse source ACL: {parse_result.error}"
                    )
                source_data = parse_result.unwrap()
            else:
                source_data = data

            # Step 2: Convert source → RFC
            to_rfc_result = source_acl_quirk.convert_acl_to_rfc(source_data)
            if to_rfc_result.is_failure:
                return FlextResult[str].fail(
                    f"Failed to convert source→RFC: {to_rfc_result.error}"
                )
            rfc_data = to_rfc_result.unwrap()

            # Step 3: Convert RFC → target
            from_rfc_result = target_acl_quirk.convert_acl_from_rfc(rfc_data)
            if from_rfc_result.is_failure:
                return FlextResult[str].fail(
                    f"Failed to convert RFC→target: {from_rfc_result.error}"
                )
            target_data = from_rfc_result.unwrap()

            # Step 4: Write target format
            write_result = target_acl_quirk.write_acl_to_rfc(target_data)
            if write_result.is_failure:
                return FlextResult[str].fail(
                    f"Failed to write target format: {write_result.error}"
                )

            return write_result

        except Exception as e:
            return FlextResult[str].fail(f"ACL conversion failed: {e}")

    def _convert_entry(
        self,
        source_quirk: Any,
        target_quirk: Any,
        data: str | FlextLdifTypes.Dict,
    ) -> FlextResult[str]:
        """Convert entry from source to target quirk via RFC.

        Pipeline: parse → to_rfc → from_rfc → write
        """
        try:
            # Access Entry quirk components
            source_entry_quirk = getattr(source_quirk, "entry", None)
            target_entry_quirk = getattr(target_quirk, "entry", None)

            if source_entry_quirk is None:
                return FlextResult[str].fail("Source quirk does not have Entry support")
            if target_entry_quirk is None:
                return FlextResult[str].fail("Target quirk does not have Entry support")

            # Step 1: Parse source format (if string)
            if isinstance(data, str):
                # For entry, we need to parse LDIF - use basic parser first
                # This is a simplified approach; real implementation may need full LDIF parsing
                return FlextResult[str].fail(
                    "String input for entry conversion not yet supported - pass parsed dict"
                )
            else:
                source_data = data

            # Step 2: Convert source → RFC
            to_rfc_result = source_entry_quirk.convert_entry_to_rfc(source_data)
            if to_rfc_result.is_failure:
                return FlextResult[str].fail(
                    f"Failed to convert source→RFC: {to_rfc_result.error}"
                )
            rfc_data = to_rfc_result.unwrap()

            # Step 3: Convert RFC → target
            from_rfc_result = target_entry_quirk.convert_entry_from_rfc(rfc_data)
            if from_rfc_result.is_failure:
                return FlextResult[str].fail(
                    f"Failed to convert RFC→target: {from_rfc_result.error}"
                )
            target_data = from_rfc_result.unwrap()

            # Step 4: Write target format
            write_result = target_entry_quirk.write_entry_to_ldif(target_data)
            if write_result.is_failure:
                return FlextResult[str].fail(
                    f"Failed to write target format: {write_result.error}"
                )

            return write_result

        except Exception as e:
            return FlextResult[str].fail(f"Entry conversion failed: {e}")

    def batch_convert(
        self,
        source_quirk: Any,
        target_quirk: Any,
        data_type: DataType,
        data_list: list[str | FlextLdifTypes.Dict],
    ) -> FlextResult[list[str | FlextLdifTypes.Dict]]:
        """Convert multiple items from source to target quirk via RFC.

        This is a convenience method that applies convert() to a list of items.

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
                error_msg = f"Batch conversion completed with {len(errors)} errors:\n" + "\n".join(errors[:5])
                if len(errors) > 5:
                    error_msg += f"\n... and {len(errors) - 5} more errors"
                return FlextResult[list[str | FlextLdifTypes.Dict]].fail(error_msg)

            return FlextResult[list[str | FlextLdifTypes.Dict]].ok(converted)

        except Exception as e:
            return FlextResult[list[str | FlextLdifTypes.Dict]].fail(
                f"Batch conversion failed: {e}"
            )

    def get_supported_conversions(self, quirk: Any) -> dict[str, bool]:
        """Check which data types a quirk supports for conversion.

        Args:
            quirk: Quirk instance to check

        Returns:
            Dictionary mapping data_type to support status

        Examples:
            >>> oud = FlextLdifQuirksServersOud()
            >>> supported = matrix.get_supported_conversions(oud)
            >>> print(supported)
            {'attribute': True, 'objectclass': True, 'acl': True, 'entry': True}
        """
        support = {
            "attribute": False,
            "objectclass": False,
            "acl": False,
            "entry": False,
        }

        # Check schema support
        if hasattr(quirk, "parse_attribute") and hasattr(quirk, "convert_attribute_to_rfc"):
            support["attribute"] = True
        if hasattr(quirk, "parse_objectclass") and hasattr(quirk, "convert_objectclass_to_rfc"):
            support["objectclass"] = True

        # Check ACL support
        acl_quirk = getattr(quirk, "acl", None)
        if acl_quirk and hasattr(acl_quirk, "parse_acl") and hasattr(acl_quirk, "convert_acl_to_rfc"):
            support["acl"] = True

        # Check Entry support
        entry_quirk = getattr(quirk, "entry", None)
        if entry_quirk and hasattr(entry_quirk, "convert_entry_to_rfc"):
            support["entry"] = True

        return support


__all__ = ["QuirksConversionMatrix", "DataType"]
