"""Relaxed Quirks for Lenient LDIF Processing.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Implements relaxed/lenient quirks that allow processing of broken, non-compliant,
or malformed LDIF files. The relaxed mode is useful for:
- Broken LDIF files from legacy systems
- Non-standard LDAP server implementations
- Files with RFC violations
- Emergency data recovery scenarios

Relaxed Mode Features:
- Skip validation errors and continue processing
- Lenient DN parsing (allow malformed DNs)
- Flexible attribute parsing (allow non-standard formats)
- Ignore RFC compliance violations
- Best-effort parsing (extract what's possible)
- Log warnings instead of failing
"""

from __future__ import annotations

import logging
import re
from typing import ClassVar

from flext_core import FlextResult
from pydantic import Field

from flext_ldif.quirks.base import (
    FlextLdifQuirksBaseAclQuirk,
    FlextLdifQuirksBaseEntryQuirk,
    FlextLdifQuirksBaseSchemaQuirk,
)
from flext_ldif.typings import FlextLdifTypes

logger = logging.getLogger(__name__)


class FlextLdifQuirksServersRelaxedSchema(FlextLdifQuirksBaseSchemaQuirk):
    """Relaxed schema quirk for lenient LDIF processing.

    Implements minimal validation and best-effort parsing of schema definitions.
    Suitable for broken or non-compliant LDIF files.

    Features:
    - Allows malformed OIDs
    - Skips missing required attributes
    - Accepts non-standard syntax OIDs
    - Lenient matching rule validation
    - Logs warnings instead of failing

    **Priority**: 200 (very low - last resort)
    """

    server_type: str = Field(
        default="relaxed",
        description="Relaxed lenient parsing mode",
    )
    priority: int = Field(default=200, description="Very low priority - last resort")

    # Permissive OID pattern - matches anything that looks like an OID
    OID_PATTERN: ClassVar[re.Pattern[str]] = re.compile(r"\(?\s*([0-9a-zA-Z._\-]+)")

    def model_post_init(self, _context: object, /) -> None:
        """Initialize relaxed schema quirk."""

    def can_handle_attribute(self, attr_definition: str) -> bool:
        """Accept any attribute definition in relaxed mode.

        Args:
            attr_definition: AttributeType definition string

        Returns:
            Always True - relaxed mode accepts everything

        """
        return bool(attr_definition.strip())

    def parse_attribute(
        self, attr_definition: str
    ) -> FlextResult[FlextLdifTypes.Models.CustomDataDict]:
        """Parse attribute with best-effort approach.

        Args:
            attr_definition: AttributeType definition string

        Returns:
            FlextResult with parsed attribute or error details

        """
        try:
            # Extract OID - be very permissive
            oid_match = re.search(r"\(?\s*([0-9a-zA-Z._\-]+)", attr_definition)
            oid = oid_match.group(1) if oid_match else "unknown"

            # Extract NAME - optional, be lenient
            name_match = re.search(r"NAME\s+['\"]?([^'\" ]+)['\"]?", attr_definition)
            name = name_match.group(1) if name_match else oid

            return FlextResult[FlextLdifTypes.Models.CustomDataDict].ok({
                "oid": oid,
                "name": name,
                "definition": attr_definition,
                "relaxed_parsed": True,
            })
        except Exception as e:
            logger.warning(f"Relaxed attribute parse failed: {e}")
            return FlextResult[FlextLdifTypes.Models.CustomDataDict].ok({
                "name": "unknown",
                "definition": attr_definition,
                "relaxed_parsed": False,
                "parse_error": str(e),
            })

    def can_handle_objectclass(self, oc_definition: str) -> bool:
        """Accept any objectClass definition in relaxed mode.

        Args:
            oc_definition: ObjectClass definition string

        Returns:
            Always True - relaxed mode accepts everything

        """
        return bool(oc_definition.strip())

    def parse_objectclass(
        self, oc_definition: str
    ) -> FlextResult[FlextLdifTypes.Models.CustomDataDict]:
        """Parse objectClass with best-effort approach.

        Args:
            oc_definition: ObjectClass definition string

        Returns:
            FlextResult with parsed objectClass or error details

        """
        try:
            # Extract OID - be very permissive
            oid_match = re.search(r"\(?\s*([0-9a-zA-Z._\-]+)", oc_definition)
            oid = oid_match.group(1) if oid_match else "unknown"

            # Extract NAME - optional, be lenient
            name_match = re.search(r"NAME\s+['\"]?([^'\" ]+)['\"]?", oc_definition)
            name = name_match.group(1) if name_match else oid

            return FlextResult[FlextLdifTypes.Models.CustomDataDict].ok({
                "oid": oid,
                "name": name,
                "definition": oc_definition,
                "relaxed_parsed": True,
            })
        except Exception as e:
            logger.warning(f"Relaxed objectClass parse failed: {e}")
            return FlextResult[FlextLdifTypes.Models.CustomDataDict].ok({
                "name": "unknown",
                "definition": oc_definition,
                "relaxed_parsed": False,
                "parse_error": str(e),
            })

    def convert_attribute_to_rfc(
        self, attr_data: FlextLdifTypes.Models.CustomDataDict
    ) -> FlextResult[FlextLdifTypes.Models.CustomDataDict]:
        """Convert attribute to RFC format - pass-through in relaxed mode.

        Args:
            attr_data: Attribute data dictionary

        Returns:
            FlextResult with data (unchanged)

        """
        return FlextResult[FlextLdifTypes.Models.CustomDataDict].ok(attr_data)

    def convert_objectclass_to_rfc(
        self, oc_data: FlextLdifTypes.Models.CustomDataDict
    ) -> FlextResult[FlextLdifTypes.Models.CustomDataDict]:
        """Convert objectClass to RFC format - pass-through in relaxed mode.

        Args:
            oc_data: ObjectClass data dictionary

        Returns:
            FlextResult with data (unchanged)

        """
        return FlextResult[FlextLdifTypes.Models.CustomDataDict].ok(oc_data)

    def convert_attribute_from_rfc(
        self, rfc_data: FlextLdifTypes.Models.CustomDataDict
    ) -> FlextResult[FlextLdifTypes.Models.CustomDataDict]:
        """Convert attribute from RFC format - pass-through in relaxed mode.

        Args:
            rfc_data: RFC-compliant attribute data

        Returns:
            FlextResult with data (unchanged)

        """
        return FlextResult[FlextLdifTypes.Models.CustomDataDict].ok(rfc_data)

    def convert_objectclass_from_rfc(
        self, rfc_data: FlextLdifTypes.Models.CustomDataDict
    ) -> FlextResult[FlextLdifTypes.Models.CustomDataDict]:
        """Convert objectClass from RFC format - pass-through in relaxed mode.

        Args:
            rfc_data: RFC-compliant objectClass data

        Returns:
            FlextResult with data (unchanged)

        """
        return FlextResult[FlextLdifTypes.Models.CustomDataDict].ok(rfc_data)

    def write_attribute_to_rfc(
        self, attr_data: FlextLdifTypes.Models.CustomDataDict
    ) -> FlextResult[str]:
        """Write attribute to RFC format - stringify in relaxed mode.

        Args:
            attr_data: Attribute data dictionary

        Returns:
            FlextResult with stringified data

        """
        try:
            definition = attr_data.get("definition", "")
            if isinstance(definition, str):
                return FlextResult[str].ok(definition)
            return FlextResult[str].ok(str(attr_data))
        except Exception as e:
            logger.warning(f"Write attribute failed: {e}")
            return FlextResult[str].ok(str(attr_data))

    def write_objectclass_to_rfc(
        self, oc_data: FlextLdifTypes.Models.CustomDataDict
    ) -> FlextResult[str]:
        """Write objectClass to RFC format - stringify in relaxed mode.

        Args:
            oc_data: ObjectClass data dictionary

        Returns:
            FlextResult with stringified data

        """
        try:
            definition = oc_data.get("definition", "")
            if isinstance(definition, str):
                return FlextResult[str].ok(definition)
            return FlextResult[str].ok(str(oc_data))
        except Exception as e:
            logger.warning(f"Write objectClass failed: {e}")
            return FlextResult[str].ok(str(oc_data))


class FlextLdifQuirksServersRelaxedAcl(FlextLdifQuirksBaseAclQuirk):
    """Relaxed ACL quirk for lenient LDIF processing.

    Implements minimal validation for ACL entries.
    Accepts any ACL format in relaxed mode.

    **Priority**: 200 (very low - last resort)
    """

    server_type: str = Field(
        default="relaxed",
        description="Relaxed lenient parsing mode",
    )
    priority: int = Field(default=200, description="Very low priority - last resort")

    def model_post_init(self, _context: object, /) -> None:
        """Initialize relaxed ACL quirk."""

    def can_handle_acl(self, acl_line: str) -> bool:
        """Accept any ACL line in relaxed mode.

        Args:
            acl_line: ACL definition line

        Returns:
            Always True - relaxed mode accepts everything

        """
        return bool(acl_line.strip())

    def parse_acl(
        self, acl_line: str
    ) -> FlextResult[FlextLdifTypes.Models.CustomDataDict]:
        """Parse ACL with best-effort approach.

        Args:
            acl_line: ACL definition line

        Returns:
            FlextResult with parsed ACL or error details

        """
        try:
            return FlextResult[FlextLdifTypes.Models.CustomDataDict].ok({
                "raw_acl": acl_line,
                "relaxed_parsed": True,
            })
        except Exception as e:
            logger.warning(f"Relaxed ACL parse failed: {e}")
            return FlextResult[FlextLdifTypes.Models.CustomDataDict].ok({
                "raw_acl": acl_line,
                "relaxed_parsed": False,
                "parse_error": str(e),
            })

    def convert_acl_to_rfc(
        self, acl_data: FlextLdifTypes.Models.CustomDataDict
    ) -> FlextResult[FlextLdifTypes.Models.CustomDataDict]:
        """Convert ACL to RFC format - pass-through in relaxed mode.

        Args:
            acl_data: ACL data dictionary

        Returns:
            FlextResult with data (unchanged)

        """
        return FlextResult[FlextLdifTypes.Models.CustomDataDict].ok(acl_data)

    def convert_acl_from_rfc(
        self, acl_data: FlextLdifTypes.Models.CustomDataDict
    ) -> FlextResult[FlextLdifTypes.Models.CustomDataDict]:
        """Convert ACL from RFC format - pass-through in relaxed mode.

        Args:
            acl_data: RFC-compliant ACL data

        Returns:
            FlextResult with data (unchanged)

        """
        return FlextResult[FlextLdifTypes.Models.CustomDataDict].ok(acl_data)

    def write_acl_to_rfc(
        self, acl_data: FlextLdifTypes.Models.CustomDataDict
    ) -> FlextResult[str]:
        """Write ACL to RFC format - stringify in relaxed mode.

        Args:
            acl_data: ACL data dictionary

        Returns:
            FlextResult with stringified data

        """
        try:
            raw_acl = acl_data.get("raw_acl", "")
            if isinstance(raw_acl, str):
                return FlextResult[str].ok(raw_acl)
            return FlextResult[str].ok(str(acl_data))
        except Exception as e:
            logger.warning(f"Write ACL failed: {e}")
            return FlextResult[str].ok(str(acl_data))


class FlextLdifQuirksServersRelaxedEntry(FlextLdifQuirksBaseEntryQuirk):
    """Relaxed entry quirk for lenient LDIF processing.

    Implements minimal validation for LDIF entries.
    Accepts any entry format in relaxed mode.

    **Priority**: 200 (very low - last resort)
    """

    server_type: str = Field(
        default="relaxed",
        description="Relaxed lenient parsing mode",
    )
    priority: int = Field(default=200, description="Very low priority - last resort")

    def model_post_init(self, _context: object, /) -> None:
        """Initialize relaxed entry quirk."""

    def process_entry(
        self, entry_dn: str, attributes: FlextLdifTypes.Models.CustomDataDict
    ) -> FlextResult[dict[str, object]]:
        """Process entry for relaxed mode.

        Args:
            entry_dn: Entry distinguished name
            attributes: Entry attributes

        Returns:
            FlextResult with processed entry data

        """
        try:
            return FlextResult[dict[str, object]].ok({
                "dn": entry_dn,
                "attributes": attributes,
                "relaxed_processed": True,
            })
        except Exception as e:
            logger.warning(f"Relaxed entry processing failed: {e}")
            return FlextResult[dict[str, object]].ok({
                "dn": entry_dn,
                "attributes": attributes,
                "relaxed_processed": False,
                "process_error": str(e),
            })

    def can_handle_entry(
        self,
        entry_dn: str,
        attributes: FlextLdifTypes.Models.CustomDataDict,  # noqa: ARG002
    ) -> bool:
        """Accept any entry in relaxed mode.

        Args:
            entry_dn: Entry distinguished name
            attributes: Entry attributes (unused - relaxed mode accepts everything)

        Returns:
            Always True - relaxed mode accepts everything

        """
        return bool(entry_dn.strip())

    def parse_entry(
        self, entry_dn: str, attributes: FlextLdifTypes.Models.CustomDataDict
    ) -> FlextResult[FlextLdifTypes.Models.CustomDataDict]:
        """Parse entry with best-effort approach.

        Args:
            entry_dn: Entry distinguished name
            attributes: Entry attributes

        Returns:
            FlextResult with parsed entry or error details

        """
        try:
            return FlextResult[FlextLdifTypes.Models.CustomDataDict].ok({
                "dn": entry_dn,
                "attributes": attributes,
                "relaxed_parsed": True,
            })
        except Exception as e:
            logger.warning(f"Relaxed entry parse failed: {e}")
            return FlextResult[FlextLdifTypes.Models.CustomDataDict].ok({
                "dn": entry_dn,
                "attributes": attributes,
                "relaxed_parsed": False,
                "parse_error": str(e),
            })

    def normalize_dn(self, dn: str) -> FlextResult[str]:
        """Normalize DN - best-effort in relaxed mode.

        Args:
            dn: Distinguished name

        Returns:
            FlextResult with normalized DN

        """
        try:
            # Minimal normalization: just lowercase component names
            components = dn.split(",")
            normalized = ",".join(
                comp.split("=")[0].lower() + "=" + comp.split("=", 1)[1]
                if "=" in comp
                else comp
                for comp in components
            )
            return FlextResult[str].ok(normalized)
        except Exception as e:
            logger.warning(f"DN normalization failed, using original: {e}")
            return FlextResult[str].ok(dn)

    def convert_entry_to_rfc(
        self, entry_data: FlextLdifTypes.Models.CustomDataDict
    ) -> FlextResult[FlextLdifTypes.Models.CustomDataDict]:
        """Convert entry to RFC format - pass-through in relaxed mode.

        Args:
            entry_data: Entry data dictionary

        Returns:
            FlextResult with data (unchanged)

        """
        return FlextResult[FlextLdifTypes.Models.CustomDataDict].ok(entry_data)

    def convert_entry_from_rfc(
        self, entry_data: FlextLdifTypes.Models.CustomDataDict
    ) -> FlextResult[FlextLdifTypes.Models.CustomDataDict]:
        """Convert entry from RFC format - pass-through in relaxed mode.

        Args:
            entry_data: RFC-compliant entry data

        Returns:
            FlextResult with data (unchanged)

        """
        return FlextResult[FlextLdifTypes.Models.CustomDataDict].ok(entry_data)


__all__ = [
    "FlextLdifQuirksServersRelaxedAcl",
    "FlextLdifQuirksServersRelaxedEntry",
    "FlextLdifQuirksServersRelaxedSchema",
]
