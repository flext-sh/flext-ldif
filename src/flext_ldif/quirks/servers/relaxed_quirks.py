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

# Pydantic removed
from flext_ldif.models import FlextLdifModels
from flext_ldif.quirks.base import (
    BaseAclQuirk,
    BaseEntryQuirk,
    BaseSchemaQuirk,
)
from flext_ldif.typings import FlextLdifTypes

logger = logging.getLogger(__name__)


class FlextLdifQuirksServersRelaxed(BaseSchemaQuirk):
    """Relaxed schema quirk - main class for lenient LDIF processing.

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

    # Permissive OID pattern - matches anything that looks like an OID
    OID_PATTERN: ClassVar[re.Pattern[str]] = re.compile(r"\(?\s*([0-9a-zA-Z._\-]+)")

    def __init__(
        self,
        server_type: str = "relaxed",
        priority: int = 200,
    ) -> None:
        """Initialize relaxed schema quirk.

        Args:
            server_type: Relaxed lenient parsing mode
            priority: Very low priority - last resort

        """
        super().__init__(server_type=server_type, priority=priority)

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
    ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
        """Parse attribute with best-effort approach.

        Args:
            attr_definition: AttributeType definition string

        Returns:
            FlextResult with parsed SchemaAttribute or error details

        """
        try:
            # Extract OID - be very permissive
            oid_match = re.search(r"\(?\s*([0-9a-zA-Z._\-]+)", attr_definition)
            oid = oid_match.group(1) if oid_match else "unknown"

            # Extract NAME - optional, be lenient
            name_match = re.search(r"NAME\s+['\"]?([^'\" ]+)['\"]?", attr_definition)
            name = name_match.group(1) if name_match else oid

            # Store relaxed-specific metadata
            metadata = FlextLdifModels.QuirkMetadata(
                quirk_type="relaxed",
                original_format=attr_definition,
                extensions={
                    "relaxed_parsed": True,
                },
            )

            return FlextResult[FlextLdifModels.SchemaAttribute].ok(
                FlextLdifModels.SchemaAttribute(
                    name=name,
                    oid=oid,
                    desc=None,  # Relaxed - not extracted
                    sup=None,  # Relaxed - not extracted
                    equality=None,  # Relaxed - not extracted
                    ordering=None,  # Relaxed - not extracted
                    substr=None,  # Relaxed - not extracted
                    syntax=None,  # Relaxed - not extracted
                    length=None,  # Relaxed - not extracted
                    usage=None,  # Relaxed - not extracted
                    metadata=metadata,
                )
            )
        except Exception as e:
            logger.warning(f"Relaxed attribute parse failed: {e}")
            metadata = FlextLdifModels.QuirkMetadata(
                quirk_type="relaxed",
                original_format=attr_definition
                if isinstance(attr_definition, str)
                else "",
                extensions={"relaxed_parsed": False, "parse_error": str(e)},
            )
            return FlextResult[FlextLdifModels.SchemaAttribute].ok(
                FlextLdifModels.SchemaAttribute(
                    name="unknown",
                    oid="unknown",
                    desc=None,  # Relaxed - parse failed
                    sup=None,  # Relaxed - parse failed
                    equality=None,  # Relaxed - parse failed
                    ordering=None,  # Relaxed - parse failed
                    substr=None,  # Relaxed - parse failed
                    syntax=None,  # Relaxed - parse failed
                    length=None,  # Relaxed - parse failed
                    usage=None,  # Relaxed - parse failed
                    metadata=metadata,
                )
            )

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
    ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
        """Parse objectClass with best-effort approach.

        Args:
            oc_definition: ObjectClass definition string

        Returns:
            FlextResult with parsed SchemaObjectClass or error details

        """
        try:
            # Extract OID - be very permissive
            oid_match = re.search(r"\(?\s*([0-9a-zA-Z._\-]+)", oc_definition)
            oid = oid_match.group(1) if oid_match else "unknown"

            # Extract NAME - optional, be lenient
            name_match = re.search(r"NAME\s+['\"]?([^'\" ]+)['\"]?", oc_definition)
            name = name_match.group(1) if name_match else oid

            # Store relaxed-specific metadata
            metadata = FlextLdifModels.QuirkMetadata(
                quirk_type="relaxed",
                original_format=oc_definition,
                extensions={
                    "relaxed_parsed": True,
                },
            )

            return FlextResult[FlextLdifModels.SchemaObjectClass].ok(
                FlextLdifModels.SchemaObjectClass(
                    name=name,
                    oid=oid,
                    desc=None,  # Relaxed - not extracted
                    sup=None,  # Relaxed - not extracted
                    metadata=metadata,
                )
            )
        except Exception as e:
            logger.warning(f"Relaxed objectClass parse failed: {e}")
            metadata = FlextLdifModels.QuirkMetadata(
                quirk_type="relaxed",
                original_format=oc_definition if isinstance(oc_definition, str) else "",
                extensions={"relaxed_parsed": False, "parse_error": str(e)},
            )
            return FlextResult[FlextLdifModels.SchemaObjectClass].ok(
                FlextLdifModels.SchemaObjectClass(
                    name="unknown",
                    oid="unknown",
                    desc=None,  # Relaxed - parse failed
                    sup=None,  # Relaxed - parse failed
                    metadata=metadata,
                )
            )

    def convert_attribute_to_rfc(
        self, attr_data: FlextLdifModels.SchemaAttribute
    ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
        """Convert attribute to RFC format - pass-through in relaxed mode.

        Args:
            attr_data: SchemaAttribute model

        Returns:
            FlextResult with data (unchanged)

        """
        return FlextResult[FlextLdifModels.SchemaAttribute].ok(attr_data)

    def convert_objectclass_to_rfc(
        self, oc_data: FlextLdifModels.SchemaObjectClass
    ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
        """Convert objectClass to RFC format - pass-through in relaxed mode.

        Args:
            oc_data: SchemaObjectClass model

        Returns:
            FlextResult with data (unchanged)

        """
        return FlextResult[FlextLdifModels.SchemaObjectClass].ok(oc_data)

    def convert_attribute_from_rfc(
        self, rfc_data: FlextLdifModels.SchemaAttribute
    ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
        """Convert attribute from RFC format - pass-through in relaxed mode.

        Args:
            rfc_data: RFC-compliant SchemaAttribute

        Returns:
            FlextResult with data (unchanged)

        """
        return FlextResult[FlextLdifModels.SchemaAttribute].ok(rfc_data)

    def convert_objectclass_from_rfc(
        self, rfc_data: FlextLdifModels.SchemaObjectClass
    ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
        """Convert objectClass from RFC format - pass-through in relaxed mode.

        Args:
            rfc_data: RFC-compliant SchemaObjectClass

        Returns:
            FlextResult with data (unchanged)

        """
        return FlextResult[FlextLdifModels.SchemaObjectClass].ok(rfc_data)

    def write_attribute_to_rfc(
        self, attr_data: FlextLdifModels.SchemaAttribute
    ) -> FlextResult[str]:
        """Write attribute to RFC format - stringify in relaxed mode.

        Args:
            attr_data: SchemaAttribute model

        Returns:
            FlextResult with stringified data

        """
        try:
            # Try to get original definition from metadata
            if attr_data.metadata and attr_data.metadata.custom_data:
                definition = attr_data.metadata.custom_data.get("original_definition")
                if isinstance(definition, str):
                    return FlextResult[str].ok(definition)
            # Fallback to model string representation
            return FlextResult[str].ok(str(attr_data.model_dump()))
        except Exception as e:
            logger.warning(f"Write attribute failed: {e}")
            return FlextResult[str].ok(str(attr_data.model_dump()))

    def write_objectclass_to_rfc(
        self, oc_data: FlextLdifModels.SchemaObjectClass
    ) -> FlextResult[str]:
        """Write objectClass to RFC format - stringify in relaxed mode.

        Args:
            oc_data: SchemaObjectClass model

        Returns:
            FlextResult with stringified data

        """
        try:
            # Try to get original definition from metadata
            if oc_data.metadata and oc_data.metadata.custom_data:
                definition = oc_data.metadata.custom_data.get("original_definition")
                if isinstance(definition, str):
                    return FlextResult[str].ok(definition)
            # Fallback to model string representation
            return FlextResult[str].ok(str(oc_data.model_dump()))
        except Exception as e:
            logger.warning(f"Write objectClass failed: {e}")
            return FlextResult[str].ok(str(oc_data.model_dump()))

    class AclQuirk(BaseAclQuirk):
        """Relaxed ACL quirk for lenient LDIF processing.

        Implements minimal validation for ACL entries.
        Accepts any ACL format in relaxed mode.

        **Priority**: 200 (very low - last resort)
        """

        def __init__(self) -> None:
            """Initialize relaxed ACL quirk with priority 200."""
            super().__init__(server_type="relaxed", priority=200)

        def can_handle_acl(self, acl_line: str) -> bool:
            """Accept any ACL line in relaxed mode.

            Args:
                acl_line: ACL definition line

            Returns:
                Always True - relaxed mode accepts everything

            """
            return bool(acl_line.strip())

        def parse_acl(self, acl_line: str) -> FlextResult[FlextLdifModels.Acl]:
            """Parse ACL with best-effort approach.

            Args:
                acl_line: ACL definition line

            Returns:
                FlextResult with parsed Acl or error details

            """
            try:
                # Create minimal Acl model with relaxed parsing
                acl = FlextLdifModels.Acl(
                    name="relaxed_acl",
                    target=FlextLdifModels.AclTarget(target_dn="*", attributes=[]),
                    subject=FlextLdifModels.AclSubject(
                        subject_type="*", subject_value="*"
                    ),
                    permissions=FlextLdifModels.AclPermissions(),
                    server_type="generic",  # Use generic server type for relaxed parsing
                    raw_acl=acl_line,
                )
                return FlextResult[FlextLdifModels.Acl].ok(acl)
            except Exception as e:
                logger.warning(f"Relaxed ACL parse failed: {e}")
                # Return generic ACL as fallback when parsing fails
                acl = FlextLdifModels.Acl(
                    name="relaxed_acl_error",
                    target=FlextLdifModels.AclTarget(target_dn="*", attributes=[]),
                    subject=FlextLdifModels.AclSubject(
                        subject_type="*", subject_value="*"
                    ),
                    permissions=FlextLdifModels.AclPermissions(),
                    server_type="generic",  # Use generic server type for relaxed parsing
                    raw_acl=acl_line,
                )
                return FlextResult[FlextLdifModels.Acl].ok(acl)

        def convert_acl_to_rfc(
            self, acl_data: FlextLdifModels.Acl
        ) -> FlextResult[FlextLdifModels.Acl]:
            """Convert ACL to RFC format - pass-through in relaxed mode.

            Args:
                acl_data: Acl model

            Returns:
                FlextResult with data (unchanged)

            """
            return FlextResult[FlextLdifModels.Acl].ok(acl_data)

        def convert_acl_from_rfc(
            self, acl_data: FlextLdifModels.Acl
        ) -> FlextResult[FlextLdifModels.Acl]:
            """Convert ACL from RFC format - pass-through in relaxed mode.

            Args:
                acl_data: RFC-compliant Acl model

            Returns:
                FlextResult with data (unchanged)

            """
            return FlextResult[FlextLdifModels.Acl].ok(acl_data)

        def write_acl_to_rfc(self, acl_data: FlextLdifModels.Acl) -> FlextResult[str]:
            """Write ACL to RFC format - stringify in relaxed mode.

            Args:
                acl_data: Acl model

            Returns:
                FlextResult with stringified data

            """
            try:
                # Use raw_acl field from Acl model
                if acl_data.raw_acl and isinstance(acl_data.raw_acl, str):
                    return FlextResult[str].ok(acl_data.raw_acl)
                return FlextResult[str].ok(str(acl_data.model_dump()))
            except Exception as e:
                logger.warning(f"Write ACL failed: {e}")
                return FlextResult[str].ok(str(acl_data.model_dump()))

    class EntryQuirk(BaseEntryQuirk):
        """Relaxed entry quirk for lenient LDIF processing.

        Implements minimal validation for LDIF entries.
        Accepts any entry format in relaxed mode.

        **Priority**: 200 (very low - last resort)
        """

        def __init__(self) -> None:
            """Initialize relaxed entry quirk with priority 200."""
            super().__init__(server_type="relaxed", priority=200)

        def process_entry(
            self, entry_dn: str, attributes: FlextLdifTypes.Models.EntryAttributesDict
        ) -> FlextResult[FlextLdifTypes.Models.EntryAttributesDict]:
            """Process entry for relaxed mode.

            Args:
                entry_dn: Entry distinguished name
                attributes: Entry attributes

            Returns:
                FlextResult with processed entry attributes

            """
            try:
                # Suppress unused parameter warning - required by interface
                _ = entry_dn
                # In relaxed mode, pass through attributes unchanged
                return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].ok(
                    attributes
                )
            except Exception as e:
                logger.warning(f"Relaxed entry processing failed: {e}")
                return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].ok(
                    attributes
                )

        def can_handle_entry(
            self,
            entry_dn: str,
            attributes: FlextLdifTypes.Models.EntryAttributesDict,
        ) -> bool:
            """Accept any entry in relaxed mode.

            Args:
                entry_dn: Entry distinguished name
                attributes: Entry attributes (unused - relaxed mode accepts everything)

            Returns:
                Always True - relaxed mode accepts everything

            """
            # Suppress unused parameter warning - required by interface
            _ = attributes
            return bool(entry_dn.strip())

        def parse_entry(
            self, _entry_dn: str, attributes: FlextLdifTypes.Models.EntryAttributesDict
        ) -> FlextResult[FlextLdifTypes.Models.EntryAttributesDict]:
            """Parse entry with best-effort approach.

            Args:
                _entry_dn: Entry distinguished name
                attributes: Entry attributes

            Returns:
                FlextResult with parsed entry attributes

            """
            try:
                # In relaxed mode, pass through attributes unchanged
                return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].ok(
                    attributes
                )
            except Exception as e:
                logger.warning(f"Relaxed entry parse failed: {e}")
                return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].ok(
                    attributes
                )

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
            self, entry_data: FlextLdifTypes.Models.EntryAttributesDict
        ) -> FlextResult[FlextLdifTypes.Models.EntryAttributesDict]:
            """Convert entry to RFC format - pass-through in relaxed mode.

            Args:
                entry_data: Entry attributes dictionary

            Returns:
                FlextResult with data (unchanged)

            """
            return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].ok(entry_data)

        def convert_entry_from_rfc(
            self, entry_data: FlextLdifTypes.Models.EntryAttributesDict
        ) -> FlextResult[FlextLdifTypes.Models.EntryAttributesDict]:
            """Convert entry from RFC format - pass-through in relaxed mode.

            Args:
                entry_data: RFC-compliant entry attributes

            Returns:
                FlextResult with data (unchanged)

            """
            return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].ok(entry_data)


# Backward compatibility exports
FlextLdifQuirksServersRelaxedSchema = FlextLdifQuirksServersRelaxed
FlextLdifQuirksServersRelaxedAcl = FlextLdifQuirksServersRelaxed.AclQuirk
FlextLdifQuirksServersRelaxedEntry = FlextLdifQuirksServersRelaxed.EntryQuirk

__all__ = [
    "FlextLdifQuirksServersRelaxed",
    "FlextLdifQuirksServersRelaxedAcl",  # Backward compatibility
    "FlextLdifQuirksServersRelaxedEntry",  # Backward compatibility
    "FlextLdifQuirksServersRelaxedSchema",  # Backward compatibility
]
