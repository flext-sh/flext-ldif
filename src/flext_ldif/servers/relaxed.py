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

import re
from collections.abc import Mapping
from typing import ClassVar

from flext_core import FlextLogger, FlextResult

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.servers.rfc import FlextLdifServersRfc

logger = FlextLogger(__name__)


class FlextLdifServersRelaxed(FlextLdifServersRfc):
    """Relaxed mode server quirks for non-compliant LDIF."""

    # Top-level configuration - mirrors Schema class for direct access
    server_type = FlextLdifConstants.ServerTypes.RELAXED
    priority = 200

    class Schema(FlextLdifServersRfc.Schema):
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

        # Relaxed mode configuration defaults
        server_type: ClassVar[str] = FlextLdifConstants.ServerTypes.RELAXED
        priority: ClassVar[int] = 200

        def can_handle_attribute(
            self, attribute: FlextLdifModels.SchemaAttribute
        ) -> bool:
            """Accept any attribute definition in relaxed mode.

            Args:
                attribute: SchemaAttribute model

            Returns:
                Always True - relaxed mode accepts everything

            """
            return True

        # --------------------------------------------------------------------- #
        # Schema parsing and conversion methods
        # --------------------------------------------------------------------- #
        # --------------------------------------------------------------------- #
        # OVERRIDDEN METHODS (from FlextLdifServersBase.Schema)
        # --------------------------------------------------------------------- #
        # These methods override the base class with relaxed/lenient logic:
        # - parse_attribute(): Lenient parsing that accepts malformed definitions
        # - parse_objectclass(): Lenient parsing that accepts malformed definitions
        # - convert_attribute_to_rfc(): Strips server metadata (no-op in relaxed mode)
        # - convert_objectclass_to_rfc(): Strips server metadata (no-op in relaxed mode)
        # - convert_attribute_from_rfc(): Adds minimal metadata for relaxed mode
        # - convert_objectclass_from_rfc(): Adds minimal metadata for relaxed mode
        # - write_attribute_to_rfc(): Uses RFC writer with relaxed error handling
        # - write_objectclass_to_rfc(): Uses RFC writer with relaxed error handling
        # - should_filter_out_attribute(): Returns False (accept all in relaxed mode)
        # - should_filter_out_objectclass(): Returns False (accept all in relaxed mode)
        # - create_quirk_metadata(): Creates minimal metadata for relaxed mode

        def parse_attribute(
            self,
            attr_definition: str,
        ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
            """Parse attribute with best-effort approach using RFC baseline.

            Uses RFC baseline parser with lenient mode, with fallback to minimal
            parsing for severely broken definitions.

            Args:
                attr_definition: AttributeType definition string

            Returns:
                FlextResult with parsed SchemaAttribute or fallback with minimal data

            """
            try:
                # Try RFC baseline parser first with lenient mode for broken LDIF
                result = FlextLdifServersRfc.AttributeParser.parse_common(
                    attr_definition,
                    case_insensitive=True,  # Relaxed - accept case variations
                    allow_syntax_quotes=True,  # Relaxed - allow 'OID' format
                )

                if result.is_success:
                    # RFC parser succeeded - enhance metadata as relaxed mode
                    attribute = result.unwrap()
                    if not attribute.metadata:
                        attribute.metadata = FlextLdifModels.QuirkMetadata(
                            quirk_type=FlextLdifConstants.ServerTypes.RELAXED,
                            original_format=attr_definition.strip(),
                            extensions={"relaxed_parsed": True, "rfc_parsed": True},
                        )
                    else:
                        attribute.metadata.extensions["relaxed_parsed"] = True

                    return FlextResult[FlextLdifModels.SchemaAttribute].ok(attribute)

                # RFC parser failed - fall back to minimal best-effort parsing
                logger.debug(
                    f"RFC parser failed, using best-effort fallback: {result.error}"
                )
                oid_match = re.search(r"\(?\s*([0-9a-zA-Z._\-]+)", attr_definition)
                oid = oid_match.group(1) if oid_match else "unknown"

                name_match = re.search(
                    r"NAME\s+['\"]?([^'\" ]+)['\"]?",
                    attr_definition,
                    re.IGNORECASE,
                )
                name = name_match.group(1) if name_match else oid

                # Return minimal attribute with relaxed metadata
                metadata = FlextLdifModels.QuirkMetadata(
                    quirk_type=FlextLdifConstants.ServerTypes.RELAXED,
                    original_format=attr_definition.strip(),
                    extensions={
                        "relaxed_parsed": True,
                        "rfc_parsed": False,
                        "fallback": True,
                    },
                )

                return FlextResult[FlextLdifModels.SchemaAttribute].ok(
                    FlextLdifModels.SchemaAttribute(
                        name=name,
                        oid=oid,
                        desc=None,
                        sup=None,
                        equality=None,
                        ordering=None,
                        substr=None,
                        syntax=None,
                        length=None,
                        usage=None,
                        single_value=False,
                        no_user_modification=False,
                        metadata=metadata,
                    ),
                )

            except Exception as e:
                logger.debug("Relaxed attribute parse exception: %s", e)
                # Last resort: return minimal fallback
                metadata = FlextLdifModels.QuirkMetadata(
                    quirk_type=FlextLdifConstants.ServerTypes.RELAXED,
                    original_format=attr_definition.strip()
                    if isinstance(attr_definition, str)
                    else "",
                    extensions={"relaxed_parsed": False, "error": str(e)},
                )
                return FlextResult[FlextLdifModels.SchemaAttribute].ok(
                    FlextLdifModels.SchemaAttribute(
                        name="unknown",
                        oid="unknown",
                        desc=None,
                        sup=None,
                        equality=None,
                        ordering=None,
                        substr=None,
                        syntax=None,
                        length=None,
                        usage=None,
                        single_value=False,
                        no_user_modification=False,
                        metadata=metadata,
                    ),
                )

        def can_handle_objectclass(
            self, objectclass: FlextLdifModels.SchemaObjectClass
        ) -> bool:
            """Accept any objectClass definition in relaxed mode.

            Args:
                objectclass: SchemaObjectClass model

            Returns:
                Always True - relaxed mode accepts everything

            """
            return True

        def parse_objectclass(
            self,
            oc_definition: str,
        ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
            """Parse objectClass with best-effort approach using RFC baseline.

            Uses RFC baseline parser with lenient mode, with fallback to minimal
            parsing for severely broken definitions.

            Args:
                oc_definition: ObjectClass definition string

            Returns:
                FlextResult with parsed SchemaObjectClass or fallback with minimal data

            """
            try:
                # Try RFC baseline parser first with lenient mode for broken LDIF
                result = FlextLdifServersRfc.ObjectClassParser.parse_common(
                    oc_definition,
                    case_insensitive=True,  # Relaxed - accept case variations
                )

                if result.is_success:
                    # RFC parser succeeded - enhance metadata as relaxed mode
                    objectclass = result.unwrap()
                    if not objectclass.metadata:
                        objectclass.metadata = FlextLdifModels.QuirkMetadata(
                            quirk_type=FlextLdifConstants.ServerTypes.RELAXED,
                            original_format=oc_definition.strip(),
                            extensions={"relaxed_parsed": True, "rfc_parsed": True},
                        )
                    else:
                        objectclass.metadata.extensions["relaxed_parsed"] = True

                    return FlextResult[FlextLdifModels.SchemaObjectClass].ok(
                        objectclass
                    )

                # RFC parser failed - fall back to minimal best-effort parsing
                logger.debug(
                    f"RFC parser failed, using best-effort fallback: {result.error}"
                )
                oid_match = re.search(r"\(?\s*([0-9a-zA-Z._\-]+)", oc_definition)
                oid = oid_match.group(1) if oid_match else "unknown"

                name_match = re.search(
                    r"NAME\s+['\"]?([^'\" ]+)['\"]?",
                    oc_definition,
                    re.IGNORECASE,
                )
                name = name_match.group(1) if name_match else oid

                # Return minimal objectClass with relaxed metadata
                metadata = FlextLdifModels.QuirkMetadata(
                    quirk_type=FlextLdifConstants.ServerTypes.RELAXED,
                    original_format=oc_definition.strip(),
                    extensions={
                        "relaxed_parsed": True,
                        "rfc_parsed": False,
                        "fallback": True,
                    },
                )

                return FlextResult[FlextLdifModels.SchemaObjectClass].ok(
                    FlextLdifModels.SchemaObjectClass(
                        name=name,
                        oid=oid,
                        desc=None,
                        sup=None,
                        kind=FlextLdifConstants.Schema.STRUCTURAL,  # Default kind
                        must=None,
                        may=None,
                        metadata=metadata,
                    ),
                )

            except Exception as e:
                logger.debug("Relaxed objectClass parse exception: %s", e)
                # Last resort: return minimal fallback
                metadata = FlextLdifModels.QuirkMetadata(
                    quirk_type=FlextLdifConstants.ServerTypes.RELAXED,
                    original_format=oc_definition.strip()
                    if isinstance(oc_definition, str)
                    else "",
                    extensions={"relaxed_parsed": False, "error": str(e)},
                )
                return FlextResult[FlextLdifModels.SchemaObjectClass].ok(
                    FlextLdifModels.SchemaObjectClass(
                        name="unknown",
                        oid="unknown",
                        desc=None,
                        sup=None,
                        kind=FlextLdifConstants.Schema.STRUCTURAL,
                        must=None,
                        may=None,
                        metadata=metadata,
                    ),
                )

        def convert_attribute_to_rfc(
            self,
            attr_data: FlextLdifModels.SchemaAttribute,
        ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
            """Convert attribute to RFC format - pass-through in relaxed mode.

            Args:
                attr_data: SchemaAttribute model

            Returns:
                FlextResult with data (unchanged)

            """
            return FlextResult[FlextLdifModels.SchemaAttribute].ok(attr_data)

        def convert_objectclass_to_rfc(
            self,
            oc_data: FlextLdifModels.SchemaObjectClass,
        ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
            """Convert objectClass to RFC format - pass-through in relaxed mode.

            Args:
                oc_data: SchemaObjectClass model

            Returns:
                FlextResult with data (unchanged)

            """
            return FlextResult[FlextLdifModels.SchemaObjectClass].ok(oc_data)

        def convert_attribute_from_rfc(
            self,
            rfc_data: FlextLdifModels.SchemaAttribute,
        ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
            """Convert attribute from RFC format - pass-through in relaxed mode.

            Args:
                rfc_data: RFC-compliant SchemaAttribute

            Returns:
                FlextResult with data (unchanged)

            """
            return FlextResult[FlextLdifModels.SchemaAttribute].ok(rfc_data)

        def convert_objectclass_from_rfc(
            self,
            rfc_data: FlextLdifModels.SchemaObjectClass,
        ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
            """Convert objectClass from RFC format - pass-through in relaxed mode.

            Args:
                rfc_data: RFC-compliant SchemaObjectClass

            Returns:
                FlextResult with data (unchanged)

            """
            return FlextResult[FlextLdifModels.SchemaObjectClass].ok(rfc_data)

        def write_attribute_to_rfc(
            self,
            attr_data: FlextLdifModels.SchemaAttribute,
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
                    definition = attr_data.metadata.custom_data.get(
                        "original_definition",
                    )
                    if isinstance(definition, str):
                        return FlextResult[str].ok(definition)
                # Fallback to model string representation
                return FlextResult[str].ok(str(attr_data.model_dump()))
            except Exception as e:
                logger.debug("Write attribute failed: %s", e)
                return FlextResult[str].ok(str(attr_data.model_dump()))

        def write_objectclass_to_rfc(
            self,
            oc_data: FlextLdifModels.SchemaObjectClass,
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
                logger.debug("Write objectClass failed: %s", e)
                return FlextResult[str].ok(str(oc_data.model_dump()))

        # --------------------------------------------------------------------- #
        # OVERRIDDEN METHODS (from FlextLdifServersBase.Acl)
        # --------------------------------------------------------------------- #
        # These methods override the base class with relaxed/lenient logic:
        # - can_handle_acl(): Accepts any ACL line in relaxed mode
        # - parse_acl(): Parses ACL with best-effort approach
        # - convert_acl_to_rfc(): Converts to RFC format
        # - convert_acl_from_rfc(): Converts from RFC format
        # - write_acl_to_rfc(): Writes ACL to RFC format - stringify in relaxed mode
        # - get_acl_attribute_name(): Returns "acl" (RFC baseline, inherited)

    class Acl(FlextLdifServersRfc.Acl):
        """Relaxed ACL quirk for lenient LDIF processing.

        Implements minimal validation for ACL entries.
        Accepts any ACL format in relaxed mode.

        **Priority**: 200 (very low - last resort)
        """

        server_type: ClassVar[str] = FlextLdifConstants.ServerTypes.RELAXED
        priority: ClassVar[int] = 200

        def __init__(self) -> None:
            """Initialize relaxed ACL quirk with priority 200."""
            super().__init__(server_type=FlextLdifConstants.ServerTypes.GENERIC)

        def can_handle_acl(self, acl: FlextLdifModels.Acl) -> bool:
            """Accept any ACL line in relaxed mode.

            Args:
                acl: Acl model

            Returns:
                Always True - relaxed mode accepts everything

            """
            return True

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
                        subject_type="*",
                        subject_value="*",
                    ),
                    permissions=FlextLdifModels.AclPermissions(),
                    server_type="generic",  # Use generic server type for relaxed parsing
                    raw_acl=acl_line,
                )
                return FlextResult[FlextLdifModels.Acl].ok(acl)
            except Exception as e:
                logger.debug("Relaxed ACL parse failed: %s", e)
                # Return generic ACL as fallback when parsing fails
                acl = FlextLdifModels.Acl(
                    name="relaxed_acl_error",
                    target=FlextLdifModels.AclTarget(target_dn="*", attributes=[]),
                    subject=FlextLdifModels.AclSubject(
                        subject_type="*",
                        subject_value="*",
                    ),
                    permissions=FlextLdifModels.AclPermissions(),
                    server_type="generic",  # Use generic server type for relaxed parsing
                    raw_acl=acl_line,
                )
                return FlextResult[FlextLdifModels.Acl].ok(acl)

        def convert_acl_to_rfc(
            self,
            acl_data: FlextLdifModels.Acl,
        ) -> FlextResult[FlextLdifModels.Acl]:
            """Convert ACL to RFC format - pass-through in relaxed mode.

            Args:
                acl_data: Acl model

            Returns:
                FlextResult with data (unchanged)

            """
            return FlextResult[FlextLdifModels.Acl].ok(acl_data)

        def convert_acl_from_rfc(
            self,
            acl_data: FlextLdifModels.Acl,
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
                logger.debug("Write ACL failed: %s", e)
                return FlextResult[str].ok(str(acl_data.model_dump()))

    class Entry(FlextLdifServersRfc.Entry):
        """Relaxed entry quirk for lenient LDIF processing.

        Implements minimal validation for LDIF entries.
        Accepts any entry format in relaxed mode.

        **Priority**: 200 (very low - last resort)
        """

        server_type: ClassVar[str] = FlextLdifConstants.ServerTypes.RELAXED
        priority: ClassVar[int] = 200

        def __init__(self) -> None:
            """Initialize relaxed entry quirk with priority 200."""
            super().__init__(server_type=FlextLdifConstants.ServerTypes.RELAXED)

        # --------------------------------------------------------------------- #
        # OVERRIDDEN METHODS (from FlextLdifServersBase.Entry)
        # --------------------------------------------------------------------- #
        # These methods override the base class with relaxed/lenient logic:
        # - can_handle_entry(): Accepts any entry in relaxed mode
        # - process_entry(): Pass-through processing for relaxed mode
        # - convert_entry_to_rfc(): Pass-through conversion for relaxed mode

        def process_entry(
            self,
            entry: FlextLdifModels.Entry,
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Process entry for relaxed mode.

            Args:
                entry: Entry model

            Returns:
                FlextResult with processed entry

            """
            try:
                # In relaxed mode, pass through entry unchanged
                return FlextResult[FlextLdifModels.Entry].ok(entry)
            except Exception as e:
                logger.debug("Relaxed entry processing failed: %s", e)
                return FlextResult[FlextLdifModels.Entry].ok(entry)

        def can_handle_entry(
            self,
            entry: FlextLdifModels.Entry,
        ) -> bool:
            """Accept any entry in relaxed mode.

            Args:
                entry: Entry model

            Returns:
                Always True - relaxed mode accepts everything

            """
            return True

        def parse_entry(
            self,
            entry_dn: str,
            entry_attrs: Mapping[str, object],
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Parse entry with best-effort approach.

            Args:
                entry_dn: Entry distinguished name
                entry_attrs: Entry attributes

            Returns:
                FlextResult with parsed Entry object

            """
            # Try parent's parse_entry first
            parent_result = super().parse_entry(entry_dn, entry_attrs)
            if parent_result.is_success:
                return parent_result

            # Best-effort fallback: create Entry with raw data if parsing fails
            logger.debug("Relaxed entry parse failed: %s", parent_result.error)
            try:
                # Use provided DN if valid, otherwise create a fallback DN
                effective_dn_str = entry_dn if entry_dn.strip() else "cn=relaxed-entry"
                effective_dn = FlextLdifModels.DistinguishedName(value=effective_dn_str)

                # Convert attributes dict to LdifAttributes if needed
                if isinstance(entry_attrs, FlextLdifModels.LdifAttributes):
                    ldif_attrs = entry_attrs
                else:
                    # Create LdifAttributes from dict - convert values to lists if needed
                    attr_dict: dict[str, list[str]] = {}
                    for key, value in entry_attrs.items():
                        if isinstance(value, list):
                            attr_dict[str(key)] = [str(v) for v in value]
                        else:
                            attr_dict[str(key)] = [str(value)]
                    ldif_attrs = FlextLdifModels.LdifAttributes(attributes=attr_dict)

                return FlextResult[FlextLdifModels.Entry].ok(
                    FlextLdifModels.Entry(
                        dn=effective_dn,
                        attributes=ldif_attrs,
                    ),
                )
            except Exception as fallback_error:
                # Absolute fallback: create minimum valid Entry
                logger.debug(
                    "Relaxed entry creation failed: %s",
                    fallback_error,
                )
                try:
                    return FlextResult[FlextLdifModels.Entry].ok(
                        FlextLdifModels.Entry(
                            dn=FlextLdifModels.DistinguishedName(
                                value="cn=relaxed-entry"
                            ),
                            attributes=FlextLdifModels.LdifAttributes(
                                attributes={},
                            ),
                        ),
                    )
                except Exception as final_error:
                    logger.warning(
                        "All relaxed entry creation attempts failed: %s",
                        final_error,
                    )
                    # Final fallback - return success with error logged
                    try:
                        return FlextResult[FlextLdifModels.Entry].ok(
                            FlextLdifModels.Entry(
                                dn=FlextLdifModels.DistinguishedName(
                                    value="cn=relaxed-entry"
                                ),
                                attributes=FlextLdifModels.LdifAttributes(
                                    attributes={},
                                ),
                            ),
                        )
                    except Exception as absolute_final_error:
                        logger.warning(
                            "Absolute final relaxed entry creation failed: %s",
                            absolute_final_error,
                        )
                        # This shouldn't happen, but if it does, we still return success
                        # with a fallback entry
                        return FlextResult[FlextLdifModels.Entry].ok(
                            FlextLdifModels.Entry(
                                dn=FlextLdifModels.DistinguishedName(
                                    value="cn=fallback"
                                ),
                                attributes=FlextLdifModels.LdifAttributes(
                                    attributes={},
                                ),
                            ),
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
                    (
                        comp.split("=")[0].lower() + "=" + comp.split("=", 1)[1]
                        if "=" in comp
                        else comp
                    )
                    for comp in components
                )
                return FlextResult[str].ok(normalized)
            except Exception as e:
                logger.debug("DN normalization failed, using original: %s", e)
                return FlextResult[str].ok(dn)

        def convert_entry_to_rfc(
            self,
            entry_data: FlextLdifModels.Entry,
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Convert entry to RFC format - pass-through in relaxed mode.

            Args:
                entry_data: Entry model

            Returns:
                FlextResult with data (unchanged)

            """
            return FlextResult[FlextLdifModels.Entry].ok(entry_data)

        def convert_entry_from_rfc(
            self,
            entry_data: FlextLdifModels.Entry,
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Convert entry from RFC format - pass-through in relaxed mode.

            Args:
                entry_data: RFC-compliant entry model

            Returns:
                FlextResult with data (unchanged)

            """
            return FlextResult[FlextLdifModels.Entry].ok(entry_data)


__all__ = [
    "FlextLdifServersRelaxed",
]
