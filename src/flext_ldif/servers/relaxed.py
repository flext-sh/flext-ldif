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
from enum import StrEnum
from typing import ClassVar, cast

from flext_core import FlextLogger, FlextResult

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.servers.rfc import FlextLdifServersRfc
from flext_ldif.typings import FlextLdifTypes
from flext_ldif.utilities import FlextLdifUtilities

logger = FlextLogger(__name__)


class FlextLdifServersRelaxed(FlextLdifServersRfc):
    """Relaxed mode server quirks for non-compliant LDIF."""

    # =========================================================================
    class Constants(FlextLdifServersRfc.Constants):
        """Standardized constants for Relaxed (lenient) quirk."""

        # Server identity and priority (defined at Constants level)
        SERVER_TYPE: ClassVar[str] = FlextLdifConstants.ServerTypes.RELAXED
        PRIORITY: ClassVar[int] = 200  # Lowest priority - fallback for broken LDIF

        # Auto-discovery constants
        CANONICAL_NAME: ClassVar[str] = "relaxed"
        ALIASES: ClassVar[frozenset[str]] = frozenset(["relaxed", "lenient"])
        CAN_NORMALIZE_FROM: ClassVar[frozenset[str]] = frozenset(["relaxed"])
        CAN_DENORMALIZE_TO: ClassVar[frozenset[str]] = frozenset(["relaxed", "rfc"])

        # Relaxed mode ACL format constants (uses RFC format)
        ACL_FORMAT: ClassVar[str] = "rfc_generic"  # Relaxed mode uses RFC format
        ACL_ATTRIBUTE_NAME: ClassVar[str] = "aci"  # RFC 4876 ACI attribute

        # Relaxed-specific patterns - permissive OID pattern matches anything that looks like an OID
        OID_PATTERN: ClassVar[re.Pattern[str]] = re.compile(r"\(?\s*([0-9a-zA-Z._\-]+)")

        # OID extraction patterns (migrated from _parse_attribute and _parse_objectclass methods)
        OID_NUMERIC_WITH_PAREN: ClassVar[str] = r"\(\s*([0-9]+(?:\.[0-9]+)+)"
        OID_NUMERIC_ANYWHERE: ClassVar[str] = r"([0-9]+\.[0-9]+(?:\.[0-9]+)*)"
        OID_ALPHANUMERIC_RELAXED: ClassVar[str] = r"\(\s*([a-zA-Z0-9._-]+)"

        # Schema parsing patterns (migrated from Schema class)
        SCHEMA_MUST_SEPARATOR: ClassVar[str] = "$"
        SCHEMA_MAY_SEPARATOR: ClassVar[str] = "$"
        SCHEMA_NAME_PATTERN: ClassVar[str] = r"NAME\s+['\"]?([^'\" ]+)['\"]?"

        # ACL-specific constants (migrated from Acl class)
        ACL_DEFAULT_NAME: ClassVar[str] = "relaxed_acl"
        ACL_DEFAULT_TARGET_DN: ClassVar[str] = "*"
        ACL_DEFAULT_SUBJECT_TYPE: ClassVar[str] = "*"
        ACL_DEFAULT_SUBJECT_VALUE: ClassVar[str] = "*"
        ACL_WRITE_PREFIX: ClassVar[str] = "acl: "

        # Entry writing constants (migrated from _write_entry method)
        LDIF_DN_PREFIX: ClassVar[str] = "dn: "
        LDIF_ATTR_SEPARATOR: ClassVar[str] = ": "

        # Metadata extension keys (migrated from parsing methods)
        METADATA_RELAXED_PARSED: ClassVar[str] = "relaxed_parsed"
        METADATA_RFC_PARSED: ClassVar[str] = "rfc_parsed"

        # Encoding constants (migrated from _parse_entry method)
        ENCODING_UTF8: ClassVar[str] = "utf-8"
        ENCODING_ERROR_HANDLING: ClassVar[str] = "replace"

        # LDIF formatting constants (migrated from _write_entry method)
        LDIF_NEWLINE: ClassVar[str] = "\n"
        LDIF_JOIN_SEPARATOR: ClassVar[str] = "\n"

        # === NESTED STRENUM DEFINITIONS ===
        # StrEnum definitions for type-safe permission, action, and encoding handling

        class AclPermission(StrEnum):
            """Relaxed mode-specific ACL permissions (lenient parsing)."""

            READ = "read"
            WRITE = "write"
            ADD = "add"
            DELETE = "delete"
            SEARCH = "search"
            COMPARE = "compare"
            AUTH = "auth"
            ALL = "all"
            NONE = "none"

        class AclAction(StrEnum):
            """Relaxed mode ACL action types."""

            ALLOW = "allow"
            DENY = "deny"

        class Encoding(StrEnum):
            """Relaxed mode-supported encodings."""

            UTF_8 = "utf-8"
            UTF_16 = "utf-16"
            UTF_32 = "utf-32"
            ASCII = "ascii"
            LATIN_1 = "latin-1"
            CP1252 = "cp1252"

    # =========================================================================
    # Server identification - accessed via Constants via properties in base.py
    # =========================================================================
    # NOTE: server_type and priority are accessed via properties in base.py
    # which read from Constants.SERVER_TYPE and Constants.PRIORITY

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

        def can_handle_attribute(
            self,
            attr_definition: str | FlextLdifModels.SchemaAttribute,
        ) -> bool:
            """Accept any attribute definition in relaxed mode.

            Args:
                attr_definition: Attribute definition string or SchemaAttribute model

            Returns:
                True for non-empty strings, False for empty/whitespace

            """
            if isinstance(attr_definition, str):
                return bool(attr_definition.strip())
            return True

        # Schema parsing and conversion methods
        # OVERRIDDEN METHODS (from FlextLdifServersBase.Schema)
        # These methods override the base class with relaxed/lenient logic:
        # - _parse_attribute(): Lenient parsing that accepts malformed definitions
        # - _parse_objectclass(): Lenient parsing that accepts malformed definitions
        # - _write_attribute(): Uses RFC writer with relaxed error handling
        # - _write_objectclass(): Uses RFC writer with relaxed error handling

        def _extract_oid_from_attribute(self, attr_definition: str) -> str | None:
            """Extract OID from attribute definition using multiple strategies.

            Tries in order:
            1. RFC-compliant extraction using utilities
            2. Numeric OID with parentheses
            3. Numeric OID anywhere in string
            4. Alphanumeric identifier (relaxed mode)

            Args:
                attr_definition: Attribute definition string

            Returns:
                Extracted OID string or None if not found

            """
            # Try RFC-compliant extraction first
            oid = FlextLdifUtilities.Parser.extract_oid(attr_definition)
            if oid:
                return oid

            # Try numeric OID with parentheses
            oid_match = re.search(
                FlextLdifServersRelaxed.Constants.OID_NUMERIC_WITH_PAREN,
                attr_definition,
            )
            if oid_match:
                return oid_match.group(1)

            # Try numeric OID anywhere in string
            oid_match = re.search(
                FlextLdifServersRelaxed.Constants.OID_NUMERIC_ANYWHERE,
                attr_definition,
            )
            if oid_match:
                return oid_match.group(1)

            # Try alphanumeric identifier (relaxed mode)
            oid_match = re.search(
                FlextLdifServersRelaxed.Constants.OID_ALPHANUMERIC_RELAXED,
                attr_definition,
            )
            if oid_match:
                return oid_match.group(1)

            return None

        def _parse_attribute(
            self,
            attr_definition: str,
        ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
            """Parse attribute with best-effort approach using RFC baseline.

            Override RFC implementation with relaxed mode parsing for broken definitions.
            No fallbacks - proper error handling only.

            Args:
                attr_definition: AttributeType definition string

            Returns:
                FlextResult with parsed SchemaAttribute or error

            """
            # Validate input - empty strings are not handled
            if not attr_definition or not attr_definition.strip():
                return FlextResult[FlextLdifModels.SchemaAttribute].fail(
                    "Attribute definition cannot be empty",
                )

            # Always try parent's _parse_attribute first (RFC format)
            parent_result = super()._parse_attribute(attr_definition)
            if parent_result.is_success:
                # RFC parser succeeded - enhance metadata as relaxed mode
                attribute = parent_result.unwrap()
                if not attribute.metadata:
                    attribute.metadata = FlextLdifModels.QuirkMetadata(
                        quirk_type=self._get_server_type(),
                        extensions={
                            "original_format": attr_definition.strip(),
                            FlextLdifServersRelaxed.Constants.METADATA_RELAXED_PARSED: True,
                            FlextLdifServersRelaxed.Constants.METADATA_RFC_PARSED: True,
                        },
                    )
                else:
                    if not attribute.metadata.extensions:
                        attribute.metadata.extensions = {}
                    attribute.metadata.extensions[
                        FlextLdifServersRelaxed.Constants.METADATA_RELAXED_PARSED
                    ] = True
                    attribute.metadata.quirk_type = self._get_server_type()
                    # Ensure original_format is set
                    if not attribute.metadata.extensions.get("original_format"):
                        attribute.metadata.extensions["original_format"] = (
                            attr_definition.strip()
                        )
                return FlextResult[FlextLdifModels.SchemaAttribute].ok(attribute)

            # RFC parser failed - use minimal best-effort parsing (no fallback, proper parsing)
            logger.debug(
                f"RFC parser failed, using best-effort parsing: {parent_result.error}",
            )
            try:
                # Extract OID using helper method with multiple strategies
                oid = self._extract_oid_from_attribute(attr_definition)
                if not oid:
                    return FlextResult[FlextLdifModels.SchemaAttribute].fail(
                        "Cannot extract OID from attribute definition",
                    )

                name_match = re.search(
                    FlextLdifServersRelaxed.Constants.SCHEMA_NAME_PATTERN,
                    attr_definition,
                    re.IGNORECASE,
                )
                name = name_match.group(1) if name_match else oid

                # Return minimal attribute with relaxed metadata
                metadata = FlextLdifModels.QuirkMetadata(
                    quirk_type=self._get_server_type(),
                    original_format=attr_definition.strip(),
                    extensions={
                        FlextLdifServersRelaxed.Constants.METADATA_RELAXED_PARSED: True,
                        FlextLdifServersRelaxed.Constants.METADATA_RFC_PARSED: False,
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
                        x_origin=None,
                        x_file_ref=None,
                        x_name=None,
                        x_alias=None,
                        x_oid=None,
                    ),
                )
            except Exception as e:
                logger.debug("Relaxed attribute parse exception: %s", e)
                # Return error result for failed parsing
                return FlextResult[FlextLdifModels.SchemaAttribute].fail(
                    f"Failed to parse attribute definition: {e}",
                )

        def can_handle_objectclass(
            self,
            oc_definition: str | FlextLdifModels.SchemaObjectClass,
        ) -> bool:
            """Accept any objectClass definition in relaxed mode.

            Args:
                oc_definition: ObjectClass definition string or SchemaObjectClass model

            Returns:
                True for non-empty strings, False for empty/whitespace

            """
            if isinstance(oc_definition, str):
                return bool(oc_definition.strip())
            return True

        def _enhance_objectclass_metadata(
            self,
            objectclass: FlextLdifModels.SchemaObjectClass,
            original_definition: str,
        ) -> FlextLdifModels.SchemaObjectClass:
            """Enhance objectClass metadata to indicate relaxed mode parsing.

            Args:
                objectclass: Parsed objectClass from RFC parser
                original_definition: Original definition string

            Returns:
                ObjectClass with enhanced metadata

            """
            if not objectclass.metadata:
                objectclass.metadata = FlextLdifModels.QuirkMetadata(
                    quirk_type=self._get_server_type(),
                    original_format=original_definition.strip(),
                    extensions={
                        FlextLdifServersRelaxed.Constants.METADATA_RELAXED_PARSED: True,
                        FlextLdifServersRelaxed.Constants.METADATA_RFC_PARSED: True,
                    },
                )
            else:
                if not objectclass.metadata.extensions:
                    objectclass.metadata.extensions = {}
                objectclass.metadata.extensions[
                    FlextLdifServersRelaxed.Constants.METADATA_RELAXED_PARSED
                ] = True
                objectclass.metadata.quirk_type = self._get_server_type()
                # Ensure original_format is set
                if not objectclass.metadata.extensions.get("original_format"):
                    objectclass.metadata.extensions["original_format"] = (
                        original_definition.strip()
                    )
            return objectclass

        def _parse_objectclass_relaxed(
            self,
            oc_definition: str,
        ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
            """Parse objectClass with relaxed/best-effort parsing using utilities.

            No fallbacks - returns error if OID cannot be extracted.

            Args:
                oc_definition: ObjectClass definition string

            Returns:
                FlextResult with parsed SchemaObjectClass or error

            """
            # Extract OID using utilities first (numeric OID)
            oid = FlextLdifUtilities.Parser.extract_oid(oc_definition)
            if not oid:
                # Try relaxed pattern for numeric OID
                oid_match = re.search(
                    FlextLdifServersRelaxed.Constants.OID_NUMERIC_WITH_PAREN,
                    oc_definition,
                )
                if oid_match:
                    oid = oid_match.group(1)
                else:
                    # Look for any numeric OID pattern
                    oid_match = re.search(
                        FlextLdifServersRelaxed.Constants.OID_NUMERIC_ANYWHERE,
                        oc_definition,
                    )
                    if oid_match:
                        oid = oid_match.group(1)
                # Relaxed mode: if no numeric OID found, try alphanumeric identifier
                if not oid:
                    # Match alphanumeric identifier after opening paren (relaxed mode)
                    oid_match = re.search(
                        FlextLdifServersRelaxed.Constants.OID_ALPHANUMERIC_RELAXED,
                        oc_definition,
                    )
                    if oid_match:
                        oid = oid_match.group(1)

            if not oid:
                return FlextResult[FlextLdifModels.SchemaObjectClass].fail(
                    "Failed to extract OID from objectClass definition",
                )

            # Extract fields using utilities
            name = FlextLdifUtilities.Parser.extract_optional_field(
                oc_definition,
                FlextLdifConstants.LdifPatterns.SCHEMA_NAME,
                default=oid,
            )
            desc = FlextLdifUtilities.Parser.extract_optional_field(
                oc_definition,
                FlextLdifConstants.LdifPatterns.SCHEMA_DESC,
            )

            # Extract SUP
            sup = None
            sup_match = re.search(
                FlextLdifConstants.LdifPatterns.SCHEMA_OBJECTCLASS_SUP,
                oc_definition,
            )
            if sup_match:
                sup_value = (sup_match.group(1) or sup_match.group(2)).strip()
                sup = (
                    next(
                        s.strip()
                        for s in sup_value.split(
                            FlextLdifServersRelaxed.Constants.SCHEMA_MUST_SEPARATOR,
                        )
                    )
                    if FlextLdifServersRelaxed.Constants.SCHEMA_MUST_SEPARATOR
                    in sup_value
                    else sup_value
                )

            # Determine kind
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

            # Extract MUST/MAY
            must = None
            must_match = re.search(
                FlextLdifConstants.LdifPatterns.SCHEMA_OBJECTCLASS_MUST,
                oc_definition,
            )
            if must_match:
                must_value = (must_match.group(1) or must_match.group(2)).strip()
                must = [
                    m.strip()
                    for m in must_value.split(
                        FlextLdifServersRelaxed.Constants.SCHEMA_MUST_SEPARATOR,
                    )
                ]

            may = None
            may_match = re.search(
                FlextLdifConstants.LdifPatterns.SCHEMA_OBJECTCLASS_MAY,
                oc_definition,
            )
            if may_match:
                may_value = (may_match.group(1) or may_match.group(2)).strip()
                may = [
                    m.strip()
                    for m in may_value.split(
                        FlextLdifServersRelaxed.Constants.SCHEMA_MAY_SEPARATOR,
                    )
                ]

            # Build metadata
            extensions = FlextLdifUtilities.Parser.extract_extensions(oc_definition)
            extensions[FlextLdifServersRelaxed.Constants.METADATA_RELAXED_PARSED] = True
            extensions[FlextLdifServersRelaxed.Constants.METADATA_RFC_PARSED] = False

            metadata = FlextLdifModels.QuirkMetadata(
                quirk_type=self._get_server_type(),
                original_format=oc_definition.strip(),
                extensions=extensions,
            )

            return FlextResult[FlextLdifModels.SchemaObjectClass].ok(
                FlextLdifModels.SchemaObjectClass(
                    name=name or oid,
                    oid=oid,
                    desc=desc,
                    sup=sup,
                    kind=kind,
                    must=must,
                    may=may,
                    metadata=metadata,
                ),
            )

        def _parse_objectclass(
            self,
            oc_definition: str,
        ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
            """Parse objectClass with best-effort approach using RFC baseline.

            Override RFC implementation with relaxed mode parsing for broken definitions.
            No fallbacks - proper error handling only.

            Args:
                oc_definition: ObjectClass definition string

            Returns:
                FlextResult with parsed SchemaObjectClass or error

            """
            # Validate input - empty strings are not handled
            if not oc_definition or not oc_definition.strip():
                return FlextResult[FlextLdifModels.SchemaObjectClass].fail(
                    "ObjectClass definition cannot be empty",
                )

            # Always try parent's _parse_objectclass first (RFC format)
            parent_result = super()._parse_objectclass(oc_definition)
            if parent_result.is_success:
                # RFC parser succeeded - enhance metadata as relaxed mode
                objectclass = parent_result.unwrap()
                return FlextResult[FlextLdifModels.SchemaObjectClass].ok(
                    self._enhance_objectclass_metadata(objectclass, oc_definition),
                )

            # RFC parser failed - use best-effort parsing with utilities
            logger.debug(
                f"RFC parser failed, using best-effort parsing: {parent_result.error}",
            )
            return self._parse_objectclass_relaxed(oc_definition)

        def _write_attribute(
            self,
            attr_data: FlextLdifModels.SchemaAttribute,
        ) -> FlextResult[str]:
            """Write attribute to RFC format - stringify in relaxed mode.

            Args:
                attr_data: SchemaAttribute model

            Returns:
                FlextResult with RFC-compliant attribute string

            """
            # Try parent's write method first (RFC format)
            parent_result = super()._write_attribute(attr_data)
            if parent_result.is_success:
                return parent_result
            # Use original format from metadata if available
            if attr_data.metadata and attr_data.metadata.extensions.get(
                "original_format"
            ):
                return FlextResult[str].ok(
                    cast(
                        "str", attr_data.metadata.extensions.get("original_format", "")
                    )
                )
            # Format from model data
            if not attr_data.oid:
                return FlextResult[str].fail("Attribute OID is required for writing")
            name = attr_data.name or attr_data.oid
            return FlextResult[str].ok(f"( {attr_data.oid} NAME '{name}' )")

        def _write_objectclass(
            self,
            oc_data: FlextLdifModels.SchemaObjectClass,
        ) -> FlextResult[str]:
            """Write objectClass to RFC format - stringify in relaxed mode.

            Args:
                oc_data: SchemaObjectClass model

            Returns:
                FlextResult with RFC-compliant objectClass string

            """
            # Try parent's write method first (RFC format)
            parent_result = super()._write_objectclass(oc_data)
            if parent_result.is_success:
                return parent_result
            # Use original format from metadata if available
            if oc_data.metadata and oc_data.metadata.extensions.get("original_format"):
                return FlextResult[str].ok(
                    cast("str", oc_data.metadata.extensions.get("original_format", ""))
                )
            # Format from model data
            if not oc_data.oid:
                return FlextResult[str].fail("ObjectClass OID is required for writing")
            name: str = oc_data.name or oc_data.oid
            kind = oc_data.kind or FlextLdifConstants.Schema.STRUCTURAL
            return FlextResult[str].ok(f"( {oc_data.oid} NAME '{name}' {kind} )")

        # OVERRIDDEN METHODS (from FlextLdifServersBase.Acl)
        # These methods override the base class with relaxed/lenient logic:
        # - can_handle_acl(): Accepts any ACL line in relaxed mode
        # - _parse_acl(): Parses ACL with best-effort approach
        # - _write_acl(): Writes ACL to RFC format - stringify in relaxed mode

    class Acl(FlextLdifServersRfc.Acl):
        """Relaxed ACL quirk for lenient LDIF processing.

        Implements minimal validation for ACL entries.
        Accepts any ACL format in relaxed mode.

        **Priority**: 200 (very low - last resort)
        """

        def can_handle(self, acl_line: FlextLdifTypes.AclOrString) -> bool:
            """Check if this is a relaxed ACL (public method).

            Args:
                acl_line: ACL line string or Acl model to check.

            Returns:
                Always True - relaxed mode accepts everything

            """
            return self.can_handle_acl(acl_line)

        def can_handle_acl(self, acl_line: FlextLdifTypes.AclOrString) -> bool:
            """Accept any ACL line in relaxed mode.

            Args:
                acl_line: ACL line string or Acl model (unused - relaxed accepts all)

            Returns:
                Always True - relaxed mode accepts everything

            """
            _ = acl_line  # Relaxed mode accepts everything, parameter not used
            return True

        def _parse_acl(self, acl_line: str) -> FlextResult[FlextLdifModels.Acl]:
            """Parse ACL with best-effort approach.

            Args:
                acl_line: ACL definition line

            Returns:
                FlextResult with parsed Acl or error details

            """
            if not acl_line or not acl_line.strip():
                return FlextResult[FlextLdifModels.Acl].fail("ACL line cannot be empty")
            try:
                # Try parent's parse method first (RFC format)
                parent_result = super()._parse_acl(acl_line)
                if parent_result.is_success:
                    acl = parent_result.unwrap()
                    # Enhance metadata to indicate relaxed mode
                    if not acl.metadata:
                        acl.metadata = FlextLdifModels.QuirkMetadata(
                            quirk_type=self._get_server_type(),
                            original_format=acl_line.strip(),
                            extensions={
                                FlextLdifServersRelaxed.Constants.METADATA_RELAXED_PARSED: True,
                                FlextLdifServersRelaxed.Constants.METADATA_RFC_PARSED: True,
                            },
                        )
                    else:
                        if not acl.metadata.extensions:
                            acl.metadata.extensions = {}
                        acl.metadata.extensions[
                            FlextLdifServersRelaxed.Constants.METADATA_RELAXED_PARSED
                        ] = True
                        acl.metadata.quirk_type = self._get_server_type()
                    return FlextResult[FlextLdifModels.Acl].ok(acl)
                # Create minimal Acl model with relaxed parsing
                acl = FlextLdifModels.Acl(
                    name=FlextLdifServersRelaxed.Constants.ACL_DEFAULT_NAME,
                    target=FlextLdifModels.AclTarget(
                        target_dn=FlextLdifServersRelaxed.Constants.ACL_DEFAULT_TARGET_DN,
                        attributes=[],
                    ),
                    subject=FlextLdifModels.AclSubject(
                        subject_type=FlextLdifServersRelaxed.Constants.ACL_DEFAULT_SUBJECT_TYPE,
                        subject_value=FlextLdifServersRelaxed.Constants.ACL_DEFAULT_SUBJECT_VALUE,
                    ),
                    permissions=FlextLdifModels.AclPermissions(),
                    raw_acl=acl_line,
                    metadata=FlextLdifModels.QuirkMetadata(
                        quirk_type=self._get_server_type(),
                        original_format=acl_line.strip(),
                        extensions={
                            FlextLdifServersRelaxed.Constants.METADATA_RELAXED_PARSED: True,
                            FlextLdifServersRelaxed.Constants.METADATA_RFC_PARSED: False,
                        },
                    ),
                )
                return FlextResult[FlextLdifModels.Acl].ok(acl)
            except Exception as e:
                logger.debug("Relaxed ACL parse failed: %s", e)
                return FlextResult[FlextLdifModels.Acl].fail(
                    f"Failed to parse ACL: {e}",
                )

        def _write_acl(self, acl_data: FlextLdifModels.Acl) -> FlextResult[str]:
            """Write ACL to RFC format - stringify in relaxed mode.

            Args:
                acl_data: Acl model

            Returns:
                FlextResult with RFC-compliant ACL string

            """
            # Try parent's write method first (RFC format)
            parent_result = super()._write_acl(acl_data)
            if parent_result.is_success:
                return parent_result
            # Use raw_acl field from Acl model if available
            if acl_data.raw_acl and isinstance(acl_data.raw_acl, str):
                return FlextResult[str].ok(acl_data.raw_acl)
            # Format minimal ACL string
            return FlextResult[str].ok(
                f"{FlextLdifServersRelaxed.Constants.ACL_WRITE_PREFIX}{acl_data.name or FlextLdifServersRelaxed.Constants.ACL_DEFAULT_NAME}",
            )

        def can_handle_attribute(
            self,
            attribute: FlextLdifModels.SchemaAttribute,
        ) -> bool:
            """Check if this ACL quirk should be aware of a specific attribute definition.

            Relaxed mode accepts all attributes.

            Args:
                attribute: The SchemaAttribute model to check (unused - relaxed accepts all).

            Returns:
                True - relaxed mode accepts everything

            """
            _ = attribute  # Relaxed mode accepts all, parameter not used
            return True

        def can_handle_objectclass(
            self,
            objectclass: FlextLdifModels.SchemaObjectClass,
        ) -> bool:
            """Check if this ACL quirk should be aware of a specific objectClass definition.

            Relaxed mode accepts all objectClasses.

            Args:
                objectclass: The SchemaObjectClass model to check.

            Returns:
                True - relaxed mode accepts everything

            """
            _ = objectclass
            return True

    class Entry(FlextLdifServersRfc.Entry):
        """Relaxed entry quirk for lenient LDIF processing.

        Implements minimal validation for LDIF entries.
        Accepts any entry format in relaxed mode.

        **Priority**: 200 (very low - last resort)
        """

        # OVERRIDDEN METHODS (from FlextLdifServersBase.Entry)
        # These methods override the base class with relaxed/lenient logic:
        # - can_handle(): Accepts any entry in relaxed mode
        # - process_entry(): Pass-through processing for relaxed mode

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
            # In relaxed mode, pass through entry unchanged
            return FlextResult[FlextLdifModels.Entry].ok(entry)

        def can_handle(
            self,
            entry_dn: str,
            attributes: Mapping[str, object],
        ) -> bool:
            """Accept any entry in relaxed mode.

            Args:
                entry_dn: Entry distinguished name
                attributes: Entry attributes

            Returns:
                Always True - relaxed mode accepts everything

            """
            _ = entry_dn
            _ = attributes
            return True

        def _parse_entry(
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
            # Try parent's _parse_entry first
            parent_result = super()._parse_entry(entry_dn, entry_attrs)
            if parent_result.is_success:
                return parent_result

            # Best-effort: create Entry with raw data if RFC parsing fails
            logger.debug(
                "RFC entry parse failed, using relaxed mode: %s",
                parent_result.error,
            )
            try:
                # Validate DN
                if not entry_dn or not entry_dn.strip():
                    return FlextResult[FlextLdifModels.Entry].fail(
                        "Entry DN cannot be empty",
                    )

                effective_dn = FlextLdifModels.DistinguishedName(value=entry_dn.strip())

                # Convert attributes dict to LdifAttributes if needed
                if isinstance(entry_attrs, FlextLdifModels.LdifAttributes):
                    ldif_attrs = entry_attrs
                else:
                    # Create LdifAttributes from dict - convert values to lists if needed
                    attr_dict: dict[str, list[str]] = {}
                    for key, value in entry_attrs.items():
                        if isinstance(value, list):
                            attr_dict[str(key)] = [
                                (
                                    v.decode(
                                        FlextLdifServersRelaxed.Constants.ENCODING_UTF8,
                                        errors=FlextLdifServersRelaxed.Constants.ENCODING_ERROR_HANDLING,
                                    )
                                    if isinstance(v, bytes)
                                    else str(v)
                                )
                                for v in value
                            ]
                        elif isinstance(value, bytes):
                            attr_dict[str(key)] = [
                                value.decode(
                                    FlextLdifServersRelaxed.Constants.ENCODING_UTF8,
                                    errors=FlextLdifServersRelaxed.Constants.ENCODING_ERROR_HANDLING,
                                ),
                            ]
                        else:
                            attr_dict[str(key)] = [str(value)]
                    ldif_attrs = FlextLdifModels.LdifAttributes(attributes=attr_dict)

                entry = FlextLdifModels.Entry(
                    dn=effective_dn,
                    attributes=ldif_attrs,
                )
                return FlextResult[FlextLdifModels.Entry].ok(entry)
            except Exception as e:
                logger.debug("Relaxed entry creation failed: %s", e)
                return FlextResult[FlextLdifModels.Entry].fail(
                    f"Failed to parse entry: {e}",
                )

        def _parse_content(
            self,
            ldif_content: str,
        ) -> FlextResult[list[FlextLdifModels.Entry]]:
            """Parse raw LDIF content string into Entry models (internal).

            Override RFC implementation with relaxed mode fallback for broken LDIF.

            Args:
                ldif_content: Raw LDIF content as string

            Returns:
                FlextResult with list of parsed Entry objects

            """
            # Always try parent's _parse_content first (RFC format)
            parent_result = super()._parse_content(ldif_content)
            if parent_result.is_success:
                return parent_result

            # RFC parser failed - use relaxed mode parsing
            logger.debug("RFC parser failed, using relaxed mode")
            try:
                entries: list[FlextLdifModels.Entry] = []

                # Handle empty/whitespace-only content gracefully
                if not ldif_content.strip():
                    return FlextResult[list[FlextLdifModels.Entry]].ok(entries)

                # Use shared RFC 2849-compliant LDIF parser
                parsed_entries = FlextLdifUtilities.Parser.parse_ldif_lines(
                    ldif_content,
                )

                # Convert parsed (dn, attrs) tuples to Entry models
                for dn, attrs in parsed_entries:
                    entry_result = self._parse_entry(dn, attrs)
                    if entry_result.is_success:
                        entries.append(entry_result.unwrap())

                return FlextResult[list[FlextLdifModels.Entry]].ok(entries)

            except (ValueError, TypeError, AttributeError, OSError, Exception) as e:
                logger.debug("Relaxed LDIF content parse failed: %s", e)
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    f"Failed to parse LDIF content: {e}",
                )

        def _write_entry(
            self,
            entry_data: FlextLdifModels.Entry,
        ) -> FlextResult[str]:
            """Write Entry model to RFC-compliant LDIF string format (internal).

            Override RFC implementation with relaxed mode fallback for broken entries.

            Args:
                entry_data: Entry model to write

            Returns:
                FlextResult with RFC-compliant LDIF string

            """
            # Always try parent's write method first (RFC format)
            parent_result = super()._write_entry(entry_data)
            if parent_result.is_success:
                return parent_result

            # RFC write failed - use relaxed mode
            logger.debug("RFC write failed, using relaxed mode")
            try:
                # Build LDIF string from Entry model
                ldif_lines: list[str] = []

                # DN line (required)
                if not entry_data.dn or not entry_data.dn.value:
                    return FlextResult[str].fail("Entry DN is required for LDIF output")
                ldif_lines.append(
                    f"{FlextLdifServersRelaxed.Constants.LDIF_DN_PREFIX}{entry_data.dn.value}",
                )

                # Attributes
                if entry_data.attributes and entry_data.attributes.attributes:
                    for (
                        attr_name,
                        attr_values,
                    ) in entry_data.attributes.attributes.items():
                        if isinstance(attr_values, list):
                            ldif_lines.extend(
                                f"{attr_name}{FlextLdifServersRelaxed.Constants.LDIF_ATTR_SEPARATOR}{value}"
                                for value in attr_values
                            )
                        else:
                            ldif_lines.append(
                                f"{attr_name}{FlextLdifServersRelaxed.Constants.LDIF_ATTR_SEPARATOR}{attr_values}",
                            )

                # Join with newlines and ensure proper LDIF formatting
                ldif_text = FlextLdifServersRelaxed.Constants.LDIF_JOIN_SEPARATOR.join(
                    ldif_lines,
                )
                if ldif_text and not ldif_text.endswith(
                    FlextLdifServersRelaxed.Constants.LDIF_NEWLINE,
                ):
                    ldif_text += FlextLdifServersRelaxed.Constants.LDIF_NEWLINE

                return FlextResult[str].ok(ldif_text)

            except Exception as e:
                logger.debug("Write entry failed: %s", e)
                return FlextResult[str].fail(f"Failed to write entry: {e}")

        def can_handle_attribute(
            self,
            attribute: FlextLdifModels.SchemaAttribute,
        ) -> bool:
            """Check if this Entry quirk has special handling for an attribute definition.

            Relaxed mode accepts all attributes.

            Args:
                attribute: The SchemaAttribute model to check.

            Returns:
                True - relaxed mode accepts everything

            """
            _ = attribute
            return True

        def can_handle_objectclass(
            self,
            objectclass: FlextLdifModels.SchemaObjectClass,
        ) -> bool:
            """Check if this Entry quirk has special handling for an objectClass definition.

            Relaxed mode accepts all objectClasses.

            Args:
                objectclass: The SchemaObjectClass model to check.

            Returns:
                True - relaxed mode accepts everything

            """
            _ = objectclass
            return True

        def normalize_dn(self, dn: str) -> FlextResult[str]:
            """Normalize DN using RFC 4514 compliant utility.

            Uses utility DN normalization (RFC 4514 compliant).
            Returns error if normalization fails - no fallbacks.

            Args:
                dn: Distinguished name

            Returns:
                FlextResult with normalized DN or error

            """
            if not dn or not dn.strip():
                return FlextResult[str].fail("DN cannot be empty")
            try:
                # Use RFC 4514 compliant utility normalization
                normalized = FlextLdifUtilities.DN.norm(dn)
                if normalized:
                    return FlextResult[str].ok(normalized)
                # No fallback - return error if normalization fails
                return FlextResult[str].fail(f"DN normalization failed for DN: {dn}")
            except Exception as e:
                logger.debug("DN normalization exception: %s", e)
                return FlextResult[str].fail(f"DN normalization failed: {e}")


__all__ = [
    "FlextLdifServersRelaxed",
]
