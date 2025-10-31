"""Oracle Unified Directory (OUD) Quirks.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Provides OUD-specific quirks for schema, ACL, and entry processing.
"""

from __future__ import annotations

import re
from typing import Any, ClassVar

from flext_core import FlextLogger, FlextResult

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.servers.rfc import FlextLdifServersRfc
from flext_ldif.typings import FlextLdifTypes
from flext_ldif.utilities import FlextLdifUtilities

logger = FlextLogger(__name__)


class FlextLdifServersOud(FlextLdifServersRfc):
    """Oracle Unified Directory (OUD) Quirks."""

    # Top-level configuration - mirrors Schema class for direct access
    server_type = FlextLdifConstants.ServerTypes.OUD
    priority = 10

    class AttributeWriter(FlextLdifServersRfc.AttributeWriter):
        """OUD-specific attribute writer."""

    class ObjectClassWriter(FlextLdifServersRfc.ObjectClassWriter):
        """OUD-specific object class writer."""

        def _transform_objectclass_for_write(
            self,
            oc_data: FlextLdifModels.SchemaObjectClass,
        ) -> FlextLdifModels.SchemaObjectClass:
            """Fix illegal characters in MUST/MAY attribute names for OUD."""
            if oc_data.must:
                oc_data.must = [a.replace("_", "-") for a in oc_data.must]
            if oc_data.may:
                oc_data.may = [a.replace("_", "-") for a in oc_data.may]
            return oc_data

    class AttributeParser(FlextLdifServersRfc.AttributeParser):
        """OUD-specific attribute parser."""

        @staticmethod
        def parse_common(
            attr_definition: str,
            *,
            case_insensitive: bool = False,
            allow_syntax_quotes: bool = False,
        ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
            """Parse OUD attribute, then apply OUD-specific modifications."""
            # Use the base class's parse_common method directly
            result = FlextLdifServersRfc.AttributeParser.parse_common(
                attr_definition,
                case_insensitive=case_insensitive,
                allow_syntax_quotes=allow_syntax_quotes,
            )

            if result.is_failure:
                return result

            attribute = result.unwrap()

            # OUD-specific: OUD doesn't use the USAGE field.
            attribute.usage = None

            # Set quirk type to OUD
            if attribute.metadata:
                attribute.metadata.quirk_type = FlextLdifConstants.ServerTypes.OUD
            else:
                attribute.metadata = FlextLdifModels.QuirkMetadata(
                    quirk_type=FlextLdifConstants.ServerTypes.OUD
                )

            return FlextResult.ok(attribute)

    class ObjectClassParser(FlextLdifServersRfc.ObjectClassParser):
        """OUD-specific object class parser."""

        @classmethod
        def parse_common(
            cls,
            oc_definition: str,
            *,
            case_insensitive: bool = False,
        ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
            """Parse OUD object class, then apply OUD-specific modifications."""
            # Use the base class's parse_common method directly
            result = FlextLdifServersRfc.ObjectClassParser.parse_common(
                oc_definition,
                case_insensitive=case_insensitive,
            )

            if result.is_failure:
                return result

            objectclass = result.unwrap()

            # Set quirk type to OUD
            if objectclass.metadata:
                objectclass.metadata.quirk_type = FlextLdifConstants.ServerTypes.OUD
            else:
                objectclass.metadata = FlextLdifModels.QuirkMetadata(
                    quirk_type=FlextLdifConstants.ServerTypes.OUD
                )

            return FlextResult.ok(objectclass)

    class Schema(FlextLdifServersRfc.Schema):
        """Oracle OUD schema quirk - implements FlextLdifProtocols.Quirks.SchemaProtocol.

        Extends RFC 4512 schema parsing with Oracle OUD-specific features:
        - OUD namespace (2.16.840.1.113894.*)
        - OUD-specific syntaxes
        - OUD attribute extensions
        - Compatibility with OID schemas
        - DN case registry management for schema consistency

        **Protocol Compliance**: Fully implements
        FlextLdifProtocols.Quirks.SchemaProtocol through structural typing.
        All methods match protocol signatures exactly for type safety.

        **Validation**: Verify protocol compliance with:
            from flext_ldif.protocols import FlextLdifProtocols
            quirk = FlextLdifServersOud()
            assert isinstance(quirk, FlextLdifProtocols.Quirks.SchemaProtocol)

        Example:
            quirk = FlextLdifServersOud(server_type="oracle_oud")
            if quirk.can_handle_attribute(attr_def):
                result = quirk.parse_attribute(attr_def)
                if result.is_success:
                    parsed_attr = result.unwrap()

        """

        server_type: ClassVar[str] = FlextLdifConstants.ServerTypes.OUD
        priority: ClassVar[int] = 10
        ORACLE_OUD_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
            r"2\.16\.840\.1\.113894\.",
        )
        BOOLEAN_ATTRIBUTES: ClassVar[frozenset[str]] = (
            FlextLdifConstants.OperationalAttributes.OUD_BOOLEAN_ATTRIBUTES
        )

        @staticmethod
        def _normalize_server_type_for_literal(
            server_type: str,
        ) -> FlextLdifConstants.LiteralTypes.ServerType:
            """Normalize server type to literal-compatible form.

            Converts short-form identifiers (oid, oud) to long-form (oracle_oid, oracle_oud).
            Other types are returned as-is.

            Args:
                server_type: Server type identifier

            Returns:
                Normalized server type for LiteralTypes.ServerType

            """
            server_type_map: dict[str, FlextLdifConstants.LiteralTypes.ServerType] = {
                "oid": "oracle_oid",
                "oud": "oracle_oud",
            }

            # Return mapped type or default to "rfc" if not in map
            # "rfc" is a valid ServerType literal, though type checker may need assistance
            mapped = server_type_map.get(server_type)
            return mapped if mapped is not None else "rfc"

        def __init__(
            self,
        ) -> None:
            """Initialize OUD schema quirk and nested ACL quirk."""
            super().__init__()
            # Instantiate nested ACL quirk for conversion matrix access
            self.acl = FlextLdifServersOud.Acl()

        def can_handle_attribute(
            self, attribute: str | FlextLdifModels.SchemaAttribute
        ) -> bool:
            """Check if attribute should be handled with OUD-specific quirks.

            Detects OUD-specific attributes and patterns:
            - X-ORIGIN extension (OUD metadata)
            - pwdPolicy* attributes (OUD password policy)
            - ds-* attributes (OUD directory service attributes)
            - OUD operational attributes

            Acts as a fallback handler for Oracle Unified Directory entries.
            Returns False for namespace-specific attributes (OID, OpenLDAP, etc.)
            to allow other quirks to handle them first.

            Args:
                attribute: SchemaAttribute model or definition string

            Returns:
                True if attribute should be handled with OUD-specific logic

            """
            if isinstance(attribute, FlextLdifModels.SchemaAttribute):
                attr_def = self.write_attribute_to_rfc(attribute).unwrap_or("")
            elif isinstance(attribute, str):
                attr_def = attribute
            else:
                return False

            attr_lower = attr_def.lower()
            return any(
                keyword in attr_lower
                for keyword in ["pwd", "ds-", "x-origin", "2.16.840.1.113894"]
            )

        # --------------------------------------------------------------------- #
        # Schema parsing and conversion methods
        # --------------------------------------------------------------------- #
        # --------------------------------------------------------------------- #
        # OVERRIDDEN METHODS (from FlextLdifServersBase.Schema)
        # --------------------------------------------------------------------- #
        # These methods override the base class with Oracle OUD-specific logic:
        # - parse_attribute(): Custom parsing logic for Oracle OUD schema
        # - parse_objectclass(): Custom parsing logic for Oracle OUD schema
        # - convert_attribute_to_rfc(): Strips OUD-specific metadata
        # - convert_objectclass_to_rfc(): Strips OUD-specific metadata
        # - convert_attribute_from_rfc(): Adds OUD-specific metadata
        # - convert_objectclass_from_rfc(): Adds OUD-specific metadata
        # - write_attribute_to_rfc(): Uses RFC writer with OUD error handling
        # - write_objectclass_to_rfc(): Uses RFC writer with OUD error handling
        # - should_filter_out_attribute(): Returns False (accept all in OUD mode)
        # - should_filter_out_objectclass(): Returns False (accept all in OUD mode)
        # - create_quirk_metadata(): Creates OUD-specific metadata

        def parse_attribute(
            self,
            attr_definition: str,
        ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
            """Parse Oracle OUD attribute definition using the OUD parser."""
            try:
                # Use OUD-specific parser which will handle extensions via hooks
                return FlextLdifServersOud.AttributeParser.parse_common(
                    attr_definition,
                    case_insensitive=False,  # OUD uses strict RFC-compliant NAME matching
                    allow_syntax_quotes=False,  # OUD uses standard SYNTAX format
                )
            except Exception as e:
                return FlextResult[FlextLdifModels.SchemaAttribute].fail(
                    f"OUD attribute parsing failed: {e}",
                )

        def can_handle_objectclass(
            self, objectclass: str | FlextLdifModels.SchemaObjectClass
        ) -> bool:
            """Check if objectClass should be handled with OUD-specific quirks.

            Detects OUD-specific objectClasses and patterns:
            - X-ORIGIN extension (OUD metadata)
            - ds-cfg-* objectClasses (OUD configuration classes)
            - pwdPolicy-related classes (OUD password policy)
            - OUD operational objectClasses

            Acts as a fallback handler for Oracle Unified Directory entries.
            Returns False for namespace-specific objectClasses (OID, OpenLDAP, etc.)
            to allow other quirks to handle them first.

            Args:
                objectclass: ObjectClass definition string

            Returns:
                True if objectClass should be handled with OUD-specific logic

            """
            if isinstance(objectclass, FlextLdifModels.SchemaObjectClass):
                oc_def = self.write_objectclass_to_rfc(objectclass).unwrap_or("")
            elif isinstance(objectclass, str):
                oc_def = objectclass
            else:
                return False

            oc_lower = oc_def.lower()
            return any(
                keyword in oc_lower
                for keyword in ["ds-cfg-", "pwd", "x-origin", "2.16.840.1.113894"]
            )

        def parse_objectclass(
            self,
            oc_definition: str,
        ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
            """Parse Oracle OUD objectClass definition using the OUD parser."""
            try:
                # Use OUD-specific parser which will handle extensions via hooks
                return FlextLdifServersOud.ObjectClassParser.parse_common(
                    oc_definition,
                    case_insensitive=False,  # OUD uses strict RFC-compliant NAME matching
                )
            except Exception as e:
                return FlextResult[FlextLdifModels.SchemaObjectClass].fail(
                    f"OUD objectClass parsing failed: {e}",
                )

        def validate_objectclass_dependencies(
            self,
            oc_data: FlextLdifModels.SchemaObjectClass,
            available_attributes: set[str],
        ) -> FlextResult[bool]:
            """Validate that all MUST and MAY attributes for objectclass exist in schema.

            Checks if all required (MUST) and optional (MAY) attributes referenced by an
            objectclass definition are available in the provided set of available attributes.
            This prevents schema corruption when objectclasses with missing attributes are
            loaded into OUD.

            CRITICAL: Also validates attributes from parent objectclasses (SUP) to ensure
            inheritance chains are valid.

            Args:
                oc_data: Parsed objectclass Pydantic model with must, may fields
                available_attributes: Set of attribute names (lowercase) in current schema

            Returns:
                FlextResult[bool]:
                    - True if all attributes are available or no attributes required
                    - False if any MUST/MAY attribute is missing

            Example:
                >>> oc_data = FlextLdifModels.SchemaObjectClass(
                ...     oid="1.2.3.4",
                ...     name="orclDbServer",
                ...     must=[],
                ...     may=["orcladminprivilege"],
                ... )
                >>> available = {"cn", "description"}  # orcladminprivilege missing!
                >>> result = quirk.validate_objectclass_dependencies(oc_data, available)
                >>> # result.is_success and not result.unwrap() → False (missing attribute)

            """
            oc_name = str(oc_data.name) if oc_data.name else "unknown"
            oc_oid = str(oc_data.oid) if oc_data.oid else "unknown"
            missing_attrs: list[str] = []

            # PHASE 1: Check MUST attributes (required - failure if missing)
            must_attrs = oc_data.must
            if must_attrs:
                must_list: list[str] = (
                    must_attrs if isinstance(must_attrs, list) else [str(must_attrs)]
                )
                for attr in must_list:
                    attr_lower = str(attr).lower()
                    if attr_lower not in available_attributes:
                        missing_attrs.append(str(attr))

            # PHASE 2: Check MAY attributes (optional - failure if missing)
            # CRITICAL FIX: MAY attributes MUST also be present in schema
            # Missing MAY attributes cause: "No attribute type matching this name or OID exists"
            may_attrs = oc_data.may
            if may_attrs:
                may_list: list[str] = (
                    may_attrs if isinstance(may_attrs, list) else [str(may_attrs)]
                )
                for attr in may_list:
                    attr_lower = str(attr).lower()
                    if attr_lower not in available_attributes:
                        missing_attrs.append(str(attr))

            # Report validation failure if any attributes missing
            if missing_attrs:
                logger.warning(
                    f"ObjectClass '{oc_name}' (OID {oc_oid}) "
                    f"has unresolved attributes (MUST/MAY): {', '.join(missing_attrs)}. "
                    f"This objectclass will be filtered out to prevent OUD startup failure: "
                    f'"No attribute type matching this name or OID exists in the server schema"',
                )
                return FlextResult[bool].ok(False)

            # All MUST and MAY attributes are available
            return FlextResult[bool].ok(True)

        def convert_attribute_to_rfc(
            self,
            attr_data: FlextLdifModels.SchemaAttribute,
        ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
            """Convert OUD attribute to RFC-compliant format.

            OUD attributes are already RFC-compliant, so pass through.

            Args:
            attr_data: OUD attribute data

            Returns:
            FlextResult with RFC-compliant attribute data (same model)

            """
            # OUD attributes are RFC-compliant - return as-is
            return FlextResult[FlextLdifModels.SchemaAttribute].ok(attr_data)

        def convert_objectclass_to_rfc(
            self,
            oc_data: FlextLdifModels.SchemaObjectClass,
        ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
            """Convert OUD objectClass to RFC-compliant format.

            OUD objectClasses are already RFC-compliant, so pass through.

            Args:
            oc_data: OUD objectClass data

            Returns:
            FlextResult with RFC-compliant objectClass data (same model)

            """
            # OUD objectClasses are RFC-compliant - return as-is
            return FlextResult[FlextLdifModels.SchemaObjectClass].ok(oc_data)

        def write_attribute_to_rfc(
            self,
            attr_data: FlextLdifModels.SchemaAttribute,
        ) -> FlextResult[str]:
            """Write OUD attribute data to RFC 4512 compliant string format."""
            try:
                # Use OUD-specific writer
                writer = FlextLdifServersOud.AttributeWriter()
                return writer.write_common(attr_data)
            except Exception as e:
                return FlextResult[str].fail(f"Failed to write attribute to RFC: {e}")

        def write_objectclass_to_rfc(
            self,
            oc_data: FlextLdifModels.SchemaObjectClass,
        ) -> FlextResult[str]:
            """Write OUD objectClass data to RFC 4512 compliant string format."""
            try:
                # Use OUD-specific writer
                writer = FlextLdifServersOud.ObjectClassWriter()
                return writer.write_common(oc_data)
            except Exception as e:
                return FlextResult[str].fail(f"Failed to write objectClass to RFC: {e}")

        def convert_attribute_from_rfc(
            self,
            rfc_data: FlextLdifModels.SchemaAttribute,
        ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
            """Convert RFC-compliant attribute to OUD-specific format.

            Args:
            rfc_data: RFC-compliant attribute data

            Returns:
            FlextResult with OUD attribute data

            """
            try:
                # Oracle OUD uses RFC-compliant schema format
                # Set OUD server type in metadata
                if rfc_data.metadata:
                    # Update existing metadata
                    oud_data = rfc_data.model_copy(
                        update={
                            "metadata": rfc_data.metadata.model_copy(
                                update={
                                    "server_type": FlextLdifConstants.LdapServers.ORACLE_OUD,
                                },
                            ),
                        },
                    )
                else:
                    # Create new metadata with OUD server type
                    oud_data = rfc_data.model_copy(
                        update={
                            "metadata": FlextLdifModels.QuirkMetadata(
                                quirk_type=FlextLdifConstants.LdapServers.ORACLE_OUD,
                            ),
                        },
                    )

                return FlextResult[FlextLdifModels.SchemaAttribute].ok(oud_data)

            except Exception as e:
                return FlextResult[FlextLdifModels.SchemaAttribute].fail(
                    f"RFC→OUD attribute conversion failed: {e}",
                )

        def convert_objectclass_from_rfc(
            self,
            rfc_data: FlextLdifModels.SchemaObjectClass,
        ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
            """Convert RFC-compliant objectClass to OUD-specific format.

            Applies OUD-specific transformations:
            - Fixes broken OID schema definitions (missing SUP for AUXILIARY classes)
            - OUD requires AUXILIARY classes to have explicit SUP clause

            Args:
            rfc_data: RFC-compliant objectClass model

            Returns:
            FlextResult with OUD objectClass model

            """
            try:
                # Check if we need to fix missing SUP for AUXILIARY objectClasses
                # OUD requires AUXILIARY classes to have explicit SUP clause
                if (
                    not rfc_data.sup
                    and rfc_data.kind == FlextLdifConstants.Schema.AUXILIARY
                ):
                    name_lower = rfc_data.name.lower()
                    auxiliary_without_sup = {
                        "orcldAsAttrCategory".lower(),
                        "orcldasconfigpublicgroup",
                    }

                    if name_lower in auxiliary_without_sup:
                        # Create new model with sup="top"
                        oud_data = rfc_data.model_copy(update={"sup": "top"})
                        logger.debug(
                            f"Fixed missing SUP for AUXILIARY class {rfc_data.name}",
                        )
                        return FlextResult[FlextLdifModels.SchemaObjectClass].ok(
                            oud_data,
                        )

                # No modifications needed - return as-is
                return FlextResult[FlextLdifModels.SchemaObjectClass].ok(rfc_data)

            except Exception as e:
                return FlextResult[FlextLdifModels.SchemaObjectClass].fail(
                    f"RFC→OUD objectClass conversion failed: {e}",
                )

        def extract_schemas_from_ldif(
            self,
            ldif_content: str,
        ) -> FlextResult[FlextLdifTypes.Models.EntryAttributesDict]:
            """Extract and parse all schema definitions from LDIF content.

            Strategy pattern: OUD-specific approach to extract attributeTypes
            and objectClasses from cn=schema LDIF entries, handling OUD's
            case variations.

            Filters only Oracle internal objectClasses that OUD already provides built-in.
            All custom objectClasses pass through, including those with unresolved
            dependencies (OUD will validate at startup).

            Args:
                ldif_content: Raw LDIF content containing schema definitions

            Returns:
                FlextResult with dict containing ATTRIBUTES and
                objectclasses lists (filtered only for Oracle internal classes)

            """
            try:
                objectclasses_parsed: list[FlextLdifModels.SchemaObjectClass] = []

                # PHASE 1: Extract all attributeTypes first using shared extractor
                attributes_parsed = (
                    FlextLdifServersRfc.SchemaExtractor.extract_attributes_from_lines(
                        ldif_content,
                        self.parse_attribute,
                    )
                )

                # Build set of available attribute names (lowercase) for dependency validation
                available_attributes: set[str] = set()
                for attr_data in attributes_parsed:
                    if isinstance(
                        attr_data,
                        FlextLdifModels.SchemaAttribute,
                    ) and hasattr(attr_data, "name"):
                        attr_name = str(attr_data.name).lower()
                        available_attributes.add(attr_name)

                # PHASE 2: Extract objectClasses with dependency validation using shared extractor
                # Must happen AFTER all attributes are collected
                objectclasses_raw_data = FlextLdifServersRfc.SchemaExtractor.extract_objectclasses_from_lines(
                    ldif_content,
                    self.parse_objectclass,
                )

                # PHASE 3: Pass all objectClasses through to migration service
                objectclasses_parsed.extend(objectclasses_raw_data)

                return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].ok({
                    FlextLdifConstants.DictKeys.ATTRIBUTES: attributes_parsed,
                    "objectclasses": objectclasses_parsed,
                })

            except Exception as e:
                return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].fail(
                    f"OUD schema extraction failed: {e}",
                )

    class Acl(FlextLdifServersRfc.Acl):
        """Oracle OUD ACL quirk (nested).

        Extends RFC ACL parsing with Oracle OUD-specific ACL formats:
        - ds-cfg-access-control-handler: OUD access control
        - OUD-specific ACL syntax (different from OID orclaci)

        Example:
            quirk = FlextLdifServersOud.Acl(server_type="oracle_oud")
            if quirk.can_handle_acl(acl_line):
                result = quirk.parse_acl(acl_line)

        """

        # OVERRIDE: Oracle OUD uses RFC 4876 compliant "aci" for ACL attribute names (not inherited)
        acl_attribute_name = FlextLdifConstants.AclAttributes.ACI

        # --------------------------------------------------------------------- #
        # OVERRIDDEN METHODS (from FlextLdifServersBase.Acl)
        # --------------------------------------------------------------------- #
        # These methods override the base class with Oracle OUD-specific logic:
        # - can_handle_acl(): Detects OUD ACL formats
        # - parse_acl(): Parses Oracle OUD ACL definitions
        # - convert_acl_to_rfc(): Converts to RFC format
        # - convert_acl_from_rfc(): Converts from RFC format
        # - write_acl_to_rfc(): Writes RFC-compliant ACL strings
        # - get_acl_attribute_name(): Returns "aci" (OUD-specific, overridden)

        # Oracle OUD server configuration defaults
        server_type: ClassVar[str] = FlextLdifConstants.ServerTypes.OUD
        priority: ClassVar[int] = 10

        def __init__(self) -> None:
            """Initialize OUD ACL quirk and register conversion hooks."""
            super().__init__()
            # Register OID→OUD specific conversion hooks
            self._register_oid_to_oud_hooks()

        def _register_oid_to_oud_hooks(self) -> None:
            """Register OID→OUD specific conversion hooks with advanced utilities."""
            from flext_ldif.utilities import FlextLdifUtilities

            # Register permission conversion hook for OID→OUD
            def oid_to_oud_permission_hook(
                permissions: list[str], source_server: str, target_server: str
            ) -> tuple[list[str], list[str]]:
                """Convert OID-specific permissions to OUD equivalents."""
                allowed = []
                denied = []

                for perm in permissions:
                    perm_lower = perm.lower()
                    # Use constants for permission names
                    if perm_lower == FlextLdifConstants.PermissionNames.SELF_WRITE.lower():
                        # OUD doesn't support self_write - promote to write
                        allowed.append(FlextLdifConstants.PermissionNames.WRITE)
                    elif perm_lower == FlextLdifConstants.PermissionNames.PROXY.lower():
                        # OUD doesn't support proxy - will be noted in comments
                        denied.append(FlextLdifConstants.PermissionNames.PROXY)
                    elif perm_lower == FlextLdifConstants.PermissionNames.BROWSE.lower():
                        # OID browse maps to read+search in OUD
                        allowed.extend(
                            [
                                FlextLdifConstants.PermissionNames.READ,
                                FlextLdifConstants.PermissionNames.SEARCH,
                            ]
                        )
                    elif perm_lower == "auth":
                        # OID auth maps to compare in OUD
                        allowed.append(FlextLdifConstants.PermissionNames.COMPARE)
                    elif perm_lower in {
                        FlextLdifConstants.PermissionNames.READ.lower(),
                        FlextLdifConstants.PermissionNames.WRITE.lower(),
                        FlextLdifConstants.PermissionNames.ADD.lower(),
                        FlextLdifConstants.PermissionNames.DELETE.lower(),
                        FlextLdifConstants.PermissionNames.SEARCH.lower(),
                        FlextLdifConstants.PermissionNames.COMPARE.lower(),
                    }:
                        # Standard permissions are preserved
                        allowed.append(perm_lower)

                return allowed, denied

            FlextLdifUtilities.AclConverter.register_permission_hook(
                "oracle_oid", "oracle_oud", oid_to_oud_permission_hook
            )

            # Register comment generation hook for OID→OUD
            def oid_to_oud_comment_hook(
                metadata_info: dict[str, Any], source_server: str, target_server: str
            ) -> list[str]:
                """Generate OID→OUD specific conversion comments."""
                comments = []
                extensions = metadata_info.get("extensions", {})

                # Add OID-specific feature comments
                if extensions.get("filter_clause"):
                    comments.append(
                        f"# OID filter clause: {extensions['filter_clause']}"
                    )

                if extensions.get("added_object_constraint"):
                    constraint = extensions["added_object_constraint"]
                    comments.append(f"# OID entry-level constraint: {constraint}")

                    # Check if convertible to OUD targattrfilters
                    if constraint.startswith("objectClass="):
                        comments.append("# Converted to OUD targattrfilters")
                    else:
                        comments.append("# Complex constraint preserved as comment")

                if "multi_subject_blocks" in extensions:
                    blocks = extensions["multi_subject_blocks"]
                    if isinstance(blocks, list) and len(blocks) > 1:
                        comments.append(
                            f"# OID multi-subject ACL with {len(blocks)} subjects"
                        )

                return comments

            FlextLdifUtilities.AclConverter.register_comment_hook(
                "oracle_oid", "oracle_oud", oid_to_oud_comment_hook
            )

            # Register conversion hook for OID→OUD specific metadata
            def oid_to_oud_conversion_hook(
                acl_data: FlextLdifModels.Acl, source_server: str, target_server: str
            ) -> FlextResult[FlextLdifModels.Acl]:
                """Custom OID→OUD conversion that sets expected metadata keys."""
                # Use the built-in conversion
                builtin_result = FlextLdifUtilities.AclConverter._convert_acl_builtin(
                    acl_data, source_server, target_server
                )

                if builtin_result.is_success:
                    converted_acl = builtin_result.unwrap()

                    # Add OUD-specific metadata extensions
                    if converted_acl.metadata and converted_acl.metadata.extensions:
                        extensions = converted_acl.metadata.extensions.copy()

                        # Add OUD-specific keys expected by tests
                        extensions["converted_from_oid"] = True
                        extensions["oud_conversion_comments"] = extensions.get(
                            "conversion_comments", []
                        )

                        # Update metadata with OUD-specific extensions
                        updated_metadata = converted_acl.metadata.model_copy(
                            update={"extensions": extensions}
                        )

                        # Return ACL with updated metadata
                        return FlextResult.ok(
                            converted_acl.model_copy(
                                update={"metadata": updated_metadata}
                            )
                        )

                return builtin_result

            FlextLdifUtilities.AclConverter.register_conversion_hook(
                "oracle_oid", "oracle_oud", oid_to_oud_conversion_hook
            )

        def can_handle_acl(self, acl: FlextLdifModels.Acl | str) -> bool:
            """Check if this is an Oracle OUD ACL.

            Args:
            acl: ACL definition model or string

            Returns:
            True if this is OUD ACL format

            """
            if isinstance(acl, str):
                # Check if string format looks like OUD ACI format
                return acl.strip().startswith((
                    "targetattr=",
                    "targetscope=",
                    "version 3.0",
                    "ds-cfg-",
                    "aci:",
                ))

            # For model instances, check the raw_acl format
            if hasattr(acl, "raw_acl") and acl.raw_acl:
                return acl.raw_acl.startswith((
                    "ds-cfg-",
                    "aci:",
                    "targetattr=",
                    "targetscope=",
                    "version 3.0",
                ))

            # Fallback to checking server_type or other properties
            return getattr(acl, "server_type", "") in {"oracle_oud", "rfc", ""}

        def parse_acl(self, acl_line: str) -> FlextResult[FlextLdifModels.Acl]:
            """Parse Oracle OUD ACL definition to Pydantic model.

            Parses ACI (Access Control Instruction) format used by OUD, extracting:
            - targetattr: Target attributes
            - targetscope: Target scope (base, onelevel, subtree)
            - version: ACI version
            - acl_name: ACL description name
            - permissions: List of permissions (read, write, search, etc.)
            - bind_rules: Bind rules (userdn, groupdn, etc.)

            Handles complex multi-line ACIs with:
            - Line continuations (multiple allow/deny rules)
            - Varied indentation patterns
            - Spaces after commas in DNs
            - Multiple permission rules per ACI (4+ rules)

            Args:
            acl_line: ACL definition line (may contain newlines for multi-line ACIs)

            Returns:
            FlextResult with OUD ACL Pydantic model

            """
            try:
                # Initialize parsed values
                acl_name = "OUD ACL"
                targetattr = "*"
                targetscope = None
                version = "3.0"
                permissions_list: list[str] = []
                bind_rules_data: list[dict[str, str]] = []
                line_breaks: list[int] = []
                dn_spaces = False

                # Detect line breaks for multi-line ACIs
                if "\n" in acl_line:
                    current_pos = 0
                    for line_num, line in enumerate(acl_line.split("\n")):
                        if line_num > 0:  # Skip first line
                            line_breaks.append(current_pos)
                        current_pos += len(line) + 1  # +1 for newline

                # Parse ACI components if it's ACI format
                if acl_line.startswith("aci:"):
                    aci_content = acl_line.split(":", 1)[1].strip()

                    # Extract targetattr
                    targetattr_match = re.search(
                        r'\(targetattr\s*(!?=)\s*"([^"]+)"\)',
                        aci_content,
                    )
                    if targetattr_match:
                        targetattr = targetattr_match.group(2)

                    # Extract targetscope
                    targetscope_match = re.search(
                        r'\(targetscope\s*=\s*"([^"]+)"\)',
                        aci_content,
                    )
                    if targetscope_match:
                        targetscope = targetscope_match.group(1)

                    # Extract version and ACL name
                    version_match = re.search(
                        r'version\s+([\d.]+);\s*acl\s+"([^"]+)"',
                        aci_content,
                    )
                    if version_match:
                        version = version_match.group(1)
                        acl_name = version_match.group(2)

                    # Extract permissions (allow/deny with operations)
                    permission_matches = re.findall(
                        r"(allow|deny)\s+\(([^)]+)\)",
                        aci_content,
                    )
                    for action, ops in permission_matches:
                        if action == "allow":  # Only process allow rules
                            ops_list = [
                                op.strip() for op in ops.split(",") if op.strip()
                            ]
                            permissions_list.extend(ops_list)

                    # Extract userdn rules
                    userdn_matches = re.findall(r'userdn\s*=\s*"([^"]+)"', aci_content)
                    for userdn in userdn_matches:
                        bind_rules_data.append({"type": "userdn", "value": userdn})
                        if ", " in userdn:
                            dn_spaces = True

                    # Extract groupdn rules
                    groupdn_matches = re.findall(
                        r'groupdn\s*=\s*"([^"]+)"',
                        aci_content,
                    )
                    for groupdn in groupdn_matches:
                        bind_rules_data.append({"type": "groupdn", "value": groupdn})
                        if ", " in groupdn:
                            dn_spaces = True

                # Build AclPermissions from parsed permissions
                permissions_data: dict[str, bool] = {
                    "read": False,
                    "write": False,
                    "add": False,
                    "delete": False,
                    "search": False,
                    "compare": False,
                    "self_write": False,
                    "proxy": False,
                }

                for perm in permissions_list:
                    perm_lower = perm.lower()
                    # Use constants for permission names
                    if perm_lower == FlextLdifConstants.PermissionNames.READ.lower():
                        permissions_data["read"] = True
                    elif perm_lower == FlextLdifConstants.PermissionNames.WRITE.lower():
                        permissions_data["write"] = True
                    elif perm_lower == FlextLdifConstants.PermissionNames.ADD.lower():
                        permissions_data["add"] = True
                    elif perm_lower == FlextLdifConstants.PermissionNames.DELETE.lower():
                        permissions_data["delete"] = True
                    elif perm_lower == FlextLdifConstants.PermissionNames.SEARCH.lower():
                        permissions_data["search"] = True
                    elif perm_lower == FlextLdifConstants.PermissionNames.COMPARE.lower():
                        permissions_data["compare"] = True
                    elif perm_lower in {
                        FlextLdifConstants.PermissionNames.SELFWRITE.lower(),
                        FlextLdifConstants.PermissionNames.SELF_WRITE.lower(),
                    }:
                        permissions_data["self_write"] = True
                    elif perm_lower == FlextLdifConstants.PermissionNames.PROXY.lower():
                        permissions_data["proxy"] = True
                    elif perm_lower == FlextLdifConstants.PermissionNames.ALL.lower():
                        # Enable all permissions
                        for key in permissions_data:
                            permissions_data[key] = True

                # Build AclSubject from first bind rule (OUD can have multiple, take first)
                subject_type = FlextLdifConstants.AclSubjectTypes.ANONYMOUS
                subject_value = "*"

                if bind_rules_data:
                    first_rule = bind_rules_data[0]
                    rule_type = first_rule["type"]
                    rule_value = first_rule["value"]

                    if rule_type == "userdn":
                        if rule_value == "ldap:///self":
                            subject_type = FlextLdifConstants.AclSubjectTypes.SELF
                            subject_value = "ldap:///self"
                        elif rule_value in {"ldap:///*", "ldap:///anyone"}:
                            subject_type = FlextLdifConstants.AclSubjectTypes.ANONYMOUS
                            subject_value = "*"
                        else:
                            subject_type = "bind_rules"
                            subject_value = f'userdn="{rule_value}"'
                    elif rule_type == "groupdn":
                        subject_type = FlextLdifConstants.AclSubjectTypes.GROUP
                        subject_value = rule_value

                # Build QuirkMetadata with extensions
                extensions: dict[str, object] = {}
                if line_breaks:
                    extensions[FlextLdifConstants.MetadataKeys.LINE_BREAKS] = (
                        line_breaks
                    )
                    extensions[FlextLdifConstants.MetadataKeys.IS_MULTILINE] = True
                if dn_spaces:
                    extensions[FlextLdifConstants.MetadataKeys.DN_SPACES] = True
                if targetscope:
                    extensions[FlextLdifConstants.MetadataKeys.TARGETSCOPE] = (
                        targetscope
                    )
                if version != "3.0":
                    extensions[FlextLdifConstants.MetadataKeys.VERSION] = version

                # Create Acl model (no metadata field in unified Acl model)
                # Note: Parsed ACL is converted to generic (RFC) format after parsing OUD-specific format
                acl = FlextLdifModels.Acl(
                    name=acl_name,
                    target=FlextLdifModels.AclTarget(
                        target_dn=targetattr,
                        attributes=[],
                    ),
                    subject=FlextLdifModels.AclSubject(
                        subject_type=subject_type,
                        subject_value=subject_value,
                    ),
                    permissions=FlextLdifModels.AclPermissions(**permissions_data),
                    server_type="generic",
                    raw_acl=acl_line,
                )

                return FlextResult[FlextLdifModels.Acl].ok(acl)

            except Exception as e:
                return FlextResult[FlextLdifModels.Acl].fail(
                    f"OUD ACL parsing failed: {e}",
                )

        def convert_acl_to_rfc(
            self,
            acl_data: FlextLdifModels.Acl,
        ) -> FlextResult[FlextLdifModels.Acl]:
            """Convert OUD ACL to RFC-compliant format with comprehensive OID→OUD transformation.

            **Enhanced OID→OUD Conversion with Zero Data Loss:**
            - Detects OID source via metadata and applies complete transformation
            - Converts OID-specific permissions (self_write, proxy, browse, etc.)
            - Transforms OID subject types (dnattr, guidattr, groupattr)
            - Converts entry-level constraints to OUD targattrfilters
            - Preserves filter clauses as OUD filter expressions where possible
            - Generates comprehensive comments for unconvertible OID features
            - Maintains multi-subject support through comment preservation

            **Conversion Strategy:**
            1. Direct conversion where OUD has equivalent features
            2. Comment preservation for OID-only features
            3. Permission promotion (self_write → write)
            4. Subject transformation (OID dynamic groups → OUD bind rules)
            5. Constraint mapping (added_object_constraint → targattrfilters)

            Args:
                acl_data: ACL model (may be from OID or OUD source)

            Returns:
                FlextResult with RFC-compliant ACL data optimized for OUD with metadata

            """
            try:
                # **Use Advanced Utilities for Comprehensive ACL Conversion**
                # Detect if this is from OID and delegate to advanced conversion system
                metadata = acl_data.metadata
                is_from_oid = metadata and (
                    metadata.quirk_type == FlextLdifConstants.LdapServerType.ORACLE_OID.value
                    or metadata.server_type == FlextLdifConstants.LdapServerType.ORACLE_OID.value
                    or (
                        hasattr(metadata, "extensions")
                        and metadata.extensions
                        and metadata.extensions.get("acl_type")
                        in FlextLdifConstants.AclAttributes.OID_ACL_ATTRS
                    )
                )

                if not is_from_oid:
                    # Native OUD ACL - just set server type and return
                    return FlextResult[FlextLdifModels.Acl].ok(
                        acl_data.model_copy(update={"server_type": "oracle_oud"})
                    )

                # **Delegate to Advanced ACL Converter with Hooks**
                conversion_result = (
                    FlextLdifUtilities.AclConverter.convert_acl_with_hooks(
                        acl_data, "oracle_oid", "oracle_oud"
                    )
                )

                if conversion_result.is_success:
                    return conversion_result

                # **Fallback: Manual OID→OUD Conversion with Advanced Utilities**
                # Extract OID features using advanced metadata processor
                oid_features = (
                    FlextLdifUtilities.MetadataProcessor.extract_oid_features(metadata)
                )

                # Generate comprehensive comments using advanced utilities
                conversion_comments = []

                # Use advanced permission mapping
                converted_permissions = (
                    FlextLdifUtilities.AclConverter.convert_permissions_advanced(
                        acl_data.permissions, "oracle_oid", "oracle_oud"
                    )
                    if acl_data.permissions
                    else None
                )

                # Use advanced subject transformation
                transformed_subject = (
                    FlextLdifUtilities.AclConverter.transform_subject_advanced(
                        acl_data.subject, "oracle_oid", "oracle_oud"
                    )
                    if acl_data.subject
                    else None
                )

                # Generate OID→OUD specific comments
                conversion_comments.extend([
                    "# OID ACL converted to OUD format",
                    f"# Original OID type: {oid_features.get('acl_type', 'orclaci')}",
                ])

                # Add feature-specific comments
                for feature_name, feature_value in oid_features.items():
                    if feature_value and feature_name in {
                        "filter_clause",
                        "added_object_constraint",
                    }:
                        is_convertible = (
                            FlextLdifUtilities.MetadataProcessor.is_feature_convertible(
                                feature_name, feature_value, "oracle_oud"
                            )
                        )
                        if is_convertible:
                            conversion_comments.append(
                                f"# {feature_name} converted to OUD syntax"
                            )
                        else:
                            conversion_comments.append(
                                f"# {feature_name} preserved as comment (not convertible)"
                            )

                # Build comprehensive metadata
                oud_metadata = FlextLdifModels.QuirkMetadata(
                    original_format=metadata.original_format if metadata else "",
                    quirk_type="oud",
                    server_type="oracle_oud",
                    extensions={
                        "converted_from_oid": True,
                        "oud_conversion_comments": conversion_comments,
                        "original_oid_features": oid_features,
                        "conversion_method": "advanced_utilities",
                    },
                )

                # Build final converted ACL
                final_acl = FlextLdifModels.Acl(
                    name=f"Converted from OID: {acl_data.name}",
                    target=acl_data.target,
                    subject=transformed_subject,
                    permissions=converted_permissions,
                    server_type="oracle_oud",
                    raw_acl=acl_data.raw_acl,
                    metadata=oud_metadata,
                )

                return FlextResult[FlextLdifModels.Acl].ok(final_acl)

            except Exception as e:
                return FlextResult[FlextLdifModels.Acl].fail(
                    f"OUD ACL→RFC conversion failed: {e}",
                )

        def _is_filter_convertible_to_oud(self, filter_clause: str) -> bool:
            """Check if OID filter clause can be converted to OUD syntax.

            Args:
                filter_clause: OID filter expression

            Returns:
                True if convertible to OUD, False if needs comment preservation

            """
            if not filter_clause:
                return True

            # Simple equality filters are usually convertible
            # Complex logical operations may need preservation
            complex_operators = ["&", "|", "!", ">=", "<=", "~=", "^="]
            has_complex = any(op in filter_clause for op in complex_operators)

            # Simple single condition filters are convertible
            return bool(not has_complex and "=" in filter_clause)

        def _is_constraint_convertible_to_targattrfilters(
            self, constraint: str
        ) -> bool:
            """Check if OID constraint can be converted to OUD targattrfilters.

            Args:
                constraint: OID added_object_constraint expression

            Returns:
                True if convertible to OUD targattrfilters

            """
            if not constraint:
                return True

            # Simple objectClass constraints are convertible
            # Complex expressions may need comments
            if constraint.startswith("objectClass=") and "=" not in constraint[12:]:
                return True

            # Check for complex operators
            complex_operators = ["&", "|", "!", ">=", "<=", "~="]
            return not any(op in constraint for op in complex_operators)

        def _convert_constraint_to_targattrfilters(self, oid_constraint: str) -> str:
            """Convert OID added_object_constraint to OUD targattrfilters format.

            OID format: added_object_constraint=(objectClass=person)
            OUD format: targattrfilters="add=objectClass:(objectClass=person)"

            Args:
                oid_constraint: OID constraint string

            Returns:
                OUD targattrfilters string

            """
            # Remove outer parentheses if present
            constraint = oid_constraint.strip()
            if constraint.startswith("(") and constraint.endswith(")"):
                constraint = constraint[1:-1]

            # OUD targattrfilters format requires operation prefix
            # add= for added entries, del= for deleted entries
            return f"add=objectClass:({constraint})"

        def convert_acl_from_rfc(
            self,
            acl_data: FlextLdifModels.Acl,
        ) -> FlextResult[FlextLdifModels.Acl]:
            """Convert RFC ACL to OUD format with permission mapping and server type update.

            Args:
                acl_data: RFC-compliant Acl model

            Returns:
                FlextResult with OUD Acl model with proper server type and permission mapping

            """
            try:
                # Create OUD-specific permission mapping
                oud_permissions = {}

                if acl_data.permissions:
                    # Copy all existing permissions
                    oud_permissions = {
                        "read": acl_data.permissions.read,
                        "write": acl_data.permissions.write,
                        "add": acl_data.permissions.add,
                        "delete": acl_data.permissions.delete,
                        "search": acl_data.permissions.search,
                        "compare": acl_data.permissions.compare,
                        "self_write": acl_data.permissions.self_write,
                        "proxy": acl_data.permissions.proxy,
                    }

                    # OUD-specific mapping: self_write → write (if self_write is True)
                    if acl_data.permissions.self_write:
                        oud_permissions["write"] = True

                # Create OUD-specific metadata
                oud_metadata = acl_data.metadata
                if oud_metadata:
                    # Update server type in metadata
                    oud_metadata = oud_metadata.model_copy(update={
                        "server_type": "oracle_oud",
                        "quirk_type": "oracle_oud"
                    })

                # Create the OUD ACL with updated server type and permissions
                oud_acl = acl_data.model_copy(update={
                    "server_type": "oracle_oud",
                    "permissions": FlextLdifModels.AclPermissions(**oud_permissions),
                    "metadata": oud_metadata
                })

                return FlextResult[FlextLdifModels.Acl].ok(oud_acl)

            except Exception as e:
                return FlextResult[FlextLdifModels.Acl].fail(
                    f"RFC→OUD ACL conversion failed: {e}",
                )

        def write_acl_to_rfc(self, acl_data: FlextLdifModels.Acl) -> FlextResult[str]:
            """Write OUD ACL model to ACI string format with OID conversion comment preservation.

            Converts ACL Pydantic model to RFC-compliant ACI format string with comprehensive
            comment generation for OID→OUD conversions to ensure zero data loss.

            Args:
                acl_data: ACL Pydantic model (potentially converted from OID)

            Returns:
                FlextResult with ACI formatted string including conversion comments

            Example:
                Input: FlextLdifModels.Acl(name="Test", ...)
                Output: '(targetattr="*")(version 3.0; acl "Test"; allow (read) userdn="ldap:///self";)'

            """
            try:
                aci_output_lines = []

                # **Generate OID→OUD Conversion Comments**
                if (
                    acl_data.metadata
                    and hasattr(acl_data.metadata, "extensions")
                    and acl_data.metadata.extensions
                ):
                    extensions = acl_data.metadata.extensions

                    # Include conversion comments if this ACL was converted from OID
                    if extensions.get("converted_from_oid"):
                        conversion_comments = extensions.get(
                            "oud_conversion_comments", []
                        )
                        if conversion_comments and isinstance(
                            conversion_comments, list
                        ):
                            aci_output_lines.extend(
                                str(comment) for comment in conversion_comments
                            )
                            aci_output_lines.append("")  # Empty line after comments

                # If raw_acl is available, use it for perfect round-trip
                if acl_data.raw_acl and acl_data.raw_acl.startswith("aci:"):
                    aci_output_lines.append(acl_data.raw_acl)
                    return FlextResult[str].ok("\n".join(aci_output_lines))

                # Build ACI from model fields
                aci_parts = []

                # Target attributes
                if acl_data.target and acl_data.target.target_dn:
                    target = acl_data.target.target_dn
                else:
                    target = "*"
                aci_parts.append(f'(targetattr="{target}")')

                # Version and ACL name
                acl_name = acl_data.name or "OUD ACL"
                aci_parts.append(f'(version 3.0; acl "{acl_name}";')

                # Permissions (from model's permissions computed field)
                # OUD supports: read, write, add, delete, search, compare
                # OUD does NOT support: self_write, proxy (OID-specific)
                if acl_data.permissions:
                    ops_property = acl_data.permissions.permissions
                    # ops_property is a property, call it to get list[str]
                    ops: list[str] = (
                        ops_property() if callable(ops_property) else ops_property
                    )
                    # Filter to only OUD-supported rights
                    oud_supported_rights = {
                        "read",
                        "write",
                        "add",
                        "delete",
                        "search",
                        "compare",
                    }
                    filtered_ops = [op for op in ops if op in oud_supported_rights]

                    # Use metadata bridge: check if self_write needs to be promoted to write
                    # This allows OUD to properly convert OID→OUD without knowing OID format details
                    if (
                        acl_data.metadata
                        and acl_data.metadata.self_write_to_write
                        and "self_write" in ops
                        and "write" not in filtered_ops
                    ):
                        # self_write was present in OID ACL - promote to write for OUD
                        filtered_ops.append("write")

                    if filtered_ops:
                        ops_str = ",".join(filtered_ops)
                        aci_parts.append(f"allow ({ops_str})")
                    else:
                        return FlextResult[str].fail(
                            "ACL model has no OUD-supported permissions (all were OID-specific like self_write)",
                        )
                else:
                    return FlextResult[str].fail("ACL model has no permissions object")

                # Bind rules (from model's subject field)
                if acl_data.subject:
                    subject_type = acl_data.subject.subject_type
                    subject_value = acl_data.subject.subject_value

                    # Convert to RFC format
                    if subject_type == FlextLdifConstants.AclSubjectTypes.SELF:
                        aci_parts.append('userdn="ldap:///self";)')
                    elif subject_type == FlextLdifConstants.AclSubjectTypes.ANONYMOUS:
                        aci_parts.append('userdn="ldap:///*";)')
                    elif subject_type == FlextLdifConstants.AclSubjectTypes.GROUP:
                        # Ensure LDAP URL format
                        if not subject_value.startswith("ldap:///"):
                            subject_value = f"ldap:///{subject_value}"
                        aci_parts.append(f'groupdn="{subject_value}";)')
                    elif subject_type == "bind_rules":
                        # Already in proper format (e.g., userattr="manager#LDAPURL")
                        aci_parts.append(f"{subject_value};)")
                    else:
                        # Default: treat as userdn
                        if not subject_value.startswith("ldap:///"):
                            subject_value = f"ldap:///{subject_value}"
                        aci_parts.append(f'userdn="{subject_value}";)')
                else:
                    # Default: allow for self
                    aci_parts.append('userdn="ldap:///self";)')

                aci_string = "aci: " + " ".join(aci_parts)
                aci_output_lines.append(aci_string)

                return FlextResult[str].ok("\n".join(aci_output_lines))

            except Exception as e:
                return FlextResult[str].fail(f"Failed to write ACL to RFC: {e}")

        def extract_acls_from_ldif(
            self,
            ldif_content: str,
        ) -> FlextResult[list[FlextLdifModels.Acl]]:
            """Extract and parse all ACL definitions from LDIF content.

            Strategy pattern: OUD-specific approach to extract ACIs from LDIF entries.

            Args:
            ldif_content: Raw LDIF content containing ACL definitions

            Returns:
            FlextResult with list of parsed ACL models

            """
            try:
                acls: list[FlextLdifModels.Acl] = []
                current_aci: list[str] = []
                in_multiline_aci = False

                for line in ldif_content.split("\n"):
                    stripped = line.strip()

                    # Detect ACI start (case-insensitive)
                    if stripped.lower().startswith("aci:"):
                        if current_aci:
                            # Parse accumulated multiline ACI
                            aci_text = "\n".join(current_aci)
                            result = self.parse_acl(aci_text)
                            if result.is_success:
                                acls.append(result.unwrap())
                            current_aci = []

                        current_aci.append(stripped)
                        # Check if this ACI continues on next lines
                        # (no closing parenthesis)
                        in_multiline_aci = not stripped.rstrip().endswith(")")

                    elif in_multiline_aci and stripped:
                        # Continuation of multiline ACI
                        current_aci.append(stripped)
                        if stripped.rstrip().endswith(")"):
                            in_multiline_aci = False

                    # Also handle ds-cfg format
                    elif stripped.lower().startswith("ds-cfg-"):
                        result = self.parse_acl(stripped)
                        if result.is_success:
                            acls.append(result.unwrap())

                # Parse any remaining ACI
                if current_aci:
                    aci_text = "\n".join(current_aci)
                    result = self.parse_acl(aci_text)
                    if result.is_success:
                        acls.append(result.unwrap())

                return FlextResult[list[FlextLdifModels.Acl]].ok(acls)

            except Exception as e:
                return FlextResult[list[FlextLdifModels.Acl]].fail(
                    f"OUD ACL extraction failed: {e}",
                )

        def convert_rfc_acl_to_aci(
            self,
            rfc_acl_attrs: dict[str, object],
            target_server: str,
        ) -> FlextResult[dict[str, object]]:
            """Convert RFC ACL attributes to OUD ACI format.

            Takes ACL attributes in internal RFC/metadata format and converts
            them to proper ACI attributes for OUD server.

            Args:
                rfc_acl_attrs: ACL attributes in RFC metadata format
                target_server: Target server (should be 'oud' or 'oracle_oud')

            Returns:
                FlextResult with ACI attributes in OUD format

            """
            try:
                if target_server.lower() not in {"oud", "oracle_oud"}:
                    return FlextResult[dict[str, object]].fail(
                        f"Invalid target server for OUD ACL conversion: {target_server}",
                    )

                aci_values = []

                # Convert all ACL attributes to OUD ACI format
                for attr_values in rfc_acl_attrs.values():
                    if isinstance(attr_values, list):
                        aci_values.extend(str(val) for val in attr_values)
                    else:
                        aci_values.append(str(attr_values))

                if aci_values:
                    return FlextResult[dict[str, object]].ok({
                        self.acl_attribute_name: aci_values
                    })
                return FlextResult[dict[str, object]].ok({})

            except (ValueError, TypeError, AttributeError) as e:
                return FlextResult[dict[str, object]].fail(
                    f"OUD ACL conversion failed: {e}",
                )

        def get_acl_attribute_name(self) -> str:
            """Get OUD-specific ACL attribute name.

            OUD uses RFC 4876 compliant 'aci' attribute for ACL definitions,
            not the generic 'acl' attribute.

            Returns:
                'aci' - OUD-specific ACL attribute name

            """
            return self.acl_attribute_name

    class Entry(FlextLdifServersRfc.Entry):
        """Oracle OUD entry quirk (nested).

        Handles OUD-specific entry transformations:
        - OUD-specific operational attributes
        - OUD entry formatting
        - Compatibility with OID entries

        Example:
            quirk = FlextLdifServersOud.Entry(server_type="oracle_oud")
            if quirk.can_handle_entry(dn, attributes):
                result = quirk.process_entry(dn, attributes)

        """

        server_type: ClassVar[str] = FlextLdifConstants.ServerTypes.OUD
        priority: ClassVar[int] = 10

        def __init__(
            self,
        ) -> None:
            """Initialize OUD entry quirk."""
            super().__init__()

        # --------------------------------------------------------------------- #
        # OVERRIDDEN METHODS (from FlextLdifServersBase.Entry)
        # --------------------------------------------------------------------- #
        # These methods override the base class with Oracle OUD-specific logic:
        # - can_handle_entry(): Detects OUD entries by DN/attributes
        # - process_entry(): Normalizes OUD entries with metadata
        # - convert_entry_to_rfc(): Converts OUD entries to RFC format

        def can_handle_entry(
            self,
            entry: FlextLdifModels.Entry,
        ) -> bool:
            """Check if this quirk should handle the entry.

            Only handles entries when schema/filters indicate OUD-specific processing:
            - Entries with Oracle OUD attributes (ds-cfg-* prefix)

            Args:
                entry: Entry model

            Returns:
                True if this quirk should handle the entry

            """
            if not entry or not isinstance(entry, FlextLdifModels.Entry):
                return False

            # Correctly access the attributes dictionary from the LdifAttributes model
            entry_attrs = entry.attributes.attributes

            if not entry_attrs or not isinstance(entry_attrs, dict):
                return False

            dn_value_lower = entry.dn.value.lower()

            if (
                FlextLdifConstants.DnPatterns.CN_CONFIG.lower() in dn_value_lower
                and FlextLdifConstants.DnPatterns.CN_SCHEMA.lower() in dn_value_lower
            ):
                return True

            if (
                FlextLdifConstants.DnPatterns.CN_CONFIG.lower() in dn_value_lower
                and ("cn=directory" in dn_value_lower or "cn=ds" in dn_value_lower)
            ):
                return True

            if any(attr_name.startswith("ds-") for attr_name in entry_attrs):
                return True

            if any(
                attr_name.lower() in self.BOOLEAN_ATTRIBUTES
                for attr_name in entry_attrs
            ):
                return True

            if any(
                "pwd" in attr_name.lower() or "password" in attr_name.lower()
                for attr_name in entry_attrs
            ):
                return True

            # Check for X-ORIGIN in metadata if present
            if entry.metadata and entry.metadata.x_origin:
                return True

            if any(attr_name.startswith("orcl") for attr_name in entry_attrs):
                return False

            return "objectclass" in entry_attrs

        # Oracle OUD boolean attributes that expect TRUE/FALSE instead of 0/1
        # This IS format-specific - OUD requires TRUE/FALSE, not 0/1
        # Boolean attributes that expect TRUE/FALSE instead of 0/1
        # Consolidated in FlextLdifConstants.OperationalAttributes.OUD_BOOLEAN_ATTRIBUTES
        # Kept as ClassVar for backward compatibility and type hints
        BOOLEAN_ATTRIBUTES: ClassVar[frozenset[str]] = (
            FlextLdifConstants.OperationalAttributes.OUD_BOOLEAN_ATTRIBUTES
        )

        # Attribute name casing map: lowercase source → proper OUD camelCase
        # Maps common LDAP attributes with incorrect casing to OUD-expected camelCase
        ATTRIBUTE_CASE_MAP: ClassVar[dict[str, str]] = {
            "uniquemember": "uniqueMember",
            "displayname": "displayName",
            "distinguishedname": "distinguishedName",
            "objectclass": "objectClass",
            "memberof": "memberOf",
            "seealsodescription": "seeAlsoDescription",
            FlextLdifConstants.AclAttributes.ORCLACI: FlextLdifConstants.AclAttributes.ACI,
            FlextLdifConstants.AclAttributes.ORCL_ENTRY_LEVEL_ACI: FlextLdifConstants.AclAttributes.ACI,
            "acl": FlextLdifConstants.AclAttributes.ACI,
        }

        def process_entry(
            self,
            entry: FlextLdifModels.Entry,
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Process entry for Oracle OUD format."""
            try:
                # Initialize a dictionary to hold processed attributes
                processed_attrs_dict: dict[str, list[str]] = {}

                # Preserve base64 encoding metadata from entry extraction
                if "_base64_attrs" in entry.attributes.attributes:
                    # Re-add as an internal metadata key, not a regular attribute
                    processed_attrs_dict["_base64_attrs"] = entry.attributes.attributes[
                        "_base64_attrs"
                    ]

                # Preserve special LDIF modify markers for schema entries
                if "_modify_add_attributetypes" in entry.attributes.attributes:
                    processed_attrs_dict["_modify_add_attributetypes"] = (
                        entry.attributes.attributes["_modify_add_attributetypes"]
                    )
                if "_modify_add_objectclasses" in entry.attributes.attributes:
                    processed_attrs_dict["_modify_add_objectclasses"] = (
                        entry.attributes.attributes["_modify_add_objectclasses"]
                    )

                # PHASE 0: Normalize attribute names to proper camelCase and apply OUD-specific transformations
                final_attributes_for_new_entry: dict[str, list[str]] = {}
                for attr_name, attr_values in entry.attributes.attributes.items():
                    attr_lower = attr_name.lower()
                    normalized_name = self.ATTRIBUTE_CASE_MAP.get(attr_lower, attr_name)

                    # Process values based on attribute type
                    if normalized_name.lower() in self.BOOLEAN_ATTRIBUTES:
                        # Convert 0/1 to TRUE/FALSE for OUD
                        if isinstance(attr_values, list):
                            converted_values = []
                            for val in attr_values:
                                str_val = str(val).strip()
                                converted_val = (
                                    FlextLdifConstants.BooleanFormats.OID_TO_RFC.get(
                                        str_val, val
                                    )
                                )
                                converted_values.append(str(converted_val))
                            final_attributes_for_new_entry[normalized_name] = (
                                converted_values
                            )
                        else:
                            str_val = str(attr_values).strip()
                            converted_val = (
                                FlextLdifConstants.BooleanFormats.OID_TO_RFC.get(
                                    str_val, str(attr_values)
                                )
                            )
                            final_attributes_for_new_entry[normalized_name] = [
                                str(converted_val)
                            ]
                    elif normalized_name.lower() == "telephonenumber":
                        # Validate telephone numbers - must contain at least one digit
                        valid_numbers = []
                        values_to_process = (
                            [attr_values]
                            if not isinstance(attr_values, list)
                            else attr_values
                        )
                        for val in values_to_process:
                            str_val = str(val).strip()
                            if any(c.isdigit() for c in str_val):
                                valid_numbers.append(str_val)
                        if valid_numbers:
                            final_attributes_for_new_entry[normalized_name] = (
                                valid_numbers
                            )
                    else:
                        # Copy other attributes as is, ensuring list[str] format
                        final_attributes_for_new_entry[normalized_name] = [
                            str(val)
                            for val in (
                                [attr_values]
                                if not isinstance(attr_values, list)
                                else attr_values
                            )
                        ]

                # Create LdifAttributes model for the new entry, combining processed and internal attributes
                combined_attributes = final_attributes_for_new_entry.copy()
                combined_attributes.update({
                    k: v for k, v in processed_attrs_dict.items() if k.startswith("_")
                })
                new_ldif_attributes = FlextLdifModels.LdifAttributes(
                    attributes=combined_attributes
                )

                # Preserve metadata for DN quirks and attribute ordering
                metadata_extensions: dict[str, object] = {}

                if ", " in entry.dn.value:
                    metadata_extensions["dn_spaces"] = True

                if final_attributes_for_new_entry:
                    attr_order: list[str] = list(final_attributes_for_new_entry.keys())
                    metadata_extensions["attribute_order"] = attr_order

                if (
                    FlextLdifConstants.DictKeys.OBJECTCLASS
                    in final_attributes_for_new_entry
                ):
                    oc_values = final_attributes_for_new_entry[
                        FlextLdifConstants.DictKeys.OBJECTCLASS
                    ]
                    if isinstance(oc_values, list):
                        oracle_ocs: list[str] = [
                            str(oc)
                            for oc in oc_values
                            if any(
                                prefix in str(oc).lower()
                                for prefix in ["orcl", "oracle"]
                            )
                        ]
                        if oracle_ocs:
                            metadata_extensions[
                                FlextLdifConstants.MetadataKeys.ORACLE_OBJECTCLASSES
                            ] = oracle_ocs

                new_metadata = FlextLdifModels.QuirkMetadata.create_for_quirk(
                    quirk_type=FlextLdifConstants.ServerTypes.OUD,
                    extensions=metadata_extensions,
                )

                # Create and return the new Entry model
                return FlextResult.ok(
                    FlextLdifModels.Entry.create(
                        dn=entry.dn,
                        attributes=new_ldif_attributes,
                        metadata=new_metadata,
                    ).unwrap()
                )

            except Exception as e:
                return FlextResult.fail(f"OUD entry processing failed: {e}")

        def convert_entry_to_rfc(
            self,
            entry_data: FlextLdifModels.Entry,
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Convert server-specific entry to RFC-compliant format."""
            try:
                # OUD entries are already RFC-compliant
                return FlextResult.ok(entry_data)
            except Exception as e:
                return FlextResult.fail(
                    f"OUD entry→RFC conversion failed: {e}",
                )

        def convert_entry_from_rfc(
            self,
            entry_data: FlextLdifModels.Entry,
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Convert RFC-compliant entry to OUD-specific format."""
            # Transform boolean attributes from 0/1 to TRUE/FALSE for OUD
            transformed_attributes = {}
            for attr_name, attr_values in entry_data.attributes.attributes.items():
                if attr_name.lower() in self.BOOLEAN_ATTRIBUTES:
                    # Transform boolean values
                    transformed_values = []
                    for value in attr_values if isinstance(attr_values, list) else [attr_values]:
                        str_value = str(value).lower()
                        if str_value in ('0', 'false', 'f', 'no', 'n'):
                            transformed_values.append('FALSE')
                        elif str_value in ('1', 'true', 't', 'yes', 'y'):
                            transformed_values.append('TRUE')
                        else:
                            # Keep original value if not clearly boolean
                            transformed_values.append(str(value))

                    transformed_attributes[attr_name] = (
                        transformed_values if isinstance(attr_values, list)
                        else transformed_values[0]
                    )
                else:
                    transformed_attributes[attr_name] = attr_values

            # Create new LdifAttributes with transformed attributes
            new_attributes = FlextLdifModels.LdifAttributes(
                attributes=transformed_attributes,
                attribute_metadata=entry_data.attributes.attribute_metadata
            )

            # Create new entry with transformed attributes
            new_entry = entry_data.model_copy(update={"attributes": new_attributes})

            # Ensure OUD server type is set in metadata
            if new_entry.metadata:
                new_entry.metadata.server_type = (
                    FlextLdifConstants.LdapServers.ORACLE_OUD
                )
            else:
                new_entry.metadata = FlextLdifModels.QuirkMetadata(
                    server_type=FlextLdifConstants.LdapServers.ORACLE_OUD
                )

            return FlextResult.ok(new_entry)

        def convert_rfc_acl_to_aci(
            self,
            rfc_acl_attrs: dict[str, object],
            target_server: str,
        ) -> FlextResult[dict[str, object]]:
            """Convert RFC ACL attributes to OUD ACI format.

            Takes ACL attributes in internal RFC/metadata format and converts
            them to proper ACI attributes for OUD server.

            Args:
                rfc_acl_attrs: ACL attributes in RFC metadata format
                target_server: Target server (should be 'oud' or 'oracle_oud')

            Returns:
                FlextResult with ACI attributes in OUD format

            """
            try:
                if target_server.lower() not in {"oud", "oracle_oud"}:
                    return FlextResult[dict[str, object]].fail(
                        f"Invalid target server for OUD ACL conversion: {target_server}",
                    )

                aci_values = []

                # Convert all ACL attributes to OUD ACI format
                for attr_values in rfc_acl_attrs.values():
                    if isinstance(attr_values, list):
                        aci_values.extend(str(val) for val in attr_values)
                    else:
                        aci_values.append(str(attr_values))

                if aci_values:
                    return FlextResult[dict[str, object]].ok({
                        FlextLdifConstants.AclAttributes.ACI: aci_values
                    })
                return FlextResult[dict[str, object]].ok({})

            except (ValueError, TypeError, AttributeError) as e:
                return FlextResult[dict[str, object]].fail(
                    f"OUD ACL conversion failed: {e}",
                )

        def write_entry_to_ldif(
            self,
            entry_data: dict[str, object],
        ) -> FlextResult[str]:
            r"""Write OUD entry data to standard LDIF string format.

            Converts parsed entry dictionary to LDIF format string.
            Handles Oracle-specific attributes and preserves DN formatting.

            Args:
                entry_data: Parsed OUD entry data dictionary

            Returns:
                FlextResult with LDIF formatted entry string

            Example:
                Input: {FlextLdifConstants.DictKeys.DN: "cn=test,dc=example",
                        FlextLdifConstants.DictKeys.CN: ["test"],
                        FlextLdifConstants.DictKeys.OBJECTCLASS: ["person"]}
                Output: "dn: cn=test,dc=example\\ncn: test\\nobjectClass: person\\n"

            """
            try:
                # DEBUG: Log input entry_data
                input_attrs = {
                    k: v for k, v in entry_data.items() if not k.startswith("_")
                }
                logger.debug(
                    "[OUD.write_entry_to_ldif] START - Writing entry to LDIF",
                    entry_data_count=len(input_attrs),
                    attribute_names=list(input_attrs.keys()),
                )

                # Check for required DN field
                if FlextLdifConstants.DictKeys.DN not in entry_data:
                    return FlextResult[str].fail(
                        "Missing required FlextLdifConstants.DictKeys.DN field",
                    )

                dn = entry_data[FlextLdifConstants.DictKeys.DN]
                ldif_lines = [f"dn: {dn}"]

                # Check if this is a schema modification entry (changetype: modify)
                is_modify = False
                changetype_list = entry_data.get("changetype", [])
                if isinstance(changetype_list, list) and "modify" in changetype_list:
                    is_modify = True
                    ldif_lines.append("changetype: modify")

                # Handle LDIF modify format for schema additions
                # NOTE: Schema definitions MUST be already transformed to OUD format by pipeline
                # via RFC canonical format (OID quirk → RFC → OUD quirk)
                if is_modify and (
                    "_modify_add_attributetypes" in entry_data
                    or "_modify_add_objectclasses" in entry_data
                ):
                    # Write modify-add operations for attributetypes
                    if "_modify_add_attributetypes" in entry_data:
                        attr_types = entry_data["_modify_add_attributetypes"]
                        if isinstance(attr_types, list) and attr_types:
                            ldif_lines.append("add: attributetypes")
                            ldif_lines.extend(
                                f"attributetypes: {attr_type}"
                                for attr_type in attr_types
                            )
                            ldif_lines.append("-")

                    # Write modify-add operations for objectclasses
                    if "_modify_add_objectclasses" in entry_data:
                        obj_classes = entry_data["_modify_add_objectclasses"]
                        if isinstance(obj_classes, list) and obj_classes:
                            ldif_lines.append("add: objectclasses")
                            ldif_lines.extend(
                                f"objectclasses: {obj_class}"
                                for obj_class in obj_classes
                            )
                            ldif_lines.append("-")
                else:
                    # Standard entry format (not a modify operation)
                    # Get attribute ordering from metadata if available
                    attr_order = None
                    if "_metadata" in entry_data:
                        metadata = entry_data["_metadata"]
                        if isinstance(metadata, FlextLdifModels.QuirkMetadata):
                            attr_order = metadata.extensions.get("attribute_order")
                        elif isinstance(metadata, dict):
                            attr_order = metadata.get("extensions", {}).get(
                                "attribute_order",
                            )

                    # Determine attribute iteration order
                    # Type narrowing: ensure attr_order is list before iteration
                    if attr_order is not None and isinstance(attr_order, list):
                        # Use preserved ordering
                        attrs_to_process = [
                            (key, entry_data[key])
                            for key in attr_order
                            if key in entry_data
                            and key
                            not in {
                                FlextLdifConstants.DictKeys.DN,
                                "_metadata",
                                FlextLdifConstants.DictKeys.SERVER_TYPE,
                                "_acl_attributes",  # Processed by ACL service, not written as attribute
                            }
                        ]
                    else:
                        # Default ordering: filter out special keys
                        attrs_to_process = [
                            (key, value)
                            for key, value in entry_data.items()
                            if key
                            not in {
                                FlextLdifConstants.DictKeys.DN,
                                "_metadata",
                                FlextLdifConstants.DictKeys.SERVER_TYPE,
                                "changetype",
                                "_acl_attributes",  # Processed by ACL service, not written as attribute
                            }
                        ]

                    # DEBUG: Log attributes to be processed
                    logger.debug(
                        f"[OUD.write_entry_to_ldif] ATTRS_TO_PROCESS - {len(attrs_to_process)} attributes ready",
                        attr_names=[name for name, _ in attrs_to_process],
                    )

                    # Extract base64 attributes metadata
                    base64_attrs = set()
                    if "_base64_attrs" in entry_data:
                        base64_data = entry_data["_base64_attrs"]
                        if isinstance(base64_data, set):
                            base64_attrs = base64_data
                        elif isinstance(base64_data, list):
                            base64_attrs = set(base64_data)

                    # Write attributes
                    # SAFETY: Filter out DN if it somehow appears in attributes
                    for attr_name, attr_value in attrs_to_process:
                        # Critical: DN is NOT an attribute - skip if present
                        if attr_name.lower() == FlextLdifConstants.DictKeys.DN:
                            continue
                        # Skip internal metadata attributes
                        if attr_name.startswith("_"):
                            continue
                        # Apply attribute name mapping (e.g., orclaci → aci, uniquemember → uniqueMember)
                        mapped_attr_name = self.ATTRIBUTE_CASE_MAP.get(
                            attr_name.lower(),
                            attr_name,
                        )
                        # Check if this attribute should be base64-encoded
                        is_base64 = attr_name in base64_attrs
                        attr_prefix = (
                            f"{mapped_attr_name}::"
                            if is_base64
                            else f"{mapped_attr_name}:"
                        )

                        # DEBUG: Log attribute being written
                        if isinstance(attr_value, list):
                            logger.debug(
                                f"[OUD.write_entry_to_ldif] WRITING attribute {mapped_attr_name}",
                                value_count=len(attr_value),
                                is_base64=is_base64,
                                first_value_str=str(attr_value[0])[:50]
                                if attr_value
                                else None,
                            )
                        else:
                            logger.debug(
                                f"[OUD.write_entry_to_ldif] WRITING attribute {mapped_attr_name}",
                                is_base64=is_base64,
                                value_str=str(attr_value)[:50],
                            )

                        # Handle both list and single values
                        if isinstance(attr_value, list):
                            ldif_lines.extend(
                                f"{attr_prefix} {value}" for value in attr_value
                            )
                        else:
                            ldif_lines.append(f"{attr_prefix} {attr_value}")

                # Join with newlines and add trailing newline
                ldif_string = "\n".join(ldif_lines) + "\n"

                # DEBUG: Log final LDIF output
                ldif_lines_count = len(ldif_lines)
                aci_count = sum(
                    1 for line in ldif_lines if line.lower().startswith("aci:")
                )
                logger.debug(
                    f"[OUD.write_entry_to_ldif] COMPLETE - Final LDIF has {ldif_lines_count} lines",
                    total_lines=ldif_lines_count,
                    aci_attribute_count=aci_count,
                    ldif_size_bytes=len(ldif_string),
                    first_5_lines=ldif_lines[:5],
                )

                return FlextResult[str].ok(ldif_string)

            except Exception as e:
                return FlextResult[str].fail(f"Failed to write entry to LDIF: {e}")

        def extract_entries_from_ldif(
            self,
            ldif_content: str,
        ) -> FlextResult[list[dict[str, object]]]:
            """Extract and parse all directory entries from LDIF content.

            Strategy pattern: OUD-specific approach to extract entries from LDIF.

            Args:
            ldif_content: Raw LDIF content containing directory entries

            Returns:
            FlextResult with list of parsed entry dictionaries

            """
            try:
                entries = []
                current_entry: dict[str, object] = {}
                current_attr: str | None = None
                current_values: list[str] = []

                for line in ldif_content.split("\n"):
                    # Empty line indicates end of entry
                    if not line.strip():
                        if current_entry:
                            # Save any pending attribute
                            if current_attr and current_values:
                                if len(current_values) == 1:
                                    current_entry[current_attr] = current_values[0]
                                else:
                                    current_entry[current_attr] = current_values
                                current_attr = None
                                current_values = []

                            # Process complete entry
                            if FlextLdifConstants.DictKeys.DN in current_entry:
                                dn = str(
                                    current_entry.pop(FlextLdifConstants.DictKeys.DN),
                                )
                                result = self.process_entry(dn, current_entry)
                                if result.is_success:
                                    entries.append(result.unwrap())

                            current_entry = {}
                        continue

                    # Skip comments
                    if line.startswith("#"):
                        continue

                    # Continuation line (starts with space)
                    if line.startswith(" ") and current_attr:
                        # Append to current attribute value
                        if current_values:
                            current_values[-1] += line[1:]  # Remove leading space
                        continue

                    # New attribute line
                    if ":" in line:
                        # Save previous attribute
                        if current_attr and current_values:
                            if len(current_values) == 1:
                                current_entry[current_attr] = current_values[0]
                            else:
                                current_entry[current_attr] = current_values

                        # Parse new attribute
                        attr_name, attr_value = line.split(":", 1)
                        attr_name = attr_name.strip()
                        attr_value = attr_value.strip()

                        # Handle base64 encoding (::) - PRESERVE for writing
                        if attr_value.startswith(":"):
                            attr_value = attr_value[1:].strip()
                            # Mark this attribute as base64-encoded in metadata
                            # We'll store this in _base64_attrs for write_entry_to_ldif
                            if "_base64_attrs" not in current_entry:
                                current_entry["_base64_attrs"] = set()
                            if isinstance(current_entry["_base64_attrs"], set):
                                current_entry["_base64_attrs"].add(attr_name)

                        # Check if this attribute already exists (multi-valued)
                        if attr_name in current_entry and attr_name != "_base64_attrs":
                            # Convert to list if needed
                            existing = current_entry[attr_name]
                            if not isinstance(existing, list):
                                current_entry[attr_name] = [existing, attr_value]
                            else:
                                existing.append(attr_value)
                            current_attr = None
                            current_values = []
                        else:
                            current_attr = attr_name
                            current_values = [attr_value]

                # Process final entry
                if current_entry:
                    if current_attr and current_values:
                        if len(current_values) == 1:
                            current_entry[current_attr] = current_values[0]
                        else:
                            current_entry[current_attr] = current_values

                    if FlextLdifConstants.DictKeys.DN in current_entry:
                        dn = str(current_entry.pop(FlextLdifConstants.DictKeys.DN))
                        result = self.process_entry(dn, current_entry)
                        if result.is_success:
                            entries.append(result.unwrap())

                return FlextResult[list[dict[str, object]]].ok(entries)

            except Exception as e:
                return FlextResult[list[dict[str, object]]].fail(
                    f"OUD entry extraction failed: {e}",
                )

    def __init__(self, **_kwargs: object) -> None:
        """Initialize Oracle Unified Directory server quirks.

        Args:
            **_kwargs: Ignored keyword arguments for backward compatibility (e.g., server_type)

        """
        super().__init__()
        self.schema = self.Schema()
        self.acl = self.Acl()
        self.entry = self.Entry()

    def extract_schemas_from_ldif(
        self,
        ldif_content: str,
    ) -> FlextResult[FlextLdifTypes.Models.EntryAttributesDict]:
        """Delegate to schema instance."""
        return self.schema.extract_schemas_from_ldif(ldif_content)

    def convert_attribute_to_rfc(
        self,
        attr_data: FlextLdifModels.SchemaAttribute,
    ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
        """Delegate to schema instance."""
        return self.schema.convert_attribute_to_rfc(attr_data)

    def convert_objectclass_to_rfc(
        self,
        oc_data: FlextLdifModels.SchemaObjectClass,
    ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
        """Delegate to schema instance."""
        return self.schema.convert_objectclass_to_rfc(oc_data)

    def convert_objectclass_from_rfc(
        self,
        rfc_data: FlextLdifModels.SchemaObjectClass,
    ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
        """Delegate to schema instance."""
        return self.schema.convert_objectclass_from_rfc(rfc_data)

    def convert_attribute_from_rfc(
        self,
        rfc_data: FlextLdifModels.SchemaAttribute,
    ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
        """Delegate to schema instance."""
        return self.schema.convert_attribute_from_rfc(rfc_data)

    def write_objectclass_to_rfc(
        self,
        oc_data: FlextLdifModels.SchemaObjectClass,
    ) -> FlextResult[str]:
        """Delegate to schema instance."""
        return self.schema.write_objectclass_to_rfc(oc_data)

    def write_attribute_to_rfc(
        self,
        attr_data: FlextLdifModels.SchemaAttribute,
    ) -> FlextResult[str]:
        """Delegate to schema instance."""
        return self.schema.write_attribute_to_rfc(attr_data)

    # =========================================================================
    # QuirksPort Protocol Implementation (Concrete Methods for OUD)
    # =========================================================================

    def normalize_entry_to_rfc(
        self, entry: FlextLdifModels.Entry
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Delegate Entry normalization to the nested Entry quirk."""
        return self.entry.convert_entry_to_rfc(entry)

    def denormalize_entry_from_rfc(
        self, entry: FlextLdifModels.Entry
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Delegate Entry denormalization to the nested Entry quirk."""
        return self.entry.convert_entry_from_rfc(entry)

    def normalize_attribute_to_rfc(
        self, attribute: FlextLdifModels.SchemaAttribute
    ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
        """Delegate SchemaAttribute normalization to the nested Schema quirk."""
        return self.schema.convert_attribute_to_rfc(attribute)

    def denormalize_attribute_from_rfc(
        self, attribute: FlextLdifModels.SchemaAttribute
    ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
        """Delegate SchemaAttribute denormalization to the nested Schema quirk."""
        return self.schema.convert_attribute_from_rfc(attribute)

    def normalize_objectclass_to_rfc(
        self, objectclass: FlextLdifModels.SchemaObjectClass
    ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
        """Delegate SchemaObjectClass normalization to the nested Schema quirk."""
        return self.schema.convert_objectclass_to_rfc(objectclass)

    def denormalize_objectclass_from_rfc(
        self, objectclass: FlextLdifModels.SchemaObjectClass
    ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
        """Delegate SchemaObjectClass denormalization to the nested Schema quirk."""
        return self.schema.convert_objectclass_from_rfc(objectclass)

    def convert_acl_to_rfc(
        self,
        acl_data: FlextLdifModels.Acl,
    ) -> FlextResult[FlextLdifModels.Acl]:
        """Convert ACL to RFC-compliant format, delegating to nested Acl quirk."""
        return self.acl.convert_acl_to_rfc(acl_data)

    def normalize_acl_to_rfc(
        self, acl: FlextLdifModels.Acl
    ) -> FlextResult[FlextLdifModels.Acl]:
        """Delegate Acl normalization to the nested Acl quirk."""
        return self.acl.convert_acl_to_rfc(acl)

    def denormalize_acl_from_rfc(
        self, acl: FlextLdifModels.Acl
    ) -> FlextResult[FlextLdifModels.Acl]:
        """Delegate Acl denormalization to the nested Acl quirk."""
        return self.acl.convert_acl_from_rfc(acl)


__all__ = ["FlextLdifServersOud"]
