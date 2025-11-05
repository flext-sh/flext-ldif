"""Oracle Unified Directory (OUD) Quirks.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Provides OUD-specific quirks for schema, ACL, and entry processing.
"""

from __future__ import annotations

import re
from typing import ClassVar, Final

from flext_core import FlextLogger, FlextResult

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.servers.rfc import FlextLdifServersRfc
from flext_ldif.typings import FlextLdifTypes

logger = FlextLogger(__name__)


class FlextLdifServersOud(FlextLdifServersRfc):
    """Oracle Unified Directory (OUD) Quirks."""

    # Top-level configuration - mirrors Schema class for direct access
    # =========================================================================
    # Class-level attributes for server identification
    # =========================================================================
    # Class-level attributes for server identification (from Constants)
    # =========================================================================
    server_type: ClassVar[str] = Constants.SERVER_TYPE
    priority: ClassVar[int] = Constants.PRIORITY

    class Constants(FlextLdifServersRfc.Constants):
        """Oracle Unified Directory-specific constants centralized for operations in oud.py.

        These constants follow a standardized naming pattern that can be replicated
        in other server quirks implementations for consistency.
        """

        # === STANDARDIZED CONSTANTS FOR AUTO-DISCOVERY ===
        SERVER_TYPE: ClassVar[str] = FlextLdifConstants.ServerTypes.OUD
        CANONICAL_NAME: ClassVar[str] = "oud"
        ALIASES: ClassVar[frozenset[str]] = frozenset(["oud", "oracle_oud"])
        PRIORITY: ClassVar[int] = 10
        CAN_NORMALIZE_FROM: ClassVar[frozenset[str]] = frozenset(["oud", "rfc"])
        CAN_DENORMALIZE_TO: ClassVar[frozenset[str]] = frozenset(["oud", "rfc"])

        # OID pattern for server detection
        OID_PATTERN: Final[re.Pattern[str]] = re.compile(
            r"2\.16\.840\.1\.113894\.",
        )

        # Server-specific boolean attributes
        BOOLEAN_ATTRIBUTES: Final[frozenset[str]] = (
            frozenset(["pwdlockout", "pwdmustchange", "pwdallowuserchange", "pwdexpirewarning", "pwdgraceauthnlimit", "pwdlockoutduration", "pwdmaxfailure", "pwdminage", "pwdmaxage", "pwdmaxlength", "pwdminlength", "orcldasselfmodifiable"])
        )

        # Oracle OUD operational attributes (server-specific)
        OPERATIONAL_ATTRIBUTES: Final[frozenset[str]] = frozenset([
            "ds-sync-hist",
            "ds-sync-state",
            "ds-pwp-account-disabled",
            "ds-cfg-backend-id",
            "entryUUID",  # OUD specific version
        ])

        # DN patterns used for detection
        DN_PREFIX_CN_CONFIG: Final[str] = "cn=config"
        DN_PREFIX_CN_SCHEMA: Final[str] = "cn=schema"

        # Oracle Unified Directory ACL format constants
        ACL_FORMAT: ClassVar[str] = "aci"  # RFC 4876 ACI attribute
        ACL_ATTRIBUTE_NAME: ClassVar[str] = "aci"  # ACL attribute name

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

        def __init__(
            self,
            server_type: str | None = None,
            priority: int | None = None,
        ) -> None:
            """Initialize OUD schema quirk.

            OUD extends RFC baseline with Oracle-specific enhancements.

            Args:
                server_type: Optional server type (inherited from parent)
                priority: Optional priority (inherited from parent)

            """
            super().__init__(server_type=server_type, priority=priority)

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
            if quirk._can_handle(acl_line):
                result = quirk.parse(acl_line)

        """

        # OVERRIDE: Oracle OUD uses RFC 4876 compliant "aci" for ACL attribute names (not inherited)
        acl_attribute_name = FlextLdifConstants.AclAttributes.ACI

        # OVERRIDDEN METHODS (from FlextLdifServersBase.Acl)
        # These methods override the base class with Oracle OUD-specific logic:
        # - can_handle(): Detects OUD ACL formats
        # - parse(): Normalizes Oracle OUD ACL to RFC-compliant internal model
        # - write(): Serializes RFC-compliant model to OUD ACI format
        # - get_attribute_name(): Returns "aci" (OUD-specific, overridden)

        # Oracle OUD server configuration defaults

        def __init__(
            self,
            server_type: str | None = None,
            priority: int | None = None,
        ) -> None:
            """Initialize OUD ACL quirk.

            Args:
                server_type: Optional server type (inherited from parent)
                priority: Optional priority (inherited from parent)

            """
            super().__init__(server_type=server_type, priority=priority)
            # NOTE: Hook registration was removed - AclConverter was moved to services/acl.py
            # Use FlextLdifAclService instead for ACL conversion operations

        # NOTE: Obsolete method removed - hook registration pattern changed
        # AclConverter was moved to services/acl.py as FlextLdifAclService
        # Use FlextLdifAclService for OID→OUD ACL conversions instead

        def can_handle(self, acl_line: str) -> bool:
            """Check if this is an Oracle OUD ACL line.

            Detects Oracle OUD ACL by checking if the line starts with:
            - "aci:" (RFC 4876 compliant ACI)
            - "targetattr=" (inline ACI format)
            - "targetscope=" (inline ACI format)
            - "version 3.0" (ACI version marker)
            - "ds-cfg-" (OUD configuration ACL)

            Args:
                acl_line: Raw ACL line from LDIF

            Returns:
                True if this is Oracle OUD ACL format

            """
            if not acl_line:
                return False

            normalized = acl_line.strip()
            return normalized.startswith((
                "aci:",
                "targetattr=",
                "targetscope=",
                "version 3.0",
                "ds-cfg-",
            ))

        def parse(self, acl_line: str) -> FlextResult[FlextLdifModels.Acl]:
            """Parse Oracle OUD ACL string to RFC-compliant internal model.

            Normalizes OUD ACI (Access Control Instruction) format to RFC-compliant
            internal representation.

            Parses ACI format used by OUD, extracting:
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
                        # Use utility for DN space detection
                        if FlextLdifUtilities.DN.contains_pattern(userdn, ", "):
                            dn_spaces = True

                    # Extract groupdn rules
                    groupdn_matches = re.findall(
                        r'groupdn\s*=\s*"([^"]+)"',
                        aci_content,
                    )
                    for groupdn in groupdn_matches:
                        bind_rules_data.append({"type": "groupdn", "value": groupdn})
                        # Use utility for DN space detection
                        if FlextLdifUtilities.DN.contains_pattern(groupdn, ", "):
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
                    elif (
                        perm_lower == FlextLdifConstants.PermissionNames.DELETE.lower()
                    ):
                        permissions_data["delete"] = True
                    elif (
                        perm_lower == FlextLdifConstants.PermissionNames.SEARCH.lower()
                    ):
                        permissions_data["search"] = True
                    elif (
                        perm_lower == FlextLdifConstants.PermissionNames.COMPARE.lower()
                    ):
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

        def write(self, acl_data: FlextLdifModels.Acl) -> FlextResult[str]:
            """Write RFC-compliant ACL model to OUD ACI string format.

            Serializes the RFC-compliant internal model to Oracle OUD ACI format string,
            including comprehensive comment generation for OID→OUD conversions to ensure
            zero data loss.

            Args:
                acl_data: RFC-compliant ACL Pydantic model

            Returns:
                FlextResult with OUD ACI formatted string including conversion comments

            Example:
                Input: Acl(name="Test", target=..., subject=..., permissions=...)
                Output: 'aci: (targetattr="*")(version 3.0; acl "Test"; allow (read) userdn="ldap:///self";)'

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
                            result = self.parse(aci_text)
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
                        result = self.parse(stripped)
                        if result.is_success:
                            acls.append(result.unwrap())

                # Parse any remaining ACI
                if current_aci:
                    aci_text = "\n".join(current_aci)
                    result = self.parse(aci_text)
                    if result.is_success:
                        acls.append(result.unwrap())

                return FlextResult[list[FlextLdifModels.Acl]].ok(acls)

            except Exception as e:
                return FlextResult[list[FlextLdifModels.Acl]].fail(
                    f"OUD ACL extraction failed: {e}",
                )

        def get_attribute_name(self) -> str:
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
            if quirk.can_handle_entry(entry):
                result = quirk.parse_entry(entry.dn.value, entry.attributes.attributes)

        """

        def __init__(
            self,
            server_type: str | None = None,
            priority: int | None = None,
        ) -> None:
            """Initialize OUD entry quirk.

            Args:
                server_type: Optional server type (inherited from parent)
                priority: Optional priority (inherited from parent)

            """
            super().__init__(server_type=server_type, priority=priority)

        # OVERRIDDEN METHODS (from FlextLdifServersBase.Entry)
        # These methods override the base class with Oracle OUD-specific logic:
        # - can_handle_entry(): Detects OUD entries by DN/attributes
        # - parse_entry(): Normalizes OUD entries with metadata during parsing
        # - write_entry(): Writes OUD entries with proper formatting

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

            entry_dn = entry.dn.value

            # Use utility methods for DN pattern matching
            if (
                FlextLdifUtilities.DN.contains_pattern(
                    entry_dn, FlextLdifServersOud.Constants.DN_PREFIX_CN_CONFIG
                )
                and FlextLdifUtilities.DN.contains_pattern(
                    entry_dn, FlextLdifServersOud.Constants.DN_PREFIX_CN_SCHEMA
                )
            ):
                return True

            if (
                FlextLdifUtilities.DN.contains_pattern(
                    entry_dn, FlextLdifServersOud.Constants.DN_PREFIX_CN_CONFIG
                )
                and (
                    FlextLdifUtilities.DN.contains_pattern(entry_dn, "cn=directory")
                    or FlextLdifUtilities.DN.contains_pattern(entry_dn, "cn=ds")
                )
            ):
                return True

            if any(attr_name.startswith("ds-") for attr_name in entry_attrs):
                return True

            if any(
                attr_name.lower() in FlextLdifServersOud.Constants.BOOLEAN_ATTRIBUTES
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
        # BOOLEAN_ATTRIBUTES moved to Constants class

        # Attribute name casing map: lowercase source → proper OUD camelCase
        # Maps common LDAP attributes with incorrect casing to OUD-expected camelCase
        ATTRIBUTE_CASE_MAP: ClassVar[dict[str, str]] = {
            "uniquemember": "uniqueMember",
            "displayname": "displayName",
            "distinguishedname": "distinguishedName",
            "objectclass": "objectClass",
            "memberof": "memberOf",
            "seealsodescription": "seeAlsoDescription",
            "orclaci": FlextLdifConstants.AclAttributes.ACI,  # Oracle OID ACI → OUD RFC ACI
            "orclentrylevelaci": FlextLdifConstants.AclAttributes.ACI,  # Oracle OID entry-level ACI → OUD RFC ACI
            "acl": FlextLdifConstants.AclAttributes.ACI,
        }

        def parse_entry(
            self,
            entry_dn: str,
            entry_attrs: Mapping[str, object],
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Parse raw LDIF entry data into Entry model with OUD-specific transformations.

            Applies OUD-specific normalizations during parsing:
            - Normalize attribute names to proper camelCase
            - Convert boolean attributes from 0/1 to TRUE/FALSE
            - Validate telephone numbers
            - Preserve metadata for DN quirks and attribute ordering

            Args:
                entry_dn: Raw DN string from LDIF parser
                entry_attrs: Raw attributes mapping from LDIF parser

            Returns:
                FlextResult with parsed Entry model with OUD-specific transformations

            """
            # First call parent parse_entry to get base Entry model
            base_result = super().parse_entry(entry_dn, entry_attrs)
            if base_result.is_failure:
                return base_result

            entry = base_result.unwrap()

            try:
                # Initialize a dictionary to hold processed attributes
                processed_attrs_dict: dict[str, list[str]] = {}

                # Preserve base64 encoding metadata from entry extraction
                if "_base64_attrs" in entry.attributes.attributes:
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

                # Normalize attribute names to proper camelCase and apply OUD-specific transformations
                final_attributes_for_new_entry: dict[str, list[str]] = {}
                for attr_name, attr_values in entry.attributes.attributes.items():
                    # Skip internal metadata attributes
                    if attr_name.startswith("_"):
                        continue

                    attr_lower = attr_name.lower()
                    normalized_name = self.ATTRIBUTE_CASE_MAP.get(attr_lower, attr_name)

                    # Process values based on attribute type
                    if normalized_name.lower() in FlextLdifServersOud.Constants.BOOLEAN_ATTRIBUTES:
                        # Convert 0/1 to TRUE/FALSE for OUD using utilities
                        converted_values = FlextLdifUtilities.Entry.convert_boolean_attributes(
                            attr_values if isinstance(attr_values, list) else [attr_values],
                            set(FlextLdifServersOud.Constants.BOOLEAN_ATTRIBUTES),
                        )
                        final_attributes_for_new_entry[normalized_name] = converted_values
                    elif normalized_name.lower() == "telephonenumber":
                        # Validate telephone numbers using utilities
                        valid_numbers = FlextLdifUtilities.Entry.validate_telephone_numbers(
                            attr_values if isinstance(attr_values, list) else [attr_values]
                        )
                        if valid_numbers:
                            final_attributes_for_new_entry[normalized_name] = valid_numbers
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

                # Create LdifAttributes model, combining processed and internal attributes
                combined_attributes = final_attributes_for_new_entry.copy()
                combined_attributes.update({
                    k: v for k, v in processed_attrs_dict.items() if k.startswith("_")
                })
                new_ldif_attributes = FlextLdifModels.LdifAttributes(
                    attributes=combined_attributes
                )

                # Build metadata extensions
                metadata_extensions: dict[str, object] = {}
                if FlextLdifUtilities.DN.contains_pattern(entry.dn.value, ", "):
                    metadata_extensions["dn_spaces"] = True
                if final_attributes_for_new_entry:
                    metadata_extensions["attribute_order"] = list(
                        final_attributes_for_new_entry.keys()
                    )
                if (
                    FlextLdifConstants.DictKeys.OBJECTCLASS
                    in final_attributes_for_new_entry
                ):
                    oc_values = final_attributes_for_new_entry[
                        FlextLdifConstants.DictKeys.OBJECTCLASS
                    ]
                    if isinstance(oc_values, list):
                        oracle_ocs = [
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
                return FlextResult.fail(f"OUD entry parsing failed: {e}")

        def _format_aci_with_semicolons(self, aci_value: str) -> str:
            """Format ACI value with semicolons between multiple 'by' clauses for OUD.

            OUD requires semicolons (;) to separate multiple 'by' clauses in ACI.

            Example:
              Input:  "aci: access to entry by group=... (...) by group=... (...) by * (...)"
              Output: "aci: access to entry by group=... (...) ; by group=... (...) ; by * (...)"

            Args:
                aci_value: ACI value string (may be multiline)

            Returns:
                Formatted ACI with semicolons inserted after each 'by' clause (except last)

            """
            import re

            # CRITICAL: This method only does semantic transformation (add semicolons).
            # Line formatting (folding/unfolding) is the writer's responsibility, NOT the quirk's.
            # Always normalize whitespace and remove newlines - let writer handle formatting.

            # Normalize whitespace: replace all whitespace (including newlines) with single spaces)
            # This ensures the quirk only does semantic transformation, not formatting
            normalized = re.sub(r"\s+", " ", aci_value.strip())

            # OUD format requires semicolons after each "by" clause (except the last one)
            # Format: "by group=\"...\" ;" or "by *" (no semicolon if last)
            # Find all "by group=\"...\"" and "by *" clauses
            by_group_pattern = r"by\s+group=\"[^\"]+\""
            by_star_pattern = r"by\s+\*"

            # Find all by clauses with their end positions
            by_clauses = []
            for match in re.finditer(by_group_pattern, normalized, re.IGNORECASE):
                by_clauses.append((match.end(), "group"))
            for match in re.finditer(by_star_pattern, normalized, re.IGNORECASE):
                by_clauses.append((match.end(), "star"))

            # Sort by position (first element of tuple)
            by_clauses.sort(key=lambda x: x[0])

            if len(by_clauses) <= 1:
                # Only one or zero "by" clauses - no formatting needed, but still normalize whitespace
                return normalized

            # Insert semicolons after each "by" clause except the last one
            # Check if each is followed by (permissions) by next_clause
            result_parts = []
            last_pos = 0

            for i, (pos, _clause_type) in enumerate(by_clauses):
                # Add text up to this position
                result_parts.append(normalized[last_pos:pos])

                # Check if this is NOT the last clause and is followed by (permissions) by
                if i < len(by_clauses) - 1:
                    # Check what comes after this clause
                    next_text = normalized[pos : min(len(normalized), pos + 100)]
                    # Pattern: space(s) followed by (permissions) followed by space(s) and "by"
                    if re.search(r"^\s+\([^)]+\)\s+by\s+", next_text, re.IGNORECASE):
                        # Add semicolon after the closing quote or *
                        result_parts.append(" ;")

                last_pos = pos

            # Add remaining text
            result_parts.append(normalized[last_pos:])

            formatted = "".join(result_parts)

            # Always return single-line normalized string - writer will handle line folding if needed
            # NEVER preserve newlines - that's the writer's job based on format_options
            return formatted

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
                                FlextLdifConstants.QuirkMetadataKeys.SERVER_TYPE,
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
                                FlextLdifConstants.QuirkMetadataKeys.SERVER_TYPE,
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
                                result = self.parse_entry(dn, current_entry)
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
                        result = self.parse_entry(dn, current_entry)
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
        # Use object.__setattr__ to bypass Pydantic validation for dynamic attributes
        object.__setattr__(self, "schema", self.Schema())
        object.__setattr__(self, "acl", self.Acl())
        object.__setattr__(self, "entry", self.Entry())


__all__ = ["FlextLdifServersOud"]
