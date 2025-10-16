"""Oracle Unified Directory (OUD) Quirks.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Provides OUD-specific quirks for schema, ACL, and entry processing.
"""

from __future__ import annotations

import re
from typing import ClassVar

from flext_core import FlextResult, FlextTypes
from pydantic import Field

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.quirks.base import (
    FlextLdifQuirksBaseAclQuirk,
    FlextLdifQuirksBaseEntryQuirk,
    FlextLdifQuirksBaseSchemaQuirk,
)
from flext_ldif.typings import FlextLdifTypes


class FlextLdifQuirksServersOud(FlextLdifQuirksBaseSchemaQuirk):
    """Oracle OUD schema quirk.

    Extends RFC 4512 schema parsing with Oracle OUD-specific features:
    - OUD namespace (2.16.840.1.113894.*)
    - OUD-specific syntaxes
    - OUD attribute extensions
    - Compatibility with OID schemas

    Example:
        quirk = FlextLdifQuirksServersOud(server_type="oud")
        if quirk.can_handle_attribute(attr_def):
            result = quirk.parse_attribute(attr_def)

    """

    server_type: str = Field(
        default=FlextLdifConstants.ServerTypes.OUD, description="Oracle OUD server type"
    )
    priority: int = Field(
        default=10, description="High priority for OUD-specific parsing"
    )

    # Oracle OUD namespace pattern (same as OID for compatibility)
    ORACLE_OUD_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"2\.16\.840\.1\.113894\."
    )

    def model_post_init(self, _context: object, /) -> None:
        """Initialize OUD schema quirk."""

    def can_handle_attribute(self, attr_definition: str) -> bool:
        """Check if this is an Oracle OUD attribute.

        Args:
            attr_definition: AttributeType definition string

        Returns:
            True if this contains Oracle OUD namespace

        """
        return bool(self.ORACLE_OUD_PATTERN.search(attr_definition))

    def parse_attribute(self, attr_definition: str) -> FlextResult[FlextLdifTypes.Dict]:
        """Parse Oracle OUD attribute definition.

        OUD uses RFC 4512 compliant schema format. Parses the definition
        to extract OID, NAME, DESC, SYNTAX, and other RFC 4512 attributes.

        Args:
            attr_definition: AttributeType definition string

        Returns:
            FlextResult with parsed OUD attribute data

        """
        try:
            # Parse RFC 4512 schema definition
            parsed_data: FlextLdifTypes.Dict = {}

            # Extract OID (first element after opening parenthesis)
            oid_match = re.match(r"\(\s*([0-9.]+)", attr_definition)
            if oid_match:
                parsed_data["oid"] = oid_match.group(1)

            # Extract NAME (single or multiple)
            name_match = re.search(r"NAME\s+(?:\(\s*)?'([^']+)'", attr_definition)
            if name_match:
                parsed_data["name"] = name_match.group(1)

            # Extract DESC
            desc_match = re.search(r"DESC\s+'([^']+)'", attr_definition)
            if desc_match:
                parsed_data["desc"] = desc_match.group(1)

            # Extract SYNTAX
            syntax_match = re.search(
                r"SYNTAX\s+([0-9.]+)(?:\{(\d+)\})?", attr_definition
            )
            if syntax_match:
                parsed_data["syntax"] = syntax_match.group(1)
                if syntax_match.group(2):
                    parsed_data["syntax_length"] = syntax_match.group(2)

            # Extract EQUALITY
            equality_match = re.search(r"EQUALITY\s+(\w+)", attr_definition)
            if equality_match:
                parsed_data["equality"] = equality_match.group(1)

            # Extract SUBSTR
            substr_match = re.search(r"SUBSTR\s+(\w+)", attr_definition)
            if substr_match:
                parsed_data["substr"] = substr_match.group(1)

            # Extract ORDERING
            ordering_match = re.search(r"ORDERING\s+(\w+)", attr_definition)
            if ordering_match:
                parsed_data["ordering"] = ordering_match.group(1)

            # Check for SINGLE-VALUE
            parsed_data["single_value"] = "SINGLE-VALUE" in attr_definition

            # Extract SUP (superior attribute)
            sup_match = re.search(r"SUP\s+(\w+)", attr_definition)
            if sup_match:
                parsed_data["sup"] = sup_match.group(1)

            # Extract X-ORIGIN
            xorigin_match = re.search(r"X-ORIGIN\s+'([^']+)'", attr_definition)
            if xorigin_match:
                parsed_data["x_origin"] = xorigin_match.group(1)

            # Add OUD server type metadata
            parsed_data[FlextLdifConstants.DictKeys.SERVER_TYPE] = "oud"

            # Preserve original format in metadata for perfect round-trip
            parsed_data["_metadata"] = FlextLdifModels.QuirkMetadata.create_for_quirk(
                quirk_type="oud", original_format=attr_definition.strip()
            )

            return FlextResult[FlextLdifTypes.Dict].ok(parsed_data)

        except Exception as e:
            return FlextResult[FlextLdifTypes.Dict].fail(
                f"OUD attribute parsing failed: {e}"
            )

    def can_handle_objectclass(self, oc_definition: str) -> bool:
        """Check if this is an Oracle OUD objectClass.

        Args:
            oc_definition: ObjectClass definition string

        Returns:
            True if this contains Oracle OUD namespace

        """
        return bool(self.ORACLE_OUD_PATTERN.search(oc_definition))

    def parse_objectclass(self, oc_definition: str) -> FlextResult[FlextLdifTypes.Dict]:
        """Parse Oracle OUD objectClass definition.

        OUD uses RFC 4512 compliant schema format. Parses the definition
        to extract OID, NAME, DESC, SUP, KIND, MUST, and MAY attributes.

        Args:
            oc_definition: ObjectClass definition string

        Returns:
            FlextResult with parsed OUD objectClass data

        """
        try:
            # Parse RFC 4512 objectClass definition
            parsed_data: FlextLdifTypes.Dict = {}

            # Extract OID (first element after opening parenthesis)
            oid_match = re.match(r"\(\s*([0-9.]+)", oc_definition)
            if oid_match:
                parsed_data["oid"] = oid_match.group(1)

            # Extract NAME (single or multiple)
            name_match = re.search(r"NAME\s+(?:\(\s*)?'([^']+)'", oc_definition)
            if name_match:
                parsed_data["name"] = name_match.group(1)

            # Extract DESC
            desc_match = re.search(r"DESC\s+'([^']+)'", oc_definition)
            if desc_match:
                parsed_data["desc"] = desc_match.group(1)

            # Extract SUP (superior objectClass)
            sup_match = re.search(
                r"SUP\s+(?:\(\s*([\w\s$]+)\s*\)|(\w+))", oc_definition
            )
            if sup_match:
                sup_value = sup_match.group(1) or sup_match.group(2)
                sup_value = sup_value.strip()
                # Handle multiple superior classes like "organization $ organizationalUnit"
                if "$" in sup_value:
                    parsed_data["sup"] = [s.strip() for s in sup_value.split("$")]
                else:
                    parsed_data["sup"] = sup_value

            # Determine kind (STRUCTURAL, AUXILIARY, ABSTRACT)
            if "STRUCTURAL" in oc_definition:
                parsed_data["kind"] = "STRUCTURAL"
            elif "AUXILIARY" in oc_definition:
                parsed_data["kind"] = "AUXILIARY"
            elif "ABSTRACT" in oc_definition:
                parsed_data["kind"] = "ABSTRACT"

            # Extract MUST attributes
            must_match = re.search(
                r"MUST\s+\(\s*([^)]+)\s*\)|MUST\s+(\w+)", oc_definition
            )
            if must_match:
                must_value = must_match.group(1) or must_match.group(2)
                if "$" in must_value:
                    parsed_data["must"] = [m.strip() for m in must_value.split("$")]
                else:
                    parsed_data["must"] = [must_value.strip()]

            # Extract MAY attributes
            may_match = re.search(r"MAY\s+\(\s*([^)]+)\s*\)|MAY\s+(\w+)", oc_definition)
            if may_match:
                may_value = may_match.group(1) or may_match.group(2)
                if "$" in may_value:
                    parsed_data["may"] = [m.strip() for m in may_value.split("$")]
                else:
                    parsed_data["may"] = [may_value.strip()]

            # Extract X-ORIGIN
            xorigin_match = re.search(r"X-ORIGIN\s+'([^']+)'", oc_definition)
            if xorigin_match:
                parsed_data["x_origin"] = xorigin_match.group(1)

            # Add OUD server type metadata
            parsed_data[FlextLdifConstants.DictKeys.SERVER_TYPE] = "oud"

            # Preserve original format in metadata for perfect round-trip
            parsed_data["_metadata"] = FlextLdifModels.QuirkMetadata.create_for_quirk(
                quirk_type="oud", original_format=oc_definition.strip()
            )

            return FlextResult[FlextLdifTypes.Dict].ok(parsed_data)

        except Exception as e:
            return FlextResult[FlextLdifTypes.Dict].fail(
                f"OUD objectClass parsing failed: {e}"
            )

    def convert_attribute_to_rfc(
        self, attr_data: FlextLdifTypes.Dict
    ) -> FlextResult[FlextLdifTypes.Dict]:
        """Convert OUD attribute to RFC-compliant format.

        OUD attributes are already RFC-compliant, so minimal conversion needed.

        Args:
            attr_data: OUD attribute data

        Returns:
            FlextResult with RFC-compliant attribute data

        """
        try:
            # OUD attributes are RFC-compliant
            rfc_data = {
                FlextLdifConstants.DictKeys.OID: attr_data.get("oid"),
                FlextLdifConstants.DictKeys.NAME: attr_data.get("name"),
                FlextLdifConstants.DictKeys.DESC: attr_data.get("desc"),
                FlextLdifConstants.DictKeys.SYNTAX: attr_data.get("syntax"),
                FlextLdifConstants.DictKeys.EQUALITY: attr_data.get("equality"),
            }

            return FlextResult[FlextLdifTypes.Dict].ok(rfc_data)

        except Exception as e:
            return FlextResult[FlextLdifTypes.Dict].fail(
                f"OUD→RFC conversion failed: {e}"
            )

    def convert_objectclass_to_rfc(
        self, oc_data: FlextLdifTypes.Dict
    ) -> FlextResult[FlextLdifTypes.Dict]:
        """Convert OUD objectClass to RFC-compliant format.

        OUD objectClasses are already RFC-compliant.

        Args:
            oc_data: OUD objectClass data

        Returns:
            FlextResult with RFC-compliant objectClass data

        """
        try:
            # OUD objectClasses are RFC-compliant
            rfc_data = {
                FlextLdifConstants.DictKeys.OID: oc_data.get("oid"),
                FlextLdifConstants.DictKeys.NAME: oc_data.get("name"),
                FlextLdifConstants.DictKeys.DESC: oc_data.get("desc"),
                FlextLdifConstants.DictKeys.SUP: oc_data.get("sup"),
                "kind": oc_data.get("kind"),
                "must": oc_data.get("must"),
                "may": oc_data.get("may"),
            }

            return FlextResult[FlextLdifTypes.Dict].ok(rfc_data)

        except Exception as e:
            return FlextResult[FlextLdifTypes.Dict].fail(
                f"OUD→RFC conversion failed: {e}"
            )

    def write_attribute_to_rfc(
        self, attr_data: FlextLdifTypes.Dict
    ) -> FlextResult[str]:
        """Write OUD attribute data to RFC 4512 compliant string format.

        Converts parsed attribute dictionary back to RFC 4512 schema definition format.
        If metadata contains original_format, uses it for perfect round-trip.

        Args:
            attr_data: Parsed OUD attribute data dictionary

        Returns:
            FlextResult with RFC 4512 formatted attribute definition string

        Example:
            Input: {"oid": "2.16.840.1.113894.1.1.1", "name": "orclGUID", "syntax": "1.3.6.1.4.1.1466.115.121.1.15"}
            Output: "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"

        """
        try:
            # Check if we have metadata with original format for perfect round-trip
            if "_metadata" in attr_data:
                metadata = attr_data["_metadata"]
                if (
                    isinstance(metadata, FlextLdifModels.QuirkMetadata)
                    and metadata.original_format
                ):
                    return FlextResult[str].ok(metadata.original_format)
                if isinstance(metadata, dict) and "original_format" in metadata:
                    return FlextResult[str].ok(str(metadata["original_format"]))

            # Build RFC 4512 attribute definition from scratch
            parts = []

            # Start with OID (required)
            if "oid" not in attr_data:
                return FlextResult[str].fail("Missing required 'oid' field")
            parts.append(f"( {attr_data['oid']}")

            # Add NAME (required)
            if "name" in attr_data:
                parts.append(f"NAME '{attr_data['name']}'")

            # Add DESC (optional)
            if "desc" in attr_data:
                parts.append(f"DESC '{attr_data['desc']}'")

            # Add SUP (optional)
            if "sup" in attr_data:
                parts.append(f"SUP {attr_data['sup']}")

            # Add EQUALITY (optional)
            if "equality" in attr_data:
                parts.append(f"EQUALITY {attr_data['equality']}")

            # Add ORDERING (optional)
            if "ordering" in attr_data:
                parts.append(f"ORDERING {attr_data['ordering']}")

            # Add SUBSTR (optional)
            if "substr" in attr_data:
                parts.append(f"SUBSTR {attr_data['substr']}")

            # Add SYNTAX (optional but common)
            if "syntax" in attr_data:
                syntax_str = str(attr_data["syntax"])
                if "syntax_length" in attr_data:
                    syntax_str += f"{{{attr_data['syntax_length']}}}"
                parts.append(f"SYNTAX {syntax_str}")

            # Add SINGLE-VALUE flag (optional)
            if attr_data.get("single_value", False):
                parts.append("SINGLE-VALUE")

            # Add X-ORIGIN (optional)
            if "x_origin" in attr_data:
                parts.append(f"X-ORIGIN '{attr_data['x_origin']}'")

            # Close the definition
            rfc_string = " ".join(parts) + " )"

            return FlextResult[str].ok(rfc_string)

        except Exception as e:
            return FlextResult[str].fail(f"Failed to write attribute to RFC: {e}")

    def write_objectclass_to_rfc(
        self, oc_data: FlextLdifTypes.Dict
    ) -> FlextResult[str]:
        """Write OUD objectClass data to RFC 4512 compliant string format.

        Converts parsed objectClass dictionary back to RFC 4512 schema definition format.
        If metadata contains original_format, uses it for perfect round-trip.

        Args:
            oc_data: Parsed OUD objectClass data dictionary

        Returns:
            FlextResult with RFC 4512 formatted objectClass definition string

        Example:
            Input: {"oid": "2.16.840.1.113894.2.1.1", "name": "orclContext", "kind": "STRUCTURAL", "must": [FlextLdifConstants.DictKeys.CN], "may": ["description"]}
            Output: "( 2.16.840.1.113894.2.1.1 NAME 'orclContext' STRUCTURAL MUST cn MAY description )"

        """
        try:
            # Check if we have metadata with original format for perfect round-trip
            if "_metadata" in oc_data:
                metadata = oc_data["_metadata"]
                if (
                    isinstance(metadata, FlextLdifModels.QuirkMetadata)
                    and metadata.original_format
                ):
                    return FlextResult[str].ok(metadata.original_format)
                if isinstance(metadata, dict) and "original_format" in metadata:
                    return FlextResult[str].ok(str(metadata["original_format"]))

            # Build RFC 4512 objectClass definition from scratch
            parts = []

            # Start with OID (required)
            if "oid" not in oc_data:
                return FlextResult[str].fail("Missing required 'oid' field")
            parts.append(f"( {oc_data['oid']}")

            # Add NAME (required)
            if "name" in oc_data:
                parts.append(f"NAME '{oc_data['name']}'")

            # Add DESC (optional)
            if "desc" in oc_data:
                parts.append(f"DESC '{oc_data['desc']}'")

            # Add SUP (optional)
            if "sup" in oc_data:
                sup_value = oc_data["sup"]
                if isinstance(sup_value, list):
                    # Multiple superior classes: "SUP ( org $ orgUnit )"
                    sup_str = " $ ".join(sup_value)
                    parts.append(f"SUP ( {sup_str} )")
                else:
                    parts.append(f"SUP {sup_value}")

            # Add KIND (STRUCTURAL, AUXILIARY, ABSTRACT)
            if "kind" in oc_data:
                parts.append(str(oc_data["kind"]))

            # Add MUST attributes (optional)
            if oc_data.get("must"):
                must_attrs = oc_data["must"]
                if isinstance(must_attrs, list) and len(must_attrs) > 1:
                    # Multiple required attributes: "MUST ( cn $ sn )"
                    must_str = " $ ".join(must_attrs)
                    parts.append(f"MUST ( {must_str} )")
                elif isinstance(must_attrs, list) and len(must_attrs) == 1:
                    parts.append(f"MUST {must_attrs[0]}")
                else:
                    parts.append(f"MUST {must_attrs}")

            # Add MAY attributes (optional)
            if oc_data.get("may"):
                may_attrs = oc_data["may"]
                if isinstance(may_attrs, list) and len(may_attrs) > 1:
                    # Multiple optional attributes: "MAY ( description $ seeAlso )"
                    may_str = " $ ".join(may_attrs)
                    parts.append(f"MAY ( {may_str} )")
                elif isinstance(may_attrs, list) and len(may_attrs) == 1:
                    parts.append(f"MAY {may_attrs[0]}")
                else:
                    parts.append(f"MAY {may_attrs}")

            # Add X-ORIGIN (optional)
            if "x_origin" in oc_data:
                parts.append(f"X-ORIGIN '{oc_data['x_origin']}'")

            # Close the definition
            rfc_string = " ".join(parts) + " )"

            return FlextResult[str].ok(rfc_string)

        except Exception as e:
            return FlextResult[str].fail(f"Failed to write objectClass to RFC: {e}")

    def convert_attribute_from_rfc(
        self, rfc_data: FlextLdifTypes.Dict
    ) -> FlextResult[FlextLdifTypes.Dict]:
        """Convert RFC-compliant attribute to OUD-specific format.

        Args:
            rfc_data: RFC-compliant attribute data

        Returns:
            FlextResult with OUD attribute data

        """
        try:
            # Oracle OUD uses RFC-compliant schema format
            # Just ensure OUD server type is set
            oud_data = dict(rfc_data)
            oud_data[FlextLdifConstants.DictKeys.SERVER_TYPE] = (
                FlextLdifConstants.ServerTypes.OUD
            )

            return FlextResult[FlextLdifTypes.Dict].ok(oud_data)

        except Exception as e:
            return FlextResult[FlextLdifTypes.Dict].fail(
                f"RFC→OUD attribute conversion failed: {e}"
            )

    def convert_objectclass_from_rfc(
        self, rfc_data: FlextLdifTypes.Dict
    ) -> FlextResult[FlextLdifTypes.Dict]:
        """Convert RFC-compliant objectClass to OUD-specific format.

        Args:
            rfc_data: RFC-compliant objectClass data

        Returns:
            FlextResult with OUD objectClass data

        """
        try:
            # Oracle OUD uses RFC-compliant schema format
            # Just ensure OUD server type is set
            oud_data = dict(rfc_data)
            oud_data[FlextLdifConstants.DictKeys.SERVER_TYPE] = (
                FlextLdifConstants.ServerTypes.OUD
            )

            return FlextResult[FlextLdifTypes.Dict].ok(oud_data)

        except Exception as e:
            return FlextResult[FlextLdifTypes.Dict].fail(
                f"RFC→OUD objectClass conversion failed: {e}"
            )

    def extract_schemas_from_ldif(
        self, ldif_content: str
    ) -> FlextResult[FlextLdifTypes.Dict]:
        """Extract and parse all schema definitions from LDIF content.

        Strategy pattern: OUD-specific approach to extract attributeTypes and objectClasses
        from cn=schema LDIF entries, handling OUD's case variations.

        Args:
            ldif_content: Raw LDIF content containing schema definitions

        Returns:
            FlextResult with FlextTypes.Dict containing FlextLdifConstants.DictKeys.ATTRIBUTES and 'objectclasses' lists

        """
        try:
            attributes = []
            objectclasses = []

            for raw_line in ldif_content.split("\n"):
                line = raw_line.strip()

                # OUD uses case-insensitive attribute names in LDIF
                # Match: attributeTypes:, attributetypes:, or any case variation
                if line.lower().startswith("attributetypes:"):
                    attr_def = line.split(":", 1)[1].strip()
                    result = self.parse_attribute(attr_def)
                    if result.is_success:
                        attributes.append(result.unwrap())

                # Match: objectClasses:, objectclasses:, or any case variation
                elif line.lower().startswith("objectclasses:"):
                    oc_def = line.split(":", 1)[1].strip()
                    result = self.parse_objectclass(oc_def)
                    if result.is_success:
                        objectclasses.append(result.unwrap())

            return FlextResult[FlextLdifTypes.Dict].ok({
                FlextLdifConstants.DictKeys.ATTRIBUTES: attributes,
                "objectclasses": objectclasses,
            })

        except Exception as e:
            return FlextResult[FlextLdifTypes.Dict].fail(
                f"OUD schema extraction failed: {e}"
            )

    class AclQuirk(FlextLdifQuirksBaseAclQuirk):
        """Oracle OUD ACL quirk (nested).

        Extends RFC ACL parsing with Oracle OUD-specific ACL formats:
        - ds-cfg-access-control-handler: OUD access control
        - OUD-specific ACL syntax (different from OID orclaci)

        Example:
            quirk = FlextLdifQuirksServersOud.AclQuirk(server_type="oud")
            if quirk.can_handle_acl(acl_line):
                result = quirk.parse_acl(acl_line)

        """

        server_type: str = Field(
            default=FlextLdifConstants.ServerTypes.OUD,
            description="Oracle OUD server type",
        )
        priority: int = Field(
            default=10, description="High priority for OUD ACL parsing"
        )

        def model_post_init(self, _context: object, /) -> None:
            """Initialize OUD ACL quirk."""

        def can_handle_acl(self, acl_line: str) -> bool:
            """Check if this is an Oracle OUD ACL.

            Args:
                acl_line: ACL definition line

            Returns:
                True if this is OUD ACL format

            """
            # OUD uses different ACL format than OID
            return acl_line.startswith(("ds-cfg-", "aci:"))

        def parse_acl(self, acl_line: str) -> FlextResult[FlextLdifTypes.Dict]:
            """Parse Oracle OUD ACL definition with multi-line support.

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
                FlextResult with parsed OUD ACL data including metadata

            """
            try:
                # Parse ACI format
                oudacl_data: FlextLdifTypes.Dict = {
                    FlextLdifConstants.DictKeys.TYPE: "oud_acl",
                    FlextLdifConstants.DictKeys.RAW: acl_line,
                    FlextLdifConstants.DictKeys.FORMAT: "ds-cfg"
                    if acl_line.startswith("ds-cfg-")
                    else FlextLdifConstants.AclFormats.ACI,
                }

                # Detect line breaks for multi-line ACIs
                line_breaks = []
                if "\n" in acl_line:
                    current_pos = 0
                    for line_num, line in enumerate(acl_line.split("\n")):
                        if line_num > 0:  # Skip first line
                            line_breaks.append(current_pos)
                        current_pos += len(line) + 1  # +1 for newline

                # Parse ACI components if it's ACI format
                if acl_line.startswith("aci:"):
                    aci_content = acl_line.split(":", 1)[1].strip()

                    # Extract targetattr (what attributes the ACI applies to)
                    targetattr_match = re.search(
                        r'\(targetattr\s*(!?=)\s*"([^"]+)"\)', aci_content
                    )
                    if targetattr_match:
                        oudacl_data["targetattr_op"] = targetattr_match.group(1)
                        oudacl_data["targetattr"] = targetattr_match.group(2)

                    # Extract targetscope
                    targetscope_match = re.search(
                        r'\(targetscope\s*=\s*"([^"]+)"\)', aci_content
                    )
                    if targetscope_match:
                        oudacl_data["targetscope"] = targetscope_match.group(1)

                    # Extract version and ACL name
                    version_match = re.search(
                        r'version\s+([\d.]+);\s*acl\s+"([^"]+)"', aci_content
                    )
                    if version_match:
                        oudacl_data["version"] = version_match.group(1)
                        oudacl_data["acl_name"] = version_match.group(2)

                    # Extract permissions (allow/deny with operations)
                    permission_matches = re.findall(
                        r"(allow|deny)\s+\(([^)]+)\)", aci_content
                    )
                    if permission_matches:
                        permissions = []
                        for action, ops in permission_matches:
                            ops_list = [
                                op.strip() for op in ops.split(",") if op.strip()
                            ]
                            permissions.append({
                                "action": action,
                                "operations": ops_list,
                            })
                        oudacl_data["permissions"] = permissions

                    # Extract bind rules (userdn, groupdn, etc.)

                    # Extract userdn rules
                    userdn_matches = re.findall(r'userdn\s*=\s*"([^"]+)"', aci_content)
                    bind_rules = [
                        {"type": "userdn", "value": userdn} for userdn in userdn_matches
                    ]

                    # Extract groupdn rules
                    groupdn_matches = re.findall(
                        r'groupdn\s*=\s*"([^"]+)"', aci_content
                    )
                    bind_rules.extend(
                        {"type": "groupdn", "value": groupdn}
                        for groupdn in groupdn_matches
                    )

                    if bind_rules:
                        oudacl_data["bind_rules"] = bind_rules

                # Preserve original format in metadata with extensions
                metadata_extensions: FlextTypes.Dict = {}
                if line_breaks:
                    metadata_extensions["line_breaks"] = line_breaks
                    metadata_extensions["is_multiline"] = True

                # Detect DN spaces quirk (spaces after commas in DNs)
                if "bind_rules" in oudacl_data and isinstance(
                    oudacl_data["bind_rules"], list
                ):
                    for rule in oudacl_data["bind_rules"]:
                        if (
                            isinstance(rule, dict)
                            and "value" in rule
                            and ", " in str(rule["value"])
                        ):  # Space after comma
                            metadata_extensions["dn_spaces"] = True
                            break

                oudacl_data["_metadata"] = (
                    FlextLdifModels.QuirkMetadata.create_for_quirk(
                        quirk_type="oud",
                        original_format=acl_line,
                        extensions=metadata_extensions,
                    )
                )

                return FlextResult[FlextLdifTypes.Dict].ok(oudacl_data)

            except Exception as e:
                return FlextResult[FlextLdifTypes.Dict].fail(
                    f"OUD ACL parsing failed: {e}"
                )

        def convert_acl_to_rfc(
            self, acl_data: FlextLdifTypes.Dict
        ) -> FlextResult[FlextLdifTypes.Dict]:
            """Convert OUD ACL to RFC-compliant format.

            Args:
                acl_data: OUD ACL data

            Returns:
                FlextResult with RFC-compliant ACL data

            """
            try:
                # OUD ACLs don't have direct RFC equivalent
                rfc_data: FlextLdifTypes.Dict = {
                    FlextLdifConstants.DictKeys.TYPE: FlextLdifConstants.DictKeys.ACL,
                    FlextLdifConstants.DictKeys.FORMAT: FlextLdifConstants.AclFormats.RFC_GENERIC,
                    FlextLdifConstants.DictKeys.SOURCE_FORMAT: FlextLdifConstants.AclFormats.OUD_ACL,
                    FlextLdifConstants.DictKeys.DATA: acl_data,
                }

                return FlextResult[FlextLdifTypes.Dict].ok(rfc_data)

            except Exception as e:
                return FlextResult[FlextLdifTypes.Dict].fail(
                    f"OUD ACL→RFC conversion failed: {e}"
                )

        def convert_acl_from_rfc(
            self, acl_data: FlextLdifTypes.Dict
        ) -> FlextResult[FlextLdifTypes.Dict]:
            """Convert RFC ACL to OUD-specific format.

            Args:
                acl_data: RFC-compliant ACL data

            Returns:
                FlextResult with OUD ACL data

            """
            try:
                # Convert RFC ACL to Oracle OUD format
                oud_data: FlextLdifTypes.Dict = {
                    FlextLdifConstants.DictKeys.FORMAT: FlextLdifConstants.AclFormats.OUD_ACL,
                    FlextLdifConstants.DictKeys.TARGET_FORMAT: "ds-cfg",
                    FlextLdifConstants.DictKeys.DATA: acl_data,
                }

                return FlextResult[FlextLdifTypes.Dict].ok(oud_data)

            except Exception as e:
                return FlextResult[FlextLdifTypes.Dict].fail(
                    f"RFC→OUD ACL conversion failed: {e}"
                )

        def write_acl_to_rfc(self, acl_data: FlextLdifTypes.Dict) -> FlextResult[str]:
            """Write OUD ACL data to ACI string format with multi-line support.

            Converts parsed ACL dictionary back to ACI format string.
            If metadata contains original_format, uses it for perfect round-trip.

            Handles multi-line ACIs with:
            - Proper indentation for continuation lines
            - Multiple permission rules (4+ rules per ACI)
            - DN formatting preservation (spaces after commas)

            Args:
                acl_data: Parsed OUD ACL data dictionary

            Returns:
                FlextResult with ACI formatted string

            Example:
                Input: {"targetattr": "*", "acl_name": "Test ACL", "permissions": [...]}
                Output: '(targetattr="*")(version 3.0; acl "Test ACL"; allow (read,search) userdn="ldap:///anyone";)'

            """
            try:
                # Check if we have metadata with original format for perfect round-trip
                if "_metadata" in acl_data:
                    metadata = acl_data["_metadata"]
                    if (
                        isinstance(metadata, FlextLdifModels.QuirkMetadata)
                        and metadata.original_format
                    ):
                        return FlextResult[str].ok(metadata.original_format)
                    if isinstance(metadata, dict) and "original_format" in metadata:
                        return FlextResult[str].ok(str(metadata["original_format"]))

                # Build ACI from scratch
                if acl_data.get("format") == "ds-cfg":
                    # ds-cfg format (different from ACI)
                    return FlextResult[str].ok(str(acl_data.get("raw", "")))

                # Build ACI format: (targetattr="*")(version 3.0; acl "name"; permissions)
                aci_parts = []

                # Target attributes
                if "targetattr" in acl_data:
                    targetattr_op = acl_data.get("targetattr_op", "=")
                    aci_parts.append(
                        f'(targetattr{targetattr_op}"{acl_data["targetattr"]}")'
                    )

                # Target scope (optional)
                if "targetscope" in acl_data:
                    aci_parts.append(f'(targetscope="{acl_data["targetscope"]}")')

                # Version and ACL name
                version = acl_data.get("version", "3.0")
                acl_name = acl_data.get("acl_name", "Generated ACL")
                aci_parts.append(f'(version {version}; acl "{acl_name}";')

                # Permissions and bind rules
                permissions = acl_data.get("permissions", [])
                bind_rules = acl_data.get("bind_rules", [])

                # Check if this is a multi-line ACI
                is_multiline = False
                if "_metadata" in acl_data:
                    metadata = acl_data["_metadata"]
                    if isinstance(metadata, FlextLdifModels.QuirkMetadata):
                        multiline_value = metadata.extensions.get("is_multiline", False)
                        is_multiline = (
                            bool(multiline_value)
                            if isinstance(multiline_value, bool)
                            else False
                        )
                    elif isinstance(metadata, dict):
                        is_multiline = metadata.get("extensions", {}).get(
                            "is_multiline", False
                        )

                # Build permission rules
                permission_lines: FlextTypes.StringList = []
                if permissions and bind_rules:
                    # Match permissions with bind rules
                    if isinstance(permissions, list) and isinstance(bind_rules, list):
                        for i, perm in enumerate(permissions):
                            if i < len(bind_rules) and isinstance(perm, dict):
                                action = perm.get("action", "allow")
                                ops = perm.get("operations", [])
                                if isinstance(ops, list):
                                    ops_str = ",".join(str(op) for op in ops)
                                else:
                                    ops_str = str(ops)

                                rule = bind_rules[i]
                                if isinstance(rule, dict):
                                    rule_type = rule.get("type", "userdn")
                                    rule_value = rule.get("value", "")

                                    permission_line = f'{action} ({ops_str}) {rule_type}="{rule_value}";'
                                    permission_lines.append(permission_line)
                elif isinstance(permissions, list):
                    # Generic permission handling
                    for perm in permissions:
                        if isinstance(perm, dict):
                            action = perm.get("action", "allow")
                            ops = perm.get("operations", [])
                            if isinstance(ops, list):
                                ops_str = ",".join(str(op) for op in ops)
                            else:
                                ops_str = str(ops)
                            permission_lines.append(f"{action} ({ops_str});")

                # Format output (multi-line vs single-line)
                if is_multiline and len(permission_lines) > 1:
                    # Multi-line format with indentation
                    result_lines = [aci_parts[0]]  # First line (targetattr)
                    if len(aci_parts) > 1:
                        # Version and ACL name on first line
                        result_lines[0] += f" {aci_parts[1]}"

                    # Add permission lines with indentation (6 spaces typical)
                    result_lines.extend(
                        f"      {perm_line}" for perm_line in permission_lines
                    )

                    # Close the ACI
                    result_lines[-1] = result_lines[-1].rstrip(";") + ")"

                    aci_string = "\n".join(result_lines)
                else:
                    # Single-line format
                    aci_string = " ".join(aci_parts)
                    for perm_line in permission_lines:
                        aci_string += f" {perm_line}"
                    aci_string += ")"

                return FlextResult[str].ok(aci_string)

            except Exception as e:
                return FlextResult[str].fail(f"Failed to write ACL to RFC: {e}")

        def extract_acls_from_ldif(
            self, ldif_content: str
        ) -> FlextResult[list[FlextLdifTypes.Dict]]:
            """Extract and parse all ACL definitions from LDIF content.

            Strategy pattern: OUD-specific approach to extract ACIs from LDIF entries.

            Args:
                ldif_content: Raw LDIF content containing ACL definitions

            Returns:
                FlextResult with list of parsed ACL dictionaries

            """
            try:
                acls = []
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
                        # Check if this ACI continues on next lines (no closing parenthesis)
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

                return FlextResult[list[FlextLdifTypes.Dict]].ok(acls)

            except Exception as e:
                return FlextResult[list[FlextLdifTypes.Dict]].fail(
                    f"OUD ACL extraction failed: {e}"
                )

    class EntryQuirk(FlextLdifQuirksBaseEntryQuirk):
        """Oracle OUD entry quirk (nested).

        Handles OUD-specific entry transformations:
        - OUD-specific operational attributes
        - OUD entry formatting
        - Compatibility with OID entries

        Example:
            quirk = FlextLdifQuirksServersOud.EntryQuirk(server_type="oud")
            if quirk.can_handle_entry(dn, attributes):
                result = quirk.process_entry(dn, attributes)

        """

        server_type: str = Field(
            default=FlextLdifConstants.ServerTypes.OUD,
            description="Oracle OUD server type",
        )
        priority: int = Field(
            default=10, description="High priority for OUD entry processing"
        )

        def model_post_init(self, _context: object, /) -> None:
            """Initialize OUD entry quirk."""

        def can_handle_entry(self, entry_dn: str, attributes: FlextTypes.Dict) -> bool:
            """Check if this quirk should handle the entry.

            Args:
                entry_dn: Entry distinguished name
                attributes: Entry attributes

            Returns:
                True if this is an OUD-specific entry

            """
            # Handle all entries for OUD target
            # Can add specific OUD entry detection logic here
            _ = entry_dn
            _ = attributes
            return True

        # Oracle OUD boolean attributes that expect TRUE/FALSE instead of 0/1
        BOOLEAN_ATTRIBUTES: ClassVar[set[str]] = {
            "pwdlockout",
            "pwdmustchange",
            "pwdallowuserchange",
            "pwdexpirewarning",
            "pwdgraceauthnlimit",
            "pwdlockoutduration",
            "pwdmaxfailure",
            "pwdminage",
            "pwdmaxage",
            "pwdmaxlength",
            "pwdminlength",
        }

        def process_entry(
            self, entry_dn: str, attributes: dict[str, list[str]] | FlextTypes.Dict
        ) -> FlextResult[FlextLdifTypes.Dict]:
            """Process entry for OUD format with metadata preservation.

            Handles OUD-specific transformations:
            - Boolean attributes: Convert 0/1 to TRUE/FALSE for OUD compatibility

            Args:
                entry_dn: Entry distinguished name
                attributes: Entry attributes

            Returns:
                FlextResult with processed entry data including metadata

            """
            try:
                # OUD entries are RFC-compliant
                # Add OUD-specific processing for boolean attributes
                processed_entry: FlextLdifTypes.Dict = {
                    FlextLdifConstants.DictKeys.DN: entry_dn,
                    FlextLdifConstants.DictKeys.SERVER_TYPE: "oud",
                }

                # Process attributes with boolean conversion
                for attr_name, attr_values in attributes.items():
                    # Check if this is a boolean attribute that needs conversion
                    if attr_name.lower() in self.BOOLEAN_ATTRIBUTES:
                        # Convert 0/1 to TRUE/FALSE for OUD
                        if isinstance(attr_values, list):
                            converted_values = []
                            for val in attr_values:
                                str_val = str(val).strip()
                                if str_val == "0":
                                    converted_values.append("FALSE")
                                elif str_val == "1":
                                    converted_values.append("TRUE")
                                else:
                                    # Already TRUE/FALSE or other value
                                    converted_values.append(val)
                            processed_entry[attr_name] = converted_values
                        else:
                            # Single value
                            str_val = str(attr_values).strip()
                            if str_val == "0":
                                processed_entry[attr_name] = "FALSE"
                            elif str_val == "1":
                                processed_entry[attr_name] = "TRUE"
                            else:
                                processed_entry[attr_name] = attr_values
                    else:
                        # Non-boolean attribute, copy as-is
                        processed_entry[attr_name] = attr_values

                # Preserve metadata for DN quirks and attribute ordering
                metadata_extensions: FlextTypes.Dict = {}

                # Detect DN spaces quirk (spaces after commas)
                if ", " in entry_dn:
                    metadata_extensions["dn_spaces"] = True

                # Preserve attribute ordering
                if attributes:
                    attr_order: FlextTypes.StringList = list(attributes.keys())
                    metadata_extensions["attribute_order"] = attr_order

                # Detect Oracle-specific objectClasses
                if FlextLdifConstants.DictKeys.OBJECTCLASS in attributes:
                    oc_values = attributes[FlextLdifConstants.DictKeys.OBJECTCLASS]
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
                            metadata_extensions["oracle_objectclasses"] = oracle_ocs

                processed_entry["_metadata"] = (
                    FlextLdifModels.QuirkMetadata.create_for_quirk(
                        quirk_type="oud", extensions=metadata_extensions
                    )
                )

                return FlextResult[FlextLdifTypes.Dict].ok(processed_entry)

            except Exception as e:
                return FlextResult[FlextLdifTypes.Dict].fail(
                    f"OUD entry processing failed: {e}"
                )

        def convert_entry_to_rfc(
            self, entry_data: FlextLdifTypes.Dict
        ) -> FlextResult[FlextLdifTypes.Dict]:
            """Convert server-specific entry to RFC-compliant format.

            Args:
                entry_data: Server-specific entry data

            Returns:
                FlextResult with RFC-compliant entry data

            """
            try:
                # OUD entries are already RFC-compliant
                return FlextResult[FlextLdifTypes.Dict].ok(entry_data)
            except Exception as e:
                return FlextResult[FlextLdifTypes.Dict].fail(
                    f"OUD entry→RFC conversion failed: {e}"
                )

        def convert_entry_from_rfc(
            self, entry_data: FlextLdifTypes.Dict
        ) -> FlextResult[FlextLdifTypes.Dict]:
            """Convert RFC-compliant entry to OUD-specific format.

            Args:
                entry_data: RFC-compliant entry data

            Returns:
                FlextResult with OUD entry data

            """
            try:
                # Oracle OUD uses RFC-compliant format
                # Just ensure OUD server type is set
                oud_entry = dict(entry_data)
                oud_entry[FlextLdifConstants.DictKeys.SERVER_TYPE] = (
                    FlextLdifConstants.ServerTypes.OUD
                )

                return FlextResult[FlextLdifTypes.Dict].ok(oud_entry)

            except Exception as e:
                return FlextResult[FlextLdifTypes.Dict].fail(
                    f"RFC→OUD entry conversion failed: {e}"
                )

        def write_entry_to_ldif(
            self, entry_data: FlextLdifTypes.Dict
        ) -> FlextResult[str]:
            r"""Write OUD entry data to standard LDIF string format.

            Converts parsed entry dictionary to LDIF format string.
            Handles Oracle-specific attributes and preserves DN formatting.

            Args:
                entry_data: Parsed OUD entry data dictionary

            Returns:
                FlextResult with LDIF formatted entry string

            Example:
                Input: {FlextLdifConstants.DictKeys.DN: "cn=test,dc=example,dc=com", FlextLdifConstants.DictKeys.CN: ["test"], FlextLdifConstants.DictKeys.OBJECTCLASS: ["person"]}
                Output: "dn: cn=test,dc=example,dc=com\\ncn: test\\nobjectClass: person\\n"

            """
            try:
                # Check for required DN field
                if FlextLdifConstants.DictKeys.DN not in entry_data:
                    return FlextResult[str].fail(
                        "Missing required FlextLdifConstants.DictKeys.DN field"
                    )

                dn = entry_data[FlextLdifConstants.DictKeys.DN]
                ldif_lines = [f"dn: {dn}"]

                # Get attribute ordering from metadata if available
                attr_order = None
                if "_metadata" in entry_data:
                    metadata = entry_data["_metadata"]
                    if isinstance(metadata, FlextLdifModels.QuirkMetadata):
                        attr_order = metadata.extensions.get("attribute_order")
                    elif isinstance(metadata, dict):
                        attr_order = metadata.get("extensions", {}).get(
                            "attribute_order"
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
                        }
                    ]

                # Write attributes
                # SAFETY: Filter out DN if it somehow appears in attributes
                for attr_name, attr_value in attrs_to_process:
                    # CRITICAL: DN is NOT an attribute - skip if present
                    if attr_name.lower() == FlextLdifConstants.DictKeys.DN:
                        continue
                    # Handle both list and single values
                    if isinstance(attr_value, list):
                        ldif_lines.extend(
                            f"{attr_name}: {value}" for value in attr_value
                        )
                    else:
                        ldif_lines.append(f"{attr_name}: {attr_value}")

                # Join with newlines and add trailing newline
                ldif_string = "\n".join(ldif_lines) + "\n"

                return FlextResult[str].ok(ldif_string)

            except Exception as e:
                return FlextResult[str].fail(f"Failed to write entry to LDIF: {e}")

        def extract_entries_from_ldif(
            self, ldif_content: str
        ) -> FlextResult[list[FlextLdifTypes.Dict]]:
            """Extract and parse all directory entries from LDIF content.

            Strategy pattern: OUD-specific approach to extract entries from LDIF.

            Args:
                ldif_content: Raw LDIF content containing directory entries

            Returns:
                FlextResult with list of parsed entry dictionaries

            """
            try:
                entries = []
                current_entry: FlextLdifTypes.Dict = {}
                current_attr: str | None = None
                current_values: FlextTypes.StringList = []

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
                                    current_entry.pop(FlextLdifConstants.DictKeys.DN)
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

                        # Handle base64 encoding (::)
                        if attr_value.startswith(":"):
                            attr_value = attr_value[1:].strip()
                            # Note: Not decoding base64 here, just storing raw

                        # Check if this attribute already exists (multi-valued)
                        if attr_name in current_entry:
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

                return FlextResult[list[FlextLdifTypes.Dict]].ok(entries)

            except Exception as e:
                return FlextResult[list[FlextLdifTypes.Dict]].fail(
                    f"OUD entry extraction failed: {e}"
                )


__all__ = ["FlextLdifQuirksServersOud"]
