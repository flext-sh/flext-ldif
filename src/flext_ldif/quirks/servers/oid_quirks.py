"""Oracle Internet Directory (OID) Quirks.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Implements Oracle OID-specific extensions as quirks on top of RFC-compliant
base parsers. This wraps existing OID parser logic as composable quirks.

OID-specific features:
- Oracle OID attribute types (2.16.840.1.113894.* namespace)
- Oracle orclaci and orclentrylevelaci ACLs
- Oracle-specific schema attributes
- Oracle operational attributes
"""

from __future__ import annotations

import re
from typing import ClassVar

from flext_core import FlextResult
from pydantic import Field

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.quirks.base import (
    FlextLdifQuirksBaseAclQuirk,
    FlextLdifQuirksBaseEntryQuirk,
    FlextLdifQuirksBaseSchemaQuirk,
)
from flext_ldif.typings import FlextLdifTypes


class FlextLdifQuirksServersOid(FlextLdifQuirksBaseSchemaQuirk):
    """Oracle OID schema quirk.

    Extends RFC 4512 schema parsing with Oracle OID-specific features:
    - Oracle OID namespace (2.16.840.1.113894.*)
    - Oracle-specific syntaxes
    - Oracle attribute extensions

    Example:
        quirk = FlextLdifQuirksServersOid(server_type="oid")
        if quirk.can_handle_attribute(attr_def):
            result = quirk.parse_attribute(attr_def)

    """

    server_type: str = Field(
        default=FlextLdifConstants.ServerTypes.OID,
        description="Oracle OID server type",
    )
    priority: int = Field(
        default=10, description="High priority for OID-specific parsing"
    )

    # Oracle OID namespace pattern
    ORACLE_OID_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"2\.16\.840\.1\.113894\."
    )

    def model_post_init(self, _context: object, /) -> None:
        """Initialize OID schema quirk."""

    def can_handle_attribute(self, attr_definition: str) -> bool:
        """Check if this is an Oracle OID attribute.

        Args:
            attr_definition: AttributeType definition string

        Returns:
            True if this contains Oracle OID namespace

        """
        return bool(self.ORACLE_OID_PATTERN.search(attr_definition))

    def parse_attribute(self, attr_definition: str) -> FlextResult[FlextLdifTypes.Dict]:
        """Parse Oracle OID attribute definition.

        OID uses RFC 4512 compliant schema format. Parses the definition
        to extract OID, NAME, DESC, SYNTAX, and other RFC 4512 attributes.

        Args:
            attr_definition: AttributeType definition string
                            (without "attributetypes:" prefix)

        Returns:
            FlextResult with parsed OID attribute data with metadata

        """
        try:
            # Parse RFC 4512 schema definition (same approach as OUD)
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
                r"SYNTAX\s+'?([0-9.]+)(?:\{(\d+)\})?'?", attr_definition
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

            # Check for NO-USER-MODIFICATION
            parsed_data["no_user_mod"] = "NO-USER-MODIFICATION" in attr_definition

            # Extract SUP (superior attribute)
            sup_match = re.search(r"SUP\s+(\w+)", attr_definition)
            if sup_match:
                parsed_data["sup"] = sup_match.group(1)

            # Extract USAGE
            usage_match = re.search(r"USAGE\s+(\w+)", attr_definition)
            if usage_match:
                parsed_data["usage"] = usage_match.group(1)

            # Add OID server type metadata
            parsed_data[FlextLdifConstants.DictKeys.SERVER_TYPE] = "oid"

            # Add metadata for perfect round-trip preservation
            parsed_data["_metadata"] = FlextLdifModels.QuirkMetadata.create_for_quirk(
                quirk_type="oid",
                original_format=attr_definition.strip()
            )

            return FlextResult[FlextLdifTypes.Dict].ok(parsed_data)

        except Exception as e:
            return FlextResult[FlextLdifTypes.Dict].fail(
                f"OID attribute parsing failed: {e}"
            )

    def can_handle_objectclass(self, oc_definition: str) -> bool:
        """Check if this is an Oracle OID objectClass.

        Args:
            oc_definition: ObjectClass definition string

        Returns:
            True if this contains Oracle OID namespace

        """
        return bool(self.ORACLE_OID_PATTERN.search(oc_definition))

    def parse_objectclass(self, oc_definition: str) -> FlextResult[FlextLdifTypes.Dict]:
        """Parse Oracle OID objectClass definition.

        OID uses RFC 4512 compliant schema format. Parses the definition
        to extract OID, NAME, DESC, SUP, KIND, MUST, and MAY attributes.

        Args:
            oc_definition: ObjectClass definition string
                          (without "objectclasses:" prefix)

        Returns:
            FlextResult with parsed OID objectClass data with metadata

        """
        try:
            # Parse RFC 4512 objectClass definition (same approach as OUD)
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

            # Add OID server type metadata
            parsed_data[FlextLdifConstants.DictKeys.SERVER_TYPE] = "oid"

            # Add metadata for perfect round-trip preservation
            parsed_data["_metadata"] = FlextLdifModels.QuirkMetadata.create_for_quirk(
                quirk_type="oid",
                original_format=oc_definition.strip()
            )

            return FlextResult[FlextLdifTypes.Dict].ok(parsed_data)

        except Exception as e:
            return FlextResult[FlextLdifTypes.Dict].fail(
                f"OID objectClass parsing failed: {e}"
            )

    def convert_attribute_to_rfc(
        self, attr_data: FlextLdifTypes.Dict
    ) -> FlextResult[FlextLdifTypes.Dict]:
        """Convert OID attribute to RFC-compliant format.

        Args:
            attr_data: OID attribute data

        Returns:
            FlextResult with RFC-compliant attribute data

        """
        try:
            # Oracle OID attributes can be represented in RFC format
            # by removing Oracle-specific extensions
            rfc_data = {
                FlextLdifConstants.DictKeys.OID: attr_data.get(
                    FlextLdifConstants.DictKeys.OID
                ),
                FlextLdifConstants.DictKeys.NAME: attr_data.get(
                    FlextLdifConstants.DictKeys.NAME
                ),
                FlextLdifConstants.DictKeys.DESC: attr_data.get(
                    FlextLdifConstants.DictKeys.DESC
                ),
                FlextLdifConstants.DictKeys.SYNTAX: attr_data.get(
                    FlextLdifConstants.DictKeys.SYNTAX
                ),
                FlextLdifConstants.DictKeys.EQUALITY: attr_data.get(
                    FlextLdifConstants.DictKeys.EQUALITY
                ),
            }

            return FlextResult[FlextLdifTypes.Dict].ok(rfc_data)

        except Exception as e:
            return FlextResult[FlextLdifTypes.Dict].fail(
                f"OID→RFC conversion failed: {e}"
            )

    def convert_objectclass_to_rfc(
        self, oc_data: FlextLdifTypes.Dict
    ) -> FlextResult[FlextLdifTypes.Dict]:
        """Convert OID objectClass to RFC-compliant format.

        Args:
            oc_data: OID objectClass data

        Returns:
            FlextResult with RFC-compliant objectClass data

        """
        try:
            # Convert Oracle OID objectClass to RFC format
            rfc_data = {
                FlextLdifConstants.DictKeys.OID: oc_data.get(
                    FlextLdifConstants.DictKeys.OID
                ),
                FlextLdifConstants.DictKeys.NAME: oc_data.get(
                    FlextLdifConstants.DictKeys.NAME
                ),
                FlextLdifConstants.DictKeys.DESC: oc_data.get(
                    FlextLdifConstants.DictKeys.DESC
                ),
                FlextLdifConstants.DictKeys.SUP: oc_data.get(
                    FlextLdifConstants.DictKeys.SUP
                ),
                FlextLdifConstants.DictKeys.KIND: oc_data.get(
                    FlextLdifConstants.DictKeys.KIND
                ),
                FlextLdifConstants.DictKeys.MUST: oc_data.get(
                    FlextLdifConstants.DictKeys.MUST
                ),
                FlextLdifConstants.DictKeys.MAY: oc_data.get(
                    FlextLdifConstants.DictKeys.MAY
                ),
            }

            return FlextResult[FlextLdifTypes.Dict].ok(rfc_data)

        except Exception as e:
            return FlextResult[FlextLdifTypes.Dict].fail(
                f"OID→RFC conversion failed: {e}"
            )

    def write_attribute_to_rfc(
        self, attr_data: FlextLdifTypes.Dict
    ) -> FlextResult[str]:
        """Write OID attribute data to RFC 4512 compliant string format.

        Converts parsed attribute dictionary back to RFC 4512 schema definition format.
        If metadata contains original_format, uses it for perfect round-trip.

        Args:
            attr_data: Parsed OID attribute data dictionary

        Returns:
            FlextResult with RFC 4512 formatted attribute definition string

        Example:
            Input: {"oid": "2.16.840.1.113894.1.1.1", "name": "orclguid", "syntax": "1.3.6.1.4.1.1466.115.121.1.15"}
            Output: "( 2.16.840.1.113894.1.1.1 NAME 'orclguid' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"

        """
        try:
            # Check if we have metadata with original format for perfect round-trip
            if "_metadata" in attr_data:
                metadata = attr_data["_metadata"]
                if isinstance(metadata, FlextLdifModels.QuirkMetadata) and metadata.original_format:
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
                syntax_str = str(attr_data['syntax'])
                if "syntax_length" in attr_data:
                    syntax_str += f"{{{attr_data['syntax_length']}}}"
                parts.append(f"SYNTAX {syntax_str}")

            # Add SINGLE-VALUE flag (optional)
            if attr_data.get("single_value", False):
                parts.append("SINGLE-VALUE")

            # Add NO-USER-MODIFICATION flag (optional)
            if attr_data.get("no_user_mod", False):
                parts.append("NO-USER-MODIFICATION")

            # Add USAGE (optional)
            if "usage" in attr_data:
                parts.append(f"USAGE {attr_data['usage']}")

            # Add X-ORIGIN (optional)
            if "x_origin" in attr_data:
                parts.append(f"X-ORIGIN '{attr_data['x_origin']}'")

            # Close the definition
            rfc_string = " ".join(parts) + " )"

            return FlextResult[str].ok(rfc_string)

        except Exception as e:
            return FlextResult[str].fail(f"Failed to write OID attribute to RFC: {e}")

    def write_objectclass_to_rfc(
        self, oc_data: FlextLdifTypes.Dict
    ) -> FlextResult[str]:
        """Write OID objectClass data to RFC 4512 compliant string format.

        Converts parsed objectClass dictionary back to RFC 4512 schema definition format.
        If metadata contains original_format, uses it for perfect round-trip.

        Args:
            oc_data: Parsed OID objectClass data dictionary

        Returns:
            FlextResult with RFC 4512 formatted objectClass definition string

        Example:
            Input: {"oid": "2.16.840.1.113894.2.1.1", "name": "orclContainer", "kind": "STRUCTURAL", "must": ["cn"], "may": ["description"]}
            Output: "( 2.16.840.1.113894.2.1.1 NAME 'orclContainer' STRUCTURAL MUST cn MAY description )"

        """
        try:
            # Check if we have metadata with original format for perfect round-trip
            if "_metadata" in oc_data:
                metadata = oc_data["_metadata"]
                if isinstance(metadata, FlextLdifModels.QuirkMetadata) and metadata.original_format:
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
            return FlextResult[str].fail(f"Failed to write OID objectClass to RFC: {e}")

    def extract_schemas_from_ldif(
        self, ldif_content: str
    ) -> FlextResult[FlextLdifTypes.Dict]:
        """Extract and parse all schema definitions from LDIF content.

        Strategy pattern: OID-specific approach to extract attributeTypes and objectClasses
        from cn=schema LDIF entries, handling OID's format variations.

        Args:
            ldif_content: Raw LDIF content containing schema definitions

        Returns:
            FlextResult with dict containing 'attributes' and 'objectclasses' lists

        """
        try:
            attributes = []
            objectclasses = []

            for raw_line in ldif_content.split('\n'):
                line = raw_line.strip()
                
                # OID uses case-insensitive attribute names in LDIF
                # Match: attributeTypes:, attributetypes:, or any case variation
                if line.lower().startswith('attributetypes:'):
                    attr_def = line.split(':', 1)[1].strip()
                    result = self.parse_attribute(attr_def)
                    if result.is_success:
                        attributes.append(result.unwrap())
                
                # Match: objectClasses:, objectclasses:, or any case variation
                elif line.lower().startswith('objectclasses:'):
                    oc_def = line.split(':', 1)[1].strip()
                    result = self.parse_objectclass(oc_def)
                    if result.is_success:
                        objectclasses.append(result.unwrap())

            return FlextResult[FlextLdifTypes.Dict].ok({
                "attributes": attributes,
                "objectclasses": objectclasses
            })

        except Exception as e:
            return FlextResult[FlextLdifTypes.Dict].fail(
                f"OID schema extraction failed: {e}"
            )

    def convert_attribute_from_rfc(
        self, rfc_data: FlextLdifTypes.Dict
    ) -> FlextResult[FlextLdifTypes.Dict]:
        """Convert RFC-compliant attribute to OID-specific format.

        Args:
            rfc_data: RFC-compliant attribute data

        Returns:
            FlextResult with OID attribute data

        """
        try:
            # Oracle OID uses RFC-compliant schema format
            # Just ensure OID server type is set
            oid_data = dict(rfc_data)
            oid_data[FlextLdifConstants.DictKeys.SERVER_TYPE] = FlextLdifConstants.ServerTypes.OID

            return FlextResult[FlextLdifTypes.Dict].ok(oid_data)

        except Exception as e:
            return FlextResult[FlextLdifTypes.Dict].fail(
                f"RFC→OID attribute conversion failed: {e}"
            )

    def convert_objectclass_from_rfc(
        self, rfc_data: FlextLdifTypes.Dict
    ) -> FlextResult[FlextLdifTypes.Dict]:
        """Convert RFC-compliant objectClass to OID-specific format.

        Args:
            rfc_data: RFC-compliant objectClass data

        Returns:
            FlextResult with OID objectClass data

        """
        try:
            # Oracle OID uses RFC-compliant schema format
            # Just ensure OID server type is set
            oid_data = dict(rfc_data)
            oid_data[FlextLdifConstants.DictKeys.SERVER_TYPE] = FlextLdifConstants.ServerTypes.OID

            return FlextResult[FlextLdifTypes.Dict].ok(oid_data)

        except Exception as e:
            return FlextResult[FlextLdifTypes.Dict].fail(
                f"RFC→OID objectClass conversion failed: {e}"
            )

    class AclQuirk(FlextLdifQuirksBaseAclQuirk):
        """Oracle OID ACL quirk (nested).

        Extends RFC ACL parsing with Oracle OID-specific ACL formats:
        - orclaci: Oracle standard ACIs
        - orclentrylevelaci: Oracle entry-level ACIs

        Example:
            quirk = FlextLdifQuirksServersOid.AclQuirk(server_type="oid")
            if quirk.can_handle_acl(acl_line):
                result = quirk.parse_acl(acl_line)

        """

        server_type: str = Field(
            default=FlextLdifConstants.ServerTypes.OID,
            description="Oracle OID server type",
        )
        priority: int = Field(
            default=10, description="High priority for OID ACL parsing"
        )

        def model_post_init(self, _context: object, /) -> None:
            """Initialize OID ACL quirk."""

        def can_handle_acl(self, acl_line: str) -> bool:
            """Check if this is an Oracle OID ACL.

            Args:
                acl_line: ACL definition line

            Returns:
                True if this is orclaci or orclentrylevelaci

            """
            return acl_line.startswith(("orclaci:", "orclentrylevelaci:"))

        def parse_acl(self, acl_line: str) -> FlextResult[FlextLdifTypes.Dict]:
            """Parse Oracle OID ACL definition.

            Parses orclaci and orclentrylevelaci formats from real OID fixtures:
            - orclaci: access to entry/attr=(...) [filter=(...)] by <subject> (<perms>) [by ...]
            - orclentrylevelaci: access to entry by <subject> [added_object_constraint=(...)] (<perms>)

            Args:
                acl_line: ACL definition line

            Returns:
                FlextResult with parsed OID ACL data with metadata

            """
            try:
                # Determine ACL type
                is_entry_level = acl_line.startswith("orclentrylevelaci:")
                acl_content = acl_line.split(":", 1)[1].strip() if ":" in acl_line else acl_line

                acl_data: FlextLdifTypes.Dict = {
                    FlextLdifConstants.DictKeys.TYPE: (
                        FlextLdifConstants.DictKeys.ENTRY_LEVEL
                        if is_entry_level
                        else FlextLdifConstants.DictKeys.STANDARD
                    ),
                    FlextLdifConstants.DictKeys.RAW: acl_line,
                    FlextLdifConstants.DictKeys.FORMAT: FlextLdifConstants.AclFormats.OID_ACL,
                }

                # Extract target (entry or attr)
                if "access to entry" in acl_content:
                    acl_data["target"] = "entry"
                elif "access to attr=" in acl_content:
                    attr_match = re.search(r"access to attr=\(([^)]+)\)", acl_content)
                    if attr_match:
                        acl_data["target"] = "attr"
                        acl_data["target_attrs"] = attr_match.group(1)

                # Extract filter (if present)
                filter_match = re.search(r"filter=(\([^)]+(?:\([^)]*\))*[^)]*\))", acl_content)
                if filter_match:
                    acl_data["filter"] = filter_match.group(1)

                # Extract added_object_constraint (for orclentrylevelaci)
                constraint_match = re.search(
                    r"added_object_constraint=(\([^)]+(?:\([^)]*\))*[^)]*\))", acl_content
                )
                if constraint_match:
                    acl_data["added_object_constraint"] = constraint_match.group(1)

                # Extract "by" clauses with subjects and permissions
                # Pattern: by <subject> (<permissions>)
                by_clauses = []
                by_pattern = r'by\s+(group="[^"]+"|\*|[^\s(]+)\s+\(([^)]+)\)'
                for match in re.finditer(by_pattern, acl_content):
                    subject = match.group(1).strip()
                    permissions = match.group(2).strip()

                    by_clauses.append({
                        "subject": subject,
                        "permissions": [p.strip() for p in permissions.split(",")]
                    })

                if by_clauses:
                    acl_data["by_clauses"] = by_clauses

                # Add metadata for perfect round-trip preservation
                acl_data["_metadata"] = FlextLdifModels.QuirkMetadata.create_for_quirk(
                    quirk_type="oid",
                    original_format=acl_line
                )

                return FlextResult[FlextLdifTypes.Dict].ok(acl_data)

            except Exception as e:
                return FlextResult[FlextLdifTypes.Dict].fail(
                    f"OID ACL parsing failed: {e}"
                )

        def convert_acl_to_rfc(
            self, acl_data: FlextLdifTypes.Dict
        ) -> FlextResult[FlextLdifTypes.Dict]:
            """Convert OID ACL to RFC-compliant format.

            Args:
                acl_data: OID ACL data

            Returns:
                FlextResult with RFC-compliant ACL data

            """
            try:
                # Oracle OID ACLs don't have direct RFC equivalent
                # Return generic ACL representation
                rfc_data: FlextLdifTypes.Dict = {
                    FlextLdifConstants.DictKeys.TYPE: FlextLdifConstants.DictKeys.ACL,
                    FlextLdifConstants.DictKeys.FORMAT: FlextLdifConstants.AclFormats.RFC_GENERIC,
                    FlextLdifConstants.DictKeys.SOURCE_FORMAT: FlextLdifConstants.AclFormats.OID_ACL,
                    FlextLdifConstants.DictKeys.DATA: acl_data,
                }

                return FlextResult[FlextLdifTypes.Dict].ok(rfc_data)

            except Exception as e:
                return FlextResult[FlextLdifTypes.Dict].fail(
                    f"OID ACL→RFC conversion failed: {e}"
                )

        def convert_acl_from_rfc(
            self, acl_data: FlextLdifTypes.Dict
        ) -> FlextResult[FlextLdifTypes.Dict]:
            """Convert RFC ACL to OID-specific format.

            Args:
                acl_data: RFC-compliant ACL data

            Returns:
                FlextResult with OID ACL data

            """
            try:
                # Convert RFC ACL to Oracle OID format
                # This is target-specific conversion for migrations
                oid_data: FlextLdifTypes.Dict = {
                    FlextLdifConstants.DictKeys.FORMAT: FlextLdifConstants.AclFormats.OID_ACL,
                    FlextLdifConstants.DictKeys.TARGET_FORMAT: FlextLdifConstants.DictKeys.ORCLACI,
                    FlextLdifConstants.DictKeys.DATA: acl_data,
                }

                return FlextResult[FlextLdifTypes.Dict].ok(oid_data)

            except Exception as e:
                return FlextResult[FlextLdifTypes.Dict].fail(
                    f"RFC→OID ACL conversion failed: {e}"
                )

        def write_acl_to_rfc(
            self, acl_data: FlextLdifTypes.Dict
        ) -> FlextResult[str]:
            """Write OID ACL data to Oracle ACL string format.

            Converts parsed ACL dictionary back to OID ACL format string.
            If metadata contains original_format, uses it for perfect round-trip.

            Args:
                acl_data: Parsed OID ACL data dictionary

            Returns:
                FlextResult with OID ACL formatted string

            Example:
                Input: {"type": "standard", "target": "entry", "by_clauses": [...]}
                Output: "orclaci: access to entry by * (browse)"

            """
            try:
                # Check if we have metadata with original format for perfect round-trip
                if "_metadata" in acl_data:
                    metadata = acl_data["_metadata"]
                    if isinstance(metadata, FlextLdifModels.QuirkMetadata) and metadata.original_format:
                        return FlextResult[str].ok(metadata.original_format)
                    if isinstance(metadata, dict) and "original_format" in metadata:
                        return FlextResult[str].ok(str(metadata["original_format"]))

                # Build OID ACL from scratch
                parts = []

                # Determine ACL type prefix
                is_entry_level = acl_data.get(FlextLdifConstants.DictKeys.TYPE) == FlextLdifConstants.DictKeys.ENTRY_LEVEL
                acl_prefix = "orclentrylevelaci:" if is_entry_level else "orclaci:"

                # Build access clause
                access_parts = ["access to"]

                # Add target
                target = acl_data.get("target", "entry")
                if target == "attr" and "target_attrs" in acl_data:
                    access_parts.append(f"attr=({acl_data['target_attrs']})")
                else:
                    access_parts.append("entry")

                # Add filter (if present)
                if "filter" in acl_data:
                    access_parts.append(f"filter={acl_data['filter']}")

                # Add added_object_constraint (for orclentrylevelaci)
                if "added_object_constraint" in acl_data:
                    access_parts.append(f"added_object_constraint={acl_data['added_object_constraint']}")

                parts.append(" ".join(access_parts))

                # Add "by" clauses
                by_clauses_raw = acl_data.get("by_clauses", [])
                by_clauses = by_clauses_raw if isinstance(by_clauses_raw, list) else []
                for by_clause in by_clauses:
                    subject = by_clause.get("subject", "*")
                    permissions = by_clause.get("permissions", [])
                    perms_str = ",".join(permissions)
                    parts.append(f"by {subject} ({perms_str})")

                # Combine all parts
                acl_content = " ".join(parts)
                acl_string = f"{acl_prefix} {acl_content}"

                return FlextResult[str].ok(acl_string)

            except Exception as e:
                return FlextResult[str].fail(f"Failed to write OID ACL to RFC: {e}")

        def extract_acls_from_ldif(self, ldif_content: str) -> FlextResult[list[FlextLdifTypes.Dict]]:
            """Strategy pattern: OID-specific approach to extract ACLs from LDIF entries.

            OID ACLs use:
            - orclaci: for OID standard ACLs
            - orclentrylevelaci: for entry-level ACLs

            Args:
                ldif_content: LDIF content containing ACL definitions

            Returns:
                FlextResult containing list of parsed ACL dictionaries

            Examples:
                >>> ldif_text = '''
                ... dn: cn=OracleContext,dc=example,dc=com
                ... orclaci: access to entry by * (browse)
                ... orclentrylevelaci: access to attr=userPassword by self (write)
                ... '''
                >>> result = oid_quirk.acl.extract_acls_from_ldif(ldif_text)
                >>> acls = result.unwrap()
                >>> len(acls)
                2

            """
            try:
                acls = []
                current_acl: list[str] = []
                in_multiline_acl = False

                for line in ldif_content.split("\n"):
                    stripped = line.strip()

                    # Detect OID ACL start (orclaci: or orclentrylevelaci:)
                    if stripped.lower().startswith("orclaci:") or stripped.lower().startswith(
                        "orclentrylevelaci:"
                    ):
                        # Parse previous ACL if exists
                        if current_acl:
                            acl_text = "\n".join(current_acl)
                            result = self.parse_acl(acl_text)
                            if result.is_success:
                                acls.append(result.unwrap())
                            current_acl = []

                        current_acl.append(stripped)
                        # Check if ACL continues on next line (doesn't end with complete structure)
                        in_multiline_acl = not stripped.rstrip().endswith(")")

                    # Continuation line for multiline ACL
                    elif in_multiline_acl and stripped:
                        current_acl.append(stripped)
                        if stripped.rstrip().endswith(")"):
                            in_multiline_acl = False

                # Parse any remaining ACL
                if current_acl:
                    acl_text = "\n".join(current_acl)
                    result = self.parse_acl(acl_text)
                    if result.is_success:
                        acls.append(result.unwrap())

                return FlextResult[list[FlextLdifTypes.Dict]].ok(acls)

            except Exception as e:
                return FlextResult[list[FlextLdifTypes.Dict]].fail(
                    f"Failed to extract OID ACLs from LDIF: {e}"
                )

    class EntryQuirk(FlextLdifQuirksBaseEntryQuirk):
        """Oracle OID entry quirk (nested).

        Handles Oracle OID-specific entry transformations:
        - Oracle operational attributes
        - OID-specific object classes
        - Oracle namespace attributes

        Example:
            quirk = FlextLdifQuirksServersOid.EntryQuirk(server_type="oid")
            if quirk.can_handle_entry(dn, attributes):
                result = quirk.process_entry(dn, attributes)

        """

        server_type: str = Field(
            default=FlextLdifConstants.ServerTypes.OID,
            description="Oracle OID server type",
        )
        priority: int = Field(
            default=10, description="High priority for OID entry processing"
        )

        def model_post_init(self, _context: object, /) -> None:
            """Initialize OID entry quirk."""

        def can_handle_entry(
            self,
            entry_dn: str,
            attributes: dict[str, object],
        ) -> bool:
            """Check if this quirk should handle the entry.

            Args:
                entry_dn: Entry distinguished name
                attributes: Entry attributes

            Returns:
                True if this is an Oracle OID-specific entry

            """
            # Check for Oracle OID-specific attributes
            oid_attrs = [
                "orclguid",
                "orclobjectguid",
                "orclaci",
                "orclentrylevelaci",
                "orclaci",
                "orclentrycreatetime",
                "orclentrymodifytime",
            ]

            has_oid_attrs = any(
                attr.lower() in [a.lower() for a in attributes] for attr in oid_attrs
            )

            # Check for Oracle OID object classes
            object_classes = attributes.get(FlextLdifConstants.DictKeys.OBJECTCLASS, [])
            if not isinstance(object_classes, list):
                object_classes = [object_classes]

            has_oid_classes = any(
                str(oc).lower().startswith("orcl") for oc in object_classes
            )

            # Check DN patterns for OID entries - more flexible detection
            dn_lower = entry_dn.lower()
            has_oid_dn_pattern = (
                "oracle" in dn_lower
                or "orcl" in dn_lower
                or "ou=oracle" in dn_lower
                or "dc=oracle" in dn_lower
            )

            return has_oid_attrs or has_oid_classes or has_oid_dn_pattern

        def process_entry(
            self, entry_dn: str, attributes: dict[str, object]
        ) -> FlextResult[FlextLdifTypes.Dict]:
            """Process entry for Oracle OID format.

            Args:
                entry_dn: Entry distinguished name
                attributes: Entry attributes

            Returns:
                FlextResult with processed entry data

            """
            try:
                # Oracle OID entries are RFC-compliant
                # Add OID-specific metadata
                processed_entry: FlextLdifTypes.Dict = {
                    FlextLdifConstants.DictKeys.DN: entry_dn,
                    FlextLdifConstants.DictKeys.SERVER_TYPE: FlextLdifConstants.ServerTypes.OID,
                    FlextLdifConstants.DictKeys.HAS_OID_ACLS: any(
                        attr in attributes
                        for attr in [
                            FlextLdifConstants.DictKeys.ORCLACI,
                            FlextLdifConstants.DictKeys.ORCLENTRYLEVELACI,
                        ]
                    ),
                }
                processed_entry.update(attributes)

                return FlextResult[FlextLdifTypes.Dict].ok(processed_entry)

            except Exception as e:
                return FlextResult[FlextLdifTypes.Dict].fail(
                    f"OID entry processing failed: {e}"
                )

        def convert_entry_to_rfc(
            self, entry_data: FlextLdifTypes.Dict
        ) -> FlextResult[FlextLdifTypes.Dict]:
            """Convert Oracle OID entry to RFC-compliant format.

            Args:
                entry_data: Oracle OID entry data

            Returns:
                FlextResult with RFC-compliant entry data

            """
            try:
                # Oracle OID entries are already RFC-compliant
                # Remove Oracle-specific operational attributes if needed
                rfc_data = dict(entry_data)

                # Optional: Remove OID-specific operational attributes
                # that don't exist in standard LDAP
                oid_operational_attrs = [
                    "orclguid",
                    "orclobjectguid",
                    "orclentrycreatetime",
                    "orclentrymodifytime",
                    "has_oid_acls",
                    "server_type",
                ]

                for attr in oid_operational_attrs:
                    rfc_data.pop(attr, None)

                return FlextResult[FlextLdifTypes.Dict].ok(rfc_data)

            except Exception as e:
                return FlextResult[FlextLdifTypes.Dict].fail(
                    f"OID entry→RFC conversion failed: {e}"
                )

        def convert_entry_from_rfc(
            self, entry_data: FlextLdifTypes.Dict
        ) -> FlextResult[FlextLdifTypes.Dict]:
            """Convert RFC-compliant entry to Oracle OID format.

            Args:
                entry_data: RFC-compliant entry data

            Returns:
                FlextResult with OID entry data

            """
            try:
                # Oracle OID uses RFC-compliant format
                # Just ensure OID server type is set
                oid_entry = dict(entry_data)
                oid_entry[FlextLdifConstants.DictKeys.SERVER_TYPE] = FlextLdifConstants.ServerTypes.OID

                return FlextResult[FlextLdifTypes.Dict].ok(oid_entry)

            except Exception as e:
                return FlextResult[FlextLdifTypes.Dict].fail(
                    f"RFC→OID entry conversion failed: {e}"
                )

        def write_entry_to_ldif(
            self, entry_data: FlextLdifTypes.Dict
        ) -> FlextResult[str]:
            r"""Write OID entry data to standard LDIF string format.

            Converts parsed entry dictionary to LDIF format string.
            Handles Oracle-specific attributes like orclaci, orclguid, etc.

            Args:
                entry_data: Parsed OID entry data dictionary

            Returns:
                FlextResult with LDIF formatted entry string

            Example:
                Input: {"dn": "cn=test,dc=example,dc=com", "cn": ["test"], "objectClass": ["person"]}
                Output: "dn: cn=test,dc=example,dc=com\ncn: test\nobjectClass: person\n"

            """
            try:
                # Check for required DN field
                if FlextLdifConstants.DictKeys.DN not in entry_data:
                    return FlextResult[str].fail("Missing required 'dn' field")

                dn = entry_data[FlextLdifConstants.DictKeys.DN]
                ldif_lines = [f"dn: {dn}"]

                # Get attribute ordering from metadata if available
                attr_order = None
                if "_metadata" in entry_data:
                    metadata = entry_data["_metadata"]
                    if isinstance(metadata, FlextLdifModels.QuirkMetadata):
                        attr_order = metadata.extensions.get("attribute_order")
                    elif isinstance(metadata, dict):
                        attr_order = metadata.get("extensions", {}).get("attribute_order")

                # Determine attribute iteration order
                # Define excluded keys as a set for efficient membership testing
                excluded_keys = {
                    FlextLdifConstants.DictKeys.DN,
                    "_metadata",
                    FlextLdifConstants.DictKeys.SERVER_TYPE,
                    FlextLdifConstants.DictKeys.HAS_OID_ACLS,
                }

                if attr_order:
                    # Use preserved ordering
                    attrs_to_process = [
                        (key, entry_data[key])
                        for key in attr_order
                        if key in entry_data and key not in excluded_keys
                    ]
                else:
                    # Default ordering: filter out special keys
                    attrs_to_process = [
                        (key, value)
                        for key, value in entry_data.items()
                        if key not in excluded_keys
                    ]

                # Write attributes
                for attr_name, attr_value in attrs_to_process:
                    # Handle both list and single values
                    if isinstance(attr_value, list):
                        ldif_lines.extend(f"{attr_name}: {value}" for value in attr_value)
                    else:
                        ldif_lines.append(f"{attr_name}: {attr_value}")

                # Join with newlines and add trailing newline
                ldif_string = "\n".join(ldif_lines) + "\n"

                return FlextResult[str].ok(ldif_string)

            except Exception as e:
                return FlextResult[str].fail(f"Failed to write OID entry to LDIF: {e}")

        def extract_entries_from_ldif(
            self, ldif_content: str
        ) -> FlextResult[list[FlextLdifTypes.Dict]]:
            """Strategy pattern: OID-specific approach to extract entries from LDIF.

            Handles:
            - DN parsing with OID-specific contexts (cn=OracleContext, etc.)
            - Continuation lines (lines starting with space)
            - Multi-valued attributes
            - Base64 encoded values (:: marker)
            - OID-specific objectClasses and attributes

            Args:
                ldif_content: LDIF content containing directory entries

            Returns:
                FlextResult containing list of parsed entry dictionaries

            Examples:
                >>> ldif_text = '''
                ... dn: cn=OracleContext,dc=example,dc=com
                ... objectClass: orclContext
                ... orclVersion: 90600
                ... cn: OracleContext
                ...
                ... dn: cn=users,cn=OracleContext,dc=example,dc=com
                ... objectClass: organizationalUnit
                ... cn: users
                ... '''
                >>> result = oid_quirk.entry.extract_entries_from_ldif(ldif_text)
                >>> entries = result.unwrap()
                >>> len(entries)
                2

            """
            try:
                entries = []
                current_entry: FlextLdifTypes.Dict = {}
                current_attr: str | None = None
                current_values: list[str] = []

                for line in ldif_content.split("\n"):
                    # Empty line indicates end of entry
                    if not line.strip():
                        if current_entry and "dn" in current_entry:
                            # Save last attribute if exists
                            if current_attr and current_values:
                                if current_attr in current_entry:
                                    existing_value = current_entry[current_attr]
                                    if isinstance(existing_value, list):
                                        existing_value.extend(current_values)
                                    else:
                                        current_entry[current_attr] = [
                                            existing_value,
                                            *current_values,
                                        ]
                                else:
                                    current_entry[current_attr] = (
                                        current_values if len(current_values) > 1 else current_values[0]
                                    )

                            # Process entry
                            dn = str(current_entry.pop("dn"))
                            result = self.process_entry(dn, current_entry)
                            if result.is_success:
                                entries.append(result.unwrap())

                            # Reset for next entry
                            current_entry = {}
                            current_attr = None
                            current_values = []
                        continue

                    # Skip comments
                    if line.startswith("#"):
                        continue

                    # Continuation line (starts with space)
                    if line.startswith(" ") and current_attr:
                        if current_values:
                            # Append continuation to last value
                            current_values[-1] += line[1:]
                        continue

                    # New attribute line
                    if ":" in line:
                        # Save previous attribute
                        if current_attr and current_values:
                            if current_attr in current_entry:
                                existing_value = current_entry[current_attr]
                                if isinstance(existing_value, list):
                                    existing_value.extend(current_values)
                                else:
                                    current_entry[current_attr] = [
                                        existing_value,
                                        *current_values,
                                    ]
                            else:
                                current_entry[current_attr] = (
                                    current_values if len(current_values) > 1 else current_values[0]
                                )
                            current_values = []

                        # Parse new attribute
                        if "::" in line:
                            # Base64 encoded value
                            parts = line.split("::", 1)
                            attr_name = parts[0].strip().lower()
                            attr_value = parts[1].strip() if len(parts) > 1 else ""
                            # Note: Real implementation should decode base64
                            # For now, preserve the marker for downstream processing
                            attr_value = f"base64:{attr_value}"
                        else:
                            parts = line.split(":", 1)
                            attr_name = parts[0].strip().lower()
                            attr_value = parts[1].strip() if len(parts) > 1 else ""

                        current_attr = attr_name
                        current_values = [attr_value]

                # Handle last entry if file doesn't end with blank line
                if current_entry and "dn" in current_entry:
                    if current_attr and current_values:
                        if current_attr in current_entry:
                            existing_value = current_entry[current_attr]
                            if isinstance(existing_value, list):
                                existing_value.extend(current_values)
                            else:
                                current_entry[current_attr] = [
                                    existing_value,
                                    *current_values,
                                ]
                        else:
                            current_entry[current_attr] = (
                                current_values if len(current_values) > 1 else current_values[0]
                            )

                    dn = str(current_entry.pop("dn"))
                    result = self.process_entry(dn, current_entry)
                    if result.is_success:
                        entries.append(result.unwrap())

                return FlextResult[list[FlextLdifTypes.Dict]].ok(entries)

            except Exception as e:
                return FlextResult[list[FlextLdifTypes.Dict]].fail(
                    f"Failed to extract OID entries from LDIF: {e}"
                )


__all__ = [
    "FlextLdifQuirksServersOid",
]
