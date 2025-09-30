"""OID Schema Parser - Parse Oracle Internet Directory schema from LDIF files.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path

from flext_core import FlextLogger, FlextResult, FlextService
from flext_ldif.models import FlextLdifModels


class FlextLdifOidSchemaParserService(FlextService[FlextLdifModels.OidSchema]):
    """OID Schema Parser Service - Parse OID schema LDIF files.

    Parses Oracle Internet Directory (OID) schema definitions from LDIF files,
    extracting attributeTypes and objectClasses into OidSchema models.

    This service handles the parsing of OID-specific schema format including:
    - attributetypes: ( OID NAME 'name' ... )
    - objectclasses: ( OID NAME 'name' ... )

    Example usage:
        parser = FlextLdifOidSchemaParserService()
        result = parser.execute({"file_path": "data/input/5_schema.ldif"})
        if result.is_success:
            oid_schema = result.value
            print(f"Parsed {len(oid_schema.attributes)} attributes")
    """

    def __init__(self) -> None:
        """Initialize OID schema parser service."""
        super().__init__()
        self._logger = FlextLogger(__name__)

    def execute(self, params: dict) -> FlextResult[FlextLdifModels.OidSchema]:
        """Execute OID schema parsing from LDIF file.

        Args:
            params: Dictionary with:
                - file_path: Path to OID schema LDIF file
                - parse_attributes: Whether to parse attributes (default True)
                - parse_objectclasses: Whether to parse objectClasses (default True)

        Returns:
            FlextResult with parsed OidSchema or error

        """
        try:
            # Extract parameters
            file_path_str = params.get("file_path", "")
            if not file_path_str:
                return FlextResult[FlextLdifModels.OidSchema].fail(
                    "file_path parameter is required"
                )

            file_path = Path(file_path_str)
            if not file_path.exists():
                return FlextResult[FlextLdifModels.OidSchema].fail(
                    f"Schema file not found: {file_path}"
                )

            parse_attributes = params.get("parse_attributes", True)
            parse_objectclasses = params.get("parse_objectclasses", True)

            self._logger.info(
                f"Parsing OID schema from {file_path}",
                extra={
                    "file_path": str(file_path),
                    "parse_attributes": parse_attributes,
                    "parse_objectclasses": parse_objectclasses,
                },
            )

            # Parse schema file
            parse_result = self._parse_schema_file(
                file_path,
                parse_attributes=parse_attributes,
                parse_objectclasses=parse_objectclasses,
            )

            if parse_result.is_failure:
                return FlextResult[FlextLdifModels.OidSchema].fail(parse_result.error)

            oid_schema = parse_result.value

            self._logger.info(
                "OID schema parsed successfully",
                extra={
                    "total_attributes": len(oid_schema.attributes),
                    "total_objectclasses": len(oid_schema.objectclasses),
                    "oracle_specific_attrs": oid_schema.schema_summary[
                        "oracle_specific_attributes"
                    ],
                    "oracle_specific_ocs": oid_schema.schema_summary[
                        "oracle_specific_objectclasses"
                    ],
                },
            )

            return FlextResult[FlextLdifModels.OidSchema].ok(oid_schema)

        except Exception as e:
            error_msg = f"Failed to execute OID schema parser: {e}"
            self._logger.exception(error_msg)
            return FlextResult[FlextLdifModels.OidSchema].fail(error_msg)

    def _parse_schema_file(
        self,
        file_path: Path,
        *,
        parse_attributes: bool,
        parse_objectclasses: bool,
    ) -> FlextResult[FlextLdifModels.OidSchema]:
        """Parse OID schema from LDIF file.

        Args:
            file_path: Path to schema LDIF file
            parse_attributes: Whether to parse attributeTypes
            parse_objectclasses: Whether to parse objectClasses

        Returns:
            FlextResult with OidSchema

        """
        try:
            attributes: dict[str, FlextLdifModels.OidSchemaAttribute] = {}
            objectclasses: dict[str, FlextLdifModels.OidSchemaObjectClass] = {}
            source_dn = "cn=subschemasubentry"

            # Read file and parse line by line
            with file_path.open("r", encoding="utf-8") as f:
                current_line = ""

                for raw_line in f:
                    line = raw_line.rstrip("\n")

                    # Handle line continuation (lines starting with space)
                    if line.startswith(" "):
                        current_line += line[1:]  # Remove leading space
                        continue

                    # Process complete line
                    if current_line:
                        self._process_schema_line(
                            current_line,
                            attributes,
                            objectclasses,
                            parse_attributes=parse_attributes,
                            parse_objectclasses=parse_objectclasses,
                        )

                    # Check for DN line
                    if line.startswith("dn:"):
                        source_dn = line[3:].strip()

                    current_line = line

                # Process last line
                if current_line:
                    self._process_schema_line(
                        current_line,
                        attributes,
                        objectclasses,
                        parse_attributes=parse_attributes,
                        parse_objectclasses=parse_objectclasses,
                    )

            # Create OidSchema
            oid_schema = FlextLdifModels.OidSchema(
                attributes=attributes,
                objectclasses=objectclasses,
                source_dn=source_dn,
            )

            return FlextResult[FlextLdifModels.OidSchema].ok(oid_schema)

        except Exception as e:
            return FlextResult[FlextLdifModels.OidSchema].fail(
                f"Failed to parse schema file: {e}"
            )

    def _process_schema_line(
        self,
        line: str,
        attributes: dict[str, FlextLdifModels.OidSchemaAttribute],
        objectclasses: dict[str, FlextLdifModels.OidSchemaObjectClass],
        *,
        parse_attributes: bool,
        parse_objectclasses: bool,
    ) -> None:
        """Process a single schema line.

        Args:
            line: Complete schema line (after continuation handling)
            attributes: Dictionary to store parsed attributes
            objectclasses: Dictionary to store parsed objectClasses
            parse_attributes: Whether to parse attributes
            parse_objectclasses: Whether to parse objectClasses

        """
        try:
            # Parse attributeTypes
            if parse_attributes and line.startswith("attributetypes:"):
                result = FlextLdifModels.OidSchemaAttribute.from_ldif_line(line)
                if result.is_success:
                    attr = result.value
                    attributes[attr.name] = attr
                else:
                    self._logger.warning(
                        f"Failed to parse attribute: {result.error}",
                        extra={"line": line[:100]},
                    )

            # Parse objectClasses
            elif parse_objectclasses and line.startswith("objectclasses:"):
                result = FlextLdifModels.OidSchemaObjectClass.from_ldif_line(line)
                if result.is_success:
                    oc = result.value
                    objectclasses[oc.name] = oc
                else:
                    self._logger.warning(
                        f"Failed to parse objectClass: {result.error}",
                        extra={"line": line[:100]},
                    )

        except Exception as e:
            self._logger.warning(
                f"Error processing schema line: {e}",
                extra={"line": line[:100]},
            )

    def parse_from_string(
        self, schema_content: str
    ) -> FlextResult[FlextLdifModels.OidSchema]:
        """Parse OID schema from string content.

        Args:
            schema_content: LDIF content as string

        Returns:
            FlextResult with OidSchema

        """
        try:
            attributes: dict[str, FlextLdifModels.OidSchemaAttribute] = {}
            objectclasses: dict[str, FlextLdifModels.OidSchemaObjectClass] = {}
            source_dn = "cn=subschemasubentry"

            lines = schema_content.split("\n")
            current_line = ""

            for raw_line in lines:
                line = raw_line.rstrip("\n")

                # Handle line continuation
                if line.startswith(" "):
                    current_line += line[1:]
                    continue

                # Process complete line
                if current_line:
                    self._process_schema_line(
                        current_line, attributes, objectclasses, True, True
                    )

                # Check for DN line
                if line.startswith("dn:"):
                    source_dn = line[3:].strip()

                current_line = line

            # Process last line
            if current_line:
                self._process_schema_line(
                    current_line, attributes, objectclasses, True, True
                )

            # Create OidSchema
            oid_schema = FlextLdifModels.OidSchema(
                attributes=attributes,
                objectclasses=objectclasses,
                source_dn=source_dn,
            )

            return FlextResult[FlextLdifModels.OidSchema].ok(oid_schema)

        except Exception as e:
            return FlextResult[FlextLdifModels.OidSchema].fail(
                f"Failed to parse schema from string: {e}"
            )


__all__ = ["FlextLdifOidSchemaParserService"]
