"""RFC 4512 Compliant LDAP Schema Parser.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Implements RFC 4512: Lightweight Directory Access Protocol (LDAP):
Directory Information Models

Key RFC 4512 features:
- AttributeTypes: OID, NAME, SYNTAX, EQUALITY, ORDERING, SUBSTR
- ObjectClasses: OID, NAME, SUP, STRUCTURAL/AUXILIARY/ABSTRACT, MUST, MAY
- Schema subentry: cn=subschemasubentry
- Standard LDAP syntaxes
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import ClassVar

from flext_core import FlextLogger, FlextResult, FlextService
from flext_ldif.quirks.registry import QuirkRegistryService


class RfcSchemaParserService(FlextService[dict]):
    """RFC 4512 compliant schema parser service.

    Parses LDAP schema definitions strictly according to RFC 4512 specification.
    Does NOT handle vendor-specific OIDs or extensions - those belong in quirks.

    model_config = ConfigDict(ignored_types=(ClassVar,))

    Features:
    - AttributeType parsing (RFC 4512 Section 4.1.2)
    - ObjectClass parsing (RFC 4512 Section 4.1.1)
    - Standard LDAP syntaxes (RFC 4517)
    - Schema subentry discovery

    Example:
        from flext_ldif.quirks.registry import QuirkRegistryService

        registry = QuirkRegistryService()
        params = {"file_path": "schema.ldif", "parse_attributes": True}
        parser = RfcSchemaParserService(params=params, quirk_registry=registry)
        result = parser.execute()
        if result.is_success:
            attrs = result.value["attributes"]
            classes = result.value["objectclasses"]

    """

    # RFC 4512: AttributeType definition regex
    ATTRIBUTE_TYPE_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"\(\s*"  # Opening parenthesis
        r"(?P<oid>[\d\.]+)\s+"  # OID (numeric)
        r"(?:NAME\s+'(?P<name>[^']+)'\s+)?"  # Optional NAME
        r"(?:DESC\s+'(?P<desc>[^']+)'\s+)?"  # Optional DESC
        r"(?:OBSOLETE\s+)?"  # Optional OBSOLETE
        r"(?:SUP\s+(?P<sup>\w+)\s+)?"  # Optional SUP
        r"(?:EQUALITY\s+(?P<equality>\w+)\s+)?"  # Optional EQUALITY
        r"(?:ORDERING\s+(?P<ordering>\w+)\s+)?"  # Optional ORDERING
        r"(?:SUBSTR\s+(?P<substr>\w+)\s+)?"  # Optional SUBSTR
        r"(?:SYNTAX\s+'(?P<syntax>[\d\.]+)'(?:\{(?P<length>\d+)\})?\s+)?"  # Optional SYNTAX
        r"(?:SINGLE-VALUE\s+)?"  # Optional SINGLE-VALUE
        r"(?:COLLECTIVE\s+)?"  # Optional COLLECTIVE
        r"(?:NO-USER-MODIFICATION\s+)?"  # Optional NO-USER-MODIFICATION
        r"(?:USAGE\s+(?P<usage>\w+)\s+)?"  # Optional USAGE
        r"\)",  # Closing parenthesis
        re.VERBOSE,
    )

    # RFC 4512: ObjectClass definition regex
    OBJECT_CLASS_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"\(\s*"  # Opening parenthesis
        r"(?P<oid>[\d\.]+)\s+"  # OID (numeric)
        r"(?:NAME\s+'(?P<name>[^']+)'\s+)?"  # Optional NAME
        r"(?:DESC\s+'(?P<desc>[^']+)'\s+)?"  # Optional DESC
        r"(?:OBSOLETE\s+)?"  # Optional OBSOLETE
        r"(?:SUP\s+(?P<sup>[\w\$]+)\s+)?"  # Optional SUP
        r"(?:(?P<kind>STRUCTURAL|AUXILIARY|ABSTRACT)\s+)?"  # Optional kind
        r"(?:MUST\s+\((?P<must>[^\)]+)\)\s+)?"  # Optional MUST
        r"(?:MAY\s+\((?P<may>[^\)]+)\)\s+)?"  # Optional MAY
        r"\)",  # Closing parenthesis
        re.VERBOSE,
    )

    def __init__(
        self,
        *,
        params: dict,
        quirk_registry: QuirkRegistryService,
        server_type: str | None = None,
    ) -> None:
        """Initialize RFC schema parser with quirks integration.

        Args:
            params: Parsing parameters (file_path, parse_attributes, parse_objectclasses)
            quirk_registry: Quirk registry for server-specific extensions (MANDATORY)
            server_type: Optional server type to select specific quirks

        """
        super().__init__()
        self._logger = FlextLogger(__name__)
        self._params = params
        self._quirk_registry = quirk_registry
        self._server_type = server_type

    def execute(self) -> FlextResult[dict]:
        """Execute RFC-compliant schema parsing.

        Returns:
            FlextResult with parsed schema data containing:
                - attributes: Dict of attribute definitions by name
                - objectclasses: Dict of objectClass definitions by name
                - source_dn: DN of schema subentry
                - stats: Parsing statistics

        """
        try:
            # Extract parameters
            file_path_str = self._params.get("file_path", "")
            if not file_path_str:
                return FlextResult[dict].fail("file_path parameter is required")

            file_path = Path(file_path_str)
            if not file_path.exists():
                return FlextResult[dict].fail(f"Schema file not found: {file_path}")

            parse_attributes = self._params.get("parse_attributes", True)
            parse_objectclasses = self._params.get("parse_objectclasses", True)

            self._logger.info(
                f"Parsing LDAP schema (RFC 4512): {file_path}",
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
                return FlextResult[dict].fail(parse_result.error)

            data = parse_result.value

            self._logger.info(
                "LDAP schema parsed successfully",
                extra={
                    "total_attributes": len(data["attributes"]),
                    "total_objectclasses": len(data["objectclasses"]),
                },
            )

            return FlextResult[dict].ok(data)

        except Exception as e:
            error_msg = f"Failed to execute RFC schema parser: {e}"
            self._logger.exception(error_msg)
            return FlextResult[dict].fail(error_msg)

    def _parse_schema_file(
        self,
        file_path: Path,
        *,
        parse_attributes: bool,
        parse_objectclasses: bool,
    ) -> FlextResult[dict]:
        """Parse schema file according to RFC 4512.

        Args:
            file_path: Path to schema LDIF file
            parse_attributes: Parse attributeTypes
            parse_objectclasses: Parse objectClasses

        Returns:
            FlextResult with parsed schema data

        """
        try:
            attributes: dict[str, dict[str, object]] = {}
            objectclasses: dict[str, dict[str, object]] = {}
            source_dn = "cn=subschemasubentry"

            with file_path.open("r", encoding="utf-8") as f:
                current_line = ""

                for raw_line in f:
                    line = raw_line.rstrip("\n\r")

                    # Handle line folding (lines starting with space)
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

                    # Check for DN line (schema subentry)
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

            return FlextResult[dict].ok(
                {
                    "attributes": attributes,
                    "objectclasses": objectclasses,
                    "source_dn": source_dn,
                    "stats": {
                        "total_attributes": len(attributes),
                        "total_objectclasses": len(objectclasses),
                    },
                }
            )

        except Exception as e:
            return FlextResult[dict].fail(f"Failed to parse schema file: {e}")

    def _process_schema_line(
        self,
        line: str,
        attributes: dict[str, dict[str, object]],
        objectclasses: dict[str, dict[str, object]],
        *,
        parse_attributes: bool,
        parse_objectclasses: bool,
    ) -> None:
        """Process a single schema line.

        Args:
            line: Complete schema line (after folding)
            attributes: Dict to store parsed attributes
            objectclasses: Dict to store parsed objectClasses
            parse_attributes: Parse attributeTypes
            parse_objectclasses: Parse objectClasses

        """
        try:
            # RFC 4512: AttributeType definition
            if parse_attributes and line.startswith("attributetypes:"):
                attr_def = line[15:].strip()  # Remove "attributetypes:"
                attr_data = self._parse_attribute_type(attr_def)
                if attr_data and "name" in attr_data:
                    attributes[str(attr_data["name"])] = attr_data

            # RFC 4512: ObjectClass definition
            elif parse_objectclasses and line.startswith("objectclasses:"):
                oc_def = line[14:].strip()  # Remove "objectclasses:"
                oc_data = self._parse_object_class(oc_def)
                if oc_data and "name" in oc_data:
                    objectclasses[str(oc_data["name"])] = oc_data

        except Exception as e:
            self._logger.warning(
                f"Error processing schema line: {e}",
                extra={"line": line[:100]},
            )

    def _parse_attribute_type(self, definition: str) -> dict[str, object] | None:
        """Parse RFC 4512 AttributeType definition with quirks support.

        Args:
            definition: AttributeType definition string

        Returns:
            Dict with attribute metadata or None if parsing fails

        """
        # Try quirks first if available and server_type specified
        if self._quirk_registry and self._server_type:
            schema_quirks = self._quirk_registry.get_schema_quirks(self._server_type)
            for quirk in schema_quirks:
                if quirk.can_handle_attribute(definition):
                    self._logger.debug(
                        f"Using {quirk.server_type} quirk for attribute parsing",
                        extra={"definition": definition[:100]},
                    )
                    quirk_result = quirk.parse_attribute(definition)
                    if quirk_result.is_success:
                        return quirk_result.unwrap()  # type: ignore[return-value]

        # Fall back to RFC 4512 standard parsing
        match = self.ATTRIBUTE_TYPE_PATTERN.match(definition)
        if not match:
            return None

        return {
            "oid": match.group("oid"),
            "name": match.group("name") or match.group("oid"),
            "desc": match.group("desc"),
            "sup": match.group("sup"),
            "equality": match.group("equality"),
            "ordering": match.group("ordering"),
            "substr": match.group("substr"),
            "syntax": match.group("syntax"),
            "length": int(match.group("length")) if match.group("length") else None,
            "usage": match.group("usage"),
        }

    def _parse_object_class(self, definition: str) -> dict[str, object] | None:
        """Parse RFC 4512 ObjectClass definition with quirks support.

        Args:
            definition: ObjectClass definition string

        Returns:
            Dict with objectClass metadata or None if parsing fails

        """
        # Try quirks first if available and server_type specified
        if self._quirk_registry and self._server_type:
            schema_quirks = self._quirk_registry.get_schema_quirks(self._server_type)
            for quirk in schema_quirks:
                if quirk.can_handle_objectclass(definition):
                    self._logger.debug(
                        f"Using {quirk.server_type} quirk for objectClass parsing",
                        extra={"definition": definition[:100]},
                    )
                    quirk_result = quirk.parse_objectclass(definition)
                    if quirk_result.is_success:
                        return quirk_result.unwrap()  # type: ignore[return-value]

        # Fall back to RFC 4512 standard parsing
        match = self.OBJECT_CLASS_PATTERN.match(definition)
        if not match:
            return None

        # Parse MUST and MAY attribute lists
        must_attrs = []
        if match.group("must"):
            must_attrs = [
                attr.strip() for attr in match.group("must").split("$") if attr.strip()
            ]

        may_attrs = []
        if match.group("may"):
            may_attrs = [
                attr.strip() for attr in match.group("may").split("$") if attr.strip()
            ]

        return {
            "oid": match.group("oid"),
            "name": match.group("name") or match.group("oid"),
            "desc": match.group("desc"),
            "sup": match.group("sup"),
            "kind": match.group("kind") or "STRUCTURAL",
            "must": must_attrs,
            "may": may_attrs,
        }


__all__ = ["RfcSchemaParserService"]
