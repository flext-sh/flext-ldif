"""OID to OUD Migration Pipeline - Complete conversion orchestration.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path

from flext_core import FlextLogger, FlextResult, FlextService
from flext_ldif.acl import FlextLdifOidAciParserService
from flext_ldif.models import FlextLdifModels
from flext_ldif.schema import FlextLdifOidSchemaParserService


class FlextLdifOidOudPipelineService(FlextService[dict]):
    """OID to OUD Migration Pipeline Service.

    Complete orchestration service for converting Oracle Internet Directory (OID)
    LDIF data to Oracle Unified Directory (OUD) format.

    This service coordinates:
    1. Schema conversion (attributeTypes, objectClasses)
    2. ACI conversion (orclaci, orclentrylevelaci)
    3. Entry processing and transformation
    4. Output generation for OUD import

    Example usage:
        pipeline = FlextLdifOidOudPipelineService()
        result = pipeline.execute({
            "input_dir": "data/input",
            "output_dir": "data/output",
            "process_schema": True,
            "process_aci": True,
            "process_entries": True,
        })
        if result.is_success:
            conversion_result = result.value
            print(f"Converted {conversion_result['stats']['total_entries']} entries")
    """

    def __init__(self) -> None:
        """Initialize OID to OUD pipeline service."""
        super().__init__()
        self._logger = FlextLogger(__name__)
        self._schema_parser = FlextLdifOidSchemaParserService()
        self._aci_parser = FlextLdifOidAciParserService()

    def execute(self, params: dict) -> FlextResult[dict]:
        """Execute OID to OUD conversion pipeline.

        Args:
            params: Dictionary with:
                - input_dir: Input directory with OID LDIF files
                - output_dir: Output directory for OUD LDIF files
                - process_schema: Whether to process schema files (default True)
                - process_aci: Whether to process ACI files (default True)
                - process_entries: Whether to process entry files (default True)
                - schema_file: Optional specific schema file (default: search for *schema*.ldif)
                - aci_file: Optional specific ACI file (default: search for *aci*.ldif)

        Returns:
            FlextResult with conversion results containing:
                - schema: Converted schema (OidSchema + OUD SchemaDiscoveryResult)
                - acis: Converted ACIs (OidAci/OidEntryLevelAci + OUD UnifiedAcl)
                - entries: Converted entries
                - stats: Conversion statistics
                - output_files: Generated output file paths

        """
        try:
            # Extract parameters
            input_dir_str = params.get("input_dir", "")
            if not input_dir_str:
                return FlextResult[dict].fail("input_dir parameter is required")

            output_dir_str = params.get("output_dir", "")
            if not output_dir_str:
                return FlextResult[dict].fail("output_dir parameter is required")

            input_dir = Path(input_dir_str)
            output_dir = Path(output_dir_str)

            if not input_dir.exists():
                return FlextResult[dict].fail(f"Input directory not found: {input_dir}")

            # Create output directory if it doesn't exist
            output_dir.mkdir(parents=True, exist_ok=True)

            process_schema = params.get("process_schema", True)
            process_aci = params.get("process_aci", True)
            process_entries = params.get("process_entries", True)

            self._logger.info(
                "Starting OID to OUD conversion pipeline",
                extra={
                    "input_dir": str(input_dir),
                    "output_dir": str(output_dir),
                    "process_schema": process_schema,
                    "process_aci": process_aci,
                    "process_entries": process_entries,
                },
            )

            # Initialize result structure
            result: dict = {
                "schema": None,
                "acis": None,
                "entries": [],
                "stats": {
                    "schema_attributes": 0,
                    "schema_objectclasses": 0,
                    "orclaci_count": 0,
                    "entry_level_aci_count": 0,
                    "total_entries": 0,
                    "conversion_warnings": [],
                },
                "output_files": [],
            }

            # Phase 1: Process Schema
            if process_schema:
                schema_result = self._process_schema(params, input_dir, output_dir)
                if schema_result.is_success:
                    result["schema"] = schema_result.value
                    if schema_result.value:
                        result["stats"]["schema_attributes"] = len(
                            schema_result.value.get("oid_schema", {}).get(
                                "attributes", {}
                            )
                        )
                        result["stats"]["schema_objectclasses"] = len(
                            schema_result.value.get("oid_schema", {}).get(
                                "objectclasses", {}
                            )
                        )
                else:
                    result["stats"]["conversion_warnings"].append(
                        f"Schema processing failed: {schema_result.error}"
                    )

            # Phase 2: Process ACIs
            if process_aci:
                aci_result = self._process_acis(params, input_dir, output_dir)
                if aci_result.is_success:
                    result["acis"] = aci_result.value
                    if aci_result.value:
                        result["stats"]["orclaci_count"] = len(
                            aci_result.value.get("orclaci", [])
                        )
                        result["stats"]["entry_level_aci_count"] = len(
                            aci_result.value.get("entry_level_aci", [])
                        )
                else:
                    result["stats"]["conversion_warnings"].append(
                        f"ACI processing failed: {aci_result.error}"
                    )

            # Phase 3: Process Entries
            if process_entries:
                entries_result = self._process_entries(params, input_dir, output_dir)
                if entries_result.is_success:
                    result["entries"] = entries_result.value
                    result["stats"]["total_entries"] = len(entries_result.value)
                else:
                    result["stats"]["conversion_warnings"].append(
                        f"Entry processing failed: {entries_result.error}"
                    )

            self._logger.info(
                "OID to OUD conversion pipeline completed",
                extra={
                    "schema_attributes": result["stats"]["schema_attributes"],
                    "schema_objectclasses": result["stats"]["schema_objectclasses"],
                    "orclaci_count": result["stats"]["orclaci_count"],
                    "entry_level_aci_count": result["stats"]["entry_level_aci_count"],
                    "total_entries": result["stats"]["total_entries"],
                    "warnings_count": len(result["stats"]["conversion_warnings"]),
                },
            )

            return FlextResult[dict].ok(result)

        except Exception as e:
            error_msg = f"OID to OUD pipeline failed: {e}"
            self._logger.exception(error_msg)
            return FlextResult[dict].fail(error_msg)

    def _process_schema(
        self, params: dict, input_dir: Path, output_dir: Path
    ) -> FlextResult[dict]:
        """Process OID schema files and convert to OUD format.

        Args:
            params: Pipeline parameters
            input_dir: Input directory
            output_dir: Output directory

        Returns:
            FlextResult with schema conversion results

        """
        try:
            # Find schema file
            schema_file = params.get("schema_file")
            if not schema_file:
                # Search for schema files
                schema_files = list(input_dir.glob("*schema*.ldif"))
                if not schema_files:
                    return FlextResult[dict].ok(None)  # No schema files found
                schema_file = schema_files[0]  # Use first schema file
            else:
                schema_file = Path(schema_file)

            if not schema_file.exists():
                return FlextResult[dict].fail(f"Schema file not found: {schema_file}")

            self._logger.info(f"Processing schema file: {schema_file}")

            # Parse OID schema
            parse_result = self._schema_parser.execute({"file_path": str(schema_file)})
            if parse_result.is_failure:
                return FlextResult[dict].fail(
                    f"Failed to parse OID schema: {parse_result.error}"
                )

            oid_schema = parse_result.value

            # Convert to OUD format
            oud_result = oid_schema.to_oud_schema()
            if oud_result.is_failure:
                return FlextResult[dict].fail(
                    f"Failed to convert schema to OUD: {oud_result.error}"
                )

            oud_schema = oud_result.value

            # Write output files
            output_file = output_dir / "01_converted_schema_oud.ldif"
            self._write_schema_to_ldif(oud_schema, output_file)

            return FlextResult[dict].ok({
                "oid_schema": {
                    "attributes": oid_schema.attributes,
                    "objectclasses": oid_schema.objectclasses,
                    "source_dn": oid_schema.source_dn,
                },
                "oud_schema": oud_schema,
                "output_file": str(output_file),
            })

        except Exception as e:
            return FlextResult[dict].fail(f"Schema processing failed: {e}")

    def _process_acis(
        self, params: dict, input_dir: Path, output_dir: Path
    ) -> FlextResult[dict]:
        """Process OID ACI files and convert to OUD format.

        Args:
            params: Pipeline parameters
            input_dir: Input directory
            output_dir: Output directory

        Returns:
            FlextResult with ACI conversion results

        """
        try:
            # Find ACI file
            aci_file = params.get("aci_file")
            if not aci_file:
                # Search for ACI files
                aci_files = list(input_dir.glob("*aci*.ldif"))
                if not aci_files:
                    return FlextResult[dict].ok(None)  # No ACI files found
                aci_file = aci_files[0]  # Use first ACI file
            else:
                aci_file = Path(aci_file)

            if not aci_file.exists():
                return FlextResult[dict].fail(f"ACI file not found: {aci_file}")

            self._logger.info(f"Processing ACI file: {aci_file}")

            # Parse OID ACIs
            parse_result = self._aci_parser.execute({"file_path": str(aci_file)})
            if parse_result.is_failure:
                return FlextResult[dict].fail(
                    f"Failed to parse OID ACIs: {parse_result.error}"
                )

            acis = parse_result.value

            # Convert ACIs to OUD format
            converted_orclaci = []
            converted_entry_level = []

            for aci in acis["orclaci"]:
                oud_result = aci.to_oud_aci()
                if oud_result.is_success:
                    converted_orclaci.append(oud_result.value)

            for aci in acis["entry_level_aci"]:
                oud_result = aci.to_oud_aci()
                if oud_result.is_success:
                    converted_entry_level.append(oud_result.value)

            # Write output files
            output_file = output_dir / "02_converted_acis_oud.ldif"
            self._write_acis_to_ldif(
                converted_orclaci, converted_entry_level, output_file
            )

            return FlextResult[dict].ok({
                "orclaci": acis["orclaci"],
                "entry_level_aci": acis["entry_level_aci"],
                "converted_orclaci": converted_orclaci,
                "converted_entry_level": converted_entry_level,
                "entries": acis["entries"],
                "output_file": str(output_file),
            })

        except Exception as e:
            return FlextResult[dict].fail(f"ACI processing failed: {e}")

    def _process_entries(
        self, _params: dict, input_dir: Path, _output_dir: Path
    ) -> FlextResult[list]:
        """Process OID entry files and convert to OUD format.

        Args:
            _params: Pipeline parameters (not yet used)
            input_dir: Input directory
            _output_dir: Output directory (not yet used)

        Returns:
            FlextResult with entry conversion results

        Note:
            Entry processing is not yet implemented. This placeholder returns
            an empty list. Will be implemented in the next phase after schema
            and ACI conversion is validated and working in production.

        """
        try:
            # Find entry files (exclude schema and ACI files)
            entry_files = [
                f
                for f in input_dir.glob("*.ldif")
                if "schema" not in f.name.lower() and "aci" not in f.name.lower()
            ]

            if not entry_files:
                return FlextResult[list].ok([])  # No entry files found

            self._logger.info(f"Processing {len(entry_files)} entry files")

            # Entry processing will be implemented in next phase
            return FlextResult[list].ok([])

        except Exception as e:
            return FlextResult[list].fail(f"Entry processing failed: {e}")

    def _write_schema_to_ldif(
        self, schema: FlextLdifModels.SchemaDiscoveryResult, output_file: Path
    ) -> None:
        """Write converted OUD schema to LDIF file.

        Args:
            schema: Converted OUD schema
            output_file: Output file path

        """
        with output_file.open("w", encoding="utf-8") as f:
            f.write("# Converted OUD Schema from OID\n")
            f.write("# Generated by FlextLdifOidOudPipelineService\n\n")
            f.write("dn: cn=schema\n")
            f.write("objectClass: top\n")
            f.write("objectClass: ldapSubentry\n")
            f.write("objectClass: subschema\n")
            f.write("cn: schema\n\n")

            # Write attributes
            for attr_name, attr in schema.attributes.items():
                f.write(f"# Attribute: {attr_name}\n")
                f.write(f"# Description: {attr.description}\n")
                f.write(f"# Single-value: {attr.single_value}\n\n")

            # Write objectClasses
            for oc_name, oc in schema.object_classes.items():
                f.write(f"# ObjectClass: {oc_name}\n")
                f.write(f"# Description: {oc.description}\n")
                f.write(
                    f"# Required attributes: {', '.join(oc.required_attributes)}\n\n"
                )

    def _write_acis_to_ldif(
        self,
        orclaci_list: list,
        entry_level_list: list,
        output_file: Path,
    ) -> None:
        """Write converted OUD ACIs to LDIF file.

        Args:
            orclaci_list: List of converted orclaci
            entry_level_list: List of converted entry-level ACIs
            output_file: Output file path

        """
        with output_file.open("w", encoding="utf-8") as f:
            f.write("# Converted OUD ACIs from OID\n")
            f.write("# Generated by FlextLdifOidOudPipelineService\n\n")
            f.write(f"# Total orclaci: {len(orclaci_list)}\n")
            f.write(f"# Total entry-level ACI: {len(entry_level_list)}\n\n")

            # Write converted ACIs
            for idx, aci in enumerate(orclaci_list, 1):
                f.write(f"# Converted orclaci #{idx}\n")
                f.write(f"# Server type: {aci.server_type}\n")
                f.write(f"# Raw OID ACI: {aci.raw_acl[:100]}...\n\n")

            for idx, aci in enumerate(entry_level_list, 1):
                f.write(f"# Converted entry-level ACI #{idx}\n")
                f.write(f"# Server type: {aci.server_type}\n")
                f.write(f"# Raw OID ACI: {aci.raw_acl[:100]}...\n\n")


__all__ = ["FlextLdifOidOudPipelineService"]
