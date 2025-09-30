"""OID ACI Parser - Parse Oracle Internet Directory ACIs from LDIF files.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path

from flext_core import FlextLogger, FlextResult, FlextService
from flext_ldif.models import FlextLdifModels


class FlextLdifOidAciParserService(FlextService[dict[str, list]]):
    """OID ACI Parser Service - Parse OID ACI LDIF files.

    Parses Oracle Internet Directory (OID) Access Control Information (ACI) from
    LDIF files, extracting both orclaci and orclentrylevelaci attributes.

    This service handles the parsing of OID-specific ACI format including:
    - orclaci: access to entry/attr by <subject> (<permissions>)
    - orclentrylevelaci: access to entry/attr by <subject> (<permissions>)

    Example usage:
        parser = FlextLdifOidAciParserService()
        result = parser.execute({"file_path": "data/input/10_aci_dump.ldif"})
        if result.is_success:
            acis = result.value
            print(f"Parsed {len(acis['orclaci'])} orclaci entries")
    """

    def __init__(self) -> None:
        """Initialize OID ACI parser service."""
        super().__init__()
        self._logger = FlextLogger(__name__)

    def execute(self, params: dict) -> FlextResult[dict[str, list]]:
        """Execute OID ACI parsing from LDIF file.

        Args:
            params: Dictionary with:
                - file_path: Path to OID ACI LDIF file
                - parse_orclaci: Whether to parse orclaci (default True)
                - parse_entry_level_aci: Whether to parse orclentrylevelaci (default True)

        Returns:
            FlextResult with dict containing:
                - orclaci: list of OidAci
                - entry_level_aci: list of OidEntryLevelAci
                - entries: dict mapping DN to list of ACIs

        """
        try:
            # Extract parameters
            file_path_str = params.get("file_path", "")
            if not file_path_str:
                return FlextResult[dict[str, list]].fail(
                    "file_path parameter is required"
                )

            file_path = Path(file_path_str)
            if not file_path.exists():
                return FlextResult[dict[str, list]].fail(
                    f"ACI file not found: {file_path}"
                )

            parse_orclaci = params.get("parse_orclaci", True)
            parse_entry_level_aci = params.get("parse_entry_level_aci", True)

            self._logger.info(
                f"Parsing OID ACIs from {file_path}",
                extra={
                    "file_path": str(file_path),
                    "parse_orclaci": parse_orclaci,
                    "parse_entry_level_aci": parse_entry_level_aci,
                },
            )

            # Parse ACI file
            parse_result = self._parse_aci_file(
                file_path,
                parse_orclaci=parse_orclaci,
                parse_entry_level_aci=parse_entry_level_aci,
            )

            if parse_result.is_failure:
                return FlextResult[dict[str, list]].fail(parse_result.error)

            acis = parse_result.value

            self._logger.info(
                "OID ACIs parsed successfully",
                extra={
                    "total_orclaci": len(acis["orclaci"]),
                    "total_entry_level_aci": len(acis["entry_level_aci"]),
                    "total_entries": len(acis["entries"]),
                },
            )

            return FlextResult[dict[str, list]].ok(acis)

        except Exception as e:
            error_msg = f"Failed to execute OID ACI parser: {e}"
            self._logger.exception(error_msg)
            return FlextResult[dict[str, list]].fail(error_msg)

    def _parse_aci_file(
        self,
        file_path: Path,
        *,
        parse_orclaci: bool,
        parse_entry_level_aci: bool,
    ) -> FlextResult[dict[str, list]]:
        """Parse OID ACIs from LDIF file.

        Args:
            file_path: Path to ACI LDIF file
            parse_orclaci: Whether to parse orclaci attributes
            parse_entry_level_aci: Whether to parse orclentrylevelaci attributes

        Returns:
            FlextResult with dict containing parsed ACIs

        """
        try:
            orclaci_list: list[FlextLdifModels.OidAci] = []
            entry_level_aci_list: list[FlextLdifModels.OidEntryLevelAci] = []
            entries: dict[str, dict[str, list]] = {}

            current_dn = ""

            # Read file and parse line by line
            with file_path.open("r", encoding="utf-8") as f:
                current_line = ""

                for raw_line in f:
                    processed_line = raw_line.rstrip("\n")

                    # Handle line continuation (lines starting with space)
                    if processed_line.startswith(" "):
                        current_line += processed_line[1:]  # Remove leading space
                        continue

                    # Process complete line
                    if current_line:
                        self._process_aci_line(
                            current_line,
                            current_dn,
                            orclaci_list,
                            entry_level_aci_list,
                            entries,
                            parse_orclaci=parse_orclaci,
                            parse_entry_level_aci=parse_entry_level_aci,
                        )

                    # Check for DN line
                    if processed_line.startswith("dn:"):
                        current_dn = processed_line[3:].strip()
                        # Initialize entry in dict
                        if current_dn not in entries:
                            entries[current_dn] = {"orclaci": [], "entry_level_aci": []}

                    current_line = processed_line

                # Process last line
                if current_line:
                    self._process_aci_line(
                        current_line,
                        current_dn,
                        orclaci_list,
                        entry_level_aci_list,
                        entries,
                        parse_orclaci=parse_orclaci,
                        parse_entry_level_aci=parse_entry_level_aci,
                    )

            return FlextResult[dict[str, list]].ok({
                "orclaci": orclaci_list,
                "entry_level_aci": entry_level_aci_list,
                "entries": entries,
            })

        except Exception as e:
            return FlextResult[dict[str, list]].fail(f"Failed to parse ACI file: {e}")

    def _process_aci_line(
        self,
        line: str,
        current_dn: str,
        orclaci_list: list[FlextLdifModels.OidAci],
        entry_level_aci_list: list[FlextLdifModels.OidEntryLevelAci],
        entries: dict[str, dict[str, list]],
        *,
        parse_orclaci: bool,
        parse_entry_level_aci: bool,
    ) -> None:
        """Process a single ACI line.

        Args:
            line: Complete ACI line (after continuation handling)
            current_dn: Current entry DN
            orclaci_list: List to append parsed orclaci
            entry_level_aci_list: List to append parsed entry-level ACIs
            entries: Dict mapping DN to ACIs
            parse_orclaci: Whether to parse orclaci
            parse_entry_level_aci: Whether to parse entry-level ACIs

        """
        try:
            # Parse orclaci
            if parse_orclaci and line.startswith("orclaci:"):
                result = FlextLdifModels.OidAci.from_ldif_line(line)
                if result.is_success:
                    aci = result.value
                    orclaci_list.append(aci)
                    # Add to entry dict if we have a DN
                    if current_dn and current_dn in entries:
                        entries[current_dn]["orclaci"].append(aci)
                else:
                    self._logger.warning(
                        f"Failed to parse orclaci: {result.error}",
                        extra={"line": line[:100]},
                    )

            # Parse orclentrylevelaci
            elif parse_entry_level_aci and line.startswith("orclentrylevelaci:"):
                result = FlextLdifModels.OidEntryLevelAci.from_ldif_line(line)
                if result.is_success:
                    aci = result.value
                    entry_level_aci_list.append(aci)
                    # Add to entry dict if we have a DN
                    if current_dn and current_dn in entries:
                        entries[current_dn]["entry_level_aci"].append(aci)
                else:
                    self._logger.warning(
                        f"Failed to parse orclentrylevelaci: {result.error}",
                        extra={"line": line[:100]},
                    )

        except Exception as e:
            self._logger.warning(
                f"Error processing ACI line: {e}",
                extra={"line": line[:100]},
            )

    def parse_from_string(self, aci_content: str) -> FlextResult[dict[str, list]]:
        """Parse OID ACIs from string content.

        Args:
            aci_content: LDIF content as string

        Returns:
            FlextResult with dict containing parsed ACIs

        """
        try:
            orclaci_list: list[FlextLdifModels.OidAci] = []
            entry_level_aci_list: list[FlextLdifModels.OidEntryLevelAci] = []
            entries: dict[str, dict[str, list]] = {}

            current_dn = ""

            lines = aci_content.split("\n")
            current_line = ""

            for raw_line in lines:
                line = raw_line.rstrip("\n")

                # Handle line continuation
                if line.startswith(" "):
                    current_line += line[1:]
                    continue

                # Process complete line
                if current_line:
                    self._process_aci_line(
                        current_line,
                        current_dn,
                        orclaci_list,
                        entry_level_aci_list,
                        entries,
                        parse_orclaci=True,
                        parse_entry_level_aci=True,
                    )

                # Check for DN line
                if line.startswith("dn:"):
                    current_dn = line[3:].strip()
                    if current_dn not in entries:
                        entries[current_dn] = {"orclaci": [], "entry_level_aci": []}

                current_line = line

            # Process last line
            if current_line:
                self._process_aci_line(
                    current_line,
                    current_dn,
                    orclaci_list,
                    entry_level_aci_list,
                    entries,
                    parse_orclaci=True,
                    parse_entry_level_aci=True,
                )

            return FlextResult[dict[str, list]].ok({
                "orclaci": orclaci_list,
                "entry_level_aci": entry_level_aci_list,
                "entries": entries,
            })

        except Exception as e:
            return FlextResult[dict[str, list]].fail(
                f"Failed to parse ACIs from string: {e}"
            )


__all__ = ["FlextLdifOidAciParserService"]
