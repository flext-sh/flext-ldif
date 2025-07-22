"""LDIF Service Adapter - Implements flext-core LDIFProcessorInterface.

This adapter bridges the flext-core abstract domain interface with
the concrete FLEXT LDIF infrastructure implementation.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pathlib import Path

    from flext_core.application.interfaces.ldif_services import LDIFEntryProtocol
    from flext_core.domain.shared_types import ServiceResult

from flext_core.application.interfaces.ldif_services import (
    LDIFAdapterInterface,
    LDIFProcessorInterface,
)


class FlextLDIFProcessor(LDIFProcessorInterface):
    """Concrete implementation of LDIFProcessorInterface using FLEXT LDIF."""

    def __init__(self) -> None:
        """Initialize FLEXT LDIF processor."""
        # Delay imports to avoid circular dependencies
        from flext_ldif.processor import LDIFProcessor
        from flext_ldif.utils import LDIFHierarchicalSorter
        from flext_ldif.writer import FlextLDIFWriter

        self._processor = LDIFProcessor()
        self._sorter = LDIFHierarchicalSorter()
        self._writer = FlextLDIFWriter()

    async def read_entries(
        self,
        file_path: Path,
    ) -> ServiceResult[list[LDIFEntryProtocol]]:
        """Read entries from LDIF file using FLEXT LDIF.

        Args:
            file_path: Path to LDIF file

        Returns:
            ServiceResult containing list of entries or error

        """
        try:
            # Use FLEXT LDIF processor to read file
            result = self._processor.parse_ldif_file(file_path)

            from flext_core.domain.shared_types import ServiceResult

            if result.success and result.data:
                # Convert FLEXT LDIF entries to LDIFEntryProtocol format
                entries = []
                for entry in result.data:
                    # Create a simple object that implements LDIFEntryProtocol
                    class LDIFEntry:
                        def __init__(
                            self,
                            dn: str,
                            changetype: str | None,
                            attributes: dict[str, Any],
                        ) -> None:
                            self.dn = dn
                            self.changetype = changetype
                            self.attributes = attributes

                    ldif_entry = LDIFEntry(
                        dn=str(entry.dn),
                        changetype=getattr(entry, "changetype", None),
                        attributes=entry.attributes.attributes
                        if hasattr(entry.attributes, "attributes")
                        else dict(entry.attributes),
                    )
                    entries.append(ldif_entry)

                return ServiceResult.ok(entries)
            return ServiceResult.fail(f"Failed to read LDIF file: {result.error}")

        except Exception as e:
            from flext_core.domain.shared_types import ServiceResult

            return ServiceResult.fail(f"LDIF read error: {e}")

    async def write_entries(
        self,
        entries: list[LDIFEntryProtocol],
        file_path: Path,
    ) -> ServiceResult[bool]:
        """Write entries to LDIF file using FLEXT LDIF.

        Args:
            entries: List of LDIF entries to write
            file_path: Path where to write LDIF file

        Returns:
            ServiceResult indicating success or failure

        """
        try:
            # Convert LDIFEntryProtocol to dict format expected by FLEXT LDIF writer
            dict_entries = []
            for entry in entries:
                dict_entry = {"dn": entry.dn, **entry.attributes}
                if entry.changetype:
                    dict_entry["changetype"] = entry.changetype
                dict_entries.append(dict_entry)

            # Use FLEXT LDIF writer
            result = self._writer.write_entries_to_file(
                file_path=file_path,
                entries=dict_entries,
                sort_hierarchically=True,
                include_comments=True,
            )

            from flext_core.domain.shared_types import ServiceResult

            if result.success:
                return ServiceResult.ok(True)
            return ServiceResult.fail(f"Failed to write LDIF file: {result.error}")

        except Exception as e:
            from flext_core.domain.shared_types import ServiceResult

            return ServiceResult.fail(f"LDIF write error: {e}")

    async def sort_entries_hierarchical(
        self,
        entries: list[LDIFEntryProtocol],
    ) -> ServiceResult[list[LDIFEntryProtocol]]:
        """Sort entries in hierarchical order using FLEXT LDIF.

        Args:
            entries: List of LDIF entries to sort

        Returns:
            ServiceResult containing sorted entries or error

        """
        try:
            # Convert to dict format for FLEXT LDIF sorter
            dict_entries = []
            for entry in entries:
                dict_entry = {"dn": entry.dn, **entry.attributes}
                if entry.changetype:
                    dict_entry["changetype"] = entry.changetype
                dict_entries.append(dict_entry)

            # Use FLEXT LDIF hierarchical sorter
            result = self._sorter.sort_by_hierarchy(dict_entries)

            from flext_core.domain.shared_types import ServiceResult

            if result.success and result.data:
                # Convert back to LDIFEntryProtocol format
                sorted_entries = []
                for sorted_entry in result.data:
                    # Create a simple object that implements LDIFEntryProtocol
                    class LDIFEntry:
                        def __init__(
                            self,
                            dn: str,
                            changetype: str | None,
                            attributes: dict[str, Any],
                        ) -> None:
                            self.dn = dn
                            self.changetype = changetype
                            self.attributes = attributes

                    # Extract changetype and other attributes
                    changetype = sorted_entry.pop("changetype", None)
                    dn = sorted_entry.pop("dn", "")
                    attributes = sorted_entry

                    ldif_entry = LDIFEntry(
                        dn=dn,
                        changetype=changetype,
                        attributes=attributes,
                    )
                    sorted_entries.append(ldif_entry)

                return ServiceResult.ok(sorted_entries)
            return ServiceResult.fail(f"Failed to sort entries: {result.error}")

        except Exception as e:
            from flext_core.domain.shared_types import ServiceResult

            return ServiceResult.fail(f"LDIF sort error: {e}")

    async def validate_entry(
        self,
        entry: LDIFEntryProtocol,
    ) -> ServiceResult[bool]:
        """Validate LDIF entry using FLEXT LDIF validator.

        Args:
            entry: LDIF entry to validate

        Returns:
            ServiceResult indicating validation success or failure

        """
        try:
            # Use FLEXT LDIF validator
            from flext_ldif.validator import LDIFValidator

            validator = LDIFValidator()

            # Convert to LDIF string format for validation
            ldif_content = f"dn: {entry.dn}\n"
            if entry.changetype:
                ldif_content += f"changetype: {entry.changetype}\n"

            for attr_name, attr_values in entry.attributes.items():
                if isinstance(attr_values, list):
                    for value in attr_values:
                        ldif_content += f"{attr_name}: {value}\n"
                else:
                    ldif_content += f"{attr_name}: {attr_values}\n"
            ldif_content += "\n"

            # Validate the LDIF content
            result = validator.validate(ldif_content)

            from flext_core.domain.shared_types import ServiceResult

            if hasattr(result, "success"):
                return (
                    ServiceResult.ok(True)
                    if result.success
                    else ServiceResult.fail(f"Validation failed: {result.error}")
                )
            # If result is just boolean
            return ServiceResult.ok(bool(result))

        except Exception as e:
            from flext_core.domain.shared_types import ServiceResult

            return ServiceResult.fail(f"LDIF validation error: {e}")

    async def merge_entries(
        self,
        entries1: list[LDIFEntryProtocol],
        entries2: list[LDIFEntryProtocol],
    ) -> ServiceResult[list[LDIFEntryProtocol]]:
        """Merge two lists of LDIF entries.

        Args:
            entries1: First list of entries
            entries2: Second list of entries

        Returns:
            ServiceResult containing merged entries or error

        """
        try:
            # Simple merge by combining the lists and removing duplicates by DN
            merged_dict = {}

            # Add entries from first list
            for entry in entries1:
                merged_dict[entry.dn] = entry

            # Add entries from second list (overwrites duplicates)
            for entry in entries2:
                merged_dict[entry.dn] = entry

            # Convert back to list
            merged_entries = list(merged_dict.values())

            from flext_core.domain.shared_types import ServiceResult

            return ServiceResult.ok(merged_entries)

        except Exception as e:
            from flext_core.domain.shared_types import ServiceResult

            return ServiceResult.fail(f"LDIF merge error: {e}")


class FlextLDIFProcessorAdapter(LDIFAdapterInterface):
    """Adapter that provides FLEXT LDIF processor implementation."""

    def get_ldif_processor(self) -> LDIFProcessorInterface:
        """Get FLEXT LDIF processor implementation.

        Returns:
            Configured FLEXT LDIF processor implementation

        """
        return FlextLDIFProcessor()
