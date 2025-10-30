"""Unified LDIF Writer Service.

Routes to quirks system via FlextLdifRegistry for RFC-compliant LDIF writing.

The FlextLdifWriterService is the single unified interface for all LDIF writing
operations. It uses FlextLdifRegistry to find and route EACH entry to the
appropriate quirk which handles server-specific entry processing.

The writer ONLY:
1. Uses registry.find_entry_quirk() to find appropriate quirk for EACH entry
2. Calls quirk.process_entry() for server-specific entry transformations
3. Formats processed attributes to LDIF text (simple key:value format)
4. Writes LDIF text to output stream

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import Sequence
from io import StringIO
from pathlib import Path
from typing import TextIO, cast

from flext_core import FlextResult, FlextService

from flext_ldif.config import FlextLdifConfig
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.services.registry import FlextLdifRegistry


class FlextLdifWriterService(FlextService[dict[str, object]]):
    """Unified LDIF Writer Service - Routes entries to quirks via registry.

    Uses FlextLdifRegistry dependency injection to find and route entries to
    appropriate quirks. Each entry is processed independently via per-entry
    quirk routing.

    Features:
    - ✅ Per-entry quirk routing via FlextLdifRegistry.find_entry_quirk()
    - ✅ Server-specific entry processing via quirk.process_entry()
    - ✅ Supports RFC 2849/4512 compliant quirks
    - ✅ Server-specific quirks (OID, OUD, OpenLDAP, AD, etc.)
    - ✅ Relaxed mode for broken/non-compliant LDIF
    - ✅ File and string output support

    Example:
        writer = FlextLdifWriterService(
            config=config,
            quirk_registry=registry,
        )

        # Write entries with per-entry quirk routing
        result = writer.write(entries=entries, output_path=Path("output.ldif"))

        # Or create LDIF content as string
        content_result = writer.write_to_string(entries=entries)

    """

    def __init__(
        self,
        *,
        config: FlextLdifConfig,
        quirk_registry: FlextLdifRegistry,
        target_server_type: str | None = None,
    ) -> None:
        """Initialize unified LDIF writer.

        Args:
            config: FlextLdifConfig with mode selection settings
            quirk_registry: Quirk registry for per-entry quirk routing
            target_server_type: Target server type for routing (takes precedence over config)

        """
        super().__init__()
        self._config = config
        self._quirk_registry = quirk_registry
        self._target_server_type = target_server_type
        self._effective_server_type = self._determine_effective_server_type()

    def _determine_effective_server_type(self) -> str:
        """Determine effective server type for writing.

        Priority:
        1. target_server_type parameter (if provided) → routing override
        2. Relaxed mode → "relaxed"
        3. Config manual override → quirks_server_type
        4. Config auto-detect → detected type
        5. Config disabled → "rfc"

        Returns:
            Effective server type string

        """
        if self._target_server_type:
            return self._target_server_type

        if self._config.enable_relaxed_parsing:
            return FlextLdifConstants.ServerTypes.RELAXED

        if self._config.quirks_detection_mode == "manual":
            return self._config.quirks_server_type or FlextLdifConstants.ServerTypes.RFC

        if self._config.quirks_detection_mode == "disabled":
            return FlextLdifConstants.ServerTypes.RFC

        return self._config.ldif_default_server_type

    def write(
        self,
        entries: Sequence[FlextLdifModels.Entry],
        output_path: Path | None = None,
    ) -> FlextResult[dict[str, object]]:
        """Write LDIF entries with per-entry quirk routing via registry.

        Routes each entry to the appropriate quirk from registry for server-specific
        processing. Writer formats processed attributes to LDIF text.

        Args:
            entries: Sequence of Entry objects containing all data
            output_path: Optional file path for output

        Returns:
            FlextResult with write results

        """
        try:
            if output_path:
                return self._write_to_file(entries, output_path)
            return self._write_to_string(entries)

        except Exception as e:
            return FlextResult[dict[str, object]].fail(f"LDIF writing failed: {e}")

    def write_to_file(
        self,
        entries: Sequence[FlextLdifModels.Entry],
        output_path: Path | str,
    ) -> FlextResult[dict[str, object]]:
        """Write LDIF entries to file.

        Args:
            entries: Sequence of Entry objects
            output_path: File path for output

        Returns:
            FlextResult with file write results

        """
        path = Path(output_path) if isinstance(output_path, str) else output_path
        return self.write(entries=entries, output_path=path)

    def write_to_string(
        self,
        entries: Sequence[FlextLdifModels.Entry],
    ) -> FlextResult[str]:
        """Write LDIF entries to string format.

        Args:
            entries: Sequence of Entry objects

        Returns:
            FlextResult with LDIF string content

        """
        result = self.write(entries=entries)

        if result.is_failure:
            return FlextResult[str].fail(result.error)

        content = result.unwrap().get(FlextLdifConstants.DictKeys.CONTENT)
        if isinstance(content, str):
            return FlextResult[str].ok(content)

        return FlextResult[str].fail("No content in result")

    def execute(self) -> FlextResult[dict[str, object]]:
        """Execute writing (FlextService interface).

        Returns:
            FlextResult with write results

        """
        return self.write(entries=[])

    def _write_to_file(
        self,
        entries: Sequence[FlextLdifModels.Entry],
        output_path: Path,
    ) -> FlextResult[dict[str, object]]:
        """Write LDIF to file using per-entry quirk routing.

        Args:
            entries: Sequence of Entry objects
            output_path: Output file path

        Returns:
            FlextResult with write results

        """
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)

            with cast(
                "TextIO",
                output_path.open(
                    "w",
                    encoding=FlextLdifConstants.Encoding.DEFAULT_ENCODING,
                ),
            ) as f:
                self._write_output(f, entries)

            return FlextResult[dict[str, object]].ok({
                FlextLdifConstants.DictKeys.OUTPUT_FILE: str(output_path),
                FlextLdifConstants.DictKeys.ENTRIES_WRITTEN: len(entries),
            })

        except Exception as e:
            return FlextResult[dict[str, object]].fail(f"File writing failed: {e}")

    def _write_to_string(
        self,
        entries: Sequence[FlextLdifModels.Entry],
    ) -> FlextResult[dict[str, object]]:
        """Write LDIF to string using per-entry quirk routing.

        Args:
            entries: Sequence of Entry objects

        Returns:
            FlextResult with string content

        """
        try:
            output = StringIO()
            self._write_output(output, entries)
            content = output.getvalue()
            output.close()

            return FlextResult[dict[str, object]].ok({
                FlextLdifConstants.DictKeys.CONTENT: content,
                FlextLdifConstants.DictKeys.ENTRIES_WRITTEN: len(entries),
            })

        except Exception as e:
            return FlextResult[dict[str, object]].fail(f"String writing failed: {e}")

    def _write_output(
        self,
        output: StringIO | TextIO,
        entries: Sequence[FlextLdifModels.Entry],
    ) -> None:
        """Write entries to output stream via per-entry quirk routing.

        Routes EACH entry to the appropriate quirk via registry for server-specific
        processing, then formats and writes LDIF text.

        Args:
            output: Output stream (file or StringIO)
            entries: Sequence of Entry objects

        """
        output.write(FlextLdifConstants.ConfigDefaults.LDIF_VERSION_STRING + "\n")

        # Write each entry with per-entry quirk routing
        for entry in entries:
            self._write_entry_via_quirk(output, entry)

    def _write_entry_via_quirk(
        self,
        output: StringIO | TextIO,
        entry: FlextLdifModels.Entry,
    ) -> None:
        """Write single entry via quirk routing.

        Pure delegation - finds quirk, routes entry, writes result.

        1. Find quirk via registry.find_entry_quirk()
        2. Process entry via quirk.process_entry()
        3. Get formatted LDIF from quirk.write_entry_to_ldif()
        4. Write to output (no formatting done by writer)

        Args:
            output: Output stream
            entry: Entry to write

        Raises:
            Exception: If quirk not found or processing fails

        """
        # Find quirk for this entry
        quirk = self._quirk_registry.find_entry_quirk(
            server_type=self._effective_server_type,
            entry_dn=entry.dn.value,
            attributes=cast("dict[str, object]", entry.attributes.attributes),
        )

        if not quirk:
            msg = (
                f"No quirk found for entry {entry.dn.value} "
                f"in server type {self._effective_server_type}"
            )
            raise ValueError(msg)

        # Process entry via quirk
        process_result = quirk.process_entry(
            entry_dn=entry.dn.value,
            attributes=cast(
                "dict[str, list[str] | object]", entry.attributes.attributes
            ),
        )

        if process_result.is_failure:
            msg = f"Failed to process entry: {process_result.error}"
            raise ValueError(msg)

        processed_attrs = process_result.unwrap()

        # Get formatted LDIF text from quirk (quirk does ALL formatting)
        write_result = quirk.write_entry_to_ldif(processed_attrs)

        if write_result.is_failure:
            msg = f"Failed to write entry to LDIF: {write_result.error}"
            raise ValueError(msg)

        ldif_text = write_result.unwrap()
        output.write(ldif_text)
        if not ldif_text.endswith("\n"):
            output.write("\n")

    def get_effective_server_type(self) -> str:
        """Get effective server type being used.

        Returns:
            Server type string

        """
        return self._effective_server_type


__all__ = ["FlextLdifWriterService"]
