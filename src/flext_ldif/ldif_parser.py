"""FLEXT-LDIF Parser Service.

LDIF parsing implementation using flext-core patterns.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from flext_core import FlextDomainService, FlextResult, get_logger
from pydantic import Field

if TYPE_CHECKING:
    from .config import FlextLdifConfig
from .constants import DEFAULT_INPUT_ENCODING
from .models import FlextLdifEntry, FlextLdifFactory

logger = get_logger(__name__)


class FlextLdifParserService(FlextDomainService[list[FlextLdifEntry]]):
    """Concrete LDIF parsing service using flext-core patterns."""

    config: FlextLdifConfig | None = Field(default=None)

    def execute(self) -> FlextResult[list[FlextLdifEntry]]:
        """Execute the default parsing operation.

        Returns:
            FlextResult[list[FlextLdifEntry]]: Always returns an empty list in
            this implementation. Real executions should call `parse()` with
            concrete content or use `parse_ldif_file()`.

        """
        # This would be called with specific content in real usage
        return FlextResult.ok([])

    def parse(self, content: str | object) -> FlextResult[list[FlextLdifEntry]]:
        """Parse raw LDIF content into domain entities.

        Args:
            content: Raw LDIF text. Non-string values result in a failure.

        Returns:
            FlextResult[list[FlextLdifEntry]]: Parsed entries on success. For
            empty or whitespace-only content, returns success with an empty
            list. On parse errors, returns failure with context.

        """
        if not isinstance(content, str):
            return FlextResult.fail("Invalid LDIF content type")
        if not content or not content.strip():
            return FlextResult.ok([])

        try:
            entries = []
            entry_blocks = content.strip().split("\n\n")
            failed_blocks = []

            for block in entry_blocks:
                if not block.strip():
                    continue

                entry_result = self._parse_entry_block(block.strip())
                if entry_result.success and entry_result.data:
                    entries.append(entry_result.data)
                elif entry_result.is_failure:
                    logger.warning(f"Failed to parse entry block: {entry_result.error}")
                    failed_blocks.append(entry_result.error)

            # If we have content but no successful entries, it's invalid LDIF
            non_empty_blocks = [b for b in entry_blocks if b.strip()]
            if non_empty_blocks and not entries:
                return FlextResult.fail(
                    f"Invalid LDIF: {len(failed_blocks)} blocks failed to parse",
                )

            return FlextResult.ok(entries)

        except Exception as e:
            return FlextResult.fail(f"Parse error: {e!s}")

    def parse_ldif_file(
        self,
        file_path: str | Path,
        encoding: str = DEFAULT_INPUT_ENCODING,
    ) -> FlextResult[list[FlextLdifEntry]]:
        """Parse an LDIF file into domain entities.

        Args:
            file_path: Path to the LDIF file to read.
            encoding: Text encoding used to read the file.

        Returns:
            FlextResult[list[FlextLdifEntry]]: Parsed entries on success, or
            failure when the file cannot be read or parsed.

        """
        try:
            path_obj = Path(file_path)
            if not path_obj.exists():
                return FlextResult.fail(f"File not found: {file_path}")

            content = path_obj.read_text(encoding=encoding)
            return self.parse(content)

        except Exception as e:
            return FlextResult.fail(f"File read error: {e!s}")

    def parse_entries_from_string(
        self,
        ldif_string: str,
    ) -> FlextResult[list[FlextLdifEntry]]:
        """Parse multiple entries from a single LDIF string.

        This is a thin wrapper over `parse()` provided for clarity in callers
        that already distinguish entry-oriented inputs.

        Args:
            ldif_string: Raw LDIF text containing one or more entries.

        Returns:
            FlextResult[list[FlextLdifEntry]]: Parsed entries or failure.

        """
        return self.parse(ldif_string)

    def _parse_entry_block(self, block: str) -> FlextResult[FlextLdifEntry]:
        """Parse a single LDIF entry block.

        Args:
            block: A contiguous block of LDIF lines representing one entry.

        Returns:
            FlextResult[FlextLdifEntry]: The parsed entry on success, or a
            failure with a descriptive reason when the block is invalid.

        """
        if not block.strip():
            return FlextResult.fail("Empty entry block")

        lines = block.split("\n")
        if not lines:
            return FlextResult.fail("No lines in entry block")

        # Parse DN from first line
        dn_line = lines[0].strip()
        if not dn_line.startswith("dn:"):
            return FlextResult.fail("Entry must start with DN")

        dn = dn_line[3:].strip()
        if not dn:
            return FlextResult.fail("DN cannot be empty")

        # Parse attributes
        attributes: dict[str, list[str]] = {}
        changetype = None

        for raw_line in lines[1:]:
            line = raw_line.strip()
            if not line or ":" not in line:
                continue

            attr_name, attr_value = line.split(":", 1)
            attr_name = attr_name.strip()
            attr_value = attr_value.strip()

            if attr_name == "changetype":
                changetype = attr_value
                continue

            if attr_name not in attributes:
                attributes[attr_name] = []
            attributes[attr_name].append(attr_value)

        return FlextLdifFactory.create_entry(dn, attributes, changetype)


__all__ = ["FlextLdifParserService"]
