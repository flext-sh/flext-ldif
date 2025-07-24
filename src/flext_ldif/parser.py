"""FlextLdif parser using flext-core patterns and ldif3 library.

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import re
from io import StringIO
from pathlib import Path
from typing import TYPE_CHECKING, Any

# 🚨 ARCHITECTURAL COMPLIANCE: Using flext-core root namespace imports
from flext_core import FlextResult

try:
    from ldif3 import LDIFParser as Ldif3Parser
except ImportError:
    Ldif3Parser = None

from .models import FlextLdifEntry

if TYPE_CHECKING:
    from .types import LDIFContent


class FlextLdifParser:
    """LDIF parser using flext-core patterns and ldif3 library."""

    def parse_ldif_content(
        self,
        content: str | LDIFContent,
    ) -> FlextResult[Any]:
        """Parse LDIF content into entries using ldif3 if available.

        Args:
            content: LDIF content string

        Returns:
            FlextResult containing list of FlextLdifEntry objects

        """
        try:
            # Convert to string if it's a LDIFContent NewType
            content_str = str(content)

            # Try using ldif3 library first for better LDIF parsing
            if Ldif3Parser is not None:
                ldif3_result = self._parse_with_ldif3(content_str)
                # Use ldif3 result if it succeeds AND has data, OR if content is empty
                if ldif3_result.success and (
                    ldif3_result.data or not content_str.strip()
                ):
                    return ldif3_result
                # If ldif3 succeeds but returns empty for non-empty content, fall back

            # Use simple parsing as fallback
            return self._parse_simple(content_str)

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult.fail(
                f"Failed to parse LDIF content: {e}",
            )

    def _parse_with_ldif3(self, content_str: str) -> FlextResult[Any]:
        """Parse LDIF content using ldif3 library with full feature support."""
        try:
            # Handle empty or whitespace-only content
            if not content_str or not content_str.strip():
                return FlextResult.ok([])

            entries: list[FlextLdifEntry] = []
            ldif_input = StringIO(content_str)

            class FlextLdif3Handler:
                """Enhanced handler supporting both entries and change records."""

                def __init__(self) -> None:
                    self.parsed_records: list[dict[str, Any]] = []
                    self.errors: list[str] = []

                def handle(self, dn: str, entry: dict[str, list[str]]) -> None:
                    """Handle regular LDIF entry records."""
                    try:
                        # Check if this is a change record
                        if "changetype" in entry:
                            self._handle_change_record(dn, entry)
                        else:
                            self._handle_entry_record(dn, entry)
                    except Exception as e:
                        self.errors.append(f"Error processing entry {dn}: {e}")

                def _handle_entry_record(
                    self, dn: str, entry: dict[str, list[str]],
                ) -> None:
                    """Handle standard LDIF entry records."""
                    self.parsed_records.append(
                        {"type": "entry", "dn": dn, "attributes": entry},
                    )

                def _handle_change_record(
                    self, dn: str, entry: dict[str, list[str]],
                ) -> None:
                    """Handle LDIF change records (modify, add, delete, modrdn)."""
                    changetype = entry.get("changetype", [""])[0]

                    # Extract changetype and remove from attributes
                    attributes = {k: v for k, v in entry.items() if k != "changetype"}

                    self.parsed_records.append(
                        {
                            "type": "change",
                            "dn": dn,
                            "changetype": changetype,
                            "attributes": attributes,
                        },
                    )

            handler = FlextLdif3Handler()

            # Configure ldif3 parser with enhanced options
            parser = Ldif3Parser(
                ldif_input,
                strict=False,  # Allow non-strict parsing for better error recovery
                process_url_schemes=["file"],  # Enable basic URL processing
                ignored_attr_types=set(),  # Don't ignore any attributes by default
            )

            parser.handle = handler.handle
            parser.parse()

            # Check for parsing errors
            if handler.errors:
                error_msg = "; ".join(handler.errors[:3])  # Limit error messages
                return FlextResult.fail(f"ldif3 parsing errors: {error_msg}")

            # Convert parsed records to FlextLdifEntry objects
            for record in handler.parsed_records:
                try:
                    entry = self._create_entry_from_record(record)
                    if entry:
                        entries.append(entry)
                except Exception as ex:
                    # Log error but continue processing other entries
                    import logging

                    logger = logging.getLogger(__name__)
                    logger.warning("Failed to create entry from record: %s", ex)
                    continue

            return FlextResult.ok(entries)

        except Exception as e:
            # If ldif3 fails completely, provide detailed error for debugging
            return FlextResult.fail(f"ldif3 parsing failed: {e}")

    def _create_entry_from_record(
        self, record: dict[str, Any],
    ) -> FlextLdifEntry | None:
        """Create FlextLdifEntry from parsed ldif3 record."""
        try:
            dn = record["dn"]
            attributes = record["attributes"]

            # Build LDIF block representation
            ldif_lines = [f"dn: {dn}"]

            # Add changetype if this is a change record
            if record.get("type") == "change":
                changetype = record.get("changetype", "")
                if changetype:
                    ldif_lines.append(f"changetype: {changetype}")

            # Add attributes
            for attr_name, attr_values in attributes.items():
                if isinstance(attr_values, list):
                    for value in attr_values:
                        # Handle base64 encoded values
                        if isinstance(value, bytes):
                            import base64

                            encoded_value = base64.b64encode(value).decode("ascii")
                            ldif_lines.append(f"{attr_name}:: {encoded_value}")
                        else:
                            ldif_lines.append(f"{attr_name}: {value}")
                else:
                    ldif_lines.append(f"{attr_name}: {attr_values}")

            ldif_block = "\n".join(ldif_lines)
            return FlextLdifEntry.from_ldif_block(ldif_block)

        except Exception:
            return None

    def _parse_simple(self, content_str: str) -> FlextResult[Any]:
        """Simple fallback LDIF parsing without ldif3."""
        try:
            entries: list[FlextLdifEntry] = []

            # Handle empty or whitespace-only content
            if not content_str or not content_str.strip():
                return FlextResult.ok(entries)

            # Split into entry blocks (separated by empty lines)
            entry_blocks = re.split(r"\n\s*\n", content_str.strip())

            for block in entry_blocks:
                if block.strip():
                    try:
                        entry = FlextLdifEntry.from_ldif_block(block)
                        entries.append(entry)
                    except ValueError as e:
                        return FlextResult.fail(
                            f"Failed to parse LDIF entry: {e}",
                        )

            if not entries:
                return FlextResult.fail("No valid LDIF entries found in content")
            return FlextResult.ok(entries)

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult.fail(
                f"Failed to parse LDIF content: {e}",
            )

    def parse_ldif_file(self, file_path: str) -> FlextResult[Any]:
        """Parse LDIF file into entries.

        Args:
            file_path: Path to LDIF file

        Returns:
            FlextResult containing list of FlextLdifEntry objects

        """
        try:
            with Path(file_path).open(encoding="utf-8") as f:
                content = f.read()
            from .types import LDIFContent

            return self.parse_ldif_content(LDIFContent(content))

        except OSError as e:
            return FlextResult.fail(
                f"Failed to read LDIF file {file_path}: {e}",
            )


__all__ = [
    "FlextLdifParser",
]
