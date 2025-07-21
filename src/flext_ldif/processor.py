"""LDIF processor - main processing class.

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from flext_core import ServiceResult

from .config import LDIFConfig
from .parser import LDIFParser
from .types import LDIFContent
from .utils import LDIFUtils
from .validator import LDIFValidator

if TYPE_CHECKING:
    from .models import LDIFEntry


class LDIFProcessor:
    """Main LDIF processor using flext-core patterns."""

    def __init__(self, config: LDIFConfig | None = None) -> None:
        """Initialize LDIF processor.

        Args:
            config: LDIF configuration, creates default if None

        """
        self.config = config or LDIFConfig()
        self.parser = LDIFParser()
        self.validator = LDIFValidator()

    def parse_ldif_content(self, content: str) -> ServiceResult[list[LDIFEntry]]:
        """Parse LDIF content into entries.

        Args:
            content: LDIF content string

        Returns:
            ServiceResult containing list of LDIFEntry objects

        """
        try:
            ldif_content = LDIFContent(content)

            # Parse entries
            parse_result = self.parser.parse_ldif_content(ldif_content)
            if not parse_result.is_success:
                return parse_result

            entries = parse_result.value
            if entries is None:
                return ServiceResult.fail(
                    "Failed to parse entries: no data returned",
                )

            # Validate if strict validation is enabled
            if self.config.strict_validation:
                validate_result = self.validator.validate_entries(entries)
                if not validate_result.is_success:
                    return ServiceResult.fail(
                        validate_result.error or "Validation failed",
                    )

            # Check limits
            if len(entries) > self.config.max_entries:
                return ServiceResult.fail(
                    f"Too many entries: {len(entries)} > {self.config.max_entries}",
                )

            return ServiceResult.ok(data=entries)

        except (ValueError, TypeError, OSError) as e:
            return ServiceResult.fail(f"Processing failed: {e}")

    def parse_ldif_file(self, file_path: str | Path) -> ServiceResult[list[LDIFEntry]]:
        """Parse LDIF file into entries.

        Args:
            file_path: Path to LDIF file

        Returns:
            ServiceResult containing list of LDIFEntry objects

        """
        try:
            file_path = Path(file_path)

            if not file_path.exists():
                return ServiceResult.fail(
                    f"LDIF file not found: {file_path}",
                )

            # Check file size
            file_size = file_path.stat().st_size
            if file_size > self.config.max_entry_size * self.config.max_entries:
                return ServiceResult.fail(
                    f"File too large: {file_size} bytes",
                )

            with Path(file_path).open(encoding=self.config.input_encoding) as f:
                content = f.read()

            return self.parse_ldif_content(content)

        except (OSError, UnicodeDecodeError, ValueError) as e:
            return ServiceResult.fail(f"File processing failed: {e}")

    def write_ldif_file(
        self,
        entries: list[LDIFEntry],
        file_path: str | Path,
    ) -> ServiceResult[bool]:
        """Write entries to LDIF file.

        Args:
            entries: List of LDIFEntry objects
            file_path: Output file path

        Returns:
            ServiceResult indicating success

        """
        try:
            file_path = Path(file_path)

            # Create output directory if needed
            if self.config.create_output_dir and not file_path.parent.exists():
                file_path.parent.mkdir(parents=True, exist_ok=True)

            # Convert entries to LDIF content
            ldif_content = LDIFUtils.entries_to_ldif(entries)

            # Write to file
            with Path(file_path).open("w", encoding=self.config.output_encoding) as f:
                f.write(ldif_content)

            return ServiceResult.ok(data=True)

        except (OSError, UnicodeEncodeError) as e:
            return ServiceResult.fail(f"File write failed: {e}")

    def filter_entries(
        self,
        entries: list[LDIFEntry],
        object_class: str,
    ) -> list[LDIFEntry]:
        """Filter entries by objectClass.

        Args:
            entries: List of LDIFEntry objects
            object_class: ObjectClass to filter by

        Returns:
            Filtered list of entries

        """
        return LDIFUtils.filter_entries_by_objectclass(entries, object_class)

    def validate_entries(self, entries: list[LDIFEntry]) -> ServiceResult[bool]:
        """Validate LDIF entries.

        Args:
            entries: List of LDIFEntry objects

        Returns:
            ServiceResult indicating validation success

        """
        return self.validator.validate_entries(entries)


__all__ = [
    "LDIFProcessor",
]
