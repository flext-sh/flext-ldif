"""FlextLdif processor - main processing class.

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

# 🚨 ARCHITECTURAL COMPLIANCE: Using flext-core root namespace imports
from flext_core import FlextResult

from .config import FlextLdifConfig
from .domain.specifications import (
    FlextLdifPersonSpecification,
    FlextLdifValidSpecification,
)

# REMOVED: Unnecessary DI abstraction for FlextResult
from .parser import FlextLdifParser
from .types import LDIFContent
from .utils import FlextLdifUtils
from .validator import FlextLdifValidator

if TYPE_CHECKING:
    from .models import FlextLdifEntry


class FlextLdifProcessor:
    """Main LDIF processor using flext-core patterns."""

    def __init__(self, config: FlextLdifConfig | None = None) -> None:
        """Initialize LDIF processor.

        Args:
            config: LDIF configuration, creates default if None

        """
        self.config = config or FlextLdifConfig()
        self.parser = FlextLdifParser()
        self.validator = FlextLdifValidator()

        # REMOVED: Unnecessary DI abstraction - use FlextResult directly

        # Initialize domain specifications
        self.valid_spec = FlextLdifValidSpecification()
        self.person_spec = FlextLdifPersonSpecification()

    def parse_ldif_content(self, content: str | LDIFContent) -> FlextResult[Any]:
        """Parse LDIF content into entries.

        Args:
            content: LDIF content string

        Returns:
            FlextResult containing list of FlextLdifEntry objects

        """
        try:
            # Convert to LDIFContent - since LDIFContent is NewType(str),
            # both str and LDIFContent are handled the same way at runtime
            ldif_content = LDIFContent(content) if isinstance(content, str) else content

            # Parse entries
            parse_result = self.parser.parse_ldif_content(ldif_content)
            if not parse_result.success:
                return parse_result

            entries = parse_result.data
            if entries is None:
                return FlextResult.fail(
                    "Failed to parse entries: no data returned",
                )

            # Validate if strict validation is enabled
            if self.config.strict_validation:
                validate_result = self.validator.validate_entries(entries)
                if not validate_result.success:
                    return FlextResult.fail(
                        validate_result.error or "Validation failed",
                    )

            # Check limits
            if len(entries) > self.config.max_entries:
                return FlextResult.fail(
                    f"Too many entries: {len(entries)} > {self.config.max_entries}",
                )

            return FlextResult.ok(entries)

        except (ValueError, TypeError, OSError) as e:
            return FlextResult.fail(f"Processing failed: {e}")

    def parse_ldif_file(self, file_path: str | Path) -> FlextResult[Any]:
        """Parse LDIF file into entries.

        Args:
            file_path: Path to LDIF file

        Returns:
            FlextResult containing list of FlextLdifEntry objects

        """
        try:
            file_path = Path(file_path)

            if not file_path.exists():
                return FlextResult.fail(
                    f"LDIF file not found: {file_path}",
                )

            # Check file size
            file_size = file_path.stat().st_size
            if file_size > self.config.max_entry_size * self.config.max_entries:
                return FlextResult.fail(
                    f"File too large: {file_size} bytes",
                )

            with Path(file_path).open(encoding=self.config.input_encoding) as f:
                content = f.read()

            return self.parse_ldif_content(content)

        except (OSError, UnicodeDecodeError, ValueError) as e:
            return FlextResult.fail(f"File processing failed: {e}")

    def write_ldif_file(
        self,
        entries: list[FlextLdifEntry],
        file_path: str | Path,
    ) -> FlextResult[Any]:
        """Write entries to LDIF file.

        Args:
            entries: List of LDIFEntry objects
            file_path: Output file path

        Returns:
            FlextResult indicating success

        """
        try:
            file_path = Path(file_path)

            # Create output directory if needed
            if self.config.create_output_dir and not file_path.parent.exists():
                file_path.parent.mkdir(parents=True, exist_ok=True)

            # Convert entries to LDIF content
            ldif_content = FlextLdifUtils.entries_to_ldif(entries)

            # Write to file
            with Path(file_path).open("w", encoding=self.config.output_encoding) as f:
                f.write(ldif_content)

            return FlextResult.ok(True)

        except (OSError, UnicodeEncodeError) as e:
            return FlextResult.fail(f"File write failed: {e}")

    def filter_entries(
        self,
        entries: list[FlextLdifEntry],
        object_class: str,
    ) -> list[FlextLdifEntry]:
        """Filter entries by objectClass.

        Args:
            entries: List of LDIFEntry objects
            object_class: ObjectClass to filter by

        Returns:
            Filtered list of entries

        """
        return FlextLdifUtils.filter_entries_by_objectclass(entries, object_class)

    def validate_entries(self, entries: list[FlextLdifEntry]) -> FlextResult[Any]:
        """Validate LDIF entries.

        Args:
            entries: List of LDIFEntry objects

        Returns:
            FlextResult indicating validation success

        """
        return self.validator.validate_entries(entries)

    def filter_valid_entries(
        self,
        entries: list[FlextLdifEntry],
    ) -> FlextResult[list[FlextLdifEntry]]:
        """Filter entries using domain specifications for valid entries.

        Args:
            entries: List of FlextLdifEntry objects to filter

        Returns:
            FlextResult containing valid entries only

        """
        try:
            valid_entries = [
                entry for entry in entries if self.valid_spec.is_satisfied_by(entry)
            ]
            return FlextResult.ok(valid_entries)
        except Exception as e:
            return FlextResult.fail(f"Failed to filter valid entries: {e}")

    def filter_person_entries(
        self,
        entries: list[FlextLdifEntry],
    ) -> FlextResult[list[FlextLdifEntry]]:
        """Filter entries using domain specifications for person entries.

        Args:
            entries: List of FlextLdifEntry objects to filter

        Returns:
            FlextResult containing person entries only

        """
        try:
            person_entries = [
                entry for entry in entries if self.person_spec.is_satisfied_by(entry)
            ]
            return FlextResult.ok(person_entries)
        except Exception as e:
            return FlextResult.fail(f"Failed to filter person entries: {e}")

    def validate_entry_with_specifications(
        self,
        entry: FlextLdifEntry,
    ) -> FlextResult[dict[str, bool]]:
        """Validate single entry using all domain specifications.

        Args:
            entry: FlextLdifEntry to validate

        Returns:
            FlextResult containing specification validation results

        """
        try:
            results = {
                "is_valid": self.valid_spec.is_satisfied_by(entry),
                "is_person": self.person_spec.is_satisfied_by(entry),
            }
            return FlextResult.ok(results)
        except Exception as e:
            return FlextResult.fail(
                f"Failed to validate entry with specifications: {e}",
            )


__all__ = [
    "FlextLdifProcessor",
]
