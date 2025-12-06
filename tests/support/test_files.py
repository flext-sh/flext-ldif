"""Test file utilities for flext-ldif tests.

Extends object with LDIF-specific file operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import types
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Self

from .ldif_data import LdifSample, LdifTestData


class FileManager:
    """Manages test files for LDIF testing.

    Extends object with LDIF-specific file operations.
    Generic file operations (create_text_file, create_binary_file, etc.)
    are inherited from object.

    """

    def create_ldif_file(
        self,
        content: str,
        filename: str = "test.ldif",
        directory: Path | None = None,
    ) -> Path:
        """Create LDIF file with given content.

        Args:
            content: LDIF content to write.
            filename: Name for the LDIF file (default: test.ldif).
            directory: Directory to create file in.

        Returns:
            Path to the created LDIF file.

        """
        return self.create_text_file(content, filename, directory)

    def create_sample_file(
        self,
        sample: LdifSample,
        filename: str | None = None,
        directory: Path | None = None,
    ) -> Path:
        """Create file from LDIF sample.

        Args:
            sample: LdifSample with content and description.
            filename: Optional filename. If None, generated from description.
            directory: Directory to create file in.

        Returns:
            Path to the created file.

        """
        if filename is None:
            safe_name = "".join(
                c for c in sample.description.lower() if c.isalnum() or c in " -_"
            ).strip()
            safe_name = safe_name.replace(" ", "_")
            filename = f"{safe_name}.ldif"

        return self.create_ldif_file(sample.content, filename, directory)

    def create_all_samples(self, directory: Path | None = None) -> dict[str, Path]:
        """Create files for all test samples.

        Args:
            directory: Directory to create files in. If None, uses temp directory.

        Returns:
            Dictionary mapping sample names to created file paths.

        """
        target_dir = self._resolve_directory(directory)
        files: dict[str, Path] = {}

        for name, sample in LdifTestData.all_samples().items():
            file_path = self.create_sample_file(sample, f"{name}.ldif", target_dir)
            files[name] = file_path

        return files

    def create_large_ldif_file(
        self,
        num_entries: int = 1000,
        filename: str = "large_test.ldif",
        directory: Path | None = None,
    ) -> Path:
        """Create large LDIF file for performance testing.

        Args:
            num_entries: Number of entries to generate.
            filename: Name for the file.
            directory: Directory to create file in.

        Returns:
            Path to the created file.

        """
        sample = LdifTestData.large_dataset(num_entries)
        return self.create_sample_file(sample, filename, directory)

    def create_invalid_file(
        self,
        filename: str = "invalid.ldif",
        directory: Path | None = None,
    ) -> Path:
        """Create file with invalid LDIF data for error testing.

        Args:
            filename: Name for the file.
            directory: Directory to create file in.

        Returns:
            Path to the created file with invalid LDIF data.

        """
        sample = LdifTestData.invalid_data()
        return self.create_sample_file(sample, filename, directory)

    @classmethod
    @contextmanager
    def sample_files(cls) -> Generator[dict[str, Path]]:
        """Context manager for all sample files.

        Yields:
            Dictionary mapping sample names to file paths.

        """
        with cls() as manager:
            files = manager.create_all_samples()
            yield files

    @classmethod
    @contextmanager
    def ldif_files(
        cls,
        files: dict[str, str],
    ) -> Generator[dict[str, Path]]:
        """Context manager for LDIF files.

        Args:
            files: Dictionary mapping names to LDIF content.

        Yields:
            Dictionary mapping names to created file paths.

        """
        with cls() as manager:
            created_files = manager.create_file_set(files, extension=".ldif")
            yield created_files

    def __init__(self) -> None:
        """Initialize FileManager."""
        self._temp_dir: TemporaryDirectory[str] | None = None

    def __enter__(self) -> Self:
        """Enter context manager."""
        self._temp_dir = TemporaryDirectory()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: types.TracebackType | None,
    ) -> None:
        """Exit context manager."""
        if self._temp_dir:
            self._temp_dir.cleanup()

    def _resolve_directory(self, directory: Path | None) -> Path:
        """Resolve directory for file creation."""
        if directory is not None:
            return directory
        if self._temp_dir:
            return Path(self._temp_dir.name)
        msg = "No directory specified and not in context manager"
        raise RuntimeError(msg)

    def create_text_file(
        self,
        content: str,
        filename: str,
        directory: Path | None = None,
    ) -> Path:
        """Create text file with given content."""
        target_dir = self._resolve_directory(directory)
        file_path = target_dir / filename
        file_path.write_text(content, encoding="utf-8")
        return file_path

    def create_file_set(
        self,
        files: dict[str, str],
        extension: str = "",
    ) -> dict[str, Path]:
        """Create set of files."""
        created = {}
        for name, content in files.items():
            filename = f"{name}{extension}"
            created[name] = self.create_text_file(content, filename)
        return created
