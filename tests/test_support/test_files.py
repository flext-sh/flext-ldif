from __future__ import annotations

import shutil
import tempfile
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path
from typing import Self

from flext_core import FlextTypes

from flext_ldif.ldif_data import LdifSample, LdifTestData


class TestFileManager:
    """Manages test files for LDIF testing."""

    def __init__(self, base_dir: Path | None = None) -> None:
        """Initialize file manager with optional base directory."""
        self.base_dir = base_dir
        self.created_files: list[Path] = []
        self.created_dirs: list[Path] = []

    @contextmanager
    def temporary_directory(self) -> Generator[Path]:
        """Create and manage a temporary directory."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            yield temp_path

    def create_ldif_file(
        self,
        content: str,
        filename: str = "test.ldif",
        directory: Path | None = None,
    ) -> Path:
        """Create LDIF file with given content."""
        if directory is None:
            if self.base_dir is None:
                # Use temporary directory
                temp_dir = tempfile.mkdtemp()
                directory = Path(temp_dir)
                self.created_dirs.append(directory)
            else:
                directory = self.base_dir

        directory.mkdir(parents=True, exist_ok=True)
        file_path = directory / filename
        file_path.write_text(content, encoding="utf-8")
        self.created_files.append(file_path)
        return file_path

    def create_sample_file(
        self,
        sample: LdifSample,
        filename: str | None = None,
        directory: Path | None = None,
    ) -> Path:
        """Create file from LDIF sample."""
        if filename is None:
            # Generate filename from sample description
            safe_name = "".join(
                c for c in sample.description.lower() if c.isalnum() or c in " -_"
            ).strip()
            safe_name = safe_name.replace(" ", "_")
            filename = f"{safe_name}.ldif"

        return self.create_ldif_file(sample.content, filename, directory)

    def create_all_samples(self, directory: Path | None = None) -> dict[str, Path]:
        """Create files for all test samples."""
        if directory is None:
            directory = Path(tempfile.mkdtemp())
            self.created_dirs.append(directory)

        files = {}
        for name, sample in LdifTestData.all_samples().items():
            file_path = self.create_sample_file(sample, f"{name}.ldif", directory)
            files[name] = file_path

        return files

    def create_binary_file(
        self,
        binary_content: bytes,
        filename: str = "binary_data.bin",
        directory: Path | None = None,
    ) -> Path:
        """Create binary file for testing binary LDIF data."""
        if directory is None:
            directory = Path(tempfile.mkdtemp())
            self.created_dirs.append(directory)

        directory.mkdir(parents=True, exist_ok=True)
        file_path = directory / filename
        file_path.write_bytes(binary_content)
        self.created_files.append(file_path)
        return file_path

    def create_large_ldif_file(
        self,
        num_entries: int = 1000,
        filename: str = "large_test.ldif",
        directory: Path | None = None,
    ) -> Path:
        """Create large LDIF file for performance testing."""
        sample = LdifTestData.large_dataset(num_entries)
        return self.create_sample_file(sample, filename, directory)

    def create_invalid_file(
        self,
        filename: str = "invalid.ldif",
        directory: Path | None = None,
    ) -> Path:
        """Create file with invalid LDIF data for error testing."""
        sample = LdifTestData.invalid_data()
        return self.create_sample_file(sample, filename, directory)

    def create_empty_file(
        self,
        filename: str = "empty.ldif",
        directory: Path | None = None,
    ) -> Path:
        """Create empty file for edge case testing."""
        return self.create_ldif_file("", filename, directory)

    def create_file_set(
        self,
        samples: FlextTypes.Core.Headers,
        directory: Path | None = None,
    ) -> dict[str, Path]:
        """Create multiple files from content dictionary."""
        if directory is None:
            directory = Path(tempfile.mkdtemp())
            self.created_dirs.append(directory)

        files = {}
        for name, content in samples.items():
            filename = f"{name}.ldif" if not name.endswith(".ldif") else name
            file_path = self.create_ldif_file(content, filename, directory)
            files[name] = file_path

        return files

    def cleanup(self) -> None:
        """Clean up created files and directories."""
        # Remove files
        for file_path in self.created_files:
            if file_path.exists():
                file_path.unlink()

        # Remove directories
        for dir_path in self.created_dirs:
            if dir_path.exists():
                shutil.rmtree(dir_path)

        self.created_files.clear()
        self.created_dirs.clear()

    def __enter__(self) -> Self:
        """Context manager entry."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: object,
    ) -> None:
        """Context manager exit with cleanup."""
        self.cleanup()

    @classmethod
    @contextmanager
    def temporary_files(
        cls, samples: FlextTypes.Core.Headers
    ) -> Generator[dict[str, Path]]:
        """Context manager for temporary files."""
        with cls() as manager:
            files = manager.create_file_set(samples)
            yield files

    @classmethod
    @contextmanager
    def sample_files(cls) -> Generator[dict[str, Path]]:
        """Context manager for all sample files."""
        with cls() as manager:
            files = manager.create_all_samples()
            yield files

    def get_file_info(self, file_path: Path) -> FlextTypes.Core.Dict:
        """Get information about a test file."""
        if not file_path.exists():
            return {"exists": False}

        stat = file_path.stat()
        content = file_path.read_text(encoding="utf-8", errors="replace")

        return {
            "exists": True,
            "size": stat.st_size,
            "lines": content.count("\n") + 1 if content else 0,
            "encoding": "utf-8",
            "is_empty": len(content.strip()) == 0,
            "first_line": content.split("\n")[0] if content else "",
        }
