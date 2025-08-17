from pathlib import Path

from _typeshed import Incomplete
from flext_core import FlextResult

from flext_ldif.models import FlextLdifEntry
from flext_ldif.types import LDIFContent

__all__ = ["TLdif"]

class TLdif:
    DN_PATTERN: Incomplete
    ATTR_NAME_PATTERN: Incomplete
    @classmethod
    def parse(cls, content: str | LDIFContent) -> FlextResult[list[FlextLdifEntry]]: ...
    @classmethod
    def validate(cls, entry: FlextLdifEntry | None) -> FlextResult[bool]: ...
    @classmethod
    def validate_entries(cls, entries: list[FlextLdifEntry]) -> FlextResult[bool]: ...
    @classmethod
    def write(cls, entries: list[FlextLdifEntry]) -> FlextResult[str]: ...
    @classmethod
    def write_file(
        cls,
        entries: list[FlextLdifEntry],
        file_path: str | Path,
        encoding: str = "utf-8",
    ) -> FlextResult[bool]: ...
    @classmethod
    def read_file(
        cls, file_path: str | Path, encoding: str = "utf-8"
    ) -> FlextResult[list[FlextLdifEntry]]: ...
