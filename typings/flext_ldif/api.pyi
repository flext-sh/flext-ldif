from pathlib import Path
from typing import ClassVar

from _typeshed import Incomplete
from flext_core import FlextResult

from flext_ldif.config import FlextLdifConfig
from flext_ldif.ldif_parser import FlextLdifParserService as _FlextLdifParserService
from flext_ldif.models import FlextLdifEntry

__all__ = ["FlextLdifAPI", "TLdif"]

class TLdif(_FlextLdifParserService):
    DN_PATTERN: ClassVar[object]

class FlextLdifAPI:
    config: Incomplete
    def __init__(self, config: FlextLdifConfig | None = None) -> None: ...
    def parse(self, content: str) -> FlextResult[list[FlextLdifEntry]]: ...
    def parse_file(
        self, file_path: str | Path
    ) -> FlextResult[list[FlextLdifEntry]]: ...
    def parse_entries_from_string(
        self, ldif_string: str
    ) -> FlextResult[list[FlextLdifEntry]]: ...
    def discover_ldif_files(
        self,
        directory_path: str | Path | None = None,
        file_pattern: str = "*.ldif",
        file_path: str | Path | None = None,
        max_file_size_mb: int = 100,
    ) -> FlextResult[list[Path]]: ...
    def write(
        self, entries: list[FlextLdifEntry], file_path: str | None = None
    ) -> FlextResult[str]: ...
    def entries_to_ldif(self, entries: list[FlextLdifEntry]) -> FlextResult[str]: ...
    def write_file(
        self, entries: list[FlextLdifEntry], file_path: str | Path
    ) -> FlextResult[bool]: ...
    def validate(self, entries: list[FlextLdifEntry]) -> FlextResult[bool]: ...
    def validate_entry(self, entry: FlextLdifEntry) -> FlextResult[bool]: ...
    def validate_dn_format(self, dn: str) -> FlextResult[bool]: ...
    def filter_persons(
        self, entries: list[FlextLdifEntry]
    ) -> FlextResult[list[FlextLdifEntry]]: ...
    def filter_groups(
        self, entries: list[FlextLdifEntry]
    ) -> FlextResult[list[FlextLdifEntry]]: ...
    def filter_organizational_units(
        self, entries: list[FlextLdifEntry] | None
    ) -> FlextResult[list[FlextLdifEntry]]: ...
    def filter_valid(
        self, entries: list[FlextLdifEntry] | None
    ) -> FlextResult[list[FlextLdifEntry]]: ...
    def filter_by_objectclass(
        self, entries: list[FlextLdifEntry], objectclass: str
    ) -> FlextResult[list[FlextLdifEntry]]: ...
    def filter_by_attribute(
        self, entries: list[FlextLdifEntry], attribute: str, value: str
    ) -> FlextResult[list[FlextLdifEntry]]: ...
    def find_entry_by_dn(
        self, entries: list[FlextLdifEntry], dn: str
    ) -> FlextResult[FlextLdifEntry | None]: ...
    def get_entry_statistics(
        self, entries: list[FlextLdifEntry]
    ) -> FlextResult[dict[str, int]]: ...
    def analyze_entry_patterns(
        self, entries: list[FlextLdifEntry]
    ) -> FlextResult[dict[str, int]]: ...
    def get_objectclass_distribution(
        self, entries: list[FlextLdifEntry]
    ) -> FlextResult[dict[str, int]]: ...
    def get_dn_depth_analysis(
        self, entries: list[FlextLdifEntry]
    ) -> FlextResult[dict[str, int]]: ...
    def filter_change_records(
        self, entries: list[FlextLdifEntry] | None
    ) -> FlextResult[list[FlextLdifEntry]]: ...
    def sort_hierarchically(
        self, entries: list[FlextLdifEntry] | None
    ) -> FlextResult[list[FlextLdifEntry]]: ...
