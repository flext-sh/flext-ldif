from pathlib import Path
from typing import Protocol

from flext_core import FlextResult

from flext_ldif.models import FlextLdifEntry

__all__ = [
    "FlextLdifAnalyticsProtocol",
    "FlextLdifParserProtocol",
    "FlextLdifRepositoryProtocol",
    "FlextLdifTransformerProtocol",
    "FlextLdifValidatorProtocol",
    "FlextLdifWriterProtocol",
    "LdifParserProtocol",
    "LdifRepositoryProtocol",
    "LdifTransformerProtocol",
    "LdifValidatorProtocol",
    "LdifWriterProtocol",
]

class FlextLdifParserProtocol(Protocol):
    def parse(self, content: str) -> FlextResult[list[FlextLdifEntry]]: ...
    def parse_file(
        self, file_path: str | Path
    ) -> FlextResult[list[FlextLdifEntry]]: ...
    def parse_entries_from_string(
        self, ldif_string: str
    ) -> FlextResult[list[FlextLdifEntry]]: ...

class FlextLdifValidatorProtocol(Protocol):
    def validate(self, data: list[FlextLdifEntry]) -> FlextResult[bool]: ...
    def validate_entry(self, entry: FlextLdifEntry) -> FlextResult[bool]: ...
    def validate_entries(self, entries: list[FlextLdifEntry]) -> FlextResult[bool]: ...
    def validate_dn_format(self, dn: str) -> FlextResult[bool]: ...

class FlextLdifWriterProtocol(Protocol):
    def write(self, entries: list[FlextLdifEntry]) -> FlextResult[str]: ...
    def write_file(
        self, entries: list[FlextLdifEntry], file_path: str | Path
    ) -> FlextResult[bool]: ...
    def write_entry(self, entry: FlextLdifEntry) -> FlextResult[str]: ...

class FlextLdifRepositoryProtocol(Protocol):
    def find_by_dn(
        self, entries: list[FlextLdifEntry], dn: str
    ) -> FlextResult[FlextLdifEntry | None]: ...
    def filter_by_objectclass(
        self, entries: list[FlextLdifEntry], objectclass: str
    ) -> FlextResult[list[FlextLdifEntry]]: ...
    def filter_by_attribute(
        self, entries: list[FlextLdifEntry], attribute: str, value: str
    ) -> FlextResult[list[FlextLdifEntry]]: ...
    def get_statistics(
        self, entries: list[FlextLdifEntry]
    ) -> FlextResult[dict[str, int]]: ...

class FlextLdifTransformerProtocol(Protocol):
    def transform_entry(self, entry: FlextLdifEntry) -> FlextResult[FlextLdifEntry]: ...
    def transform_entries(
        self, entries: list[FlextLdifEntry]
    ) -> FlextResult[list[FlextLdifEntry]]: ...
    def normalize_dns(
        self, entries: list[FlextLdifEntry]
    ) -> FlextResult[list[FlextLdifEntry]]: ...

class FlextLdifAnalyticsProtocol(Protocol):
    def analyze_entry_patterns(
        self, entries: list[FlextLdifEntry]
    ) -> FlextResult[dict[str, int]]: ...
    def get_objectclass_distribution(
        self, entries: list[FlextLdifEntry]
    ) -> FlextResult[dict[str, int]]: ...
    def get_dn_depth_analysis(
        self, entries: list[FlextLdifEntry]
    ) -> FlextResult[dict[str, int]]: ...

LdifParserProtocol = FlextLdifParserProtocol
LdifValidatorProtocol = FlextLdifValidatorProtocol
LdifWriterProtocol = FlextLdifWriterProtocol
LdifRepositoryProtocol = FlextLdifRepositoryProtocol
LdifTransformerProtocol = FlextLdifTransformerProtocol
