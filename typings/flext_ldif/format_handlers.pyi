from collections.abc import Iterator

from flext_core import FlextResult

__all__ = [
    "FlextLDIFParser",
    "FlextLDIFWriter",
    "is_dn",
    "modernized_ldif_parse",
    "modernized_ldif_write",
]

def is_dn(s: str) -> bool: ...

class FlextLDIFWriter:
    records_written: int
    def __init__(
        self,
        base64_attrs: list[str] | None = None,
        cols: int = 76,
        line_sep: str = "\n",
        encoding: str = "utf-8",
    ) -> None: ...
    def unparse(self, dn: str, record: dict[str, list[str]]) -> None: ...
    def get_output(self) -> str: ...

class FlextLDIFParser:
    line_counter: int
    records_read: int
    def __init__(
        self,
        input_content: str,
        ignored_attr_types: list[str] | None = None,
        encoding: str = "utf-8",
        *,
        strict: bool = True,
    ) -> None: ...
    def parse(self) -> Iterator[tuple[str, dict[str, list[str]]]]: ...

def modernized_ldif_parse(
    content: str,
) -> FlextResult[list[tuple[str, dict[str, list[str]]]]]: ...
def modernized_ldif_write(
    entries: list[tuple[str, dict[str, list[str]]]] | None,
) -> FlextResult[str]: ...
