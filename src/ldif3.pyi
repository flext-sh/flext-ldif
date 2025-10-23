# Type stubs for ldif3 library
# This provides typing information for the ldif3 library used in flext-ldif

from collections.abc import Iterator
from io import IOBase

class LDIFParser:
    def __init__(self, input_stream: IOBase) -> None: ...
    def parse(self) -> Iterator[tuple[str, dict[str, list[bytes]]]]: ...
