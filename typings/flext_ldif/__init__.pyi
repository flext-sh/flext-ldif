from collections.abc import Callable

from _typeshed import Incomplete

from .api import FlextLdifAPI as FlextLdifAPI, TLdif as TLdif
from .config import FlextLdifConfig as FlextLdifConfig
from .entry_analytics import FlextLdifAnalyticsService as FlextLdifAnalyticsService
from .entry_repository import FlextLdifRepositoryService as FlextLdifRepositoryService
from .entry_transformer import (
    FlextLdifTransformerService as FlextLdifTransformerService,
)
from .entry_validator import FlextLdifValidatorService as FlextLdifValidatorService
from .exceptions import (
    FlextLdifEntryError as FlextLdifEntryError,
    FlextLdifError as FlextLdifError,
    FlextLdifParseError as FlextLdifParseError,
    FlextLdifValidationError as FlextLdifValidationError,
)
from .ldif_parser import FlextLdifParserService as FlextLdifParserService
from .ldif_writer import FlextLdifWriterService as FlextLdifWriterService
from .models import (
    FlextLdifAttributes as FlextLdifAttributes,
    FlextLdifDistinguishedName as FlextLdifDistinguishedName,
    FlextLdifEntry as FlextLdifEntry,
    FlextLdifFactory as FlextLdifFactory,
)
from .types import (
    AttributeName as AttributeName,
    AttributeValue as AttributeValue,
    FilePath as FilePath,
    FlextLdifAttributesDict as FlextLdifAttributesDict,
    FlextLdifDNDict as FlextLdifDNDict,
    FlextLdifEntryDict as FlextLdifEntryDict,
    LDAPObjectClass as LDAPObjectClass,
    LDIFContent as LDIFContent,
    LDIFLines as LDIFLines,
    ProcessingMode as ProcessingMode,
    StringList as StringList,
    ValidationLevel as ValidationLevel,
)

__all__ = [
    "AttributeName",
    "AttributeValue",
    "FilePath",
    "FlextLdifAPI",
    "FlextLdifAnalyticsService",
    "FlextLdifAttributes",
    "FlextLdifAttributesDict",
    "FlextLdifConfig",
    "FlextLdifDNDict",
    "FlextLdifDistinguishedName",
    "FlextLdifEntry",
    "FlextLdifEntryDict",
    "FlextLdifEntryError",
    "FlextLdifError",
    "FlextLdifFactory",
    "FlextLdifParseError",
    "FlextLdifParserService",
    "FlextLdifRepositoryService",
    "FlextLdifTransformerService",
    "FlextLdifValidationError",
    "FlextLdifValidatorService",
    "FlextLdifWriterService",
    "LDAPObjectClass",
    "LDIFContent",
    "LDIFLines",
    "ProcessingMode",
    "StringList",
    "TLdif",
    "ValidationLevel",
    "__version__",
    "__version_info__",
    "cli_main",
    "flext_ldif_get_api",
    "flext_ldif_parse",
    "flext_ldif_validate",
    "flext_ldif_write",
]

cli_main: Callable[[], None] | None
__version__: str
__version_info__: Incomplete

def flext_ldif_get_api(config: FlextLdifConfig | None = None) -> FlextLdifAPI: ...
def flext_ldif_parse(content: str) -> list[FlextLdifEntry]: ...
def flext_ldif_validate(entries: list[FlextLdifEntry]) -> bool: ...
def flext_ldif_write(entries: list[FlextLdifEntry]) -> str: ...
