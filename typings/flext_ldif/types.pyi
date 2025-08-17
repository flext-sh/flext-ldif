from collections.abc import Callable
from typing import NotRequired, TypedDict

from _typeshed import Incomplete

from .constants import (
    DEFAULT_LINE_WRAP_LENGTH as DEFAULT_LINE_WRAP_LENGTH,
    LDAP_DN_ATTRIBUTES as DN_COMPONENT_ATTRIBUTES,
    LDAP_GROUP_CLASSES as GROUP_OBJECT_CLASSES,
    LDAP_OU_CLASSES as STRUCTURAL_OBJECT_CLASSES,
    LDAP_PERSON_CLASSES as PERSON_OBJECT_CLASSES,
    MAX_LINE_WRAP_LENGTH as MAX_LINE_WRAP_LENGTH,
    MIN_LINE_WRAP_LENGTH as MIN_LINE_WRAP_LENGTH,
)

__all__ = [
    "DEFAULT_LINE_WRAP_LENGTH",
    "DN_COMPONENT_ATTRIBUTES",
    "GROUP_OBJECT_CLASSES",
    "MAX_LINE_WRAP_LENGTH",
    "MIN_LINE_WRAP_LENGTH",
    "PERSON_OBJECT_CLASSES",
    "PROCESSING_MODES",
    "STRUCTURAL_OBJECT_CLASSES",
    "SUPPORTED_ENCODINGS",
    "VALIDATION_LEVELS",
    "APIServiceType",
    "AnalyticsFunction",
    "AnalyticsResultData",
    "AnalyticsServiceType",
    "AttributeCount",
    "AttributeDict",
    "AttributeName",
    "AttributeValue",
    "ConfigData",
    "ConfigMergeFunction",
    "ConfigServiceType",
    "ConfigValidateFunction",
    "DistinguishedName",
    "EntryCount",
    "EntryHash",
    "EntryID",
    "ErrorCode",
    "ErrorContext",
    "ErrorMessage",
    "FileContent",
    "FilePath",
    "FilterFunction",
    "FlextLdifAnalyticsResult",
    "FlextLdifAttributesDict",
    "FlextLdifConfigDict",
    "FlextLdifDNDict",
    "FlextLdifEntryDict",
    "FlextLdifParseResult",
    "FlextLdifValidationResult",
    "FormatVersion",
    "GroupType",
    "JSONData",
    "LDAPObjectClass",
    "LDIFBytes",
    "LDIFContent",
    "LDIFLines",
    "LDIFText",
    "LdifAttributes",
    "LdifDN",
    "LdifEntry",
    "LegacyParseFunction",
    "LegacyValidateFunction",
    "LegacyWriteFunction",
    "NormalizeFunction",
    "ObjectClassName",
    "OperationStatus",
    "ParseFileFunction",
    "ParseFunction",
    "ParseResultData",
    "ParserServiceType",
    "PersonType",
    "ProcessingMode",
    "ProcessingTime",
    "RelativeDistinguishedName",
    "RepositoryServiceType",
    "ResultStatus",
    "StringDict",
    "StringList",
    "TransformFunction",
    "TransformerServiceType",
    "ValidateEntryFunction",
    "ValidateFunction",
    "ValidationLevel",
    "ValidationResultData",
    "ValidationScore",
    "ValidatorServiceType",
    "WriteFileFunction",
    "WriteFunction",
    "WriteResultData",
    "WriterServiceType",
]

type LDIFContent = str | bytes
LDIFText = str
LDIFBytes = bytes
type LDIFLines = list[str]
FilePath: Incomplete
type FileContent = str | bytes
StringList: Incomplete
StringDict: Incomplete
type AttributeDict = dict[str, list[str]]
JSONData: Incomplete
ConfigData: Incomplete
LDAPObjectClass: Incomplete
AttributeName: Incomplete
AttributeValue: Incomplete
DistinguishedName: Incomplete
RelativeDistinguishedName = str
EntryID: Incomplete
EntryHash = str
ValidationLevel: Incomplete
ProcessingMode = str
FormatVersion = str
ObjectClassName: Incomplete
PersonType = str
GroupType = str
EntryCount = int
AttributeCount = int
ValidationScore = float
ProcessingTime = float

class FlextLdifDNDict(TypedDict):
    value: str
    depth: NotRequired[int]
    components: NotRequired[dict[str, str]]
    parent_dn: NotRequired[str]

class FlextLdifAttributesDict(TypedDict):
    attributes: dict[str, list[str]]
    total_values: NotRequired[int]
    attribute_names: NotRequired[list[str]]

class FlextLdifEntryDict(TypedDict):
    id: NotRequired[str]
    dn: str
    attributes: dict[str, list[str]]
    changetype: NotRequired[str]
    object_classes: NotRequired[list[str]]

class FlextLdifParseResult(TypedDict):
    entries: list[FlextLdifEntryDict]
    entry_count: int
    parse_time: NotRequired[float]
    warnings: NotRequired[list[str]]

class FlextLdifValidationResult(TypedDict):
    is_valid: bool
    validation_score: NotRequired[float]
    errors: NotRequired[list[str]]
    warnings: NotRequired[list[str]]

class FlextLdifAnalyticsResult(TypedDict):
    total_entries: int
    total_attributes: int
    object_class_distribution: dict[str, int]
    dn_depth_stats: NotRequired[dict[str, float]]
    processing_metrics: NotRequired[dict[str, str | int | float]]

class FlextLdifConfigDict(TypedDict):
    max_entries: NotRequired[int]
    max_entry_size: NotRequired[int]
    strict_validation: NotRequired[bool]
    input_encoding: NotRequired[str]
    output_encoding: NotRequired[str]
    line_wrap_length: NotRequired[int]
    sort_attributes: NotRequired[bool]
    normalize_dn: NotRequired[bool]

type ParseFunction = Callable[[LDIFContent], list[FlextLdifEntryDict]]
ParseFileFunction: Incomplete
type ValidateFunction = Callable[[list[FlextLdifEntryDict]], bool]
type ValidateEntryFunction = Callable[[FlextLdifEntryDict], bool]
type WriteFunction = Callable[[list[FlextLdifEntryDict]], LDIFText]
WriteFileFunction: Incomplete
type AnalyticsFunction = Callable[[list[FlextLdifEntryDict]], FlextLdifAnalyticsResult]
type FilterFunction = Callable[
    [list[FlextLdifEntryDict], str], list[FlextLdifEntryDict]
]
type TransformFunction = Callable[[FlextLdifEntryDict], FlextLdifEntryDict]
type NormalizeFunction = Callable[[str], str]
type ConfigValidateFunction = Callable[[FlextLdifConfigDict], bool]
type ConfigMergeFunction = Callable[
    [FlextLdifConfigDict, FlextLdifConfigDict], FlextLdifConfigDict
]
ErrorMessage: Incomplete
ErrorCode: Incomplete
ErrorContext: Incomplete
type ParseResultData = list[FlextLdifEntryDict]
ValidationResultData = bool
WriteResultData = LDIFText
AnalyticsResultData = FlextLdifAnalyticsResult
OperationStatus = bool
ResultStatus = str
ParserServiceType: Incomplete
ValidatorServiceType: Incomplete
WriterServiceType: Incomplete
AnalyticsServiceType: Incomplete
RepositoryServiceType: Incomplete
TransformerServiceType: Incomplete
ConfigServiceType: Incomplete
APIServiceType: Incomplete
LdifEntry = FlextLdifEntryDict
LdifAttributes = FlextLdifAttributesDict
LdifDN = FlextLdifDNDict
type LegacyParseFunction = Callable[[str], list[dict[str, str | list[str]]]]
type LegacyValidateFunction = Callable[[list[dict[str, str | list[str]]]], bool]
type LegacyWriteFunction = Callable[[list[dict[str, str | list[str]]]], str]
VALIDATION_LEVELS: Incomplete
PROCESSING_MODES: Incomplete
SUPPORTED_ENCODINGS: Incomplete
