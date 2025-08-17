from collections.abc import Callable
from typing import ClassVar

from flext_core import FlextResult

from flext_ldif.constants import FlextLdifFormatConstants as FlextLdifFormatConstants
from flext_ldif.models import FlextLdifEntry as FlextLdifEntry

type ValidatorFunc = Callable[[str], bool]

class LdifValidator:
    PERSON_CLASSES: ClassVar[set[str]]
    OU_CLASSES: ClassVar[set[str]]
    GROUP_CLASSES: ClassVar[set[str]]
    @classmethod
    def validate_dn(cls, dn_value: str) -> FlextResult[bool]: ...
    @classmethod
    def validate_attribute_name(cls, attr_name: str) -> FlextResult[bool]: ...
    @classmethod
    def validate_required_objectclass(
        cls, entry: FlextLdifEntry
    ) -> FlextResult[bool]: ...
    @classmethod
    def validate_entry_completeness(
        cls, entry: FlextLdifEntry
    ) -> FlextResult[bool]: ...
    @classmethod
    def validate_entry_type(
        cls, entry: FlextLdifEntry, expected_classes: set[str]
    ) -> FlextResult[bool]: ...
    @classmethod
    def is_person_entry(cls, entry: FlextLdifEntry) -> FlextResult[bool]: ...
    @classmethod
    def is_ou_entry(cls, entry: FlextLdifEntry) -> FlextResult[bool]: ...
    @classmethod
    def is_group_entry(cls, entry: FlextLdifEntry) -> FlextResult[bool]: ...

class LdifSchemaValidator:
    @classmethod
    def validate_required_attributes(
        cls, entry: FlextLdifEntry, required_attrs: list[str]
    ) -> FlextResult[bool]: ...
    @classmethod
    def validate_person_schema(cls, entry: FlextLdifEntry) -> FlextResult[bool]: ...
    @classmethod
    def validate_ou_schema(cls, entry: FlextLdifEntry) -> FlextResult[bool]: ...

def validate_attribute_format(attr_name: str, attr_value: str) -> FlextResult[bool]: ...
def validate_dn_format(dn_value: str) -> FlextResult[bool]: ...
def validate_ldif_structure(entry: object) -> FlextResult[bool]: ...
