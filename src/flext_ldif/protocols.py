"""LDIF protocol definitions for flext-ldif domain."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Protocol, Self, runtime_checkable

from flext_core import FlextProtocols, FlextResult

from flext_ldif.constants import c
from flext_ldif.typings import t


class FlextLdifProtocols(FlextProtocols):
    """Unified LDIF protocol definitions extending FlextProtocols."""

    class Ldif:
        """LDIF-specific protocol namespace."""

        @runtime_checkable
        class EntryProtocol(Protocol):
            """Protocol for LDIF Entry models."""

            dn: str | None

            attributes: Mapping[str, Sequence[str]] | None

            metadata: object | None

            def get_objectclass_names(self) -> Sequence[str]:
                """Get list of objectClass values from entry."""
                ...

            def model_copy(
                self,
                *,
                deep: bool = False,
                update: Mapping[str, str | int | float | bool | Sequence[str] | None]
                | None = None,
            ) -> Self:
                """Create a copy of the entry with optional updates."""
                ...

        @runtime_checkable
        class EntryWithDnProtocol(Protocol):
            """Protocol for objects that have a DN attribute."""

            dn: str | None

        @runtime_checkable
        class AttributeValueProtocol(Protocol):
            """Protocol for objects that have attribute values."""

            values: list[str] | str

        @runtime_checkable
        class AclProtocol(Protocol):
            """Protocol for LDIF ACL models."""

            name: str

            raw_acl: str

            server_type: c.Ldif.LiteralTypes.ServerTypeLiteral

        @runtime_checkable
        class SchemaAttributeProtocol(Protocol):
            """Protocol for LDIF SchemaAttribute models."""

            name: str
            oid: str
            syntax: str | None
            single_valued: bool
            description: str | None

        @runtime_checkable
        class SchemaObjectClassProtocol(Protocol):
            """Protocol for LDIF SchemaObjectClass models."""

            name: str
            oid: str
            type: str
            must_attributes: Sequence[str]
            may_attributes: Sequence[str]
            description: str | None

        @runtime_checkable
        class HasParseMethodProtocol(Protocol):
            """Protocol for objects with parse method."""

            def parse(
                self,
                ldif_input: str | Path,
                server_type: str | None = None,
            ) -> FlextResult[Sequence[FlextLdifProtocols.Ldif.EntryProtocol]]:
                """Parse LDIF content."""
                ...

        @runtime_checkable
        class HasEntriesProtocol(Protocol):
            """Protocol for objects that have an entries attribute."""

            entries: Sequence[FlextLdifProtocols.Ldif.EntryProtocol]

        @runtime_checkable
        class SchemaConversionPipelineConfigProtocol(Protocol):
            """Protocol for schema conversion pipeline configuration objects."""

            @property
            def write_method(self) -> Callable[..., FlextResult[str]]:
                """Method to write schema object to LDIF."""
                ...

            @property
            def source_schema(
                self,
            ) -> (
                FlextLdifProtocols.Ldif.SchemaAttributeProtocol
                | FlextLdifProtocols.Ldif.SchemaObjectClassProtocol
                | FlextLdifProtocols.Ldif.SchemaQuirkProtocol
            ):
                """Source schema object to convert."""
                ...

            @property
            def parse_method(self) -> Callable[..., FlextResult[object]]:
                """Method to parse LDIF into schema object."""
                ...

            @property
            def target_schema(
                self,
            ) -> (
                FlextLdifProtocols.Ldif.SchemaAttributeProtocol
                | FlextLdifProtocols.Ldif.SchemaObjectClassProtocol
                | FlextLdifProtocols.Ldif.SchemaQuirkProtocol
            ):
                """Target schema object template."""
                ...

            @property
            def item_name(self) -> str:
                """Name of the schema item being converted."""
                ...

        @runtime_checkable
        class EntryResultProtocol(Protocol):
            """Protocol for EntryResult model."""

            entries: Sequence[FlextLdifProtocols.Ldif.EntryProtocol]

            content: Sequence[FlextLdifProtocols.Ldif.EntryProtocol]

            def __len__(self) -> int:
                """Return the number of entries."""
                ...

        @runtime_checkable
        class SchemaQuirkProtocol(Protocol):
            """Protocol for Schema quirk implementations."""

            def parse(
                self,
                attr_definition: str,
            ) -> FlextResult[
                FlextLdifProtocols.Ldif.SchemaAttributeProtocol
                | FlextLdifProtocols.Ldif.SchemaObjectClassProtocol
            ]:
                """Parse schema definition."""
                ...

            def write(
                self,
                model: FlextLdifProtocols.Ldif.SchemaAttributeProtocol
                | FlextLdifProtocols.Ldif.SchemaObjectClassProtocol,
            ) -> FlextResult[str]:
                """Write schema definition."""
                ...

            def parse_attribute(
                self,
                attr_definition: str,
            ) -> FlextResult[object]:
                """Parse individual attribute definition."""
                ...

            def write_attribute(
                self,
                attribute: object,
            ) -> FlextResult[str]:
                """Write individual attribute definition."""
                ...

            def parse_objectclass(
                self,
                oc_definition: str,
            ) -> FlextResult[object]:
                """Parse individual objectClass definition."""
                ...

            def write_objectclass(
                self,
                objectclass: object,
            ) -> FlextResult[str]:
                """Write individual objectClass definition."""
                ...

        @runtime_checkable
        class AclQuirkProtocol(Protocol):
            """Protocol for ACL quirk implementations."""

            def parse(
                self,
                acl_line: str,
            ) -> FlextResult[FlextLdifProtocols.Ldif.AclProtocol]:
                """Parse ACL definition."""
                ...

            def write(
                self,
                acl_data: FlextLdifProtocols.Ldif.AclProtocol,
            ) -> FlextResult[str]:
                """Write ACL definition."""
                ...

        @runtime_checkable
        class EntryQuirkProtocol(Protocol):
            """Protocol for Entry quirk implementations."""

            def parse(
                self,
                entry_lines: Sequence[str],
            ) -> FlextResult[FlextLdifProtocols.Ldif.EntryProtocol]:
                """Parse entry definition."""
                ...

            def parse_entry(
                self,
                entry_dn: str,
                entry_attrs: Mapping[str, Sequence[str]],
            ) -> FlextResult[FlextLdifProtocols.Ldif.EntryProtocol]:
                """Parse single entry from DN and attributes."""
                ...

            def write(
                self,
                entries: FlextLdifProtocols.Ldif.EntryProtocol
                | Sequence[FlextLdifProtocols.Ldif.EntryProtocol],
                format_options: object | None = None,
            ) -> FlextResult[str]:
                """Write entries to LDIF."""
                ...

        @runtime_checkable
        class QuirkRegistryProtocol(Protocol):
            """Protocol for quirk registry implementations."""

            def get_quirk(
                self,
                server_type: str,
            ) -> FlextLdifProtocols.Ldif.SchemaQuirkProtocol | None:
                """Get quirk for server type."""
                ...

            def register_quirk(
                self,
                server_type: str,
                quirk: FlextLdifProtocols.Ldif.SchemaQuirkProtocol,
            ) -> None:
                """Register a quirk for server type."""
                ...

        @runtime_checkable
        class ServerConstantsProtocol(Protocol):
            """Protocol for server Constants classes."""

            DETECTION_OID_PATTERN: str | None
            DETECTION_ATTRIBUTE_PREFIXES: frozenset[str] | None
            DETECTION_OBJECTCLASS_NAMES: frozenset[str] | None
            DETECTION_DN_MARKERS: frozenset[str] | None
            ACL_ATTRIBUTE_NAME: str | None

        @runtime_checkable
        class ModelWithValidationMetadataProtocol(Protocol):
            """Protocol for models with validation_metadata attribute."""

            validation_metadata: t.Ldif.MetadataType | None

        @runtime_checkable
        class TransformerProtocol[T](Protocol):
            """Protocol for transformers in pipelines."""

            def apply(self, item: T) -> T | FlextResult[T]:
                """Apply the transformation."""
                ...

        @runtime_checkable
        class BatchTransformerProtocol[T](Protocol):
            """Protocol for batch transformers."""

            def apply_batch(self, items: Sequence[T]) -> FlextResult[list[T]]:
                """Apply transformation to batch."""
                ...

        @runtime_checkable
        class FilterProtocol[T](Protocol):
            """Protocol for filters in pipelines."""

            def matches(self, item: object) -> bool:
                """Check if item matches filter criteria."""
                ...

            def __and__(
                self,
                other: FlextLdifProtocols.Ldif.FilterProtocol[T],
            ) -> FlextLdifProtocols.Ldif.FilterProtocol[T]:
                """AND combination."""
                ...

            def __or__(
                self,
                other: FlextLdifProtocols.Ldif.FilterProtocol[T],
            ) -> FlextLdifProtocols.Ldif.FilterProtocol[T]:
                """OR combination."""
                ...

            def __invert__(self) -> FlextLdifProtocols.Ldif.FilterProtocol[T]:
                """NOT negation."""
                ...

        @runtime_checkable
        class ValidatorProtocol[T](Protocol):
            """Protocol for validators."""

            def validate(
                self,
                item: T,
            ) -> FlextResult[object]:
                """Validate an item."""
                ...

        @runtime_checkable
        class ValidationRuleProtocol[T](Protocol):
            """Protocol for validation rules."""

            name: str

            def check(self, item: T) -> tuple[bool, str | None]:
                """Check an item against this rule."""
                ...

        @runtime_checkable
        class PipelineStepProtocol[TIn, TOut](Protocol):
            """Protocol for pipeline steps."""

            name: str

            def execute(self, input_data: TIn) -> FlextResult[TOut]:
                """Execute pipeline step."""
                ...

        @runtime_checkable
        class FluentBuilderProtocol[TConfig](Protocol):
            """Protocol for fluent builders."""

            def build(self) -> TConfig:
                """Build the final configuration object."""
                ...

        @runtime_checkable
        class FluentOpsProtocol[T](Protocol):
            """Protocol for fluent operation chains."""

            def build(self) -> FlextResult[T]:
                """Build/finalize and return the result."""
                ...

        @runtime_checkable
        class LoadableProtocol[T](Protocol):
            """Protocol for loadable data sources."""

            def load(self) -> FlextResult[T]:
                """Load and return the data."""
                ...

        @runtime_checkable
        class PredicateProtocol[T](Protocol):
            """Protocol for predicate functions that test items."""

            def __call__(self, item: T) -> bool:
                """Test if item matches criteria, return True if it does."""
                ...

        @runtime_checkable
        class ValuePredicate(Protocol):
            """Protocol for predicates that test GeneralValueType values."""

            def __call__(self, value: t.GeneralValueType, /) -> bool:
                """Test if value matches predicate condition."""
                ...

        class Constants:
            """Constants namespace for protocol access."""

        class Quirks:
            """Quirks namespace containing quirk protocol aliases."""


p = FlextLdifProtocols
fldif = FlextLdifProtocols

__all__ = ["FlextLdifProtocols", "fldif", "p"]
