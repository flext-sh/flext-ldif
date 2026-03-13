"""LDIF protocol definitions for flext-ldif domain."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from flext_core import FlextProtocols, r

from flext_ldif import c

if TYPE_CHECKING:
    from flext_ldif import m
    from flext_ldif._models.domain import FlextLdifModelsDomains


class FlextLdifProtocols(FlextProtocols):
    """Unified LDIF protocol definitions extending FlextProtocols."""

    class Ldif:
        """LDIF-specific protocol namespace."""

        @runtime_checkable
        class Entry(Protocol):
            """Protocol for LDIF Entry models."""

            dn: str | None
            attributes: Mapping[str, Sequence[str]] | None
            metadata: m.ConfigMap | None

            def get_objectclass_names(self) -> Sequence[str]:
                """Get list of objectClass values from entry."""
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
        class SchemaMetadataProtocol(Protocol):
            """Protocol for schema quirk metadata."""

            @property
            def quirk_type(self) -> str:
                """Get the quirk type (e.g., 'novell', 'rfc')."""
                ...

            @property
            def extensions(self) -> Mapping[str, object]:
                """Get server-specific extensions."""
                ...

            @property
            def schema_format_details(
                self,
            ) -> FlextLdifModelsDomains.SchemaFormatDetails | None:
                """Get original schema formatting details."""
                ...

        @runtime_checkable
        class AclProtocol(Protocol):
            """Protocol for LDIF ACL models."""

            name: str
            raw_acl: str
            server_type: c.Ldif.LiteralTypes.ServerTypeLiteral

        @runtime_checkable
        class SchemaAttributeProtocol(Protocol):
            """Protocol for LDIF schema attributes."""

            @property
            def oid(self) -> str:
                """Get the attribute OID."""
                ...

            @property
            def name(self) -> str:
                """Get the attribute name."""
                ...

            @property
            def desc(self) -> str | None:
                """Get the attribute description."""
                ...

            @property
            def equality(self) -> str | None:
                """Get the equality matching rule."""
                ...

            @property
            def ordering(self) -> str | None:
                """Get the ordering matching rule."""
                ...

            @property
            def substr(self) -> str | None:
                """Get the substring matching rule."""
                ...

            @property
            def syntax(self) -> str | None:
                """Get the attribute syntax OID."""
                ...

            @property
            def length(self) -> int | None:
                """Get the maximum length of the attribute."""
                ...

            @property
            def single_value(self) -> bool:
                """Whether the attribute is single-valued."""
                ...

            @property
            def no_user_modification(self) -> bool:
                """Whether the attribute is non-user-modifiable."""
                ...

            @property
            def usage(self) -> str | None:
                """Get the attribute usage (e.g., 'userApplications')."""
                ...

            @property
            def sup(self) -> str | None:
                """Get the superior attribute type."""
                ...

            @property
            def metadata(
                self,
            ) -> FlextLdifProtocols.Ldif.SchemaMetadataProtocol | None:
                """Get quirk-specific metadata."""
                ...

        @runtime_checkable
        class SchemaObjectClassProtocol(Protocol):
            """Protocol for LDIF schema object classes."""

            @property
            def oid(self) -> str:
                """Get the objectClass OID."""
                ...

            @property
            def name(self) -> str:
                """Get the objectClass name."""
                ...

            @property
            def desc(self) -> str | None:
                """Get the objectClass description."""
                ...

            @property
            def sup(self) -> str | Sequence[str] | None:
                """Get the superior objectClass(es)."""
                ...

            @property
            def kind(self) -> str:
                """Get the class type (e.g., 'STRUCTURAL')."""
                ...

            @property
            def must(self) -> Sequence[str] | None:
                """Get the required attributes."""
                ...

            @property
            def may(self) -> Sequence[str] | None:
                """Get the optional attributes."""
                ...

            @property
            def metadata(
                self,
            ) -> FlextLdifProtocols.Ldif.SchemaMetadataProtocol | None:
                """Get quirk-specific metadata."""
                ...

        @runtime_checkable
        class HasParseMethodProtocol(Protocol):
            """Protocol for objects with parse method."""

            def parse(
                self, ldif_input: str | Path, server_type: str | None = None
            ) -> r[Sequence[FlextLdifProtocols.Ldif.Entry]]:
                """Parse LDIF content."""
                ...

        @runtime_checkable
        class HasEntriesProtocol(Protocol):
            """Protocol for objects that have an entries attribute."""

            entries: Sequence[FlextLdifProtocols.Ldif.Entry]

        @runtime_checkable
        class SchemaConversionPipelineConfigProtocol(Protocol):
            """Protocol for schema conversion pipeline configuration objects."""

            @property
            def item_name(self) -> str:
                """Name of the schema item being converted."""
                ...

            @property
            def parse_method(
                self,
            ) -> Callable[
                ...,
                r[
                    FlextLdifProtocols.Ldif.SchemaAttributeProtocol
                    | FlextLdifProtocols.Ldif.SchemaObjectClassProtocol
                ],
            ]:
                """Method to parse LDIF into schema object."""
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
            def write_method(self) -> Callable[..., r[str]]:
                """Method to write schema object to LDIF."""
                ...

        @runtime_checkable
        class EntryResultProtocol(Protocol):
            """Protocol for EntryResult model."""

            entries: Sequence[FlextLdifProtocols.Ldif.Entry]
            content: Sequence[FlextLdifProtocols.Ldif.Entry]

            def __len__(self) -> int:
                """Return the number of entries."""
                ...

        @runtime_checkable
        class SchemaQuirkProtocol(Protocol):
            """Protocol for Schema quirk implementations."""

            def parse(
                self, definition: str
            ) -> r[
                FlextLdifModelsDomains.SchemaAttribute
                | FlextLdifModelsDomains.SchemaObjectClass
            ]:
                """Parse schema definition."""
                ...

            def parse_attribute(
                self, definition: str
            ) -> r[FlextLdifModelsDomains.SchemaAttribute]:
                """Parse individual attribute definition."""
                ...

            def parse_objectclass(
                self, definition: str
            ) -> r[FlextLdifModelsDomains.SchemaObjectClass]:
                """Parse individual objectClass definition."""
                ...

            def write(
                self,
                model: (
                    FlextLdifModelsDomains.SchemaAttribute
                    | FlextLdifModelsDomains.SchemaObjectClass
                ),
            ) -> r[str]:
                """Write schema definition."""
                ...

            def write_attribute(
                self, attr_data: FlextLdifModelsDomains.SchemaAttribute
            ) -> r[str]:
                """Write individual attribute definition."""
                ...

            def write_objectclass(
                self, oc_data: FlextLdifModelsDomains.SchemaObjectClass
            ) -> r[str]:
                """Write individual objectClass definition."""
                ...

        @runtime_checkable
        class AclQuirkProtocol(Protocol):
            """Protocol for ACL quirk implementations."""

            def parse(self, acl_line: str) -> r[FlextLdifModelsDomains.Acl]:
                """Parse ACL definition."""
                ...

            def write(self, acl_data: FlextLdifModelsDomains.Acl) -> r[str]:
                """Write ACL definition."""
                ...

        @runtime_checkable
        class EntryQuirkProtocol(Protocol):
            """Protocol for Entry quirk implementations."""

            def parse(self, ldif_content: str) -> r[list[FlextLdifModelsDomains.Entry]]:
                """Parse entry definition."""
                ...

            def parse_entry(
                self, entry_dn: str, entry_attrs: Mapping[str, list[str]]
            ) -> r[FlextLdifModelsDomains.Entry]:
                """Parse single entry from DN and attributes."""
                ...

            def write(
                self,
                entry_data: FlextLdifModelsDomains.Entry
                | list[FlextLdifModelsDomains.Entry],
                write_options: m.Ldif.WriteFormatOptions | None = None,
            ) -> r[str]:
                """Write entries to LDIF."""
                ...

        @runtime_checkable
        class QuirkRegistryProtocol(Protocol):
            """Protocol for quirk registry implementations."""

            def schema(
                self, server_type: str
            ) -> FlextLdifProtocols.Ldif.SchemaQuirkProtocol | None:
                """Get schema quirk for server type."""
                ...

            def acl(
                self, server_type: str
            ) -> FlextLdifProtocols.Ldif.AclQuirkProtocol | None:
                """Get ACL quirk for server type."""
                ...

            def entry(
                self, server_type: str
            ) -> FlextLdifProtocols.Ldif.EntryQuirkProtocol | None:
                """Get entry quirk for server type."""
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

            validation_metadata: m.ConfigMap | None

        @runtime_checkable
        class TransformerProtocol[T](Protocol):
            """Protocol for transformers in pipelines."""

            def apply(self, item: T) -> T | r[T]:
                """Apply the transformation."""
                ...

        @runtime_checkable
        class BatchTransformerProtocol[T](Protocol):
            """Protocol for batch transformers."""

            def apply_batch(self, items: Sequence[T]) -> r[list[T]]:
                """Apply transformation to batch."""
                ...

        @runtime_checkable
        class FilterProtocol[T](Protocol):
            """Protocol for filters in pipelines."""

            def __and__(
                self, other: FlextLdifProtocols.Ldif.FilterProtocol[T]
            ) -> FlextLdifProtocols.Ldif.FilterProtocol[T]:
                """AND combination."""
                ...

            def __invert__(self) -> FlextLdifProtocols.Ldif.FilterProtocol[T]:
                """NOT negation."""
                ...

            def __or__(
                self, other: FlextLdifProtocols.Ldif.FilterProtocol[T]
            ) -> FlextLdifProtocols.Ldif.FilterProtocol[T]:
                """OR combination."""
                ...

            def matches(self, item: T) -> bool:
                """Check if item matches filter criteria."""
                ...

        @runtime_checkable
        class ValidatorProtocol[T](Protocol):
            """Protocol for validators."""

            def validate(self, item: T) -> r[T]:
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

            def execute(self, input_data: TIn) -> r[TOut]:
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

            def build(self) -> r[T]:
                """Build/finalize and return the result."""
                ...

        @runtime_checkable
        class ServerBaseProtocol(Protocol):
            """Protocol for LDIF/LDAP server quirk implementations."""

            server_type: str
            priority: int

            def parse(self, ldif_text: str) -> r[object]:
                """Parse LDIF text to Entry models."""
                ...

            def write(
                self,
                entries: list[FlextLdifProtocols.Ldif.Entry],
            ) -> r[str]:
                """Write Entry models to LDIF text."""
                ...

            def execute(
                self,
                *,
                ldif_text: str | None = None,
                entries: (Sequence[FlextLdifProtocols.Ldif.Entry] | None),
                _operation: str | None = None,
            ) -> r[FlextLdifProtocols.Ldif.Entry]:
                """Execute quirk operation with auto-detection."""
                ...

        # =================================================================
        # PROTOCOL ALIASES — for backwards compatibility and shorter access
        # =================================================================

        Entry = Entry
        SchemaAttribute = SchemaAttributeProtocol
        SchemaObjectClass = SchemaObjectClassProtocol
        SchemaQuirk = SchemaQuirkProtocol
        AclQuirk = AclQuirkProtocol
        EntryQuirk = EntryQuirkProtocol
        Acl = AclProtocol
        Parser = SchemaQuirkProtocol  # Often referred to as Parser in tests
        QuirkRegistry = QuirkRegistryProtocol
        ServerBase = ServerBaseProtocol

        @runtime_checkable
        class LoadableProtocol[T](Protocol):
            """Protocol for loadable data sources."""

            def load(self) -> r[T]:
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
            """Protocol for predicates that tesobject values."""

            def __call__(self, value: object, /) -> bool:
                """Test if value matches predicate condition."""
                ...

        class Constants:
            """Constants namespace for protocol access."""

        class Quirks:
            """Quirks namespace containing quirk protocol aliases."""


p = FlextLdifProtocols
__all__ = ["FlextLdifProtocols", "p"]
