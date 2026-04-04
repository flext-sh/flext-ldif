"""Base Quirk Classes for LDIF/LDAP Server Extensions."""

from __future__ import annotations

from collections.abc import Callable, MutableSequence
from typing import ClassVar, Self, overload, override

from pydantic import ConfigDict

from flext_core import FlextLogger
from flext_ldif import (
    FlextLdifModelsResults,
    FlextLdifServersBaseEntry,
    FlextLdifServersBaseSchema,
    FlextLdifServersBaseSchemaAcl,
    m,
    p,
    r,
    s,
    t,
    u,
)

logger = FlextLogger(__name__)


class FlextLdifServersBase(s[m.Ldif.Entry]):
    """Base class for LDIF/LDAP server quirks as FlextService V2."""

    model_config: ClassVar[ConfigDict] = ConfigDict(
        arbitrary_types_allowed=True,
        extra="allow",
    )
    server_type: ClassVar[str]
    priority: ClassVar[int]

    def __init__(self, **kwargs: t.Scalar) -> None:
        """Initialize base quirk and its nested quirks."""
        init_kwargs: t.MutableScalarMapping = {}
        for key, value in kwargs.items():
            if u.is_primitive(value):
                init_kwargs[key] = value
        parent_ref: FlextLdifServersBase = self
        self._schema_quirk = self.Schema()
        object.__setattr__(self._schema_quirk, "_parent_quirk", parent_ref)
        self._acl_quirk = self.Acl()
        object.__setattr__(self._acl_quirk, "_parent_quirk", parent_ref)
        self._entry_quirk = self.Entry()
        object.__setattr__(self._entry_quirk, "_parent_quirk", parent_ref)

    def __init_subclass__(cls, **kwargs: str | float | bool | None) -> None:
        """Initialize subclass with server_type and priority from Constants."""
        super().__init_subclass__()
        constants_class = getattr(cls, "Constants", None)
        if constants_class is None:
            msg = f"{cls.__name__} must define a Constants nested class"
            raise AttributeError(msg)
        server_type_value = getattr(constants_class, "SERVER_TYPE", None)
        if server_type_value is None:
            msg = f"{cls.__name__}.Constants must define SERVER_TYPE"
            raise AttributeError(msg)
        server_type_text = str(server_type_value)
        priority_value = getattr(constants_class, "PRIORITY", None)
        if priority_value is None:
            msg = f"{cls.__name__}.Constants must define PRIORITY"
            raise AttributeError(msg)
        priority_number = int(priority_value)
        type.__setattr__(cls, "server_type", server_type_text)
        type.__setattr__(cls, "priority", priority_number)

    @property
    def acl(self) -> FlextLdifServersBaseSchemaAcl:
        """Access to nested acl quirk instance."""
        return self._acl_quirk

    @property
    def acl_quirk(self) -> FlextLdifServersBaseSchemaAcl:
        """Access to nested acl quirk instance (alias for acl)."""
        return self._acl_quirk

    @property
    def entry(self) -> FlextLdifServersBaseEntry:
        """Access to nested entry quirk instance."""
        return self._entry_quirk

    @property
    def entry_quirk(self) -> FlextLdifServersBaseEntry:
        """Access to nested entry quirk instance (alias for entry)."""
        return self._entry_quirk

    @property
    def schema_quirk(self) -> FlextLdifServersBaseSchema:
        """Access to nested schema quirk instance (alias for schema)."""
        return self._schema_quirk

    def get_schema_quirk(self) -> FlextLdifServersBaseSchema:
        """Get schema quirk instance."""
        return self.schema_quirk

    auto_execute: ClassVar[bool] = False

    def __new__(cls, **kwargs: t.Scalar) -> Self:
        """Override __new__ to support auto-execute and processor instantiation."""
        instance: Self = object.__new__(cls)
        filtered_kwargs: t.MutableConfigValueMapping = {}
        execute_kwargs: t.MutableContainerMapping = {}
        for k, v in kwargs.items():
            value = v
            if isinstance(value, (str, float, bool)):
                filtered_kwargs[k] = value
            if isinstance(value, (str, int, bool, list)):
                execute_kwargs[k] = value
        type(instance).__init__(instance, **filtered_kwargs)
        if cls.auto_execute:
            ldif_text, entries, operation = cls._extract_execute_params(execute_kwargs)
            result = instance.execute(
                ldif_text=ldif_text,
                entries=entries,
                _operation=operation,
            )
            unwrapped = result.value
            if isinstance(unwrapped, cls):
                return unwrapped
        return instance

    @overload
    def __call__(
        self,
        ldif_text: str,
        *,
        entries: None = None,
        operation: str | None = None,
    ) -> m.Ldif.Entry | str: ...

    @overload
    def __call__(
        self,
        *,
        ldif_text: None = None,
        entries: MutableSequence[m.Ldif.Entry],
        operation: str | None = None,
    ) -> str: ...

    @overload
    def __call__(
        self,
        ldif_text: str | None = None,
        entries: MutableSequence[m.Ldif.Entry] | None = None,
        operation: str | None = None,
    ) -> m.Ldif.Entry | str: ...

    def __call__(
        self,
        ldif_text: str | None = None,
        entries: MutableSequence[m.Ldif.Entry] | None = None,
        operation: str | None = None,
    ) -> m.Ldif.Entry | str:
        """Callable interface - use as processor."""
        result = self.execute(
            ldif_text=ldif_text,
            entries=entries,
            _operation=operation,
        )
        return result.value

    @classmethod
    def _extract_execute_params(
        cls,
        kwargs: t.MutableContainerMapping,
    ) -> tuple[str | None, MutableSequence[m.Ldif.Entry] | None, str | None]:
        """Extract type-safe execution parameters from kwargs."""
        return (
            cls._extract_ldif_text(kwargs),
            cls._extract_entries(kwargs),
            cls._extract_operation(kwargs),
        )

    @classmethod
    def _get_priority_from_mro(cls, quirk_class: type[t.NormalizedValue]) -> int:
        """Get priority from parent class Constants via MRO traversal."""

        def is_valid_server_class(mro_cls: type[t.NormalizedValue]) -> bool:
            """Check if MRO class is a valid server class with PRIORITY."""
            if not mro_cls.__name__.startswith("FlextLdifServers"):
                return False
            if mro_cls.__name__.endswith(("Schema", "Acl", "Entry")):
                return False
            constants = getattr(mro_cls, "Constants", None)
            priority = getattr(constants, "PRIORITY", None)
            return isinstance(priority, int)

        def extract_priority(mro_cls: type[t.NormalizedValue]) -> int | None:
            """Extract priority if it's a valid integer."""
            constants = getattr(mro_cls, "Constants", None)
            if constants is None:
                return None
            priority = getattr(constants, "PRIORITY", None)
            if isinstance(priority, int):
                return priority
            return None

        try:
            priority = next(
                (
                    p
                    for cls in quirk_class.__mro__
                    if is_valid_server_class(cls)
                    and (p := extract_priority(cls)) is not None
                ),
                None,
            )
            if priority is not None:
                return priority
        except StopIteration:
            pass
        msg = (
            f"Cannot find PRIORITY in Constants for quirk class: {quirk_class.__name__}"
        )
        raise AttributeError(msg)

    @classmethod
    def _get_server_type_from_mro(cls, quirk_class: type[t.NormalizedValue]) -> str:
        """Get server_type from parent class Constants via MRO traversal."""

        def is_valid_server_class(mro_cls: type[t.NormalizedValue]) -> bool:
            """Check if MRO class is a valid server class with SERVER_TYPE."""
            if not mro_cls.__name__.startswith("FlextLdifServers"):
                return False
            if mro_cls.__name__.endswith(("Schema", "Acl", "Entry")):
                return False
            constants = getattr(mro_cls, "Constants", None)
            server_type = getattr(constants, "SERVER_TYPE", None)
            return isinstance(server_type, str)

        def extract_server_type(mro_cls: type[t.NormalizedValue]) -> str | None:
            """Extract server type if it's a valid string."""
            constants = getattr(mro_cls, "Constants", None)
            if constants is None:
                return None
            server_type = getattr(constants, "SERVER_TYPE", None)
            if isinstance(server_type, str):
                return server_type
            return None

        try:
            server_type = next(
                (
                    st
                    for cls in quirk_class.__mro__
                    if is_valid_server_class(cls)
                    and (st := extract_server_type(cls)) is not None
                ),
                None,
            )
            if server_type:
                return u.Ldif.normalize_server_type(server_type)
        except StopIteration:
            pass
        msg = f"Cannot find SERVER_TYPE in Constants for quirk class: {quirk_class.__name__}"
        raise AttributeError(msg)

    @classmethod
    def _register_in_registry(
        cls,
        quirk_instance: p.Ldif.SchemaQuirk | FlextLdifServersBase,
        registry: p.Ldif.QuirkRegistry | t.NormalizedValue,
    ) -> None:
        """Helper method to register a quirk instance in the registry."""

        def validate_registry(
            registry_obj: p.Ldif.QuirkRegistry | t.NormalizedValue,
        ) -> (
            Callable[
                [str, p.Ldif.SchemaQuirk | t.NormalizedValue | FlextLdifServersBase],
                None,
            ]
            | None
        ):
            """Validate registry has register method."""
            method = getattr(registry_obj, "register_quirk", None)
            if method is not None and callable(method):
                captured = method

                def typed_register(
                    server_type: str,
                    quirk: p.Ldif.SchemaQuirk
                    | t.NormalizedValue
                    | FlextLdifServersBase,
                ) -> None:
                    _ = captured(server_type, quirk)

                return typed_register
            return None

        def perform_registration(
            register_func: Callable[
                [str, p.Ldif.SchemaQuirk | t.NormalizedValue | FlextLdifServersBase],
                None,
            ]
            | None,
            instance: p.Ldif.SchemaQuirk | FlextLdifServersBase,
        ) -> None:
            """Execute registration if method is available."""
            if register_func is not None:
                required_methods = ("parse", "write")
                if all(
                    callable(getattr(instance, method, None))
                    for method in required_methods
                ):
                    register_func("auto", instance)

        register_method_typed = validate_registry(registry)
        perform_registration(register_method_typed, quirk_instance)

    @staticmethod
    def _extract_entries(
        kwargs: t.MutableContainerMapping,
    ) -> MutableSequence[m.Ldif.Entry] | None:
        """Extract and validate entries parameter."""
        if "entries" not in kwargs:
            return None
        raw = kwargs["entries"]
        if raw is None:
            return None
        if not isinstance(raw, list):
            msg = f"Expected MutableSequence[Entry | None] for entries, got {type(raw)}"
            raise TypeError(msg)
        if not raw:
            return []
        entries: MutableSequence[m.Ldif.Entry] = []
        for item in raw:
            if isinstance(item, m.Ldif.Entry):
                entries.append(item)
            else:
                msg = f"Expected MutableSequence[Entry] for entries, got item of type {type(item)}"
                raise TypeError(msg)
        return entries

    @staticmethod
    def _extract_ldif_text(
        kwargs: t.MutableContainerMapping,
    ) -> str | None:
        """Extract and validate ldif_text parameter."""
        if "ldif_text" not in kwargs:
            return None
        raw = kwargs["ldif_text"]
        if raw is None or isinstance(raw, str):
            return raw
        msg = f"Expected str | None for ldif_text, got {type(raw)}"
        raise TypeError(msg)

    @staticmethod
    def _extract_operation(
        kwargs: t.MutableContainerMapping,
    ) -> str | None:
        """Extract and validate operation parameter."""
        if "operation" not in kwargs:
            return None
        raw = kwargs["operation"]
        if raw is None:
            return None
        if raw == "parse":
            return "parse"
        if raw == "write":
            return "write"
        msg = f"Expected 'parse' | 'write' | None for operation, got {raw}"
        raise ValueError(msg)

    @override
    def execute(
        self,
        *,
        ldif_text: str | None = None,
        entries: MutableSequence[m.Ldif.Entry] | None = None,
        _operation: str | None = None,
    ) -> r[m.Ldif.Entry]:
        """Execute quirk operation with auto-detection."""
        if ldif_text is not None:
            return self._execute_parse(ldif_text)
        if entries:
            first_entry = entries[0]
            return r[m.Ldif.Entry].ok(first_entry)
        return r[m.Ldif.Entry].fail("No valid parameters")

    def parse_ldif(self, value: str) -> r[FlextLdifModelsResults.ParseResponse]:
        """Parse LDIF text to Entry models."""
        entry_quirk = getattr(self, "entry_quirk", None)
        if entry_quirk is None:
            return r[FlextLdifModelsResults.ParseResponse].fail(
                "Entry quirk not available",
            )
        entries_result: r[MutableSequence[m.Ldif.Entry]] = entry_quirk.parse_quirk(
            value,
        )
        if entries_result.is_failure:
            error_msg = entries_result.error or "Entry parsing failed"
            return r[FlextLdifModelsResults.ParseResponse].fail(error_msg)
        entries = entries_result.value
        detected_server = getattr(self, "server_type", None)
        statistics = FlextLdifModelsResults.Statistics(
            total_entries=len(entries),
            processed_entries=len(entries),
            detected_server_type=detected_server,
        )
        domain_entries: MutableSequence[m.Ldif.Entry] = [
            entry.model_copy(deep=True) for entry in entries
        ]
        parse_response = FlextLdifModelsResults.ParseResponse(
            entries=list(domain_entries),
            statistics=statistics,
            detected_server_type=detected_server,
        )
        return r[FlextLdifModelsResults.ParseResponse].ok(parse_response)

    def write(self, entries: MutableSequence[m.Ldif.Entry]) -> r[str]:
        """Write Entry models to LDIF text."""
        entry_quirk = getattr(self, "entry_quirk", None)
        if not entry_quirk:
            return r[str].fail("Entry quirk not available")

        def write_single_entry(entry_model: m.Ldif.Entry) -> r[str]:
            """Write single entry using entry quirk."""
            if entry_quirk is not None:
                result: r[str] = entry_quirk.write(entry_model)
                return result
            return r[str].fail("No entry quirk found")

        def format_ldif_output(ldif_lines: t.StrSequence) -> str:
            """Format LDIF output with proper newline handling."""
            ldif = "\n".join(ldif_lines)
            if ldif and (not ldif.endswith("\n")):
                ldif += "\n"
            return ldif

        return r.traverse(entries, write_single_entry).map(format_ldif_output)

    def _execute_parse(self, ldif_text: str) -> r[m.Ldif.Entry]:
        """Execute parse operation."""
        parse_result = self.parse_ldif(ldif_text)
        if not parse_result.is_success:
            return r[m.Ldif.Entry].fail(parse_result.error or "Parse failed")
        parse_response = parse_result.value
        entries = getattr(parse_response, "entries", [])
        if not entries:
            return r[m.Ldif.Entry].fail("No entries parsed")
        first_entry = entries[0]
        return r[m.Ldif.Entry].ok(first_entry)

    class Acl(FlextLdifServersBaseSchemaAcl):
        """Nested Acl quirk base class."""

    class Entry(FlextLdifServersBaseEntry):
        """Nested Entry quirk base class."""

    class Schema(FlextLdifServersBaseSchema):
        """Nested Schema quirk base class."""

    def _normalize_attribute_name(self, attr_name: str) -> str:
        """Normalize attribute name to RFC 2849 canonical form."""
        if not attr_name:
            return attr_name
        if attr_name.lower() == "objectclass":
            return "objectClass"
        return attr_name


FlextLdifServersBase.server_type = "unknown"
FlextLdifServersBase.priority = 0
__all__ = ["FlextLdifServersBase"]
