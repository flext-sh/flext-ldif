"""Base Quirk Classes for LDIF/LDAP Server Extensions."""

from __future__ import annotations

from abc import ABC
from collections.abc import Callable, Sequence
from typing import (
    ClassVar,
    Self,
    overload,
)

from flext_core import FlextLogger, r, s
from pydantic import ConfigDict

from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif.constants import c
from flext_ldif.models import m
from flext_ldif.results import FlextLdifModelsResults
from flext_ldif.servers._base import (
    FlextLdifServersBaseEntry,
    FlextLdifServersBaseSchema,
    FlextLdifServersBaseSchemaAcl,
)
from flext_ldif.utilities import u


def _get_server_type_from_utilities(
    quirk_class: type[FlextLdifServersBase | object],
) -> c.Ldif.LiteralTypes.ServerTypeLiteral:
    """Get server type from utilities using type-safe access pattern."""
    return u.Ldif.Server.get_parent_server_type(quirk_class)


logger = FlextLogger(__name__)


class FlextLdifServersBase(s[m.Ldif.Entry], ABC):
    """Abstract base class for LDIF/LDAP server quirks as FlextService V2."""

    model_config = ConfigDict(
        arbitrary_types_allowed=True,
        extra="allow",
    )

    server_type: ClassVar[str]
    priority: ClassVar[int]

    def __init__(self, **kwargs: str | float | bool | None) -> None:
        """Initialize base quirk and its nested quirks."""
        super().__init__(**kwargs)

        parent_ref: FlextLdifServersBase = self

        self._schema_quirk = self.Schema()
        object.__setattr__(self._schema_quirk, "_parent_quirk", parent_ref)
        self._acl_quirk = self.Acl()
        object.__setattr__(self._acl_quirk, "_parent_quirk", parent_ref)
        self._entry_quirk = self.Entry()
        object.__setattr__(self._entry_quirk, "_parent_quirk", parent_ref)

    @property
    def acl(self) -> FlextLdifServersBaseSchemaAcl:
        """Access to nested acl quirk instance."""
        return self._acl_quirk

    @property
    def entry(self) -> FlextLdifServersBaseEntry:
        """Access to nested entry quirk instance."""
        return self._entry_quirk

    def __init_subclass__(cls, **kwargs: str | float | bool | None) -> None:
        """Initialize subclass with server_type and priority from Constants."""
        super().__init_subclass__()

        if not hasattr(cls, "Constants"):
            msg = f"{cls.__name__} must define a Constants nested class"
            raise AttributeError(msg)

        constants_class = getattr(cls, "Constants", None)
        if constants_class is None:
            msg = f"{cls.__name__} must define a Constants nested class"
            raise AttributeError(msg)

        if not hasattr(constants_class, "SERVER_TYPE"):
            msg = f"{cls.__name__}.Constants must define SERVER_TYPE"
            raise AttributeError(msg)
        if not hasattr(constants_class, "PRIORITY"):
            msg = f"{cls.__name__}.Constants must define PRIORITY"
            raise AttributeError(msg)

        server_type_value = constants_class.SERVER_TYPE
        priority_value = constants_class.PRIORITY

        type.__setattr__(cls, "server_type", _ServerTypeDescriptor(server_type_value))
        type.__setattr__(cls, "priority", _PriorityDescriptor(priority_value))

    def get_schema_quirk(
        self,
    ) -> object:
        """Get schema quirk instance."""
        return self.schema_quirk

    auto_execute: ClassVar[bool] = False

    def execute(
        self,
        *,
        ldif_text: str | None = None,
        entries: Sequence[m.Ldif.Entry] | None = None,
        _operation: str | None = None,
    ) -> r[m.Ldif.Entry]:
        """Execute quirk operation with auto-detection."""
        if ldif_text is not None and isinstance(ldif_text, str):
            return self._execute_parse(ldif_text)

        if entries is not None and isinstance(entries, Sequence) and entries:
            first_entry = entries[0]
            if isinstance(first_entry, m.Ldif.Entry):
                return r[m.Ldif.Entry].ok(first_entry)
            return r[m.Ldif.Entry].fail(
                f"Invalid entry type: {type(first_entry).__name__}",
            )

        return r[m.Ldif.Entry].fail("No valid parameters")

    def _execute_parse(self, ldif_text: str) -> r[m.Ldif.Entry]:
        """Execute parse operation."""
        parse_result = self.parse(ldif_text)
        if not parse_result.is_success:
            return r[m.Ldif.Entry].fail(
                parse_result.error or "Parse failed",
            )
        parse_response = parse_result.value
        entries = getattr(parse_response, "entries", [])
        if not entries:
            return r[m.Ldif.Entry].fail("No entries parsed")

        first_entry = entries[0]
        if isinstance(first_entry, m.Ldif.Entry):
            return r[m.Ldif.Entry].ok(first_entry)

        return r[m.Ldif.Entry].fail("Invalid entry type")

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
        entries: list[m.Ldif.Entry],
        operation: str | None = None,
    ) -> str: ...

    @overload
    def __call__(
        self,
        ldif_text: str | None = None,
        entries: list[m.Ldif.Entry] | None = None,
        operation: str | None = None,
    ) -> m.Ldif.Entry | str: ...

    def __call__(
        self,
        ldif_text: str | None = None,
        entries: list[m.Ldif.Entry] | None = None,
        operation: str | None = None,
    ) -> m.Ldif.Entry | str:
        """Callable interface - use as processor."""
        result = self.execute(
            ldif_text=ldif_text,
            entries=entries,
            _operation=operation,
        )
        return result.value

    def __new__(
        cls,
        **kwargs: object,
    ) -> Self:
        """Override __new__ to support auto-execute and processor instantiation."""
        instance_raw = object.__new__(cls)
        if not isinstance(instance_raw, cls):
            msg = f"Expected {cls.__name__}, got {type(instance_raw)}"
            raise TypeError(msg)
        instance: Self = instance_raw

        filtered_kwargs: dict[str, str | float | bool | None] = {}
        execute_kwargs: dict[str, str | int | bool | list[str] | None] = {}
        for k, v in kwargs.items():
            value = v
            if isinstance(value, (str, float, bool, type(None))):
                filtered_kwargs[k] = value

            if isinstance(value, (str, int, bool, list, type(None))):
                execute_kwargs[k] = value
        type(instance).__init__(instance, **filtered_kwargs)

        if cls.auto_execute:
            ldif_text, entries, operation = cls._extract_execute_params(execute_kwargs)
            result = instance.execute(
                ldif_text=ldif_text,
                entries=entries,
                _operation=operation,
            )
            unwrapped: m.Ldif.Entry | str = result.value
            if not isinstance(unwrapped, cls):
                msg = f"Expected {cls.__name__}, got {type(unwrapped)}"
                raise TypeError(msg)
            return unwrapped

        return instance

    @staticmethod
    def _extract_ldif_text(
        kwargs: object,
    ) -> str | None:
        """Extract and validate ldif_text parameter."""
        if not isinstance(kwargs, dict) or "ldif_text" not in kwargs:
            return None
        raw = kwargs["ldif_text"]
        if raw is None or isinstance(raw, str):
            return raw
        msg = f"Expected str | None for ldif_text, got {type(raw)}"
        raise TypeError(msg)

    @staticmethod
    def _extract_entries(
        kwargs: object,
    ) -> list[m.Ldif.Entry] | None:
        """Extract and validate entries parameter."""
        if not isinstance(kwargs, dict) or "entries" not in kwargs:
            return None
        raw = kwargs["entries"]
        if raw is None:
            return None
        if not isinstance(raw, list):
            msg = f"Expected list[Entry | None] for entries, got {type(raw)}"
            raise TypeError(msg)
        if not raw:
            return []

        entries: list[m.Ldif.Entry] = []
        for idx in range(len(raw)):
            item: m.Ldif.Entry | str = raw[idx]
            if isinstance(item, m.Ldif.Entry):
                entries.append(item)
            else:
                msg = f"Expected list[Entry] for entries, got item of type {type(item)}"
                raise TypeError(msg)
        return entries

    @staticmethod
    def _extract_operation(
        kwargs: object,
    ) -> str | None:
        """Extract and validate operation parameter."""
        if not isinstance(kwargs, dict):
            return None
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

    @classmethod
    def _extract_execute_params(
        cls,
        kwargs: object,
    ) -> tuple[
        str | None,
        list[m.Ldif.Entry] | None,
        str | None,
    ]:
        """Extract type-safe execution parameters from kwargs."""
        return (
            cls._extract_ldif_text(kwargs),
            cls._extract_entries(kwargs),
            cls._extract_operation(kwargs),
        )

    @property
    def schema_quirk(self) -> FlextLdifServersBaseSchema:
        """Get the Schema quirk instance."""
        return self._schema_quirk

    @property
    def acl_quirk(self) -> FlextLdifServersBaseSchemaAcl:
        """Get the Acl quirk instance."""
        return self._acl_quirk

    @property
    def entry_quirk(self) -> FlextLdifServersBaseEntry:
        """Get the Entry quirk instance."""
        return self._entry_quirk

    def parse(
        self,
        ldif_text: str,
    ) -> r[FlextLdifModelsResults.ParseResponse]:
        """Parse LDIF text to Entry models."""
        entry_class = getattr(type(self), "Entry", None)
        if not entry_class:
            return r[FlextLdifModelsResults.ParseResponse].fail(
                "Entry nested class not available"
            )
        entry_quirk = entry_class()
        entries_result: r[list[m.Ldif.Entry]] = entry_quirk.parse(
            ldif_text,
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

        domain_entries: Sequence[m.Ldif.Entry] = [
            entry if isinstance(entry, m.Ldif.Entry) else entry.model_copy(deep=True)
            for entry in entries
        ]
        parse_response = FlextLdifModelsResults.ParseResponse(
            entries=list(domain_entries),
            statistics=statistics,
            detected_server_type=detected_server,
        )
        return r[FlextLdifModelsResults.ParseResponse].ok(parse_response)

    def write(self, entries: list[m.Ldif.Entry]) -> r[str]:
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

        def format_ldif_output(ldif_lines: list[str]) -> str:
            """Format LDIF output with proper newline handling."""
            ldif = "\n".join(ldif_lines)
            if ldif and not ldif.endswith("\n"):
                ldif += "\n"
            return ldif

        return r.traverse(entries, write_single_entry).map(format_ldif_output)

    def _route_model_to_write(
        self,
        model: m.Ldif.Entry
        | m.Ldif.SchemaAttribute
        | m.Ldif.SchemaObjectClass
        | m.Ldif.Acl,
    ) -> r[str]:
        """Route a single model to appropriate write method."""
        if isinstance(model, m.Ldif.Entry):
            return self.entry.write(model)
        if isinstance(model, FlextLdifModelsDomains.SchemaAttribute):
            return self._schema_quirk.write_attribute(model)
        if isinstance(model, FlextLdifModelsDomains.SchemaObjectClass):
            return self._schema_quirk.write_objectclass(model)
        if isinstance(model, FlextLdifModelsDomains.Acl):
            return self.acl.write(model)

        return r[str].fail(f"Unknown model type: {type(model).__name__}")

    def _handle_parse_operation(
        self,
        ldif_text: str,
    ) -> r[m.Ldif.Entry | str]:
        """Handle parse operation for main quirk."""
        parse_result = self.parse(ldif_text)
        if parse_result.is_success:
            parse_response = parse_result.value
            entries = getattr(parse_response, "entries", [])

            if u.Guards.is_list_non_empty(entries):
                domain_entry = entries[0]

                if isinstance(domain_entry, m.Ldif.Entry):
                    return r[m.Ldif.Entry | str].ok(domain_entry)

                public_entry = m.Ldif.Entry.model_validate(
                    domain_entry.model_dump(mode="python"),
                )
                return r[m.Ldif.Entry | str].ok(public_entry)
            return r[m.Ldif.Entry | str].ok("")
        error_msg: str = parse_result.error or "Parse failed"
        return r[m.Ldif.Entry | str].fail(error_msg)

    def _handle_write_operation(
        self,
        entries: list[m.Ldif.Entry],
    ) -> r[m.Ldif.Entry | str]:
        """Handle write operation for main quirk."""
        write_result = self.write(entries)
        if write_result.is_success:
            written_text: str = write_result.value
            return r[m.Ldif.Entry | str].ok(written_text)
        error_msg: str = write_result.error or "Write failed"
        return r[m.Ldif.Entry | str].fail(error_msg)

    @classmethod
    def _get_server_type_from_mro(
        cls,
        quirk_class: type[object],
    ) -> str:
        """Get server_type from parent class Constants via MRO traversal."""

        def is_valid_server_class(mro_cls: type[object]) -> bool:
            """Check if MRO class is a valid server class with SERVER_TYPE."""
            if not mro_cls.__name__.startswith("FlextLdifServers"):
                return False
            if mro_cls.__name__.endswith(("Schema", "Acl", "Entry")):
                return False
            constants = getattr(mro_cls, "Constants", None)
            return constants is not None and hasattr(constants, "SERVER_TYPE")

        def extract_server_type(mro_cls: type[object]) -> str | None:
            """Extract server type if it's a valid string."""
            constants = getattr(mro_cls, "Constants", None)
            if constants is None:
                return None
            server_type = getattr(constants, "SERVER_TYPE", None)
            return server_type if isinstance(server_type, str) else None

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
            if server_type and isinstance(server_type, str):
                return u.Ldif.Server.normalize_server_type(server_type)
        except StopIteration:
            pass

        msg = (
            f"Cannot find SERVER_TYPE in Constants for quirk class: "
            f"{quirk_class.__name__}"
        )
        raise AttributeError(msg)

    @classmethod
    def _get_priority_from_mro(cls, quirk_class: type[object]) -> int:
        """Get priority from parent class Constants via MRO traversal."""

        def is_valid_server_class(mro_cls: type[object]) -> bool:
            """Check if MRO class is a valid server class with PRIORITY."""
            if not mro_cls.__name__.startswith("FlextLdifServers"):
                return False
            if mro_cls.__name__.endswith(("Schema", "Acl", "Entry")):
                return False
            constants = getattr(mro_cls, "Constants", None)
            return constants is not None and hasattr(constants, "PRIORITY")

        def extract_priority(mro_cls: type[object]) -> int | None:
            """Extract priority if it's a valid integer."""
            constants = getattr(mro_cls, "Constants", None)
            if constants is None:
                return None
            priority = getattr(constants, "PRIORITY", None)
            return priority if isinstance(priority, int) else None

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
    def _register_in_registry(
        cls,
        quirk_instance: (object | FlextLdifServersBase),
        registry: object,
    ) -> None:
        """Helper method to register a quirk instance in the registry."""

        def validate_registry(
            registry_obj: object,
        ) -> (
            Callable[
                [
                    str,
                    object,
                ],
                None,
            ]
            | None
        ):
            """Validate registry has register method."""
            method = getattr(registry_obj, "register_quirk", None)
            if method is not None and callable(method):
                captured = method

                def typed_register(server_type: str, quirk: object) -> None:
                    captured(server_type, quirk)

                return typed_register
            return None

        def perform_registration(
            register_func: (
                Callable[
                    [
                        str,
                        object,
                    ],
                    None,
                ]
                | None
            ),
            instance: (object | FlextLdifServersBase),
        ) -> None:
            """Execute registration if method is available."""
            if register_func is not None:
                required_methods = ("parse", "write")
                if all(
                    hasattr(instance, method) and callable(getattr(instance, method))
                    for method in required_methods
                ):
                    schema_quirk = instance
                    register_func("auto", schema_quirk)

        register_method = validate_registry(registry)
        perform_registration(register_method, quirk_instance)

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


class _ServerTypeDescriptor:
    """Descriptor that returns SERVER_TYPE from Constants (single source of truth)."""

    def __init__(self, value: str) -> None:
        self.value = value

    def __get__(
        self,
        obj: FlextLdifServersBase | None,
        _objtype: type | None = None,
    ) -> str:
        """Return the stored SERVER_TYPE value."""
        return self.value


class _PriorityDescriptor:
    """Descriptor that returns PRIORITY from Constants (single source of truth)."""

    def __init__(self, value: int) -> None:
        self.value = value

    def __get__(
        self,
        obj: FlextLdifServersBase | None,
        _objtype: type | None = None,
    ) -> int:
        """Return the stored PRIORITY value."""
        return self.value


setattr(FlextLdifServersBase, "server_type", _ServerTypeDescriptor("unknown"))
setattr(FlextLdifServersBase, "priority", _PriorityDescriptor(0))

__all__ = [
    "FlextLdifServersBase",
]
