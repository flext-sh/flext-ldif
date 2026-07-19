"""Base Server Classes for LDIF/LDAP Server Extensions."""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar, Self, cast, overload, override

from flext_ldif import c, m, p, r, s, t, u
from flext_ldif.servers._base.acl import FlextLdifServersBaseSchemaAcl
from flext_ldif.servers._base.entry import FlextLdifServersBaseEntry
from flext_ldif.servers._base.mixins import FlextLdifServerMethodsMixin
from flext_ldif.servers._base.schema import FlextLdifServersBaseSchema

if TYPE_CHECKING:
    from collections.abc import (
        Callable,
    )


class FlextLdifServersBase(s[m.Ldif.Entry]):
    """Base class for LDIF/LDAP server servers built on `s`."""

    model_config: ClassVar[m.ConfigDict] = m.ConfigDict(
        arbitrary_types_allowed=True,
        extra="forbid",
    )
    server_type: ClassVar[str] = c.Ldif.UNKNOWN_VALUE
    priority: ClassVar[int] = 0

    def __init__(self, **kwargs: t.Ldif.Scalar) -> None:
        """Initialize base server and its nested servers."""
        init_kwargs: t.MutableScalarMapping = {}
        for key, value in kwargs.items():
            if isinstance(value, t.PRIMITIVES_TYPES):
                init_kwargs[key] = value
        super().__init__()
        parent_ref: FlextLdifServersBase = self
        schema_server: FlextLdifServersBaseSchema = self.Schema().model_copy(
            update={"server_type": self.server_type},
        )
        self._schema_server = schema_server
        object.__setattr__(self._schema_server, "_parent_server", parent_ref)
        acl_server: FlextLdifServersBaseSchemaAcl = self.Acl().model_copy(
            update={"server_type": self.server_type},
        )
        self._acl_server = acl_server
        object.__setattr__(self._acl_server, "_parent_server", parent_ref)
        entry_server: FlextLdifServersBaseEntry = self.Entry().model_copy(
            update={"server_type": self.server_type},
        )
        self._entry_server = entry_server
        object.__setattr__(self._entry_server, "_parent_server", parent_ref)

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
        """Access to nested acl server instance."""
        acl_server: FlextLdifServersBaseSchemaAcl = self._acl_server
        return acl_server

    @property
    def acl_server(self) -> p.Ldif.AclServer:
        """Access to nested acl server instance (alias for acl)."""
        acl_server: FlextLdifServersBaseSchemaAcl = self._acl_server
        return acl_server

    @property
    def entry(self) -> FlextLdifServersBaseEntry:
        """Access to nested entry server instance."""
        entry_server: FlextLdifServersBaseEntry = self._entry_server
        return entry_server

    @property
    def entry_server(self) -> p.Ldif.EntryServer:
        """Access to nested entry server instance (alias for entry)."""
        entry_server: FlextLdifServersBaseEntry = self._entry_server
        return entry_server

    @property
    def schema_server(self) -> p.Ldif.SchemaServer:
        """Access to nested schema server instance (alias for schema)."""
        schema_server: FlextLdifServersBaseSchema = self._schema_server
        return schema_server

    def resolve_schema_server(self) -> p.Ldif.SchemaServer:
        """Get schema server instance."""
        return self.schema_server

    auto_execute: ClassVar[bool] = False

    def __new__(cls, **kwargs: t.Ldif.Scalar) -> Self:
        """Override __new__ to support auto-execute and processor instantiation."""
        instance: Self = object.__new__(cls)
        filtered_kwargs: t.MutableConfigValueMapping = {}
        execute_kwargs: t.MutableMappingKV[
            str,
            str | int | bool | t.MutableSequenceOf[m.Ldif.Entry],
        ] = {}
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
                operation=operation,
            )
            unwrapped = result.value
            if isinstance(unwrapped, cls):
                return unwrapped
        return instance

    @overload
    def __call__(
        self,
        *,
        server: p.Ldif.ServerRegistry | None = None,
        settings: p.Ldif.Settings | None = None,
    ) -> Self: ...

    @overload
    def __call__(
        self,
        ldif_text: str | None = None,
        entries: t.MutableSequenceOf[m.Ldif.Entry] | None = None,
        operation: str | None = None,
    ) -> m.Ldif.Entry | str: ...

    def __call__(
        self,
        *args: str | t.MutableSequenceOf[m.Ldif.Entry] | None,
        server: p.Ldif.ServerRegistry | None = None,
        settings: p.Ldif.Settings | None = None,
        **fields: t.JsonValue | t.MutableSequenceOf[m.Ldif.Entry],
    ) -> Self | m.Ldif.Entry | str:
        """Callable interface - use as processor."""
        builder_fields = FlextLdifServerMethodsMixin.project_processor_fields(
            fields,
            frozenset({"ldif_text", "entries", "operation"}),
            force_dispatch=server is not None or settings is not None,
        )
        if builder_fields is not None:
            configured = super().__call__(
                server=server,
                settings=settings,
                **builder_fields,
            )
            return cast("Self", configured)
        execute_kwargs: t.MutableMappingKV[
            str,
            str | int | bool | t.MutableSequenceOf[m.Ldif.Entry],
        ] = {}
        ldif_text_raw = fields.get("ldif_text")
        if ldif_text_raw is not None:
            validated_ldif_text: str = t.str_adapter().validate_python(ldif_text_raw)
            execute_kwargs["ldif_text"] = validated_ldif_text
        entries_raw = fields.get("entries")
        if entries_raw is not None:
            validated_entries: t.MutableSequenceOf[m.Ldif.Entry] = u.Ldif.as_entries(
                entries_raw,
            )
            execute_kwargs["entries"] = validated_entries
        operation_raw = fields.get("operation")
        if operation_raw is not None:
            validated_operation: str = t.str_adapter().validate_python(operation_raw)
            execute_kwargs["operation"] = validated_operation
        for index, value in enumerate(args[:3]):
            match index:
                case 0 if "ldif_text" not in execute_kwargs and isinstance(value, str):
                    execute_kwargs["ldif_text"] = value
                case 0 if "entries" not in execute_kwargs and value is not None:
                    execute_kwargs["entries"] = u.Ldif.as_entries(value)
                case 1 if "entries" not in execute_kwargs and value is not None:
                    execute_kwargs["entries"] = u.Ldif.as_entries(value)
                case 2 if "operation" not in execute_kwargs and isinstance(value, str):
                    execute_kwargs["operation"] = value
                case _:
                    continue
        ldif_text, entries, operation = self._extract_execute_params(execute_kwargs)
        result = self.execute(
            ldif_text=ldif_text,
            entries=entries,
            operation=operation,
        )
        value = result.unwrap()
        if isinstance(value, str):
            return value
        as_entry: m.Ldif.Entry = u.Ldif.as_entry(value)
        return as_entry

    @classmethod
    def _extract_execute_params(
        cls,
        kwargs: t.MutableMappingKV[
            str,
            str | int | bool | t.MutableSequenceOf[m.Ldif.Entry],
        ],
    ) -> tuple[str | None, t.MutableSequenceOf[m.Ldif.Entry] | None, str | None]:
        """Extract type-safe execution parameters from kwargs."""
        return (
            cls._extract_ldif_text(kwargs),
            cls._extract_entries(kwargs),
            cls._extract_operation(kwargs),
        )

    def _get_server_type(self) -> str:
        """Get server_type from parent class Constants via MRO traversal."""
        return self._get_server_type_from_mro(type(self))

    @classmethod
    def _get_priority_from_mro(
        cls,
        server_class: type,
    ) -> int:
        """Get priority from parent class Constants via MRO traversal."""
        for mro_cls in server_class.__mro__:
            if not mro_cls.__name__.startswith(
                "FlextLdifServers",
            ) or mro_cls.__name__.endswith(("Schema", "Acl", "Entry")):
                continue
            priority = getattr(getattr(mro_cls, "Constants", None), "PRIORITY", None)
            if isinstance(priority, int):
                return priority
        msg = f"Cannot find PRIORITY in Constants for server class: {server_class.__name__}"
        raise AttributeError(msg)

    @classmethod
    def _get_server_type_from_mro(
        cls,
        server_class: type,
    ) -> str:
        """Get server_type from parent class Constants via MRO traversal."""
        for mro_cls in server_class.__mro__:
            if not mro_cls.__name__.startswith(
                "FlextLdifServers",
            ) or mro_cls.__name__.endswith(("Schema", "Acl", "Entry")):
                continue
            server_type = getattr(
                getattr(mro_cls, "Constants", None),
                "SERVER_TYPE",
                None,
            )
            if isinstance(server_type, str) and server_type:
                normalized: str = u.Ldif.normalize_server_type(server_type)
                return normalized
        msg = f"Cannot find SERVER_TYPE in Constants for server class: {server_class.__name__}"
        raise AttributeError(msg)

    @classmethod
    def _register_in_registry(
        cls,
        server_instance: p.Ldif.SchemaServer | FlextLdifServersBase,
        registry: p.Ldif.ServerRegistry | t.JsonValue,
    ) -> None:
        """Register a server instance in the registry."""

        def validate_registry(
            registry_obj: p.Ldif.ServerRegistry | t.JsonValue,
        ) -> (
            Callable[
                [str, p.Ldif.SchemaServer | t.JsonValue | FlextLdifServersBase],
                None,
            ]
            | None
        ):
            """Validate registry has register method."""
            method = getattr(registry_obj, "register_server", None)
            if method is not None and callable(method):
                captured = method

                def typed_register(
                    server_type: str,
                    server: p.Ldif.SchemaServer | t.JsonValue | FlextLdifServersBase,
                ) -> None:
                    _ = captured(server_type, server)

                return typed_register
            return None

        def perform_registration(
            register_func: Callable[
                [str, p.Ldif.SchemaServer | t.JsonValue | FlextLdifServersBase],
                None,
            ]
            | None,
            instance: p.Ldif.SchemaServer | FlextLdifServersBase,
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
        perform_registration(register_method_typed, server_instance)

    @staticmethod
    def _extract_entries(
        kwargs: t.MutableMappingKV[
            str,
            str | int | bool | t.MutableSequenceOf[m.Ldif.Entry],
        ],
    ) -> t.MutableSequenceOf[m.Ldif.Entry] | None:
        """Extract and validate entries parameter."""
        if "entries" not in kwargs:
            return None
        raw = kwargs["entries"]
        if not raw:
            return []
        try:
            entries: t.MutableSequenceOf[m.Ldif.Entry] = u.Ldif.as_entries(raw)
            return entries
        except c.EXC_VALIDATION_TYPE as exc:
            msg = f"Expected t.MutableSequenceOf[Entry | None] for entries, got {type(raw)}"
            raise TypeError(msg) from exc

    @staticmethod
    def _extract_ldif_text(
        kwargs: t.MutableMappingKV[
            str,
            str | int | bool | t.MutableSequenceOf[m.Ldif.Entry],
        ],
    ) -> str | None:
        """Extract and validate ldif_text parameter."""
        if "ldif_text" not in kwargs:
            return None
        match kwargs.get("ldif_text"):
            case None:
                return None
            case str() as raw_text:
                return raw_text
            case raw:
                msg = f"Expected str | None for ldif_text, got {type(raw)}"
                raise TypeError(msg)

    @staticmethod
    def _extract_operation(
        kwargs: t.MutableMappingKV[
            str,
            str | int | bool | t.MutableSequenceOf[m.Ldif.Entry],
        ],
    ) -> str | None:
        """Extract and validate operation parameter."""
        if "operation" not in kwargs:
            return None
        match kwargs.get("operation"):
            case None:
                return None
            case "parse":
                return "parse"
            case "write":
                return "write"
            case str() as raw_operation:
                msg = f"Expected 'parse' | 'write' | None for operation, got {raw_operation}"
                raise ValueError(msg)
            case raw:
                msg = (
                    f"Expected 'parse' | 'write' | None for operation, got {type(raw)}"
                )
                raise TypeError(msg)

    @override
    def execute(
        self,
        *,
        ldif_text: str | None = None,
        entries: t.MutableSequenceOf[m.Ldif.Entry] | None = None,
        operation: str | None = None,
    ) -> p.Result[m.Ldif.Entry]:
        """Execute server operation with auto-detection."""
        result: p.Result[m.Ldif.Entry]
        if operation == "parse":
            if ldif_text is None:
                result = r[m.Ldif.Entry].fail("Parse operation requires ldif_text")
            else:
                result = self._execute_parse(ldif_text)
        elif operation == "write":
            if not entries:
                result = r[m.Ldif.Entry].fail("Write operation requires entries")
            else:
                result = r[m.Ldif.Entry].ok(entries[0])
        elif ldif_text is not None:
            result = self._execute_parse(ldif_text)
        elif entries:
            first_entry = entries[0]
            result = r[m.Ldif.Entry].ok(first_entry)
        else:
            result = r[m.Ldif.Entry].fail("No valid parameters")
        return result

    def parse_ldif(self, value: str) -> p.Result[m.Ldif.ParseResponse]:
        """Parse LDIF text to Entry models."""
        entry_server = getattr(self, "entry_server", None)
        if entry_server is None:
            return r[m.Ldif.ParseResponse].fail(
                "Entry server not available",
            )
        detected_server = getattr(self, "server_type", None)
        detected_server_type: c.Ldif.ServerTypes | None = None
        if isinstance(detected_server, c.Ldif.ServerTypes):
            detected_server_type = detected_server
        elif isinstance(detected_server, str):
            try:
                detected_server_type = c.Ldif.ServerTypes(
                    u.Ldif.normalize_server_type(detected_server),
                )
            except ValueError:
                detected_server_type = None

        def normalize_parse_error(error: str) -> str:
            return error or "Entry parsing failed"

        def build_parse_response(
            parsed_entries: t.Ldif.EntrySequence,
        ) -> m.Ldif.ParseResponse:
            domain_entries = u.Ldif.as_entries(parsed_entries)
            for entry in domain_entries:
                if entry.metadata and detected_server_type is not None:
                    entry.metadata = entry.metadata.model_copy(
                        update={"original_server_type": detected_server_type},
                    )
            statistics = m.Ldif.Statistics(
                total_entries=len(domain_entries),
                processed_entries=len(domain_entries),
                detected_server_type=detected_server_type,
            )
            return m.Ldif.ParseResponse(
                entries=[entry.model_copy(deep=True) for entry in domain_entries],
                statistics=statistics,
                detected_server_type=detected_server_type,
            )

        parse_response_result: p.Result[m.Ldif.ParseResponse] = (
            entry_server
            .parse_server(value)
            .map_error(
                normalize_parse_error,
            )
            .map(
                build_parse_response,
            )
        )
        return parse_response_result

    def write(
        self,
        entries: t.MutableSequenceOf[m.Ldif.Entry],
        write_options: m.Ldif.WriteFormatOptions | None = None,
    ) -> p.Result[str]:
        """Write Entry models to LDIF text."""
        entry_server = getattr(self, "entry_server", None)
        if not entry_server:
            return r[str].fail("Entry server not available")
        write_result: p.Result[str] = entry_server.write(entries, write_options).map(
            lambda ldif: ldif if not ldif or ldif.endswith("\n") else f"{ldif}\n",
        )
        return write_result

    def _execute_parse(self, ldif_text: str) -> p.Result[m.Ldif.Entry]:
        """Execute parse operation."""
        parse_result = self.parse_ldif(ldif_text)
        if not parse_result.success:
            return r[m.Ldif.Entry].fail(parse_result.error or "Parse failed")
        entries = u.Ldif.as_entries(parse_result.unwrap())
        if not entries:
            return r[m.Ldif.Entry].fail("No entries parsed")
        first_entry = entries[0]
        return r[m.Ldif.Entry].ok(first_entry)

    class Acl(FlextLdifServersBaseSchemaAcl):
        """Nested Acl server base class."""

    class Entry(FlextLdifServersBaseEntry):
        """Nested Entry server base class."""

    class Schema(FlextLdifServersBaseSchema):
        """Nested Schema server base class."""

    def _normalize_attribute_name(self, attr_name: str) -> str:
        """Normalize attribute name to RFC 2849 canonical form."""
        if not attr_name:
            return attr_name
        if attr_name.lower() == "objectclass":
            return "objectClass"
        return attr_name


__all__: list[str] = ["FlextLdifServersBase"]
