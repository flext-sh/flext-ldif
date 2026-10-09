"""Base Server Classes for LDIF/LDAP Server Extensions.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import ClassVar, Self, cast, overload, override

from flext_ldif import c, m, p, r, s, t, u
from flext_ldif.servers._base.acl import FlextLdifServersBaseSchemaAcl
from flext_ldif.servers._base.entry import FlextLdifServersBaseEntry
from flext_ldif.servers._base.execute_params import (
    FlextLdifServersBaseExecuteParamsMixin,
)
from flext_ldif.servers._base.schema import FlextLdifServersBaseSchema
from flext_ldif.servers._base.server_io import FlextLdifServersBaseIoMixin
from flext_ldif.servers._base.server_type import FlextLdifServersBaseMroMixin


class FlextLdifServersBase(
    FlextLdifServersBaseMroMixin,
    FlextLdifServersBaseExecuteParamsMixin,
    FlextLdifServersBaseIoMixin,
    s[m.Ldif.Entry],
):
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
            if isinstance(value, c.PRIMITIVES_TYPES):
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
        """Initialize subclass with server_type and priority from Constants.

        Raises:
            AttributeError: If ``constants_class is None``; or if ``server_type_value is
                None``; or if ``priority_value is None``.
        """
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
        """Get schema server instance.

        Returns:
            The resulting ``p.Ldif.SchemaServer``.
        """
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

    @overload
    def __call__(
        self,
        *args: str | t.MutableSequenceOf[m.Ldif.Entry] | None,
        server: p.Ldif.ServerRegistry | None = None,
        settings: p.Ldif.Settings | None = None,
        **fields: t.JsonValue | t.MutableSequenceOf[m.Ldif.Entry],
    ) -> Self | m.Ldif.Entry | str: ...

    def __call__(
        self,
        *args: str | t.MutableSequenceOf[m.Ldif.Entry] | None,
        server: p.Ldif.ServerRegistry | None = None,
        settings: p.Ldif.Settings | None = None,
        **fields: t.JsonValue | t.MutableSequenceOf[m.Ldif.Entry],
    ) -> Self | m.Ldif.Entry | str:
        """Callable interface - use as processor.

        Returns:
            The resulting ``Self | m.Ldif.Entry | str``.
        """
        from flext_ldif.servers._base.mixins import FlextLdifServerMethodsMixin

        configured = FlextLdifServerMethodsMixin.dispatch_builder(
            super().__call__,
            fields,
            frozenset({"ldif_text", "entries", "operation"}),
            server,
            settings,
        )
        if configured is not None:
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
        self._absorb_positional_args(args, execute_kwargs)
        ldif_text, entries, operation = self._extract_execute_params(execute_kwargs)
        result = self.execute(ldif_text=ldif_text, entries=entries, operation=operation)
        value = result.unwrap()
        if isinstance(value, str):
            return value
        as_entry: m.Ldif.Entry = u.Ldif.as_entry(value)
        return as_entry

    @staticmethod
    def _absorb_positional_args(
        args: tuple[str | t.MutableSequenceOf[m.Ldif.Entry] | None, ...],
        execute_kwargs: t.MutableMappingKV[
            str,
            str | int | bool | t.MutableSequenceOf[m.Ldif.Entry],
        ],
    ) -> None:
        """Absorb up to three positional arguments into the execute kwargs."""
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

    @override
    def execute(
        self,
        *,
        ldif_text: str | None = None,
        entries: t.MutableSequenceOf[m.Ldif.Entry] | None = None,
        operation: str | None = None,
    ) -> p.Result[m.Ldif.Entry]:
        """Execute server operation with auto-detection.

        Returns:
            The resulting ``p.Result[m.Ldif.Entry]``.
        """
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

    Acl: ClassVar[type[FlextLdifServersBaseSchemaAcl]] = FlextLdifServersBaseSchemaAcl
    Entry: ClassVar[type[FlextLdifServersBaseEntry]] = FlextLdifServersBaseEntry
    Schema: ClassVar[type[FlextLdifServersBaseSchema]] = FlextLdifServersBaseSchema


__all__: list[str] = ["FlextLdifServersBase"]
