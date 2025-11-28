"""Base Quirk Classes for LDIF/LDAP Server Extensions.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Defines base classes for implementing server-specific quirks that extend
RFC-compliant LDIF/LDAP parsing with vendor-specific features.

Quirks allow extending the RFC base without modifying core parser logic.

ARCHITECTURE:
    Base classes use Python 3.13+ abstract base classes (ABC) with
    decorators for explicit inheritance contracts, while also implementing
    all methods required by FlextLdifProtocols for structural typing
    validation.

    This dual approach provides:
    - Explicit inheritance contracts through ABC
    - Structural typing validation through protocols
    - isinstance() checks for protocol compliance
    - Type safety at development and runtime

PROTOCOL COMPLIANCE:
    All base classes and implementations MUST satisfy corresponding protocols:
    - FlextLdifServersBase.Schema -> FlextLdifProtocols.Quirks.SchemaProtocol
    - FlextLdifServersBase.Acl -> FlextLdifProtocols.Quirks.AclProtocol
    - FlextLdifServersBase.Entry -> FlextLdifProtocols.Quirks.EntryProtocol

    All method signatures must match protocol definitions exactly for type safety.
"""

from __future__ import annotations

import re
from abc import ABC
from collections.abc import Callable, Mapping, Sequence
from typing import (
    ClassVar,
    Protocol,
    Self,
    Union,
    cast,
    overload,
)

from flext_core import FlextLogger, FlextResult, FlextRuntime, FlextService
from pydantic import ConfigDict, Field

from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.protocols import FlextLdifProtocols
from flext_ldif.typings import FlextLdifTypes
from flext_ldif.utilities import FlextLdifUtilities

logger = FlextLogger(__name__)

# NOTE: BaseServerConstants has been consolidated into FlextLdifServersRfc.Constants
# All server-specific Constants should inherit from FlextLdifServersRfc.Constants


class FlextLdifServersBase(FlextService[FlextLdifModels.Entry], ABC):
    r"""Abstract base class for LDIF/LDAP server quirks as FlextService V2.

    Configuration:
        Allows arbitrary types and extra attributes for nested quirk classes.

    This class defines the complete contract for a server quirk implementation
    that satisfies `FlextLdifProtocols.Quirks.QuirksPort` through structural typing.
    It uses the `ABC` helper class to define all methods as abstract,
    ensuring that any concrete subclass must implement the full interface.

    Note: This class satisfies FlextLdifProtocols.Quirks.QuirksPort through
    structural typing (duck typing), not through inheritance, to avoid
    metaclass conflicts between ABC and Protocol.

    **FlextService V2 Integration:**
    - Inherits from FlextService for dependency injection, logging, and validation
    - Uses V2 patterns: .result property, .execute(), monadic composition,
      builder pattern
    - Auto-registration in DI container via FlextService
    - Type-safe with TDomainResult = list[Entry] | str
    - Can be used as processor via __call__ or direct method calls

    **Usage as Processor:**
        >>> processor = FlextLdifServersRfc()
        >>> # Parse LDIF text
        >>> entries = processor(ldif_text="dn: cn=test\n")
        >>> # Write Entry models
        >>> ldif = processor(entries=entries)
        >>> # Or explicit methods
        >>> entries = processor.parse("...").result
        >>> ldif = processor.write(entries).result
        >>> # Monadic composition
        >>> entries = processor.parse("...").map(filter_entries).unwrap()

    It also preserves the nested abstract base classes for `Schema`, `Acl`, and
    `Entry` quirks. These nested classes define the internal implementation
    contracts that concrete server classes use to structure their specialized logic.
    """

    model_config = ConfigDict(
        arbitrary_types_allowed=True,
        extra="allow",
    )

    # Type annotations - descriptors behave as their return types when accessed
    server_type: ClassVar[
        FlextLdifConstants.LiteralTypes.ServerTypeLiteral | _DescriptorProtocol
    ]
    priority: ClassVar[int | _DescriptorProtocol]

    # Instance attributes for nested quirks (initialized in __init__)
    # schema_quirk: Self.Schema  # Commented out to avoid forward reference issues
    # acl_quirk: Self.Acl  # Commented out to avoid forward reference issues
    # entry_quirk: Self.Entry  # Commented out to avoid forward reference issues

    def __init__(self, **kwargs: str | float | bool | None) -> None:
        """Initialize base quirk and its nested quirks.

        Args:
            **kwargs: Passed to parent FlextService.__init__.

        """
        super().__init__(**kwargs)
        # Instantiate nested quirks, passing self as _parent_quirk
        # Use private attributes as properties are read-only
        # Type narrowing: self is FlextLdifServersBase instance
        parent_ref: FlextLdifServersBase = self
        self._schema_quirk = self.Schema(_parent_quirk=parent_ref)
        self._acl_quirk = self.Acl(_parent_quirk=parent_ref)
        self._entry_quirk = self.Entry(_parent_quirk=parent_ref)
        # Set parent_quirk Field after initialization
        self._schema_quirk.parent_quirk = parent_ref
        self._acl_quirk.parent_quirk = parent_ref
        self._entry_quirk.parent_quirk = parent_ref

    def __getattr__(
        self, name: str
    ) -> (
        FlextResult[
            FlextLdifModels.SchemaAttribute
            | FlextLdifModels.SchemaObjectClass
            | FlextLdifModels.Acl
            | FlextLdifModels.Entry
            | str
        ]
        | FlextLdifServersBase.Schema
        | FlextLdifServersBase.Acl
        | FlextLdifServersBase.Entry
    ):
        """Delegate method calls to nested Schema, Acl, or Entry instances.

        This enables calling schema/acl/entry methods directly on the main
        server instance.

        Args:
            name: Method or attribute name to look up

        Returns:
            Method or attribute from nested instance

        Raises:
            AttributeError: If attribute not found in any nested instance

        """
        # Use object.__getattribute__ to avoid recursion when checking for nested quirks
        # Try schema methods first (most common)
        try:
            schema_quirk = object.__getattribute__(self, "_schema_quirk")
            if schema_quirk is not None and hasattr(schema_quirk, name):
                return getattr(schema_quirk, name)
        except AttributeError:
            pass

        # Try entry methods before acl (Entry has can_handle with different signature)
        try:
            entry_quirk = object.__getattribute__(self, "_entry_quirk")
            if entry_quirk is not None and hasattr(entry_quirk, name):
                return getattr(entry_quirk, name)
        except AttributeError:
            pass

        # Try acl methods
        try:
            acl_quirk = object.__getattribute__(self, "_acl_quirk")
            if acl_quirk is not None and hasattr(acl_quirk, name):
                return getattr(acl_quirk, name)
        except AttributeError:
            pass

        # Not found in any nested instance
        msg = f"'{type(self).__name__}' object has no attribute '{name}'"
        raise AttributeError(msg)

    def __init_subclass__(cls, **kwargs: str | float | bool | None) -> None:
        """Initialize subclass with server_type and priority from Constants.

        Single source of truth: SERVER_TYPE and PRIORITY must be defined in
        the nested Constants class. No fallbacks, no dual patterns.

        This ensures:
        - FlextLdifServersOid.server_type comes from
          FlextLdifServersOid.Constants.SERVER_TYPE
        - Descriptors expose them at instance level via
          _ServerTypeDescriptor

        Args:
            **kwargs: Passed to parent __init_subclass__

        Raises:
            AttributeError: If Constants class is missing or lacks required attributes

        """
        super().__init_subclass__()

        # Require Constants class with SERVER_TYPE and PRIORITY
        if not hasattr(cls, "Constants"):
            msg = f"{cls.__name__} must define a Constants nested class"
            raise AttributeError(msg)

        # Get Constants - use getattr with validation
        # hasattr validates at runtime, so we can safely get the attribute
        constants_class = getattr(cls, "Constants", None)
        if constants_class is None:
            msg = f"{cls.__name__} must define a Constants nested class"
            raise AttributeError(msg)

        # Validate required attributes exist
        if not hasattr(constants_class, "SERVER_TYPE"):
            msg = f"{cls.__name__}.Constants must define SERVER_TYPE"
            raise AttributeError(msg)
        if not hasattr(constants_class, "PRIORITY"):
            msg = f"{cls.__name__}.Constants must define PRIORITY"
            raise AttributeError(msg)

        # Set descriptors for server_type and priority
        # Use getattr to access attributes safely after hasattr validation
        server_type_value = constants_class.SERVER_TYPE
        priority_value = constants_class.PRIORITY
        cls.server_type = _ServerTypeDescriptor(server_type_value)
        cls.priority = _PriorityDescriptor(priority_value)

    def get_schema_quirk(
        self,
    ) -> FlextLdifProtocols.Quirks.SchemaProtocol:
        """Get schema quirk instance.

        Returns:
            Schema quirk instance

        """
        # Return via property which handles type conversion
        return self.schema_quirk

    def acl(
        self,
    ) -> FlextLdifServersBase.Acl:
        """Get ACL quirk instance.

        Returns:
            ACL quirk instance

        """
        return self.acl_quirk

    def entry(
        self,
    ) -> FlextLdifServersBase.Entry:
        """Get entry quirk instance.

        Returns:
            Entry quirk instance

        """
        return self.entry_quirk

    # =========================================================================
    # Server identification - accessed via descriptors (class + instance level)
    # =========================================================================
    # NOTE: server_type and priority are defined in Constants nested class
    # in subclasses (e.g., FlextLdifServersRfc.Constants.SERVER_TYPE)
    # They are accessed via descriptors that work at both class and instance level
    # - Class level: FlextLdifServersOid.server_type -> "oid"
    # - Instance level: instance.server_type -> "oid"
    # The descriptors are set AFTER the class definition to avoid Pydantic issues

    # =========================================================================
    # FlextService V2: execute() method
    # =========================================================================
    # Required by FlextService - provides default implementation for health checks.
    # Subclasses should override parse() and write() for actual operations.

    # Control auto-execution
    auto_execute: ClassVar[bool] = False

    def execute(
        self,
        *,
        ldif_text: str | None = None,
        entries: Sequence[FlextLdifModels.Entry] | None = None,
        _operation: FlextLdifConstants.LiteralTypes.ParseWriteOperationLiteral
        | None = None,
    ) -> FlextResult[FlextLdifModels.Entry]:
        r"""Execute quirk operation with auto-detection.

        Args:
            ldif_text: LDIF text to parse
            entries: List of entries to process
            _operation: Explicit operation type (optional, auto-detected if None)

        Returns:
            FlextResult[Entry]

        """
        if ldif_text is not None and isinstance(ldif_text, str):
            return self._execute_parse(ldif_text)

        if entries is not None and FlextRuntime.is_list_like(entries) and entries:
            first_entry = entries[0]
            if isinstance(first_entry, FlextLdifModels.Entry):
                return FlextResult[FlextLdifModels.Entry].ok(first_entry)
            return FlextResult[FlextLdifModels.Entry].fail(
                f"Invalid entry type: {type(first_entry).__name__}",
            )

        return FlextResult[FlextLdifModels.Entry].fail("No valid parameters")

    def _execute_parse(self, ldif_text: str) -> FlextResult[FlextLdifModels.Entry]:
        """Execute parse operation."""
        parse_result = self.parse(ldif_text)
        if not parse_result.is_success:
            return FlextResult[FlextLdifModels.Entry].fail(
                parse_result.error or "Parse failed",
            )
        parse_response = parse_result.unwrap()
        if not parse_response.entries:
            return FlextResult[FlextLdifModels.Entry].fail("No entries parsed")
        # Get first entry - it's already a valid Entry model
        first_entry = parse_response.entries[0]
        if isinstance(first_entry, FlextLdifModels.Entry):
            return FlextResult[FlextLdifModels.Entry].ok(first_entry)
        # Should never reach here, but handle just in case
        return FlextResult[FlextLdifModels.Entry].fail("Invalid entry type")

    @overload
    def __call__(
        self,
        ldif_text: str,
        *,
        entries: None = None,
        operation: FlextLdifConstants.LiteralTypes.ParseOperationLiteral | None = None,
    ) -> FlextLdifModels.Entry | str: ...

    @overload
    def __call__(
        self,
        *,
        ldif_text: None = None,
        entries: list[FlextLdifModels.Entry],
        operation: FlextLdifConstants.LiteralTypes.WriteOperationLiteral | None = None,
    ) -> str: ...

    @overload
    def __call__(
        self,
        ldif_text: str | None = None,
        entries: list[FlextLdifModels.Entry] | None = None,
        operation: FlextLdifConstants.LiteralTypes.ParseWriteOperationLiteral
        | None = None,
    ) -> FlextLdifModels.Entry | str: ...

    def __call__(
        self,
        ldif_text: str | None = None,
        entries: list[FlextLdifModels.Entry] | None = None,
        operation: FlextLdifConstants.LiteralTypes.ParseWriteOperationLiteral
        | None = None,
    ) -> FlextLdifModels.Entry | str:
        r"""Callable interface - use as processor.

        Enables direct usage as processor:
            >>> processor = FlextLdifServersRfc()
            >>> entries = processor(ldif_text="dn: cn=test\n")  # Parse
            >>> ldif = processor(entries=[...])  # Write

        When auto_execute=True, called automatically on instantiation.
        Otherwise, use execute() for FlextResult composition.

        Args:
            ldif_text: LDIF text to parse
            entries: Entry models to write
            operation: Explicit operation type

        Returns:
            Unwrapped result (list[Entry] or str).

        """
        result = self.execute(ldif_text=ldif_text, entries=entries, operation=operation)
        return result.unwrap()

    def __new__(
        cls,
        **kwargs: FlextLdifTypes.Server.ServerInitKwargs,
    ) -> Self:
        """Override __new__ to support auto-execute and processor instantiation.

        When auto_execute=True, automatically executes and returns unwrapped result.
        When auto_execute=False, returns instance for use as processor.

        Args:
            **kwargs: Initialization parameters (ldif_text, entries, operation)

        Returns:
            Service instance OR unwrapped domain result (cast to Self for type safety).

        """
        # Use object.__new__ directly to avoid FlextService.__new__
        instance_raw = object.__new__(cls)
        if not isinstance(instance_raw, cls):
            msg = f"Expected {cls.__name__}, got {type(instance_raw)}"
            raise TypeError(msg)
        instance: Self = instance_raw

        # Initialize the instance
        # Filter kwargs to only pass primitive types to __init__
        # Also filter for _extract_execute_params which expects flat dict
        filtered_kwargs: dict[str, str | float | bool | None] = {}
        execute_kwargs: dict[str, str | int | bool | list[str] | None] = {}
        for k, v in kwargs.items():
            if isinstance(v, (str, float, bool, type(None))):
                filtered_kwargs[k] = v
            if isinstance(v, (str, int, bool, list, type(None))):
                # For execute params, allow list[str] but not nested dicts
                if isinstance(v, list):
                    if all(isinstance(item, str) for item in v):
                        execute_kwargs[k] = v
                else:
                    execute_kwargs[k] = v
        type(instance).__init__(instance, **filtered_kwargs)

        if cls.auto_execute:
            # Extract and execute with type-safe params
            ldif_text, entries, operation = cls._extract_execute_params(execute_kwargs)
            result = instance.execute(
                ldif_text=ldif_text,
                entries=entries,
                operation=operation,
            )
            unwrapped: FlextLdifModels.Entry | str = result.unwrap()
            if not isinstance(unwrapped, cls):
                msg = f"Expected {cls.__name__}, got {type(unwrapped)}"
                raise TypeError(msg)
            return unwrapped

        return instance

    @staticmethod
    def _extract_ldif_text(
        kwargs: FlextLdifTypes.Server.ServerInitKwargs,
    ) -> str | None:
        """Extract and validate ldif_text parameter."""
        if "ldif_text" not in kwargs:
            return None
        raw = kwargs["ldif_text"]
        if raw is None or isinstance(raw, str):
            return raw
        msg = f"Expected Optional[str] for ldif_text, got {type(raw)}"
        raise TypeError(msg)

    @staticmethod
    def _extract_entries(
        kwargs: FlextLdifTypes.Server.ServerInitKwargs,
    ) -> list[FlextLdifModels.Entry] | None:
        """Extract and validate entries parameter."""
        if "entries" not in kwargs:
            return None
        raw = kwargs["entries"]
        if raw is None:
            return None
        if not isinstance(raw, list):
            msg = f"Expected Optional[list[Entry]] for entries, got {type(raw)}"
            raise TypeError(msg)
        if not raw:
            return []
        # Type narrowing: verify all items are Entry instances
        # Use list comprehension to create properly typed list
        entries: list[FlextLdifModels.Entry] = []
        for item in raw:
            if isinstance(item, FlextLdifModels.Entry):
                entries.append(item)
            else:
                msg = f"Expected list[Entry] for entries, got item of type {type(item)}"
                raise TypeError(msg)
        return entries

    @staticmethod
    def _extract_operation(
        kwargs: FlextLdifTypes.Server.ServerInitKwargs,
    ) -> FlextLdifConstants.LiteralTypes.ParseWriteOperationLiteral | None:
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

    @classmethod
    def _extract_execute_params(
        cls,
        kwargs: FlextLdifTypes.Server.ServerInitKwargs,
    ) -> tuple[
        str | None,
        list[FlextLdifModels.Entry] | None,
        FlextLdifConstants.LiteralTypes.ParseWriteOperationLiteral | None,
    ]:
        """Extract type-safe execution parameters from kwargs."""
        return (
            cls._extract_ldif_text(kwargs),
            cls._extract_entries(kwargs),
            cls._extract_operation(kwargs),
        )

    # =========================================================================
    # Properties for accessing nested quirks (bypasses Pydantic's schema() method)
    # =========================================================================

    @property
    def schema_quirk(self) -> FlextLdifProtocols.Quirks.SchemaProtocol:
        """Get the Schema quirk instance."""
        # Type narrowing: _schema_quirk implements SchemaProtocol structurally
        # The concrete Schema class implements all protocol methods
        # Structural typing ensures protocol compliance at runtime
        schema_instance = self._schema_quirk
        # Verify protocol compliance via structural typing
        if not hasattr(schema_instance, "parse") or not hasattr(
            schema_instance, "write"
        ):
            msg = "Schema instance does not implement SchemaProtocol"
            raise TypeError(msg)
        # Type assertion: Schema class implements SchemaProtocol structurally
        # All required methods are present, so this is safe
        # Return as protocol type - structural typing ensures compatibility
        # Protocol compliance verified at runtime via hasattr checks above
        # Type assertion: Schema implements SchemaProtocol structurally
        # This is safe because all protocol methods are verified above
        # and Schema class implements all required protocol methods
        # Runtime checkable protocol allows isinstance check
        if isinstance(schema_instance, FlextLdifProtocols.Quirks.SchemaProtocol):
            return schema_instance
        # Fallback: structural typing ensures compatibility even if isinstance fails
        # This should never happen due to hasattr checks above
        msg = "Schema instance does not satisfy SchemaProtocol"
        raise TypeError(msg)

    @property
    def acl_quirk(self) -> FlextLdifServersBase.Acl:
        """Get the Acl quirk instance."""
        return self._acl_quirk

    @property
    def entry_quirk(self) -> FlextLdifServersBase.Entry:
        """Get the Entry quirk instance."""
        return self._entry_quirk

    # =========================================================================
    # Core Quirk Methods - Parsing and Writing (Primary Interface)
    # =========================================================================

    def parse(
        self,
        ldif_text: str,
    ) -> FlextResult[FlextLdifModels.ParseResponse]:
        """Parse LDIF text to Entry models.

        Routes to Entry quirk for server-specific parsing logic.

        **V2 Usage:**
            >>> quirk = FlextLdifServersRfc()
            >>> entries = quirk.parse(ldif_text).result
            >>> entries = quirk.parse(ldif_text).map(filter_fn).unwrap()

        Args:
            ldif_text: LDIF content string

        Returns:
            FlextResult[ParseResponse]

        """
        # Instantiate Entry nested class for parsing
        entry_class = getattr(type(self), "Entry", None)
        if not entry_class:
            return FlextResult.fail("Entry nested class not available")
        entry_quirk = entry_class()
        entries_result: FlextResult[list[FlextLdifModels.Entry]] = entry_quirk.parse(
            ldif_text,
        )
        if entries_result.is_failure:
            error_msg = entries_result.error or "Entry parsing failed"
            return FlextResult[FlextLdifModels.ParseResponse].fail(error_msg)

        entries = entries_result.unwrap()
        detected_server = getattr(self, "server_type", None)
        statistics = FlextLdifModels.Statistics(
            total_entries=len(entries),
            processed_entries=len(entries),
            detected_server_type=detected_server,
        )
        # Convert entries for ParseResponse - use model_copy() for safety
        domain_entries: Sequence[FlextLdifModels.Entry] = [
            entry
            if isinstance(entry, FlextLdifModels.Entry)
            else entry.model_copy(deep=True)
            for entry in entries
        ]
        parse_response = FlextLdifModels.ParseResponse(
            entries=list(domain_entries),
            statistics=statistics,
            detected_server_type=detected_server,
        )
        return FlextResult[FlextLdifModels.ParseResponse].ok(parse_response)

    def write(self, entries: list[FlextLdifModels.Entry]) -> FlextResult[str]:
        """Write Entry models to LDIF text.

        Routes to Entry quirk for server-specific writing logic.

        **V2 Usage:**
            >>> quirk = FlextLdifServersRfc()
            >>> ldif_text = quirk.write(entries).result
            >>> ldif_text = quirk.write(entries).map(str.upper).unwrap()

        Args:
            entries: List of Entry models

        Returns:
            FlextResult[str]

        """
        # Get entry quirk with validation
        entry_quirk = getattr(self, "entry_quirk", None)
        if not entry_quirk:
            return FlextResult[str].fail("Entry quirk not available")

        # Use functional composition to write all entries
        def write_single_entry(entry_model: FlextLdifModels.Entry) -> FlextResult[str]:
            """Write single entry using entry quirk."""
            if entry_quirk is not None:
                # Cast to FlextResult[str] - entry_quirk.write returns FlextResult[str]
                result: FlextResult[str] = entry_quirk.write(entry_model)
                return result
            return FlextResult[str].fail("No entry quirk found")

        # Process all entries with early return on first failure
        ldif_lines: list[str] = []
        for entry_model in entries:
            result = write_single_entry(entry_model)
            if result.is_failure:
                return FlextResult[str].fail(f"Failed to write entry: {result.error}")
            ldif_lines.append(result.unwrap())

        # Finalize LDIF with proper formatting
        ldif = "\n".join(ldif_lines)
        if ldif and not ldif.endswith("\n"):
            ldif += "\n"

        return FlextResult[str].ok(ldif)

    def _route_model_to_write(
        self, model: FlextLdifTypes.ConvertibleModel
    ) -> FlextResult[str]:
        """Route a single model to appropriate write method.

        Automatically detects model type and routes to correct quirk write method.
        Uses isinstance for proper type narrowing.

        This is a generic method available to all server implementations.
        It routes Entry, SchemaAttribute, SchemaObjectClass, or Acl models
        to their respective quirk write methods.

        Args:
            model: Model instance to write (Entry, SchemaAttribute,
                SchemaObjectClass, or Acl).

        Returns:
            FlextResult with LDIF string representation.

        """
        # Use isinstance for proper type narrowing and direct method calls
        if isinstance(model, FlextLdifModels.Entry):
            return self.entry_quirk.write(model)
        if isinstance(model, FlextLdifModels.SchemaAttribute):
            # Use _schema_quirk directly to access write_attribute method
            # which is not in the protocol but exists on the concrete Schema class
            return self._schema_quirk.write_attribute(model)
        if isinstance(model, FlextLdifModels.SchemaObjectClass):
            # Use _schema_quirk directly to access write_objectclass method
            # which is not in the protocol but exists on the concrete Schema class
            return self._schema_quirk.write_objectclass(model)
        if isinstance(model, FlextLdifModels.Acl):
            return self.acl_quirk.write(model)

        return FlextResult[str].fail(f"Unknown model type: {type(model).__name__}")

    def _handle_parse_operation(
        self,
        ldif_text: str,
    ) -> FlextResult[FlextLdifModels.Entry | str]:
        """Handle parse operation for main quirk.

        Generic implementation that parses LDIF text and returns the first entry
        or empty string if no entries found. This method is available to all
        server implementations.

        Args:
            ldif_text: LDIF content as string to parse.

        Returns:
            FlextResult with first Entry from parsed content, or empty string
            if no entries found, or error if parsing failed.

        """
        parse_result = self.parse(ldif_text)
        if parse_result.is_success:
            parse_response = parse_result.unwrap()
            entries = parse_response.entries
            # ParseResponse.entries is always Sequence[Entry] (never a single Entry)
            if entries and len(entries) > 0:
                domain_entry = entries[0]
                # Convert domain Entry to public Entry type for type compatibility
                # FlextLdifModels.Entry extends FlextLdifModelsDomains.Entry
                if isinstance(domain_entry, FlextLdifModels.Entry):
                    # Already public type
                    return FlextResult[FlextLdifModels.Entry | str].ok(domain_entry)
                # Convert domain entry to public entry using model_validate
                public_entry = FlextLdifModels.Entry.model_validate(
                    domain_entry.model_dump(mode="python"),
                )
                return FlextResult[FlextLdifModels.Entry | str].ok(public_entry)
            return FlextResult[FlextLdifModels.Entry | str].ok("")
        error_msg: str = parse_result.error or "Parse failed"
        return FlextResult[FlextLdifModels.Entry | str].fail(error_msg)

    def _handle_write_operation(
        self,
        entries: list[FlextLdifModels.Entry],
    ) -> FlextResult[FlextLdifModels.Entry | str]:
        """Handle write operation for main quirk.

        Generic implementation that writes Entry models to LDIF text.
        This method is available to all server implementations.

        Args:
            entries: List of Entry models to write.

        Returns:
            FlextResult with LDIF string representation, or error if writing failed.

        """
        write_result = self.write(entries)
        if write_result.is_success:
            written_text: str = write_result.unwrap()
            return FlextResult[FlextLdifModels.Entry | str].ok(written_text)
        error_msg: str = write_result.error or "Write failed"
        return FlextResult[FlextLdifModels.Entry | str].fail(error_msg)

    # =========================================================================
    # Registry method for DI-based automatic registration
    # =========================================================================
    # NOTE: server_type and priority are ClassVar in the PARENT SERVER CLASS ONLY
    # NOT in nested Schema/Acl/Entry classes
    # (e.g., FlextLdifServersOid.server_type, FlextLdifServersOid.priority)
    # All constants must be in FlextLdifServers[Server].Constants, NOT in subclasses

    @classmethod
    def _get_server_type_from_mro(
        cls, quirk_class: type[object]
    ) -> FlextLdifConstants.LiteralTypes.ServerTypeLiteral:
        """Get server_type from parent class Constants via MRO traversal.

        Uses functional patterns.
        """

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

            # Use functional composition: filter + map + first valid result

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
                # Type narrowing: ensure server_type is a valid ServerTypeLiteral
                # Use normalize_server_type for proper validation and type narrowing
                return FlextLdifConstants.normalize_server_type(server_type)
        except StopIteration:
            pass

        # Error message
        msg = (
            f"Cannot find SERVER_TYPE in Constants for quirk class: "
            f"{quirk_class.__name__}"
        )
        raise AttributeError(msg)

    @classmethod
    def _get_priority_from_mro(cls, quirk_class: type[object]) -> int:
        """Get priority from parent class Constants via MRO traversal.

        Uses functional patterns.
        """

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

        # Use functional composition: filter + map + first valid result
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

        # Error message
        msg = (
            f"Cannot find PRIORITY in Constants for quirk class: {quirk_class.__name__}"
        )
        raise AttributeError(msg)

    @classmethod
    def _register_in_registry(
        cls,
        quirk_instance: (
            FlextLdifProtocols.Quirks.SchemaProtocol
            | FlextLdifProtocols.Quirks.AclProtocol
            | FlextLdifProtocols.Quirks.EntryProtocol
            | FlextLdifServersBase
        ),
        registry: FlextLdifProtocols.Registry.QuirkRegistryProtocol,
    ) -> None:
        """Helper method to register a quirk instance in the registry.

        Uses functional validation.

        This method can be used by subclasses or registry to automatically register
        quirks. The base class itself does NOT register automatically - this is
        just a helper for registration logic.

        Args:
            quirk_instance: Instance of any quirk (Schema, Acl, Entry, base)
            registry: Registry instance to register the quirk (has register)

        """

        # Functional composition: validate + register
        def validate_registry(
            registry_obj: FlextLdifProtocols.Registry.QuirkRegistryProtocol,
        ) -> (
            Callable[
                [
                    FlextLdifConstants.LiteralTypes.ServerTypeLiteral | str,
                    FlextLdifProtocols.Quirks.SchemaProtocol,
                ],
                None,
            ]
            | None
        ):
            """Validate registry has register method."""
            method = getattr(registry_obj, "register_quirk", None)
            if method and callable(method):
                return method
            return None

        def perform_registration(
            register_func: (
                Callable[
                    [
                        FlextLdifConstants.LiteralTypes.ServerTypeLiteral | str,
                        FlextLdifProtocols.Quirks.SchemaProtocol,
                    ],
                    None,
                ]
                | None
            ),
            instance: (
                FlextLdifProtocols.Quirks.SchemaProtocol
                | FlextLdifProtocols.Quirks.AclProtocol
                | FlextLdifProtocols.Quirks.EntryProtocol
                | FlextLdifServersBase
            ),
        ) -> None:
            """Execute registration if method is available."""
            if register_func and isinstance(
                instance,
                (
                    FlextLdifProtocols.Quirks.SchemaProtocol,
                    FlextLdifProtocols.Quirks.AclProtocol,
                    FlextLdifProtocols.Quirks.EntryProtocol,
                ),
            ):
                # Cast to SchemaProtocol for register_quirk signature
                schema_quirk = cast(
                    "FlextLdifProtocols.Quirks.SchemaProtocol", instance
                )
                register_func("auto", schema_quirk)

        # Compose validation and registration
        register_method = validate_registry(registry)
        perform_registration(register_method, quirk_instance)

    # =========================================================================
    # Automatic Routing Methods - Moved to rfc.py (concrete implementations)
    # =========================================================================
    # Note: _detect_model_type, _get_for_model, _route_model_to_write,
    # _route_models_to_write, _validate_ldif_text, _validate_entries are now
    # concrete implementations in FlextLdifServersRfc. Subclasses can override
    # these methods if needed.

    # =========================================================================
    # Nested Abstract Base Classes for Internal Implementation
    # =========================================================================

    class Schema(
        FlextService[
            (FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str)
        ],
    ):
        """Base class for schema quirks - FlextService V2 with enhanced usability.

        NOTE: This is an implementation detail - DO NOT import directly.
        Use FlextLdifServersBase.Schema instead.

        Schema quirks extend RFC 4512 schema parsing with server-specific features
        for attribute and objectClass processing.

        **FlextService V2 Integration:**
        - Inherits from FlextService for dependency injection,
          logging, and validation
        - Uses V2 patterns: .result property for direct access,
          .execute() for FlextResult
        - Auto-registration in DI container via FlextService
        - Type-safe with TDomainResult = FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass

        **V2 Usage Patterns:**
            >>> schema = FlextLdifServersRfc.Schema()
            >>> # Parse attribute with direct access
            >>> attr = schema.parse_attribute(attr_def).result
            >>> # Or use execute() for FlextResult composition
            >>> result = schema.parse_attribute(attr_def)

        """

        # Protocol-required fields
        server_type: FlextLdifConstants.LiteralTypes.ServerTypeLiteral = "rfc"
        """Server type identifier (e.g., 'oid', 'oud', 'openldap', 'rfc')."""

        priority: int = 0
        """Quirk priority (lower number = higher priority).

        **STANDARDIZED CONSTANTS REQUIRED**: Each Schema implementation MUST define
        a Constants nested class with:
        - CANONICAL_NAME: Unique server identifier (e.g., "oid", "oud")
        - ALIASES: All valid names for this server including canonical
        - PRIORITY: Selection priority (lower = higher priority)
        - CAN_NORMALIZE_FROM: What source types this quirk can normalize
        - CAN_DENORMALIZE_TO: What target types this quirk can denormalize to

        **Protocol Compliance**: All implementations MUST satisfy
        FlextLdifProtocols.Quirks.SchemaProtocol through structural typing.
        This means all public methods must match protocol signatures exactly.

        **Validation**: Use isinstance(quirk, FlextLdifProtocols.Quirks.SchemaProtocol)
        to check protocol compliance at runtime.

        Common schema extension patterns:
        - Vendor-specific prefixes (e.g., vendor prefix + attribute name)
        - Enhanced schema features beyond RFC baseline
        - Configuration-specific attributes
        - Vendor-specific schema extensions
        - RFC 4512 compliant baseline (no extensions)
        """

        # Parent quirk reference for accessing server-level configuration
        parent_quirk: FlextLdifServersBase | None = Field(
            default=None,
            exclude=True,
            repr=False,
            description=(
                "Reference to parent FlextLdifServersBase instance "
                "for server-level access"
            ),
        )

        # Auto-execute parameters (for __new__ pattern with auto_execute)
        # These fields are excluded from serialization and only processed by __new__
        attr_definition: str | None = Field(
            default=None,
            exclude=True,
            repr=False,
            description="Attribute definition for auto-execute pattern",
        )
        oc_definition: str | None = Field(
            default=None,
            exclude=True,
            repr=False,
            description="ObjectClass definition for auto-execute pattern",
        )
        attr_model: FlextLdifProtocols.Models.SchemaAttributeProtocol | None = Field(
            default=None,
            exclude=True,
            repr=False,
            description="SchemaAttribute model for auto-execute pattern",
        )
        oc_model: FlextLdifProtocols.Models.SchemaObjectClassProtocol | None = Field(
            default=None,
            exclude=True,
            repr=False,
            description="SchemaObjectClass model for auto-execute pattern",
        )
        operation: str | None = Field(
            default=None,
            exclude=True,
            repr=False,
            description="Operation type for auto-execute pattern",
        )

        def __init__(
            self,
            schema_service: FlextLdifProtocols.Services.HasParseMethodProtocol
            | None = None,
            _parent_quirk: FlextLdifServersBase | None = None,
            **kwargs: str | float | bool | None,
        ) -> None:
            """Initialize schema quirk service with optional DI service injection.

            Args:
                schema_service: Injected FlextLdifSchema service
                    (optional, lazy-created if None)
                parent_quirk: Reference to parent FlextLdifServersBase
                **kwargs: Additional initialization parameters for FlextService

            Note:
                server_type and priority are no longer passed to nested classes.
                They should be accessed via _get_server_type() and Constants.PRIORITY
                from the parent server class.

            """
            super().__init__(**kwargs)
            self._schema_service = schema_service  # Store for use by subclasses
            # Note: server_type and priority descriptors are only available on parent server classes
            # Nested classes (Schema/Acl/Entry) access them via _get_server_type() when needed

        # =====================================================================
        # HOOKS for Customization - Override in subclasses to customize behavior
        # =====================================================================

        def _get_server_type(self) -> FlextLdifConstants.LiteralTypes.ServerTypeLiteral:
            """Get server_type from parent server class via __qualname__."""
            return FlextLdifUtilities.Server.get_parent_server_type(self)

        def _get_priority(self) -> int:
            """Get priority from parent server class Constants."""
            parent = getattr(self, "_parent_quirk", None)
            if (
                parent
                and hasattr(parent, "Constants")
                and hasattr(parent.Constants, "PRIORITY")
            ):
                priority_value = parent.Constants.PRIORITY
                if not isinstance(priority_value, int):
                    msg = f"Expected int, got {type(priority_value)}"
                    raise TypeError(msg)
                return priority_value
            return 100  # Default priority

        # Control auto-execution
        auto_execute: ClassVar[bool] = False

        # =====================================================================
        # Automatic Routing Methods - Moved to rfc.py.Schema
        # =====================================================================
        # Concrete implementations of routing methods are now in
        # FlextLdifServersRfc.Schema
        # Base class keeps only abstract methods and hooks

        def _parse_attribute(
            self,
            attr_definition: str,
        ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
            """Parse server-specific attribute definition (internal).

            Extracts attribute metadata (OID, NAME, DESC, SYNTAX, etc.)
            from RFC 4512 format and applies server-specific enhancements.

            Args:
                attr_definition: AttributeType definition string

            Returns:
                FlextResult with parsed SchemaAttribute model

            """
            del attr_definition  # Unused in base, required by protocol
            return FlextResult.fail("Must be implemented by subclass")

        def _parse_objectclass(
            self,
            oc_definition: str,
        ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
            """Parse server-specific objectClass definition (internal).

            Extracts objectClass metadata (OID, NAME, SUP, MUST, MAY, etc.)
            from RFC 4512 format and applies server-specific enhancements.

            Args:
                oc_definition: ObjectClass definition string

            Returns:
                FlextResult with parsed SchemaObjectClass model

            """
            _ = oc_definition  # Explicitly mark as intentionally unused in base
            return FlextResult.fail("Must be implemented by subclass")

        # =====================================================================
        # Concrete Routing Methods - Moved to rfc.py.Schema
        # =====================================================================
        # _route_write, _route_can_handle, _handle_parse_operation,
        # _handle_write_operation, _auto_detect_operation, _route_operation,
        # execute, __call__, __new__ are now concrete implementations in FlextLdifServersRfc.Schema

        def _hook_post_parse_attribute(
            self,
            attr: FlextLdifModels.SchemaAttribute,
        ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
            """Hook called after parsing an attribute definition.

            Override in subclasses for server-specific post-processing of parsed attributes.

            Default behavior: returns attribute unchanged (pass-through).

            **When to use:**
            - Normalize attribute properties after parsing
            - Add server-specific metadata
            - Validate attribute constraints
            - Transform attribute format

            Args:
                attr: Parsed SchemaAttribute from parse_attribute()

            Returns:
                FlextResult[FlextLdifModels.SchemaAttribute] - modified or original attribute

            **Example:**
                def _hook_post_parse_attribute(self, attr):
                    # OID-specific: normalize OID format
                    if attr.oid:
                        attr.oid = normalize_oid(attr.oid)
                    return FlextResult.ok(attr)

            """
            return FlextResult.ok(attr)

        def _hook_post_parse_objectclass(
            self,
            oc: FlextLdifModels.SchemaObjectClass,
        ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
            """Hook called after parsing an objectClass definition.

            Override in subclasses for server-specific post-processing of parsed objectClasses.

            Default behavior: returns objectClass unchanged (pass-through).

            **When to use:**
            - Normalize objectClass properties after parsing
            - Add server-specific metadata
            - Validate objectClass constraints
            - Transform objectClass format

            Args:
                oc: Parsed SchemaObjectClass from parse_objectclass()

            Returns:
                FlextResult[FlextLdifModels.SchemaObjectClass] - modified or original objectClass

            **Example:**
                def _hook_post_parse_objectclass(self, oc):
                    # OID-specific: validate MUST/MAY attributes exist
                    if oc.must:
                        for attr_name in oc.must:
                            if not self.validate_attribute_exists(attr_name):
                                return FlextResult.fail(f"Unknown attribute: {attr_name}")
                    return FlextResult.ok(oc)

            """
            return FlextResult.ok(oc)

        def can_handle_attribute(
            self,
            attr_definition: str | FlextLdifModels.SchemaAttribute,
        ) -> bool:
            """Check if this quirk can handle the attribute definition.

            Called BEFORE parsing to detect if this quirk should process the definition.
            Receives the raw attribute definition string (e.g., "( 2.5.4.3 NAME 'cn' ...)")
            OR SchemaAttribute model object (for convenience in tests).

            Args:
                attr_definition: AttributeType definition string

            Returns:
                True if this quirk can parse this attribute definition

            """
            _ = attr_definition  # Explicitly mark as intentionally unused in base
            return False  # CONSOLIDATED into parse(definition, model_type=None)  # CONSOLIDATED into parse(definition, model_type=None)

        # CONSOLIDATED into parse(definition, model_type=None)
        # See consolidated parse() method below

        def can_handle_objectclass(
            self,
            oc_definition: str | FlextLdifModels.SchemaObjectClass,
        ) -> bool:
            """Check if this quirk can handle the objectClass definition.

            Called BEFORE parsing to detect if this quirk should process the definition.
            Receives the raw objectClass definition string (e.g., "( 2.5.6.6 NAME 'person' ...)")
            OR SchemaObjectClass model object (for convenience in tests).

            Args:
                oc_definition: ObjectClass definition string or model

            Returns:
                True if this quirk can parse this objectClass definition

            """
            _ = oc_definition  # Explicitly mark as intentionally unused in base
            return False  # CONSOLIDATED into parse(definition, model_type=None)

        # CONSOLIDATED into parse(definition, model_type=None)
        # See consolidated parse() method below

        # REMOVED: convert_attribute - Entry is always RFC with metadata
        # All conversion is handled by quirk_metadata in the model itself

        # REMOVED: convert_objectclass - See convert_attribute

        # REMOVED: convert_attribute - See convert_attribute

        # REMOVED: convert_objectclass - See convert_attribute

        # =====================================================================
        # Concrete Helper Methods - Moved to rfc.py.Schema
        # =====================================================================
        # create_metadata is now a concrete implementation in FlextLdifServersRfc.Schema

        def parse_attribute(
            self,
            attr_definition: str,
        ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
            """Parse attribute definition (public API).

            Delegates to _parse_attribute() for server-specific implementation.

            Args:
                attr_definition: Attribute definition string

            Returns:
                FlextResult with parsed SchemaAttribute model

            """
            return self._parse_attribute(attr_definition)

        def parse_objectclass(
            self,
            oc_definition: str,
        ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
            """Parse objectClass definition (public API).

            Delegates to _parse_objectclass() for server-specific implementation.

            Args:
                oc_definition: ObjectClass definition string

            Returns:
                FlextResult with parsed SchemaObjectClass model

            """
            return self._parse_objectclass(oc_definition)

        def route_parse(
            self,
            definition: str,
        ) -> FlextResult[
            FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass
        ]:
            """Route schema definition to appropriate parse method.

            Generic implementation that automatically detects if definition is
            attribute or objectclass and routes to the appropriate parser.
            This method is available to all server implementations.

            Args:
                definition: Schema definition string.

            Returns:
                FlextResult with SchemaAttribute or SchemaObjectClass.

            """
            schema_type = FlextLdifUtilities.Schema.detect_schema_type(definition)
            if schema_type == "objectclass":
                oc_result = self._parse_objectclass(definition)
                if oc_result.is_failure:
                    return FlextResult[
                        (
                            FlextLdifModels.SchemaAttribute
                            | FlextLdifModels.SchemaObjectClass
                        )
                    ].fail(oc_result.error or "Parse failed")
                return FlextResult[
                    (
                        FlextLdifModels.SchemaAttribute
                        | FlextLdifModels.SchemaObjectClass
                    )
                ].ok(oc_result.unwrap())
            attr_result = self._parse_attribute(definition)
            if attr_result.is_failure:
                return FlextResult[
                    (
                        FlextLdifModels.SchemaAttribute
                        | FlextLdifModels.SchemaObjectClass
                    )
                ].fail(attr_result.error or "Parse failed")
            return FlextResult[
                (FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass)
            ].ok(attr_result.unwrap())

        def parse(
            self,
            definition: str,
        ) -> FlextResult[
            FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass
        ]:
            """Parse schema definition (attribute or objectClass).

            Generic implementation that automatically routes to parse_attribute()
            or parse_objectclass() based on content. This method is available
            to all server implementations.

            Args:
                definition: Schema definition string (attribute or objectClass)

            Returns:
                FlextResult with SchemaAttribute or SchemaObjectClass model

            """
            return self.route_parse(definition)

        def write_attribute(
            self,
            attr_data: FlextLdifModels.SchemaAttribute,
        ) -> FlextResult[str]:
            """Write attribute to RFC-compliant string format (public API).

            Delegates to _write_attribute() for server-specific implementation.

            Args:
                attr_data: SchemaAttribute model

            Returns:
                FlextResult with RFC-compliant attribute string

            """
            return self._write_attribute(attr_data)

        def write_objectclass(
            self,
            oc_data: FlextLdifModels.SchemaObjectClass,
        ) -> FlextResult[str]:
            """Write objectClass to RFC-compliant string format (public API).

            Delegates to _write_objectclass() for server-specific implementation.

            Args:
                oc_data: SchemaObjectClass model

            Returns:
                FlextResult with RFC-compliant objectClass string

            """
            return self._write_objectclass(oc_data)

        def _write_attribute(
            self,
            attr_data: FlextLdifModels.SchemaAttribute,
        ) -> FlextResult[str]:
            """Write attribute data to RFC-compliant string format (internal).

            Args:
                attr_data: SchemaAttribute model to write

            Returns:
                FlextResult with RFC-compliant attribute string

            """
            _ = attr_data  # Explicitly mark as intentionally unused in base
            return FlextResult.fail(
                "Must be implemented by subclass",
            )  # Must be implemented by subclass

        def _write_objectclass(
            self,
            oc_data: FlextLdifModels.SchemaObjectClass,
        ) -> FlextResult[str]:
            """Write objectClass data to RFC-compliant string format (internal).

            Args:
                oc_data: SchemaObjectClass model

            Returns:
                FlextResult with RFC-compliant objectClass string

            """
            _ = oc_data  # Explicitly mark as intentionally unused in base
            return FlextResult.fail("Must be implemented by subclass")

        def _hook_validate_attributes(
            self,
            attributes: list[FlextLdifModels.SchemaAttribute],
            available_attrs: set[str],
        ) -> FlextResult[bool]:
            """Hook for server-specific attribute validation during schema extraction.

            Subclasses can override this to perform validation of attribute dependencies
            before objectClass extraction. This is called only when validate_dependencies=True.

            Default implementation: No validation (pass-through).

            Args:
                attributes: List of parsed SchemaAttribute models
                available_attrs: Set of lowercase attribute names available

            Returns:
                FlextResult[bool] - True if valid, fails with error if invalid

            Example Override (in OUD):
                def _hook_validate_attributes(self, attributes, available_attrs):
                    # OUD-specific validation logic
                    for attr in attributes:
                        if attr.requires_dependency not in available_attrs:
                            return FlextResult.fail("Missing dependency")
                    return FlextResult.ok(True)

            """
            # Default: No validation needed
            _ = attributes
            _ = available_attrs
            return FlextResult[bool].ok(True)

        @staticmethod
        def validate_and_track_oid(
            metadata_extensions: dict[str, list[str] | str | bool | None],
            oid_value: str | None,
            oid_name: str,
        ) -> None:
            """Validate OID and track result in metadata extensions.

            Uses FlextLdifConstants.MetadataKeys for standardized metadata keys.

            Args:
                metadata_extensions: Metadata extensions dict to update
                oid_value: OID value to validate (optional)
                oid_name: Name of OID for error messages (e.g., "attribute", "syntax", "equality")

            """
            if not oid_value:
                return

            oid_validate_result = FlextLdifUtilities.OID.validate_format(oid_value)
            if oid_validate_result.is_failure:
                metadata_extensions[
                    FlextLdifConstants.MetadataKeys.SYNTAX_VALIDATION_ERROR
                ] = f"{oid_name.capitalize()} OID validation failed: {oid_validate_result.error}"
                metadata_extensions[
                    FlextLdifConstants.MetadataKeys.SYNTAX_OID_VALID
                ] = False
            elif not oid_validate_result.unwrap():
                metadata_extensions[
                    FlextLdifConstants.MetadataKeys.SYNTAX_VALIDATION_ERROR
                ] = (
                    f"Invalid {oid_name} OID format: {oid_value} "
                    f"(must be numeric dot-separated format)"
                )
                metadata_extensions[
                    FlextLdifConstants.MetadataKeys.SYNTAX_OID_VALID
                ] = False
            else:
                # OID is valid - track in metadata
                metadata_extensions[
                    FlextLdifConstants.MetadataKeys.SYNTAX_OID_VALID
                ] = True

        @staticmethod
        def build_attribute_metadata(
            attr_definition: str,
            syntax: str | None,
            syntax_validation_error: str | None,
            attribute_oid: str | None = None,
            equality_oid: str | None = None,
            ordering_oid: str | None = None,
            substr_oid: str | None = None,
            sup_oid: str | None = None,
            server_type: str | None = None,
        ) -> FlextLdifModels.QuirkMetadata | None:
            """Build metadata for attribute including extensions and OID validation.

            Tracks OID validation for:
            - Attribute OID (required)
            - Syntax OID (optional)
            - Matching rule OIDs: equality, ordering, substr (optional)
            - SUP OID (optional)

            Uses FlextLdifConstants.MetadataKeys for standardized metadata keys.

            Args:
                attr_definition: Original attribute definition
                syntax: Syntax OID (optional)
                syntax_validation_error: Validation error for syntax OID if any
                attribute_oid: Attribute OID (optional, for validation tracking)
                equality_oid: Equality matching rule OID (optional)
                ordering_oid: Ordering matching rule OID (optional)
                substr_oid: Substring matching rule OID (optional)
                sup_oid: SUP OID (optional)
                server_type: Server type identifier (optional, defaults to RFC)

            Returns:
                QuirkMetadata or None

            """
            # Extract extensions and widen type to include bool for validation tracking
            metadata_extensions: dict[str, list[str] | str | bool | None] = (
                FlextLdifUtilities.Parser.extract_extensions(attr_definition)
            )

            # Track syntax OID validation (if syntax is present)
            if syntax:
                metadata_extensions[
                    FlextLdifConstants.MetadataKeys.SYNTAX_OID_VALID
                ] = syntax_validation_error is None
                if syntax_validation_error:
                    metadata_extensions[
                        FlextLdifConstants.MetadataKeys.SYNTAX_VALIDATION_ERROR
                    ] = syntax_validation_error

            # Track attribute OID validation (if attribute_oid is provided)
            # Use helper method for DRY OID validation
            FlextLdifServersBase.Schema.validate_and_track_oid(
                metadata_extensions,
                attribute_oid,
                "attribute",
            )

            # Track matching rule OID validation (equality, ordering, substr)
            # These are OIDs that should be validated per RFC 4517
            for matching_rule_name, matching_rule_oid in [
                ("equality matching rule", equality_oid),
                ("ordering matching rule", ordering_oid),
                ("substring matching rule", substr_oid),
            ]:
                FlextLdifServersBase.Schema.validate_and_track_oid(
                    metadata_extensions,
                    matching_rule_oid,
                    matching_rule_name,
                )

            # Track SUP OID validation (supertype OID)
            FlextLdifServersBase.Schema.validate_and_track_oid(
                metadata_extensions,
                sup_oid,
                "SUP",
            )

            # Preserve complete original format
            metadata_extensions[FlextLdifConstants.MetadataKeys.ORIGINAL_FORMAT] = (
                attr_definition.strip()
            )
            metadata_extensions[
                FlextLdifConstants.MetadataKeys.SCHEMA_ORIGINAL_STRING_COMPLETE
            ] = attr_definition  # Complete with all formatting

            # Create metadata with schema formatting details
            # Use provided server_type or default to RFC
            # Type narrowing: ensure server_type is ServerTypeLiteral
            quirk_type: FlextLdifConstants.LiteralTypes.ServerTypeLiteral
            if server_type and isinstance(server_type, str):
                valid_types = set(FlextLdifConstants.ServerTypes)
                if server_type in valid_types:
                    quirk_type = cast(
                        "FlextLdifConstants.LiteralTypes.ServerTypeLiteral", server_type
                    )
                else:
                    quirk_type = cast(
                        "FlextLdifConstants.LiteralTypes.ServerTypeLiteral", "rfc"
                    )
            else:
                quirk_type = cast(
                    "FlextLdifConstants.LiteralTypes.ServerTypeLiteral", "rfc"
                )
            metadata = (
                FlextLdifModels.QuirkMetadata(
                    quirk_type=quirk_type,
                    extensions=FlextLdifModels.DynamicMetadata(**metadata_extensions),
                )
                if metadata_extensions
                else FlextLdifModels.QuirkMetadata(
                    quirk_type=quirk_type, extensions=FlextLdifModels.DynamicMetadata()
                )
            )

            # Preserve ALL schema formatting details for zero data loss
            FlextLdifUtilities.Metadata.preserve_schema_formatting(
                metadata,
                attr_definition,
            )

            # Log formatting preservation for debugging (FlextLogger adds source automatically)
            preview_length = FlextLdifConstants.DN_TRUNCATE_LENGTH
            logger.debug(
                "Preserved schema formatting details",
                attr_definition_preview=attr_definition[:preview_length]
                if len(attr_definition) > preview_length
                else attr_definition,
            )

            return (
                metadata
                if metadata_extensions or metadata.schema_format_details
                else None
            )

        # =====================================================================
        # Concrete Template Methods - Moved to rfc.py.Schema
        # =====================================================================
        # extract_schemas_from_ldif is now a concrete implementation in FlextLdifServersRfc.Schema

        # REMOVED: should_filter_out_attribute - Roteamento interno, não deve ser abstrato

        # REMOVED: should_filter_out_objectclass - Roteamento interno, não deve ser abstrato

        def _handle_parse_operation(
            self,
            attr_definition: str | None,
            oc_definition: str | None,
        ) -> FlextResult[
            FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str
        ]:
            """Handle parse operation for schema quirk.

            Generic implementation that routes to parse_attribute() or
            parse_objectclass() based on provided parameters. This method is
            available to all server implementations.

            Args:
                attr_definition: Attribute definition string to parse (optional).
                oc_definition: ObjectClass definition string to parse (optional).

            Returns:
                FlextResult with parsed SchemaAttribute or SchemaObjectClass model,
                or error if parsing failed or no parameter provided.

            """
            if attr_definition:
                attr_result = self.parse_attribute(attr_definition)
                if attr_result.is_success:
                    parsed_attr: FlextLdifModels.SchemaAttribute = attr_result.unwrap()
                    return FlextResult[
                        (
                            FlextLdifModels.SchemaAttribute
                            | FlextLdifModels.SchemaObjectClass
                            | str
                        )
                    ].ok(parsed_attr)
                error_msg: str = attr_result.error or "Parse attribute failed"
                return FlextResult[
                    (
                        FlextLdifModels.SchemaAttribute
                        | FlextLdifModels.SchemaObjectClass
                        | str
                    )
                ].fail(error_msg)
            if oc_definition:
                oc_result = self.parse_objectclass(oc_definition)
                if oc_result.is_success:
                    parsed_oc: FlextLdifModels.SchemaObjectClass = oc_result.unwrap()
                    return FlextResult[
                        (
                            FlextLdifModels.SchemaAttribute
                            | FlextLdifModels.SchemaObjectClass
                            | str
                        )
                    ].ok(parsed_oc)
                error_msg = oc_result.error or "Parse objectclass failed"
                return FlextResult[
                    (
                        FlextLdifModels.SchemaAttribute
                        | FlextLdifModels.SchemaObjectClass
                        | str
                    )
                ].fail(error_msg)
            return FlextResult[
                (
                    FlextLdifModels.SchemaAttribute
                    | FlextLdifModels.SchemaObjectClass
                    | str
                )
            ].fail("No parse parameter provided")

        def _handle_write_operation(
            self,
            attr_model: FlextLdifModels.SchemaAttribute | None,
            oc_model: FlextLdifModels.SchemaObjectClass | None,
        ) -> FlextResult[
            FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str
        ]:
            """Handle write operation for schema quirk.

            Generic implementation that routes to write_attribute() or
            write_objectclass() based on provided parameters. This method is
            available to all server implementations.

            Args:
                attr_model: SchemaAttribute model to write (optional).
                oc_model: SchemaObjectClass model to write (optional).

            Returns:
                FlextResult with LDIF string representation, or error if writing
                failed or no parameter provided.

            """
            if attr_model:
                write_result = self.write_attribute(attr_model)
                if write_result.is_success:
                    written_text: str = write_result.unwrap()
                    return FlextResult[
                        (
                            FlextLdifModels.SchemaAttribute
                            | FlextLdifModels.SchemaObjectClass
                            | str
                        )
                    ].ok(written_text)
                error_msg: str = write_result.error or "Write attribute failed"
                return FlextResult[
                    (
                        FlextLdifModels.SchemaAttribute
                        | FlextLdifModels.SchemaObjectClass
                        | str
                    )
                ].fail(error_msg)
            if oc_model:
                write_oc_result = self.write_objectclass(oc_model)
                if write_oc_result.is_success:
                    written_text = write_oc_result.unwrap()
                    return FlextResult[
                        (
                            FlextLdifModels.SchemaAttribute
                            | FlextLdifModels.SchemaObjectClass
                            | str
                        )
                    ].ok(written_text)
                error_msg = write_oc_result.error or "Write objectclass failed"
                return FlextResult[
                    (
                        FlextLdifModels.SchemaAttribute
                        | FlextLdifModels.SchemaObjectClass
                        | str
                    )
                ].fail(error_msg)
            return FlextResult[
                (
                    FlextLdifModels.SchemaAttribute
                    | FlextLdifModels.SchemaObjectClass
                    | str
                )
            ].fail("No write parameter provided")

        def _auto_detect_operation(
            self,
            data: (
                str
                | FlextLdifModels.SchemaAttribute
                | FlextLdifModels.SchemaObjectClass
            ),
            operation: FlextLdifConstants.LiteralTypes.ParseWriteOperationLiteral
            | None,
        ) -> (
            FlextLdifConstants.LiteralTypes.ParseWriteOperationLiteral
            | FlextResult[
                FlextLdifModels.SchemaAttribute
                | FlextLdifModels.SchemaObjectClass
                | str
            ]
        ):
            """Auto-detect operation from data type.

            Generic implementation that detects whether to parse or write based on
            data type. Returns operation or error result. This method is available
            to all server implementations.

            Args:
                data: Data to process (str for parse, SchemaAttribute/SchemaObjectClass
                    for write, or None).
                operation: Explicit operation to use (optional, auto-detected if None).

            Returns:
                ParseWriteOperationLiteral if operation can be determined, or
                FlextResult with error if data type is unknown.

            """
            if operation is not None:
                return operation

            if isinstance(data, str):
                return cast(
                    "FlextLdifConstants.LiteralTypes.ParseWriteOperationLiteral",
                    "parse",
                )
            if isinstance(
                data,
                (
                    FlextLdifModels.SchemaAttribute,
                    FlextLdifModels.SchemaObjectClass,
                ),
            ):
                return "write"

            return FlextResult[
                (
                    FlextLdifModels.SchemaAttribute
                    | FlextLdifModels.SchemaObjectClass
                    | str
                )
            ].fail(
                f"Unknown data type: {type(data).__name__}. "
                "Expected str, SchemaAttribute, or SchemaObjectClass",
            )

        def _route_operation(
            self,
            data: (
                str
                | FlextLdifModels.SchemaAttribute
                | FlextLdifModels.SchemaObjectClass
            ),
            operation: FlextLdifConstants.LiteralTypes.ParseWriteOperationLiteral,
        ) -> FlextResult[
            FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str
        ]:
            """Route data to appropriate parse or write handler.

            Generic implementation that routes data to _handle_parse_operation()
            or _handle_write_operation() based on operation type. This method is
            available to all server implementations.

            Args:
                data: Data to process (str, SchemaAttribute, or SchemaObjectClass).
                operation: Operation to perform ("parse" or "write").

            Returns:
                FlextResult with parsed model or written string, or error if
                operation/data type mismatch.

            """
            if operation == "parse":
                if not isinstance(data, str):
                       return FlextResult[
                        (
                            FlextLdifModels.SchemaAttribute
                            | FlextLdifModels.SchemaObjectClass
                            | str
                        )
                    ].fail(f"parse operation requires str, got {type(data).__name__}")
                # Detect if attribute or objectClass definition
                if (
                    FlextLdifUtilities.Schema.detect_schema_type(data)
                    == FlextLdifConstants.Schema.OBJECTCLASS
                ):
                    return self._handle_parse_operation(
                        attr_definition=None,
                        oc_definition=data,
                    )
                return self._handle_parse_operation(
                    attr_definition=data,
                    oc_definition=None,
                )

            if operation == "write":
                if isinstance(data, FlextLdifModels.SchemaAttribute):
                    return self._handle_write_operation(attr_model=data, oc_model=None)
                if isinstance(data, FlextLdifModels.SchemaObjectClass):
                    return self._handle_write_operation(attr_model=None, oc_model=data)
                return FlextResult[
                    Union[
                        FlextLdifModels.SchemaAttribute,
                        FlextLdifModels.SchemaObjectClass | str,
                    ]
                ].fail(
                    f"write operation requires SchemaAttribute or "
                    f"SchemaObjectClass, got {type(data).__name__}",
                )

            # Should not reach here (Literal type ensures only parse or write)
            msg = f"Unknown operation: {operation}"
            raise AssertionError(msg)

        def execute(
            self,
            *,
            data: (
                str
                | FlextLdifModels.SchemaAttribute
                | FlextLdifModels.SchemaObjectClass
                | None
            ) = None,
            operation: str | None = None,
            **kwargs: FlextLdifTypes.Server.ServerInitKwargs,
        ) -> FlextResult[
            FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str
        ]:
            """Execute schema operation with auto-detection: str→parse, Model→write.

            Generic implementation that auto-detects operation type and routes to
            appropriate handler. This method is available to all server implementations.

            Args:
                **kwargs: data (str | SchemaAttribute | SchemaObjectClass), operation (optional)

            Returns:
                FlextResult with parsed model or written string

            """
            # Extract from kwargs if not provided
            if data is None:
                data_raw = kwargs.get("data")
                if isinstance(
                    data_raw,
                    (
                        str,
                        FlextLdifModels.SchemaAttribute,
                        FlextLdifModels.SchemaObjectClass,
                    ),
                ):
                    data = data_raw

            if operation is None:
                operation_raw = kwargs.get("operation")
                # Type narrowing: check if operation_raw is a valid Literal value
                if isinstance(operation_raw, str):
                    if operation_raw == "parse":
                        operation = cast(
                            "FlextLdifConstants.LiteralTypes.ParseWriteOperationLiteral",
                            "parse",
                        )
                    elif operation_raw == "write":
                        operation = cast(
                            "FlextLdifConstants.LiteralTypes.ParseWriteOperationLiteral",
                            "write",
                        )

            # Health check: no data provided
            if data is None:
                empty_str: str = ""
                return FlextResult[
                    (
                        FlextLdifModels.SchemaAttribute
                        | FlextLdifModels.SchemaObjectClass
                        | str
                    )
                ].ok(empty_str)

            # Auto-detect or validate operation
            # Type narrowing: ensure operation is ParseWriteOperationLiteral | None
            operation_typed: (
                FlextLdifConstants.LiteralTypes.ParseWriteOperationLiteral | None
            ) = (
                cast(
                    "FlextLdifConstants.LiteralTypes.ParseWriteOperationLiteral",
                    operation,
                )
                if isinstance(operation, str) and operation in {"parse", "write"}
                else None
            )
            detected_op = self._auto_detect_operation(data, operation_typed)
            if isinstance(detected_op, FlextResult):
                return detected_op

            # Route to appropriate handler
            return self._route_operation(data, detected_op)

        def write(
            self,
            model: FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass,
        ) -> FlextResult[str]:
            """Write schema model to string format.

            Dispatches to write_attribute or write_objectclass based on model type.
            This satisfies FlextLdifProtocols.Quirks.SchemaProtocol.

            Args:
                model: SchemaAttribute or SchemaObjectClass model to write

            Returns:
                FlextResult with string representation

            """
            if isinstance(model, FlextLdifModels.SchemaAttribute):
                return self.write_attribute(model)
            if isinstance(model, FlextLdifModels.SchemaObjectClass):
                return self.write_objectclass(model)
            return FlextResult.fail(f"Unsupported model type: {type(model)}")

    class Acl(
        FlextService[FlextLdifModels.Acl | str],
    ):
        """Base class for ACL quirks - satisfies FlextLdifProtocols.Quirks.AclProtocol.

        NOTE: This is an implementation detail - DO NOT import directly.
        Use FlextLdifServersBase.Acl instead.

        ACL quirks extend RFC 4516 ACL parsing with server-specific formats
        for access control list processing.

        **STANDARDIZED CONSTANTS REQUIRED**: Each Acl implementation MUST define
        a Constants nested class with:
        - CANONICAL_NAME: Unique server identifier (e.g., "oid", "oud")
        - ALIASES: All valid names for this server including canonical
        - PRIORITY: Selection priority (lower = higher priority)
        - CAN_NORMALIZE_FROM: What source types this quirk can normalize
        - CAN_DENORMALIZE_TO: What target types this quirk can denormalize to

        **Protocol Compliance**: All implementations MUST satisfy
        FlextLdifProtocols.Quirks.AclProtocol through structural typing.
        This means all public methods must match protocol signatures exactly.

        **Validation**: Use isinstance(quirk, FlextLdifProtocols.Quirks.AclProtocol)
        to check protocol compliance at runtime.

        Common ACL patterns:
        - Vendor-specific ACI attributes
        - Enhanced ACI formats beyond RFC baseline
        - Access control directives
        - Vendor-specific security descriptors
        - RFC 4516 compliant baseline

        **FlextService V2 Integration:**
        - Inherits from FlextService for dependency injection, logging, and validation
        - Uses V2 patterns: .result property for direct access, .execute() for FlextResult
        - Auto-registration in DI container via FlextService
        - Type-safe with TDomainResult = Acl
        """

        # Registry method for DI-based automatic registration
        # Default ACL attribute name (RFC baseline). Override in subclass for server-specific name.
        acl_attribute_name: ClassVar[str] = "acl"

        # NOTE: server_type and priority are ClassVar in the PARENT SERVER CLASS ONLY
        # NOT in nested Schema/Acl/Entry classes
        # (e.g., FlextLdifServersOid.server_type, FlextLdifServersOid.priority)
        # All constants must be in FlextLdifServers[Server].Constants, NOT in subclasses

        # Protocol-required fields
        server_type: FlextLdifConstants.LiteralTypes.ServerTypeLiteral = "rfc"
        """Server type identifier (e.g., 'oid', 'oud', 'openldap', 'rfc')."""

        priority: int = 0
        """Quirk priority (lower number = higher priority)."""

        # Parent quirk reference for accessing server-level configuration
        parent_quirk: FlextLdifServersBase | None = Field(
            default=None,
            exclude=True,
            repr=False,
            description=(
                "Reference to parent FlextLdifServersBase instance "
                "for server-level access"
            ),
        )

        def __init__(
            self,
            acl_service: FlextLdifProtocols.Services.HasParseMethodProtocol
            | None = None,
            _parent_quirk: FlextLdifServersBase | None = None,
            **kwargs: str | float | bool | None,
        ) -> None:
            """Initialize ACL quirk service with optional DI service injection.

            Args:
                acl_service: Injected FlextLdifAcl service (optional, lazy-created if None)
                parent_quirk: Reference to parent FlextLdifServersBase
                **kwargs: Additional initialization parameters for FlextService

            Note:
                server_type and priority are no longer passed to nested classes.
                They should be accessed via _get_server_type() and Constants.PRIORITY
                from the parent server class.

            """
            super().__init__(**kwargs)
            self._acl_service = acl_service  # Store for use by subclasses
            # Note: server_type and priority descriptors are only available on parent server classes
            # Nested classes (Schema/Acl/Entry) access them via _get_server_type() when needed

        def _get_server_type(self) -> FlextLdifConstants.LiteralTypes.ServerTypeLiteral:
            """Get server_type from parent server class via __qualname__."""
            return FlextLdifUtilities.Server.get_parent_server_type(self)

        def _get_priority(self) -> int:
            """Get priority from parent server class Constants."""
            parent = getattr(self, "_parent_quirk", None)
            if (
                parent
                and hasattr(parent, "Constants")
                and hasattr(parent.Constants, "PRIORITY")
            ):
                priority_value = parent.Constants.PRIORITY
                if not isinstance(priority_value, int):
                    msg = f"Expected int, got {type(priority_value)}"
                    raise TypeError(msg)
                return priority_value
            return 100  # Default priority

        # =====================================================================
        # ServerAclProtocol Implementation - Required by Protocol
        # =====================================================================

        # RFC Foundation - Standard LDAP ACL attributes (all servers start here)
        RFC_ACL_ATTRIBUTES: ClassVar[list[str]] = [
            "aci",  # Standard LDAP (RFC 4876)
            "acl",  # Alternative format
            "olcAccess",  # Configuration-based access control
            "aclRights",  # Generic rights
            "aclEntry",  # ACL entry
        ]

        def get_acl_attributes(self) -> list[str]:
            """Get ACL attributes for this server.

            Returns RFC foundation attributes. Subclasses should override to add
            server-specific attributes.

            Returns:
                List of ACL attribute names (lowercase)

            """
            return self.RFC_ACL_ATTRIBUTES

        def is_acl_attribute(self, attribute_name: str) -> bool:
            """Check if attribute is ACL attribute (case-insensitive).

            Args:
                attribute_name: Attribute name to check

            Returns:
                True if attribute is ACL attribute, False otherwise

            """
            # Use set for O(1) lookup performance
            all_attrs_lower = {a.lower() for a in self.get_acl_attributes()}
            return attribute_name.lower() in all_attrs_lower

        # Control auto-execution
        auto_execute: ClassVar[bool] = False

        # =====================================================================
        # Concrete Routing Methods - Moved to rfc.py.Acl
        # =====================================================================
        # _route_parse, _route_write, _handle_parse_acl, _handle_write_acl,
        # execute, __call__, __new__ are now concrete implementations in
        # FlextLdifServersRfc.Acl

        def _hook_post_parse_acl(
            self,
            acl: FlextLdifModels.Acl,
        ) -> FlextResult[FlextLdifModels.Acl]:
            """Hook called after parsing an ACL line.

            Override in subclasses for server-specific post-processing of parsed ACLs.

            Default behavior: returns ACL unchanged (pass-through).

            **When to use:**
            - Normalize ACL properties after parsing
            - Add server-specific metadata
            - Validate ACL constraints
            - Transform ACL format

            Args:
                acl: Parsed Acl from parse_acl()

            Returns:
                FlextResult[Acl] - modified or original ACL

            **Example:**
                def _hook_post_parse_acl(self, acl):
                    # OID-specific: normalize permission format
                    if acl.permissions:
                        acl.permissions = normalize_permissions(acl.permissions)
                    return FlextResult.ok(acl)

            """
            return FlextResult.ok(acl)

        def can_handle_acl(self, acl_line: str | FlextLdifModels.Acl) -> bool:
            """Check if this quirk can handle the ACL definition.

            Called BEFORE parsing to detect if this quirk should process the ACL line.
            Receives the raw ACL line string (e.g., "orclaci: { ... }") or Acl model.

            Args:
                acl_line: ACL definition line string

            Returns:
                True if this quirk can handle this ACL definition

            """
            _ = acl_line  # Explicitly mark as intentionally unused in base
            return False  # Must be implemented by subclass  # Must be implemented by subclass

        def can_handle(self, acl_line: FlextLdifTypes.AclOrString) -> bool:
            """Check if this ACL can be handled after parsing.

            Generic implementation that assumes any ACL that has been successfully
            parsed into the Acl model is handleable. This method is available to
            all server implementations.

            Subclasses can override for server-specific validation logic.

            Args:
                acl_line: The ACL string or Acl model to check.

            Returns:
                True if the ACL can be handled, False otherwise.

            """
            _ = acl_line  # Unused in base implementation
            return True  # Default: all parsed ACLs are handleable

        def _supports_feature(self, feature_id: str) -> bool:
            """Check if this server supports a specific feature.

            Generic implementation that checks if feature_id is in
            RFC_STANDARD_FEATURES. This method is available to all server
            implementations.

            Subclasses can override to declare additional supported features
            beyond RFC_STANDARD_FEATURES.

            Args:
                feature_id: Feature ID from FeatureCapabilities

            Returns:
                True if feature is supported, False otherwise.

            """
            return (
                feature_id
                in FlextLdifConstants.FeatureCapabilities.RFC_STANDARD_FEATURES
            )

        def _get_feature_fallback(self, feature_id: str) -> str | None:
            """Get RFC fallback value for unsupported vendor feature.

            Generic implementation that uses FeatureCapabilities.RFC_FALLBACKS
            for standard fallbacks. This method is available to all server
            implementations.

            Subclasses can override to customize fallback behavior.

            Args:
                feature_id: Feature ID from FeatureCapabilities

            Returns:
                Fallback permission string, or None if no fallback.

            """
            return FlextLdifConstants.FeatureCapabilities.RFC_FALLBACKS.get(feature_id)

        # =====================================================================
        # Public Interface Methods - Moved to rfc.py.Acl
        # =====================================================================
        # parse, can_handle, write are now concrete implementations in
        # FlextLdifServersRfc.Acl. Subclasses should override _parse_acl,
        # _write_acl, and can_handle_acl for server-specific logic.

        def _parse_acl(self, acl_line: str) -> FlextResult[FlextLdifModels.Acl]:
            r"""REQUIRED: Parse server-specific ACL definition (internal).

            Parses an ACL (Access Control List) definition line into Acl model.
            Called for each acl attribute during entry parsing.

            **What you must do:**
            1. Parse the ACL definition line (format varies by server)
            2. Extract permissions, subjects, targets, and server-specific rules
            3. Create Acl model with structured representation
            4. Call _hook_post_parse_acl() if implementing hooks
            5. Return FlextResult.ok(acl)

            **Important constraints:**
            - NEVER raise exceptions - return FlextResult.fail()
            - Handle malformed ACL rules gracefully with best-effort parsing
            - Preserve server-specific syntax in quirk_metadata
            - Different servers have different ACL syntax (vendor-specific formats)

            **Edge cases to handle:**
            - Empty string -> return fail("ACL line is empty")
            - Malformed rule -> handle gracefully or reject with clear message
            - Unknown permission types -> preserve as string for server-specific handling
            - Complex nested rules -> flatten or preserve structure as appropriate
            - Server-specific extensions -> preserve in quirk_metadata for round-trip conversion
            - Partial/incomplete rules -> validate completeness if needed

            Args:
                acl_line: ACL definition line (server-specific format)

            Returns:
                FlextResult with Acl model or fail(message) on error

            Examples of vendor-specific ACL formats:
                - Configuration-based: "access to attrs=cn by * read"
                - ACI-based: "aci: (targetdn=\"...\") (version 3.0;...)"

            """
            _ = acl_line  # Explicitly mark as intentionally unused in base
            return FlextResult.fail("Must be implemented by subclass")

        def can_handle_attribute(
            self,
            attribute: FlextLdifModels.SchemaAttribute,
        ) -> bool:
            """Check if this ACL quirk should be aware of a specific attribute definition.

            ACL quirks may need to evaluate rules based on attribute schema properties
            (e.g., sensitivity, usage). This method allows the quirk to indicate
            if it has special handling for a given attribute model.

            Args:
                attribute: The SchemaAttribute model.

            Returns:
                True if this quirk has specific logic related to this attribute.

            """
            _ = attribute  # Explicitly mark as intentionally unused in base
            return False  # Must be implemented by subclass  # Must be implemented by subclass

        def can_handle_objectclass(
            self,
            objectclass: FlextLdifModels.SchemaObjectClass,
        ) -> bool:
            """Check if this ACL quirk should be aware of a specific objectClass definition.

            ACL quirks may need to evaluate rules based on objectClass properties.

            Args:
                objectclass: The SchemaObjectClass model.

            Returns:
                True if this quirk has specific logic related to this objectClass.

            """
            _ = objectclass  # Explicitly mark as intentionally unused in base
            return False  # Must be implemented by subclass  # Must be implemented by subclass

        def _write_acl(self, acl_data: FlextLdifModels.Acl) -> FlextResult[str]:
            """Write ACL data to RFC-compliant string format (internal).

            Base class stub - must be implemented by subclass.

            Args:
                acl_data: Acl model

            Returns:
                FlextResult.fail with "Must be implemented by subclass"

            """
            _ = acl_data
            return FlextResult[str].fail("Must be implemented by subclass")

        def parse(self, acl_line: str) -> FlextResult[FlextLdifModels.Acl]:
            """Parse ACL line to Acl model.

            This satisfies FlextLdifProtocols.Quirks.AclProtocol.

            Args:
                acl_line: ACL definition line

            Returns:
                FlextResult with Acl model

            """
            return self._parse_acl(acl_line)

        def write(self, acl_data: FlextLdifModels.Acl) -> FlextResult[str]:
            """Write Acl model to string format.

            This satisfies FlextLdifProtocols.Quirks.AclProtocol.

            Args:
                acl_data: Acl model

            Returns:
                FlextResult with string representation

            """
            return self._write_acl(acl_data)

        def _extract_acl_parameters(
            self,
            kwargs: dict[
                str,
                str
                | int
                | float
                | bool
                | list[str]
                | dict[str, str | int | float | bool | list[str] | None]
                | None,
            ],
        ) -> tuple[
            str | FlextLdifModels.Acl | None,
            FlextLdifConstants.LiteralTypes.ParseWriteOperationLiteral | None,
        ]:
            """Extract and validate ACL operation parameters from kwargs.

            Args:
                kwargs: Keyword arguments containing 'data' and optional 'operation'

            Returns:
                Tuple of (data, operation) with type narrowing applied

            """
            # Extract data parameter
            data_raw = kwargs.get("data")
            data: str | FlextLdifModels.Acl | None = (
                data_raw
                if isinstance(data_raw, (str, FlextLdifModels.Acl, type(None)))
                else None
            )

            # Extract operation parameter with type narrowing
            operation_raw = kwargs.get("operation")
            operation: (
                FlextLdifConstants.LiteralTypes.ParseWriteOperationLiteral | None
            ) = None
            if isinstance(operation_raw, str) and operation_raw in {"parse", "write"}:
                operation = cast(
                    "FlextLdifConstants.LiteralTypes.ParseWriteOperationLiteral",
                    operation_raw,
                )

            return data, operation

        def _execute_acl_parse(
            self,
            data: str,
        ) -> FlextResult[FlextLdifModels.Acl | str]:
            """Execute ACL parse operation.

            Args:
                data: ACL data string to parse

            Returns:
                FlextResult with parsed Acl model

            """
            parse_result = self.parse(data)
            if parse_result.is_success:
                return FlextResult[FlextLdifModels.Acl | str].ok(
                    parse_result.unwrap()
                )
            return FlextResult[FlextLdifModels.Acl | str].fail(
                parse_result.error or "Parse failed"
            )

        def _execute_acl_write(
            self,
            data: FlextLdifModels.Acl,
        ) -> FlextResult[FlextLdifModels.Acl | str]:
            """Execute ACL write operation.

            Args:
                data: Acl model to write

            Returns:
                FlextResult with written string

            """
            write_result = self.write(data)
            if write_result.is_success:
                return FlextResult[FlextLdifModels.Acl | str].ok(
                    write_result.unwrap()
                )
            return FlextResult[FlextLdifModels.Acl | str].fail(
                write_result.error or "Write failed"
            )

        def execute(
            self,
            *,
            data: str | FlextLdifModels.Acl | None = None,
            operation: str | None = None,
            **kwargs: FlextLdifTypes.Server.ServerInitKwargs,
        ) -> FlextResult[FlextLdifModels.Acl | str]:
            """Execute ACL operation with auto-detection: str→parse, Acl→write.

            Generic implementation that auto-detects operation type and routes to
            appropriate handler. This method is available to all server implementations.

            Args:
                **kwargs: data (str | Acl), operation (optional)

            Returns:
                FlextResult with parsed Acl model or written string

            """
            # Extract from kwargs if not provided
            if data is None:
                data_raw = kwargs.get("data")
                if isinstance(data_raw, (str, FlextLdifModels.Acl)):
                    data = data_raw

            if operation is None:
                operation_raw = kwargs.get("operation")
                if isinstance(operation_raw, str) and operation_raw in {
                    "parse",
                    "write",
                }:
                    operation = operation_raw

            # Health check: no data provided
            if data is None:
                empty_acl: FlextLdifModels.Acl = FlextLdifModels.Acl()
                return FlextResult[FlextLdifModels.Acl | str].ok(empty_acl)

            # Auto-detect operation from data type, unless overridden
            detected_operation: (
                FlextLdifConstants.LiteralTypes.ParseWriteOperationLiteral | None
            ) = (
                cast(
                    "FlextLdifConstants.LiteralTypes.ParseWriteOperationLiteral",
                    operation,
                )
                if operation is not None
                else None
            )
            if detected_operation is None:
                detected_operation = "parse" if isinstance(data, str) else "write"  # type: ignore[assignment]

            # Execute based on detected/forced operation
            if detected_operation == "parse":
                if not isinstance(data, str):
                    return FlextResult[FlextLdifModels.Acl | str].fail(
                        f"parse operation requires str, got {type(data).__name__}",
                    )
                return self._execute_acl_parse(data)

            # detected_operation == "write"
            if not isinstance(data, FlextLdifModels.Acl):
                return FlextResult[FlextLdifModels.Acl | str].fail(
                    f"write operation requires Acl, got {type(data).__name__}",
                )
            return self._execute_acl_write(data)

        def create_metadata(
            self,
            original_format: str,
            extensions: FlextLdifTypes.MetadataDictMutable | None = None,
        ) -> FlextLdifModels.QuirkMetadata:
            """Create ACL quirk metadata.

            Generic implementation that creates QuirkMetadata with quirk_type
            and extensions. This method is available to all server implementations.

            Args:
                original_format: Original ACL format string to store in metadata.
                extensions: Optional additional extensions to include in metadata.

            Returns:
                QuirkMetadata with quirk_type and extensions.

            """
            all_extensions: FlextLdifTypes.MetadataDictMutable = {
                FlextLdifConstants.MetadataKeys.ACL_ORIGINAL_FORMAT: original_format
            }
            if extensions:
                all_extensions.update(extensions)
            # Convert dict to DynamicMetadata for QuirkMetadata
            extensions_model = FlextLdifModels.DynamicMetadata(**all_extensions)
            return FlextLdifModels.QuirkMetadata(
                quirk_type=self._get_server_type(),
                extensions=extensions_model,
            )

        def format_acl_value(
            self,
            acl_value: str,
            acl_metadata: FlextLdifModels.AclWriteMetadata,
            *,
            use_original_format_as_name: bool = False,
        ) -> FlextResult[str]:
            """Format ACL value for writing, optionally using original format as name.

            Generic implementation that optionally replaces ACL name with sanitized
            original format when use_original_format_as_name is True and original
            format is available. This method is available to all server implementations.

            Subclasses can override _hook_format_acl_name_pattern() to customize
            the pattern matching and replacement logic for server-specific ACL formats.

            Args:
                acl_value: The ACL string value to format (e.g., ACI attribute value).
                acl_metadata: AclWriteMetadata extracted from entry metadata.
                use_original_format_as_name: If True, replace ACL name with
                    sanitized original format from metadata.

            Returns:
                FlextResult[str] with formatted ACL value, or unchanged value
                if formatting not applicable.

            """
            # If option not enabled or no original format available, return unchanged
            if not use_original_format_as_name:
                return FlextResult[str].ok(acl_value)

            if not acl_metadata.has_original_format():
                return FlextResult[str].ok(acl_value)

            original_format = acl_metadata.original_format
            if not original_format:
                return FlextResult[str].ok(acl_value)

            # Sanitize the original format for use as ACL name
            sanitized_name, _was_sanitized = FlextLdifUtilities.ACL.sanitize_acl_name(
                original_format,
            )

            if not sanitized_name:
                return FlextResult[str].ok(acl_value)

            # Use hook for server-specific pattern matching and replacement
            pattern_result = self._hook_format_acl_name_pattern()
            if pattern_result.is_failure:
                return FlextResult[str].ok(acl_value)

            pattern, replacement_template = pattern_result.unwrap()
            formatted_value = pattern.sub(
                replacement_template.format(sanitized_name),
                acl_value,
            )

            return FlextResult[str].ok(formatted_value)

        def _hook_format_acl_name_pattern(
            self,
        ) -> FlextResult[tuple[re.Pattern[str], str]]:
            """Hook for server-specific ACL name pattern matching.

            Returns pattern and replacement template for formatting ACL names.
            Default implementation uses RFC ACI format pattern.

            Returns:
                FlextResult with tuple of (pattern, replacement_template).
                Replacement template should use {0} or {name} for the sanitized name.

            """
            # RFC ACI format: acl "name"
            pattern = re.compile(r'acl\s+"[^"]*"')
            replacement_template = 'acl "{0}"'
            return FlextResult[tuple[re.Pattern[str], str]].ok((
                pattern,
                replacement_template,
            ))

        def convert_rfc_acl_to_aci(
            self,
            rfc_acl_attrs: dict[str, list[str]],
            target_server: str,
        ) -> FlextResult[dict[str, list[str]]]:
            """Convert RFC ACL format to server-specific ACI format.

            Base implementation: Pass-through (RFC ACLs are already in RFC format).
            Subclasses should override for server-specific conversions.

            Args:
                rfc_acl_attrs: ACL attributes in RFC format
                target_server: Target server type identifier

            Returns:
                FlextResult[dict[str, list[str]]] with server-specific ACL attributes

            """
            _ = target_server
            return FlextResult[dict[str, list[str]]].ok(rfc_acl_attrs)

    class Entry(
        FlextService[FlextLdifModels.Entry | str],
    ):
        """Base class for entry processing quirks - satisfies FlextLdifProtocols.Quirks.EntryProtocol.

        NOTE: This is an implementation detail - DO NOT import directly.
        Use FlextLdifServersBase.Entry instead.

        Entry quirks handle server-specific entry attributes and transformations
        for LDAP entry processing.

        **STANDARDIZED CONSTANTS REQUIRED**: Each Entry implementation MUST define
        a Constants nested class with:
        - CANONICAL_NAME: Unique server identifier (e.g., "oid", "oud")
        - ALIASES: All valid names for this server including canonical
        - PRIORITY: Selection priority (lower = higher priority)
        - CAN_NORMALIZE_FROM: What source types this quirk can normalize
        - CAN_DENORMALIZE_TO: What target types this quirk can denormalize to


        **Protocol Compliance**: All implementations MUST satisfy
        FlextLdifProtocols.Quirks.EntryProtocol through structural typing.
        This means all public methods must match protocol signatures exactly.

        **Validation**: Use isinstance(quirk, FlextLdifProtocols.Quirks.EntryProtocol)
        to check protocol compliance at runtime.

        Common entry transformation patterns:
        - Vendor operational attributes
        - Configuration entries (e.g., cn=config subtree)
        - Vendor-specific attributes
        - Server-specific DN formats
        - RFC baseline entry handling

        """

        # Protocol-required fields
        server_type: str = "unknown"
        """Server type identifier."""

        priority: int = 0
        """Quirk priority (lower number = higher priority)."""

        # Registry method for DI-based automatic registration
        # NOTE: server_type and priority are ClassVar in the PARENT SERVER CLASS ONLY
        # NOT in nested Schema/Acl/Entry classes
        # (e.g., FlextLdifServersOid.server_type, FlextLdifServersOid.priority)
        # All constants must be in FlextLdifServers[Server].Constants, NOT in subclasses

        # Parent quirk reference for accessing server-level configuration
        parent_quirk: FlextLdifServersBase | None = Field(
            default=None,
            exclude=True,
            repr=False,
            description=(
                "Reference to parent FlextLdifServersBase instance "
                "for server-level access"
            ),
        )

        def __init__(
            self,
            entry_service: FlextLdifProtocols.Services.HasParseMethodProtocol
            | None = None,
            _parent_quirk: FlextLdifServersBase | None = None,
            **kwargs: str | float | bool | None,
        ) -> None:
            """Initialize entry quirk service with optional DI service injection.

            Args:
                entry_service: Injected FlextLdifEntry service (optional, lazy-created if None)
                **kwargs: Passed to FlextService for initialization (includes parent_quirk)

            Note:
                server_type and priority are no longer passed to nested classes.
                They should be accessed via _get_server_type() and Constants.PRIORITY
                from the parent server class.

            """
            super().__init__(**kwargs)
            self._entry_service = entry_service  # Store for use by subclasses
            # Note: server_type and priority descriptors are only available on parent server classes
            # Nested classes (Schema/Acl/Entry) access them via _get_server_type() when needed

        def _get_server_type(self) -> FlextLdifConstants.LiteralTypes.ServerTypeLiteral:
            """Get server_type from parent server class via __qualname__."""
            return FlextLdifUtilities.Server.get_parent_server_type(self)

        def _get_priority(self) -> int:
            """Get priority from parent server class Constants."""
            parent = getattr(self, "_parent_quirk", None)
            if (
                parent
                and hasattr(parent, "Constants")
                and hasattr(parent.Constants, "PRIORITY")
            ):
                priority_value = parent.Constants.PRIORITY
                if not isinstance(priority_value, int):
                    msg = f"Expected int, got {type(priority_value)}"
                    raise TypeError(msg)
                return priority_value
            return 100  # Default priority

        # Control auto-execution
        auto_execute: ClassVar[bool] = False

        # =====================================================================
        # Public Parse/Write Interface
        # =====================================================================
        # Concrete Routing Methods - Moved to rfc.py.Entry
        # =====================================================================
        # parse, write, _route_parse, _route_write, _route_write_many,
        # _handle_parse_entry, _handle_write_entry, execute, __call__, __new__,
        # _auto_detect_entry_operation, _route_entry_operation are now
        # concrete implementations in FlextLdifServersRfc.Entry

        def _hook_validate_entry_raw(
            self,
            dn: str,
            attrs: dict[str, list[str | bytes]],
        ) -> FlextResult[bool]:
            """Hook to validate raw entry before parsing.

            Called before parse_entry() to allow server-specific validation of raw DN and attributes.

            Default behavior: validates DN is not empty.

            **When to use:**
            - Validate DN format before parsing
            - Check required attributes exist
            - Enforce server-specific rules
            - Filter out invalid entries early

            Args:
                dn: Distinguished Name
                attrs: Raw attributes dict (not used in base implementation)

            Returns:
                FlextResult[bool] with True on success, fail() on failure

            """
            _ = attrs
            if not dn:
                return FlextResult.fail("DN cannot be empty")
            return FlextResult.ok(True)

        def _hook_post_parse_entry(
            self,
            entry: FlextLdifModels.Entry,
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Hook called after parsing an entry.

            Override in subclasses for server-specific post-processing of parsed entries.

            Default behavior: returns entry unchanged (pass-through).

            **When to use:**
            - Normalize entry properties after parsing
            - Add server-specific metadata
            - Transform entry attributes

            Args:
                entry: Parsed Entry from parse_entry()

            Returns:
                FlextResult[Entry] - modified or original entry

            """
            return FlextResult.ok(entry)

        def _hook_pre_write_entry(
            self,
            entry: FlextLdifModels.Entry,
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Hook called before writing an entry.

            Override in subclasses for server-specific pre-processing before write_entry_to_rfc().

            Default behavior: returns entry unchanged (pass-through).

            **When to use:**
            - Normalize entry properties before writing
            - Add server-specific metadata for write
            - Transform entry format for output

            Args:
                entry: Entry to write

            Returns:
                FlextResult[Entry] - modified or original entry

            """
            return FlextResult.ok(entry)

        def can_handle_attribute(
            self,
            attribute: FlextLdifModels.SchemaAttribute,
        ) -> bool:
            """Check if this quirk can handle a schema attribute.

            Entry quirks typically don't handle schema attributes - that's handled
            by Schema quirks. Base implementation returns False.

            Args:
                attribute: SchemaAttribute model

            Returns:
                False in base class (Entry doesn't handle attributes)

            """
            _ = attribute  # Entry doesn't handle attributes
            return False

        def can_handle_objectclass(
            self,
            objectclass: FlextLdifModels.SchemaObjectClass,
        ) -> bool:
            """Check if this quirk can handle a schema objectClass.

            Entry quirks typically don't handle objectclasses - that's handled
            by Schema quirks. Base implementation returns False.

            Args:
                objectclass: SchemaObjectClass model

            Returns:
                False in base class (Entry doesn't handle objectclasses)

            """
            _ = objectclass  # Entry doesn't handle objectclasses
            return False

        def can_handle(
            self,
            entry_dn: str,
            attributes: dict[str, list[str]],
        ) -> bool:
            """Check if this quirk can handle the entry.

            Called BEFORE parsing to detect if this quirk should process the entry.
            Receives raw entry data (DN and attributes) from LDIF parser.

            Args:
                entry_dn: Entry distinguished name
                attributes: Entry attributes mapping

            Returns:
                True if this quirk should process this entry

            """
            _ = entry_dn  # Explicitly mark as intentionally unused in base
            _ = attributes  # Explicitly mark as intentionally unused in base
            return False  # Must be implemented by subclass  # Must be implemented by subclass

        def _normalize_attribute_name(self, attr_name: str) -> str:
            """Normalize attribute name to RFC 2849 canonical form.

            RFC 2849 specifies: Attribute names are case-insensitive.
            This method normalizes to canonical form for consistent matching.

            Key rule: objectclass (any case) → objectClass (canonical)
            All other attributes: preserved as-is (most are already lowercase)

            Args:
                attr_name: Attribute name from LDIF (any case)

            Returns:
                Canonical form of the attribute name

            """
            # Handle empty strings
            if not attr_name:
                return attr_name
            # RFC 2849: objectclass → objectClass (canonical form)
            if attr_name.lower() == "objectclass":
                return "objectClass"
            # All other attributes: preserved as-is
            return attr_name

        def _convert_raw_attributes(
            self,
            entry_attrs: dict[str, list[str | bytes]],
        ) -> dict[str, list[str]]:
            """Convert raw LDIF attributes to dict[str, list[str]] format.

            Handles bytes values from ldif3 parser and normalizes attribute names.

            Args:
                entry_attrs: Raw attributes mapping from LDIF parser

            Returns:
                Converted attributes with normalized names and string values

            """
            converted_attrs: dict[str, list[str]] = {}
            for attr_name, attr_values in entry_attrs.items():
                # Normalize attribute name to canonical case (RFC 2849)
                canonical_attr_name = self._normalize_attribute_name(attr_name)

                # Convert values to strings
                string_values: list[str] = []
                if FlextRuntime.is_list_like(attr_values):
                    string_values = [
                        (
                            value.decode("utf-8", errors="replace")
                            if isinstance(value, bytes)
                            else str(value)
                        )
                        for value in attr_values
                    ]
                elif isinstance(attr_values, bytes):
                    string_values = [
                        attr_values.decode("utf-8", errors="replace"),
                    ]
                else:
                    string_values = [str(attr_values)]

                # RFC 2849: If attribute already exists, append values
                if canonical_attr_name in converted_attrs:
                    converted_attrs[canonical_attr_name].extend(string_values)
                else:
                    converted_attrs[canonical_attr_name] = string_values

            return converted_attrs

        def _parse_content(
            self,
            ldif_content: str,
        ) -> FlextResult[list[FlextLdifModels.Entry]]:
            """Parse raw LDIF content string into Entry models (internal).

            PRIMARY parsing entry point - called by framework with raw LDIF.

            **You must:**
            1. Use ldif3.LDIFParser to parse LDIF content
            2. For each (dn, attrs) pair from ldif3:
               - Call _hook_validate_entry_raw(dn, attrs) [optional hook]
               - Call _parse_entry(dn, attrs) [required]
               - Call _hook_post_parse_entry(entry) [optional hook]
            3. Return list of all parsed entries

            **Edge cases:**
            - Empty string -> return ok([])
            - Whitespace only -> return ok([])
            - Malformed LDIF -> return fail(message)
            - Encoding errors -> catch UnicodeDecodeError, return fail()

            **NEVER raise exceptions** - return FlextResult.fail()

            Args:
                ldif_content: Raw LDIF content as string

            Returns:
                FlextResult with list[Entry] on success or fail(message)

            """
            _ = ldif_content  # Explicitly mark as intentionally unused in base
            return FlextResult.fail("Must be implemented by subclass")

        # =====================================================================
        # Concrete Helper Methods - Moved to rfc.py.Entry
        # =====================================================================
        # parse_entry is now a concrete implementation in FlextLdifServersRfc.Entry
        # NOTE: can_handle_attribute() and can_handle_objectclass() are Schema-level
        # methods only. Entry detection uses can_handle(dn, attributes) instead.

        def _write_entry(
            self,
            entry_data: FlextLdifModels.Entry,
        ) -> FlextResult[str]:
            r"""Write Entry model to RFC-compliant LDIF string (internal).

            Converts Entry model back to LDIF text format.

            **RFC 2849 Format:**
            - Start with "dn: <distinguished-name>"
            - Follow with "attribute: value" pairs
            - Use "attribute:: <base64>" for binary/non-ASCII
            - Blank line after last attribute
            - Proper line continuations for long values

            **Edge cases:**
            - Null entry -> return fail("Entry is None")
            - Missing DN -> return fail("Entry DN is None")
            - Empty attributes -> return ok("dn: ...\n\n")
            - Special chars in DN -> proper escaping

            Args:
                entry_data: Entry model to write

            Returns:
                FlextResult with LDIF string or fail(message)

            """
            _ = entry_data  # Explicitly mark as intentionally unused in base
            return FlextResult.fail("Must be implemented by subclass")

        def parse(self, ldif_content: str) -> FlextResult[list[FlextLdifModels.Entry]]:
            """Parse LDIF content string into Entry models.

            This satisfies FlextLdifProtocols.Quirks.EntryProtocol.

            Args:
                ldif_content: Raw LDIF content as string

            Returns:
                FlextResult with list of Entry models

            """
            return self._parse_content(ldif_content)

        def write(
            self,
            entry_data: FlextLdifModels.Entry | list[FlextLdifModels.Entry],
            write_options: FlextLdifModels.WriteFormatOptions | None = None,
        ) -> FlextResult[str]:
            """Write Entry model(s) to LDIF string format.

            Generic implementation that handles single Entry or list of Entries,
            and optionally injects write_options into entry metadata. This method
            is available to all server implementations.

            Args:
                entry_data: Entry model or list of Entry models
                write_options: Optional write format options to inject into metadata

            Returns:
                FlextResult with LDIF string

            """
            # Handle list of entries
            if isinstance(entry_data, list):
                results: list[str] = []
                for entry in entry_data:
                    result = self.write(entry, write_options)
                    if result.is_failure:
                        return result
                    results.append(result.unwrap())
                return FlextResult[str].ok("\n".join(results))

            # Single entry - inject write_options into metadata if provided
            entry = entry_data
            if write_options is not None:
                new_write_opts = (
                    dict(entry.metadata.write_options)
                    if entry.metadata and entry.metadata.write_options
                    else {}
                )
                # Convert dict to WriteOptions model if needed
                write_options_typed: FlextLdifModelsDomains.WriteOptions | None = None
                if isinstance(write_options, FlextLdifModelsDomains.WriteOptions):
                    write_options_typed = write_options
                elif isinstance(write_options, dict):
                    write_options_typed = (
                        FlextLdifModelsDomains.WriteOptions.model_validate(
                            write_options
                        )
                    )
                else:
                    msg = f"Expected WriteOptions | dict, got {type(write_options)}"
                    raise TypeError(msg)
                new_write_opts[FlextLdifConstants.MetadataKeys.WRITE_OPTIONS] = (
                    write_options_typed
                )
                entry = entry.model_copy(
                    update={
                        "metadata": entry.metadata.model_copy(
                            update={"write_options": new_write_opts}
                        )
                        if entry.metadata
                        else FlextLdifModels.QuirkMetadata(
                            quirk_type="rfc", write_options=write_options_typed
                        )
                    }
                )

            return self._write_entry(entry)

        def _normalize_entry(
            self,
            entry: FlextLdifModels.Entry,
        ) -> FlextLdifModels.Entry:
            """Normalize entry to RFC format with metadata tracking.

            Hook for server-specific normalization. Override in server quirks
            to transform server-specific attributes/formats to RFC baseline.

            Base Implementation: Returns entry as-is (no normalization).
            Servers override to convert their formats to RFC.

            Args:
                entry: Entry to normalize

            Returns:
                Normalized entry (base implementation returns unchanged)

            Example Override (OID):
                def _normalize_entry(self, entry):
                    # Convert OID boolean "1"/"0" to RFC "TRUE"/"FALSE"
                    # Track in metadata via entry.track_transformation(...)
                    return normalized_entry

            """
            return entry

        def _denormalize_entry(
            self,
            entry: FlextLdifModels.Entry,
            target_server: str | None = None,
        ) -> FlextLdifModels.Entry:
            """Denormalize entry from RFC format to target server format.

            Hook for server-specific denormalization. Override in server quirks
            to convert RFC format back to server-specific representation.

            Base Implementation: Returns entry as-is (no denormalization).
            Servers override to convert RFC back to their native format.

            Args:
                entry: RFC-normalized entry
                target_server: Target server type (optional hint)

            Returns:
                Denormalized entry for target server (base implementation returns unchanged)

            Example Override (OUD):
                def _denormalize_entry(self, entry, target_server):
                    # Convert RFC booleans back to OUD format
                    # Use metadata.conversion_notes for context
                    return denormalized_entry

            """
            _ = target_server
            return entry

        def execute(
            self, **kwargs: FlextLdifTypes.FlexibleKwargsMutable
        ) -> FlextResult[FlextLdifModels.Entry | str]:
            """Execute entry operation (parse/write)."""
            ldif_content = kwargs.get("ldif_content")
            entry_model = kwargs.get("entry_model")

            if isinstance(ldif_content, str):
                entries_result = self._parse_content(ldif_content)
                if entries_result.is_success:
                    entries = entries_result.unwrap()
                    return FlextResult[FlextLdifModels.Entry | str].ok(
                        entries[0] if entries else "",
                    )
                return FlextResult[FlextLdifModels.Entry | str].ok("")
            if isinstance(entry_model, FlextLdifModels.Entry):
                str_result = self._write_entry(entry_model)
                return FlextResult[FlextLdifModels.Entry | str].ok(
                    str_result.unwrap() if str_result.is_success else "",
                )

            return FlextResult[FlextLdifModels.Entry | str].ok("")

        def parse_entry(
            self,
            entry_dn: str,
            entry_attrs: dict[str, list[str]],
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Parse a single entry from DN and attributes.

            Base implementation delegates to _parse_content() after constructing
            LDIF content string. Subclasses should override for server-specific parsing.

            Args:
                entry_dn: Entry distinguished name
                entry_attrs: Entry attributes mapping (dict[str, list[str]])

            Returns:
                FlextResult[Entry] with parsed entry model

            """
            # Convert entry_attrs to dict if needed
            if isinstance(entry_attrs, Mapping):
                attrs_dict: dict[
                    str,
                    str | list[str] | bytes | list[bytes] | int | float | bool | None,
                ] = dict(entry_attrs)
            elif isinstance(entry_attrs, dict):
                attrs_dict = entry_attrs
            else:
                msg = f"Expected Mapping | dict, got {type(entry_attrs)}"
                raise TypeError(msg)

            # Build LDIF content string from DN and attributes
            ldif_lines = [f"dn: {entry_dn}"]
            for attr_name, attr_values in attrs_dict.items():
                if FlextRuntime.is_list_like(attr_values):
                    if not isinstance(attr_values, list):
                        msg = f"Expected list, got {type(attr_values)}"
                        raise TypeError(msg)
                    # Decode bytes to string before formatting
                    ldif_lines.extend(
                        f"{attr_name}: {value.decode('utf-8') if isinstance(value, bytes) else value}"
                        for value in attr_values
                    )
                else:
                    # Decode bytes to string before formatting
                    value_str = (
                        attr_values.decode("utf-8")
                        if isinstance(attr_values, bytes)
                        else attr_values
                    )
                    ldif_lines.append(f"{attr_name}: {value_str}")
            ldif_content = "\n".join(ldif_lines) + "\n"

            # Parse using _parse_content and return first entry
            result = self._parse_content(ldif_content)
            if result.is_failure:
                return FlextResult[FlextLdifModels.Entry].fail(
                    result.error or "Failed to parse entry",
                )
            entries = result.unwrap()
            if not entries:
                return FlextResult[FlextLdifModels.Entry].fail("No entries parsed")
            return FlextResult[FlextLdifModels.Entry].ok(entries[0])

    def _normalize_attribute_name(self, attr_name: str) -> str:
        """Normalize attribute name to RFC 2849 canonical form.

        RFC 2849: Attribute names are case-insensitive.
        This method normalizes to canonical form for consistent matching.

        Key rule: objectclass (any case) → objectClass (canonical)
        All other attributes: preserved as-is (most are already lowercase)

        Args:
            attr_name: Attribute name from LDIF (any case)

        Returns:
            Canonical form of the attribute name

        """
        if not attr_name:
            return attr_name
        # Normalize objectclass variants to canonical objectClass
        if attr_name.lower() == "objectclass":
            return FlextLdifConstants.DictKeys.OBJECTCLASS
        # Other attributes: preserve as-is (cn, mail, uid, etc.)
        return attr_name


# =========================================================================


class _DescriptorProtocol(Protocol):
    """Protocol for descriptors that behave like their return type."""

    def __get__(
        self, obj: FlextLdifServersBase | None, _objtype: type | None = None
    ) -> str | int: ...


class _ServerTypeDescriptor:
    """Descriptor that returns SERVER_TYPE from Constants (single source of truth)."""

    def __init__(self, value: str) -> None:
        self.value = value

    def __get__(
        self, obj: FlextLdifServersBase | None, _objtype: type | None = None
    ) -> str:
        """Return the stored SERVER_TYPE value."""
        return self.value


class _PriorityDescriptor:
    """Descriptor that returns PRIORITY from Constants (single source of truth)."""

    def __init__(self, value: int) -> None:
        self.value = value

    def __get__(
        self, obj: FlextLdifServersBase | None, _objtype: type | None = None
    ) -> int:
        """Return the stored PRIORITY value."""
        return self.value


# Attach descriptors to FlextLdifServersBase for class and instance access
# Descriptors implement __get__ returning str/int, satisfying the type annotations above
FlextLdifServersBase.server_type = _ServerTypeDescriptor("unknown")
FlextLdifServersBase.priority = _PriorityDescriptor(0)

# Pydantic v2 automatically resolves forward references when classes are defined
# No manual model_rebuild() calls needed


__all__ = [
    "FlextLdifServersBase",
]
