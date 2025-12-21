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
    - FlextLdifServersBase.Schema -> object
    - FlextLdifServersBase.Acl -> object
    - FlextLdifServersBase.Entry -> object

    All method signatures must match protocol definitions exactly for type safety.
"""

from __future__ import annotations

from abc import ABC
from collections.abc import Callable, Sequence
from typing import (
    ClassVar,
    Self,
    overload,
)

from flext_core import FlextLogger, r, s, u
from pydantic import ConfigDict

from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif._utilities.server import FlextLdifUtilitiesServer
from flext_ldif.constants import c
from flext_ldif.results import FlextLdifModelsResults
from flext_ldif.servers._base import (
    FlextLdifServersBaseEntry,
    FlextLdifServersBaseSchema,
    FlextLdifServersBaseSchemaAcl,
)

# Removed: # Use FlextLdifUtilitiesServer directly to avoid circular import


def _get_server_type_from_utilities(
    quirk_class: type[FlextLdifServersBase | object],
) -> c.Ldif.LiteralTypes.ServerTypeLiteral:
    """Get server type from utilities using type-safe access pattern.

    Business Rule: Server type is determined by inspecting the class hierarchy
    and accessing FlextLdifUtilitiesServer.get_parent_server_type().
    This helper function encapsulates the type-safe access pattern to avoid
    repetition and ensure consistent error handling.

    Args:
        quirk_class: The quirk class to get server type for

    Returns:
        Server type literal (e.g., 'oid', 'oud', 'rfc')

    """
    # Business Rule: Access Server utility directly via FlextLdifUtilitiesServer
    # Implication: Direct access to avoid circular import with utilities.py
    return FlextLdifUtilitiesServer.get_parent_server_type(quirk_class)


logger = FlextLogger(__name__)

# NOTE: BaseServerConstants has been consolidated into FlextLdifServersRfc.Constants
# All server-specific Constants should inherit from FlextLdifServersRfc.Constants


class FlextLdifServersBase(s[FlextLdifModelsDomains.Entry], ABC):
    r"""Abstract base class for LDIF/LDAP server quirks as FlextService V2.

    Configuration:
        Allows arbitrary types and extra attributes for nested quirk classes.

    This class defines the complete contract for a server quirk implementation
    that satisfies `object` through structural typing.
    It uses the `ABC` helper class to define all methods as abstract,
    ensuring that any concrete subclass must implement the full interface.

    Note: This class satisfies object through
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
        >>> entries = processor.parse("...").map(filter_entries).value

    It also preserves the nested abstract base classes for `Schema`, `Acl`, and
    `Entry` quirks. These nested classes define the internal implementation
    contracts that concrete server classes use to structure their specialized logic.
    """

    model_config = ConfigDict(
        arbitrary_types_allowed=True,
        extra="allow",
    )

    # Class-level descriptor attributes (not Pydantic model fields)
    # These are Python descriptors assigned dynamically at class level via __init_subclass__
    # Type annotations: descriptors implement __get__ returning str/int when accessed
    # Use property annotations to indicate descriptor return types
    server_type: ClassVar[str]
    priority: ClassVar[int]

    # Instance attributes for nested quirks (initialized in __init__)
    # schema_quirk: Self.Schema  # Commented out to avoid forward reference issues
    # acl_quirk: Self.Acl  # Commented out to avoid forward reference issues
    # entry_quirk: Self.Entry  # Commented out to avoid forward reference issues

    def __init__(self, **kwargs: str | float | bool | None) -> None:
        """Initialize base quirk and its nested quirks.

        Args:
            **kwargs: Passed to parent s.__init__.

        """
        super().__init__(**kwargs)
        # Instantiate nested quirks, passing _parent_quirk directly
        # Type narrowing: self is FlextLdifServersBase instance
        parent_ref: FlextLdifServersBase = self
        # Business Rule: _parent_quirk must be set after instance creation using object.__setattr__
        # Implication: Cannot pass _parent_quirk to __new__ because it's not t.GeneralValueType
        # Create instances without _parent_quirk, then set it separately
        self._schema_quirk = self.Schema()
        object.__setattr__(self._schema_quirk, "_parent_quirk", parent_ref)
        self._acl_quirk = self.Acl()
        object.__setattr__(self._acl_quirk, "_parent_quirk", parent_ref)
        self._entry_quirk = self.Entry()
        object.__setattr__(self._entry_quirk, "_parent_quirk", parent_ref)

    @property
    def schema_quirk(self) -> object:
        """Access to nested schema quirk instance."""
        return self._schema_quirk

    @property
    def acl(self) -> object:
        """Access to nested acl quirk instance."""
        return self._acl_quirk

    @property
    def entry(self) -> object:
        """Access to nested entry quirk instance."""
        return self._entry_quirk

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
        # Use type.__setattr__ to set class-level descriptors (required to bypass
        # both Pydantic's __setattr__ and pyrefly's descriptor immutability checks)
        type.__setattr__(cls, "server_type", _ServerTypeDescriptor(server_type_value))
        type.__setattr__(cls, "priority", _PriorityDescriptor(priority_value))

    def get_schema_quirk(
        self,
    ) -> object:
        """Get schema quirk instance.

        Returns:
            Schema quirk instance

        """
        # Return via property which handles type conversion
        return self.schema_quirk

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
        entries: Sequence[FlextLdifModelsDomains.Entry] | None = None,
        _operation: str | None = None,
    ) -> r[FlextLdifModelsDomains.Entry]:
        r"""Execute quirk operation with auto-detection.

        Args:
            ldif_text: LDIF text to parse
            entries: List of entries to process
            _operation: Explicit operation type (optional, auto-detected if None)

        Returns:
            r[Entry]

        """
        if ldif_text is not None and isinstance(ldif_text, str):
            return self._execute_parse(ldif_text)

        if entries is not None and isinstance(entries, Sequence) and entries:
            first_entry = entries[0]
            if isinstance(first_entry, FlextLdifModelsDomains.Entry):
                return r[FlextLdifModelsDomains.Entry].ok(first_entry)
            return r[FlextLdifModelsDomains.Entry].fail(
                f"Invalid entry type: {type(first_entry).__name__}",
            )

        return r[FlextLdifModelsDomains.Entry].fail("No valid parameters")

    def _execute_parse(self, ldif_text: str) -> r[FlextLdifModelsDomains.Entry]:
        """Execute parse operation."""
        parse_result = self.parse(ldif_text)
        if not parse_result.is_success:
            return r[FlextLdifModelsDomains.Entry].fail(
                parse_result.error or "Parse failed",
            )
        parse_response = parse_result.value
        entries = getattr(parse_response, "entries", [])
        if not entries:
            return r[FlextLdifModelsDomains.Entry].fail("No entries parsed")
        # Get first entry - it's already a valid Entry model
        first_entry = entries[0]
        if isinstance(first_entry, FlextLdifModelsDomains.Entry):
            return r[FlextLdifModelsDomains.Entry].ok(first_entry)
        # Should never reach here, but handle just in case
        return r[FlextLdifModelsDomains.Entry].fail("Invalid entry type")

    @overload
    def __call__(
        self,
        ldif_text: str,
        *,
        entries: None = None,
        operation: str | None = None,
    ) -> FlextLdifModelsDomains.Entry | str: ...

    @overload
    def __call__(
        self,
        *,
        ldif_text: None = None,
        entries: list[FlextLdifModelsDomains.Entry],
        operation: str | None = None,
    ) -> str: ...

    @overload
    def __call__(
        self,
        ldif_text: str | None = None,
        entries: list[FlextLdifModelsDomains.Entry] | None = None,
        operation: str | None = None,
    ) -> FlextLdifModelsDomains.Entry | str: ...

    def __call__(
        self,
        ldif_text: str | None = None,
        entries: list[FlextLdifModelsDomains.Entry] | None = None,
        operation: str | None = None,
    ) -> FlextLdifModelsDomains.Entry | str:
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
        """Override __new__ to support auto-execute and processor instantiation.

        When auto_execute=True, automatically executes and returns unwrapped result.
        When auto_execute=False, returns instance for use as processor.

        Args:
            **kwargs: Initialization parameters (ldif_text, entries, operation)

        Returns:
            Service instance OR unwrapped domain result (cast to Self for type safety).

        """
        # Use object.__new__ directly to avoid s.__new__
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
            value = v
            if isinstance(value, (str, float, bool, type(None))):
                filtered_kwargs[k] = value
            # For execute params, allow str, int, bool, None, or list[str]
            if isinstance(value, (str, int, bool, type(None))):
                execute_kwargs[k] = value
            elif isinstance(value, list):
                # For execute params, allow list[str] but not nested dicts
                # Type narrowing: ensure list contains only strings
                execute_kwargs[k] = value
        type(instance).__init__(instance, **filtered_kwargs)

        if cls.auto_execute:
            # Extract and execute with type-safe params
            ldif_text, entries, operation = cls._extract_execute_params(execute_kwargs)
            result = instance.execute(
                ldif_text=ldif_text,
                entries=entries,
                _operation=operation,
            )
            unwrapped: FlextLdifModelsDomains.Entry | str = result.value
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
        msg = f"Expected Optional[str] for ldif_text, got {type(raw)}"
        raise TypeError(msg)

    @staticmethod
    def _extract_entries(
        kwargs: object,
    ) -> list[FlextLdifModelsDomains.Entry] | None:
        """Extract and validate entries parameter."""
        if not isinstance(kwargs, dict) or "entries" not in kwargs:
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
        entries: list[FlextLdifModelsDomains.Entry] = []
        for idx in range(len(raw)):
            item: FlextLdifModelsDomains.Entry | str = raw[idx]
            if isinstance(item, FlextLdifModelsDomains.Entry):
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
        list[FlextLdifModelsDomains.Entry] | None,
        str | None,
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
    def schema_quirk(self) -> object:
        """Get the Schema quirk instance."""
        # Type narrowing: _schema_quirk implements SchemaProtocol structurally
        # The concrete Schema class implements all protocol methods
        # Structural typing ensures protocol compliance at runtime
        schema_instance = self._schema_quirk
        # Verify protocol compliance via structural typing
        if not hasattr(schema_instance, "parse") or not hasattr(
            schema_instance,
            "write",
        ):
            msg = "Schema instance does not implement SchemaProtocol"
            raise TypeError(msg)
        # Type assertion: Schema class implements SchemaProtocol structurally
        # All required methods are present, so this is safe
        # Return as protocol type - structural typing ensures compatibility
        # Protocol compliance verified at runtime via hasattr checks above
        # Type assertion: Schema implements SchemaProtocol structurally
        # Business Rule: Validate Schema instance satisfies SchemaProtocol structurally
        # SchemaProtocol requires parse() and write() methods per protocol definition
        # Use structural checks only (hasattr) to avoid pyright Protocol overlap warnings
        # Runtime behavior: Structural typing ensures correct implementation
        required_methods = ("parse", "write")
        if not all(
            hasattr(schema_instance, method)
            and callable(getattr(schema_instance, method))
            for method in required_methods
        ):
            msg = "Schema instance does not satisfy SchemaProtocol - missing required methods"
            raise TypeError(msg)
        # Return after structural validation - satisfies pyright without Protocol overlap warnings

        return schema_instance

    @property
    def acl_quirk(self) -> object:
        """Get the Acl quirk instance."""
        # Type narrowing: _acl_quirk implements AclProtocol structurally
        # Acl class implements AclProtocol structurally (all methods match)
        # Mypy doesn't recognize structural typing, so we return directly
        return self._acl_quirk

    @property
    def entry_quirk(self) -> object:
        """Get the Entry quirk instance."""
        # Type narrowing: _entry_quirk implements p.Ldif.Entry.EntryProtocol structurally
        return self._entry_quirk

    # =========================================================================
    # Core Quirk Methods - Parsing and Writing (Primary Interface)
    # =========================================================================

    def parse(
        self,
        ldif_text: str,
    ) -> r[FlextLdifModelsResults.ParseResponse]:
        """Parse LDIF text to Entry models.

        Routes to Entry quirk for server-specific parsing logic.

        **V2 Usage:**
            >>> quirk = FlextLdifServersRfc()
            >>> entries = quirk.parse(ldif_text).result
            >>> entries = quirk.parse(ldif_text).map(filter_fn).value

        Args:
            ldif_text: LDIF content string

        Returns:
            r[ParseResponse]

        """
        # Instantiate Entry nested class for parsing
        entry_class = getattr(type(self), "Entry", None)
        if not entry_class:
            return r[str].fail("Entry nested class not available")
        entry_quirk = entry_class()
        entries_result: r[list[FlextLdifModelsDomains.Entry]] = entry_quirk.parse(
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
        # Convert entries for ParseResponse - use model_copy() for safety
        domain_entries: Sequence[FlextLdifModelsDomains.Entry] = [
            entry
            if isinstance(entry, FlextLdifModelsDomains.Entry)
            else entry.model_copy(deep=True)
            for entry in entries
        ]
        parse_response = FlextLdifModelsResults.ParseResponse(
            entries=list(domain_entries),
            statistics=statistics,
            detected_server_type=detected_server,
        )
        return r[FlextLdifModelsResults.ParseResponse].ok(parse_response)

    def write(self, entries: list[FlextLdifModelsDomains.Entry]) -> r[str]:
        """Write Entry models to LDIF text.

        Routes to Entry quirk for server-specific writing logic.

        **V2 Usage:**
            >>> quirk = FlextLdifServersRfc()
            >>> ldif_text = quirk.write(entries).result
            >>> ldif_text = quirk.write(entries).map(str.upper).value

        Args:
            entries: List of Entry models

        Returns:
            r[str]

        """
        # Get entry quirk with validation
        entry_quirk = getattr(self, "entry_quirk", None)
        if not entry_quirk:
            return r[str].fail("Entry quirk not available")

        # Use functional composition to write all entries
        def write_single_entry(entry_model: FlextLdifModelsDomains.Entry) -> r[str]:
            """Write single entry using entry quirk."""
            if entry_quirk is not None:
                # Cast to r[str] - entry_quirk.write returns r[str]
                result: r[str] = entry_quirk.write(entry_model)
                return result
            return r[str].fail("No entry quirk found")

        # Process all entries with early return on first failure
        ldif_lines: list[str] = []
        for entry_model in entries:
            result = write_single_entry(entry_model)
            if result.is_failure:
                return r[str].fail(f"Failed to write entry: {result.error}")
            ldif_lines.append(result.value)

        # Finalize LDIF with proper formatting
        ldif = "\n".join(ldif_lines)
        if ldif and not ldif.endswith("\n"):
            ldif += "\n"

        return r[str].ok(ldif)

    def _route_model_to_write(
        self,
        model: object,
    ) -> r[str]:
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
        if isinstance(model, FlextLdifModelsDomains.Entry):
            # Cast to p.Ldif.Entry.EntryProtocol after isinstance check for type narrowing
            # Mypy needs explicit narrowing for complex union types
            entry_protocol: object = model
            return self.entry.write(entry_protocol)
        if isinstance(model, FlextLdifModelsDomains.SchemaAttribute):
            # Use _schema_quirk directly to access write_attribute method
            # which is not in the protocol but exists on the concrete Schema class
            return self._schema_quirk.write_attribute(model)
        if isinstance(model, FlextLdifModelsDomains.SchemaObjectClass):
            # Use _schema_quirk directly to access write_objectclass method
            # which is not in the protocol but exists on the concrete Schema class
            return self._schema_quirk.write_objectclass(model)
        if isinstance(model, FlextLdifModelsDomains.Acl):
            # Cast to AclProtocol after isinstance check for type narrowing
            # Mypy needs explicit narrowing for complex union types
            acl_protocol: object = model
            return self.acl.write(acl_protocol)

        return r[str].fail(f"Unknown model type: {type(model).__name__}")

    def _handle_parse_operation(
        self,
        ldif_text: str,
    ) -> r[FlextLdifModelsDomains.Entry | str]:
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
            parse_response = parse_result.value
            entries = getattr(parse_response, "entries", [])
            # ParseResponse.entries is always Sequence[Entry] (never a single Entry)
            if u.Guards.is_list_non_empty(entries):
                domain_entry = entries[0]
                # Convert domain Entry to public Entry type for type compatibility
                # FlextLdifModelsDomains.Entry extends FlextLdifModelsDomains.Entry
                if isinstance(domain_entry, FlextLdifModelsDomains.Entry):
                    # Already public type
                    return r[FlextLdifModelsDomains.Entry | str].ok(domain_entry)
                # Convert domain entry to public entry using model_validate
                public_entry = FlextLdifModelsDomains.Entry.model_validate(
                    domain_entry.model_dump(mode="python"),
                )
                return r[FlextLdifModelsDomains.Entry | str].ok(public_entry)
            return r[FlextLdifModelsDomains.Entry | str].ok("")
        error_msg: str = parse_result.error or "Parse failed"
        return r[FlextLdifModelsDomains.Entry | str].fail(error_msg)

    def _handle_write_operation(
        self,
        entries: list[FlextLdifModelsDomains.Entry],
    ) -> r[FlextLdifModelsDomains.Entry | str]:
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
            written_text: str = write_result.value
            return r[FlextLdifModelsDomains.Entry | str].ok(written_text)
        error_msg: str = write_result.error or "Write failed"
        return r[FlextLdifModelsDomains.Entry | str].fail(error_msg)

    # =========================================================================
    # Registry method for DI-based automatic registration
    # =========================================================================
    # NOTE: server_type and priority are ClassVar in the PARENT SERVER CLASS ONLY
    # NOT in nested Schema/Acl/Entry classes
    # (e.g., FlextLdifServersOid.server_type, FlextLdifServersOid.priority)
    # All constants must be in FlextLdifServers[Server].Constants, NOT in subclasses

    @classmethod
    def _get_server_type_from_mro(
        cls,
        quirk_class: type[object],
    ) -> str:
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
                return FlextLdifUtilitiesServer.normalize_server_type(server_type)
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
        quirk_instance: (object | FlextLdifServersBase),
        registry: object,
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
            """Validate registry has register method.

            Business Rule: Validates that registry object has register_quirk method
            and returns it with proper type annotation. Returns None if method doesn't exist
            or is not callable, following fail-fast validation pattern.
            """
            method = getattr(registry_obj, "register_quirk", None)
            if method and callable(method):
                # method is already the correct callable type
                return method
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
            # Business Rule: Validate instance satisfies SchemaProtocol structurally
            # Use structural checks only to avoid pyright Protocol overlap warnings
            # Runtime behavior: Structural typing ensures correct implementation
            if register_func is not None:
                # Check if instance has required SchemaProtocol methods
                required_methods = ("parse", "write")
                if all(
                    hasattr(instance, method) and callable(getattr(instance, method))
                    for method in required_methods
                ):
                    # instance is already validated to support schema_quirk interface
                    schema_quirk = instance
                    register_func("auto", schema_quirk)
                # If not SchemaProtocol, skip registration (schema_quirk would be None)

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
    class Acl(FlextLdifServersBaseSchemaAcl):
        """Nested Acl quirk base class."""

    class Entry(FlextLdifServersBaseEntry):
        """Nested Entry quirk base class."""

    class Schema(FlextLdifServersBaseSchema):
        """Nested Schema quirk base class."""

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
            return "objectClass"
        # Other attributes: preserve as-is (cn, mail, uid, etc.)
        return attr_name


# =========================================================================


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


# Business Rule: Descriptors are attached to FlextLdifServersBase class for
# class and instance access. Descriptors implement __get__ returning str/int,
# satisfying the type annotations above. This is a class-level assignment that
# happens at module import time, not instance creation time.
# Use setattr to set class-level descriptors on Pydantic models
# Note: setattr works here because we're setting on the class, not an instance
FlextLdifServersBase.server_type = _ServerTypeDescriptor("unknown")
FlextLdifServersBase.priority = _PriorityDescriptor(0)

# Pydantic v2 automatically resolves forward references when classes are defined
# No manual model_rebuild() calls needed


__all__ = [
    "FlextLdifServersBase",
]
