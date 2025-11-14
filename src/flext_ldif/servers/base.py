"""Base Quirk Classes for LDIF/LDAP Server Extensions.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Defines base classes for implementing server-specific quirks that extend
RFC-compliant LDIF/LDAP parsing with vendor-specific features.

Quirks allow extending the RFC base without modifying core parser logic.

ARCHITECTURE:
    Base classes use Python 3.13+ abstract base classes (ABC) with    decorators for explicit inheritance contracts, while also implementing all
    methods required by FlextLdifProtocols for structural typing validation.

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

from abc import ABC
from collections.abc import Mapping
from typing import TYPE_CHECKING, ClassVar, Literal, Protocol, Self, cast, overload

from flext_core import FlextLogger, FlextResult, FlextService
from pydantic import ConfigDict, Field

from flext_ldif.models import FlextLdifModels
from flext_ldif.typings import FlextLdifTypes

if TYPE_CHECKING:
    from flext_ldif.servers.rfc import FlextLdifServersRfc

logger = FlextLogger(__name__)


# NOTE: BaseServerConstants has been consolidated into FlextLdifServersRfc.Constants
# All server-specific Constants should inherit from FlextLdifServersRfc.Constants


class FlextLdifServersBase(FlextService[FlextLdifModels.Entry | str], ABC):
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
    server_type: ClassVar[str | _DescriptorProtocol]
    priority: ClassVar[int | _DescriptorProtocol]

    # Instance attributes for nested quirks (initialized in __init__)
    # schema_quirk: Self.Schema  # Commented out to avoid forward reference issues
    # acl_quirk: Self.Acl  # Commented out to avoid forward reference issues
    # entry_quirk: Self.Entry  # Commented out to avoid forward reference issues

    def __init__(self, **kwargs: object) -> None:
        """Initialize base quirk and its nested quirks.

        Args:
            **kwargs: Passed to parent FlextService.__init__.

        """
        super().__init__(**kwargs)
        # Instantiate nested quirks, passing self as parent_quirk
        # Use private attributes as properties are read-only
        self._schema_quirk = self.Schema(parent_quirk=self)
        self._acl_quirk = self.Acl(parent_quirk=self)
        self._entry_quirk = self.Entry(parent_quirk=self)

    def __init_subclass__(cls, **kwargs: object) -> None:
        """Initialize subclass with server_type and priority from Constants.

        Single source of truth: SERVER_TYPE and PRIORITY must be defined in
        the nested Constants class. No fallbacks, no dual patterns.

        This ensures:
        - FlextLdifServersOid.server_type comes from FlextLdifServersOid.Constants.SERVER_TYPE
        - Descriptors expose them at instance level via _ServerTypeDescriptor

        Args:
            **kwargs: Passed to parent __init_subclass__

        Raises:
            AttributeError: If Constants class is missing or lacks required attributes

        """
        super().__init_subclass__(**kwargs)

        # Require Constants class with SERVER_TYPE and PRIORITY
        if not hasattr(cls, "Constants"):
            msg = f"{cls.__name__} must define a Constants nested class"
            raise AttributeError(msg)

        # Get Constants - type: ignore needed for __init_subclass__ metaclass hook
        # Pyright can't know subclass attributes, but hasattr validates at runtime
        constants_class = cls.Constants  # type: ignore[attr-defined]

        # Validate required attributes exist
        if not hasattr(constants_class, "SERVER_TYPE"):
            msg = f"{cls.__name__}.Constants must define SERVER_TYPE"
            raise AttributeError(msg)
        if not hasattr(constants_class, "PRIORITY"):
            msg = f"{cls.__name__}.Constants must define PRIORITY"
            raise AttributeError(msg)

        # Set descriptors for server_type and priority
        cls.server_type = _ServerTypeDescriptor(constants_class.SERVER_TYPE)
        cls.priority = _PriorityDescriptor(constants_class.PRIORITY)

    # @overload # type: ignore[misc]
    # def schema(self, server_type: Literal["oid"]) -> FlextLdifServersOid.Schema: ...

    @overload
    def schema(self, server_type: Literal["rfc"]) -> FlextLdifServersRfc.Schema: ...

    @overload
    def schema(self) -> Self.Schema: ...  # Access via self.schema_quirk

    def schema(
        self, server_type: str | None = None
    ) -> Self.Schema | FlextLdifServersBase.Schema | None:
        """Get schema quirk for a server type, or self.schema_quirk."""
        if server_type:
            from flext_ldif.services.server import FlextLdifServer  # noqa: PLC0415

            return FlextLdifServer.get_global_instance().schema(server_type)
        return self.schema_quirk

    # @overload # type: ignore[misc]
    # def acl(self, server_type: Literal["oid"]) -> FlextLdifServersOid.Acl: ...

    @overload
    def acl(self, server_type: Literal["rfc"]) -> FlextLdifServersRfc.Acl: ...

    @overload
    def acl(self) -> Self.Acl: ...  # Access via self.acl_quirk

    def acl(
        self, server_type: str | None = None
    ) -> Self.Acl | FlextLdifServersBase.Acl | None:
        """Get ACL quirk for a server type, or self.acl_quirk."""
        if server_type:
            from flext_ldif.services.server import FlextLdifServer  # noqa: PLC0415

            return FlextLdifServer.get_global_instance().acl(server_type)
        return self.acl_quirk

    # @overload # type: ignore[misc]
    # def entry(self, server_type: Literal["oid"]) -> FlextLdifServersOid.Entry: ...

    @overload
    def entry(self, server_type: Literal["rfc"]) -> FlextLdifServersRfc.Entry: ...

    @overload
    def entry(self) -> Self.Entry: ...  # Access via self.entry_quirk

    def entry(
        self, server_type: str | None = None
    ) -> Self.Entry | FlextLdifServersBase.Entry | None:
        """Get entry quirk for a server type, or self.entry_quirk."""
        if server_type:
            from flext_ldif.services.server import FlextLdifServer  # noqa: PLC0415

            return FlextLdifServer.get_global_instance().entry(server_type)
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
        ldif_text: str | None = None,
        entries: list[FlextLdifModels.Entry] | None = None,
        operation: Literal["parse", "write"] | None = None,
    ) -> FlextResult[FlextLdifModels.Entry | str]:
        r"""Execute quirk operation with auto-detection and V2 modes.

        Auto-detects operation from parameters:
        - ldif_text: parse operation
        - entries: write operation
        - No params -> health check
        - operation parameter for V2 DI

        **V2 Auto-execute Mode:**
            >>> class AutoQuirk(FlextLdifServersRfc):
            ...     auto_execute = True
            >>> entries = AutoQuirk(ldif_text="dn: cn=test\n")

        **V2 Property Mode:**
            >>> quirk = FlextLdifServersRfc()
            >>> entries = quirk.execute(ldif_text="...").result

        **V2 Monadic Composition:**
            >>> result = quirk.parse("...").map(filter_fn).unwrap()

        **V2 Builder Pattern:**
            >>> entries = quirk.parse("...").result
            >>> ldif = quirk.write(entries).result

        Args:
            ldif_text: LDIF text to parse
            entries: Entry models to write
            operation: Explicit operation type (auto-detected if not provided)

        Returns:
            FlextResult[list[Entry] | str]

        """
        # Use explicit operation if provided, otherwise auto-detect
        detected_operation = self._detect_operation(ldif_text, entries, operation)

        # Health check: no parameters provided and no explicit operation
        if detected_operation is None and not ldif_text and not entries:
            return self._execute_health_check()

        # Execute based on operation
        if detected_operation == "parse":
            return self._execute_parse(ldif_text)
        if detected_operation == "write":
            return self._execute_write(entries)

        # Should not reach here
        return FlextResult[FlextLdifModels.Entry | str].fail(
            "No operation parameters provided",
        )

    def _execute_health_check(self) -> FlextResult[FlextLdifModels.Entry | str]:
        """Execute health check operation."""
        # Health check returns empty string to indicate successful health check
        # This matches the expected return type of Entry | str
        return FlextResult[FlextLdifModels.Entry | str].ok("")

    def _detect_operation(
        self,
        ldif_text: str | None,
        entries: list[FlextLdifModels.Entry] | None,
        operation: Literal["parse", "write"] | None,
    ) -> Literal["parse", "write"] | None:
        """Detect operation type from parameters."""
        if operation is not None:
            return operation
        if ldif_text is not None:
            return "parse"
        if entries is not None:
            return "write"
        return None

    def _execute_parse(
        self, ldif_text: str | None
    ) -> FlextResult[FlextLdifModels.Entry | str]:
        """Execute parse operation."""
        if ldif_text is None:
            return FlextResult[FlextLdifModels.Entry | str].fail(
                "parse operation requires ldif_text",
            )
        # Delegate to concrete implementation (default in RFC)
        parse_result = self.parse(ldif_text)
        if parse_result.is_success:
            parse_response = parse_result.unwrap()
            # Return first entry if available, otherwise empty string
            if parse_response.entries:
                return FlextResult[FlextLdifModels.Entry | str].ok(
                    cast("FlextLdifModels.Entry", parse_response.entries[0])
                )
            return FlextResult[FlextLdifModels.Entry | str].ok("")
        error_msg: str = parse_result.error or "Parse failed"
        return FlextResult[FlextLdifModels.Entry | str].fail(error_msg)

    def _execute_write(
        self, entries: list[FlextLdifModels.Entry] | None
    ) -> FlextResult[FlextLdifModels.Entry | str]:
        """Execute write operation."""
        if entries is None:
            return FlextResult[FlextLdifModels.Entry | str].fail(
                "write operation requires entries",
            )
        # Delegate to concrete implementation (default in RFC)
        write_result = self.write(entries)
        if write_result.is_success:
            written_text: str = write_result.unwrap()
            return FlextResult[FlextLdifModels.Entry | str].ok(written_text)
        error_msg: str = write_result.error or "Write failed"
        return FlextResult[FlextLdifModels.Entry | str].fail(error_msg)

    @overload
    def __call__(
        self,
        ldif_text: str,
        *,
        entries: None = None,
        operation: Literal["parse"] | None = None,
    ) -> FlextLdifTypes.EntryOrString: ...

    @overload
    def __call__(
        self,
        *,
        ldif_text: None = None,
        entries: list[FlextLdifModels.Entry],
        operation: Literal["write"] | None = None,
    ) -> str: ...

    @overload
    def __call__(
        self,
        ldif_text: str | None = None,
        entries: list[FlextLdifModels.Entry] | None = None,
        operation: Literal["parse", "write"] | None = None,
    ) -> FlextLdifTypes.EntryOrString: ...

    def __call__(
        self,
        ldif_text: str | None = None,
        entries: list[FlextLdifModels.Entry] | None = None,
        operation: Literal["parse", "write"] | None = None,
    ) -> FlextLdifTypes.EntryOrString:
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

    def __new__(cls, **kwargs: object) -> Self:
        """Override __new__ to support auto-execute and processor instantiation.

        When auto_execute=True, automatically executes and returns unwrapped result.
        When auto_execute=False, returns instance for use as processor.

        Args:
            **kwargs: Initialization parameters (ldif_text, entries, operation)

        Returns:
            Service instance OR unwrapped domain result (cast to Self for type safety).

        Note:
            When auto_execute=True, the actual runtime value is list[Entry] | str,
            but it's cast to Self for type checker. Callers should
            type-annotate with the domain result type for auto_execute services.

        """
        instance = super().__new__(cls)
        type(instance).__init__(instance, **kwargs)

        if cls.auto_execute:
            # Extract operation parameters from kwargs
            # Note: kwargs values are dynamically typed as object,
            # type narrowing via isinstance checks
            ldif_text = (
                cast("str | None", kwargs.get("ldif_text"))
                if "ldif_text" in kwargs
                else None
            )
            entries = (
                cast("list[FlextLdifModels.Entry] | None", kwargs.get("entries"))
                if "entries" in kwargs
                else None
            )
            operation = (
                cast("Literal['parse', 'write'] | None", kwargs.get("operation"))
                if "operation" in kwargs
                else None
            )
            # Auto-execute and return unwrapped result (cast for type safety)
            result = instance.execute(
                ldif_text=ldif_text,
                entries=entries,
                operation=operation,
            )
            unwrapped: FlextLdifTypes.EntryOrString = result.unwrap()
            return cast("Self", unwrapped)

        return instance

    def _initialize_nested_classes(self) -> None:
        """Initialize nested Schema, Acl, and Entry classes with server_type.

        Protected template method called during server initialization to set up
        nested quirks classes with access to parent's server_type.

        This method:
        - Passes server_type to nested classes so they don't need _get_server_type()
        - Uses object.__setattr__ to bypass Pydantic validation
        - Sets schema, acl, and entry nested class instances

        Called by:
        - FlextLdifServersBase.__init__ after Constants are set
        - All child servers via super().__init__()

        Example:
            class CustomServer(FlextLdifServersRfc):
                def __init__(self) -> None:
                    super().__init__()
                    # Nested classes initialized with server_type automatically
                    self._initialize_nested_classes()  # sets schema, acl, entry

        """
        # Initialize nested class instances with private names to avoid
        # Pydantic conflicts. Concrete implementations in subclasses.
        self._schema_quirk = self.Schema()
        self._acl_quirk = self.Acl()
        self._entry_quirk = self.Entry()

        # Use schema_quirk, acl_quirk, entry_quirk properties
        # Old: object.__setattr__(self, "schema", self._schema_quirk) - removed per zero-tolerance policy

    # =========================================================================
    # Properties for accessing nested quirks (bypasses Pydantic's schema() method)
    # =========================================================================

    @property
    def schema_quirk(self) -> FlextLdifServersBase.Schema:
        """Get the Schema quirk instance."""
        return self._schema_quirk

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
        parse_response = FlextLdifModels.ParseResponse(
            entries=entries,
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
                return entry_quirk.write(entry_model)
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

    # =========================================================================
    # Registry method for DI-based automatic registration
    # =========================================================================
    # NOTE: server_type and priority are ClassVar in the PARENT SERVER CLASS ONLY
    # NOT in nested Schema/Acl/Entry classes
    # (e.g., FlextLdifServersOid.server_type, FlextLdifServersOid.priority)
    # All constants must be in FlextLdifServers[Server].Constants, NOT in subclasses

    @classmethod
    def _get_server_type_from_mro(cls, quirk_class: type[object]) -> str:
        """Get server_type from parent class Constants via MRO traversal using functional patterns."""

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
            if server_type:
                return server_type
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
        """Get priority from parent class Constants via MRO traversal using functional patterns."""

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
        quirk_instance: object,
        registry: object,
    ) -> None:
        """Helper method to register a quirk instance in the registry using functional validation.

        This method can be used by subclasses or registry to automatically register
        quirks. The base class itself does NOT register automatically - this is
        just a helper for registration logic.

        Args:
            quirk_instance: Instance of any quirk (Schema, Acl, Entry, base)
            registry: Registry instance to register the quirk (has register)

        """

        # Functional composition: validate + register
        def validate_registry(registry_obj: object) -> object | None:
            """Validate registry has register method."""
            return getattr(registry_obj, "register", None)

        def perform_registration(register_func: object, instance: object) -> None:
            """Execute registration if method is available."""
            if register_func and callable(register_func):
                register_func(instance)

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
            FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str
        ]
    ):
        """Base class for schema quirks - FlextService V2 with enhanced usability.

        NOTE: This is an implementation detail - DO NOT import directly.
        Use FlextLdifServersBase.Schema instead.

        Schema quirks extend RFC 4512 schema parsing with server-specific features
        for attribute and objectClass processing.

        **FlextService V2 Integration:**
        - Inherits from FlextService for dependency injection, logging, and validation
        - Uses V2 patterns: .result property for direct access, .execute() for FlextResult
        - Auto-registration in DI container via FlextService
        - Type-safe with TDomainResult = SchemaAttribute | SchemaObjectClass

        **V2 Usage Patterns:**
            >>> schema = FlextLdifServersRfc.Schema()
            >>> # Parse attribute with direct access
            >>> attr = schema.parse_attribute(attr_def).result
            >>> # Or use execute() for FlextResult composition
            >>> result = schema.parse_attribute(attr_def)
            >>> if result.is_success:
            ...     attr = result.unwrap()

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
        parent_quirk: object | None = Field(
            default=None,
            exclude=True,
            repr=False,
            description="Reference to parent FlextLdifServersBase instance for server-level access",
        )

        def __init__(
            self,
            schema_service: object | None = None,
            **kwargs: object,
        ) -> None:
            """Initialize schema quirk service with optional DI service injection.

            Args:
                schema_service: Injected FlextLdifSchema service (optional, lazy-created if None)
                **kwargs: Passed to FlextService for initialization (includes parent_quirk)

            Note:
                server_type and priority are no longer passed to nested classes.
                They should be accessed via _get_server_type() and Constants.PRIORITY
                from the parent server class.

            """
            super().__init__(**kwargs)
            self._schema_service = schema_service  # Store for use by subclasses

        # =====================================================================
        # HOOKS for Customization - Override in subclasses to customize behavior
        # =====================================================================

        def _get_server_type(self) -> str:
            """Get server_type from parent server class via __qualname__.

            For nested classes like FlextLdifServersAd.Schema, extracts parent
            class name from __qualname__ and gets SERVER_TYPE from parent.Constants.

            Returns:
                Server type from parent Constants.SERVER_TYPE

            Raises:
                AttributeError: If parent server class or SERVER_TYPE not found

            """
            cls = type(self)

            # For nested classes, extract parent server class from __qualname__
            # Example: "FlextLdifServersAd.Schema" -> "FlextLdifServersAd"
            if hasattr(cls, "__qualname__") and "." in cls.__qualname__:
                parent_class_name = cls.__qualname__.split(".")[0]
                try:
                    # Import parent class from module
                    parent_module = __import__(
                        cls.__module__, fromlist=[parent_class_name]
                    )
                    if hasattr(parent_module, parent_class_name):
                        parent_server_cls = getattr(parent_module, parent_class_name)
                        # Get SERVER_TYPE from parent.Constants
                        if hasattr(parent_server_cls, "Constants") and hasattr(
                            parent_server_cls.Constants, "SERVER_TYPE"
                        ):
                            return cast("str", parent_server_cls.Constants.SERVER_TYPE)
                except (ImportError, AttributeError):
                    pass

            # No parent found - error
            msg = f"{cls.__name__} nested class must have parent with Constants.SERVER_TYPE"
            raise AttributeError(msg)

        # Control auto-execution
        auto_execute: ClassVar[bool] = False

        # =====================================================================
        # Automatic Routing Methods - Moved to rfc.py.Schema
        # =====================================================================
        # Concrete implementations of routing methods are now in FlextLdifServersRfc.Schema
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
                FlextResult[SchemaAttribute] - modified or original attribute

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
                FlextResult[SchemaObjectClass] - modified or original objectClass

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
                "Must be implemented by subclass"
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
        ) -> FlextResult[None]:
            """Hook for server-specific attribute validation during schema extraction.

            Subclasses can override this to perform validation of attribute dependencies
            before objectClass extraction. This is called only when validate_dependencies=True.

            Default implementation: No validation (pass-through).

            Args:
                attributes: List of parsed SchemaAttribute models
                available_attrs: Set of lowercase attribute names available

            Returns:
                FlextResult[None] - Success or failure with validation error

            Example Override (in OUD):
                def _hook_validate_attributes(self, attributes, available_attrs):
                    # OUD-specific validation logic
                    for attr in attributes:
                        if attr.requires_dependency not in available_attrs:
                            return FlextResult.fail("Missing dependency")
                    return FlextResult.ok(None)

            """
            # Default: No validation needed
            _ = attributes
            _ = available_attrs
            return FlextResult[None].ok(None)

        # =====================================================================
        # Concrete Template Methods - Moved to rfc.py.Schema
        # =====================================================================
        # extract_schemas_from_ldif is now a concrete implementation in FlextLdifServersRfc.Schema

        # REMOVED: should_filter_out_attribute - Roteamento interno, não deve ser abstrato

        # REMOVED: should_filter_out_objectclass - Roteamento interno, não deve ser abstrato

    class Acl(FlextService[FlextLdifModels.Acl | str]):
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

        # Parent quirk reference for accessing server-level configuration
        parent_quirk: object | None = Field(
            default=None,
            exclude=True,
            repr=False,
            description="Reference to parent FlextLdifServersBase instance for server-level access",
        )

        def __init__(self, acl_service: object | None = None, **kwargs: object) -> None:
            """Initialize ACL quirk service with optional DI service injection.

            Args:
                acl_service: Injected FlextLdifAcl service (optional, lazy-created if None)
                **kwargs: Passed to FlextService for initialization (includes parent_quirk)

            Note:
                server_type and priority are no longer passed to nested classes.
                They should be accessed via _get_server_type() and Constants.PRIORITY
                from the parent server class.

            """
            super().__init__(**kwargs)
            self._acl_service = acl_service  # Store for use by subclasses

        def _get_server_type(self) -> str:
            """Get server_type from parent server class via __qualname__.

            For nested classes like FlextLdifServersAd.Schema, extracts parent
            class name from __qualname__ and gets SERVER_TYPE from parent.Constants.

            Returns:
                Server type from parent Constants.SERVER_TYPE

            Raises:
                AttributeError: If parent server class or SERVER_TYPE not found

            """
            cls = type(self)

            # For nested classes, extract parent server class from __qualname__
            # Example: "FlextLdifServersAd.Schema" -> "FlextLdifServersAd"
            if hasattr(cls, "__qualname__") and "." in cls.__qualname__:
                parent_class_name = cls.__qualname__.split(".")[0]
                try:
                    # Import parent class from module
                    parent_module = __import__(
                        cls.__module__, fromlist=[parent_class_name]
                    )
                    if hasattr(parent_module, parent_class_name):
                        parent_server_cls = getattr(parent_module, parent_class_name)
                        # Get SERVER_TYPE from parent.Constants
                        if hasattr(parent_server_cls, "Constants") and hasattr(
                            parent_server_cls.Constants, "SERVER_TYPE"
                        ):
                            return cast("str", parent_server_cls.Constants.SERVER_TYPE)
                except (ImportError, AttributeError):
                    pass

            # No parent found - error
            msg = f"{cls.__name__} nested class must have parent with Constants.SERVER_TYPE"
            raise AttributeError(msg)

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
            all_attrs = self.get_acl_attributes()
            return attribute_name.lower() in [a.lower() for a in all_attrs]

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

        # =====================================================================
        # Public Interface Methods - Moved to rfc.py.Acl
        # =====================================================================
        # parse, can_handle, write are now concrete implementations in
        # FlextLdifServersRfc.Acl. Subclasses should override _parse_acl,
        # _write_acl, and can_handle_acl for server-specific logic.

        def _parse_acl(self, acl_line: str) -> FlextResult[FlextLdifModels.Acl]:
            r"""🔴 REQUIRED: Parse server-specific ACL definition (internal).

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

            Args:
                acl_data: Acl model

            Returns:
                FlextResult with RFC-compliant ACL string

            """
            _ = acl_data  # Explicitly mark as intentionally unused in base
            return FlextResult.fail("Must be implemented by subclass")

    class Entry(FlextService[FlextLdifModels.Entry | str]):
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

        **FlextService V2 Integration:**
        - Inherits from FlextService for dependency injection, logging, and validation
        - Uses V2 patterns: .result property for direct access, .execute() for FlextResult
        - Auto-registration in DI container via FlextService
        - Type-safe with TDomainResult = Entry
        """

        # Registry method for DI-based automatic registration
        # NOTE: server_type and priority are ClassVar in the PARENT SERVER CLASS ONLY
        # NOT in nested Schema/Acl/Entry classes
        # (e.g., FlextLdifServersOid.server_type, FlextLdifServersOid.priority)
        # All constants must be in FlextLdifServers[Server].Constants, NOT in subclasses

        # Parent quirk reference for accessing server-level configuration
        parent_quirk: object | None = Field(
            default=None,
            exclude=True,
            repr=False,
            description="Reference to parent FlextLdifServersBase instance for server-level access",
        )

        def __init__(
            self,
            entry_service: object | None = None,
            **kwargs: object,
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

        def _get_server_type(self) -> str:
            """Get server_type from parent server class via __qualname__.

            For nested classes like FlextLdifServersAd.Schema, extracts parent
            class name from __qualname__ and gets SERVER_TYPE from parent.Constants.

            Returns:
                Server type from parent Constants.SERVER_TYPE

            Raises:
                AttributeError: If parent server class or SERVER_TYPE not found

            """
            cls = type(self)

            # For nested classes, extract parent server class from __qualname__
            # Example: "FlextLdifServersAd.Schema" -> "FlextLdifServersAd"
            if hasattr(cls, "__qualname__") and "." in cls.__qualname__:
                parent_class_name = cls.__qualname__.split(".")[0]
                try:
                    # Import parent class from module
                    parent_module = __import__(
                        cls.__module__, fromlist=[parent_class_name]
                    )
                    if hasattr(parent_module, parent_class_name):
                        parent_server_cls = getattr(parent_module, parent_class_name)
                        # Get SERVER_TYPE from parent.Constants
                        if hasattr(parent_server_cls, "Constants") and hasattr(
                            parent_server_cls.Constants, "SERVER_TYPE"
                        ):
                            return cast("str", parent_server_cls.Constants.SERVER_TYPE)
                except (ImportError, AttributeError):
                    pass

            # No parent found - error
            msg = f"{cls.__name__} nested class must have parent with Constants.SERVER_TYPE"
            raise AttributeError(msg)

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
            attrs: dict[str, object],
        ) -> FlextResult[None]:
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
                FlextResult[None] - fail() if validation fails

            """
            _ = attrs
            if not dn:
                return FlextResult.fail("DN cannot be empty")
            return FlextResult.ok(None)

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

        def can_handle(
            self,
            entry_dn: str,
            attributes: Mapping[str, object],
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

        def _parse_content(
            self,
            ldif_content: str,
        ) -> FlextResult[list[FlextLdifModels.Entry]]:
            """🔴 REQUIRED: Parse raw LDIF content string into Entry models (internal).

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

        def can_handle_attribute(
            self,
            attribute: FlextLdifModels.SchemaAttribute,
        ) -> bool:
            """Check if this Entry quirk has special handling for an attribute definition.

            Entry processing logic might change based on an attribute's schema
            (e.g., handling operational attributes differently).

            Args:
                attribute: The SchemaAttribute model to check.

            Returns:
                True if this quirk has specific processing logic for this attribute.

            """
            _ = attribute  # Explicitly mark as intentionally unused in base
            return False  # Must be implemented by subclass

        def can_handle_objectclass(
            self,
            objectclass: FlextLdifModels.SchemaObjectClass,
        ) -> bool:
            """Check if this Entry quirk has special handling for an objectClass definition.

            Entry processing logic might change based on an entry's objectClasses.

            Args:
                objectclass: The SchemaObjectClass model to check.

            Returns:
                True if this quirk has specific processing logic for this objectClass.

            """
            _ = objectclass  # Explicitly mark as intentionally unused in base
            return False  # Must be implemented by subclass

        def _write_entry(
            self,
            entry_data: FlextLdifModels.Entry,
        ) -> FlextResult[str]:
            r"""🔴 REQUIRED: Write Entry model to RFC-compliant LDIF string (internal).

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


# =========================================================================


class _DescriptorProtocol(Protocol):
    """Protocol for descriptors that behave like their return type."""

    def __get__(self, obj: object | None, objtype: type | None = None) -> str | int: ...


class _ServerTypeDescriptor:
    """Descriptor that returns SERVER_TYPE from Constants (single source of truth)."""

    def __init__(self, value: str) -> None:
        self.value = value

    def __get__(self, obj: object | None, objtype: type | None = None) -> str:
        """Return the stored SERVER_TYPE value."""
        return self.value


class _PriorityDescriptor:
    """Descriptor that returns PRIORITY from Constants (single source of truth)."""

    def __init__(self, value: int) -> None:
        self.value = value

    def __get__(self, obj: object | None, objtype: type | None = None) -> int:
        """Return the stored PRIORITY value."""
        return self.value


# Attach descriptors to FlextLdifServersBase for class and instance access
# Descriptors implement __get__ returning str/int, satisfying the type annotations above
FlextLdifServersBase.server_type = _ServerTypeDescriptor("unknown")
FlextLdifServersBase.priority = _PriorityDescriptor(0)


__all__ = [
    "FlextLdifServersBase",
]
