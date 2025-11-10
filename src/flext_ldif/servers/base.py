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
    - FlextLdifServersBase.Schema → FlextLdifProtocols.Quirks.SchemaProtocol
    - FlextLdifServersBase.Acl → FlextLdifProtocols.Quirks.AclProtocol
    - FlextLdifServersBase.Entry → FlextLdifProtocols.Quirks.EntryProtocol

    All method signatures must match protocol definitions exactly for type safety.
"""

from __future__ import annotations

from abc import ABC
from collections.abc import Mapping
from typing import ClassVar, Literal, Protocol, Self, cast, overload

from flext_core import FlextLogger, FlextResult, FlextService
from pydantic import ConfigDict

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.typings import FlextLdifTypes
from flext_ldif.utilities import FlextLdifUtilities

logger = FlextLogger(__name__)


# NOTE: BaseServerConstants has been consolidated into FlextLdifServersRfc.Constants
# All server-specific Constants should inherit from FlextLdifServersRfc.Constants


class FlextLdifServersBase(FlextService[FlextLdifTypes.EntryOrString], ABC):
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

        # Validate required attributes exist
        if not hasattr(cls.Constants, "SERVER_TYPE"):
            msg = f"{cls.__name__}.Constants must define SERVER_TYPE"
            raise AttributeError(msg)
        if not hasattr(cls.Constants, "PRIORITY"):
            msg = f"{cls.__name__}.Constants must define PRIORITY"
            raise AttributeError(msg)

        # Set class-level attributes from Constants (single source)
        cls.server_type = cls.Constants.SERVER_TYPE
        cls.priority = cls.Constants.PRIORITY

    def __init__(self, **kwargs: object) -> None:
        """Initialize server base class and nested quirk classes.

        Calls parent FlextService.__init__ and then initializes all nested
        Schema, Acl, and Entry quirk classes. Subclasses can override
        _initialize_nested_classes() to customize initialization.

        Args:
            **kwargs: Passed to FlextService.__init__

        """
        super().__init__(**kwargs)
        # Initialize nested quirk classes (schema, acl, entry)
        self._initialize_nested_classes()

    # =========================================================================
    # Server identification - accessed via descriptors (class + instance level)
    # =========================================================================
    # NOTE: server_type and priority are defined in Constants nested class
    # in subclasses (e.g., FlextLdifServersRfc.Constants.SERVER_TYPE)
    # They are accessed via descriptors that work at both class and instance level
    # - Class level: FlextLdifServersOid.server_type → "oid"
    # - Instance level: instance.server_type → "oid"
    # The descriptors are set AFTER the class definition to avoid Pydantic issues

    # =========================================================================
    # FlextService V2: execute() method
    # =========================================================================
    # Required by FlextService - provides default implementation for health checks.
    # Subclasses should override parse() and write() for actual operations.

    # Control auto-execution
    auto_execute: ClassVar[bool] = False

    def _handle_parse_operation(
        self,
        ldif_text: str,
    ) -> FlextResult[FlextLdifTypes.EntryOrString]:
        """Handle parse operation for main quirk."""
        parse_result = self.parse(ldif_text)
        if parse_result.is_success:
            parse_response = parse_result.unwrap()
            return FlextResult[FlextLdifTypes.EntryOrString].ok(parse_response)  # type: ignore[arg-type]
        error_msg: str = parse_result.error or "Parse failed"
        return FlextResult[FlextLdifTypes.EntryOrString].fail(error_msg)

    def _handle_write_operation(
        self,
        entries: list[FlextLdifModels.Entry],
    ) -> FlextResult[FlextLdifTypes.EntryOrString]:
        """Handle write operation for main quirk."""
        write_result = self.write(entries)
        if write_result.is_success:
            written_text: str = write_result.unwrap()
            return FlextResult[FlextLdifTypes.EntryOrString].ok(written_text)
        error_msg: str = write_result.error or "Write failed"
        return FlextResult[FlextLdifTypes.EntryOrString].fail(error_msg)

    def execute(
        self,
        ldif_text: str | None = None,
        entries: list[FlextLdifModels.Entry] | None = None,
        operation: Literal["parse", "write"] | None = None,
    ) -> FlextResult[FlextLdifTypes.EntryOrString]:
        r"""Execute quirk operation with auto-detection and V2 modes.

        Auto-detects operation from parameters:
        - ldif_text: parse operation
        - entries: write operation
        - No params → health check
        - operation parameter is for V2 DI compatibility

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
        # Health check: no parameters provided
        if not ldif_text and not entries:
            detected_server = getattr(self, "server_type", None)
            statistics = FlextLdifModels.Statistics(
                total_entries=0,
                processed_entries=0,
                detected_server_type=detected_server,
            )
            empty_response = FlextLdifModels.ParseResponse(
                entries=[],
                statistics=statistics,
                detected_server_type=detected_server,
            )
            return FlextResult[FlextLdifTypes.EntryOrString].ok(empty_response)  # type: ignore[arg-type]

        # Use explicit operation if provided, otherwise auto-detect
        detected_operation: Literal["parse", "write"] | None = operation
        if detected_operation is None:
            if ldif_text is not None:
                detected_operation = "parse"
            elif entries is not None:
                detected_operation = "write"

        # Execute based on operation
        if detected_operation == "parse":
            if ldif_text is None:
                return FlextResult[FlextLdifTypes.EntryOrString].fail(
                    "parse operation requires ldif_text",
                )
            return self._handle_parse_operation(ldif_text)

        if detected_operation == "write":
            if entries is None:
                return FlextResult[FlextLdifTypes.EntryOrString].fail(
                    "write operation requires entries",
                )
            return self._handle_write_operation(entries)

        # Should not reach here
        return FlextResult[FlextLdifTypes.EntryOrString].fail(
            "No operation parameters provided",
        )

    @overload
    def __call__(
        self,
        ldif_text: str,
        *,
        entries: None = None,
        operation: Literal["parse"] | None = None,
    ) -> list[FlextLdifModels.Entry]: ...

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
            but it's cast to Self for type checker compatibility. Callers should
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

        # Expose backwards-compatible public attributes expected by legacy callers.
        # Must use object.__setattr__ to bypass Pydantic's attribute protection.
        # PLC2801 suppressed: setattr() doesn't work here due to Pydantic conflicts.
        object.__setattr__(self, "schema", self._schema_quirk)  # noqa: PLC2801
        object.__setattr__(self, "acl", self._acl_quirk)  # noqa: PLC2801
        object.__setattr__(self, "entry", self._entry_quirk)  # noqa: PLC2801

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
        entry_quirk = getattr(self, "entry", None)
        if not entry_quirk:
            return FlextResult.fail("Entry quirk not available")
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
        entry = getattr(self, "entry", None)
        if not entry:
            return FlextResult.fail("Entry quirk not available")

        ldif_lines: list[str] = []
        for entry_model in entries:
            result: FlextResult[str] = entry.write(entry_model)
            if result.is_failure:
                return result
            ldif_lines.append(result.unwrap())

        ldif = "\n".join(ldif_lines)
        if ldif and not ldif.endswith("\n"):
            ldif += "\n"
        return FlextResult.ok(ldif)

    # =========================================================================
    # Registry method for DI-based automatic registration
    # =========================================================================
    # NOTE: server_type and priority are ClassVar in the PARENT SERVER CLASS ONLY
    # NOT in nested Schema/Acl/Entry classes
    # (e.g., FlextLdifServersOid.server_type, FlextLdifServersOid.priority)
    # All constants must be in FlextLdifServers[Server].Constants, NOT in subclasses

    @classmethod
    def _get_server_type_from_mro(cls, quirk_class: type[object]) -> str:
        """Get server_type from parent class Constants via MRO traversal."""
        # Traverse MRO to find the server class (not Schema/Acl/Entry)
        # that has Constants
        for mro_cls in quirk_class.__mro__:
            # Skip Schema/Acl/Entry classes, look for server classes
            if (
                mro_cls.__name__.startswith("FlextLdifServers")
                and not mro_cls.__name__.endswith(("Schema", "Acl", "Entry"))
                and hasattr(mro_cls, "Constants")
                and hasattr(mro_cls.Constants, "SERVER_TYPE")
            ):
                server_type = mro_cls.Constants.SERVER_TYPE
                if isinstance(server_type, str):
                    return server_type
        msg = (
            f"Cannot find SERVER_TYPE in Constants for quirk class: "
            f"{quirk_class.__name__}"
        )
        raise AttributeError(msg)

    @classmethod
    def _get_priority_from_mro(cls, quirk_class: type[object]) -> int:
        """Get priority from parent class Constants via MRO traversal."""
        # Traverse MRO to find the server class (not Schema/Acl/Entry)
        # that has Constants
        for mro_cls in quirk_class.__mro__:
            # Skip Schema/Acl/Entry classes, look for server classes
            if (
                mro_cls.__name__.startswith("FlextLdifServers")
                and not mro_cls.__name__.endswith(("Schema", "Acl", "Entry"))
                and hasattr(mro_cls, "Constants")
                and hasattr(mro_cls.Constants, "PRIORITY")
            ):
                priority = mro_cls.Constants.PRIORITY
                if isinstance(priority, int):
                    return priority
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
        """Helper method to register a quirk instance in the registry.

        This method can be used by subclasses or registry to automatically register
        quirks. The base class itself does NOT register automatically - this is
        just a helper for registration logic.

        Args:
            quirk_instance: Instance of any quirk (Schema, Acl, Entry, base)
            registry: Registry instance to register the quirk (has register)

        """
        # Simply call the registry's register method - it will handle routing internally
        register_method = getattr(registry, "register", None)
        if register_method:
            register_method(quirk_instance)

    # =========================================================================
    # Automatic Routing Methods - Helper methods for automatic quirk routing
    # =========================================================================

    def _detect_model_type(self, model: object) -> str:
        """Detect model type for automatic routing.

        Args:
            model: Model instance to detect type for.

        Returns:
            Model type name: "entry", "schema_attribute",
            "schema_objectclass", or "acl".

        """
        if isinstance(model, FlextLdifModels.Entry):
            return "entry"
        if isinstance(model, FlextLdifModels.SchemaAttribute):
            return "schema_attribute"
        if isinstance(model, FlextLdifModels.SchemaObjectClass):
            return "schema_objectclass"
        if isinstance(model, FlextLdifModels.Acl):
            return "acl"
        return "unknown"

    def _get_for_model(self, model: object) -> object | None:
        """Get appropriate quirk instance for a model type.

        Args:
            model: Model instance to get quirk for.

        Returns:
            Appropriate quirk instance (Schema, Acl, or Entry) or None if not found.

        """
        model_type = self._detect_model_type(model)
        if model_type == "entry":
            return getattr(self, "entry", None)
        if model_type in {"schema_attribute", "schema_objectclass"}:
            return getattr(self, "schema", None)
        if model_type == "acl":
            return getattr(self, "acl", None)
        return None

    def _route_model_to_write(self, model: object) -> FlextResult[str]:
        """Route a single model to appropriate write method.

        Automatically detects model type and routes to correct quirk write method.

        Args:
            model: Model instance to write (Entry, SchemaAttribute, SchemaObjectClass, or Acl).

        Returns:
            FlextResult with LDIF string representation.

        """
        if isinstance(model, FlextLdifModels.Entry):
            quirk = getattr(self, "entry", None)
            if not quirk:
                return FlextResult.fail("Entry quirk not available")
            result: FlextResult[str] = quirk.write_entry(model)
            return result
        if isinstance(model, FlextLdifModels.SchemaAttribute):
            quirk = getattr(self, "schema", None)
            if not quirk:
                return FlextResult.fail("Schema quirk not available")
            result2: FlextResult[str] = quirk.write_attribute(model)
            return result2
        if isinstance(model, FlextLdifModels.SchemaObjectClass):
            quirk = getattr(self, "schema", None)
            if not quirk:
                return FlextResult.fail("Schema quirk not available")
            result3: FlextResult[str] = quirk.write_objectclass(model)
            return result3
        if isinstance(model, FlextLdifModels.Acl):
            quirk = getattr(self, "acl", None)
            if not quirk:
                return FlextResult.fail("ACL quirk not available")
            result4: FlextResult[str] = quirk.write_acl(model)
            return result4
        return FlextResult.fail(f"Unknown model type: {type(model).__name__}")

    def _route_models_to_write(self, models: list[object]) -> FlextResult[list[str]]:
        """Route multiple models to appropriate write methods.

        Processes each model individually and routes to correct quirk.

        Args:
            models: List of model instances to write.

        Returns:
            FlextResult with list of LDIF string representations.

        """
        ldif_lines: list[str] = []
        for model in models:
            result = self._route_model_to_write(model)
            if result.is_failure:
                return FlextResult.fail(result.error)
            text = result.unwrap()
            if isinstance(text, str):
                ldif_lines.extend(text.splitlines(keepends=False))
                if text and not text.endswith("\n"):
                    ldif_lines.append("")  # Add blank line between entries
        return FlextResult.ok(ldif_lines)

    # =========================================================================
    # Validation Methods - Edge case handling for robust parsing
    # =========================================================================

    def _validate_ldif_text(self, ldif_text: str) -> FlextResult[None]:
        """Validate LDIF text before parsing - handles edge cases.

        Edge cases handled:
        - None/empty string → returns ok (will result in empty entry list)
        - Whitespace only → returns ok (will result in empty entry list)
        - Encoding issues → any decoding happens in parse_content

        Args:
            ldif_text: LDIF content to validate

        Returns:
            FlextResult.ok(None) if valid, FlextResult.fail() if invalid

        """
        # Empty or whitespace-only is valid (will parse to empty list)
        if not ldif_text or not ldif_text.strip():
            return FlextResult.ok(None)
        return FlextResult.ok(None)

    def _validate_entries(
        self,
        entries: list[FlextLdifModels.Entry] | None,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Validate entry list before writing - handles edge cases.

        Edge cases handled:
        - None → returns empty list
        - Empty list → returns empty list
        - Invalid entries → returns fail

        Args:
            entries: Entry list to validate

        Returns:
            FlextResult with validated entry list

        """
        if entries is None:
            return FlextResult.ok([])
        if not entries:
            return FlextResult.ok([])
        # All entries should be Entry models
        if not all(isinstance(entry, FlextLdifModels.Entry) for entry in entries):
            invalid = next(
                e for e in entries if not isinstance(e, FlextLdifModels.Entry)
            )
            return FlextResult.fail(f"Invalid entry type: {type(invalid).__name__}")
        return FlextResult.ok(entries)

    # =========================================================================
    # Nested Abstract Base Classes for Internal Implementation
    # =========================================================================

    class Schema(FlextService[FlextLdifTypes.SchemaModelOrString]):
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

        Example vendors:
        - Oracle OID: orclOID prefix, Oracle-specific syntaxes
        - Oracle OUD: Enhanced schema features
        - OpenLDAP: olc* configuration attributes
        - Active Directory: AD-specific schema extensions
        - RFC: RFC 4512 compliant baseline (no extensions)
        """

        def __init__(
            self,
            schema_service: object | None = None,
            **kwargs: object,
        ) -> None:
            """Initialize schema quirk service with optional DI service injection.

            Args:
                schema_service: Injected FlextLdifSchema service (optional, lazy-created if None)
                **kwargs: Passed to FlextService for initialization

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
        # Automatic Routing Methods - Helper methods for automatic routing
        # =====================================================================

        def _detect_schema_type(
            self,
            definition: (
                str
                | FlextLdifModels.SchemaAttribute
                | FlextLdifModels.SchemaObjectClass
            ),
        ) -> str:
            """Detect schema type (attribute or objectclass) for automatic routing.

            Args:
                definition: Schema definition string or model.

            Returns:
                "attribute" or "objectclass".

            """
            if isinstance(definition, FlextLdifModels.SchemaAttribute):
                return "attribute"
            if isinstance(definition, FlextLdifModels.SchemaObjectClass):
                return "objectclass"
            # Try to detect from string content
            definition_str = (
                definition if isinstance(definition, str) else str(definition)
            )
            definition_lower = definition_str.lower()

            # Check for objectClass-specific keywords (RFC 4512)
            # ObjectClasses have: STRUCTURAL, AUXILIARY, ABSTRACT, MUST, MAY
            # (Note: SUP is valid for both attributes and objectClasses, so excluded)
            # Attributes have: EQUALITY, SUBSTR, ORDERING, SYNTAX, USAGE, SINGLE-VALUE, NO-USER-MODIFICATION
            objectclass_only_keywords = [
                " structural",
                " auxiliary",
                " abstract",
                " must (",
                " may (",
            ]
            for keyword in objectclass_only_keywords:
                if keyword in definition_lower:
                    return "objectclass"

            # Check for attribute-specific keywords (more accurate detection)
            # These keywords ONLY appear in attribute definitions
            attribute_only_keywords = [
                " equality ",
                " substr ",
                " ordering ",
                " syntax ",
                " usage ",
                " single-value",
                " no-user-modification",
            ]
            for keyword in attribute_only_keywords:
                if keyword in definition_lower:
                    return "attribute"

            # Legacy check for explicit objectclass keyword
            if "objectclass" in definition_lower or "oclass" in definition_lower:
                return "objectclass"

            # Default to attribute if ambiguous
            return "attribute"

        def _route_parse(
            self,
            definition: str,
        ) -> (
            FlextResult[FlextLdifModels.SchemaAttribute]
            | FlextResult[FlextLdifModels.SchemaObjectClass]
        ):
            """Route schema definition to appropriate parse method.

            Automatically detects if definition is attribute or objectclass.

            Args:
                definition: Schema definition string.

            Returns:
                FlextResult with SchemaAttribute or SchemaObjectClass.

            """
            schema_type = self._detect_schema_type(definition)
            if schema_type == "objectclass":
                return self._parse_objectclass(definition)
            return self._parse_attribute(definition)

        def parse(
            self,
            definition: str,
        ) -> (
            FlextResult[FlextLdifModels.SchemaAttribute]
            | FlextResult[FlextLdifModels.SchemaObjectClass]
        ):
            """Parse schema definition (attribute or objectClass).

            Automatically routes to parse_attribute() or parse_objectclass() based on content.

            Args:
                definition: Schema definition string (attribute or objectClass)

            Returns:
                FlextResult with SchemaAttribute or SchemaObjectClass model

            """
            return self._route_parse(definition)

        def write(
            self,
            model: FlextLdifTypes.SchemaModel,
        ) -> FlextResult[str]:
            """Write schema model to RFC-compliant string.

            Automatically routes to _write_attribute() or _write_objectclass() based on model type.

            Args:
                model: SchemaAttribute or SchemaObjectClass model

            Returns:
                FlextResult with RFC-compliant definition string

            """
            if isinstance(model, FlextLdifModels.SchemaAttribute):
                return self._write_attribute(model)
            # isinstance narrowed to SchemaObjectClass by type checker
            return self._write_objectclass(model)

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

        def _route_write(
            self,
            model: FlextLdifTypes.SchemaModel,
        ) -> FlextResult[str]:
            """Route schema model to appropriate write method.

            Automatically detects model type and routes to correct write method.

            Args:
                model: SchemaAttribute or SchemaObjectClass model.

            Returns:
                FlextResult with string representation.

            """
            if isinstance(model, FlextLdifModels.SchemaAttribute):
                return self.write_attribute(model)
            # isinstance narrowed to SchemaObjectClass by type checker
            return self.write_objectclass(model)

        def _route_can_handle(
            self,
            definition: (
                str
                | FlextLdifModels.SchemaAttribute
                | FlextLdifModels.SchemaObjectClass
            ),
        ) -> bool:
            """Route can_handle check to appropriate method.

            Automatically detects type and routes to correct can_handle method.

            Args:
                definition: Schema definition string or model.

            Returns:
                True if quirk can handle this definition.

            """
            if isinstance(definition, FlextLdifModels.SchemaAttribute):
                return self.can_handle_attribute(definition)
            if isinstance(definition, FlextLdifModels.SchemaObjectClass):
                return self.can_handle_objectclass(definition)
            # For string definitions, try both methods
            schema_type = self._detect_schema_type(definition)
            if schema_type == "objectclass":
                return self.can_handle_objectclass(definition)
            return self.can_handle_attribute(definition)

        def _handle_parse_operation(
            self,
            attr_definition: str | None,
            oc_definition: str | None,
        ) -> FlextResult[FlextLdifTypes.SchemaModelOrString]:
            """Handle parse operation for schema quirk."""
            if attr_definition:
                attr_result = self.parse_attribute(attr_definition)
                if attr_result.is_success:
                    parsed_attr: FlextLdifModels.SchemaAttribute = attr_result.unwrap()
                    return FlextResult[
                        FlextLdifModels.SchemaAttribute
                        | FlextLdifModels.SchemaObjectClass
                        | str
                    ].ok(parsed_attr)
                error_msg: str = attr_result.error or "Parse attribute failed"
                return FlextResult[
                    FlextLdifModels.SchemaAttribute
                    | FlextLdifModels.SchemaObjectClass
                    | str
                ].fail(error_msg)
            if oc_definition:
                oc_result = self.parse_objectclass(oc_definition)
                if oc_result.is_success:
                    parsed_oc: FlextLdifModels.SchemaObjectClass = oc_result.unwrap()
                    return FlextResult[
                        FlextLdifModels.SchemaAttribute
                        | FlextLdifModels.SchemaObjectClass
                        | str
                    ].ok(parsed_oc)
                error_msg = oc_result.error or "Parse objectclass failed"
                return FlextResult[
                    FlextLdifModels.SchemaAttribute
                    | FlextLdifModels.SchemaObjectClass
                    | str
                ].fail(error_msg)
            return FlextResult[
                FlextLdifModels.SchemaAttribute
                | FlextLdifModels.SchemaObjectClass
                | str
            ].fail("No parse parameter provided")

        def _handle_write_operation(
            self,
            attr_model: FlextLdifModels.SchemaAttribute | None,
            oc_model: FlextLdifModels.SchemaObjectClass | None,
        ) -> FlextResult[FlextLdifTypes.SchemaModelOrString]:
            """Handle write operation for schema quirk."""
            if attr_model:
                write_result = self.write_attribute(attr_model)
                if write_result.is_success:
                    written_text: str = write_result.unwrap()
                    return FlextResult[
                        FlextLdifModels.SchemaAttribute
                        | FlextLdifModels.SchemaObjectClass
                        | str
                    ].ok(written_text)
                error_msg: str = write_result.error or "Write attribute failed"
                return FlextResult[
                    FlextLdifModels.SchemaAttribute
                    | FlextLdifModels.SchemaObjectClass
                    | str
                ].fail(error_msg)
            if oc_model:
                write_oc_result = self.write_objectclass(oc_model)
                if write_oc_result.is_success:
                    written_text = write_oc_result.unwrap()
                    return FlextResult[
                        FlextLdifModels.SchemaAttribute
                        | FlextLdifModels.SchemaObjectClass
                        | str
                    ].ok(written_text)
                error_msg = write_oc_result.error or "Write objectclass failed"
                return FlextResult[
                    FlextLdifModels.SchemaAttribute
                    | FlextLdifModels.SchemaObjectClass
                    | str
                ].fail(error_msg)
            return FlextResult[
                FlextLdifModels.SchemaAttribute
                | FlextLdifModels.SchemaObjectClass
                | str
            ].fail("No write parameter provided")

        def _auto_detect_operation(
            self,
            data: (
                str
                | FlextLdifModels.SchemaAttribute
                | FlextLdifModels.SchemaObjectClass
                | None
            ),
            operation: Literal["parse", "write"] | None,
        ) -> (
            Literal["parse", "write"]
            | FlextResult[
                FlextLdifModels.SchemaAttribute
                | FlextLdifModels.SchemaObjectClass
                | str
            ]
        ):
            """Auto-detect operation from data type. Returns operation or error result."""
            if operation is not None:
                return operation

            if isinstance(data, str):
                return "parse"
            if isinstance(
                data,
                (
                    FlextLdifModels.SchemaAttribute,
                    FlextLdifModels.SchemaObjectClass,
                ),
            ):
                return "write"

            return FlextResult[
                FlextLdifModels.SchemaAttribute
                | FlextLdifModels.SchemaObjectClass
                | str
            ].fail(
                f"Unknown data type: {type(data).__name__}. Expected str, SchemaAttribute, or SchemaObjectClass",
            )

        def _route_operation(
            self,
            data: (
                str
                | FlextLdifModels.SchemaAttribute
                | FlextLdifModels.SchemaObjectClass
            ),
            operation: Literal["parse", "write"],
        ) -> FlextResult[FlextLdifTypes.SchemaModelOrString]:
            """Route data to appropriate parse or write handler."""
            if operation == "parse":
                if not isinstance(data, str):
                    return FlextResult[
                        FlextLdifModels.SchemaAttribute
                        | FlextLdifModels.SchemaObjectClass
                        | str
                    ].fail(f"parse operation requires str, got {type(data).__name__}")
                if self._detect_schema_type(data) == "objectclass":
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
                    FlextLdifModels.SchemaAttribute
                    | FlextLdifModels.SchemaObjectClass
                    | str
                ].fail(
                    f"write operation requires SchemaAttribute or SchemaObjectClass, got {type(data).__name__}",
                )

            # Should not reach here (Literal type ensures only parse or write)
            msg = f"Unknown operation: {operation}"
            raise AssertionError(msg)

        def execute(
            self,
            data: (
                str
                | FlextLdifModels.SchemaAttribute
                | FlextLdifModels.SchemaObjectClass
                | None
            ) = None,
            operation: Literal["parse", "write"] | None = None,
        ) -> FlextResult[FlextLdifTypes.SchemaModelOrString]:
            """Execute schema quirk operation with automatic type detection and routing.

            Fully automatic polymorphic dispatch based on data type:
            - str (schema definition) → parse_attribute() OR parse_objectclass() → SchemaAttribute OR SchemaObjectClass
            - SchemaAttribute (model) → write_attribute() → str
            - SchemaObjectClass (model) → write_objectclass() → str
            - None → health check

            **V2 Usage - Maximum Automation:**
                >>> schema = FlextLdifServersRfc.Schema()
                >>> # Parse: pass schema definition string
                >>> attr = schema.execute(
                ...     "( 2.5.4.3 NAME 'cn' ...)"
                ... )  # → SchemaAttribute
                >>> # Write: pass model
                >>> text = schema.execute(attr)  # → str
                >>> # Auto-detect which type of schema definition
                >>> attr_or_oc = schema.execute("( 2.5.6.6 ... )")  # Detects & parses

            Args:
                data: Schema definition string OR SchemaAttribute OR SchemaObjectClass model
                      (operation auto-detected from type)
                operation: Force operation type (overrides auto-detection)

            Returns:
                FlextResult[SchemaAttribute | SchemaObjectClass | str] depending on operation

            """
            # Health check: no data provided
            if data is None:
                empty_str: str = ""
                return FlextResult[
                    FlextLdifModels.SchemaAttribute
                    | FlextLdifModels.SchemaObjectClass
                    | str
                ].ok(empty_str)

            # Auto-detect or validate operation
            detected_op = self._auto_detect_operation(data, operation)
            if isinstance(detected_op, FlextResult):
                return detected_op

            # Route to appropriate handler
            return self._route_operation(data, detected_op)

        @overload
        def __call__(
            self,
            attr_definition: str,
            *,
            oc_definition: None = None,
            attr_model: None = None,
            oc_model: None = None,
            operation: Literal["parse"] | None = None,
        ) -> FlextLdifTypes.SchemaModel: ...

        @overload
        def __call__(
            self,
            *,
            attr_definition: None = None,
            oc_definition: str,
            attr_model: None = None,
            oc_model: None = None,
            operation: Literal["parse"] | None = None,
        ) -> FlextLdifTypes.SchemaModel: ...

        @overload
        def __call__(
            self,
            *,
            attr_definition: None = None,
            oc_definition: None = None,
            attr_model: FlextLdifModels.SchemaAttribute,
            oc_model: None = None,
            operation: Literal["write"] | None = None,
        ) -> str: ...

        @overload
        def __call__(
            self,
            *,
            attr_definition: None = None,
            oc_definition: None = None,
            attr_model: None = None,
            oc_model: FlextLdifModels.SchemaObjectClass,
            operation: Literal["write"] | None = None,
        ) -> str: ...

        @overload
        def __call__(
            self,
            attr_definition: str | None = None,
            oc_definition: str | None = None,
            attr_model: FlextLdifModels.SchemaAttribute | None = None,
            oc_model: FlextLdifModels.SchemaObjectClass | None = None,
            operation: Literal["parse", "write"] | None = None,
        ) -> FlextLdifTypes.SchemaModelOrString: ...

        def __call__(
            self,
            attr_definition: str | None = None,
            oc_definition: str | None = None,
            attr_model: FlextLdifModels.SchemaAttribute | None = None,
            oc_model: FlextLdifModels.SchemaObjectClass | None = None,
            operation: Literal["parse", "write"] | None = None,
        ) -> FlextLdifTypes.SchemaModelOrString:
            """Callable interface - use as processor.

            Enables direct usage as processor:
                >>> schema = FlextLdifServersRfc.Schema()
                >>> attr = schema(attr_definition="( 2.5.4.3 NAME 'cn' ...)")  # Parse
                >>> text = schema(attr_model=attr)  # Write

            Args:
                attr_definition: Attribute definition to parse
                oc_definition: ObjectClass definition to parse
                attr_model: Attribute model to write
                oc_model: ObjectClass model to write
                operation: Explicit operation type

            Returns:
                Unwrapped result (SchemaAttribute, SchemaObjectClass, or str).

            """
            # Schema.execute() expects a single 'data' parameter, not separate parameters
            # For __call__, we need to handle multiple parameters differently
            # If attr_definition is provided, use it; otherwise use oc_definition
            # If attr_model is provided, use it; otherwise use oc_model
            data: (
                str
                | FlextLdifModels.SchemaAttribute
                | FlextLdifModels.SchemaObjectClass
                | None
            ) = None
            if attr_definition is not None:
                data = attr_definition
            elif oc_definition is not None:
                data = oc_definition
            elif attr_model is not None:
                data = attr_model
            elif oc_model is not None:
                data = oc_model

            result = self.execute(data=data, operation=operation)
            return result.unwrap()

        def __new__(
            cls,
            schema_service: object | None = None,
            **kwargs: object,
        ) -> Self:
            """Override __new__ to support auto-execute and processor instantiation."""
            instance = super().__new__(cls)
            type(instance).__init__(instance, schema_service=schema_service, **kwargs)

            if cls.auto_execute:
                attr_def = (
                    cast("str | None", kwargs.get("attr_definition"))
                    if "attr_definition" in kwargs
                    else None
                )
                oc_def = (
                    cast("str | None", kwargs.get("oc_definition"))
                    if "oc_definition" in kwargs
                    else None
                )
                attr_mod = (
                    cast(
                        "FlextLdifModels.SchemaAttribute | None",
                        kwargs.get("attr_model"),
                    )
                    if "attr_model" in kwargs
                    else None
                )
                oc_mod = (
                    cast(
                        "FlextLdifModels.SchemaObjectClass | None",
                        kwargs.get("oc_model"),
                    )
                    if "oc_model" in kwargs
                    else None
                )
                op = (
                    cast("Literal['parse'] | None", kwargs.get("operation"))
                    if "operation" in kwargs
                    else None
                )
                # Schema.execute() expects a single 'data' parameter
                data: (
                    str
                    | FlextLdifModels.SchemaAttribute
                    | FlextLdifModels.SchemaObjectClass
                    | None
                ) = None
                if attr_def is not None:
                    data = attr_def
                elif oc_def is not None:
                    data = oc_def
                elif attr_mod is not None:
                    data = attr_mod
                elif oc_mod is not None:
                    data = oc_mod
                result = instance.execute(data=data, operation=op)
                unwrapped: (
                    FlextLdifModels.SchemaAttribute
                    | FlextLdifModels.SchemaObjectClass
                    | str
                ) = result.unwrap()
                return cast("Self", unwrapped)

            return instance

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
            - Transform attribute format for compatibility

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
            - Transform objectClass format for compatibility

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

        def create_metadata(
            self,
            original_format: str,
            extensions: dict[str, object] | None = None,
        ) -> FlextLdifModels.QuirkMetadata:
            """Create quirk metadata with consistent server-specific extensions.

            Helper method to consolidate metadata creation across server quirks.
            Reduces code duplication in server-specific parse_attribute/parse_objectclass methods.

            Args:
                original_format: Original text format of the parsed element
                extensions: Optional dict of server-specific extensions/metadata

            Returns:
                FlextLdifModels.QuirkMetadata with quirk_type from Constants of parent server class

            Note:
                server_type is retrieved from Constants of the parent server class dynamically.
                This ensures all nested classes (Schema, Acl, Entry) use the same Constants
                from their parent server class (e.g., FlextLdifServersRfc.Constants,
                FlextLdifServersOid.Constants).

            """
            # Find parent server class that has Constants
            # Iterate through MRO to find the server class (not nested Schema/Acl/Entry)
            server_type = FlextLdifConstants.ServerTypes.GENERIC
            for cls in type(self).__mro__:
                # Check if this class has a Constants nested class
                if hasattr(cls, "Constants") and hasattr(cls.Constants, "SERVER_TYPE"):
                    server_type = cls.Constants.SERVER_TYPE
                    break

            return FlextLdifModels.QuirkMetadata(
                quirk_type=server_type,
                original_format=original_format,
                extensions=extensions or {},
            )

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

        def extract_schemas_from_ldif(
            self,
            ldif_content: str,
            *,
            validate_dependencies: bool = False,
        ) -> FlextResult[FlextLdifTypes.Models.EntryAttributesDict]:
            """Extract and parse all schema definitions from LDIF content (template method).

            Generic template method that consolidates schema extraction logic across all servers.
            Uses FlextLdifUtilities for parsing and provides hook for server-specific validation.

            This template method replaces duplicated extract_schemas_from_ldif implementations
            in OID (37 lines), OUD (66 lines), and OpenLDAP servers.

            Process:
                1. Extract attributes using FlextLdifUtilities.Schema
                2. If validate_dependencies: build available_attrs set and call validation hook
                3. Extract objectClasses using FlextLdifUtilities.Schema
                4. Return combined result

            Args:
                ldif_content: Raw LDIF content containing schema definitions
                validate_dependencies: If True, validate attribute dependencies before
                                     objectClass extraction (used by OUD for dep checking)

            Returns:
                FlextResult with dict containing:
                    - ATTRIBUTES: list[SchemaAttribute]
                    - OBJECTCLASS: list[SchemaObjectClass]

            Example Usage (OID - simple):
                result = self.extract_schemas_from_ldif(ldif_content)

            Example Usage (OUD - with validation):
                result = self.extract_schemas_from_ldif(
                    ldif_content,
                    validate_dependencies=True
                )

            """
            try:
                # PHASE 1: Extract all attributeTypes using FlextLdifUtilities
                attributes_parsed = (
                    FlextLdifUtilities.Schema.extract_attributes_from_lines(
                        ldif_content,
                        self.parse_attribute,
                    )
                )

                # PHASE 2: Build available attributes set (if validation requested)
                if validate_dependencies:
                    available_attrs = (
                        FlextLdifUtilities.Schema.build_available_attributes_set(
                            attributes_parsed,
                        )
                    )

                    # Call server-specific validation hook
                    validation_result = self._hook_validate_attributes(
                        attributes_parsed,
                        available_attrs,
                    )
                    if not validation_result.is_success:
                        return FlextResult[
                            FlextLdifTypes.Models.EntryAttributesDict
                        ].fail(
                            f"Attribute validation failed: {validation_result.error}",
                        )

                # PHASE 3: Extract objectClasses using FlextLdifUtilities
                objectclasses_parsed = (
                    FlextLdifUtilities.Schema.extract_objectclasses_from_lines(
                        ldif_content,
                        self.parse_objectclass,
                    )
                )

                # Return combined result
                dk = FlextLdifConstants.DictKeys
                return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].ok(
                    {
                        dk.ATTRIBUTES: attributes_parsed,
                        dk.OBJECTCLASS: objectclasses_parsed,
                    },
                )

            except Exception as e:
                return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].fail(
                    f"Schema extraction failed: {e}",
                )

        # REMOVED: should_filter_out_attribute - Roteamento interno, não deve ser abstrato

        # REMOVED: should_filter_out_objectclass - Roteamento interno, não deve ser abstrato

    class Acl(FlextService[FlextLdifTypes.AclOrString]):
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

        Example vendors:
        - Oracle OID: orclaci, orclentrylevelaci
        - Oracle OUD: Enhanced ACI format
        - OpenLDAP: olcAccess directives
        - Active Directory: NT Security Descriptors
        - RFC: RFC 4516 compliant baseline

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

        def __init__(self, acl_service: object | None = None, **kwargs: object) -> None:
            """Initialize ACL quirk service with optional DI service injection.

            Args:
                acl_service: Injected FlextLdifAcl service (optional, lazy-created if None)
                **kwargs: Passed to FlextService for initialization

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
            "olcAccess",  # OpenLDAP
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
        # Automatic Routing Methods - Helper methods for automatic routing
        # =====================================================================

        def _route_parse(self, acl_line: str) -> FlextResult[FlextLdifModels.Acl]:
            """Route ACL parsing to parse method.

            Simplified wrapper for automatic routing.

            Args:
                acl_line: ACL line string.

            Returns:
                FlextResult with Acl model.

            """
            return self.parse(acl_line)

        def _route_write(self, acl_model: FlextLdifModels.Acl) -> FlextResult[str]:
            """Route ACL writing to write method.

            Simplified wrapper for automatic routing.

            Args:
                acl_model: Acl model.

            Returns:
                FlextResult with string representation.

            """
            return self.write(acl_model)

        def _handle_parse_acl(
            self,
            acl_line: str,
        ) -> FlextResult[FlextLdifModels.Acl | str]:
            """Handle parse operation for ACL quirk."""
            parse_acl_result = self._route_parse(acl_line)
            if parse_acl_result.is_success:
                parsed_acl: FlextLdifModels.Acl = parse_acl_result.unwrap()
                return FlextResult[FlextLdifModels.Acl | str].ok(parsed_acl)
            error_msg: str = parse_acl_result.error or "Parse ACL failed"
            return FlextResult[FlextLdifModels.Acl | str].fail(error_msg)

        def _handle_write_acl(
            self,
            acl_model: FlextLdifModels.Acl,
        ) -> FlextResult[FlextLdifModels.Acl | str]:
            """Handle write operation for ACL quirk."""
            write_result = self._route_write(acl_model)
            if write_result.is_success:
                written_text: str = write_result.unwrap()
                return FlextResult[FlextLdifModels.Acl | str].ok(written_text)
            error_msg: str = write_result.error or "Write ACL failed"
            return FlextResult[FlextLdifModels.Acl | str].fail(error_msg)

        def execute(
            self,
            data: str | FlextLdifModels.Acl | None = None,
            operation: Literal["parse", "write"] | None = None,
        ) -> FlextResult[FlextLdifModels.Acl | str]:
            """Execute ACL quirk operation with automatic type detection and routing.

            Fully automatic polymorphic dispatch based on data type:
            - str (ACL line) → parse_acl() → Acl
            - Acl (model) → write_acl() → str
            - None → health check

            **V2 Usage - Maximum Automation:**
                >>> acl = FlextLdifServersRfc.Acl()
                >>> # Parse: pass ACL line string
                >>> acl_model = acl.execute("(target=...)")  # → Acl
                >>> # Write: pass model
                >>> acl_text = acl.execute(acl_model)  # → str
                >>> # Or use as callable processor
                >>> acl_model = acl("(target=...)")  # Parse
                >>> acl_text = acl(acl_model)  # Write

            Args:
                data: ACL line string OR Acl model
                      (operation auto-detected from type)
                operation: Force operation type (overrides auto-detection)

            Returns:
                FlextResult[Acl | str] depending on operation

            """
            # Health check: no data provided
            if data is None:
                empty_acl: FlextLdifModels.Acl = FlextLdifModels.Acl()
                return FlextResult[FlextLdifModels.Acl | str].ok(empty_acl)

            # Auto-detect operation from data type, unless overridden
            detected_operation: Literal["parse", "write"] | None = operation

            if detected_operation is None:
                # Type-based auto-detection
                detected_operation = "parse" if isinstance(data, str) else "write"

            # Execute based on detected/forced operation
            if detected_operation == "parse":
                if not isinstance(data, str):
                    return FlextResult[FlextLdifModels.Acl | str].fail(
                        f"parse operation requires str, got {type(data).__name__}",
                    )
                # Route to parse_acl → Acl
                return self._handle_parse_acl(data)

            # detected_operation == "write"
            if not isinstance(data, FlextLdifModels.Acl):
                return FlextResult[FlextLdifModels.Acl | str].fail(
                    f"write operation requires Acl, got {type(data).__name__}",
                )
            # Route to write_acl → str
            return self._handle_write_acl(data)

        @overload
        def __call__(
            self,
            data: str,
            *,
            operation: Literal["parse"] | None = None,
        ) -> FlextLdifModels.Acl: ...

        @overload
        def __call__(
            self,
            data: FlextLdifModels.Acl,
            *,
            operation: Literal["write"] | None = None,
        ) -> str: ...

        @overload
        def __call__(
            self,
            data: str | FlextLdifModels.Acl | None = None,
            *,
            operation: Literal["parse", "write"] | None = None,
        ) -> FlextLdifModels.Acl | str: ...

        def __call__(
            self,
            data: str | FlextLdifModels.Acl | None = None,
            *,
            operation: Literal["parse", "write"] | None = None,
        ) -> FlextLdifModels.Acl | str:
            """Callable interface - automatic polymorphic processor.

            Pass ACL line string for parsing or Acl model for writing.
            Type auto-detection handles routing automatically.
            """
            result = self.execute(data=data, operation=operation)
            return result.unwrap()

        def __new__(cls, acl_service: object | None = None, **kwargs: object) -> Self:
            """Override __new__ to support auto-execute and processor instantiation."""
            instance = super().__new__(cls)
            type(instance).__init__(instance, acl_service=acl_service, **kwargs)

            if cls.auto_execute:
                data = (
                    cast("str | FlextLdifModels.Acl | None", kwargs.get("data"))
                    if "data" in kwargs
                    else None
                )
                op = (
                    cast("Literal['parse', 'write'] | None", kwargs.get("operation"))
                    if "operation" in kwargs
                    else None
                )
                result = instance.execute(data=data, operation=op)
                unwrapped: FlextLdifModels.Acl | str = result.unwrap()
                return cast("Self", unwrapped)

            return instance

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
            - Transform ACL format for compatibility

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

        def parse(self, acl_line: str) -> FlextResult[FlextLdifModels.Acl]:
            """Parse ACL definition line.

            Routes to _parse_acl() internally.

            Args:
                acl_line: ACL definition string

            Returns:
                FlextResult with Acl model

            """
            return self._parse_acl(acl_line)

        def can_handle(self, acl_line: str | FlextLdifModels.Acl) -> bool:
            """Check if this quirk can handle the ACL definition (public interface).

            Delegates to can_handle_acl() for server-specific logic.

            Args:
                acl_line: ACL definition line string or Acl model

            Returns:
                True if this quirk can handle this ACL, False otherwise

            """
            return self.can_handle_acl(acl_line)

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
            - Different servers have different ACL syntax (OpenLDAP vs OUD vs AD, etc.)

            **Edge cases to handle:**
            - Empty string → return fail("ACL line is empty")
            - Malformed rule → handle gracefully or reject with clear message
            - Unknown permission types → preserve as string for server-specific handling
            - Complex nested rules → flatten or preserve structure as appropriate
            - Server-specific extensions → preserve in quirk_metadata for round-trip conversion
            - Partial/incomplete rules → validate completeness if needed

            Args:
                acl_line: ACL definition line (server-specific format)

            Returns:
                FlextResult with Acl model or fail(message) on error

            Examples:
                - OpenLDAP: "access to attrs=cn by * read"
                - OUD: "aci: (targetdn=\"...\") (version 3.0;...)"

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

        def write(self, acl_data: FlextLdifModels.Acl) -> FlextResult[str]:
            """Write ACL data to RFC-compliant string format.

            Routes to _write_acl() internally.

            Args:
                acl_data: Acl model

            Returns:
                FlextResult with RFC-compliant ACL string

            """
            return self._write_acl(acl_data)

        def _write_acl(self, acl_data: FlextLdifModels.Acl) -> FlextResult[str]:
            """Write ACL data to RFC-compliant string format (internal).

            Args:
                acl_data: Acl model

            Returns:
                FlextResult with RFC-compliant ACL string

            """
            _ = acl_data  # Explicitly mark as intentionally unused in base
            return FlextResult.fail("Must be implemented by subclass")

    class Entry(FlextService[FlextLdifTypes.EntryOrString]):
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

        Example use cases:
        - Oracle operational attributes
        - OpenLDAP configuration entries (cn=config)
        - Active Directory specific attributes
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

        def __init__(
            self,
            entry_service: object | None = None,
            **kwargs: object,
        ) -> None:
            """Initialize entry quirk service with optional DI service injection.

            Args:
                entry_service: Injected FlextLdifEntry service (optional, lazy-created if None)
                **kwargs: Passed to FlextService for initialization

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

        def parse(self, ldif_text: str) -> FlextResult[list[FlextLdifModels.Entry]]:
            """Parse LDIF content string to Entry models.

            Routes to _parse_content() internally.

            Args:
                ldif_text: LDIF content string

            Returns:
                FlextResult with list of Entry models

            """
            return self._parse_content(ldif_text)

        def write(self, entry: FlextLdifModels.Entry) -> FlextResult[str]:
            """Write single Entry model to LDIF string.

            Routes to _write_entry() internally.

            Args:
                entry: Entry model to write

            Returns:
                FlextResult with LDIF string

            """
            return self._write_entry(entry)

        # =====================================================================
        # Automatic Routing Methods - Helper methods for automatic routing
        # =====================================================================

        def _route_parse(
            self,
            ldif_text: str,
        ) -> FlextResult[list[FlextLdifModels.Entry]]:
            """Route LDIF parsing to parse method.

            Simplified wrapper for automatic routing.

            Args:
                ldif_text: LDIF content string.

            Returns:
                FlextResult with list of Entry models.

            """
            return self.parse(ldif_text)

        def _route_write(self, entry: FlextLdifModels.Entry) -> FlextResult[str]:
            """Route entry writing to write method.

            Simplified wrapper for automatic routing.

            Args:
                entry: Entry model.

            Returns:
                FlextResult with string representation.

            """
            return self.write(entry)

        def _route_write_many(
            self,
            entries: list[FlextLdifModels.Entry],
        ) -> FlextResult[str]:
            """Route multiple entries writing.

            Writes each entry and combines results.

            Args:
                entries: List of Entry models.

            Returns:
                FlextResult with combined LDIF string.

            """
            ldif_lines: list[str] = []
            for entry in entries:
                result = self._route_write(entry)
                if result.is_failure:
                    return result
                ldif_lines.append(result.unwrap())
            ldif_text = "\n".join(ldif_lines)
            if ldif_text and not ldif_text.endswith("\n"):
                ldif_text += "\n"
            return FlextResult.ok(ldif_text)

        def _handle_parse_entry(
            self,
            ldif_text: str,
        ) -> FlextResult[FlextLdifTypes.EntryOrString]:
            """Handle parse operation for entry quirk."""
            parse_result = self._route_parse(ldif_text)
            if parse_result.is_success:
                parsed_entries: list[FlextLdifModels.Entry] = parse_result.unwrap()
                return FlextResult[FlextLdifTypes.EntryOrString].ok(parsed_entries)
            error_msg: str = parse_result.error or "Parse failed"
            return FlextResult[FlextLdifTypes.EntryOrString].fail(error_msg)

        def _handle_write_entry(
            self,
            entries_to_write: list[FlextLdifModels.Entry],
        ) -> FlextResult[FlextLdifTypes.EntryOrString]:
            """Handle write operation for entry quirk."""
            write_result = self._route_write_many(entries_to_write)
            if write_result.is_success:
                written_text: str = write_result.unwrap()
                return FlextResult[FlextLdifTypes.EntryOrString].ok(written_text)
            error_msg: str = write_result.error or "Write failed"
            return FlextResult[FlextLdifTypes.EntryOrString].fail(error_msg)

        def execute(
            self,
            data: str | list[FlextLdifModels.Entry] | None = None,
            operation: Literal["parse", "write"] | None = None,
        ) -> FlextResult[FlextLdifTypes.EntryOrString]:
            r"""Execute entry quirk operation with automatic type detection and routing.

            Fully automatic polymorphic dispatch based on data type:
            - str (LDIF content) → parse_content() → list[Entry]
            - list[Entry] (models) → write_entry() for each → str (LDIF)
            - None → health check

            **V2 Usage as Processor - Maximum Automation:**
                >>> entry = FlextLdifServersRfc.Entry()
                >>> # Parse: pass LDIF string
                >>> entries = entry.execute("dn: cn=test\n...")
                >>> # Write: pass Entry list
                >>> ldif = entry.execute([entry1, entry2])
                >>> # Or use as callable processor
                >>> entries = entry("dn: cn=test\n...")  # Parse
                >>> ldif = entry([entry1, entry2])  # Write

            Args:
                data: LDIF content string OR list of Entry models
                      (operation auto-detected from type)
                operation: Force operation type (overrides auto-detection)

            Returns:
                FlextResult[list[Entry] | str] depending on operation

            Raises:
                Returns fail() if data type is unknown or operation fails

            """
            # Health check: no data provided
            if data is None:
                empty_list: list[FlextLdifModels.Entry] = []
                return FlextResult[FlextLdifTypes.EntryOrString].ok(empty_list)

            # Auto-detect operation from data type
            detected_operation = self._auto_detect_entry_operation(data, operation)
            if isinstance(detected_operation, FlextResult):
                return detected_operation

            # Route to appropriate handler
            return self._route_entry_operation(data, detected_operation)

        def _auto_detect_entry_operation(
            self,
            data: str | list[FlextLdifModels.Entry],
            operation: Literal["parse", "write"] | None,
        ) -> Literal["parse", "write"] | FlextResult[FlextLdifTypes.EntryOrString]:
            """Auto-detect entry operation from data type.

            If operation is forced (not None), uses it. Otherwise detects from type:
            - str → "parse"
            - list[Entry] → "write"
            - else → error

            """
            if operation is not None:
                return operation

            if isinstance(data, str):
                return "parse"

            # isinstance narrowed to list by type checker (data: str | list[Entry])
            if not data or all(
                isinstance(item, FlextLdifModels.Entry) for item in data
            ):
                return "write"
            return FlextResult[FlextLdifTypes.EntryOrString].fail(
                f"list contains unknown types, not Entry models: {[type(item).__name__ for item in data[:3]]}",
            )

        def _route_entry_operation(
            self,
            data: str | list[FlextLdifModels.Entry],
            operation: Literal["parse", "write"],
        ) -> FlextResult[FlextLdifTypes.EntryOrString]:
            """Route entry data to appropriate parse or write handler.

            Validates data type matches operation, then delegates to handler.

            """
            if operation == "parse":
                if not isinstance(data, str):
                    return FlextResult[FlextLdifTypes.EntryOrString].fail(
                        f"parse operation requires str, got {type(data).__name__}",
                    )
                return self._handle_parse_entry(data)

            if operation == "write":
                if not isinstance(data, list):
                    return FlextResult[FlextLdifTypes.EntryOrString].fail(
                        f"write operation requires list[Entry], got {type(data).__name__}",
                    )
                return self._handle_write_entry(data)

            # Should not reach here (Literal type ensures only parse or write)
            msg = f"Unknown operation: {operation}"
            raise AssertionError(msg)

        @overload
        def __call__(
            self,
            data: str,
            *,
            operation: Literal["parse"] | None = None,
        ) -> list[FlextLdifModels.Entry]: ...

        @overload
        def __call__(
            self,
            data: list[FlextLdifModels.Entry],
            *,
            operation: Literal["write"] | None = None,
        ) -> str: ...

        @overload
        def __call__(
            self,
            data: str | list[FlextLdifModels.Entry] | None = None,
            *,
            operation: Literal["parse", "write"] | None = None,
        ) -> FlextLdifTypes.EntryOrString: ...

        def __call__(
            self,
            data: str | list[FlextLdifModels.Entry] | None = None,
            *,
            operation: Literal["parse", "write"] | None = None,
        ) -> FlextLdifTypes.EntryOrString:
            """Callable interface - automatic polymorphic processor.

            Pass LDIF string for parsing or Entry list for writing.
            Type auto-detection handles routing automatically.
            """
            result = self.execute(data=data, operation=operation)
            return result.unwrap()

        def __new__(cls, entry_service: object | None = None, **kwargs: object) -> Self:
            """Override __new__ to support auto-execute and processor instantiation."""
            instance = super().__new__(cls)
            type(instance).__init__(instance, entry_service=entry_service, **kwargs)

            if cls.auto_execute:
                ldif_txt = (
                    cast("str | None", kwargs.get("ldif_text"))
                    if "ldif_text" in kwargs
                    else None
                )
                ent = (
                    cast("FlextLdifModels.Entry | None", kwargs.get("entry"))
                    if "entry" in kwargs
                    else None
                )
                ents = (
                    cast("list[FlextLdifModels.Entry] | None", kwargs.get("entries"))
                    if "entries" in kwargs
                    else None
                )
                op = (
                    cast("Literal['parse', 'write'] | None", kwargs.get("operation"))
                    if "operation" in kwargs
                    else None
                )
                # Entry.execute() expects 'data' parameter (str | list[Entry] | None)
                data: str | list[FlextLdifModels.Entry] | None = None
                if ldif_txt is not None:
                    data = ldif_txt
                elif ents is not None:
                    data = ents
                elif ent is not None:
                    data = [ent]
                result = instance.execute(data=data, operation=op)
                unwrapped: FlextLdifTypes.EntryOrString = result.unwrap()
                return cast("Self", unwrapped)

            return instance

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
            - Transform entry attributes for compatibility

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
            - Transform entry format for output compatibility

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
            - Empty string → return ok([])
            - Whitespace only → return ok([])
            - Malformed LDIF → return fail(message)
            - Encoding errors → catch UnicodeDecodeError, return fail()

            **NEVER raise exceptions** - return FlextResult.fail()

            Args:
                ldif_content: Raw LDIF content as string

            Returns:
                FlextResult with list[Entry] on success or fail(message)

            """
            _ = ldif_content  # Explicitly mark as intentionally unused in base
            return FlextResult.fail("Must be implemented by subclass")

        def parse_entry(
            self,
            entry_dn: str,
            entry_attrs: Mapping[str, object],
        ) -> FlextResult[FlextLdifModels.Entry]:
            """🔴 REQUIRED: Parse individual LDIF entry into Entry model (internal).

            Called by _parse_content() for each (dn, attrs) pair from ldif3.

            **You must:**
            1. Normalize DN (server-specific format)
            2. Convert raw attributes (handle bytes vs str)
            3. Create Entry model
            4. Return FlextResult.ok(entry)

            **IMPORTANT**: Do NOT call _hook_post_parse_entry() here!
            That hook is called by _parse_content() after you return.

            **Edge cases:**
            - Null DN → return fail("DN is None")
            - Empty DN string → return fail("DN is empty")
            - Null attributes → return fail("Attributes is None")
            - Empty attributes dict → return ok(entry) (valid!)
            - Bytes in attributes → convert to str
            - Non-string values → convert with str()

            Args:
                entry_dn: Raw DN string from LDIF parser
                entry_attrs: Raw attributes mapping (may contain bytes like {b'mail': [b'user@example.com']})

            Returns:
                FlextResult with Entry model or fail(message)

            """
            # Default RFC-compliant implementation
            # Servers can override for server-specific parsing logic
            if not entry_dn:
                return FlextResult[FlextLdifModels.Entry].fail("DN is None or empty")

            # Convert attributes to FlextLdifModels.LdifAttributes
            attrs_result = FlextLdifModels.LdifAttributes.create(dict(entry_attrs))
            if not attrs_result.is_success:
                return FlextResult[FlextLdifModels.Entry].fail(
                    f"Failed to create LdifAttributes: {attrs_result.error}",
                )
            converted_attrs = attrs_result.unwrap()

            # Create DistinguishedName object from DN string
            dn_obj = FlextLdifModels.DistinguishedName(value=entry_dn)

            # Create Entry model with defaults
            entry = FlextLdifModels.Entry(
                dn=dn_obj,
                attributes=converted_attrs,
            )

            return FlextResult[FlextLdifModels.Entry].ok(entry)

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
            - Null entry → return fail("Entry is None")
            - Missing DN → return fail("Entry DN is None")
            - Empty attributes → return ok("dn: ...\n\n")
            - Special chars in DN → proper escaping

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

    def __get__(self, obj: object | None, objtype: type | None = None) -> str:
        """Get SERVER_TYPE from Constants class - no fallbacks.

        __init_subclass__ already sets cls.server_type from Constants.SERVER_TYPE,
        so we look in MRO for the class-level attribute set there.
        """
        if objtype is None:
            objtype = type(obj) if obj is not None else FlextLdifServersBase

        # Get class-level server_type set by __init_subclass__
        for cls in objtype.__mro__:
            if "server_type" in cls.__dict__:
                return cast("str", cls.__dict__["server_type"])

        # Should never reach here - __init_subclass__ enforces Constants.SERVER_TYPE
        msg = f"{objtype.__name__} missing server_type (Constants.SERVER_TYPE not set)"
        raise AttributeError(msg)


class _PriorityDescriptor:
    """Descriptor that returns PRIORITY from Constants (single source of truth)."""

    def __get__(self, obj: object | None, objtype: type | None = None) -> int:
        """Get PRIORITY from Constants class - no fallbacks.

        __init_subclass__ already sets cls.priority from Constants.PRIORITY,
        so we look in MRO for the class-level attribute set there.
        """
        if objtype is None:
            objtype = type(obj) if obj is not None else FlextLdifServersBase

        # Get class-level priority set by __init_subclass__
        for cls in objtype.__mro__:
            if "priority" in cls.__dict__:
                return cast("int", cls.__dict__["priority"])

        # Should never reach here - __init_subclass__ enforces Constants.PRIORITY
        msg = f"{objtype.__name__} missing priority (Constants.PRIORITY not set)"
        raise AttributeError(msg)


# Attach descriptors to FlextLdifServersBase for class and instance access
# Descriptors implement __get__ returning str/int, satisfying the type annotations above
FlextLdifServersBase.server_type = _ServerTypeDescriptor()
FlextLdifServersBase.priority = _PriorityDescriptor()


__all__ = [
    "FlextLdifServersBase",
]
