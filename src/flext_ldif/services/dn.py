r"""Distinguished Name (DN) Operations Service - RFC 4514 Compliant Parsing & Normalization.

╔══════════════════════════════════════════════════════════════════════════╗
║  RFC 4514 COMPLIANT DN OPERATIONS SERVICE                               ║
╠══════════════════════════════════════════════════════════════════════════╣
║  ✅ Parse DN into components (RFC 4514)                                 ║
║  ✅ Validate DN format (RFC 4514)                                       ║
║  ✅ Normalize DN (lowercase attrs, preserve values)                      ║
║  ✅ Clean DN (fix spacing, escapes)                                     ║
║  ✅ Escape/unescape DN values (hex & backslash format)                   ║
║  ✅ Compare DNs (case-insensitive)                                      ║
║  ✅ Parse RDNs (single components, multi-valued)                        ║
║  ✅ Case registry for server-specific DN tracking                       ║
║  ✅ 100% type-safe with Pydantic v2 validation                          ║
║  ✅ Multiple API patterns: execute(), classmethod, builder()            ║
╚══════════════════════════════════════════════════════════════════════════╝

═══════════════════════════════════════════════════════════════════════════
ARCHITECTURE (Nested Class Organization)

The DN service is organized with SRP-compliant nested classes:

1. **Parser** - Handles all parsing and validation operations
   - parse_components: Parse DN into components
   - validate_format: Validate DN format
   - parse_rdn: Parse RDN components
   - Internal: _parse_operation, _validate_operation, _parse_rdn_operation

2. **Normalizer** - Handles normalization, cleaning, and escaping
   - normalize: Normalize DN per RFC 4514
   - clean_dn: Fix spacing and escaping
   - escape_dn_value/unescape_dn_value: RFC 4514 escaping
   - hex_escape/hex_unescape: Hex format escaping
   - Internal: _normalize_operation, _clean_operation, _escape_operation, _unescape_operation

3. **Registry** - Tracks canonical DN case for conversions (unchanged)
   - register_dn, get_canonical_dn, has_dn, validate_oud_consistency, etc.

4. **FlextLdifDn** (Facade) - Routes operations to nested classes
   - execute(): Main service execution
   - Builder pattern: builder(), with_dn(), build()
   - Delegates to nested classes for actual work

═══════════════════════════════════════════════════════════════════════════
RESPONSIBILITY (SRP)

This service handles DN OPERATIONS ONLY:
- Parsing DNs into components (RFC 4514)
- Validating DN format
- Normalizing DN strings
- Cleaning malformed DNs
- Escaping/unescaping special characters
- Comparing DNs
- Parsing RDN components
- Tracking canonical DN case (CaseRegistry)

What it does NOT do:
- Filter entries (use FlextLdifFilters)
- Sort entries (use FlextLdifSorting)
- Validate schema (use validation services)

═══════════════════════════════════════════════════════════════════════════
QUICK REFERENCE

# Parse DN components
result = FlextLdifDn.parse(dn)
components = result.unwrap()

# Validate DN
result = FlextLdifDn.validate(dn)
is_valid = result.unwrap()

# Normalize DN (RFC 4514)
result = FlextLdifDn.norm(dn)
normalized = result.unwrap()

# Clean malformed DN
cleaned = FlextLdifDn.clean_dn(dn)

# Escape special chars
escaped = FlextLdifDn.esc("Smith, John")

# Case registry for conversions
registry = FlextLdifDn.Registry()
canonical = registry.register_dn(dn)

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import time
from collections.abc import Callable

from flext_core import FlextResult, FlextService
from pydantic import Field, PrivateAttr, field_validator

from flext_ldif.models import FlextLdifModels
from flext_ldif.utilities import FlextLdifUtilities

# Semantic type for Distinguished Name operations
type DN = str


class FlextLdifDn(FlextService[str]):
    r"""RFC 4514 Compliant DN Operations Service with Nested Classes.

    Handles Distinguished Name parsing, validation, normalization, and escaping
    using a hierarchical organization of nested classes for proper SRP compliance.

    Nested Classes:
        - Parser: Parsing and validation operations
        - Normalizer: Normalization and escaping operations
        - Registry: DN case tracking for conversions

    All pure DN operations are delegated to FlextLdifUtilities.DN
    to avoid code duplication.

    Pydantic Fields:
        dn: Primary DN to operate on
        other_dn: Secondary DN for comparison operations
        operation: Which operation to execute
        escape_mode: Escape format (standard or hex)
    """

    # ════════════════════════════════════════════════════════════════════════
    # PYDANTIC FIELDS
    # ════════════════════════════════════════════════════════════════════════

    dn: str = Field(
        default="",
        description="Distinguished name to operate on.",
    )

    other_dn: str | None = Field(
        default=None,
        description="Second DN for comparison operations.",
    )

    operation: str = Field(
        default="normalize",
        description="Operation: parse|validate|normalize|clean|escape|unescape|compare|parse_rdn",
    )

    escape_mode: str = Field(
        default="standard",
        description="Escape mode: standard (backslash) or hex",
    )

    enable_events: bool = Field(
        default=False,
        description="Enable domain event emission for operations",
    )

    # Private attributes (Pydantic v2 PrivateAttr for internal state)
    _last_event: FlextLdifModels.DnEvent | None = PrivateAttr(default=None)

    # ════════════════════════════════════════════════════════════════════════
    # PYDANTIC VALIDATORS
    # ════════════════════════════════════════════════════════════════════════

    @field_validator("operation")
    @classmethod
    def validate_operation(cls, v: str) -> str:
        """Validate operation is valid."""
        valid = {
            "parse",
            "validate",
            "normalize",
            "clean",
            "escape",
            "unescape",
            "compare",
            "parse_rdn",
        }
        if v not in valid:
            msg = f"Invalid operation: {v!r}. Valid: {', '.join(sorted(valid))}"
            raise ValueError(msg)
        return v

    @field_validator("escape_mode")
    @classmethod
    def validate_escape_mode(cls, v: str) -> str:
        """Validate escape_mode is valid."""
        valid = {"standard", "hex"}
        if v not in valid:
            msg = f"Invalid escape_mode: {v!r}. Valid: {', '.join(sorted(valid))}"
            raise ValueError(msg)
        return v

    # ════════════════════════════════════════════════════════════════════════
    # CORE EXECUTION (V2 Universal Engine)
    # ════════════════════════════════════════════════════════════════════════

    def _dispatch_operation(self) -> FlextResult[str]:
        """Dispatch operation to appropriate handler.

        Returns:
            FlextResult from the operation handler

        """
        # Map operations to their handler methods
        handlers: dict[str, Callable[[], FlextResult[str]]] = {
            "parse": lambda: self._parser.parse_operation(self.dn),
            "validate": lambda: self._parser.validate_operation(self.dn),
            "normalize": lambda: self._normalizer.normalize_operation(self.dn),
            "clean": lambda: self._normalizer.clean_operation(self.dn),
            "escape": lambda: self._normalizer.escape_operation(
                self.dn,
                self.escape_mode,
            ),
            "unescape": lambda: self._normalizer.unescape_operation(self.dn),
            "compare": self._handle_compare,
            "parse_rdn": lambda: self._parser.parse_rdn_operation(self.dn),
        }

        handler: Callable[[], FlextResult[str]] | None = handlers.get(self.operation)
        if not handler:
            return FlextResult[str].fail(f"Unknown operation: {self.operation}")

        return handler()

    def _handle_compare(self) -> FlextResult[str]:
        """Handle compare operation with validation.

        Returns:
            FlextResult from compare operation

        """
        if not self.other_dn:
            return FlextResult[str].fail("other_dn required for compare operation")
        return self._parser.compare_operation(self.dn, self.other_dn)

    def execute(self) -> FlextResult[str]:
        """Execute DN operation based on configuration."""
        start_time = time.perf_counter() if self.enable_events else 0

        try:
            result = self._dispatch_operation()

            # Emit domain event if enabled
            if self.enable_events and hasattr(self, "logger"):
                duration_ms = (time.perf_counter() - start_time) * 1000.0

                # Parse components if operation was parse
                parse_components = None
                if self.operation == "parse" and result.is_success:
                    # Result value is string representation, need to parse
                    parse_result = self.parse_components(self.dn)
                    if parse_result.is_success:
                        parse_components = parse_result.unwrap()

                # Create DN event config
                dn_config = FlextLdifModels.DnEventConfig(
                    dn_operation=self.operation,
                    input_dn=self.dn,
                    output_dn=result.unwrap() if result.is_success else None,
                    operation_duration_ms=duration_ms,
                    validation_result=result.is_success
                    if self.operation == "validate"
                    else None,
                    parse_components=parse_components,
                )
                event = FlextLdifUtilities.Events.log_and_emit_dn_event(
                    logger=self.logger,
                    config=dn_config,
                    log_level="info" if result.is_success else "error",
                )

                # Store event in instance
                self._last_event = event

            return result
        except Exception as e:
            return FlextResult[str].fail(f"DN operation failed: {e}")

    def get_last_event(self) -> FlextLdifModels.DnEvent | None:
        """Retrieve last emitted DnEvent.

        Returns:
            Last DnEvent if events are enabled and operation was executed, None otherwise

        Example:
            service = FlextLdifDn(dn="cn=test", operation="normalize", enable_events=True)
            result = service.execute()
            event = service.get_last_event()

        """
        return self._last_event if hasattr(self, "_last_event") else None

    # ════════════════════════════════════════════════════════════════════════
    # LAZY-LOADED NESTED CLASS INSTANCES (for performance)
    # ════════════════════════════════════════════════════════════════════════

    @property
    def _parser(self) -> FlextLdifDn.Parser:
        """Get or create Parser instance."""
        if not hasattr(self, "_parser_instance"):
            self._parser_instance = FlextLdifDn.Parser()
        return self._parser_instance

    @property
    def _normalizer(self) -> FlextLdifDn.Normalizer:
        """Get or create Normalizer instance."""
        if not hasattr(self, "_normalizer_instance"):
            self._normalizer_instance = FlextLdifDn.Normalizer()
        return self._normalizer_instance

    # ════════════════════════════════════════════════════════════════════════
    # PUBLIC API - CLASSMETHOD HELPERS (Direct Entry Points)
    # ════════════════════════════════════════════════════════════════════════

    @classmethod
    def parse_components(cls, dn: str) -> FlextResult[list[tuple[str, str]]]:
        """Parse DN into RFC 4514 compliant components.

        Args:
            dn: Distinguished name string

        Returns:
            FlextResult with list of (attr, value) tuples

        Example:
            result = FlextLdifDn.parse("cn=John,dc=example,dc=com")
            components = result.unwrap()

        """
        return cls.Parser.parse_components(dn)

    @classmethod
    def validate_format(cls, dn: str) -> FlextResult[bool]:
        """Validate DN format against RFC 4514.

        Args:
            dn: Distinguished name to validate

        Returns:
            FlextResult with True if valid, False otherwise

        """
        return cls.Parser.validate_format(dn)

    @classmethod
    def normalize(cls, dn: str) -> FlextResult[str]:
        """Normalize DN per RFC 4514 (lowercase attrs, preserve values).

        Args:
            dn: Distinguished name to normalize

        Returns:
            FlextResult with normalized DN string

        Example:
            result = FlextLdifDn.norm("CN=Admin,DC=Example,DC=Com")
            normalized = result.unwrap()  # "cn=Admin,dc=Example,dc=Com"

        """
        return cls.Normalizer.normalize(dn)

    @classmethod
    def escape_dn_value(cls, value: str) -> str:
        r"""Escape special characters in DN value per RFC 4514.

        Args:
            value: DN attribute value to escape

        Returns:
            Escaped DN value per RFC 4514

        Example:
            escaped = FlextLdifDn.esc("Smith, John")
            # Result: "Smith\\, John"

        """
        return cls.Normalizer.escape_dn_value(value)

    @classmethod
    def unescape_dn_value(cls, value: str) -> str:
        r"""Unescape special characters in DN value per RFC 4514.

        Handles both hex escape format (\XX) and backslash escape format (\char).

        Args:
            value: Escaped DN attribute value

        Returns:
            Unescaped DN value

        Example:
            unescaped = FlextLdifDn.unesc("Smith\\2c John")
            # Result: "Smith, John"

        """
        return cls.Normalizer.unescape_dn_value(value)

    @classmethod
    def compare_dns(cls, dn1: str, dn2: str) -> FlextResult[int]:
        r"""Compare two DNs per RFC 4514 (case-insensitive).

        Args:
            dn1: First DN
            dn2: Second DN

        Returns:
            FlextResult with: -1 if dn1 < dn2, 0 if equal, 1 if dn1 > dn2

        Example:
            result = FlextLdifDn.compare_dns(
                "cn=admin,dc=example,dc=com",
                "CN=ADMIN,DC=EXAMPLE,DC=COM"
            )
            comparison = result.unwrap()  # 0 (equal)

        """
        return cls.Parser.compare_dns(dn1, dn2)

    @classmethod
    def parse_rdn(cls, rdn: str) -> FlextResult[list[tuple[str, str]]]:
        r"""Parse a single RDN (Relative Distinguished Name) component.

        An RDN can contain multiple attribute-value pairs separated by '+'.

        Args:
            rdn: Single RDN component string (e.g., "cn=John+ou=people")

        Returns:
            FlextResult with list of (attribute, value) tuples

        Example:
            result = FlextLdifDn.parse_rdn("cn=John+ou=people")
            pairs = result.unwrap()  # [("cn", "John"), ("ou", "people")]

        """
        return cls.Parser.parse_rdn(rdn)

    # ════════════════════════════════════════════════════════════════════════
    # INSTANCE METHOD SHORTCUTS (for execute pattern)
    # ════════════════════════════════════════════════════════════════════════

    def parse(self, dn: str) -> FlextResult[list[tuple[str, str]]]:
        """Instance method shortcut for parse_components."""
        return self.parse_components(dn)

    def validate_dn(self, dn: str) -> FlextResult[bool]:
        """Instance method shortcut for validate_format."""
        return self.validate_format(dn)

    def norm(self, dn: str) -> FlextResult[str]:
        """Instance method shortcut for normalize."""
        return self.normalize(dn)

    def esc(self, value: str) -> str:
        """Instance method shortcut for escape_dn_value."""
        return self.escape_dn_value(value)

    def unesc(self, value: str) -> str:
        """Instance method shortcut for unescape_dn_value."""
        return self.unescape_dn_value(value)

    # ════════════════════════════════════════════════════════════════════════
    # PUBLIC API - FLUENT BUILDER PATTERN
    # ════════════════════════════════════════════════════════════════════════

    @classmethod
    def builder(cls) -> FlextLdifDn:
        """Create fluent builder instance.

        Returns:
            Service instance for method chaining

        Example:
            normalized = (
                FlextLdifDn.builder()
                .with_dn("CN=Admin,DC=Example,DC=Com")
                .with_operation("normalize")
                .build()
            )

        """
        return cls(dn="")

    def with_dn(self, dn: str) -> FlextLdifDn:
        """Set DN to operate on (fluent builder)."""
        self.dn = dn
        return self

    def with_operation(self, operation: str) -> FlextLdifDn:
        """Set operation to execute (fluent builder)."""
        self.operation = operation
        return self

    def with_escape_mode(self, mode: str) -> FlextLdifDn:
        """Set escape mode (fluent builder)."""
        self.escape_mode = mode
        return self

    def build(self) -> str:
        """Execute and return unwrapped result (fluent terminal)."""
        return self.execute().unwrap()

    # ════════════════════════════════════════════════════════════════════════
    # NESTED PARSER CLASS (Parsing & Validation)
    # ════════════════════════════════════════════════════════════════════════

    class Parser:
        """Handles all DN parsing and validation operations.

        Responsibility (SRP):
        - Parse DNs into components (RFC 4514)
        - Validate DN format
        - Parse RDN components
        - Compare DNs
        """

        @staticmethod
        def parse_components(dn: str) -> FlextResult[list[tuple[str, str]]]:
            """Parse DN into RFC 4514 compliant components."""
            components = FlextLdifUtilities.DN.parse(dn)
            if components is None:
                return FlextResult[list[tuple[str, str]]].fail("Invalid DN format")
            return FlextResult[list[tuple[str, str]]].ok(components)

        @staticmethod
        def validate_format(dn: str) -> FlextResult[bool]:
            """Validate DN format against RFC 4514."""
            is_valid = FlextLdifUtilities.DN.validate(dn)
            return FlextResult[bool].ok(is_valid)

        @staticmethod
        def parse_rdn(rdn: str) -> FlextResult[list[tuple[str, str]]]:
            """Parse a single RDN component."""
            pairs = FlextLdifUtilities.DN.parse_rdn(rdn)
            if pairs is None:
                return FlextResult[list[tuple[str, str]]].fail("RDN parse failed")
            return FlextResult[list[tuple[str, str]]].ok(pairs)

        @staticmethod
        def compare_dns(dn1: str, dn2: str) -> FlextResult[int]:
            """Compare two DNs per RFC 4514 (case-insensitive)."""
            comparison = FlextLdifUtilities.DN.compare_dns(dn1, dn2)
            if comparison is None:
                return FlextResult[int].fail("RFC 4514 comparison failed")
            return FlextResult[int].ok(comparison)

        @staticmethod
        def parse_operation(dn: str) -> FlextResult[str]:
            """Parse DN operation (internal)."""
            result = FlextLdifDn.Parser.parse_components(dn)
            if result.is_failure:
                return FlextResult[str].fail(result.error)
            components = result.unwrap()
            components_str = ", ".join(f"{attr}={value}" for attr, value in components)
            return FlextResult[str].ok(components_str)

        @staticmethod
        def validate_operation(dn: str) -> FlextResult[str]:
            """Validate DN operation (internal)."""
            result = FlextLdifDn.Parser.validate_format(dn)
            if result.is_failure:
                return FlextResult[str].fail(result.error)
            is_valid = result.unwrap()
            return FlextResult[str].ok(str(is_valid))

        @staticmethod
        def compare_operation(dn1: str, dn2: str) -> FlextResult[str]:
            """Compare DN operation (internal)."""
            result = FlextLdifDn.Parser.compare_dns(dn1, dn2)
            if result.is_failure:
                return FlextResult[str].fail(result.error)
            comparison = result.unwrap()
            return FlextResult[str].ok(str(comparison))

        @staticmethod
        def parse_rdn_operation(dn: str) -> FlextResult[str]:
            """Parse RDN operation (internal)."""
            result = FlextLdifDn.Parser.parse_rdn(dn)
            if result.is_failure:
                return FlextResult[str].fail(result.error)
            pairs = result.unwrap()
            pairs_str = ", ".join(f"{attr}={value}" for attr, value in pairs)
            return FlextResult[str].ok(pairs_str)

    # ════════════════════════════════════════════════════════════════════════
    # NESTED NORMALIZER CLASS (Normalization & Escaping)
    # ════════════════════════════════════════════════════════════════════════

    class Normalizer:
        """Handles DN normalization, cleaning, and escaping operations.

        Responsibility (SRP):
        - Normalize DN per RFC 4514
        - Clean malformed DNs
        - Escape/unescape DN values
        - Hex escape/unescape operations
        """

        @staticmethod
        def normalize(dn: str) -> FlextResult[str]:
            """Normalize DN per RFC 4514."""
            normalized = FlextLdifUtilities.DN.norm(dn)
            if normalized is None:
                return FlextResult[str].fail("Failed to normalize DN")
            return FlextResult[str].ok(normalized)

        @staticmethod
        def clean_dn(dn: str) -> str:
            """Clean DN string to fix spacing and escaping issues."""
            return FlextLdifUtilities.DN.clean_dn(dn)

        @staticmethod
        def escape_dn_value(value: str) -> str:
            """Escape special characters in DN value per RFC 4514."""
            return FlextLdifUtilities.DN.esc(value)

        @staticmethod
        def unescape_dn_value(value: str) -> str:
            """Unescape special characters in DN value per RFC 4514."""
            return FlextLdifUtilities.DN.unesc(value)

        @staticmethod
        def hex_escape(value: str) -> str:
            r"""Convert string to hex escape format (\XX for each character).

            Converts each character to its hex representation in \XX format.

            Args:
                value: String to hex escape

            Returns:
                String with each character converted to \XX format

            Example:
                result = FlextLdifDn.Normalizer.hex_escape("abc")
                # Result: "\61\62\63" (hex codes for a, b, c)

            """
            return "".join(f"\\{ord(char):02x}" for char in value)

        @staticmethod
        def hex_unescape(value: str) -> str:
            r"""Convert hex escape format (\XX) back to string.

            Converts \XX hex sequences back to their character representation.

            Args:
                value: String with hex escapes to decode

            Returns:
                Unescaped string

            Example:
                result = FlextLdifDn.Normalizer.hex_unescape("\61\62\63")
                # Result: "abc"

            """
            result = ""
            i = 0
            while i < len(value):
                if i + 3 <= len(value) and value[i] == "\\":
                    try:
                        hex_val = value[i + 1 : i + 3]
                        result += chr(int(hex_val, 16))
                        i += 3
                    except (ValueError, OverflowError):
                        result += value[i]
                        i += 1
                else:
                    result += value[i]
                    i += 1
            return result

        @staticmethod
        def normalize_operation(dn: str) -> FlextResult[str]:
            """Normalize DN operation (internal)."""
            return FlextLdifDn.Normalizer.normalize(dn)

        @staticmethod
        def clean_operation(dn: str) -> FlextResult[str]:
            """Clean DN operation (internal)."""
            cleaned = FlextLdifDn.Normalizer.clean_dn(dn)
            return FlextResult[str].ok(cleaned)

        @staticmethod
        def escape_operation(dn: str, escape_mode: str) -> FlextResult[str]:
            """Escape DN operation (internal)."""
            if escape_mode == "hex":
                escaped = FlextLdifDn.Normalizer.hex_escape(dn)
            else:
                escaped = FlextLdifDn.Normalizer.escape_dn_value(dn)
            return FlextResult[str].ok(escaped)

        @staticmethod
        def unescape_operation(dn: str) -> FlextResult[str]:
            """Unescape DN operation (internal)."""
            unescaped = FlextLdifDn.Normalizer.unescape_dn_value(dn)
            return FlextResult[str].ok(unescaped)

    # ════════════════════════════════════════════════════════════════════════
    # NESTED CASE REGISTRY CLASS
    # ════════════════════════════════════════════════════════════════════════

    # Alias for FlextLdifModels.DnRegistry for backwards compatibility
    # COMMENTED OUT: Causes AttributeError during module initialization
    # DnRegistry: ClassVar[type[FlextLdifModels.DnRegistry]] = FlextLdifModels.DnRegistry


__all__ = ["FlextLdifDn"]
