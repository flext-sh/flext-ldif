"""DN Service - Distinguished Name Operations (RFC 4514)."""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Self, override

from flext_core import r
from pydantic import Field, PrivateAttr, field_validator

from flext_ldif._utilities.dn import FlextLdifUtilitiesDN
from flext_ldif._utilities.events import FlextLdifUtilitiesEvents
from flext_ldif.base import FlextLdifServiceBase
from flext_ldif.models import m

type DN = str


class FlextLdifDn(
    FlextLdifServiceBase[str],
):
    """RFC 4514 Compliant DN Operations Service with Nested Classes."""

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

    _last_event: m.Ldif.LdifResults.DnEvent | None = PrivateAttr(default=None)

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

    def _dispatch_operation(self) -> r[str]:
        """Dispatch operation to appropriate handler."""
        handlers: dict[str, Callable[[], r[str]]] = {
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

        handler: Callable[[], r[str]] | None = handlers.get(self.operation)
        if not handler:
            return r[str].fail(f"Unknown operation: {self.operation}")

        return handler()

    def _handle_compare(self) -> r[str]:
        """Handle compare operation with validation."""
        if not self.other_dn:
            return r[str].fail("other_dn required for compare operation")
        return self._parser.compare_operation(self.dn, self.other_dn)

    @override
    def execute(self) -> r[str]:
        """Execute DN operation based on configuration."""
        start_time = time.perf_counter() if self.enable_events else 0

        result = self._dispatch_operation()

        if self.enable_events and hasattr(self, "logger"):
            duration_ms = (time.perf_counter() - start_time) * 1000.0

            parse_components = None
            if self.operation == "parse" and result.is_success:
                parse_components = self.parse_components(self.dn).map_or(None)

            dn_config = m.Ldif.LdifResults.DnEventConfig(
                dn_operation=self.operation,
                input_dn=self.dn,
                output_dn=result.map_or(None),
                operation_duration_ms=duration_ms,
                validation_result=result.is_success
                if self.operation == "validate"
                else None,
                parse_components=parse_components,
            )
            event = FlextLdifUtilitiesEvents.log_and_emit_dn_event(
                logger=self.logger,
                config=dn_config,
                log_level="info" if result.is_success else "error",
            )

            object.__setattr__(self, "_last_event", event)

        return result

    def get_last_event(self) -> m.Ldif.LdifResults.DnEvent | None:
        """Retrieve last emitted DnEvent."""
        return self._last_event if hasattr(self, "_last_event") else None

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

    @classmethod
    def parse_components(cls, dn: str) -> r[list[tuple[str, str]]]:
        """Parse DN into RFC 4514 compliant components."""
        return cls.Parser.parse_components(dn)

    @classmethod
    def validate_format(cls, dn: str) -> r[bool]:
        """Validate DN format against RFC 4514."""
        return cls.Parser.validate_format(dn)

    @classmethod
    def normalize(cls, dn: str) -> r[str]:
        """Normalize DN per RFC 4514 (lowercase attrs, preserve values)."""
        return cls.Normalizer.normalize(dn)

    @classmethod
    def clean_dn(cls, dn: str) -> str:
        """Clean DN string to fix spacing and escaping issues."""
        return cls.Normalizer.clean_dn(dn)

    @classmethod
    def escape_dn_value(cls, value: str) -> str:
        """Escape special characters in DN value per RFC 4514."""
        return cls.Normalizer.escape_dn_value(value)

    @classmethod
    def unescape_dn_value(cls, value: str) -> str:
        """Unescape special characters in DN value per RFC 4514."""
        return cls.Normalizer.unescape_dn_value(value)

    @classmethod
    def compare_dns(cls, dn1: str, dn2: str) -> r[int]:
        """Compare two DNs per RFC 4514 (case-insensitive)."""
        return cls.Parser.compare_dns(dn1, dn2)

    @classmethod
    def parse_rdn(cls, rdn: str) -> r[list[tuple[str, str]]]:
        """Parse a single RDN (Relative Distinguished Name) component."""
        return cls.Parser.parse_rdn(rdn)

    def parse(self, dn: str | None) -> r[list[tuple[str, str]]]:
        """Instance method shortcut for parse_components."""
        if dn is None:
            return r[list[tuple[str, str]]].fail("DN cannot be None")
        return self.parse_components(dn)

    def validate_dn(self, dn: str | None) -> r[bool]:
        """Instance method shortcut for validate_format."""
        if dn is None:
            return r[bool].fail("DN cannot be None")
        return self.validate_format(dn)

    def norm(self, dn: str | None) -> r[str]:
        """Instance method shortcut for normalize."""
        if dn is None:
            return r[str].fail("DN cannot be None")
        return self.normalize(dn)

    def esc(self, value: str) -> str:
        """Instance method shortcut for escape_dn_value."""
        return self.escape_dn_value(value)

    def unesc(self, value: str) -> str:
        """Instance method shortcut for unescape_dn_value."""
        return self.unescape_dn_value(value)

    @classmethod
    def builder(cls) -> Self:
        """Create fluent builder instance."""
        return cls(dn="")

    def with_dn(self, dn: str) -> Self:
        """Set DN to operate on (fluent builder)."""
        return self.model_copy(update={"dn": dn})

    def with_operation(self, operation: str) -> Self:
        """Set operation to execute (fluent builder)."""
        return self.model_copy(update={"operation": operation})

    def with_escape_mode(self, mode: str) -> Self:
        """Set escape mode (fluent builder)."""
        return self.model_copy(update={"escape_mode": mode})

    def build(self) -> str:
        """Execute and return unwrapped result (fluent terminal)."""
        return self.execute().value

    class Parser:
        """Handles all DN parsing and validation operations."""

        @staticmethod
        def parse_components(dn: str) -> r[list[tuple[str, str]]]:
            """Parse DN into RFC 4514 compliant components."""
            return FlextLdifUtilitiesDN.parse(dn)

        @staticmethod
        def validate_format(dn: str) -> r[bool]:
            """Validate DN format against RFC 4514."""
            is_valid = FlextLdifUtilitiesDN.validate(dn)
            return r[bool].ok(is_valid)

        @staticmethod
        def parse_rdn(rdn: str) -> r[list[tuple[str, str]]]:
            """Parse a single RDN component."""
            return FlextLdifUtilitiesDN.parse_rdn(rdn)

        @staticmethod
        def compare_dns(dn1: str, dn2: str) -> r[int]:
            """Compare two DNs per RFC 4514 (case-insensitive)."""
            return FlextLdifUtilitiesDN.compare_dns(dn1, dn2)

        @staticmethod
        def parse_operation(dn: str) -> r[str]:
            """Parse DN operation (internal)."""
            return FlextLdifDn.Parser.parse_components(dn).map(
                lambda components: ", ".join(
                    f"{attr}={value}" for attr, value in components
                ),
            )

        @staticmethod
        def validate_operation(dn: str) -> r[str]:
            """Validate DN operation (internal)."""
            return FlextLdifDn.Parser.validate_format(dn).map(str)

        @staticmethod
        def compare_operation(dn1: str, dn2: str) -> r[str]:
            """Compare DN operation (internal)."""
            return FlextLdifDn.Parser.compare_dns(dn1, dn2).map(str)

        @staticmethod
        def parse_rdn_operation(dn: str) -> r[str]:
            """Parse RDN operation (internal)."""
            return FlextLdifDn.Parser.parse_rdn(dn).map(
                lambda pairs: ", ".join(f"{attr}={value}" for attr, value in pairs),
            )

    class Normalizer:
        """Handles DN normalization, cleaning, and escaping operations."""

        @staticmethod
        def normalize(dn: str) -> r[str]:
            """Normalize DN per RFC 4514."""
            return FlextLdifUtilitiesDN.norm(dn)

        @staticmethod
        def clean_dn(dn: str) -> str:
            """Clean DN string to fix spacing and escaping issues."""
            return FlextLdifUtilitiesDN.clean_dn(dn)

        @staticmethod
        def escape_dn_value(value: str) -> str:
            """Escape special characters in DN value per RFC 4514."""
            return FlextLdifUtilitiesDN.esc(value)

        @staticmethod
        def unescape_dn_value(value: str) -> str:
            """Unescape special characters in DN value per RFC 4514."""
            return FlextLdifUtilitiesDN.unesc(value)

        @staticmethod
        def hex_escape(value: str) -> str:
            r"""Convert string to hex escape format (\XX for each character)."""
            return "".join(f"\\{ord(char):02x}" for char in value)

        @staticmethod
        def hex_unescape(value: str) -> str:
            r"""Convert hex escape format (\XX) back to string."""
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
        def normalize_operation(dn: str) -> r[str]:
            """Normalize DN operation (internal)."""
            return FlextLdifDn.Normalizer.normalize(dn)

        @staticmethod
        def clean_operation(dn: str) -> r[str]:
            """Clean DN operation (internal)."""
            cleaned = FlextLdifDn.Normalizer.clean_dn(dn)
            return r[str].ok(cleaned)

        @staticmethod
        def escape_operation(dn: str, escape_mode: str) -> r[str]:
            """Escape DN operation (internal)."""
            if escape_mode == "hex":
                escaped = FlextLdifDn.Normalizer.hex_escape(dn)
            else:
                escaped = FlextLdifDn.Normalizer.escape_dn_value(dn)
            return r[str].ok(escaped)

        @staticmethod
        def unescape_operation(dn: str) -> r[str]:
            """Unescape DN operation (internal)."""
            unescaped = FlextLdifDn.Normalizer.unescape_dn_value(dn)
            return r[str].ok(unescaped)


__all__ = ["FlextLdifDn"]
