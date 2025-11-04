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
- Filter entries (use FlextLdifFilterService)
- Sort entries (use FlextLdifSortingService)
- Validate schema (use validation services)

═══════════════════════════════════════════════════════════════════════════
ARCHITECTURE NOTE

All pure DN operations are implemented in FlextLdifUtilities.DN.
This service wraps them with FlextResult for FLEXT-compatible APIs:
- execute() pattern for FlextService compliance
- Classmethod helpers for direct usage
- Builder pattern for fluent API

No code duplication: All logic lives in utilities.DN.

═══════════════════════════════════════════════════════════════════════════
QUICK REFERENCE

# Parse DN components
result = FlextLdifDnService.parse(dn)
components = result.unwrap()

# Validate DN
result = FlextLdifDnService.validate(dn)
is_valid = result.unwrap()

# Normalize DN (RFC 4514)
result = FlextLdifDnService.norm(dn)
normalized = result.unwrap()

# Clean malformed DN
cleaned = FlextLdifDnService.clean_dn(dn)

# Escape special chars
escaped = FlextLdifDnService.esc("Smith, John")

# Case registry for conversions
registry = FlextLdifDnService.CaseRegistry()
canonical = registry.register_dn(dn)

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import override

from flext_core import FlextDecorators, FlextModels, FlextResult, FlextService
from pydantic import ConfigDict, Field, field_validator

from flext_ldif.utilities import FlextLdifUtilities

type DN = str


class FlextLdifDnService(FlextService[str]):
    r"""RFC 4514 Compliant DN Operations Service.

    Handles Distinguished Name parsing, validation, normalization, and escaping.
    Uses ldap3.utils.dn for RFC 4514 compliant parsing.

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

    @override
    @FlextDecorators.log_operation("dn_operation")
    @FlextDecorators.track_performance()
    def execute(self) -> FlextResult[str]:
        """Execute DN operation based on configuration."""
        try:
            match self.operation:
                case "parse":
                    return self._parse_operation()
                case "validate":
                    return self._validate_operation()
                case "normalize":
                    return self._normalize_operation()
                case "clean":
                    return self._clean_operation()
                case "escape":
                    return self._escape_operation()
                case "unescape":
                    return self._unescape_operation()
                case "compare":
                    return self._compare_operation()
                case "parse_rdn":
                    return self._parse_rdn_operation()
                case _:
                    return FlextResult[str].fail(f"Unknown operation: {self.operation}")
        except Exception as e:
            return FlextResult[str].fail(f"DN operation failed: {e}")

    # ════════════════════════════════════════════════════════════════════════
    # PUBLIC API - CLASSMETHOD HELPERS (Direct Entry Points)
    # Delegates to FlextLdifUtilities.DN for pure functions
    # ════════════════════════════════════════════════════════════════════════

    @classmethod
    def parse_components(cls, dn: str) -> FlextResult[list[tuple[str, str, str]]]:
        """Parse DN into RFC 4514 compliant components.

        Args:
            dn: Distinguished name string

        Returns:
            FlextResult with list of (attr, value, rdn) tuples

        Example:
            result = FlextLdifDnService.parse("cn=John,dc=example,dc=com")
            components = result.unwrap()

        """
        components = FlextLdifUtilities.DN.parse(dn)
        if components is None:
            return FlextResult[list[tuple[str, str, str]]].fail("Parse failed")
        return FlextResult[list[tuple[str, str, str]]].ok(components)

    @classmethod
    def validate_format(cls, dn: str) -> FlextResult[bool]:
        """Validate DN format against RFC 4514.

        Args:
            dn: Distinguished name to validate

        Returns:
            FlextResult with True if valid, False otherwise

        """
        is_valid = FlextLdifUtilities.DN.validate(dn)
        return FlextResult[bool].ok(is_valid)

    @classmethod
    def normalize(cls, dn: str) -> FlextResult[str]:
        """Normalize DN per RFC 4514 (lowercase attrs, preserve values).

        Args:
            dn: Distinguished name to normalize

        Returns:
            FlextResult with normalized DN string

        Example:
            result = FlextLdifDnService.norm("CN=Admin,DC=Example,DC=Com")
            normalized = result.unwrap()  # "cn=Admin,dc=Example,dc=Com"

        """
        normalized = FlextLdifUtilities.DN.norm(dn)
        if normalized is None:
            return FlextResult[str].fail("Normalize failed")
        return FlextResult[str].ok(normalized)

    @classmethod
    def clean_dn(cls, dn: str) -> str:
        r"""Clean DN string to fix spacing and escaping issues.

        Fixes common formatting issues found in LDAP exports:
        - Removes spaces around '=' in RDN components
        - Fixes trailing backslash+space patterns
        - Normalizes whitespace around commas
        - Removes unnecessary character escapes

        Args:
            dn: Raw DN string from LDIF

        Returns:
            Cleaned DN string (static method, no FlextResult)

        Example:
            cleaned = FlextLdifDnService.clean_dn("cn = John , dc = example , dc = com")
            # Result: "cn=John,dc=example,dc=com"

        """
        return FlextLdifUtilities.DN.clean_dn(dn)

    @classmethod
    def escape_dn_value(cls, value: str) -> str:
        r"""Escape special characters in DN value per RFC 4514.

        Args:
            value: DN attribute value to escape

        Returns:
            Escaped DN value per RFC 4514

        Example:
            escaped = FlextLdifDnService.esc("Smith, John")
            # Result: "Smith\\, John"

        """
        return FlextLdifUtilities.DN.esc(value)

    @classmethod
    def unescape_dn_value(cls, value: str) -> str:
        r"""Unescape special characters in DN value per RFC 4514.

        Handles both hex escape format (\XX) and backslash escape format (\char).

        Args:
            value: Escaped DN attribute value

        Returns:
            Unescaped DN value

        Example:
            unescaped = FlextLdifDnService.unesc("Smith\\2c John")
            # Result: "Smith, John"

        """
        return FlextLdifUtilities.DN.unesc(value)

    @classmethod
    def compare_dns(cls, dn1: str, dn2: str) -> FlextResult[int]:
        r"""Compare two DNs per RFC 4514 (case-insensitive).

        Args:
            dn1: First DN
            dn2: Second DN

        Returns:
            FlextResult with: -1 if dn1 < dn2, 0 if equal, 1 if dn1 > dn2

        Example:
            result = FlextLdifDnService.compare_dns(
                "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
                "CN=ADMIN,DC=EXAMPLE,DC=COM"
            )
            comparison = result.unwrap()  # 0 (equal)

        """
        comparison = FlextLdifUtilities.DN.compare_dns(dn1, dn2)
        if comparison is None:
            return FlextResult[int].fail("Comparison failed")
        return FlextResult[int].ok(comparison)

    @classmethod
    def parse_rdn(cls, rdn: str) -> FlextResult[list[tuple[str, str]]]:
        r"""Parse a single RDN (Relative Distinguished Name) component.

        An RDN can contain multiple attribute-value pairs separated by '+'.

        Args:
            rdn: Single RDN component string (e.g., "cn=John+ou=people")

        Returns:
            FlextResult with list of (attribute, value) tuples

        Example:
            result = FlextLdifDnService.parse_rdn("cn=John+ou=people")
            pairs = result.unwrap()  # [("cn", "John"), ("ou", "people")]

        """
        pairs = FlextLdifUtilities.DN.parse_rdn(rdn)
        if pairs is None:
            return FlextResult[list[tuple[str, str]]].fail("RDN parse failed")
        return FlextResult[list[tuple[str, str]]].ok(pairs)

    # ════════════════════════════════════════════════════════════════════════
    # INSTANCE METHOD SHORTCUTS (for execute pattern)
    # ════════════════════════════════════════════════════════════════════════

    def parse(self, dn: str) -> FlextResult[list[tuple[str, str, str]]]:
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
    def builder(cls) -> FlextLdifDnService:
        """Create fluent builder instance.

        Returns:
            Service instance for method chaining

        Example:
            normalized = (
                FlextLdifDnService.builder()
                .with_dn("CN=Admin,DC=Example,DC=Com")
                .with_operation("normalize")
                .build()
            )

        """
        return cls(dn="")

    def with_dn(self, dn: str) -> FlextLdifDnService:
        """Set DN to operate on (fluent builder)."""
        self.dn = dn
        return self

    def with_operation(self, operation: str) -> FlextLdifDnService:
        """Set operation to execute (fluent builder)."""
        self.operation = operation
        return self

    def with_escape_mode(self, mode: str) -> FlextLdifDnService:
        """Set escape mode (fluent builder)."""
        self.escape_mode = mode
        return self

    def build(self) -> str:
        """Execute and return unwrapped result (fluent terminal)."""
        return self.execute().unwrap()

    # ════════════════════════════════════════════════════════════════════════
    # PRIVATE IMPLEMENTATION (DRY Core)
    # ════════════════════════════════════════════════════════════════════════

    def _parse_operation(self) -> FlextResult[str]:
        """Parse DN operation."""
        result = self.parse(self.dn)
        if result.is_failure:
            return FlextResult[str].fail(result.error)

        components = result.unwrap()
        components_str = ", ".join(f"{attr}={value}" for attr, value, _ in components)
        return FlextResult[str].ok(components_str)

    def _validate_operation(self) -> FlextResult[str]:
        """Validate DN operation."""
        result = self.validate_dn(self.dn)
        if result.is_failure:
            return FlextResult[str].fail(result.error)
        is_valid = result.unwrap()
        return FlextResult[str].ok(str(is_valid))

    def _normalize_operation(self) -> FlextResult[str]:
        """Normalize DN operation."""
        return self.norm(self.dn)

    def _clean_operation(self) -> FlextResult[str]:
        """Clean DN operation."""
        cleaned = self.clean_dn(self.dn)
        return FlextResult[str].ok(cleaned)

    def _escape_operation(self) -> FlextResult[str]:
        """Escape DN operation."""
        escaped = self.esc(self.dn)
        return FlextResult[str].ok(escaped)

    def _unescape_operation(self) -> FlextResult[str]:
        """Unescape DN operation."""
        unescaped = self.unesc(self.dn)
        return FlextResult[str].ok(unescaped)

    def _compare_operation(self) -> FlextResult[str]:
        """Compare DN operation."""
        if not self.other_dn:
            return FlextResult[str].fail("other_dn required for compare operation")

        result = self.compare_dns(self.dn, self.other_dn)
        if result.is_failure:
            return FlextResult[str].fail(result.error)

        comparison = result.unwrap()
        return FlextResult[str].ok(str(comparison))

    def _parse_rdn_operation(self) -> FlextResult[str]:
        """Parse RDN operation."""
        result = self.parse_rdn(self.dn)
        if result.is_failure:
            return FlextResult[str].fail(result.error)

        pairs = result.unwrap()
        pairs_str = ", ".join(f"{attr}={value}" for attr, value in pairs)
        return FlextResult[str].ok(pairs_str)

    # ════════════════════════════════════════════════════════════════════════
    # NESTED CASE REGISTRY CLASS
    # ════════════════════════════════════════════════════════════════════════

    class CaseRegistry(FlextModels.Value):
        """Registry for tracking canonical DN case during conversions.

        This class maintains a mapping of DNs in normalized form (lowercase, no spaces)
        to their canonical case representation. Used during server conversions to
        ensure DN case consistency.

        Examples:
            registry = FlextLdifDnService.CaseRegistry()
            canonical = registry.register_dn("CN=Admin,DC=Example,DC=Com")
            result = registry.get_canonical_dn("cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com")

        """

        model_config = ConfigDict(frozen=False)

        def __init__(self) -> None:
            """Initialize empty DN case registry."""
            super().__init__()
            self._registry: dict[str, str] = {}
            self._case_variants: dict[str, set[str]] = {}

        def _normalize_dn(self, dn: str) -> str:
            """Normalize DN for case-insensitive comparison."""
            return dn.lower().replace(" ", "")

        def register_dn(self, dn: str, *, force: bool = False) -> str:
            """Register DN and return its canonical case.

            Args:
                dn: Distinguished Name to register
                force: If True, override existing canonical case

            Returns:
                Canonical case DN string

            Example:
                canonical = registry.register_dn("CN=Admin,DC=Com")

            """
            normalized = self._normalize_dn(dn)

            if normalized not in self._case_variants:
                self._case_variants[normalized] = set()
            self._case_variants[normalized].add(dn)

            if normalized not in self._registry or force:
                self._registry[normalized] = dn

            return self._registry[normalized]

        def get_canonical_dn(self, dn: str) -> str | None:
            """Get canonical case for a DN (case-insensitive lookup).

            Args:
                dn: Distinguished Name to lookup

            Returns:
                Canonical case DN string, or None if not registered

            """
            normalized = self._normalize_dn(dn)
            return self._registry.get(normalized)

        def has_dn(self, dn: str) -> bool:
            """Check if DN is registered (case-insensitive).

            Args:
                dn: Distinguished Name to check

            Returns:
                True if DN is registered, False otherwise

            """
            normalized = self._normalize_dn(dn)
            return normalized in self._registry

        def get_case_variants(self, dn: str) -> set[str]:
            """Get all case variants seen for a DN.

            Args:
                dn: Distinguished Name to get variants for

            Returns:
                Set of all case variants seen (including canonical)

            """
            normalized = self._normalize_dn(dn)
            return self._case_variants.get(normalized, set())

        def validate_oud_consistency(self) -> FlextResult[bool]:
            """Validate DN case consistency for server conversion.

            Returns:
                FlextResult[bool]: True if consistent, False with warnings if not

            """
            inconsistencies: list[dict[str, object]] = []

            for normalized_dn, variants in self._case_variants.items():
                if len(variants) > 1:
                    canonical = self._registry[normalized_dn]
                    inconsistencies.append({
                        "normalized_dn": normalized_dn,
                        "canonical_case": canonical,
                        "variants": list(variants),
                        "variant_count": len(variants),
                    })

            if inconsistencies:
                result = FlextResult[bool].ok(False)
                result.metadata = {
                    "inconsistencies": inconsistencies,
                    "warning": f"Found {len(inconsistencies)} DNs with case inconsistencies",
                }
                return result

            return FlextResult[bool].ok(True)

        def clear(self) -> None:
            """Clear all DN registrations."""
            self._registry.clear()
            self._case_variants.clear()

        def get_stats(self) -> dict[str, int]:
            """Get registry statistics.

            Returns:
                Dictionary with registry statistics

            """
            total_variants = sum(
                len(variants) for variants in self._case_variants.values()
            )
            multiple_variants = sum(
                1 for variants in self._case_variants.values() if len(variants) > 1
            )

            return {
                "total_dns": len(self._registry),
                "total_variants": total_variants,
                "dns_with_multiple_variants": multiple_variants,
            }


__all__ = ["FlextLdifDnService"]
