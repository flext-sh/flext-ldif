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
    - FlextLdifServersBase.Schema -> SchemaProtocol (structural typing)
    - FlextLdifServersBase.Acl -> AclProtocol (structural typing)
    - FlextLdifServersBase.Entry -> EntryProtocol (structural typing)

    All method signatures must match protocol definitions exactly for type safety.
"""

from __future__ import annotations

import re
from typing import ClassVar

from flext_core import FlextLogger, FlextResult, FlextService, FlextTypes
from pydantic import Field

from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif._models.metadata import FlextLdifModelsMetadata
from flext_ldif._utilities.acl import FlextLdifUtilitiesACL

# Removed: from flext_ldif.protocols import p (use string literals or hasattr checks)
from flext_ldif.servers._base.constants import QuirkMethodsMixin

# Removed: from flext_ldif.typings import dict[str, object] (use dict[str, object])

# Removed: from flext_ldif.utilities import u (not used - removed to break circular import)

logger = FlextLogger(__name__)


class FlextLdifServersBaseSchemaAcl(
    QuirkMethodsMixin,
    FlextService[FlextLdifModelsDomains.Acl | str],
):
    """Base class for ACL quirks - satisfies AclProtocol (structural typing).

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
    AclProtocol through structural typing (hasattr checks).
    This means all public methods must match protocol signatures exactly.

    **Validation**: Use hasattr(quirk, "parse") and hasattr(quirk, "write")
    to check protocol compliance at runtime (structural typing).

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
    server_type: str = "rfc"
    """Server type identifier (e.g., 'oid', 'oud', 'openldap', 'rfc')."""

    priority: int = 0
    """Quirk priority (lower number = higher priority)."""

    # Parent quirk reference for accessing server-level configuration
    parent_quirk: object | None = Field(
        default=None,
        exclude=True,
        repr=False,
        description=("Reference to parent quirk instance for server-level access"),
    )

    def __init__(
        self,
        acl_service: object | None = None,
        _parent_quirk: object | None = None,
        **kwargs: FlextTypes.GeneralValueType,
    ) -> None:
        """Initialize ACL quirk service with optional DI service injection.

        Args:
            acl_service: Injected FlextLdifAcl service (optional, lazy-created if None)
            _parent_quirk: Reference to parent quirk instance
            **kwargs: Additional initialization parameters for FlextService

        Note:
            server_type and priority are no longer passed to nested classes.
            They should be accessed via _get_server_type() and Constants.PRIORITY
            from the parent server class.

        """
        super().__init__(**kwargs)
        self._acl_service = acl_service  # Store for use by subclasses
        # Store _parent_quirk using object.__setattr__ to avoid Pydantic validation
        # (it's not a Pydantic field, just an internal reference)
        if _parent_quirk is not None:
            object.__setattr__(self, "_parent_quirk", _parent_quirk)
        # Note: server_type and priority descriptors are only available on parent server classes
        # Nested classes (Schema/Acl/Entry) access them via _get_server_type() from QuirkMethodsMixin

    # _get_server_type, _get_priority, _get_parent_quirk_safe are provided by QuirkMethodsMixin

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
        acl: FlextLdifModelsDomains.Acl,
    ) -> FlextResult[FlextLdifModelsDomains.Acl]:
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

    def can_handle_acl(self, acl_line: str | FlextLdifModelsDomains.Acl) -> bool:
        """Check if this quirk can handle the ACL definition.

        Called BEFORE parsing to detect if this quirk should process the ACL line.
        Receives the raw ACL line string (e.g., "orclaci: { ... }") or Acl model.

        Args:
            acl_line: ACL definition line string

        Returns:
            True if this quirk can handle this ACL definition

        """
        _ = acl_line  # Explicitly mark as intentionally unused in base
        return (
            False  # Must be implemented by subclass  # Must be implemented by subclass
        )

    def can_handle(self, acl_line: str | FlextLdifModelsDomains.Acl) -> bool:
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

    def _supports_feature(self, _feature_id: str) -> bool:
        """Check if this server supports a specific feature.

        Generic implementation that checks if feature_id is in
        RFC_STANDARD_FEATURES. This method is available to all server
        implementations.

        Subclasses can override to declare additional supported features
        beyond RFC_STANDARD_FEATURES.

        Args:
            _feature_id: Feature ID from FeatureCapabilities (unused in base)

        Returns:
            True if feature is supported, False otherwise.

        """
        # RFC standard features - use empty set as default (subclasses can override)
        return False

    def _get_feature_fallback(self, _feature_id: str) -> str | None:
        """Get RFC fallback value for unsupported vendor feature.

        Generic implementation that uses FeatureCapabilities.RFC_FALLBACKS
        for standard fallbacks. This method is available to all server
        implementations.

        Subclasses can override to customize fallback behavior.

        Returns:
            Fallback permission string, or None if no fallback.

        """
        # RFC fallbacks - use empty dict as default (subclasses can override)
        return None

    # =====================================================================
    # Public Interface Methods - Moved to rfc.py.Acl
    # =====================================================================
    # parse, can_handle, write are now concrete implementations in
    # FlextLdifServersRfc.Acl. Subclasses should override _parse_acl,
    # _write_acl, and can_handle_acl for server-specific logic.

    def _parse_acl(self, acl_line: str) -> FlextResult[FlextLdifModelsDomains.Acl]:
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
        attribute: FlextLdifModelsDomains.SchemaAttribute,
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
        return (
            False  # Must be implemented by subclass  # Must be implemented by subclass
        )

    def can_handle_objectclass(
        self,
        objectclass: FlextLdifModelsDomains.SchemaObjectClass,
    ) -> bool:
        """Check if this ACL quirk should be aware of a specific objectClass definition.

        ACL quirks may need to evaluate rules based on objectClass properties.

        Args:
            objectclass: The SchemaObjectClass model.

        Returns:
            True if this quirk has specific logic related to this objectClass.

        """
        _ = objectclass  # Explicitly mark as intentionally unused in base
        return (
            False  # Must be implemented by subclass  # Must be implemented by subclass
        )

    def _write_acl(self, acl_data: FlextLdifModelsDomains.Acl) -> FlextResult[str]:
        """Write ACL data to RFC-compliant string format (internal).

        Base class stub - must be implemented by subclass.

        Args:
            acl_data: Acl model

        Returns:
            FlextResult.fail with "Must be implemented by subclass"

        """
        _ = acl_data
        return FlextResult[str].fail("Must be implemented by subclass")

    def parse(self, acl_line: str) -> FlextResult[FlextLdifModelsDomains.Acl]:
        """Parse ACL line to Acl model.

        This satisfies AclProtocol (structural typing via hasattr checks).

        Args:
            acl_line: ACL definition line

        Returns:
            FlextResult with Acl model

        """
        return self._parse_acl(acl_line)

    def write(self, acl_data: FlextLdifModelsDomains.Acl) -> FlextResult[str]:
        """Write Acl model to string format.

        This satisfies AclProtocol (structural typing via hasattr checks).

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
        str | FlextLdifModelsDomains.Acl | None,
        str | None,
    ]:
        """Extract and validate ACL operation parameters from kwargs.

        Args:
            kwargs: Keyword arguments containing 'data' and optional 'operation'

        Returns:
            Tuple of (data, operation) with type narrowing applied

        """
        # Extract data parameter
        data_raw = kwargs.get("data")
        data: str | FlextLdifModelsDomains.Acl | None = (
            data_raw
            if isinstance(data_raw, (str, FlextLdifModelsDomains.Acl, type(None)))
            else None
        )

        # Extract operation parameter with type narrowing
        # Business Rule: isinstance check with literal values provides type narrowing
        # Implication: No cast needed - type checker can infer the correct type from the guard
        operation_raw = kwargs.get("operation")
        operation: str | None = None
        if isinstance(operation_raw, str) and operation_raw in {"parse", "write"}:
            # Type narrowing: pyrefly infers Literal['parse', 'write'] from the in-check
            # Direct assignment works because pyrefly narrows str to Literal after the in-check
            operation = "parse" if operation_raw == "parse" else "write"

        return data, operation

    def _execute_acl_parse(
        self,
        data: str,
    ) -> FlextResult[FlextLdifModelsDomains.Acl | str]:
        """Execute ACL parse operation.

        Args:
            data: ACL data string to parse

        Returns:
            FlextResult with parsed Acl model

        """
        parse_result = self.parse(data)
        if parse_result.is_success:
            return FlextResult[FlextLdifModelsDomains.Acl | str].ok(
                parse_result.unwrap()
            )
        return FlextResult[FlextLdifModelsDomains.Acl | str].fail(
            parse_result.error or "Parse failed",
        )

    def _execute_acl_write(
        self,
        data: FlextLdifModelsDomains.Acl,
    ) -> FlextResult[FlextLdifModelsDomains.Acl | str]:
        """Execute ACL write operation.

        Args:
            data: Acl model to write

        Returns:
            FlextResult with written string

        """
        write_result = self.write(data)
        if write_result.is_success:
            return FlextResult[FlextLdifModelsDomains.Acl | str].ok(
                write_result.unwrap()
            )
        return FlextResult[FlextLdifModelsDomains.Acl | str].fail(
            write_result.error or "Write failed",
        )

    def _resolve_data(
        self,
        data: str | FlextLdifModelsDomains.Acl | None,
        kwargs: dict[str, dict[str, object]],
    ) -> str | FlextLdifModelsDomains.Acl | None:
        """Resolve data from parameter or kwargs."""
        if data is not None:
            return data
        data_raw = kwargs.get("data")
        if isinstance(data_raw, (str, FlextLdifModelsDomains.Acl)):
            return data_raw
        return None

    def _resolve_operation(
        self,
        operation: str | None,
        kwargs: dict[str, dict[str, object]],
    ) -> str | None:
        """Resolve operation from parameter or kwargs."""
        if operation is not None:
            return operation
        operation_raw = kwargs.get("operation")
        if isinstance(operation_raw, str) and operation_raw in {"parse", "write"}:
            return operation_raw
        return None

    def _detect_operation(
        self,
        operation: str | None,
        data: str | FlextLdifModelsDomains.Acl,
    ) -> str:
        """Detect operation type from explicit param or data type."""
        if operation is not None and operation in {"parse", "write"}:
            # Type narrowing: return explicit literal based on value
            return "parse" if operation == "parse" else "write"
        return "parse" if isinstance(data, str) else "write"

    def execute(
        self,
        *,
        data: str | FlextLdifModelsDomains.Acl | None = None,
        operation: str | None = None,
        **kwargs: dict[str, object],
    ) -> FlextResult[FlextLdifModelsDomains.Acl | str]:
        """Execute ACL operation with auto-detection: str→parse, Acl→write.

        Business Rule: Auto-detects operation from data type unless explicitly
        specified. str data triggers parse, Acl model triggers write.

        Args:
            data: Input data (str for parse, Acl for write)
            operation: Force operation type ("parse" or "write")
            **kwargs: Additional parameters

        Returns:
            FlextResult with parsed Acl model or written string

        """
        kwargs_dict = dict(kwargs)
        data = self._resolve_data(data, kwargs_dict)
        operation = self._resolve_operation(operation, kwargs_dict)

        if data is None:
            return FlextResult[FlextLdifModelsDomains.Acl | str].ok(
                FlextLdifModelsDomains.Acl()
            )

        detected_op = self._detect_operation(operation, data)

        if detected_op == "parse":
            if not isinstance(data, str):
                return FlextResult[FlextLdifModelsDomains.Acl | str].fail(
                    f"parse requires str, got {type(data).__name__}",
                )
            return self._execute_acl_parse(data)

        if not isinstance(data, FlextLdifModelsDomains.Acl):
            return FlextResult[FlextLdifModelsDomains.Acl | str].fail(
                f"write requires Acl, got {type(data).__name__}",
            )
        return self._execute_acl_write(data)

    def create_metadata(
        self,
        original_format: str,
        extensions: dict[str, FlextTypes.MetadataAttributeValue] | None = None,
    ) -> FlextLdifModelsDomains.QuirkMetadata:
        """Create ACL quirk metadata.

        Generic implementation that creates QuirkMetadata with quirk_type
        and extensions. This method is available to all server implementations.

        Args:
            original_format: Original ACL format string to store in metadata.
            extensions: Optional additional extensions to include in metadata.

        Returns:
            QuirkMetadata with quirk_type and extensions.

        """
        all_extensions: dict[str, FlextTypes.MetadataAttributeValue] = {
            "original_format": original_format,
        }
        if extensions:
            all_extensions.update(extensions)
        # Convert dict to DynamicMetadata for QuirkMetadata
        extensions_model = FlextLdifModelsMetadata.DynamicMetadata(**all_extensions)
        return FlextLdifModelsDomains.QuirkMetadata(
            quirk_type=self._get_server_type(),
            extensions=extensions_model,
        )

    def format_acl_value(
        self,
        acl_value: str,
        acl_metadata: FlextLdifModelsDomains.AclWriteMetadata,
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
        # Business Rule: ACL name sanitization uses FlextLdifUtilities.ACL
        # via lazy import pattern. Type checker cannot infer exact types.
        # Implication: We use runtime hasattr checks and getattr for type safety.
        # Use getattr to satisfy pyright strict mode while maintaining runtime safety
        # Business Rule: Sanitize ACL name using FlextLdifUtilitiesACL
        # sanitize_acl_name returns tuple[str, bool] (sanitized_name, was_sanitized)
        sanitize_result = FlextLdifUtilitiesACL.sanitize_acl_name(original_format)
        # Type narrowing: sanitize_acl_name returns tuple[str, bool]
        sanitized_name: str
        _was_sanitized: bool
        tuple_length_pair = 2
        if (
            isinstance(sanitize_result, tuple)
            and len(sanitize_result) == tuple_length_pair
        ):
            sanitized_name, _was_sanitized = sanitize_result
        else:
            sanitized_name = original_format
            _was_sanitized = False

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
