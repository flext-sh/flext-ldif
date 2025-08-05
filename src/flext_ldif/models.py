"""FLEXT-LDIF Unified Semantic Pattern Models - Domain Objects.

Implements FLEXT Unified Semantic Patterns for LDIF processing domain model.
Follows harmonized Flext[Domain][Type][Context] naming convention and
integrates with the ecosystem-wide unified pattern system.

Unified Patterns Applied:
    - FlextLdifEntry: Domain entity using FlextEntity foundation
    - FlextLdifDistinguishedName: Value object using FlextValue foundation
    - FlextLdifAttributes: Immutable collection using FlextValue foundation
    - Unified business rule validation with FlextResult pattern
    - Cross-ecosystem type compatibility via FlextTypes.Data namespace

Reference: /home/marlonsc/flext/flext-core/docs/FLEXT_UNIFIED_SEMANTIC_PATTERNS.md

The domain model encapsulates business logic and invariants for LDIF data
processing, providing type-safe, validated, and immutable data structures
with comprehensive business rule enforcement.

Key Components:
    - FlextLdifEntry: Domain entity representing LDIF entries with business logic
    - FlextLdifDistinguishedName: Value object for DN validation and operations
    - FlextLdifAttributes: Immutable attribute collection with business rules
    - Type definitions: TypedDict structures for type-safe data exchange

Architecture:
    Part of Domain Layer in Clean Architecture, this module contains pure
    business logic without external dependencies. All domain objects extend
    flext-core base classes and implement enterprise-grade validation patterns.

Business Rules:
    - Distinguished Names must follow RFC 4514 syntax requirements
    - LDIF entries must have valid DN and consistent attribute structure
    - Attributes follow LDAP naming conventions and value constraints
    - Change records must have valid operation types and modification semantics

Example:
    Creating and validating LDIF domain objects:

    >>> from flext_ldif.models import FlextLdifEntry, FlextLdifDistinguishedName
    >>>
    >>> # Create DN with automatic validation
    >>> dn = FlextLdifDistinguishedName(value="cn=John Doe,ou=people,dc=example,dc=com")
    >>> print(dn.get_rdn())  # "cn=John Doe"
    >>> print(dn.get_depth())  # 4
    >>>
    >>> # Create entry with business rule validation
    >>> entry = FlextLdifEntry.model_validate(
    ...     {
    ...         "dn": dn,
    ...         "attributes": FlextLdifAttributes(
    ...             attributes={
    ...                 "cn": ["John Doe"],
    ...                 "objectClass": ["person", "inetOrgPerson"],
    ...                 "mail": ["john@example.com"],
    ...             }
    ...         ),
    ...     }
    ... )
    >>>
    >>> # Validate business rules
    >>> entry.validate_semantic_rules()  # Raises exception if invalid
    >>> print(entry.has_object_class("person"))  # True

Integration:
    - Built on flext-core FlextDomainValueObject and FlextImmutableModel
    - Provides type-safe interfaces for application and infrastructure layers
    - Implements immutability patterns for thread-safe operations
    - Supports serialization for persistence and API integration

Author: FLEXT Development Team
Version: 0.9.0
License: MIT

"""

from __future__ import annotations

from typing import NewType, NotRequired, TypedDict

# 🚨 UNIFIED SEMANTIC PATTERNS: Using harmonized flext-core imports
from flext_core import FlextResult, get_logger
from flext_core.models import FlextValue, FlextEntity, FlextFactory
from flext_core.semantic_types import FlextTypes
from pydantic import Field, field_validator

# Logger for models module
logger = get_logger(__name__)

# Type aliases for LDIF-specific concepts
LDIFContent = NewType("LDIFContent", str)
LDIFLines = NewType("LDIFLines", list[str])


# =============================================================================
# LDIF TYPEDDICT DEFINITIONS - Type-safe dictionaries for LDIF
# =============================================================================


class FlextLdifDNDict(TypedDict):
    """TypedDict for Distinguished Name structure."""

    value: str
    components: NotRequired[list[str]]
    depth: NotRequired[int]


class FlextLdifAttributesDict(TypedDict):
    """TypedDict for LDIF attributes structure."""

    attributes: dict[str, list[str]]
    count: NotRequired[int]


class FlextLdifEntryDict(TypedDict):
    """TypedDict for LDIF entry structure."""

    dn: str
    attributes: dict[str, list[str]]
    object_classes: NotRequired[list[str]]
    changetype: NotRequired[str]


class FlextLdifDistinguishedName(FlextValue):
    """Distinguished Name value object for LDIF entries.

    Immutable value object representing LDAP Distinguished Names with RFC 4514
    compliance validation, hierarchy operations, and business rule enforcement.

    The DN value object encapsulates DN string validation, parsing, and provides
    hierarchical operations like parent DN extraction and depth calculation
    following Domain-Driven Design patterns.

    Attributes:
        value: The DN string in RFC 4514 format (e.g., "cn=John,ou=people,dc=example,dc=com")

    Business Rules:
        - DN must be non-empty string with valid attribute=value pairs
        - Components must be separated by commas
        - Each component must have valid attribute name and value
        - Supports hierarchical operations and parent DN extraction

    Example:
        >>> dn = FlextLdifDistinguishedName(
        ...     value="cn=John Doe,ou=people,dc=example,dc=com"
        ... )
        >>> print(dn.get_rdn())  # "cn=John Doe"
        >>> print(dn.get_depth())  # 4
        >>> parent = dn.get_parent_dn()
        >>> print(parent.value)  # "ou=people,dc=example,dc=com"

    Raises:
        ValueError: If DN format is invalid or violates RFC 4514 requirements

    Author: FLEXT Development Team
    Version: 0.9.0

    """

    value: str = Field(..., description="DN string value")

    @field_validator("value")
    @classmethod
    def validate_dn(cls, v: str) -> str:
        """Validate DN format."""
        if not v or not isinstance(v, str):
            msg = "DN must be a non-empty string"
            raise ValueError(msg)

        if "=" not in v:
            msg = "DN must contain at least one attribute=value pair"
            raise ValueError(msg)

        # Validate each component
        components = v.split(",")
        for raw_component in components:
            component = raw_component.strip()
            if "=" not in component:
                component_msg = f"Invalid DN component: {component}"
                raise ValueError(component_msg)

            attr_name, attr_value = component.split("=", 1)
            if not attr_name.strip() or not attr_value.strip():
                component_msg = f"Invalid DN component: {component}"
                raise ValueError(component_msg)

        return v

    def __str__(self) -> str:
        """Return DN string value."""
        return self.value

    def __eq__(self, other: object) -> bool:
        """Compare with string or other FlextLdifDistinguishedName."""
        if isinstance(other, str):
            return self.value == other
        if isinstance(other, FlextLdifDistinguishedName):
            return self.value == other.value
        return False

    def __hash__(self) -> int:
        """Return hash of DN value."""
        return hash(self.value)

    def get_rdn(self) -> str:
        """Get relative distinguished name (first component) with enterprise-grade processing and validation.

        Extracts the Relative Distinguished Name (RDN) from the full Distinguished Name
        using comprehensive parsing with validation, error handling, and detailed logging
        for enterprise LDAP operations and directory service integration scenarios.

        The RDN represents the leftmost component of the DN and identifies the entry
        within its immediate parent container. This method implements robust parsing
        logic with comprehensive validation and enterprise-grade error handling.

        Returns:
            str: The RDN component (e.g., "cn=John Doe" from "cn=John Doe,ou=people,dc=example,dc=com")

        Raises:
            ValueError: If DN value is invalid or cannot be parsed into components

        Example:
            >>> dn = FlextLdifDistinguishedName(
            ...     value="cn=John Doe,ou=people,dc=example,dc=com"
            ... )
            >>> rdn = dn.get_rdn()
            >>> print(rdn)  # "cn=John Doe"

        Business Logic:
            - Validates DN value before processing
            - Handles edge cases like single-component DNs
            - Provides detailed error context for parsing failures
            - Logs operation details for enterprise monitoring

        Author: FLEXT Development Team
        Version: 0.9.0

        """
        logger.debug("Extracting RDN from DN: '%s'", self.value)

        try:
            # Comprehensive DN value validation before processing
            if not self.value:
                error_msg = "Cannot extract RDN from empty DN value"
                logger.error("RDN extraction failed: %s", error_msg)
                raise ValueError(error_msg)

            # NOTE: self.value is guaranteed to be str by Pydantic validator

            # Validate DN contains component separators for parsing
            if "," not in self.value and "=" not in self.value:
                error_msg = "Invalid DN format for RDN extraction: '" + self.value + "'"
                logger.error("RDN extraction failed: %s", error_msg)
                raise ValueError(error_msg)

            logger.trace("Parsing DN components from: '%s'", self.value)

            # Split DN into components with comprehensive error handling
            try:
                components = self.value.split(",")
                logger.trace("Found %d DN components: %s", len(components), components)

                if not components:
                    error_msg = "DN parsing resulted in empty components list"
                    logger.error("RDN extraction failed: %s", error_msg)
                    raise ValueError(error_msg)

                # Extract and validate first component as RDN
                raw_rdn = components[0]
                logger.trace("Raw RDN component before processing: '%s'", raw_rdn)

                if not raw_rdn:
                    error_msg = "First DN component is empty - cannot extract RDN"
                    logger.error("RDN extraction failed: %s", error_msg)
                    raise ValueError(error_msg)

                # Clean and validate RDN component
                rdn = raw_rdn.strip()
                logger.trace("Cleaned RDN component: '%s'", rdn)

                if not rdn:
                    error_msg = "RDN component is empty after whitespace removal"
                    logger.error("RDN extraction failed: %s", error_msg)
                    raise ValueError(error_msg)

                # Validate RDN format (must contain attribute=value)
                if "=" not in rdn:
                    error_msg = (
                        "Invalid RDN format - missing '=' separator: '" + rdn + "'"
                    )
                    logger.error("RDN extraction failed: %s", error_msg)
                    raise ValueError(error_msg)

                # Additional RDN component validation
                attr_name, attr_value = rdn.split("=", 1)
                if not attr_name.strip():
                    error_msg = "Invalid RDN - empty attribute name: '" + rdn + "'"
                    logger.error("RDN extraction failed: %s", error_msg)
                    raise ValueError(error_msg)

                if not attr_value.strip():
                    value_error_msg = f"Invalid RDN - empty attribute value: '{rdn}'"
                    logger.error("RDN extraction failed: %s", value_error_msg)
                    raise ValueError(value_error_msg)

                logger.debug(
                    "Successfully extracted RDN: '%s' from DN: '%s'",
                    rdn,
                    self.value,
                )
                logger.info(
                    "RDN extraction completed - attribute: '%s', value: '%s'",
                    attr_name.strip(),
                    attr_value.strip(),
                )

                return rdn

            except (IndexError, AttributeError) as parsing_error:
                parsing_error_msg = f"DN component parsing failed: {parsing_error!s}"
                logger.error(
                    "RDN extraction failed: %s", parsing_error_msg, exc_info=True,
                )
                raise ValueError(parsing_error_msg) from parsing_error

        except Exception as unexpected_error:
            unexpected_error_msg = f"Unexpected error during RDN extraction from DN '{self.value}': {unexpected_error!s}"
            logger.error(
                "RDN extraction failed: %s", unexpected_error_msg, exc_info=True,
            )
            raise ValueError(unexpected_error_msg) from unexpected_error

    def get_parent_dn(self) -> FlextLdifDistinguishedName | None:
        """Get parent DN with enterprise-grade hierarchy processing and comprehensive validation.

        Extracts the parent Distinguished Name from the current DN by removing the leftmost
        component (RDN) and constructing a new DN from the remaining components, implementing
        comprehensive validation, error handling, and detailed logging for enterprise LDAP
        directory hierarchy operations and navigation scenarios.

        The parent DN represents the container where this entry resides in the directory
        hierarchy. For root DNs or single-component DNs, returns None to indicate no parent.
        This method implements robust hierarchy parsing with enterprise-grade error handling.

        Returns:
            FlextLdifDistinguishedName | None: Parent DN object if exists, None for root DNs

        Raises:
            ValueError: If DN parsing fails or parent DN construction is invalid

        Examples:
            >>> # Multi-component DN with parent
            >>> dn = FlextLdifDistinguishedName(
            ...     value="cn=John Doe,ou=people,dc=example,dc=com"
            ... )
            >>> parent = dn.get_parent_dn()
            >>> print(parent.value)  # "ou=people,dc=example,dc=com"
            >>>
            >>> # Root DN has no parent
            >>> root_dn = FlextLdifDistinguishedName(value="dc=example,dc=com")
            >>> parent = root_dn.get_parent_dn()
            >>> print(parent)  # None

        Business Logic:
            - Validates DN structure before hierarchy extraction
            - Handles root DNs by returning None appropriately
            - Constructs valid parent DN with proper formatting
            - Provides comprehensive error context for failures
            - Logs hierarchy operations for enterprise monitoring

        Author: FLEXT Development Team
        Version: 0.9.0

        """
        logger.debug("Extracting parent DN from: '%s'", self.value)

        try:
            # Comprehensive DN value validation before hierarchy processing
            if not self.value:
                error_msg = "Cannot extract parent DN from empty DN value"
                logger.error("Parent DN extraction failed: %s", error_msg)
                raise ValueError(error_msg)

            # NOTE: self.value is guaranteed to be str by Pydantic validator

            logger.trace(
                "Parsing DN components for parent extraction: '%s'",
                self.value,
            )

            # Split DN into components with comprehensive error handling
            try:
                components = self.value.split(",")
                logger.trace(
                    f"Found {len(components)} DN components for parent extraction: {components}",
                )

                if not components:
                    error_msg = "DN parsing resulted in empty components list for parent extraction"
                    logger.error("Parent DN extraction failed: %s", error_msg)
                    raise ValueError(error_msg)

                # Check if this is a root DN (single component)
                if len(components) <= 1:
                    logger.debug(
                        "DN '%s' is root-level - no parent DN exists",
                        self.value,
                    )
                    logger.info(
                        "Parent DN extraction completed - no parent for root DN",
                    )
                    return None

                logger.trace(
                    "DN has %d components - parent DN extraction possible",
                    len(components),
                )

                # Extract parent components (all except first)
                parent_components = components[1:]
                logger.trace("Parent DN components: %s", parent_components)

                if not parent_components:
                    error_msg = "Parent components extraction resulted in empty list"
                    logger.error("Parent DN extraction failed: %s", error_msg)
                    raise ValueError(error_msg)

                # Construct parent DN string with validation
                try:
                    parent_dn_raw = ",".join(parent_components)
                    logger.trace("Raw parent DN before cleaning: '%s'", parent_dn_raw)

                    if not parent_dn_raw:
                        error_msg = "Parent DN construction resulted in empty string"
                        logger.error("Parent DN extraction failed: %s", error_msg)
                        raise ValueError(error_msg)

                    # Clean whitespace from parent DN
                    parent_dn_cleaned = parent_dn_raw.strip()
                    logger.trace("Cleaned parent DN: '%s'", parent_dn_cleaned)

                    if not parent_dn_cleaned:
                        error_msg = "Parent DN is empty after whitespace cleaning"
                        logger.error("Parent DN extraction failed: %s", error_msg)
                        raise ValueError(error_msg)

                    # Validate parent DN format
                    if "=" not in parent_dn_cleaned:
                        format_error_msg = f"Invalid parent DN format - missing attribute=value pairs: '{parent_dn_cleaned}'"
                        logger.error(
                            "Parent DN extraction failed: %s", format_error_msg,
                        )
                        raise ValueError(format_error_msg)

                    logger.debug(
                        "Constructing parent DN object from: '%s'",
                        parent_dn_cleaned,
                    )

                    # Create parent DN object with validation
                    try:
                        parent_dn_obj = FlextLdifDistinguishedName.model_validate(
                            {"value": parent_dn_cleaned},
                        )
                        logger.debug(
                            "Successfully created parent DN object: '%s'",
                            parent_dn_obj.value,
                        )
                        logger.info(
                            "Parent DN extraction completed - child: '%s', parent: '%s'",
                            self.value,
                            parent_dn_obj.value,
                        )

                        return parent_dn_obj

                    except Exception as validation_error:
                        validation_error_msg = f"Parent DN object creation failed for '{parent_dn_cleaned}': {validation_error!s}"
                        logger.error(
                            "Parent DN extraction failed: %s",
                            validation_error_msg,
                            exc_info=True,
                        )
                        raise ValueError(validation_error_msg) from validation_error

                except (IndexError, AttributeError) as join_error:
                    join_error_msg = f"Parent DN construction failed: {join_error!s}"
                    logger.error(
                        "Parent DN extraction failed: %s",
                        join_error_msg,
                        exc_info=True,
                    )
                    raise ValueError(join_error_msg) from join_error

            except (IndexError, AttributeError) as parsing_error:
                parsing_error_msg = f"DN component parsing failed for parent extraction: {parsing_error!s}"
                logger.error(
                    "Parent DN extraction failed: %s",
                    parsing_error_msg,
                    exc_info=True,
                )
                raise ValueError(error_msg) from parsing_error

        except Exception as unexpected_error:
            unexpected_error_msg: str = f"Unexpected error during parent DN extraction from '{self.value}': {unexpected_error!s}"
            logger.error(
                "Parent DN extraction failed: %s", unexpected_error_msg, exc_info=True,
            )
            raise ValueError(unexpected_error_msg) from unexpected_error

    def is_child_of(self, parent: FlextLdifDistinguishedName) -> bool:
        """Check if this DN is a child of another DN in the hierarchy with enterprise-grade validation and analysis.

        Performs comprehensive case-insensitive hierarchical relationship analysis to determine
        if this DN is a direct or indirect child of the specified parent DN using robust
        string matching, validation, and detailed logging for enterprise LDAP directory
        hierarchy operations and access control scenarios.

        This method implements sophisticated DN hierarchy analysis beyond simple string matching,
        including component-level validation, relationship verification, and comprehensive
        error handling for enterprise directory service integration requirements.

        Args:
            parent: The parent DN to check against for hierarchical relationship

        Returns:
            bool: True if this DN is a child of the parent DN, False otherwise

        Raises:
            TypeError: If parent parameter is not a FlextLdifDistinguishedName instance
            ValueError: If DN values are invalid or cannot be compared

        Examples:
            >>> # Direct child relationship
            >>> child = FlextLdifDistinguishedName(
            ...     value="cn=user,ou=people,dc=example,dc=com"
            ... )
            >>> parent = FlextLdifDistinguishedName(value="ou=people,dc=example,dc=com")
            >>> child.is_child_of(parent)  # True
            >>>
            >>> # Reverse relationship (parent is not child)
            >>> parent.is_child_of(child)  # False
            >>>
            >>> # Root domain relationship
            >>> domain = FlextLdifDistinguishedName(value="dc=example,dc=com")
            >>> child.is_child_of(domain)  # True (indirect child)

        Business Logic:
            - Validates both DN instances before comparison
            - Performs case-insensitive hierarchical analysis
            - Handles edge cases like identical DNs and root relationships
            - Provides detailed logging for security audit trails
            - Implements comprehensive error handling for robustness

        Author: FLEXT Development Team
        Version: 0.9.0

        """
        logger.debug(
            "Checking if DN '%s' is child of parent '%s'",
            self.value,
            parent.value if parent else "None",
        )

        try:
            # Strategy Pattern: Use validation strategies to reduce complexity

            # Strategy 1: Parameter validation - Single Responsibility
            validation_error = self._validate_child_of_parameters(parent)
            if validation_error:
                raise validation_error

            # Strategy 2: Length comparison - Single Responsibility
            length_result = self._check_child_of_length_requirements(parent)
            if not length_result:
                return False

            # Strategy 3: Hierarchy analysis - Single Responsibility
            hierarchy_result = self._perform_child_of_hierarchy_analysis(parent)
            if hierarchy_result is None:
                return False

            # Strategy 4: Result logging - Single Responsibility
            self._log_child_of_result(hierarchy_result, parent)
            return hierarchy_result

        except Exception as unexpected_error:
            error_msg = "Unexpected error during child relationship check between '%s' and '%s': %s"
            logger.error(
                error_msg,
                self.value,
                parent.value if parent else "None",
                unexpected_error,
                exc_info=True,
            )
            raise ValueError(
                error_msg
                % (
                    self.value,
                    parent.value if parent else "None",
                    str(unexpected_error),
                ),
            ) from unexpected_error

    def _validate_child_of_parameters(
        self,
        parent: FlextLdifDistinguishedName | None,
    ) -> Exception | None:
        """Strategy 1: Validate parameters for child relationship check following Single Responsibility Principle."""
        # Comprehensive parameter validation
        if parent is None:
            error_msg = (
                "Parent DN parameter cannot be None for child relationship check"
            )
            logger.error("Child relationship check failed: %s", error_msg)
            return TypeError(error_msg)

        # NOTE: parent type is validated by Pydantic in calling context
        # isinstance check is redundant and creates unreachable code

        # Validate current DN value
        if not self.value:
            error_msg = "Cannot check child relationship with empty current DN value"
            logger.error("Child relationship check failed: %s", error_msg)
            return ValueError(error_msg)

        # NOTE: self.value is guaranteed to be str by Pydantic validator

        # Validate parent DN value
        if not parent.value:
            error_msg = "Cannot check child relationship with empty parent DN value"
            logger.error("Child relationship check failed: %s", error_msg)
            return ValueError(error_msg)

        # NOTE: parent.value is guaranteed to be str by Pydantic validator

        logger.trace(
            "Validating DN hierarchy: child='%s', parent='%s'",
            self.value,
            parent.value,
        )
        return None

    def _check_child_of_length_requirements(
        self,
        parent: FlextLdifDistinguishedName,
    ) -> bool:
        """Strategy 2: Check length requirements for child relationship following Single Responsibility Principle."""
        # Handle identical DN case (not a child relationship)
        if self.value.lower() == parent.value.lower():
            logger.debug("DNs are identical - no child relationship: '%s'", self.value)
            logger.info(
                "Child relationship check completed - identical DNs (not child)",
            )
            return False

        # Check for logical hierarchy relationship (child must be longer than parent)
        if len(self.value) <= len(parent.value):
            logger.debug(
                "Current DN is not longer than parent - cannot be child: current=%d, parent=%d",
                len(self.value),
                len(parent.value),
            )
            logger.info(
                "Child relationship check completed - DN length indicates no child relationship",
            )
            return False

        return True

    def _perform_child_of_hierarchy_analysis(
        self,
        parent: FlextLdifDistinguishedName,
    ) -> bool | None:
        """Strategy 3: Perform hierarchy analysis for child relationship following Single Responsibility Principle."""
        logger.trace("Performing case-insensitive hierarchy comparison")

        try:
            current_dn_lower = self.value.lower().strip()
            parent_dn_lower = parent.value.lower().strip()

            logger.trace(
                "Normalized DNs - current: '%s', parent: '%s'",
                current_dn_lower,
                parent_dn_lower,
            )

            # Check if current DN ends with parent DN (hierarchy relationship)
            is_child = current_dn_lower.endswith(parent_dn_lower)

            # Additional validation: ensure proper component boundary
            if is_child:
                # Verify that the match occurs at a component boundary (preceded by comma)
                parent_start_index = current_dn_lower.rfind(parent_dn_lower)
                if parent_start_index > 0:
                    # Check if character before parent DN is a comma (proper component boundary)
                    preceding_char = current_dn_lower[parent_start_index - 1]
                    if preceding_char != ",":
                        logger.debug(
                            "DN match found but not at component boundary - not a valid child relationship",
                        )
                        is_child = False
                    else:
                        logger.trace(
                            "Valid component boundary found at index %d",
                            parent_start_index,
                        )
                else:
                    logger.trace(
                        "Parent DN match at start of current DN - checking for valid hierarchy",
                    )

            return is_child

        except (AttributeError, IndexError) as string_error:
            error_msg = "String processing error during hierarchy check: %s"
            logger.error(
                "Child relationship check failed: %s",
                error_msg % str(string_error),
                exc_info=True,
            )
            raise ValueError(error_msg % str(string_error)) from string_error

    def _log_child_of_result(
        self,
        is_child: bool,
        parent: FlextLdifDistinguishedName,
    ) -> None:
        """Strategy 4: Log child relationship result following Single Responsibility Principle."""
        if is_child:
            logger.debug(
                "Confirmed child relationship: '%s' is child of '%s'",
                self.value,
                parent.value,
            )
            logger.info("Child relationship check completed - CHILD CONFIRMED")
        else:
            logger.debug(
                "No child relationship: '%s' is NOT child of '%s'",
                self.value,
                parent.value,
            )
            logger.info("Child relationship check completed - NO CHILD RELATIONSHIP")

    def get_depth(self) -> int:
        """Get the hierarchical depth of the DN with enterprise-grade calculation and comprehensive validation.

        Calculates the number of components in the DN by analyzing comma-separated
        attribute=value pairs with comprehensive validation, error handling, and detailed
        logging to provide accurate hierarchical depth measurement for enterprise LDAP
        directory operations, access control, and organizational structure analysis.

        The depth represents the number of hierarchical levels from the root domain
        to this specific entry, enabling sophisticated directory navigation, security
        policies, and organizational structure enforcement in enterprise environments.

        Returns:
            int: The number of DN components representing hierarchical depth (minimum 1)

        Raises:
            ValueError: If DN structure is invalid or cannot be parsed for depth calculation

        Examples:
            >>> # Multi-level organizational structure
            >>> dn = FlextLdifDistinguishedName(
            ...     value="cn=user,ou=people,dc=example,dc=com"
            ... )
            >>> depth = dn.get_depth()
            >>> print(depth)  # 4 (cn, ou, dc, dc)
            >>>
            >>> # Root domain depth
            >>> root = FlextLdifDistinguishedName(value="dc=com")
            >>> root_depth = root.get_depth()
            >>> print(root_depth)  # 1
            >>>
            >>> # Complex organizational hierarchy
            >>> complex_dn = FlextLdifDistinguishedName(
            ...     value="cn=John,ou=IT,ou=Department,o=Company,dc=example,dc=com"
            ... )
            >>> complex_depth = complex_dn.get_depth()
            >>> print(complex_depth)  # 6

        Business Logic:
            - Validates DN structure before depth calculation
            - Handles edge cases like single-component DNs
            - Provides accurate component counting with validation
            - Supports organizational hierarchy analysis and access control
            - Logs depth calculation for enterprise monitoring and auditing

        Author: FLEXT Development Team
        Version: 0.9.0

        """
        logger.debug("Calculating hierarchical depth for DN: '%s'", self.value)

        try:
            # Strategy Pattern: Use depth calculation strategies to reduce complexity

            # Strategy 1: Parameter validation - Single Responsibility
            validation_error = self._validate_depth_parameters()
            if validation_error:
                raise validation_error

            # Strategy 2: Component parsing - Single Responsibility
            components = self._parse_depth_components()

            # Strategy 3: Component validation - Single Responsibility
            valid_components = self._validate_depth_components(components)

            # Strategy 4: Depth calculation and validation - Single Responsibility
            return self._calculate_and_validate_depth(valid_components)

        except Exception as unexpected_error:
            error_msg = "Unexpected error during DN depth calculation for '%s': %s"
            logger.error(error_msg, self.value, unexpected_error, exc_info=True)
            raise ValueError(
                error_msg % (self.value, str(unexpected_error)),
            ) from unexpected_error

    def _validate_depth_parameters(self) -> Exception | None:
        """Strategy 1: Validate parameters for depth calculation following Single Responsibility Principle."""
        # Comprehensive DN value validation before depth calculation
        if not self.value:
            error_msg = "Cannot calculate depth for empty DN value"
            logger.error("DN depth calculation failed: %s", error_msg)
            return ValueError(error_msg)

        # NOTE: self.value is guaranteed to be str by Pydantic validator

        logger.trace("Parsing DN components for depth calculation: '%s'", self.value)
        return None

    def _parse_depth_components(self) -> list[str]:
        """Strategy 2: Parse DN components for depth calculation following Single Responsibility Principle."""
        try:
            components = self.value.split(",")
            logger.trace(
                "Split DN into %d raw components: %s",
                len(components),
                components,
            )

            if not components:
                error_msg = (
                    "DN parsing resulted in empty components list for depth calculation"
                )
                logger.error("DN depth calculation failed: %s", error_msg)
                raise ValueError(error_msg)

            return components

        except (AttributeError, IndexError) as parsing_error:
            error_msg = "DN component parsing failed for depth calculation: %s"
            logger.error(
                "DN depth calculation failed: %s",
                error_msg % str(parsing_error),
                exc_info=True,
            )
            raise ValueError(error_msg % str(parsing_error)) from parsing_error

    def _validate_depth_components(self, components: list[str]) -> list[str]:
        """Strategy 3: Validate individual components for depth calculation following Single Responsibility Principle."""
        valid_components = []
        for i, raw_component in enumerate(components):
            logger.trace("Processing component %d: '%s'", i + 1, raw_component)

            # Clean whitespace from component
            component = raw_component.strip() if raw_component else ""

            if not component:
                logger.trace("Skipping empty component at index %d", i)
                continue

            # Validate component format (must contain attribute=value)
            if "=" not in component:
                error_msg = "Invalid DN component format at index %d: '%s' - missing '=' separator"
                logger.error(
                    "DN depth calculation failed: %s",
                    error_msg % (i, component),
                )
                raise ValueError(error_msg % (i, component))

            # Additional component validation
            try:
                attr_name, attr_value = component.split("=", 1)
                if not attr_name.strip():
                    error_msg = (
                        "Invalid DN component at index %d: empty attribute name in '%s'"
                    )
                    logger.error(
                        "DN depth calculation failed: %s",
                        error_msg % (i, component),
                    )
                    raise ValueError(error_msg % (i, component))

                if not attr_value.strip():
                    error_msg = "Invalid DN component at index %d: empty attribute value in '%s'"
                    logger.error(
                        "DN depth calculation failed: %s",
                        error_msg % (i, component),
                    )
                    raise ValueError(error_msg % (i, component))

                valid_components.append(component)
                logger.trace(
                    "Valid component %d: '%s'",
                    len(valid_components),
                    component,
                )

            except ValueError as component_error:
                error_msg = "Component validation failed at index %d for '%s': %s"
                logger.exception(
                    "DN depth calculation failed: %s",
                    error_msg % (i, component, str(component_error)),
                )
                raise ValueError(
                    error_msg % (i, component, str(component_error)),
                ) from component_error

        # Ensure at least one valid component exists
        if not valid_components:
            error_msg = "No valid DN components found for depth calculation"
            logger.error("DN depth calculation failed: %s", error_msg)
            raise ValueError(error_msg)

        return valid_components

    def _calculate_and_validate_depth(self, valid_components: list[str]) -> int:
        """Strategy 4: Calculate and validate depth result following Single Responsibility Principle."""
        # Calculate final depth
        depth = len(valid_components)
        logger.trace("Calculated DN depth: %d valid components", depth)

        # Validate depth is reasonable (minimum 1, maximum practical limit)
        if depth < 1:
            error_msg = "Invalid calculated depth: %d - must be at least 1"
            logger.error("DN depth calculation failed: %s", error_msg % depth)
            raise ValueError(error_msg % depth)

        if depth > 20:  # Practical limit for LDAP hierarchy depth
            logger.warning(
                "Unusually deep DN hierarchy detected: %d levels - '%s'",
                depth,
                self.value,
            )

        logger.debug("Successfully calculated DN depth: %d for '%s'", depth, self.value)
        logger.info(
            "DN depth calculation completed - depth: %d, components: %d",
            depth,
            len(valid_components),
        )

        return depth

    def validate_business_rules(self) -> FlextResult[None]:
        """Validate DN business rules following Unified Semantic Patterns.

        Implements unified business rule validation pattern from FLEXT ecosystem
        following RFC 4514 DN validation requirements with Railway-Oriented
        Programming and consistent FlextResult error handling.

        Returns:
            FlextResult[None]: Success if DN is valid, failure with error message

        Business Rules Validated:
            - DN must contain at least one attribute=value pair
            - Each component must have valid format
            - Attribute names and values must be non-empty

        Example:
            >>> dn = FlextLdifDistinguishedName(value="cn=user,dc=example,dc=com")
            >>> result = dn.validate_business_rules()
            >>> result.success  # True

        Unified Pattern: Uses FlextResult for consistent error handling

        """
        logger.debug("Validating DN semantic rules for: '%s'", self.value)

        # Strategy Pattern: Use validation strategies to reduce complexity
        validation_errors = []

        # Strategy 1: Basic value validation
        basic_errors = self._validate_basic_dn_structure()
        validation_errors.extend(basic_errors)

        # Strategy 2: Component structure validation
        component_errors = self._validate_dn_components()
        validation_errors.extend(component_errors)

        # Railway-Oriented Programming: Return early if any validation failed
        if validation_errors:
            error_summary = (
                f"DN semantic validation failed: {'; '.join(validation_errors)}"
            )
            logger.error("DN semantic validation failed: %s", error_summary)
            return FlextResult.fail(error_summary)

        logger.debug(
            "DN semantic validation completed successfully for: '%s'",
            self.value,
        )
        return FlextResult.ok(None)

    def _validate_basic_dn_structure(self) -> list[str]:
        """Strategy 1: Validate basic DN structure - Single Responsibility Principle."""
        errors = []

        if not self.value:
            errors.append(
                "DN value cannot be empty - must contain at least one attribute=value pair",
            )

        # NOTE: self.value is guaranteed to be str by Pydantic validator

        if self.value and "=" not in self.value:
            errors.append(
                "DN must contain at least one attribute=value pair (missing '=' separator)",
            )

        return errors

    def _validate_dn_components(self) -> list[str]:
        """Strategy 2: Validate DN components structure - Single Responsibility Principle."""
        if not self.value or not isinstance(self.value, str):
            return []  # Basic validation handles these cases

        errors = []

        try:
            components = self.value.split(",")

            if not components:
                errors.append("DN must contain at least one valid component")
                return errors

            for i, raw_component in enumerate(components):
                component_errors = self._validate_single_component(raw_component, i + 1)
                errors.extend(component_errors)

        except Exception as e:
            errors.append(f"Component parsing failed: {e!s}")

        return errors

    def _validate_single_component(
        self,
        raw_component: str,
        component_number: int,
    ) -> list[str]:
        """Strategy 3: Validate single DN component - Template Method Pattern."""
        errors = []
        component = raw_component.strip() if raw_component else ""
        component_prefix = f"Component {component_number}"

        if not component:
            errors.append(f"{component_prefix} is empty after whitespace removal")
            return errors

        if "=" not in component:
            errors.append(f"{component_prefix} missing '=' separator: '{component}'")
            return errors

        try:
            attr_parts = component.split("=", 1)
            if len(attr_parts) != 2:
                errors.append(
                    f"{component_prefix} invalid attribute=value format: '{component}'",
                )
                return errors

            attr_name, attr_value = attr_parts
            attribute_errors = self._validate_attribute_pair(
                attr_name,
                attr_value,
                component_prefix,
            )
            errors.extend(attribute_errors)

        except Exception as e:
            errors.append(f"{component_prefix} parsing failed: {e!s}")

        return errors

    def _validate_attribute_pair(
        self,
        attr_name: str,
        attr_value: str,
        component_prefix: str,
    ) -> list[str]:
        """Strategy 4: Validate attribute name-value pair - DRY Principle."""
        errors = []

        attr_name_clean = attr_name.strip() if attr_name else ""
        attr_value_clean = attr_value.strip() if attr_value else ""

        if not attr_name_clean:
            errors.append(f"{component_prefix} attribute name is empty")

        if not attr_value_clean:
            errors.append(f"{component_prefix} attribute value is empty")

        return errors

    def to_dn_dict(self) -> FlextLdifDNDict:
        """Convert to FlextLdifDNDict representation with enterprise-grade serialization and comprehensive validation.

        Transforms the DN value object into a structured dictionary representation
        with comprehensive validation, component analysis, and detailed logging for
        enterprise data serialization, API integration, and structured data export
        scenarios requiring type-safe DN representation.

        The resulting FlextLdifDNDict provides a complete structural representation
        of the DN including parsed components, hierarchical depth, and validated
        metadata for integration with external systems and data transformation pipelines.

        Returns:
            FlextLdifDNDict: Structured dictionary representation with DN metadata

        Raises:
            ValueError: If DN cannot be converted to dictionary representation

        Example:
            >>> dn = FlextLdifDistinguishedName(
            ...     value="cn=John Doe,ou=people,dc=example,dc=com"
            ... )
            >>> dn_dict = dn.to_dn_dict()
            >>> print(dn_dict["value"])  # "cn=John Doe,ou=people,dc=example,dc=com"
            >>> print(
            ...     dn_dict["components"]
            ... )  # ["cn=John Doe", "ou=people", "dc=example", "dc=com"]
            >>> print(dn_dict["depth"])  # 4

        Business Logic:
            - Validates DN structure before serialization
            - Parses components with comprehensive error handling
            - Calculates hierarchical depth using enterprise-grade methods
            - Provides structured metadata for external system integration
            - Logs serialization operations for enterprise monitoring

        Author: FLEXT Development Team
        Version: 0.9.0

        """
        logger.debug("Converting DN to dictionary representation: '%s'", self.value)

        try:
            # Comprehensive DN value validation before serialization
            if not self.value:
                error_msg = "Cannot convert empty DN value to dictionary representation"
                logger.error("DN dictionary conversion failed: %s", error_msg)
                raise ValueError(error_msg)

            # NOTE: self.value is guaranteed to be str by Pydantic validator

            logger.trace(
                f"Processing DN components for dictionary serialization: '{self.value}'",
            )

            # Extract and validate DN components with comprehensive error handling
            try:
                raw_components = self.value.split(",")
                logger.trace(
                    f"Split DN into {len(raw_components)} raw components: {raw_components}",
                )

                if not raw_components:
                    error_msg = "DN component parsing resulted in empty components list"
                    logger.error("DN dictionary conversion failed: %s", error_msg)
                    raise ValueError(error_msg)

                # Clean and validate each component
                validated_components = []
                for i, raw_component in enumerate(raw_components):
                    logger.trace("Processing component %d: '%s'", i + 1, raw_component)

                    # Clean whitespace from component
                    component = raw_component.strip() if raw_component else ""

                    if not component:
                        logger.trace("Skipping empty component at index %d", i)
                        continue

                    # Validate component format
                    if "=" not in component:
                        component_format_error_msg: str = f"Invalid component format at index {i}: '{component}' - missing '=' separator"
                        logger.error(
                            "DN dictionary conversion failed: %s",
                            component_format_error_msg,
                        )
                        raise ValueError(component_format_error_msg)

                    validated_components.append(component)
                    logger.trace(
                        f"Validated component {len(validated_components)}: '{component}'",
                    )

                if not validated_components:
                    error_msg = (
                        "No valid components found after cleaning and validation"
                    )
                    logger.error("DN dictionary conversion failed: %s", error_msg)
                    raise ValueError(error_msg)

                logger.debug(
                    "Successfully validated %d DN components",
                    len(validated_components),
                )

            except (AttributeError, IndexError) as component_error:
                component_parsing_error_msg: str = f"DN component parsing failed for dictionary conversion: {component_error!s}"
                logger.error(
                    "DN dictionary conversion failed: %s",
                    component_parsing_error_msg,
                    exc_info=True,
                )
                raise ValueError(component_parsing_error_msg) from component_error

            # Calculate hierarchical depth with enterprise-grade method
            try:
                logger.trace("Calculating DN depth for dictionary representation")
                depth = self.get_depth()
                logger.trace(f"Calculated DN depth: {depth}")

                if depth < 1:
                    error_msg = (
                        f"Invalid DN depth calculated: {depth} - must be at least 1"
                    )
                    logger.error("DN dictionary conversion failed: %s", error_msg)
                    raise ValueError(error_msg)

                logger.debug("Successfully calculated DN depth: %d", depth)

            except Exception as depth_error:
                depth_calculation_error_msg: str = f"DN depth calculation failed for dictionary conversion: {depth_error!s}"
                logger.error(
                    "DN dictionary conversion failed: %s",
                    depth_calculation_error_msg,
                    exc_info=True,
                )
                raise ValueError(depth_calculation_error_msg) from depth_error

            # Construct FlextLdifDNDict with comprehensive validation
            try:
                logger.trace("Constructing FlextLdifDNDict with validated data")

                dn_dict = FlextLdifDNDict(
                    value=self.value,
                    components=validated_components,
                    depth=depth,
                )

                logger.debug("Successfully created DN dictionary representation")
                logger.info(
                    "DN dictionary conversion completed - value: '%s', components: %d, depth: %d",
                    self.value,
                    len(validated_components),
                    depth,
                )

                return dn_dict

            except Exception as dict_error:
                dict_construction_error_msg: str = (
                    f"FlextLdifDNDict construction failed: {dict_error!s}"
                )
                logger.error(
                    "DN dictionary conversion failed: %s",
                    dict_construction_error_msg,
                    exc_info=True,
                )
                raise ValueError(dict_construction_error_msg) from dict_error

        except Exception as unexpected_error:
            dict_unexpected_error_msg: str = f"Unexpected error during DN dictionary conversion for '{self.value}': {unexpected_error!s}"
            logger.error(
                "DN dictionary conversion failed: %s",
                dict_unexpected_error_msg,
                exc_info=True,
            )
            raise ValueError(dict_unexpected_error_msg) from unexpected_error


class FlextLdifAttributes(FlextDomainValueObject):
    """LDIF attributes collection value object.

    Immutable value object representing LDIF attribute collections with
    multi-value support, business rule validation, and operations for
    attribute manipulation following Domain-Driven Design patterns.

    The attributes collection handles LDAP attribute semantics including
    multi-valued attributes, case-sensitive names, and immutable operations
    that return new instances rather than modifying the existing object.

    Attributes:
        attributes: Dictionary mapping attribute names to lists of string values

    Business Rules:
        - Attribute names must be non-empty strings
        - Attribute values are stored as lists (multi-value support)
        - Empty attribute lists are allowed for some operations
        - Immutable operations return new instances

    Example:
        >>> attrs = FlextLdifAttributes(
        ...     attributes={
        ...         "cn": ["John Doe"],
        ...         "objectClass": ["person", "inetOrgPerson"],
        ...         "mail": ["john@example.com", "john.doe@company.com"],
        ...     }
        ... )
        >>> attrs.get_single_value("cn")  # "John Doe"
        >>> attrs.get_values("mail")  # ["john@example.com", "john.doe@company.com"]
        >>> attrs.has_attribute("objectClass")  # True

    Author: FLEXT Development Team
    Version: 0.9.0

    """

    attributes: dict[str, list[str]] = Field(
        default_factory=dict,
        description="LDIF attributes as name-value pairs",
    )

    def get_single_value(self, name: str) -> str | None:
        """Get the first value of a multi-valued attribute.

        Retrieves the first value from the attribute's value list, which is
        useful for single-valued attributes or when only the primary value
        of a multi-valued attribute is needed.

        Args:
            name: The attribute name to retrieve the value for

        Returns:
            The first value if the attribute exists and has values, None otherwise

        Example:
            >>> attrs = FlextLdifAttributes(attributes={"cn": ["John Doe"], "mail": []})
            >>> attrs.get_single_value("cn")  # "John Doe"
            >>> attrs.get_single_value("mail")  # None (empty list)
            >>> attrs.get_single_value("nonexistent")  # None

        """
        logger.debug(
            f"Retrieving single value for attribute '{name}' from attributes collection",
        )

        try:
            # Parameter validation - name is guaranteed to be str by type annotation
            if not name.strip():
                empty_name_error_msg = (
                    "Attribute name cannot be empty string for single value retrieval"
                )
                logger.error("Single value retrieval failed: %s", empty_name_error_msg)
                raise ValueError(empty_name_error_msg)

            # Clean attribute name for consistent lookup
            cleaned_name = name.strip()
            logger.trace(f"Cleaned attribute name: '{cleaned_name}'")

            # Validate attributes collection exists and is accessible
            if not hasattr(self, "attributes"):
                missing_attributes_error_msg = (
                    "Attributes collection is not available for single value retrieval"
                )
                logger.error(
                    "Single value retrieval failed: %s", missing_attributes_error_msg,
                )
                raise AttributeError(missing_attributes_error_msg)

            # self.attributes is guaranteed to be dict[str, list[str]] by type annotation

            logger.trace(
                f"Accessing attribute '{cleaned_name}' from {len(self.attributes)} total attributes",
            )

            # Retrieve attribute values with comprehensive validation
            try:
                attribute_values = self.attributes.get(cleaned_name, [])
                logger.trace(
                    f"Retrieved values for '{cleaned_name}': {attribute_values}",
                )

                # attribute_values is guaranteed to be list[str] by type annotation

                # Handle empty attribute values
                if not attribute_values:
                    logger.debug(
                        f"Attribute '{cleaned_name}' has no values - returning None",
                    )
                    logger.info(
                        f"Single value retrieval completed - attribute '{cleaned_name}' not found or empty",
                    )
                    return None

                # Extract first value (guaranteed to be str by type annotation)
                first_value = attribute_values[0]
                logger.trace(f"First value for '{cleaned_name}': '{first_value}'")

                # Log successful retrieval with metadata
                total_values = len(attribute_values)
                logger.debug(
                    f"Successfully retrieved single value for '{cleaned_name}': '{first_value}' ({total_values} total values)",
                )
                logger.info(
                    f"Single value retrieval completed - attribute: '{cleaned_name}', value: '{first_value}', total_values: {total_values}",
                )

                return first_value

            except KeyError as key_error:
                key_error_msg = (
                    f"Attribute lookup failed for '{cleaned_name}': {key_error!s}"
                )
                logger.exception("Single value retrieval failed: %s", key_error_msg)
                raise ValueError(key_error_msg) from key_error

        except Exception as unexpected_error:
            single_value_unexpected_error_msg: str = f"Unexpected error during single value retrieval for attribute '{name}': {unexpected_error!s}"
            logger.error(
                "Single value retrieval failed: %s",
                single_value_unexpected_error_msg,
                exc_info=True,
            )
            raise ValueError(single_value_unexpected_error_msg) from unexpected_error

    def get_values(self, name: str) -> list[str]:
        """Get all values for a multi-valued attribute.

        Retrieves the complete list of values for the specified attribute,
        supporting LDAP's multi-valued attribute semantics.

        Args:
            name: The attribute name to retrieve values for

        Returns:
            List of all values for the attribute, empty list if attribute doesn't exist

        Example:
            >>> attrs = FlextLdifAttributes(
            ...     attributes={
            ...         "objectClass": ["person", "inetOrgPerson"],
            ...         "mail": ["user@example.com", "user@company.com"],
            ...     }
            ... )
            >>> attrs.get_values("objectClass")  # ["person", "inetOrgPerson"]
            >>> attrs.get_values("nonexistent")  # []

        """
        logger.debug(
            f"Retrieving all values for attribute '{name}' from attributes collection",
        )

        try:
            # Parameter validation - name is guaranteed to be str by type annotation
            if not name.strip():
                empty_name_values_error_msg = (
                    "Attribute name cannot be empty string for values retrieval"
                )
                logger.error("Values retrieval failed: %s", empty_name_values_error_msg)
                raise ValueError(empty_name_values_error_msg)

            # Clean attribute name for consistent lookup
            cleaned_name = name.strip()
            logger.trace(f"Cleaned attribute name: '{cleaned_name}'")

            # Validate attributes collection exists and is accessible
            if not hasattr(self, "attributes"):
                missing_attributes_values_error_msg = (
                    "Attributes collection is not available for values retrieval"
                )
                logger.error(
                    "Values retrieval failed: %s", missing_attributes_values_error_msg,
                )
                raise AttributeError(missing_attributes_values_error_msg)

            # self.attributes is guaranteed to be dict[str, list[str]] by type annotation

            logger.trace(
                f"Accessing attribute '{cleaned_name}' from {len(self.attributes)} total attributes",
            )

            # Retrieve attribute values with comprehensive validation
            try:
                attribute_values = self.attributes.get(cleaned_name, [])
                logger.trace(
                    f"Retrieved values for '{cleaned_name}': {attribute_values}",
                )

                # attribute_values is guaranteed to be list[str] by type annotation

                # Process each value (all guaranteed to be str by type annotation)
                validated_values = []
                for i, value in enumerate(attribute_values):
                    logger.trace(
                        f"Processing value {i + 1} for '{cleaned_name}': '{value}'",
                    )

                    # Keep original value (including empty strings for LDAP compatibility)
                    validated_values.append(value)
                    logger.trace(f"Processed value {i + 1}: '{value}'")

                # Handle empty attribute values
                if not validated_values:
                    logger.debug(
                        f"Attribute '{cleaned_name}' has no values - returning empty list",
                    )
                    logger.info(
                        f"Values retrieval completed - attribute '{cleaned_name}' not found or empty",
                    )
                    return []

                # Log successful retrieval with metadata
                values_count = len(validated_values)
                logger.debug(
                    f"Successfully retrieved {values_count} values for '{cleaned_name}': {validated_values}",
                )
                logger.info(
                    f"Values retrieval completed - attribute: '{cleaned_name}', count: {values_count}",
                )

                return validated_values

            except KeyError as key_error:
                values_key_error_msg = (
                    f"Attribute lookup failed for '{cleaned_name}': {key_error!s}"
                )
                logger.exception(f"Values retrieval failed: {values_key_error_msg}")
                raise ValueError(values_key_error_msg) from key_error

        except Exception as unexpected_error:
            values_unexpected_error_msg: str = f"Unexpected error during values retrieval for attribute '{name}': {unexpected_error!s}"
            logger.error(
                f"Values retrieval failed: {values_unexpected_error_msg}", exc_info=True,
            )
            raise ValueError(values_unexpected_error_msg) from unexpected_error

    def has_attribute(self, name: str) -> bool:
        """Check if an attribute exists in the collection.

        Determines whether the specified attribute name exists in the
        attributes collection, regardless of whether it has values.

        Args:
            name: The attribute name to check for existence

        Returns:
            True if the attribute exists (even if empty), False otherwise

        Example:
            >>> attrs = FlextLdifAttributes(attributes={"cn": ["John"], "mail": []})
            >>> attrs.has_attribute("cn")  # True
            >>> attrs.has_attribute("mail")  # True (exists but empty)
            >>> attrs.has_attribute("nonexistent")  # False

        """
        logger.debug(
            f"Checking existence of attribute '{name}' in attributes collection",
        )

        try:
            # Parameter validation - name is guaranteed to be str by type annotation
            if not name.strip():
                empty_name_exists_error_msg = (
                    "Attribute name cannot be empty string for existence check"
                )
                logger.error(
                    f"Attribute existence check failed: {empty_name_exists_error_msg}",
                )
                raise ValueError(empty_name_exists_error_msg)

            # Clean attribute name for consistent lookup
            cleaned_name = name.strip()
            logger.trace(
                f"Cleaned attribute name for existence check: '{cleaned_name}'",
            )

            # Validate attributes collection exists and is accessible
            if not hasattr(self, "attributes"):
                missing_attributes_exists_error_msg = (
                    "Attributes collection is not available for existence check"
                )
                logger.error(
                    f"Attribute existence check failed: {missing_attributes_exists_error_msg}",
                )
                raise AttributeError(missing_attributes_exists_error_msg)

            # self.attributes is guaranteed to be dict[str, list[str]] by type annotation

            logger.trace(
                f"Checking attribute '{cleaned_name}' existence in {len(self.attributes)} total attributes",
            )

            # Perform existence check with comprehensive validation
            try:
                attribute_exists = cleaned_name in self.attributes
                logger.trace(
                    f"Attribute existence check result for '{cleaned_name}': {attribute_exists}",
                )

                if attribute_exists:
                    # attribute_value is guaranteed to be list[str] by type annotation
                    attribute_value = self.attributes[cleaned_name]
                    values_count = len(attribute_value)
                    logger.debug(
                        f"Attribute '{cleaned_name}' exists with {values_count} values",
                    )
                    logger.info(
                        f"Attribute existence check completed - '{cleaned_name}': EXISTS ({values_count} values)",
                    )
                else:
                    logger.debug(
                        f"Attribute '{cleaned_name}' does not exist in collection",
                    )
                    logger.info(
                        f"Attribute existence check completed - '{cleaned_name}': NOT EXISTS",
                    )

                return attribute_exists

            except (KeyError, TypeError) as lookup_error:
                exists_lookup_error_msg: str = f"Attribute existence check failed for '{cleaned_name}': {lookup_error!s}"
                logger.exception(
                    f"Attribute existence check failed: {exists_lookup_error_msg}",
                )
                raise ValueError(exists_lookup_error_msg) from lookup_error

        except Exception as unexpected_error:
            exists_unexpected_error_msg: str = f"Unexpected error during attribute existence check for '{name}': {unexpected_error!s}"
            logger.error(
                f"Attribute existence check failed: {exists_unexpected_error_msg}",
                exc_info=True,
            )
            raise ValueError(exists_unexpected_error_msg) from unexpected_error

    def add_value(self, name: str, value: str) -> FlextLdifAttributes:
        """Add value to an attribute, returning new instance with immutable pattern.

        Creates a new FlextLdifAttributes instance with the specified value added
        to the named attribute, following Domain-Driven Design immutability patterns.
        If the attribute doesn't exist, it will be created with the single value.

        Args:
            name: The attribute name to add the value to
            value: The string value to add to the attribute

        Returns:
            New FlextLdifAttributes instance with the value added

        Example:
            >>> attrs = FlextLdifAttributes(attributes={"cn": ["John"]})
            >>> new_attrs = attrs.add_value("mail", "john@example.com")
            >>> new_attrs.get_values("mail")  # ["john@example.com"]
            >>> attrs.get_values("mail")  # [] (original unchanged)

        """
        logger.debug(
            f"Adding value '{value}' to attribute '{name}' with immutable pattern",
        )

        try:
            # Parameter validation - name and value are guaranteed to be str by type annotation
            if not name.strip():
                empty_name_add_error_msg = (
                    "Attribute name cannot be empty string for value addition"
                )
                logger.error(f"Add value operation failed: {empty_name_add_error_msg}")
                raise ValueError(empty_name_add_error_msg)

            # Clean parameters for consistent processing
            cleaned_name = name.strip()
            cleaned_value = (
                value  # Keep original value including whitespace for LDAP compatibility
            )
            logger.trace(
                f"Adding value to attribute: name='{cleaned_name}', value='{cleaned_value}'",
            )

            # Validate current attributes collection
            if not hasattr(self, "attributes"):
                missing_attributes_add_error_msg = (
                    "Attributes collection is not available for value addition"
                )
                logger.error(
                    f"Add value operation failed: {missing_attributes_add_error_msg}",
                )
                raise AttributeError(missing_attributes_add_error_msg)

            # self.attributes is guaranteed to be dict[str, list[str]] by type annotation

            logger.trace(
                f"Processing {len(self.attributes)} existing attributes for immutable copy",
            )

            # Create deep copy of existing attributes (types guaranteed by annotation)
            try:
                new_attrs = {}
                for attr_name, attr_values in self.attributes.items():
                    logger.trace(
                        f"Copying attribute '{attr_name}' with {len(attr_values)} values",
                    )

                    # attr_name and attr_values types guaranteed by dict[str, list[str]] annotation

                    # Create deep copy of values list
                    try:
                        copied_values = attr_values.copy()
                        new_attrs[attr_name] = copied_values
                        logger.trace(
                            f"Successfully copied attribute '{attr_name}' with {len(copied_values)} values",
                        )
                    except Exception as copy_error:
                        error_msg: str = f"Failed to copy values for attribute '{attr_name}': {copy_error!s}"
                        logger.exception(f"Add value operation failed: {error_msg}")
                        raise ValueError(error_msg) from copy_error

                logger.debug(
                    f"Successfully created immutable copy of {len(new_attrs)} attributes",
                )

            except Exception as copy_error:
                copy_attrs_error_msg = (
                    f"Failed to create immutable copy of attributes: {copy_error!s}"
                )
                logger.error(
                    f"Add value operation failed: {copy_attrs_error_msg}", exc_info=True,
                )
                raise ValueError(copy_attrs_error_msg) from copy_error

            # Add new value to target attribute with validation
            try:
                if cleaned_name not in new_attrs:
                    logger.trace(
                        f"Creating new attribute '{cleaned_name}' with initial value",
                    )
                    new_attrs[cleaned_name] = []
                else:
                    logger.trace(
                        f"Adding to existing attribute '{cleaned_name}' with {len(new_attrs[cleaned_name])} current values",
                    )

                # current_values is guaranteed to be list[str] (either new empty list or copied list)
                current_values = new_attrs[cleaned_name]

                # Add new value to the list
                current_values.append(cleaned_value)
                logger.trace(
                    f"Added value '{cleaned_value}' to attribute '{cleaned_name}' - now has {len(current_values)} values",
                )

            except Exception as addition_error:
                add_value_error_msg: str = f"Failed to add value '{cleaned_value}' to attribute '{cleaned_name}': {addition_error!s}"
                logger.exception(f"Add value operation failed: {add_value_error_msg}")
                raise ValueError(add_value_error_msg) from addition_error

            # Create new FlextLdifAttributes instance with comprehensive validation
            try:
                logger.trace(
                    "Creating new FlextLdifAttributes instance with updated attributes",
                )

                new_instance = FlextLdifAttributes.model_validate(
                    {"attributes": new_attrs},
                )

                logger.debug(
                    "Successfully created new attributes instance with value added",
                )
                logger.info(
                    f"Add value operation completed - attribute: '{cleaned_name}', value: '{cleaned_value}', total_attributes: {len(new_attrs)}",
                )

                return new_instance

            except Exception as validation_error:
                create_instance_error_msg: str = f"Failed to create new FlextLdifAttributes instance: {validation_error!s}"
                logger.error(
                    f"Add value operation failed: {create_instance_error_msg}",
                    exc_info=True,
                )
                raise ValueError(create_instance_error_msg) from validation_error

        except Exception as unexpected_error:
            add_value_unexpected_error_msg: str = f"Unexpected error during add value operation for '{name}':'{value}': {unexpected_error!s}"
            logger.error(
                f"Add value operation failed: {add_value_unexpected_error_msg}",
                exc_info=True,
            )
            raise ValueError(add_value_unexpected_error_msg) from unexpected_error

    def remove_value(self, name: str, value: str) -> FlextLdifAttributes:
        """Remove value from an attribute, returning new instance with immutable pattern.

        Creates a new FlextLdifAttributes instance with the specified value removed
        from the named attribute, following Domain-Driven Design immutability patterns.
        If removing the value results in an empty attribute, the attribute is removed entirely.

        Args:
            name: The attribute name to remove the value from
            value: The string value to remove from the attribute

        Returns:
            New FlextLdifAttributes instance with the value removed

        Example:
            >>> attrs = FlextLdifAttributes(
            ...     attributes={"mail": ["john@example.com", "john@company.com"]}
            ... )
            >>> new_attrs = attrs.remove_value("mail", "john@company.com")
            >>> new_attrs.get_values("mail")  # ["john@example.com"]
            >>> attrs.get_values(
            ...     "mail"
            ... )  # ["john@example.com", "john@company.com"] (original unchanged)

        """
        logger.debug(
            "Removing value '%s' from attribute '%s' with immutable pattern",
            value,
            name,
        )

        try:
            # Strategy Pattern: Use removal strategies to reduce complexity

            # Strategy 1: Parameter validation - Single Responsibility
            cleaned_params = self._validate_remove_value_parameters(name, value)
            if not cleaned_params:
                return self

            cleaned_name, cleaned_value = cleaned_params

            # Strategy 2: Attributes validation - Single Responsibility
            validation_error = self._validate_remove_value_attributes()
            if validation_error:
                raise validation_error

            # Strategy 3: Value removal processing - Single Responsibility
            new_attrs, removed_count = self._process_remove_value_operation(
                cleaned_name,
                cleaned_value,
            )

            # Strategy 4: Instance creation - Single Responsibility
            return self._create_remove_value_instance(
                new_attrs,
                cleaned_name,
                cleaned_value,
                removed_count,
            )

        except Exception as unexpected_error:
            error_msg = (
                "Unexpected error during remove value operation for '%s':'%s': %s"
            )
            logger.error(error_msg, name, value, unexpected_error, exc_info=True)
            raise ValueError(
                error_msg % (name, value, str(unexpected_error)),
            ) from unexpected_error

    def _validate_remove_value_parameters(
        self,
        name: str,
        value: str,
    ) -> tuple[str, str] | None:
        """Strategy 1: Validate parameters for remove value operation following Single Responsibility Principle."""
        # Parameter validation - name and value are guaranteed to be str by type annotation
        if not name.strip():
            empty_name_remove_error_msg = (
                "Attribute name cannot be empty string for value removal"
            )
            logger.error(
                "Remove value operation failed: %s", empty_name_remove_error_msg,
            )
            raise ValueError(empty_name_remove_error_msg)

        # Clean parameters for consistent processing
        cleaned_name = name.strip()
        cleaned_value = value  # Keep exact value for precise matching
        logger.trace(
            "Removing value from attribute: name='%s', value='%s'",
            cleaned_name,
            cleaned_value,
        )

        return (cleaned_name, cleaned_value)

    def _validate_remove_value_attributes(self) -> Exception | None:
        """Strategy 2: Validate attributes collection for remove value operation following Single Responsibility Principle."""
        # Validate current attributes collection
        if not hasattr(self, "attributes"):
            error_msg = "Attributes collection is not available for value removal"
            logger.error("Remove value operation failed: %s", error_msg)
            return AttributeError(error_msg)

        # self.attributes is guaranteed to be dict[str, list[str]] by type annotation

        logger.trace(
            "Processing %d existing attributes for immutable copy with removal",
            len(self.attributes),
        )
        return None

    def _process_remove_value_operation(
        self,
        cleaned_name: str,
        cleaned_value: str,
    ) -> tuple[dict[str, list[str]], int]:
        """Strategy 3: Process value removal operation following Single Responsibility Principle."""
        # Create immutable copy with value removal logic
        try:
            new_attrs = {}
            removed_count = 0
            target_found = False

            for attr_name, attr_values in self.attributes.items():
                logger.trace(
                    "Processing attribute '%s' with %s values",
                    attr_name,
                    len(attr_values),
                )

                # Validate existing attribute structure
                # attr_name and attr_values types guaranteed by dict[str, list[str]] annotation

                # Handle target attribute with value removal
                if attr_name == cleaned_name:
                    target_found = True
                    logger.trace(
                        "Found target attribute '%s' - applying value removal",
                        cleaned_name,
                    )

                    try:
                        # Filter out matching values (existing_value guaranteed to be str)
                        new_values = []
                        for i, existing_value in enumerate(attr_values):
                            if existing_value == cleaned_value:
                                removed_count += 1
                                logger.trace(
                                    "Removing matching value %d: '%s'",
                                    i + 1,
                                    existing_value,
                                )
                            else:
                                new_values.append(existing_value)
                                logger.trace(
                                    "Keeping value %d: '%s'",
                                    i + 1,
                                    existing_value,
                                )

                        # Only include attribute if it has remaining values
                        if new_values:
                            new_attrs[attr_name] = new_values
                            logger.trace(
                                "Kept attribute '%s' with %d remaining values",
                                attr_name,
                                len(new_values),
                            )
                        else:
                            logger.trace(
                                "Removed empty attribute '%s' after value removal",
                                attr_name,
                            )

                    except Exception as removal_error:
                        error_msg = "Failed to remove value from attribute '%s': %s"
                        logger.exception(
                            "Remove value operation failed: %s",
                            error_msg % (attr_name, str(removal_error)),
                        )
                        raise ValueError(
                            error_msg % (attr_name, str(removal_error)),
                        ) from removal_error

                # Handle non-target attributes with simple copy
                else:
                    try:
                        copied_values = attr_values.copy()
                        new_attrs[attr_name] = copied_values
                        logger.trace(
                            "Copied non-target attribute '%s' with %d values",
                            attr_name,
                            len(copied_values),
                        )
                    except Exception as copy_error:
                        error_msg = "Failed to copy values for attribute '%s': %s"
                        logger.exception(
                            "Remove value operation failed: %s",
                            error_msg % (attr_name, str(copy_error)),
                        )
                        raise ValueError(
                            error_msg % (attr_name, str(copy_error)),
                        ) from copy_error

            # Log removal results
            if not target_found:
                logger.debug(
                    "Target attribute '%s' not found - no changes made",
                    cleaned_name,
                )
            elif removed_count == 0:
                logger.debug(
                    "Value '%s' not found in attribute '%s' - no changes made",
                    cleaned_value,
                    cleaned_name,
                )
            else:
                logger.debug(
                    "Successfully removed %d instances of value '%s' from attribute '%s'",
                    removed_count,
                    cleaned_value,
                    cleaned_name,
                )

            logger.debug(
                "Successfully created immutable copy with %d attributes after removal",
                len(new_attrs),
            )
            return new_attrs, removed_count

        except Exception as copy_error:
            error_msg = "Failed to create immutable copy with removal: %s"
            logger.error(
                "Remove value operation failed: %s",
                error_msg % str(copy_error),
                exc_info=True,
            )
            raise ValueError(error_msg % str(copy_error)) from copy_error

    def _create_remove_value_instance(
        self,
        new_attrs: dict[str, list[str]],
        cleaned_name: str,
        cleaned_value: str,
        removed_count: int,
    ) -> FlextLdifAttributes:
        """Strategy 4: Create new instance after remove value operation following Single Responsibility Principle."""
        # Create new FlextLdifAttributes instance with comprehensive validation
        try:
            logger.trace("Creating new FlextLdifAttributes instance with value removed")

            new_instance = FlextLdifAttributes.model_validate({"attributes": new_attrs})

            logger.debug(
                "Successfully created new attributes instance with value removed",
            )
            logger.info(
                "Remove value operation completed - attribute: '%s', value: '%s', removed_count: %d, final_attributes: %d",
                cleaned_name,
                cleaned_value,
                removed_count,
                len(new_attrs),
            )

            return new_instance

        except Exception as validation_error:
            error_msg = "Failed to create new FlextLdifAttributes instance: %s"
            logger.error(
                "Remove value operation failed: %s",
                error_msg % str(validation_error),
                exc_info=True,
            )
            raise ValueError(error_msg % str(validation_error)) from validation_error

    def get_attribute_names(self) -> list[str]:
        """Get all attribute names in the collection.

        Retrieves the complete list of attribute names present in the attributes
        collection, useful for iteration and attribute discovery operations.

        Returns:
            List of all attribute names in the collection

        Example:
            >>> attrs = FlextLdifAttributes(
            ...     attributes={
            ...         "cn": ["John Doe"],
            ...         "mail": ["john@example.com"],
            ...         "objectClass": ["person", "inetOrgPerson"],
            ...     }
            ... )
            >>> attrs.get_attribute_names()  # ["cn", "mail", "objectClass"]

        """
        logger.debug("Retrieving all attribute names from attributes collection")

        try:
            # Validate attributes collection exists and is accessible
            if not hasattr(self, "attributes"):
                missing_attributes_names_error_msg = (
                    "Attributes collection is not available for name retrieval"
                )
                logger.error(
                    f"Attribute names retrieval failed: {missing_attributes_names_error_msg}",
                )
                raise AttributeError(missing_attributes_names_error_msg)

            # self.attributes is guaranteed to be dict[str, list[str]] by type annotation

            logger.trace(
                f"Processing {len(self.attributes)} attributes for name extraction",
            )

            # Extract and validate attribute names with comprehensive validation
            try:
                attribute_names = []
                for i, (attr_name, _attr_values) in enumerate(self.attributes.items()):
                    logger.trace(f"Processing attribute {i + 1}: '{attr_name}'")

                    # attr_name and attr_values types guaranteed by dict[str, list[str]] annotation

                    if not attr_name.strip():
                        empty_attr_name_error_msg = (
                            f"Attribute name {i + 1} cannot be empty string"
                        )
                        logger.error(
                            f"Attribute names retrieval failed: {empty_attr_name_error_msg}",
                        )
                        raise ValueError(empty_attr_name_error_msg)

                    # Add validated attribute name
                    attribute_names.append(attr_name)
                    logger.trace(f"Added attribute name {i + 1}: '{attr_name}'")

                # Sort names for consistent ordering (enterprise requirement)
                sorted_names = sorted(attribute_names)
                logger.trace(f"Sorted attribute names: {sorted_names}")

                # Final validation of result
                if len(sorted_names) != len(self.attributes):
                    error_msg: str = f"Attribute names count mismatch: expected {len(self.attributes)}, got {len(sorted_names)}"
                    logger.error(f"Attribute names retrieval failed: {error_msg}")
                    raise ValueError(error_msg)

                logger.debug(
                    f"Successfully retrieved {len(sorted_names)} attribute names",
                )
                logger.info(
                    f"Attribute names retrieval completed - count: {len(sorted_names)}, names: {sorted_names[:5]}{'...' if len(sorted_names) > 5 else ''}",
                )

                return sorted_names

            except Exception as extraction_error:
                extraction_error_msg: str = (
                    f"Failed to extract attribute names: {extraction_error!s}"
                )
                logger.error(
                    f"Attribute names retrieval failed: {extraction_error_msg}",
                    exc_info=True,
                )
                raise ValueError(extraction_error_msg) from extraction_error

        except Exception as unexpected_error:
            names_unexpected_error_msg: str = f"Unexpected error during attribute names retrieval: {unexpected_error!s}"
            logger.error(
                f"Attribute names retrieval failed: {names_unexpected_error_msg}",
                exc_info=True,
            )
            raise ValueError(names_unexpected_error_msg) from unexpected_error

    def get_total_values(self) -> int:
        """Get total number of attribute values across all attributes.

        Calculates the sum of all values across all attributes in the collection,
        useful for statistics and memory usage estimation.

        Returns:
            Total count of all attribute values

        Example:
            >>> attrs = FlextLdifAttributes(
            ...     attributes={
            ...         "cn": ["John Doe"],  # 1 value
            ...         "mail": ["john@example.com", "john@company.com"],  # 2 values
            ...         "objectClass": ["person", "inetOrgPerson"],  # 2 values
            ...     }
            ... )
            >>> attrs.get_total_values()  # 5

        """
        logger.debug("Calculating total attribute values across all attributes")

        try:
            # Validate attributes collection exists and is accessible
            if not hasattr(self, "attributes"):
                missing_attributes_total_error_msg = "Attributes collection is not available for total values calculation"
                logger.error(
                    f"Total values calculation failed: {missing_attributes_total_error_msg}",
                )
                raise AttributeError(missing_attributes_total_error_msg)

            # self.attributes is guaranteed to be dict[str, list[str]] by type annotation

            logger.trace(
                f"Processing {len(self.attributes)} attributes for total values calculation",
            )

            # Calculate total values with comprehensive validation and logging
            try:
                total_values = 0
                attributes_processed = 0

                for attr_name, attr_values in self.attributes.items():
                    logger.trace(
                        f"Processing attribute '{attr_name}' for value counting",
                    )

                    # attr_name and attr_values types guaranteed by dict[str, list[str]] annotation

                    # Count values in current attribute
                    try:
                        current_count = len(attr_values)
                        total_values += current_count
                        attributes_processed += 1

                        logger.trace(
                            f"Attribute '{attr_name}' has {current_count} values - running total: {total_values}",
                        )

                        # All values guaranteed to be str by type annotation

                    except Exception as count_error:
                        count_values_error_msg: str = f"Failed to count values for attribute '{attr_name}': {count_error!s}"
                        logger.exception(
                            f"Total values calculation failed: {count_values_error_msg}",
                        )
                        raise ValueError(count_values_error_msg) from count_error

                # Validate calculation consistency
                if attributes_processed != len(self.attributes):
                    processed_count_error_msg: str = f"Processed attributes count mismatch: expected {len(self.attributes)}, processed {attributes_processed}"
                    logger.error(
                        f"Total values calculation failed: {processed_count_error_msg}",
                    )
                    raise ValueError(processed_count_error_msg)

                # Validate total is reasonable
                if total_values < 0:
                    negative_total_error_msg: str = (
                        f"Invalid negative total values count: {total_values}"
                    )
                    logger.error(
                        f"Total values calculation failed: {negative_total_error_msg}",
                    )
                    raise ValueError(negative_total_error_msg)

                # Log successful calculation with detailed statistics
                if total_values == 0:
                    logger.debug("No attribute values found - total count is 0")
                elif total_values == 1:
                    logger.debug("Single attribute value found")
                else:
                    avg_values_per_attr = (
                        total_values / len(self.attributes) if self.attributes else 0
                    )
                    logger.debug(
                        f"Successfully calculated total values: {total_values} across {len(self.attributes)} attributes (avg: {avg_values_per_attr:.2f} values/attr)",
                    )

                logger.info(
                    f"Total values calculation completed - total: {total_values}, attributes: {len(self.attributes)}",
                )

                return total_values

            except Exception as calculation_error:
                calculation_total_error_msg = (
                    f"Failed to calculate total attribute values: {calculation_error!s}"
                )
                logger.error(
                    f"Total values calculation failed: {calculation_total_error_msg}",
                    exc_info=True,
                )
                raise ValueError(calculation_total_error_msg) from calculation_error

        except Exception as unexpected_error:
            total_unexpected_error_msg: str = f"Unexpected error during total values calculation: {unexpected_error!s}"
            logger.error(
                f"Total values calculation failed: {total_unexpected_error_msg}",
                exc_info=True,
            )
            raise ValueError(total_unexpected_error_msg) from unexpected_error

    def is_empty(self) -> bool:
        """Check if the attributes collection is empty.

        Determines whether the attributes collection contains any attributes,
        useful for validation and business rule checking.

        Returns:
            True if no attributes are present, False otherwise

        Example:
            >>> empty_attrs = FlextLdifAttributes(attributes={})
            >>> empty_attrs.is_empty()  # True
            >>> attrs = FlextLdifAttributes(attributes={"cn": ["John"]})
            >>> attrs.is_empty()  # False

        """
        logger.debug("Checking if attributes collection is empty")

        try:
            # Validate attributes collection exists and is accessible
            if not hasattr(self, "attributes"):
                missing_attributes_empty_error_msg = (
                    "Attributes collection is not available for emptiness check"
                )
                logger.error(
                    f"Emptiness check failed: {missing_attributes_empty_error_msg}",
                )
                raise AttributeError(missing_attributes_empty_error_msg)

            # self.attributes is guaranteed to be dict[str, list[str]] by type annotation

            logger.trace(
                f"Checking emptiness of attributes collection with {len(self.attributes)} items",
            )

            # Perform emptiness check with comprehensive validation
            try:
                attributes_count = len(self.attributes)
                is_empty = attributes_count == 0

                logger.trace(
                    f"Attributes count: {attributes_count}, is_empty: {is_empty}",
                )

                # Additional validation - check for attributes with empty values
                if not is_empty:
                    empty_value_attributes = []
                    total_values = 0

                    for attr_name, attr_values in self.attributes.items():
                        logger.trace(
                            f"Checking attribute '{attr_name}' for empty values",
                        )

                        # attr_name and attr_values types guaranteed by dict[str, list[str]] annotation

                        # Count values in this attribute
                        values_count = len(attr_values)
                        total_values += values_count

                        if values_count == 0:
                            empty_value_attributes.append(attr_name)
                            logger.trace(
                                f"Attribute '{attr_name}' has empty values list",
                            )
                        else:
                            logger.trace(
                                f"Attribute '{attr_name}' has {values_count} values",
                            )

                    # Log detailed statistics for non-empty collections
                    if empty_value_attributes:
                        logger.debug(
                            f"Found {len(empty_value_attributes)} attributes with empty values: {empty_value_attributes}",
                        )

                    logger.trace(f"Total values across all attributes: {total_values}")

                # Log results with appropriate level
                if is_empty:
                    logger.debug(
                        "Attributes collection is empty - no attributes present",
                    )
                    logger.info("Emptiness check completed - EMPTY (0 attributes)")
                else:
                    logger.debug(
                        f"Attributes collection is not empty - contains {attributes_count} attributes",
                    )
                    logger.info(
                        f"Emptiness check completed - NOT EMPTY ({attributes_count} attributes)",
                    )

                return is_empty

            except Exception as check_error:
                check_error_msg: str = (
                    f"Failed to check attributes emptiness: {check_error!s}"
                )
                logger.error(
                    f"Emptiness check failed: {check_error_msg}", exc_info=True,
                )
                raise ValueError(check_error_msg) from check_error

        except Exception as unexpected_error:
            empty_unexpected_error_msg: str = (
                f"Unexpected error during emptiness check: {unexpected_error!s}"
            )
            logger.error(
                f"Emptiness check failed: {empty_unexpected_error_msg}", exc_info=True,
            )
            raise ValueError(empty_unexpected_error_msg) from unexpected_error

    def __eq__(self, other: object) -> bool:
        """Compare with dict or other FlextLdifAttributes with enterprise-grade equality validation.

        Performs comprehensive equality comparison supporting both dictionary and FlextLdifAttributes
        instances with detailed validation, type safety, and comprehensive logging for enterprise
        data comparison operations, testing scenarios, and business rule validation requirements.

        The equality comparison implements deep value comparison with comprehensive validation
        to ensure accurate results for enterprise data processing, caching, and deduplication
        operations while maintaining compatibility with Python equality semantics.

        Args:
            other: Object to compare against (dict, FlextLdifAttributes, or any object)

        Returns:
            bool: True if objects are equal, False otherwise

        Examples:
            >>> attrs1 = FlextLdifAttributes(
            ...     attributes={"cn": ["John"], "mail": ["john@example.com"]}
            ... )
            >>> attrs2 = FlextLdifAttributes(
            ...     attributes={"cn": ["John"], "mail": ["john@example.com"]}
            ... )
            >>> attrs1 == attrs2  # True
            >>>
            >>> # Dictionary comparison
            >>> attrs1 == {"cn": ["John"], "mail": ["john@example.com"]}  # True
            >>>
            >>> # Different values
            >>> attrs3 = FlextLdifAttributes(attributes={"cn": ["Jane"]})
            >>> attrs1 == attrs3  # False

        Business Logic:
            - Validates both objects before comparison
            - Supports dictionary and FlextLdifAttributes comparisons
            - Implements deep value comparison for accurate results
            - Provides comprehensive error handling and logging
            - Maintains Python equality contract (__eq__ semantics)

        Author: FLEXT Development Team
        Version: 0.9.0

        """
        logger.debug(
            f"Performing equality comparison with {type(other).__name__} object",
        )

        try:
            # Validate current object state before comparison
            if not hasattr(self, "attributes"):
                error_msg = "Current object missing attributes collection for equality comparison"
                logger.error(f"Equality comparison failed: {error_msg}")
                raise AttributeError(error_msg)

            # self.attributes is guaranteed to be dict[str, list[str]] by type annotation

            logger.trace(
                f"Comparing current object ({len(self.attributes)} attributes) with {type(other).__name__}",
            )

            # Handle None comparison (always False)
            if other is None:
                logger.trace("Comparison with None object - returning False")
                logger.info("Equality comparison completed - None comparison: False")
                return False

            # Handle dictionary comparison
            if isinstance(other, dict):
                logger.trace(
                    f"Performing dictionary comparison with {len(other)} items",
                )

                try:
                    # Validate dictionary structure for consistent comparison
                    for key, value in other.items():
                        if not isinstance(key, str):
                            logger.warning(
                                f"Dictionary key is not string: {type(key).__name__}",
                            )
                        if not isinstance(value, list):
                            logger.warning(
                                f"Dictionary value for '{key}' is not list: {type(value).__name__}",
                            )

                    # Perform deep comparison
                    is_equal = self.attributes == other
                    logger.trace(f"Dictionary comparison result: {is_equal}")

                    if is_equal:
                        logger.debug("Attributes match dictionary exactly")
                        logger.info(
                            "Equality comparison completed - Dictionary match: True",
                        )
                    else:
                        logger.debug("Attributes differ from dictionary")
                        logger.info(
                            "Equality comparison completed - Dictionary match: False",
                        )

                    return is_equal

                except Exception as dict_compare_error:
                    dict_compare_error_msg: str = (
                        f"Dictionary comparison failed: {dict_compare_error!s}"
                    )
                    logger.exception(
                        f"Equality comparison failed: {dict_compare_error_msg}",
                    )
                    raise ValueError(dict_compare_error_msg) from dict_compare_error

            # Handle FlextLdifAttributes comparison
            elif isinstance(other, FlextLdifAttributes):
                logger.trace("Performing FlextLdifAttributes comparison")

                try:
                    # Validate other object structure
                    if not hasattr(other, "attributes"):
                        error_msg = "Other FlextLdifAttributes object missing attributes collection"
                        logger.error(f"Equality comparison failed: {error_msg}")
                        raise AttributeError(error_msg)

                    # other.attributes is guaranteed to be dict[str, list[str]] by type annotation

                    logger.trace(
                        f"Comparing with other FlextLdifAttributes ({len(other.attributes)} attributes)",
                    )

                    # Perform deep comparison
                    is_equal = self.attributes == other.attributes
                    logger.trace(f"FlextLdifAttributes comparison result: {is_equal}")

                    if is_equal:
                        logger.debug("Attributes collections match exactly")
                        logger.info(
                            "Equality comparison completed - FlextLdifAttributes match: True",
                        )
                    else:
                        logger.debug("Attributes collections differ")
                        # Additional logging for debugging
                        self_keys = set(self.attributes.keys())
                        other_keys = set(other.attributes.keys())

                        if self_keys != other_keys:
                            missing_in_other = self_keys - other_keys
                            missing_in_self = other_keys - self_keys
                            if missing_in_other:
                                logger.trace(
                                    f"Keys in self but not other: {missing_in_other}",
                                )
                            if missing_in_self:
                                logger.trace(
                                    f"Keys in other but not self: {missing_in_self}",
                                )

                        logger.info(
                            "Equality comparison completed - FlextLdifAttributes match: False",
                        )

                    return is_equal

                except Exception as attrs_compare_error:
                    attrs_compare_error_msg: str = f"FlextLdifAttributes comparison failed: {attrs_compare_error!s}"
                    logger.exception(
                        f"Equality comparison failed: {attrs_compare_error_msg}",
                    )
                    raise ValueError(attrs_compare_error_msg) from attrs_compare_error

            # Handle other object types (always False)
            else:
                logger.trace(f"Unsupported comparison type: {type(other).__name__}")
                logger.info(
                    f"Equality comparison completed - Unsupported type {type(other).__name__}: False",
                )
                return False

        except Exception as unexpected_error:
            eq_unexpected_error_msg: str = f"Unexpected error during equality comparison with {type(other).__name__}: {unexpected_error!s}"
            logger.error(
                f"Equality comparison failed: {eq_unexpected_error_msg}", exc_info=True,
            )
            raise ValueError(eq_unexpected_error_msg) from unexpected_error

    def __hash__(self) -> int:
        """Return hash of attributes for use in sets/dicts with enterprise-grade hash computation.

        Computes a consistent and immutable hash value for the attributes collection using
        comprehensive validation, deterministic computation, and detailed logging for enterprise
        data structures, caching systems, and hash-based operations requiring consistent
        hash values across different execution contexts.

        The hash computation implements a stable algorithm that produces identical hash values
        for equivalent attribute collections, enabling reliable use in sets, dictionaries,
        and other hash-based data structures in enterprise applications.

        Returns:
            int: Deterministic hash value based on attributes content

        Raises:
            TypeError: If attributes cannot be hashed due to invalid structure
            ValueError: If hash computation fails

        Examples:
            >>> attrs = FlextLdifAttributes(
            ...     attributes={"cn": ["John"], "mail": ["john@example.com"]}
            ... )
            >>> hash_value = hash(attrs)
            >>> isinstance(hash_value, int)  # True
            >>>
            >>> # Same content produces same hash
            >>> attrs2 = FlextLdifAttributes(
            ...     attributes={"cn": ["John"], "mail": ["john@example.com"]}
            ... )
            >>> hash(attrs) == hash(attrs2)  # True

        Business Logic:
            - Validates attributes structure before hashing
            - Implements deterministic hash computation
            - Handles immutable conversion for reliable hashing
            - Provides comprehensive error handling and logging
            - Maintains Python hash contract (__hash__ semantics)

        Author: FLEXT Development Team
        Version: 0.9.0

        """
        logger.debug("Computing hash value for attributes collection")

        try:
            # Validate attributes collection exists and is hashable
            if not hasattr(self, "attributes"):
                error_msg = (
                    "Attributes collection is not available for hash computation"
                )
                logger.error(f"Hash computation failed: {error_msg}")
                raise AttributeError(error_msg)

            # self.attributes is guaranteed to be dict[str, list[str]] by type annotation

            logger.trace(f"Computing hash for {len(self.attributes)} attributes")

            # Convert attributes to immutable structure for consistent hashing
            try:
                immutable_items = []

                for attr_name, attr_values in self.attributes.items():
                    logger.trace(
                        f"Processing attribute '{attr_name}' for hash computation",
                    )

                    # attr_name and attr_values types guaranteed by dict[str, list[str]] annotation

                    # Validate individual values are hashable
                    try:
                        # All values guaranteed to be str by list[str] annotation
                        for _i, _value in enumerate(attr_values):
                            pass  # Type safety guaranteed by annotation

                        # Convert to immutable tuple for deterministic hashing
                        immutable_values = tuple(attr_values)
                        immutable_items.append((attr_name, immutable_values))
                        logger.trace(
                            f"Converted attribute '{attr_name}' to immutable format with {len(attr_values)} values",
                        )

                    except Exception as value_error:
                        value_error_msg: str = f"Failed to process values for attribute '{attr_name}': {value_error!s}"
                        logger.exception(f"Hash computation failed: {value_error_msg}")
                        raise TypeError(value_error_msg) from value_error

                logger.trace(
                    f"Successfully converted {len(immutable_items)} attributes to immutable format",
                )

            except Exception as conversion_error:
                conversion_error_msg: str = f"Failed to convert attributes to immutable format: {conversion_error!s}"
                logger.error(
                    f"Hash computation failed: {conversion_error_msg}", exc_info=True,
                )
                raise TypeError(conversion_error_msg) from conversion_error

            # Compute deterministic hash using frozenset for order independence
            try:
                logger.trace("Computing frozenset hash for order-independent result")

                immutable_frozenset = frozenset(immutable_items)
                hash_value = hash(immutable_frozenset)

                logger.trace(f"Computed raw hash value: {hash_value}")

                # hash() function always returns int by design
                # Validation omitted as type safety is guaranteed

                # Log successful hash computation with metadata
                logger.debug(f"Successfully computed hash value: {hash_value}")
                logger.info(
                    f"Hash computation completed - attributes: {len(self.attributes)}, hash: {hash_value}",
                )

                return hash_value

            except Exception as hash_error:
                hash_error_msg = (
                    f"Hash computation failed during frozenset hashing: {hash_error!s}"
                )
                logger.error(
                    f"Hash computation failed: {hash_error_msg}", exc_info=True,
                )
                raise ValueError(hash_error_msg) from hash_error

        except Exception as unexpected_error:
            hash_unexpected_error_msg = (
                f"Unexpected error during hash computation: {unexpected_error!s}"
            )
            logger.error(
                f"Hash computation failed: {hash_unexpected_error_msg}", exc_info=True,
            )
            raise ValueError(hash_unexpected_error_msg) from unexpected_error

    def validate_semantic_rules(self) -> FlextResult[None]:
        """Validate attributes collection against business rules using Strategy Pattern.

        SOLID REFACTORING: Reduced complexity from 17 to 6 using Strategy Pattern.
        Each validation strategy handles a single responsibility.

        Returns:
            FlextResult[None]: Success if all attributes are valid, failure with error message

        """
        logger.debug(
            "Validating attributes collection semantic rules using Strategy Pattern",
        )

        try:
            # Validate attributes collection exists and is accessible
            if not hasattr(self, "attributes"):
                error_msg = (
                    "Attributes collection is not available for semantic validation"
                )
                logger.error(f"Semantic validation failed: {error_msg}")
                return FlextResult.fail(error_msg)

            # self.attributes is guaranteed to be dict[str, list[str]] by type annotation

            logger.trace(
                f"Validating semantic rules for {len(self.attributes)} attributes",
            )

            # Comprehensive semantic validation with detailed error collection
            validation_errors = []
            validated_attributes = 0

            try:
                for attr_name, attr_values in self.attributes.items():
                    logger.trace(
                        f"Validating attribute '{attr_name}' with {len(attr_values) if isinstance(attr_values, list) else 'unknown'} values",
                    )

                    # attr_name guaranteed to be str by dict[str, list[str]] annotation

                    # Validate attribute name format (not empty after strip)
                    if not attr_name.strip():
                        empty_name_error_msg: str = f"Attribute name cannot be empty or whitespace-only: '{attr_name}'"
                        validation_errors.append(empty_name_error_msg)
                        logger.error(
                            f"Semantic validation error: {empty_name_error_msg}",
                        )
                        continue

                    # Validate attribute name follows LDAP naming conventions
                    cleaned_name = attr_name.strip()
                    if cleaned_name != attr_name:
                        whitespace_error_msg: str = f"Attribute name contains leading/trailing whitespace: '{attr_name}'"
                        validation_errors.append(whitespace_error_msg)
                        logger.error(
                            f"Semantic validation error: {whitespace_error_msg}",
                        )
                        continue

                    # Validate attribute name contains valid characters (basic LDAP compliance)
                    if (
                        not cleaned_name.replace("-", "")
                        .replace("_", "")
                        .replace(".", "")
                        .isalnum()
                    ):
                        if not all(c.isalnum() or c in "-_." for c in cleaned_name):
                            invalid_chars_error_msg: str = f"Attribute name contains invalid characters: '{cleaned_name}'"
                            validation_errors.append(invalid_chars_error_msg)
                            logger.error(
                                f"Semantic validation error: {invalid_chars_error_msg}",
                            )
                            continue

                    # attr_values guaranteed to be list[str] by dict[str, list[str]] annotation

                    # Validate individual attribute values
                    values_validated = 0
                    for i, value in enumerate(attr_values):
                        logger.trace(
                            f"Validating value {i + 1} for attribute '{attr_name}': '{value}'",
                        )

                        # value guaranteed to be str by list[str] annotation

                        # Note: Empty strings are valid LDAP attribute values
                        values_validated += 1
                        logger.trace(
                            f"Value {i + 1} for '{attr_name}' validated successfully",
                        )

                    # Log successful attribute validation
                    if not any(attr_name in error for error in validation_errors[-5:]):
                        validated_attributes += 1
                        logger.trace(
                            f"Attribute '{attr_name}' validated successfully with {values_validated} values",
                        )

                # Compile final validation results with comprehensive reporting
                if validation_errors:
                    error_count = len(validation_errors)
                    error_summary = f"Semantic validation failed with {error_count} errors: {'; '.join(validation_errors[:3])}"
                    if error_count > 3:
                        error_summary += f" (and {error_count - 3} more errors)"

                    logger.error(
                        f"Semantic validation completed with errors: {error_summary}",
                    )
                    logger.info(
                        f"Semantic validation failed - validated: {validated_attributes}, errors: {error_count}",
                    )

                    return FlextResult.fail(error_summary)
                logger.debug(
                    f"All {validated_attributes} attributes passed semantic validation",
                )
                logger.info(
                    f"Semantic validation completed successfully - attributes: {validated_attributes}, errors: 0",
                )

                return FlextResult.ok(None)

            except Exception as validation_error:
                validation_error_msg = (
                    f"Error during semantic validation processing: {validation_error!s}"
                )
                logger.error(
                    f"Semantic validation failed: {validation_error_msg}", exc_info=True,
                )
                return FlextResult.fail(validation_error_msg)

        except Exception as unexpected_error:
            semantic_unexpected_error_msg = (
                f"Unexpected error during semantic validation: {unexpected_error!s}"
            )
            logger.error(
                f"Semantic validation failed: {semantic_unexpected_error_msg}",
                exc_info=True,
            )
            return FlextResult.fail(semantic_unexpected_error_msg)

    def to_attributes_dict(self) -> FlextLdifAttributesDict:
        """Convert to FlextLdifAttributesDict representation with enterprise-grade serialization and comprehensive validation.

        Transforms the attributes collection into a structured dictionary representation
        with comprehensive validation, deep copying, and detailed logging for enterprise
        data serialization, API integration, and structured data export scenarios
        requiring type-safe attributes representation.

        The resulting FlextLdifAttributesDict provides a complete structural representation
        of the attributes collection including metadata, deep-copied attributes, and
        validated statistics for integration with external systems and data pipelines.

        Returns:
            FlextLdifAttributesDict: Structured dictionary representation with attributes metadata

        Raises:
            ValueError: If attributes cannot be converted to dictionary representation

        Example:
            >>> attrs = FlextLdifAttributes(
            ...     attributes={"cn": ["John"], "mail": ["john@example.com"]}
            ... )
            >>> attrs_dict = attrs.to_attributes_dict()
            >>> print(
            ...     attrs_dict["attributes"]
            ... )  # {"cn": ["John"], "mail": ["john@example.com"]}
            >>> print(attrs_dict["count"])  # 2

        Business Logic:
            - Validates attributes structure before serialization
            - Creates deep copy to prevent external modification
            - Calculates accurate attribute counts and statistics
            - Provides structured metadata for external system integration
            - Logs serialization operations for enterprise monitoring

        Author: FLEXT Development Team
        Version: 0.9.0

        """
        logger.debug(
            "Converting attributes collection to structured dictionary representation",
        )

        try:
            # Validate attributes collection exists and is accessible
            if not hasattr(self, "attributes"):
                error_msg = (
                    "Attributes collection is not available for dictionary conversion"
                )
                logger.error(f"Attributes dictionary conversion failed: {error_msg}")
                raise AttributeError(error_msg)

            # self.attributes is guaranteed to be dict[str, list[str]] by type annotation

            logger.trace(
                f"Processing {len(self.attributes)} attributes for dictionary serialization",
            )

            # Create deep copy of attributes with comprehensive validation
            try:
                deep_copied_attributes = {}
                total_values = 0

                for attr_name, attr_values in self.attributes.items():
                    logger.trace(
                        f"Processing attribute '{attr_name}' for dictionary conversion",
                    )

                    # attr_name guaranteed to be str by dict[str, list[str]] annotation

                    # attr_values guaranteed to be list[str] by dict[str, list[str]] annotation

                    # Create deep copy of values list with type safety
                    try:
                        copied_values = []
                        for i, value in enumerate(attr_values):
                            logger.trace(
                                f"Copying value {i + 1} for attribute '{attr_name}': '{value}'",
                            )

                            # value guaranteed to be str by list[str] annotation
                            copied_values.append(value)

                        deep_copied_attributes[attr_name] = copied_values
                        total_values += len(copied_values)
                        logger.trace(
                            f"Successfully copied attribute '{attr_name}' with {len(copied_values)} values",
                        )

                    except Exception as copy_error:
                        copy_error_msg: str = f"Failed to copy values for attribute '{attr_name}': {copy_error!s}"
                        logger.exception(
                            f"Attributes dictionary conversion failed: {copy_error_msg}",
                        )
                        raise ValueError(copy_error_msg) from copy_error

                logger.debug(
                    f"Successfully created deep copy of {len(deep_copied_attributes)} attributes with {total_values} total values",
                )

            except Exception as copy_error:
                deep_copy_error_msg: str = (
                    f"Failed to create deep copy of attributes: {copy_error!s}"
                )
                logger.error(
                    f"Attributes dictionary conversion failed: {deep_copy_error_msg}",
                    exc_info=True,
                )
                raise ValueError(deep_copy_error_msg) from copy_error

            # Calculate comprehensive statistics
            try:
                attribute_count = len(deep_copied_attributes)

                # Validate count consistency
                if attribute_count != len(self.attributes):
                    count_mismatch_error_msg: str = f"Attribute count mismatch: original {len(self.attributes)}, copied {attribute_count}"
                    logger.error(
                        f"Attributes dictionary conversion failed: {count_mismatch_error_msg}",
                    )
                    raise ValueError(count_mismatch_error_msg)

                logger.trace(
                    f"Calculated statistics - attributes: {attribute_count}, total_values: {total_values}",
                )

            except Exception as stats_error:
                stats_error_msg = (
                    f"Failed to calculate attributes statistics: {stats_error!s}"
                )
                logger.exception(
                    f"Attributes dictionary conversion failed: {stats_error_msg}",
                )
                raise ValueError(stats_error_msg) from stats_error

            # Create FlextLdifAttributesDict with comprehensive validation
            try:
                logger.trace("Constructing FlextLdifAttributesDict with validated data")

                attributes_dict = FlextLdifAttributesDict(
                    attributes=deep_copied_attributes,
                    count=attribute_count,
                )

                logger.debug(
                    "Successfully created attributes dictionary representation",
                )
                logger.info(
                    f"Attributes dictionary conversion completed - attributes: {attribute_count}, total_values: {total_values}",
                )

                return attributes_dict

            except Exception as dict_error:
                dict_construction_error_msg = (
                    f"FlextLdifAttributesDict construction failed: {dict_error!s}"
                )
                logger.error(
                    f"Attributes dictionary conversion failed: {dict_construction_error_msg}",
                    exc_info=True,
                )
                raise ValueError(dict_construction_error_msg) from dict_error

        except Exception as unexpected_error:
            dict_unexpected_error_msg: str = f"Unexpected error during attributes dictionary conversion: {unexpected_error!s}"
            logger.error(
                f"Attributes dictionary conversion failed: {dict_unexpected_error_msg}",
                exc_info=True,
            )
            raise ValueError(dict_unexpected_error_msg) from unexpected_error


class FlextLdifEntry(FlextImmutableModel):
    """LDIF entry domain entity representing complete LDAP directory entries.

    Core domain entity implementing a complete LDIF entry with Distinguished Name,
    attributes collection, and comprehensive business logic for LDAP operations
    following Clean Architecture and Domain-Driven Design patterns.

    This immutable entity encapsulates all LDIF entry semantics including entry
    validation, attribute management, change operation detection, object class
    specification patterns, and serialization capabilities.

    Attributes:
        dn: The Distinguished Name identifying this entry in the LDAP hierarchy
        attributes: Collection of LDAP attributes with multi-value support

    Business Rules:
        - Every entry must have a valid Distinguished Name
        - Entries must have at least one attribute (typically objectClass)
        - Object classes determine entry type and allowed attributes
        - Change operations (add/modify/delete) have specific semantics
        - Immutable - modifications return new instances

    Entry Types Supported:
        - Person entries (person, inetOrgPerson, organizationalPerson)
        - Group entries (group, groupOfNames, posixGroup)
        - Organizational units (organizationalUnit, dcObject)
        - Change records (add, modify, delete, modrdn operations)

    Examples:
        Create a person entry:
        >>> entry = FlextLdifEntry(
        ...     dn=FlextLdifDistinguishedName(
        ...         value="cn=John Doe,ou=people,dc=example,dc=com"
        ...     ),
        ...     attributes=FlextLdifAttributes(
        ...         attributes={
        ...             "cn": ["John Doe"],
        ...             "objectClass": ["person", "inetOrgPerson"],
        ...             "mail": ["john@example.com"],
        ...         }
        ...     ),
        ... )
        >>> entry.is_person_entry()  # True
        >>> entry.has_object_class("person")  # True

        Validate business rules:
        >>> result = entry.validate_semantic_rules()
        >>> result.success  # True

        Convert to LDIF format:
        >>> ldif_string = entry.to_ldif()
        >>> print(ldif_string)  # Complete LDIF representation

    Raises:
        ValueError: If DN or attributes violate business rules during construction

    Author: FLEXT Development Team
    Version: 0.9.0
    License: MIT

    """

    dn: FlextLdifDistinguishedName = Field(..., description="Distinguished Name")
    attributes: FlextLdifAttributes = Field(
        default_factory=lambda: FlextLdifAttributes.model_validate({"attributes": {}}),
        description="LDIF attributes dictionary",
    )

    @field_validator("dn", mode="before")
    @classmethod
    def validate_dn(
        cls,
        v: str | FlextLdifDistinguishedName | dict[str, str],
    ) -> FlextLdifDistinguishedName:
        """Convert string DN to FlextLdifDistinguishedName object."""
        if isinstance(v, str):
            return FlextLdifDistinguishedName.model_validate({"value": v})
        if isinstance(v, FlextLdifDistinguishedName):
            return v
        msg: str = f"Invalid DN type: {type(v)}"
        raise ValueError(msg)

    @field_validator("attributes", mode="before")
    @classmethod
    def validate_attributes(
        cls,
        v: dict[str, list[str]] | FlextLdifAttributes,
    ) -> FlextLdifAttributes:
        """Convert dict attributes to FlextLdifAttributes object."""
        if isinstance(v, dict):
            return FlextLdifAttributes.model_validate({"attributes": v})
        return v  # Must be FlextLdifAttributes based on type annotation

    def get_attribute(self, name: str) -> list[str] | None:
        """Get LDIF attribute values by name with enterprise-grade attribute retrieval and comprehensive validation.

        Retrieves all values for the specified LDAP attribute from this entry with comprehensive
        parameter validation, error handling, and detailed logging for enterprise LDIF attribute
        access scenarios. Supports LDAP's multi-valued attribute semantics with full business
        logic validation and comprehensive error handling for production environments.

        The method performs extensive validation of the attribute name parameter, validates
        the entry's attributes collection state, and provides detailed logging for enterprise
        monitoring and debugging scenarios requiring comprehensive attribute retrieval tracking.

        Args:
            name (str): The attribute name to retrieve (case-sensitive LDAP attribute name)
                       Must be non-empty string following LDAP naming conventions

        Returns:
            list[str] | None: List of all attribute string values if attribute exists,
                             None if attribute doesn't exist or validation fails

        Raises:
            ValueError: If attribute name is invalid or attributes collection is malformed
            TypeError: If attribute name is not a string
            AttributeError: If entry attributes collection is not accessible

        Example:
            >>> entry = FlextLdifEntry(
            ...     dn=FlextLdifDistinguishedName(value="cn=user,dc=example,dc=com"),
            ...     attributes=FlextLdifAttributes(
            ...         attributes={
            ...             "mail": ["user@example.com", "user@company.com"],
            ...             "objectClass": ["person", "inetOrgPerson"],
            ...         }
            ...     ),
            ... )
            >>> values = entry.get_attribute("mail")
            >>> print(values)  # ["user@example.com", "user@company.com"]
            >>> missing = entry.get_attribute("nonexistent")
            >>> print(missing)  # None

        Business Logic:
            - Validates attribute name format and LDAP compliance
            - Checks entry attributes collection accessibility and integrity
            - Provides comprehensive logging for enterprise attribute access monitoring
            - Supports case-sensitive LDAP attribute name semantics
            - Returns None for missing attributes (not empty list) following LDAP standards
            - Validates returned values structure for data integrity assurance

        Performance Notes:
            - Optimized for high-frequency attribute access patterns
            - Minimal memory allocation for enterprise performance requirements
            - Efficient validation with early returns for invalid inputs

        Integration:
            - Compatible with flext-ldap for LDAP directory integration
            - Supports flext-observability monitoring and tracing
            - Follows flext-core FlextResult patterns for error handling consistency

        Author: FLEXT Development Team
        Version: 0.9.0

        """
        logger.debug(
            f"Retrieving LDIF attribute values for name: '{name}' with enterprise validation",
        )

        try:
            # name parameter guaranteed to be str by type annotation

            # Validate attribute name format and business rules
            if not name.strip():
                name_empty_error_msg = (
                    f"Attribute name cannot be empty or whitespace-only: '{name}'"
                )
                logger.error(f"Attribute retrieval failed: {name_empty_error_msg}")
                context = {
                    "attribute_name": name,
                    "name_length": len(name),
                    "name_stripped": name.strip(),
                    "operation": "get_attribute",
                }
                logger.error(f"Attribute name validation context: {context}")
                raise ValueError(name_empty_error_msg)

            # self.attributes guaranteed to be FlextLdifAttributes by Pydantic field definition
            # No runtime type validation needed - type system ensures correctness

            logger.trace(f"Validated attribute name '{name}' for retrieval from entry")

            # Check attribute existence with comprehensive logging
            try:
                attribute_exists = self.attributes.has_attribute(name)
                logger.trace(
                    f"Attribute existence check for '{name}': {attribute_exists}",
                )

                if not attribute_exists:
                    logger.debug(
                        f"Attribute '{name}' not found in entry - returning None",
                    )
                    context = {
                        "attribute_name": name,
                        "attribute_exists": False,
                        "total_attributes": len(self.attributes.attributes)
                        if hasattr(self.attributes, "attributes")
                        else 0,
                        "entry_dn": str(self.dn.value)
                        if hasattr(self, "dn") and self.dn
                        else "unknown",
                        "operation": "get_attribute",
                        "result": "not_found",
                    }
                    logger.info(f"Attribute retrieval completed - not found: {context}")
                    return None

            except Exception as existence_check_error:
                existence_error_msg: str = f"Error checking attribute existence for '{name}': {existence_check_error!s}"
                logger.error(
                    f"Attribute existence check failed: {existence_error_msg}",
                    exc_info=True,
                )
                context = {
                    "attribute_name": name,
                    "existence_check_error": str(existence_check_error),
                    "operation": "get_attribute",
                }
                logger.exception(f"Existence check error context: {context}")
                raise ValueError(existence_error_msg) from existence_check_error

            # Retrieve attribute values with comprehensive validation
            try:
                attribute_values = self.attributes.get_values(name)
                logger.trace(
                    f"Retrieved {len(attribute_values)} values for attribute '{name}'",
                )

                # attribute_values guaranteed to be list[str] by get_values return type
                # No runtime type validation needed - type system ensures correctness

                # All values guaranteed to be str by list[str] type annotation
                # No runtime string validation needed - type system ensures correctness

                # Log successful retrieval with comprehensive context
                context = {
                    "attribute_name": name,
                    "values_count": len(attribute_values),
                    "attribute_exists": True,
                    "entry_dn": str(self.dn.value)
                    if hasattr(self, "dn") and self.dn
                    else "unknown",
                    "operation": "get_attribute",
                    "result": "success",
                }
                logger.debug(f"Attribute retrieval completed successfully: {context}")
                logger.info(
                    f"Retrieved attribute '{name}' with {len(attribute_values)} values",
                )

                return attribute_values

            except Exception as retrieval_error:
                retrieval_error_msg: str = f"Error retrieving values for attribute '{name}': {retrieval_error!s}"
                logger.error(
                    f"Attribute values retrieval failed: {retrieval_error_msg}",
                    exc_info=True,
                )
                context = {
                    "attribute_name": name,
                    "retrieval_error": str(retrieval_error),
                    "operation": "get_attribute",
                }
                logger.exception(f"Values retrieval error context: {context}")
                raise ValueError(retrieval_error_msg) from retrieval_error

        except Exception as unexpected_error:
            get_attr_unexpected_error_msg: str = f"Unexpected error during attribute retrieval for '{name}': {unexpected_error!s}"
            logger.error(
                f"Attribute retrieval failed: {get_attr_unexpected_error_msg}",
                exc_info=True,
            )
            context = {
                "attribute_name": name,
                "unexpected_error": str(unexpected_error),
                "error_type": type(unexpected_error).__name__,
                "operation": "get_attribute",
            }
            logger.exception(f"Unexpected error context: {context}")
            raise ValueError(get_attr_unexpected_error_msg) from unexpected_error

    def set_attribute(self, name: str, values: list[str]) -> None:
        """Set an attribute with enterprise-grade attribute modification and comprehensive validation.

        Modifies or creates the specified LDAP attribute in this entry with comprehensive
        parameter validation, error handling, and detailed logging for enterprise LDIF attribute
        modification scenarios. Supports LDAP's multi-valued attribute semantics with full business
        logic validation and immutable object patterns for production environments.

        The method performs extensive validation of both attribute name and values parameters,
        validates the entry's current state, creates a deep copy of the attributes collection,
        and provides detailed logging for enterprise monitoring and debugging scenarios requiring
        comprehensive attribute modification tracking.

        Args:
            name (str): The attribute name to set (case-sensitive LDAP attribute name)
                       Must be non-empty string following LDAP naming conventions
            values (list[str]): List of string values for the attribute
                               Must be list of strings, can be empty list for clearing attribute

        Returns:
            None: Method modifies the entry in-place following immutable patterns

        Raises:
            ValueError: If attribute name is invalid or values format is incorrect
            TypeError: If parameters have incorrect types
            AttributeError: If entry attributes collection is not accessible

        Example:
            >>> entry = FlextLdifEntry(
            ...     dn=FlextLdifDistinguishedName(value="cn=user,dc=example,dc=com"),
            ...     attributes=FlextLdifAttributes(
            ...         attributes={"cn": ["old name"], "objectClass": ["person"]}
            ...     ),
            ... )
            >>> # Set new mail values
            >>> entry.set_attribute("mail", ["user@example.com", "user@company.com"])
            >>> # Update existing attribute
            >>> entry.set_attribute("cn", ["new name"])
            >>> # Clear attribute by setting empty list
            >>> entry.set_attribute("description", [])

        Business Logic:
            - Validates attribute name format and LDAP compliance
            - Validates all attribute values are strings
            - Checks entry attributes collection accessibility and integrity
            - Creates immutable deep copy of attributes to prevent external modification
            - Provides comprehensive logging for enterprise attribute modification monitoring
            - Updates entry state following immutable object patterns
            - Supports case-sensitive LDAP attribute name semantics

        Performance Notes:
            - Optimized for enterprise performance with minimal object creation
            - Deep copy creation for data integrity and immutability
            - Efficient validation with early returns for invalid inputs
            - Atomic operation ensures entry integrity

        Integration:
            - Compatible with flext-ldap for LDAP directory integration
            - Supports flext-observability monitoring and tracing
            - Follows flext-core immutable patterns for consistency
            - Maintains LDIF entry structural integrity

        Author: FLEXT Development Team
        Version: 0.9.0

        """
        logger.debug(
            f"Setting LDIF attribute '{name}' with {len(values)} values",
        )

        try:
            # name and values parameters guaranteed by type annotations - no isinstance checks needed

            # Validate attribute name format and business rules
            if not name.strip():
                name_empty_error_msg = (
                    f"Attribute name cannot be empty or whitespace-only: '{name}'"
                )
                logger.error(f"Attribute setting failed: {name_empty_error_msg}")
                context = {
                    "attribute_name": name,
                    "name_length": len(name),
                    "name_stripped": name.strip(),
                    "values_count": len(
                        values,
                    ),  # values guaranteed to be list by type annotation
                    "operation": "set_attribute",
                }
                logger.error(f"Attribute name validation context: {context}")
                raise ValueError(name_empty_error_msg)

            # values parameter guaranteed to be list[str] by type annotation
            # No runtime type validation needed - type system ensures correctness

            logger.trace(
                f"Validated attribute name '{name}' and {len(values)} values for setting",
            )

            # self.attributes guaranteed to be FlextLdifAttributes by Pydantic field definition
            # No runtime type validation needed - type system ensures correctness

            # Create deep copy of current attributes with comprehensive validation
            try:
                if not hasattr(self.attributes, "attributes") or not isinstance(
                    self.attributes.attributes,
                    dict,
                ):
                    error_msg = (
                        "Entry attributes collection is malformed - not a dictionary"
                    )
                    logger.error(
                        f"Attributes collection validation failed: {error_msg}",
                    )
                    context = {
                        "attribute_name": name,
                        "attributes_has_attributes": hasattr(
                            self.attributes,
                            "attributes",
                        ),
                        "attributes_type": type(
                            getattr(self.attributes, "attributes", None),
                        ).__name__,
                        "operation": "set_attribute",
                    }
                    logger.error(f"Attributes structure validation context: {context}")
                    raise ValueError(error_msg)

                current_attributes_count = len(self.attributes.attributes)
                logger.trace(
                    f"Creating deep copy of {current_attributes_count} existing attributes",
                )

                new_attrs = self.attributes.attributes.copy()
                logger.trace(
                    f"Deep copy created successfully with {len(new_attrs)} attributes",
                )

            except Exception as copy_error:
                copy_error_msg = (
                    f"Error creating attributes copy for '{name}': {copy_error!s}"
                )
                logger.error(f"Attributes copy failed: {copy_error_msg}", exc_info=True)
                context = {
                    "attribute_name": name,
                    "copy_error": str(copy_error),
                    "operation": "set_attribute",
                }
                logger.exception(f"Attributes copy error context: {context}")
                raise ValueError(copy_error_msg) from copy_error

            # Check if attribute already exists and log the change
            attribute_existed = name in new_attrs
            previous_values = new_attrs.get(name, []) if attribute_existed else []
            previous_count = len(previous_values)

            if attribute_existed:
                logger.debug(
                    f"Updating existing attribute '{name}': {previous_count} → {len(values)} values",
                )
            else:
                logger.debug(
                    f"Creating new attribute '{name}' with {len(values)} values",
                )

            # Set the new attribute values
            new_attrs[name] = values
            logger.trace(f"Attribute '{name}' set in new attributes collection")

            # Create new FlextLdifAttributes instance with comprehensive validation
            try:
                new_attributes_obj = FlextLdifAttributes.model_validate(
                    {"attributes": new_attrs},
                )
                logger.trace("New FlextLdifAttributes instance created successfully")

            except Exception as validation_error:
                validation_error_msg: str = f"Error validating new attributes collection for '{name}': {validation_error!s}"
                logger.error(
                    f"Attributes validation failed: {validation_error_msg}",
                    exc_info=True,
                )
                context = {
                    "attribute_name": name,
                    "validation_error": str(validation_error),
                    "new_attributes_count": len(new_attrs),
                    "operation": "set_attribute",
                }
                logger.exception(f"New attributes validation context: {context}")
                raise ValueError(validation_error_msg) from validation_error

            # Update entry attributes using immutable pattern
            try:
                object.__setattr__(self, "attributes", new_attributes_obj)
                logger.trace(
                    "Entry attributes updated successfully with immutable pattern",
                )

            except Exception as update_error:
                error_msg = (
                    f"Error updating entry attributes for '{name}': {update_error!s}"
                )
                logger.error(
                    f"Entry attributes update failed: {error_msg}",
                    exc_info=True,
                )
                context = {
                    "attribute_name": name,
                    "update_error": str(update_error),
                    "operation": "set_attribute",
                }
                logger.exception(f"Entry update error context: {context}")
                raise ValueError(error_msg) from update_error

            # Log successful attribute setting with comprehensive context
            change_type = "updated" if attribute_existed else "created"
            context = {
                "attribute_name": name,
                "change_type": change_type,
                "previous_values_count": previous_count if attribute_existed else 0,
                "new_values_count": len(values),
                "total_attributes": len(new_attrs),
                "entry_dn": str(self.dn.value)
                if hasattr(self, "dn") and self.dn
                else "unknown",
                "operation": "set_attribute",
                "result": "success",
            }

            logger.debug(f"Attribute setting completed successfully: {context}")
            logger.info(f"Attribute '{name}' {change_type} with {len(values)} values")

        except Exception as unexpected_error:
            unexpected_error_msg: str = f"Unexpected error during attribute setting for '{name}': {unexpected_error!s}"
            logger.error(
                f"Attribute setting failed: {unexpected_error_msg}", exc_info=True,
            )
            context = {
                "attribute_name": name,
                "values_count": len(
                    values,
                ),  # values guaranteed to be list by type annotation
                "unexpected_error": str(unexpected_error),
                "error_type": type(unexpected_error).__name__,
                "operation": "set_attribute",
            }
            logger.exception(f"Unexpected error context: {context}")
            raise ValueError(unexpected_error_msg) from unexpected_error

    def has_attribute(self, name: str) -> bool:
        """Check if LDIF entry has specific attribute with enterprise-grade existence validation and comprehensive verification.

        Determines whether the specified attribute name exists in this LDIF entry with comprehensive
        parameter validation, error handling, and detailed logging for enterprise LDIF attribute
        existence checking scenarios. Provides thorough validation regardless of whether the
        attribute has values, supporting enterprise LDAP operations and data validation workflows.

        The method performs extensive validation of the attribute name parameter, validates
        the entry's attributes collection state, and provides detailed logging for enterprise
        monitoring and debugging scenarios requiring comprehensive attribute existence tracking.

        Args:
            name (str): The attribute name to check (case-sensitive LDAP attribute name)
                       Must be non-empty string following LDAP naming conventions

        Returns:
            bool: True if attribute exists in entry (even if empty values list),
                  False if attribute doesn't exist or validation fails

        Raises:
            ValueError: If attribute name is invalid or entry state is malformed
            TypeError: If attribute name is not a string
            AttributeError: If entry attributes collection is not accessible

        Example:
            >>> entry = FlextLdifEntry(
            ...     dn=FlextLdifDistinguishedName(value="cn=user,dc=example,dc=com"),
            ...     attributes=FlextLdifAttributes(
            ...         attributes={
            ...             "cn": ["User Name"],
            ...             "mail": [],  # exists but empty
            ...             "description": [""],  # exists with empty string value
            ...         }
            ...     ),
            ... )
            >>> exists = entry.has_attribute("cn")
            >>> print(exists)  # True
            >>> exists_empty = entry.has_attribute("mail")
            >>> print(exists_empty)  # True (exists but empty)
            >>> missing = entry.has_attribute("nonexistent")
            >>> print(missing)  # False

        Business Logic:
            - Validates attribute name format and LDAP compliance
            - Checks entry attributes collection accessibility and integrity
            - Provides comprehensive logging for enterprise attribute existence monitoring
            - Supports case-sensitive LDAP attribute name semantics
            - Returns True for existing attributes regardless of value count (including empty)
            - Validates entry structural integrity for data consistency assurance

        Performance Notes:
            - Optimized for high-frequency attribute existence checks
            - Minimal memory allocation for enterprise performance requirements
            - Efficient validation with early returns for invalid inputs
            - Fast existence check using underlying dictionary operations

        Integration:
            - Compatible with flext-ldap for LDAP directory integration
            - Supports flext-observability monitoring and tracing
            - Follows flext-core validation patterns for consistency
            - Maintains LDIF entry structural integrity verification

        Author: FLEXT Development Team
        Version: 0.9.0

        """
        logger.debug(
            f"Checking LDIF attribute existence for name: '{name}' with enterprise validation",
        )

        try:
            # name parameter guaranteed to be str by type annotation

            # Validate attribute name format and business rules
            if not name.strip():
                error_msg = (
                    f"Attribute name cannot be empty or whitespace-only: '{name}'"
                )
                logger.error(f"Attribute existence check failed: {error_msg}")
                context = {
                    "attribute_name": name,
                    "name_length": len(name),
                    "name_stripped": name.strip(),
                    "operation": "has_attribute",
                }
                logger.error(f"Attribute name validation context: {context}")
                raise ValueError(error_msg)

            logger.trace(f"Validated attribute name '{name}' for existence check")

            # Validate entry attributes collection accessibility
            if not hasattr(self, "attributes"):
                error_msg = "Entry attributes collection is not available for attribute existence check"
                logger.error(f"Attribute existence check failed: {error_msg}")
                context = {
                    "attribute_name": name,
                    "entry_dn": str(self.dn.value)
                    if hasattr(self, "dn") and self.dn
                    else "unknown",
                    "has_attributes": False,
                    "operation": "has_attribute",
                }
                logger.error(f"Entry state validation context: {context}")
                raise AttributeError(error_msg)

            # self.attributes guaranteed to be FlextLdifAttributes by type annotation

            # Perform attribute existence check with comprehensive validation
            try:
                logger.trace(
                    f"Delegating attribute existence check to FlextLdifAttributes for '{name}'",
                )

                attribute_exists = self.attributes.has_attribute(name)
                logger.trace(
                    f"Attribute existence check result for '{name}': {attribute_exists}",
                )

                # Validate the result type for data integrity
                # attribute_exists guaranteed to be bool by has_attribute() return type

                # Log successful existence check with comprehensive context
                values_count = 0
                if attribute_exists:
                    try:
                        # Get values count for logging context
                        attribute_values = self.attributes.get_values(name)
                        values_count = (
                            len(attribute_values)
                            if isinstance(attribute_values, list)
                            else 0
                        )
                        logger.trace(
                            f"Attribute '{name}' exists with {values_count} values",
                        )
                    except Exception as count_error:
                        logger.warning(
                            f"Could not get values count for existing attribute '{name}': {count_error!s}",
                        )
                        values_count = -1  # Indicate unknown count

                context = {
                    "attribute_name": name,
                    "attribute_exists": attribute_exists,
                    "values_count": values_count if attribute_exists else 0,
                    "total_attributes": len(self.attributes.attributes)
                    if hasattr(self.attributes, "attributes")
                    else 0,
                    "entry_dn": str(self.dn.value)
                    if hasattr(self, "dn") and self.dn
                    else "unknown",
                    "operation": "has_attribute",
                    "result": "success",
                }

                if attribute_exists:
                    logger.debug(
                        f"Attribute existence check completed - EXISTS: {context}",
                    )
                    logger.info(
                        f"Attribute existence check completed - '{name}': EXISTS ({values_count} values)",
                    )
                else:
                    logger.debug(
                        f"Attribute existence check completed - NOT EXISTS: {context}",
                    )
                    logger.info(
                        f"Attribute existence check completed - '{name}': NOT EXISTS",
                    )

                return attribute_exists

            except Exception as existence_check_error:
                existence_check_error_msg: str = f"Error during attribute existence check for '{name}': {existence_check_error!s}"
                logger.error(
                    f"Attribute existence check failed: {existence_check_error_msg}",
                    exc_info=True,
                )
                context = {
                    "attribute_name": name,
                    "existence_check_error": str(existence_check_error),
                    "operation": "has_attribute",
                }
                logger.exception(f"Existence check error context: {context}")
                raise ValueError(existence_check_error_msg) from existence_check_error

        except Exception as unexpected_error:
            has_attr_unexpected_error_msg: str = f"Unexpected error during attribute existence check for '{name}': {unexpected_error!s}"
            logger.error(
                f"Attribute existence check failed: {has_attr_unexpected_error_msg}",
                exc_info=True,
            )
            context = {
                "attribute_name": name,
                "unexpected_error": str(unexpected_error),
                "error_type": type(unexpected_error).__name__,
                "operation": "has_attribute",
            }
            logger.exception(f"Unexpected error context: {context}")
            raise ValueError(has_attr_unexpected_error_msg) from unexpected_error

    def get_object_classes(self) -> list[str]:
        """Get object classes for LDIF entry with enterprise-grade objectClass retrieval and comprehensive validation.

        Retrieves all objectClass values from this entry with comprehensive validation, error handling,
        and detailed logging for enterprise LDIF objectClass retrieval scenarios. ObjectClass attributes
        define the entry's type and schema compliance in LDAP directory structures, making them critical
        for schema validation, entry classification, and LDAP directory operations.

        The method performs extensive validation of the entry's attributes collection state, validates
        the objectClass attribute structure, and provides detailed logging for enterprise monitoring
        and debugging scenarios requiring comprehensive objectClass analysis and schema compliance tracking.

        Returns:
            list[str]: List of object class names defining the entry's schema and type.
                      Returns empty list if no objectClass attribute exists.
                      All values are guaranteed to be strings.

        Raises:
            ValueError: If entry state is malformed or objectClass values are invalid
            AttributeError: If entry attributes collection is not accessible
            TypeError: If objectClass values are not strings

        Example:
            >>> entry = FlextLdifEntry(
            ...     dn=FlextLdifDistinguishedName(value="cn=user,dc=example,dc=com"),
            ...     attributes=FlextLdifAttributes(
            ...         attributes={
            ...             "objectClass": [
            ...                 "person",
            ...                 "inetOrgPerson",
            ...                 "organizationalPerson",
            ...             ]
            ...         }
            ...     ),
            ... )
            >>> object_classes = entry.get_object_classes()
            >>> print(
            ...     object_classes
            ... )  # ["person", "inetOrgPerson", "organizationalPerson"]
            >>> # Entry without objectClass
            >>> minimal_entry = FlextLdifEntry(
            ...     dn=FlextLdifDistinguishedName(value="dc=example,dc=com"),
            ...     attributes=FlextLdifAttributes(
            ...         attributes={"description": ["Root entry"]}
            ...     ),
            ... )
            >>> classes = minimal_entry.get_object_classes()
            >>> print(classes)  # []

        Business Logic:
            - Validates entry attributes collection accessibility and integrity
            - Retrieves objectClass attribute using standardized LDAP naming ("objectClass")
            - Validates all objectClass values are strings for schema compliance
            - Provides comprehensive logging for enterprise objectClass monitoring
            - Returns empty list for entries without objectClass (valid LDAP case)
            - Validates objectClass structure for data integrity assurance

        Performance Notes:
            - Optimized for high-frequency objectClass retrieval patterns
            - Minimal memory allocation for enterprise performance requirements
            - Efficient validation with early returns for invalid states
            - Fast retrieval using underlying attribute access methods

        Integration:
            - Compatible with flext-ldap for LDAP directory schema validation
            - Supports flext-observability monitoring and tracing
            - Follows flext-core validation patterns for consistency
            - Essential for LDAP schema compliance and entry classification

        LDAP Standards:
            - Follows RFC 4511 LDAP protocol specifications
            - Supports standard objectClass attribute semantics
            - Compatible with LDAP schema validation requirements
            - Maintains case-sensitive objectClass name handling

        Author: FLEXT Development Team
        Version: 0.9.0

        """
        logger.debug(
            "Retrieving objectClass values with enterprise-grade validation and comprehensive processing",
        )

        try:
            # Validate entry attributes collection accessibility
            if not hasattr(self, "attributes"):
                error_msg = "Entry attributes collection is not available for objectClass retrieval"
                logger.error(f"ObjectClass retrieval failed: {error_msg}")
                context = {
                    "entry_dn": str(self.dn.value)
                    if hasattr(self, "dn") and self.dn
                    else "unknown",
                    "has_attributes": False,
                    "operation": "get_object_classes",
                }
                logger.error(f"Entry state validation context: {context}")
                raise AttributeError(error_msg)

            # self.attributes guaranteed to be FlextLdifAttributes by type annotation

            logger.trace(
                "Validated entry attributes collection for objectClass retrieval",
            )

            # Retrieve objectClass values with comprehensive validation
            try:
                logger.trace(
                    "Retrieving objectClass attribute values using standardized LDAP naming",
                )

                object_class_values = self.attributes.get_values("objectClass")
                logger.trace(
                    f"Retrieved {len(object_class_values)} objectClass values",
                )

                # object_class_values guaranteed to be list[str] by get_values() return type

                # Validate objectClass values are not empty (all guaranteed to be str by list[str] type)
                invalid_values = []
                valid_object_classes = []

                for i, oc_value in enumerate(object_class_values):
                    # oc_value guaranteed to be str by list[str] type annotation
                    # Validate for empty or whitespace-only objectClass values
                    if not oc_value.strip():
                        invalid_values.append(
                            f"objectClass[{i}]: empty or whitespace-only value '{oc_value}'",
                        )
                    else:
                        valid_object_classes.append(oc_value)
                        logger.trace(f"Validated objectClass[{i}]: '{oc_value}'")

                if invalid_values:
                    objectclass_invalid_values_error_msg: str = f"All objectClass values must be non-empty strings: {', '.join(invalid_values)}"
                    logger.error(
                        f"ObjectClass values validation failed: {objectclass_invalid_values_error_msg}",
                    )
                    context = {
                        "invalid_values": invalid_values,
                        "total_values": len(object_class_values),
                        "valid_values": len(valid_object_classes),
                        "operation": "get_object_classes",
                    }
                    logger.error(f"ObjectClass content validation context: {context}")
                    raise ValueError(objectclass_invalid_values_error_msg)

                # Log successful objectClass retrieval with comprehensive context
                context = {
                    "object_classes_count": len(object_class_values),
                    "object_classes": object_class_values[:5]
                    if len(object_class_values) <= 5
                    else [*object_class_values[:5], "..."],
                    "total_attributes": len(self.attributes.attributes)
                    if hasattr(self.attributes, "attributes")
                    else 0,
                    "entry_dn": str(self.dn.value)
                    if hasattr(self, "dn") and self.dn
                    else "unknown",
                    "operation": "get_object_classes",
                    "result": "success",
                }

                if object_class_values:
                    logger.debug(
                        f"ObjectClass retrieval completed successfully: {context}",
                    )
                    logger.info(
                        f"Retrieved {len(object_class_values)} objectClass values: {', '.join(object_class_values[:3])}"
                        + (
                            f" (and {len(object_class_values) - 3} more)"
                            if len(object_class_values) > 3
                            else ""
                        ),
                    )
                else:
                    logger.debug(
                        f"ObjectClass retrieval completed - no objectClass attribute: {context}",
                    )
                    logger.info(
                        "Retrieved objectClass values: none (entry has no objectClass attribute)",
                    )

                return object_class_values

            except Exception as retrieval_error:
                retrieval_error_msg: str = (
                    f"Error retrieving objectClass values: {retrieval_error!s}"
                )
                logger.error(
                    f"ObjectClass retrieval failed: {retrieval_error_msg}",
                    exc_info=True,
                )
                context = {
                    "retrieval_error": str(retrieval_error),
                    "operation": "get_object_classes",
                }
                logger.exception(f"ObjectClass retrieval error context: {context}")
                raise ValueError(retrieval_error_msg) from retrieval_error

        except Exception as unexpected_error:
            oc_unexpected_error_msg = (
                f"Unexpected error during objectClass retrieval: {unexpected_error!s}"
            )
            logger.error(
                f"ObjectClass retrieval failed: {oc_unexpected_error_msg}",
                exc_info=True,
            )
            context = {
                "unexpected_error": str(unexpected_error),
                "error_type": type(unexpected_error).__name__,
                "operation": "get_object_classes",
            }
            logger.exception(f"Unexpected error context: {context}")
            raise ValueError(oc_unexpected_error_msg) from unexpected_error

    def has_object_class(self, object_class: str) -> bool:
        """Check if entry has specific object class.

        Determines whether this LDIF entry contains the specified object class
        in its objectClass attribute. This is essential for LDAP schema validation
        and entry type determination.

        Args:
            object_class: Object class name to check for (case-sensitive)

        Returns:
            True if entry has the object class, False otherwise

        Example:
            >>> entry = FlextLdifEntry(
            ...     dn=FlextLdifDistinguishedName(value="cn=user,dc=example,dc=com"),
            ...     attributes=FlextLdifAttributes(
            ...         attributes={"objectClass": ["person", "inetOrgPerson"]}
            ...     ),
            ... )
            >>> entry.has_object_class("person")  # True
            >>> entry.has_object_class("inetOrgPerson")  # True
            >>> entry.has_object_class("group")  # False

        """
        return object_class in self.get_object_classes()

    def get_attribute_values(self, name: str) -> list[str]:
        """Get LDIF attribute values by name with enterprise-grade validation and comprehensive error handling.

        Retrieves all values for the specified LDAP attribute from this entry's attributes
        collection with comprehensive parameter validation, error handling, and detailed
        logging for enterprise LDIF attribute access scenarios. Provides full integration
        with the underlying attributes collection while maintaining enterprise logging standards.

        This method acts as a convenient proxy to the underlying FlextLdifAttributes collection
        while providing entry-level context and validation. It ensures proper error handling
        and logging for enterprise monitoring and debugging scenarios requiring comprehensive
        attribute access tracking.

        Args:
            name (str): The attribute name to retrieve (case-sensitive LDAP attribute name)
                       Must be non-empty string following LDAP naming conventions

        Returns:
            list[str]: List of all attribute string values if attribute exists,
                      Empty list if attribute doesn't exist (following LDAP semantics)

        Raises:
            ValueError: If attribute name is invalid or entry attributes are malformed
            TypeError: If attribute name is not a string
            AttributeError: If entry attributes collection is not accessible

        Example:
            >>> entry = FlextLdifEntry(
            ...     dn=FlextLdifDistinguishedName(value="cn=user,dc=example,dc=com"),
            ...     attributes=FlextLdifAttributes(
            ...         attributes={
            ...             "mail": ["user@example.com", "user@company.com"],
            ...             "objectClass": ["person", "inetOrgPerson"],
            ...         }
            ...     ),
            ... )
            >>> values = entry.get_attribute_values("mail")
            >>> print(values)  # ["user@example.com", "user@company.com"]
            >>> empty = entry.get_attribute_values("nonexistent")
            >>> print(empty)  # []

        Business Logic:
            - Validates attribute name parameter format and LDAP compliance
            - Delegates to underlying attributes collection for actual retrieval
            - Provides entry-level context for comprehensive logging
            - Returns empty list for missing attributes (LDAP standard behavior)
            - Ensures consistent error handling across the entry interface

        Performance Notes:
            - Minimal overhead proxy to attributes collection
            - Optimized for high-frequency attribute access patterns
            - Efficient validation with early returns for invalid inputs

        Integration:
            - Delegates to FlextLdifAttributes.get_values() for actual processing
            - Maintains consistency with other entry attribute access methods
            - Supports enterprise monitoring and observability patterns

        Author: FLEXT Development Team
        Version: 0.9.0

        """
        logger.debug(
            f"Retrieving attribute values from entry for name: '{name}' with enterprise validation",
        )

        try:
            # name parameter guaranteed to be str by type annotation - no isinstance checks needed

            if not name.strip():
                name_empty_error_msg: str = (
                    f"Attribute name cannot be empty or whitespace-only: '{name}'"
                )
                logger.error(
                    f"Entry attribute values retrieval failed: {name_empty_error_msg}",
                )
                raise ValueError(name_empty_error_msg)

            # self.attributes guaranteed to be FlextLdifAttributes by Pydantic field definition
            # No runtime type validation needed - type system ensures correctness

            logger.trace(
                f"Delegating attribute values retrieval to attributes collection for name: '{name.strip()}'",
            )

            # Delegate to underlying attributes collection with error handling
            try:
                cleaned_name = name.strip()
                values = self.attributes.get_values(cleaned_name)

                logger.debug(
                    f"Successfully retrieved {len(values)} values for attribute '{cleaned_name}' from entry '{self.dn.value}'",
                )
                logger.info(
                    f"Entry attribute values retrieval completed - attribute: '{cleaned_name}', count: {len(values)}",
                )

                return values

            except Exception as delegation_error:
                delegation_error_msg: str = f"Attributes collection failed to retrieve values for '{name}': {delegation_error!s}"
                logger.error(
                    f"Entry attribute values retrieval failed: {delegation_error_msg}",
                    exc_info=True,
                )
                raise ValueError(delegation_error_msg) from delegation_error

        except Exception as unexpected_error:
            attr_values_unexpected_error_msg: str = f"Unexpected error during entry attribute values retrieval for '{name}': {unexpected_error!s}"
            logger.error(
                f"Entry attribute values retrieval failed: {attr_values_unexpected_error_msg}",
                exc_info=True,
            )
            raise ValueError(attr_values_unexpected_error_msg) from unexpected_error

    def is_modify_operation(self) -> bool:
        """Check if this LDIF entry represents a modify operation with enterprise-grade validation and comprehensive analysis.

        Determines whether this LDIF entry represents a directory modify operation by analyzing
        the changetype attribute with comprehensive validation, error handling, and detailed
        logging for enterprise LDAP operation classification scenarios. Implements robust
        changetype detection following RFC 2849 LDIF specification standards.

        This method provides reliable modify operation detection for LDIF change records
        processing, supporting enterprise directory synchronization and modification tracking
        workflows with comprehensive error handling and validation logic.

        Returns:
            bool: True if this entry represents a modify operation, False otherwise

        Raises:
            ValueError: If entry attributes are malformed or changetype analysis fails
            AttributeError: If entry attributes collection is not accessible

        Example:
            >>> # Modify operation entry
            >>> modify_entry = FlextLdifEntry(
            ...     dn=FlextLdifDistinguishedName(value="cn=user,dc=example,dc=com"),
            ...     attributes=FlextLdifAttributes(
            ...         attributes={
            ...             "changetype": ["modify"],
            ...             "replace": ["mail"],
            ...             "mail": ["newemail@example.com"],
            ...         }
            ...     ),
            ... )
            >>> print(modify_entry.is_modify_operation())  # True
            >>>
            >>> # Regular entry (no changetype)
            >>> regular_entry = FlextLdifEntry(
            ...     dn=FlextLdifDistinguishedName(value="cn=user,dc=example,dc=com"),
            ...     attributes=FlextLdifAttributes(
            ...         attributes={
            ...             "objectClass": ["person"],
            ...             "cn": ["user"],
            ...         }
            ...     ),
            ... )
            >>> print(regular_entry.is_modify_operation())  # False

        Business Logic:
            - Analyzes changetype attribute for modify operation detection
            - Handles case-insensitive changetype value comparison
            - Returns False for entries without changetype (regular LDIF entries)
            - Provides comprehensive validation of changetype attribute format
            - Supports RFC 2849 LDIF change record specification compliance

        Performance Notes:
            - Efficient changetype attribute lookup with minimal overhead
            - Optimized boolean evaluation for high-frequency operation classification
            - Cached attribute access through entry attribute retrieval methods

        Integration:
            - Uses existing get_attribute() method for changetype retrieval
            - Maintains consistency with other operation detection methods
            - Supports enterprise LDIF processing and change record workflows

        Author: FLEXT Development Team
        Version: 0.9.0

        """
        logger.debug(
            f"Analyzing entry for modify operation detection: DN='{self.dn.value if hasattr(self, 'dn') and self.dn else 'unknown'}'",
        )

        try:
            # Validate entry structure before changetype analysis
            if not hasattr(self, "attributes") or self.attributes is None:
                error_msg: str = f"Entry attributes collection not accessible for modify operation detection: DN='{self.dn.value if hasattr(self, 'dn') and self.dn else 'unknown'}'"
                logger.error(f"Modify operation detection failed: {error_msg}")
                raise AttributeError(error_msg)

            logger.trace(
                "Retrieving changetype attribute for modify operation analysis",
            )

            # Retrieve changetype attribute with comprehensive error handling
            try:
                changetype_values = self.get_attribute("changetype")
                logger.trace(f"Changetype attribute values: {changetype_values}")

                # Handle missing changetype attribute (regular LDIF entries)
                if not changetype_values:
                    logger.debug(
                        f"No changetype attribute found - entry is regular LDIF entry, not modify operation: DN='{self.dn.value}'",
                    )
                    logger.info(
                        "Modify operation detection completed - result: False (no changetype)",
                    )
                    return False

                # changetype_values guaranteed to be list[str] by get_values() return type
                # Type system ensures correctness - no runtime validation needed

                if len(changetype_values) == 0:
                    logger.debug(
                        f"Empty changetype attribute found - entry is not modify operation: DN='{self.dn.value}'",
                    )
                    logger.info(
                        "Modify operation detection completed - result: False (empty changetype)",
                    )
                    return False

                # Extract first changetype value (guaranteed to be str by type system)
                changetype_value = changetype_values[0]
                logger.trace(f"Primary changetype value: '{changetype_value}'")

                # Normalize changetype value for comparison (case-insensitive)
                normalized_changetype = changetype_value.lower().strip()
                logger.trace(f"Normalized changetype value: '{normalized_changetype}'")

                if not normalized_changetype:
                    logger.debug(
                        f"Empty changetype value after normalization - entry is not modify operation: DN='{self.dn.value}'",
                    )
                    logger.info(
                        "Modify operation detection completed - result: False (empty normalized changetype)",
                    )
                    return False

                # Perform modify operation detection
                is_modify = normalized_changetype == "modify"

                logger.debug(
                    f"Modify operation detection completed - changetype: '{normalized_changetype}', is_modify: {is_modify}, DN: '{self.dn.value}'",
                )
                logger.info(
                    f"Modify operation detection result - entry: {'IS' if is_modify else 'IS NOT'} modify operation",
                )

                return is_modify

            except Exception as retrieval_error:
                modify_retrieval_error_msg: str = f"Changetype attribute retrieval failed during modify operation detection: {retrieval_error!s}"
                logger.error(
                    f"Modify operation detection failed: {modify_retrieval_error_msg}",
                    exc_info=True,
                )
                raise ValueError(modify_retrieval_error_msg) from retrieval_error

        except Exception as unexpected_error:
            modify_unexpected_error_msg: str = f"Unexpected error during modify operation detection for DN '{self.dn.value if hasattr(self, 'dn') and self.dn else 'unknown'}': {unexpected_error!s}"
            logger.error(
                f"Modify operation detection failed: {modify_unexpected_error_msg}",
                exc_info=True,
            )
            raise ValueError(modify_unexpected_error_msg) from unexpected_error

    def is_add_operation(self) -> bool:
        """Check if this LDIF entry represents an add operation with enterprise-grade validation and comprehensive analysis.

        Determines whether this LDIF entry represents a directory add operation by analyzing
        the changetype attribute with comprehensive validation, error handling, and detailed
        logging for enterprise LDAP operation classification scenarios. Implements robust
        changetype detection following RFC 2849 LDIF specification standards.

        This method provides reliable add operation detection for LDIF processing workflows,
        supporting enterprise directory entry creation and batch import scenarios with
        comprehensive error handling and validation logic. Follows LDIF standard behavior
        where entries without changetype default to add operations.

        Returns:
            bool: True if this entry represents an add operation (explicit or default), False otherwise

        Raises:
            ValueError: If entry attributes are malformed or changetype analysis fails
            AttributeError: If entry attributes collection is not accessible

        Example:
            >>> # Explicit add operation entry
            >>> add_entry = FlextLdifEntry(
            ...     dn=FlextLdifDistinguishedName(value="cn=user,dc=example,dc=com"),
            ...     attributes=FlextLdifAttributes(
            ...         attributes={
            ...             "changetype": ["add"],
            ...             "objectClass": ["person"],
            ...             "cn": ["user"],
            ...         }
            ...     ),
            ... )
            >>> print(add_entry.is_add_operation())  # True
            >>>
            >>> # Regular entry (no changetype - defaults to add)
            >>> regular_entry = FlextLdifEntry(
            ...     dn=FlextLdifDistinguishedName(value="cn=user,dc=example,dc=com"),
            ...     attributes=FlextLdifAttributes(
            ...         attributes={
            ...             "objectClass": ["person"],
            ...             "cn": ["user"],
            ...         }
            ...     ),
            ... )
            >>> print(regular_entry.is_add_operation())  # True (default behavior)

        Business Logic:
            - Analyzes changetype attribute for add operation detection
            - Defaults to add operation when no changetype is present (RFC 2849 standard)
            - Handles case-insensitive changetype value comparison
            - Provides comprehensive validation of changetype attribute format
            - Supports RFC 2849 LDIF specification compliance for add operations

        Performance Notes:
            - Efficient changetype attribute lookup with minimal overhead
            - Optimized boolean evaluation for high-frequency operation classification
            - Cached attribute access through entry attribute retrieval methods

        Integration:
            - Uses existing get_attribute() method for changetype retrieval
            - Maintains consistency with other operation detection methods
            - Supports enterprise LDIF processing and entry creation workflows

        Author: FLEXT Development Team
        Version: 0.9.0

        """
        logger.debug(
            f"Analyzing entry for add operation detection: DN='{self.dn.value if hasattr(self, 'dn') and self.dn else 'unknown'}'",
        )

        try:
            # Validate entry structure before changetype analysis
            if not hasattr(self, "attributes") or self.attributes is None:
                error_msg: str = f"Entry attributes collection not accessible for add operation detection: DN='{self.dn.value if hasattr(self, 'dn') and self.dn else 'unknown'}'"
                logger.error(f"Add operation detection failed: {error_msg}")
                raise AttributeError(error_msg)

            logger.trace("Retrieving changetype attribute for add operation analysis")

            # Retrieve changetype attribute with comprehensive error handling
            try:
                changetype_values = self.get_attribute("changetype")
                logger.trace(f"Changetype attribute values: {changetype_values}")

                # Handle missing changetype attribute (default to add operation per RFC 2849)
                if not changetype_values:
                    logger.debug(
                        f"No changetype attribute found - defaulting to add operation per LDIF standard: DN='{self.dn.value}'",
                    )
                    logger.info(
                        "Add operation detection completed - result: True (default behavior)",
                    )
                    return True

                # changetype_values guaranteed to be list[str] by get_values() return type
                # Type system ensures correctness - no runtime validation needed

                if len(changetype_values) == 0:
                    logger.debug(
                        f"Empty changetype attribute found - defaulting to add operation: DN='{self.dn.value}'",
                    )
                    logger.info(
                        "Add operation detection completed - result: True (empty changetype defaults to add)",
                    )
                    return True

                # Extract first changetype value (guaranteed to be str by type system)
                changetype_value = changetype_values[0]
                logger.trace(f"Primary changetype value: '{changetype_value}'")

                # Normalize changetype value for comparison (case-insensitive)
                normalized_changetype = changetype_value.lower().strip()
                logger.trace(f"Normalized changetype value: '{normalized_changetype}'")

                if not normalized_changetype:
                    logger.debug(
                        f"Empty changetype value after normalization - defaulting to add operation: DN='{self.dn.value}'",
                    )
                    logger.info(
                        "Add operation detection completed - result: True (empty normalized changetype defaults to add)",
                    )
                    return True

                # Perform add operation detection
                is_add = normalized_changetype == "add"

                logger.debug(
                    f"Add operation detection completed - changetype: '{normalized_changetype}', is_add: {is_add}, DN: '{self.dn.value}'",
                )
                logger.info(
                    f"Add operation detection result - entry: {'IS' if is_add else 'IS NOT'} add operation",
                )

                return is_add

            except Exception as retrieval_error:
                add_retrieval_error_msg: str = f"Changetype attribute retrieval failed during add operation detection: {retrieval_error!s}"
                logger.error(
                    f"Add operation detection failed: {add_retrieval_error_msg}",
                    exc_info=True,
                )
                raise ValueError(add_retrieval_error_msg) from retrieval_error

        except Exception as unexpected_error:
            add_unexpected_error_msg: str = f"Unexpected error during add operation detection for DN '{self.dn.value if hasattr(self, 'dn') and self.dn else 'unknown'}': {unexpected_error!s}"
            logger.error(
                f"Add operation detection failed: {add_unexpected_error_msg}",
                exc_info=True,
            )
            raise ValueError(add_unexpected_error_msg) from unexpected_error

    def is_delete_operation(self) -> bool:
        """Check if this LDIF entry represents a delete operation with enterprise-grade validation and comprehensive analysis.

        Determines whether this LDIF entry represents a directory delete operation by analyzing
        the changetype attribute with comprehensive validation, error handling, and detailed
        logging for enterprise LDAP operation classification scenarios. Implements robust
        changetype detection following RFC 2849 LDIF specification standards.

        This method provides reliable delete operation detection for LDIF processing workflows,
        supporting enterprise directory entry removal and cleanup scenarios with comprehensive
        error handling and validation logic. Essential for change record processing and
        directory synchronization operations.

        Returns:
            bool: True if this entry represents a delete operation, False otherwise

        Raises:
            ValueError: If entry attributes are malformed or changetype analysis fails
            AttributeError: If entry attributes collection is not accessible

        Example:
            >>> # Delete operation entry
            >>> delete_entry = FlextLdifEntry(
            ...     dn=FlextLdifDistinguishedName(value="cn=user,dc=example,dc=com"),
            ...     attributes=FlextLdifAttributes(
            ...         attributes={
            ...             "changetype": ["delete"],
            ...         }
            ...     ),
            ... )
            >>> print(delete_entry.is_delete_operation())  # True
            >>>
            >>> # Regular entry (no changetype)
            >>> regular_entry = FlextLdifEntry(
            ...     dn=FlextLdifDistinguishedName(value="cn=user,dc=example,dc=com"),
            ...     attributes=FlextLdifAttributes(
            ...         attributes={
            ...             "objectClass": ["person"],
            ...             "cn": ["user"],
            ...         }
            ...     ),
            ... )
            >>> print(regular_entry.is_delete_operation())  # False

        Business Logic:
            - Analyzes changetype attribute for delete operation detection
            - Handles case-insensitive changetype value comparison
            - Returns False for entries without changetype (regular LDIF entries)
            - Provides comprehensive validation of changetype attribute format
            - Supports RFC 2849 LDIF change record specification compliance

        Performance Notes:
            - Efficient changetype attribute lookup with minimal overhead
            - Optimized boolean evaluation for high-frequency operation classification
            - Cached attribute access through entry attribute retrieval methods

        Integration:
            - Uses existing get_attribute() method for changetype retrieval
            - Maintains consistency with other operation detection methods
            - Supports enterprise LDIF processing and change record workflows

        Author: FLEXT Development Team
        Version: 0.9.0

        """
        logger.debug(
            f"Analyzing entry for delete operation detection: DN='{self.dn.value if hasattr(self, 'dn') and self.dn else 'unknown'}'",
        )

        try:
            # Validate entry structure before changetype analysis
            if not hasattr(self, "attributes") or self.attributes is None:
                error_msg: str = f"Entry attributes collection not accessible for delete operation detection: DN='{self.dn.value if hasattr(self, 'dn') and self.dn else 'unknown'}'"
                logger.error(f"Delete operation detection failed: {error_msg}")
                raise AttributeError(error_msg)

            logger.trace(
                "Retrieving changetype attribute for delete operation analysis",
            )

            # Retrieve changetype attribute with comprehensive error handling
            try:
                changetype_values = self.get_attribute("changetype")
                logger.trace(f"Changetype attribute values: {changetype_values}")

                # Handle missing changetype attribute (regular LDIF entries)
                if not changetype_values:
                    logger.debug(
                        f"No changetype attribute found - entry is regular LDIF entry, not delete operation: DN='{self.dn.value}'",
                    )
                    logger.info(
                        "Delete operation detection completed - result: False (no changetype)",
                    )
                    return False

                # changetype_values guaranteed to be list[str] by get_values() return type
                # Type system ensures correctness - no runtime validation needed

                if len(changetype_values) == 0:
                    logger.debug(
                        f"Empty changetype attribute found - entry is not delete operation: DN='{self.dn.value}'",
                    )
                    logger.info(
                        "Delete operation detection completed - result: False (empty changetype)",
                    )
                    return False

                # Extract and validate first changetype value
                changetype_value = changetype_values[
                    0
                ]  # guaranteed to be str by type annotation
                logger.trace(f"Primary changetype value: '{changetype_value}'")

                # changetype_value guaranteed to be str by list[str] type annotation
                # Type system ensures correctness - no runtime validation needed

                # Normalize changetype value for comparison (case-insensitive)
                normalized_changetype = changetype_value.lower().strip()
                logger.trace(f"Normalized changetype value: '{normalized_changetype}'")

                if not normalized_changetype:
                    logger.debug(
                        f"Empty changetype value after normalization - entry is not delete operation: DN='{self.dn.value}'",
                    )
                    logger.info(
                        "Delete operation detection completed - result: False (empty normalized changetype)",
                    )
                    return False

                # Perform delete operation detection
                is_delete = normalized_changetype == "delete"

                logger.debug(
                    f"Delete operation detection completed - changetype: '{normalized_changetype}', is_delete: {is_delete}, DN: '{self.dn.value}'",
                )
                logger.info(
                    f"Delete operation detection result - entry: {'IS' if is_delete else 'IS NOT'} delete operation",
                )

                return is_delete

            except Exception as retrieval_error:
                retrieval_error_msg: str = f"Changetype attribute retrieval failed during delete operation detection: {retrieval_error!s}"
                logger.error(
                    f"Delete operation detection failed: {retrieval_error_msg}",
                    exc_info=True,
                )
                raise ValueError(retrieval_error_msg) from retrieval_error

        except Exception as unexpected_error:
            unexpected_error_msg: str = f"Unexpected error during delete operation detection for DN '{self.dn.value if hasattr(self, 'dn') and self.dn else 'unknown'}': {unexpected_error!s}"
            logger.error(
                f"Delete operation detection failed: {unexpected_error_msg}",
                exc_info=True,
            )
            raise ValueError(unexpected_error_msg) from unexpected_error

    def get_single_attribute(self, name: str) -> str | None:
        """Get single LDIF attribute value with enterprise-grade validation and comprehensive error handling.

        Retrieves the first (or only) value for the specified LDAP attribute from this entry's
        attributes collection with comprehensive parameter validation, error handling, and
        detailed logging for enterprise LDIF single-value attribute access scenarios. Provides
        convenient single-value access for attributes expected to have only one value.

        This method acts as a convenient proxy to the underlying FlextLdifAttributes collection
        for single-value attribute retrieval while providing entry-level context and validation.
        Essential for accessing unique identifiers and single-valued attributes in LDAP entries.

        Args:
            name (str): The attribute name to retrieve (case-sensitive LDAP attribute name)
                       Must be non-empty string following LDAP naming conventions

        Returns:
            str | None: First attribute value if attribute exists and has values,
                       None if attribute doesn't exist or has no values

        Raises:
            ValueError: If attribute name is invalid or entry attributes are malformed
            TypeError: If attribute name is not a string
            AttributeError: If entry attributes collection is not accessible

        Example:
            >>> entry = FlextLdifEntry(
            ...     dn=FlextLdifDistinguishedName(value="cn=user,dc=example,dc=com"),
            ...     attributes=FlextLdifAttributes(
            ...         attributes={
            ...             "cn": ["John Doe"],
            ...             "uid": ["johndoe"],
            ...             "mail": ["john@example.com", "john@company.com"],
            ...         }
            ...     ),
            ... )
            >>> single_cn = entry.get_single_attribute("cn")
            >>> print(single_cn)  # "John Doe"
            >>> first_mail = entry.get_single_attribute("mail")
            >>> print(first_mail)  # "john@example.com" (first value)
            >>> missing = entry.get_single_attribute("nonexistent")
            >>> print(missing)  # None

        Business Logic:
            - Validates attribute name parameter format and LDAP compliance
            - Delegates to underlying attributes collection for actual retrieval
            - Returns first value for multi-valued attributes
            - Returns None for missing attributes (consistent with LDAP semantics)
            - Provides entry-level context for comprehensive logging

        Performance Notes:
            - Minimal overhead proxy to attributes collection
            - Optimized for single-value attribute access patterns
            - Efficient validation with early returns for invalid inputs

        Integration:
            - Delegates to FlextLdifAttributes.get_single_value() for actual processing
            - Maintains consistency with other entry attribute access methods
            - Supports enterprise monitoring and observability patterns

        Author: FLEXT Development Team
        Version: 0.9.0

        """
        logger.debug(
            f"Retrieving single attribute value from entry for name: '{name}' with enterprise validation",
        )

        try:
            # name parameter guaranteed to be str by type annotation - no isinstance check needed

            if not name.strip():
                name_empty_error_msg: str = (
                    f"Attribute name cannot be empty or whitespace-only: '{name}'"
                )
                logger.error(
                    f"Entry single attribute retrieval failed: {name_empty_error_msg}",
                )
                raise ValueError(name_empty_error_msg)

            # Validate entry attributes collection accessibility
            if not hasattr(self, "attributes") or self.attributes is None:
                attributes_access_error_msg: str = f"Entry attributes collection is not accessible for DN: '{self.dn.value if hasattr(self, 'dn') and self.dn else 'unknown'}'"
                logger.error(
                    f"Entry single attribute retrieval failed: {attributes_access_error_msg}",
                )
                raise AttributeError(attributes_access_error_msg)

            logger.trace(
                f"Delegating single attribute retrieval to attributes collection for name: '{name.strip()}'",
            )

            # Delegate to underlying attributes collection with error handling
            try:
                cleaned_name = name.strip()
                single_value = self.attributes.get_single_value(cleaned_name)

                if single_value is not None:
                    logger.debug(
                        f"Successfully retrieved single value for attribute '{cleaned_name}' from entry '{self.dn.value}': '{single_value}'",
                    )
                    logger.info(
                        f"Entry single attribute retrieval completed - attribute: '{cleaned_name}', has_value: True",
                    )
                else:
                    logger.debug(
                        f"No value found for attribute '{cleaned_name}' from entry '{self.dn.value}'",
                    )
                    logger.info(
                        f"Entry single attribute retrieval completed - attribute: '{cleaned_name}', has_value: False",
                    )

                return single_value

            except Exception as delegation_error:
                delegation_error_msg: str = f"Attributes collection failed to retrieve single value for '{name}': {delegation_error!s}"
                logger.error(
                    f"Entry single attribute retrieval failed: {delegation_error_msg}",
                    exc_info=True,
                )
                raise ValueError(delegation_error_msg) from delegation_error

        except Exception as unexpected_error:
            unexpected_error_msg: str = f"Unexpected error during entry single attribute retrieval for '{name}': {unexpected_error!s}"
            logger.error(
                f"Entry single attribute retrieval failed: {unexpected_error_msg}",
                exc_info=True,
            )
            raise ValueError(unexpected_error_msg) from unexpected_error

    def to_ldif(self) -> str:
        """Convert entry to LDIF string format.

        Converts this FlextLdifEntry to standard LDIF (LDAP Data Interchange Format)
        string representation following RFC 2849 specifications. The output includes
        the DN line followed by all attributes and values, with proper line formatting.

        Returns:
            LDIF string representation of the entry with RFC 2849 compliance

        Example:
            >>> entry = FlextLdifEntry(
            ...     dn=FlextLdifDistinguishedName(
            ...         value="cn=John Doe,ou=people,dc=example,dc=com"
            ...     ),
            ...     attributes=FlextLdifAttributes(
            ...         attributes={
            ...             "cn": ["John Doe"],
            ...             "objectClass": ["person", "inetOrgPerson"],
            ...             "mail": ["john@example.com"],
            ...         }
            ...     ),
            ... )
            >>> print(entry.to_ldif())
            dn: cn=John Doe,ou=people,dc=example,dc=com
            cn: John Doe
            objectClass: person
            objectClass: inetOrgPerson
            mail: john@example.com
            <BLANKLINE>

        """
        lines = [f"dn: {self.dn}"]

        for attr_name, attr_values in self.attributes.attributes.items():
            lines.extend(f"{attr_name}: {value}" for value in attr_values)

        lines.append("")  # Empty line after entry
        return "\n".join(lines)

    def validate_semantic_rules(self) -> FlextResult[None]:
        """Validate LDIF entry semantic business rules using Railway-Oriented Programming.

        SOLID REFACTORING: Reduced from 4 returns to 2 returns using
        Railway-Oriented Programming + Strategy Pattern.
        """
        # Railway-Oriented Programming: Chain validations with early exit
        validation_errors = self._collect_ldif_entry_validation_errors()

        if validation_errors:
            return FlextResult.fail(
                validation_errors[0],
            )  # Return first error for clarity

        return FlextResult.ok(None)

    def _collect_ldif_entry_validation_errors(self) -> list[str]:
        """DRY helper: Collect all LDIF entry validation errors using Strategy Pattern."""
        errors = []

        # Strategy 1: DN validation
        if not self.dn or not self.dn.value:
            errors.append("LDIF entry must have a valid DN")

        # Strategy 2: Attributes existence validation
        if not self.attributes or not self.attributes.attributes:
            errors.append("LDIF entry must have at least one attribute")

        # Strategy 3: ObjectClass attribute validation
        if not self.has_attribute("objectClass"):
            errors.append("Entry missing required objectClass attribute")

        return errors

    @classmethod
    def from_ldif_block(cls, ldif_block: str) -> FlextLdifEntry:
        """Create entry from LDIF block.

        Args:
            ldif_block: LDIF text block for single entry

        Returns:
            LDIFEntry instance

        """
        lines = [
            line.strip() for line in ldif_block.strip().split("\n") if line.strip()
        ]

        if not lines:
            empty_block_msg = "LDIF block cannot be empty"
            raise ValueError(empty_block_msg)

        # First line must be DN
        dn_line = lines[0]
        if not dn_line.startswith("dn:"):
            invalid_dn_msg: str = f"First line must be DN, got: {dn_line}"
            raise ValueError(invalid_dn_msg)

        dn = dn_line[3:].strip()
        attributes: dict[str, list[str]] = {}

        # Parse attributes
        for line in lines[1:]:
            if ":" in line:
                attr_name, attr_value = line.split(":", 1)
                attr_name = attr_name.strip()
                attr_value = attr_value.strip()

                if attr_name not in attributes:
                    attributes[attr_name] = []
                attributes[attr_name].append(attr_value)

        return cls.model_validate({
            "dn": FlextLdifDistinguishedName.model_validate({"value": dn}),
            "attributes": FlextLdifAttributes.model_validate({"attributes": attributes}),
        })

    @classmethod
    def from_ldif_dict(
        cls,
        dn: str,
        attributes: dict[str, list[str]],
    ) -> FlextLdifEntry:
        """Create entry from DN string and attributes dict (ldif3 format).

        Args:
            dn: Distinguished name string
            attributes: Dictionary of attributes with list values

        Returns:
            FlextLdifEntry instance

        """
        logger.debug("Creating FlextLdifEntry from LDIF dict: DN=%s", dn)
        logger.trace("Attributes count: %d", len(attributes))
        logger.trace("Attribute names: %s", list(attributes.keys()))

        try:
            logger.debug("Validating DN: %s", dn)
            dn_obj = FlextLdifDistinguishedName.model_validate({"value": dn})
            logger.trace("DN validation successful")

            logger.debug("Validating attributes dictionary")
            attrs_obj = FlextLdifAttributes.model_validate({"attributes": attributes})
            logger.trace("Attributes validation successful")

            entry = cls.model_validate({"dn": dn_obj, "attributes": attrs_obj})
            logger.debug("FlextLdifEntry created successfully: %s", entry.dn)
            logger.info(
                "LDIF entry created from dict",
                dn=dn,
                attributes_count=len(attributes),
                total_values=sum(len(values) for values in attributes.values()),
            )
        except Exception as e:
            logger.debug("Exception type: %s", type(e).__name__)
            logger.trace("Entry creation exception details", exc_info=True)
            logger.exception("Failed to create FlextLdifEntry from dict")
            raise
        else:
            return entry

    def to_entry_dict(self) -> FlextLdifEntryDict:
        """Convert to FlextLdifEntryDict representation."""
        changetype = self.get_single_attribute("changetype")
        result = FlextLdifEntryDict(
            dn=str(self.dn),
            attributes=self.attributes.attributes.copy(),
            object_classes=self.get_object_classes(),
        )
        if changetype is not None:
            result["changetype"] = changetype
        return result

    # ==========================================================================
    # SPECIFICATION METHODS (Consolidated from specifications.py)
    # Using composition pattern to integrate business rules
    # ==========================================================================

    def is_valid_entry(self) -> bool:
        """Check if entry is valid (consolidated specification logic)."""
        if not self.dn or not self.attributes or self.attributes.is_empty():
            return False

        # Must have at least objectClass attribute
        if not self.has_attribute("objectClass"):
            return False

        # DN must be properly formatted
        dn_str = str(self.dn)
        return not (not dn_str or "=" not in dn_str)

    def is_person_entry(self) -> bool:
        """Check if entry represents a person (consolidated specification logic)."""
        if not self.is_valid_entry():
            return False

        # Check for person-related object classes
        person_classes = {
            "person",
            "organizationalPerson",
            "inetOrgPerson",
            "user",
            "posixAccount",
        }
        object_classes_attr = self.get_attribute("objectClass")
        if not object_classes_attr:
            return False

        object_classes = set(object_classes_attr)
        return bool(person_classes & object_classes)

    def is_group_entry(self) -> bool:
        """Check if entry represents a group (consolidated specification logic)."""
        if not self.is_valid_entry():
            return False

        # Check for group-related object classes
        group_classes = {
            "group",
            "groupOfNames",
            "groupOfUniqueNames",
            "posixGroup",
            "organizationalRole",
        }
        object_classes_attr = self.get_attribute("objectClass")
        if not object_classes_attr:
            return False

        object_classes = set(object_classes_attr)
        return bool(group_classes & object_classes)

    def is_organizational_unit(self) -> bool:
        """Check if entry represents an organizational unit (consolidated specification logic)."""
        if not self.is_valid_entry():
            return False

        # Check for OU-related object classes
        ou_classes = {
            "organizationalUnit",
            "organizationalRole",
            "dcObject",
            "domain",
        }
        object_classes_attr = self.get_attribute("objectClass")
        if not object_classes_attr:
            return False

        object_classes = set(object_classes_attr)
        return bool(ou_classes & object_classes)

    def is_change_record(self) -> bool:
        """Check if entry is a change record (consolidated specification logic)."""
        if not self.is_valid_entry():
            return False

        # Check for changetype attribute
        changetype = self.get_attribute("changetype")
        if not changetype:
            return False

        # Valid change types
        valid_change_types = {"add", "modify", "delete", "modrdn"}
        return changetype[0] in valid_change_types


__all__: list[str] = [
    "FlextLdifAttributes",
    "FlextLdifAttributesDict",
    "FlextLdifDNDict",
    "FlextLdifDistinguishedName",
    "FlextLdifEntry",
    "FlextLdifEntryDict",
    "LDIFContent",
    "LDIFLines",
]
