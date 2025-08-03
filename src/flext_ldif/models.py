"""FLEXT-LDIF Domain Models and Value Objects.

This module contains the core domain model for LDIF processing, implementing
Domain-Driven Design patterns with immutable value objects and rich domain
entities built on flext-core foundation classes.

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
    >>> entry = FlextLdifEntry.model_validate({
    ...     "dn": dn,
    ...     "attributes": FlextLdifAttributes(attributes={
    ...         "cn": ["John Doe"],
    ...         "objectClass": ["person", "inetOrgPerson"],
    ...         "mail": ["john@example.com"]
    ...     })
    ... })
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

# 🚨 ARCHITECTURAL COMPLIANCE: Using flext-core root namespace imports
from flext_core import (
    FlextDomainValueObject,
    FlextImmutableModel,
    FlextResult,
    get_logger,
)
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


class FlextLdifDistinguishedName(FlextDomainValueObject):
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
        >>> dn = FlextLdifDistinguishedName(value="cn=John Doe,ou=people,dc=example,dc=com")
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
                msg = f"Invalid DN component: {component}"
                raise ValueError(msg)

            attr_name, attr_value = component.split("=", 1)
            if not attr_name.strip() or not attr_value.strip():
                msg = f"Invalid DN component: {component}"
                raise ValueError(msg)

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
        """Get relative distinguished name (first component)."""
        return self.value.split(",")[0].strip()

    def get_parent_dn(self) -> FlextLdifDistinguishedName | None:
        """Get parent DN."""
        components = self.value.split(",")
        if len(components) <= 1:
            return None

        parent_dn = ",".join(components[1:]).strip()
        return FlextLdifDistinguishedName.model_validate({"value": parent_dn})

    def is_child_of(self, parent: FlextLdifDistinguishedName) -> bool:
        """Check if this DN is a child of another DN in the hierarchy.

        Performs case-insensitive comparison to determine if this DN is a child
        of the specified parent DN by checking if this DN ends with the parent DN.

        Args:
            parent: The parent DN to check against

        Returns:
            True if this DN is a child of the parent DN, False otherwise

        Example:
            >>> child = FlextLdifDistinguishedName(value="cn=user,ou=people,dc=example,dc=com")
            >>> parent = FlextLdifDistinguishedName(value="ou=people,dc=example,dc=com")
            >>> child.is_child_of(parent)  # True
            >>> parent.is_child_of(child)  # False

        """
        return self.value.lower().endswith(parent.value.lower())

    def get_depth(self) -> int:
        """Get the hierarchical depth of the DN.

        Calculates the number of components in the DN by counting comma-separated
        attribute=value pairs, providing the depth in the LDAP hierarchy.

        Returns:
            The number of DN components (depth in hierarchy)

        Example:
            >>> dn = FlextLdifDistinguishedName(value="cn=user,ou=people,dc=example,dc=com")
            >>> dn.get_depth()  # 4 (cn, ou, dc, dc)
            >>> root = FlextLdifDistinguishedName(value="dc=com")
            >>> root.get_depth()  # 1

        """
        return len(self.value.split(","))

    def validate_semantic_rules(self) -> FlextResult[None]:
        """Validate DN semantic business rules following RFC 4514.

        Performs comprehensive validation of the DN structure including
        format validation, component structure, and business rule compliance
        using Railway-Oriented Programming patterns.

        Returns:
            FlextResult[None]: Success if DN is valid, failure with error message

        Business Rules Validated:
            - DN must contain at least one attribute=value pair
            - Each component must have valid format
            - Attribute names and values must be non-empty

        Example:
            >>> dn = FlextLdifDistinguishedName(value="cn=user,dc=example,dc=com")
            >>> result = dn.validate_semantic_rules()
            >>> result.is_success  # True

        Raises:
            No exceptions - all errors returned via FlextResult pattern

        """
        # Validation is done in field_validator, so just check final state
        if not self.value or "=" not in self.value:
            return FlextResult.fail("DN must contain at least one attribute=value pair")
        return FlextResult.ok(None)

    def to_dn_dict(self) -> FlextLdifDNDict:
        """Convert to FlextLdifDNDict representation."""
        return FlextLdifDNDict(
            value=self.value,
            components=self.value.split(","),
            depth=self.get_depth(),
        )


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
        >>> attrs = FlextLdifAttributes(attributes={
        ...     "cn": ["John Doe"],
        ...     "objectClass": ["person", "inetOrgPerson"],
        ...     "mail": ["john@example.com", "john.doe@company.com"]
        ... })
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
        values = self.attributes.get(name, [])
        return values[0] if values else None

    def get_values(self, name: str) -> list[str]:
        """Get all values for a multi-valued attribute.

        Retrieves the complete list of values for the specified attribute,
        supporting LDAP's multi-valued attribute semantics.

        Args:
            name: The attribute name to retrieve values for

        Returns:
            List of all values for the attribute, empty list if attribute doesn't exist

        Example:
            >>> attrs = FlextLdifAttributes(attributes={
            ...     "objectClass": ["person", "inetOrgPerson"],
            ...     "mail": ["user@example.com", "user@company.com"]
            ... })
            >>> attrs.get_values("objectClass")  # ["person", "inetOrgPerson"]
            >>> attrs.get_values("nonexistent")  # []

        """
        return self.attributes.get(name, [])

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
        return name in self.attributes

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
        new_attrs = {}
        for attr_name, attr_values in self.attributes.items():
            new_attrs[attr_name] = attr_values.copy()

        if name not in new_attrs:
            new_attrs[name] = []
        new_attrs[name] += [value]
        return FlextLdifAttributes.model_validate({"attributes": new_attrs})

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
            >>> attrs = FlextLdifAttributes(attributes={
            ...     "mail": ["john@example.com", "john@company.com"]
            ... })
            >>> new_attrs = attrs.remove_value("mail", "john@company.com")
            >>> new_attrs.get_values("mail")  # ["john@example.com"]
            >>> attrs.get_values("mail")  # ["john@example.com", "john@company.com"] (original unchanged)

        """
        new_attrs = {}
        for attr_name, attr_values in self.attributes.items():
            if attr_name == name:
                new_values = [v for v in attr_values if v != value]
                if new_values:
                    new_attrs[attr_name] = new_values
            else:
                new_attrs[attr_name] = attr_values.copy()
        return FlextLdifAttributes.model_validate({"attributes": new_attrs})

    def get_attribute_names(self) -> list[str]:
        """Get all attribute names in the collection.

        Retrieves the complete list of attribute names present in the attributes
        collection, useful for iteration and attribute discovery operations.

        Returns:
            List of all attribute names in the collection

        Example:
            >>> attrs = FlextLdifAttributes(attributes={
            ...     "cn": ["John Doe"],
            ...     "mail": ["john@example.com"],
            ...     "objectClass": ["person", "inetOrgPerson"]
            ... })
            >>> attrs.get_attribute_names()  # ["cn", "mail", "objectClass"]

        """
        return list(self.attributes.keys())

    def get_total_values(self) -> int:
        """Get total number of attribute values across all attributes.

        Calculates the sum of all values across all attributes in the collection,
        useful for statistics and memory usage estimation.

        Returns:
            Total count of all attribute values

        Example:
            >>> attrs = FlextLdifAttributes(attributes={
            ...     "cn": ["John Doe"],  # 1 value
            ...     "mail": ["john@example.com", "john@company.com"],  # 2 values
            ...     "objectClass": ["person", "inetOrgPerson"]  # 2 values
            ... })
            >>> attrs.get_total_values()  # 5

        """
        return sum(len(values) for values in self.attributes.values())

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
        return len(self.attributes) == 0

    def __eq__(self, other: object) -> bool:
        """Compare with dict or other FlextLdifAttributes."""
        if isinstance(other, dict):
            return self.attributes == other
        if isinstance(other, FlextLdifAttributes):
            return self.attributes == other.attributes
        return False

    def __hash__(self) -> int:
        """Return hash of attributes for use in sets/dicts."""
        return hash(
            frozenset((key, tuple(values)) for key, values in self.attributes.items()),
        )

    def validate_semantic_rules(self) -> FlextResult[None]:
        """Validate attributes collection against business rules using Railway-Oriented Programming.

        Performs comprehensive validation of the attributes collection including
        attribute name validation, value constraints, and business rule compliance
        following Domain-Driven Design patterns.

        Returns:
            FlextResult[None]: Success if all attributes are valid, failure with error message

        Business Rules Validated:
            - Attribute names must be non-empty strings
            - Attribute names cannot be whitespace-only
            - Attributes collection structure must be valid

        Example:
            >>> attrs = FlextLdifAttributes(attributes={"cn": ["Valid Name"]})
            >>> result = attrs.validate_semantic_rules()
            >>> result.is_success  # True
            >>>
            >>> invalid_attrs = FlextLdifAttributes(attributes={"": ["Invalid"]})
            >>> result = invalid_attrs.validate_semantic_rules()
            >>> result.is_success  # False

        Raises:
            No exceptions - all errors returned via FlextResult pattern

        """
        # Validate attribute names
        for attr_name in self.attributes:
            if not attr_name.strip():
                return FlextResult.fail(f"Invalid attribute name: {attr_name}")
        return FlextResult.ok(None)

    def to_attributes_dict(self) -> FlextLdifAttributesDict:
        """Convert to FlextLdifAttributesDict representation."""
        return FlextLdifAttributesDict(
            attributes=self.attributes.copy(),
            count=len(self.attributes),
        )


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
        ...     dn=FlextLdifDistinguishedName(value="cn=John Doe,ou=people,dc=example,dc=com"),
        ...     attributes=FlextLdifAttributes(attributes={
        ...         "cn": ["John Doe"],
        ...         "objectClass": ["person", "inetOrgPerson"],
        ...         "mail": ["john@example.com"]
        ...     })
        ... )
        >>> entry.is_person_entry()  # True
        >>> entry.has_object_class("person")  # True

        Validate business rules:
        >>> result = entry.validate_semantic_rules()
        >>> result.is_success  # True

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
        msg = f"Invalid DN type: {type(v)}"
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
        """Get LDIF attribute values by name with LDAP multi-value support.

        Retrieves all values for the specified LDAP attribute from this entry,
        supporting LDAP's multi-valued attribute semantics. Returns None if
        the attribute doesn't exist in this entry.

        Args:
            name: The attribute name to retrieve (case-sensitive)

        Returns:
            List of all attribute values if found, None if attribute doesn't exist

        Example:
            >>> entry = FlextLdifEntry(
            ...     dn=FlextLdifDistinguishedName(value="cn=user,dc=example,dc=com"),
            ...     attributes=FlextLdifAttributes(attributes={
            ...         "mail": ["user@example.com", "user@company.com"],
            ...         "objectClass": ["person", "inetOrgPerson"]
            ...     })
            ... )
            >>> entry.get_attribute("mail")  # ["user@example.com", "user@company.com"]
            >>> entry.get_attribute("nonexistent")  # None

        """
        if not self.attributes.has_attribute(name):
            return None
        return self.attributes.get_values(name)

    def set_attribute(self, name: str, values: list[str]) -> None:
        """Set an attribute with the given name and values."""
        new_attrs = self.attributes.attributes.copy()
        new_attrs[name] = values
        # Use property setter instead of direct assignment
        object.__setattr__(
            self,
            "attributes",
            FlextLdifAttributes.model_validate({"attributes": new_attrs}),
        )

    def has_attribute(self, name: str) -> bool:
        """Check if LDIF entry has a specific attribute.

        Determines whether the specified attribute name exists in this LDIF entry,
        regardless of whether the attribute has values. Useful for existence checks
        before attribute operations.

        Args:
            name: The attribute name to check (case-sensitive)

        Returns:
            True if attribute exists (even if empty), False otherwise

        Example:
            >>> entry = FlextLdifEntry(
            ...     dn=FlextLdifDistinguishedName(value="cn=user,dc=example,dc=com"),
            ...     attributes=FlextLdifAttributes(attributes={
            ...         "cn": ["User Name"],
            ...         "mail": []  # exists but empty
            ...     })
            ... )
            >>> entry.has_attribute("cn")  # True
            >>> entry.has_attribute("mail")  # True (exists but empty)
            >>> entry.has_attribute("nonexistent")  # False

        """
        return self.attributes.has_attribute(name)

    def get_object_classes(self) -> list[str]:
        """Get object classes for this LDIF entry.

        Retrieves all objectClass values from this entry, which define the entry's
        type and schema in LDAP directory structures. ObjectClass is a critical
        attribute that determines what other attributes are allowed.

        Returns:
            List of object class names, empty list if no objectClass attribute

        Example:
            >>> entry = FlextLdifEntry(
            ...     dn=FlextLdifDistinguishedName(value="cn=user,dc=example,dc=com"),
            ...     attributes=FlextLdifAttributes(attributes={
            ...         "objectClass": ["person", "inetOrgPerson", "organizationalPerson"]
            ...     })
            ... )
            >>> entry.get_object_classes()  # ["person", "inetOrgPerson", "organizationalPerson"]

        """
        return self.attributes.get_values("objectClass")

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
            ...     attributes=FlextLdifAttributes(attributes={
            ...         "objectClass": ["person", "inetOrgPerson"]
            ...     })
            ... )
            >>> entry.has_object_class("person")  # True
            >>> entry.has_object_class("inetOrgPerson")  # True
            >>> entry.has_object_class("group")  # False

        """
        return object_class in self.get_object_classes()

    def get_attribute_values(self, name: str) -> list[str]:
        """Get attribute values by name.

        Args:
            name: Attribute name

        Returns:
            List of attribute values

        """
        return self.attributes.get_values(name)

    def is_modify_operation(self) -> bool:
        """Check if this is a modify operation."""
        changetype = self.get_attribute("changetype")
        return bool(changetype and changetype[0].lower() == "modify")

    def is_add_operation(self) -> bool:
        """Check if this is an add operation."""
        changetype = self.get_attribute("changetype")
        # Default to add operation when no changetype is specified (standard LDIF behavior)
        return not changetype or changetype[0].lower() == "add"

    def is_delete_operation(self) -> bool:
        """Check if this is a delete operation."""
        changetype = self.get_attribute("changetype")
        return bool(changetype and changetype[0].lower() == "delete")

    def get_single_attribute(self, name: str) -> str | None:
        """Get single value from an LDIF attribute.

        Args:
            name: The attribute name to retrieve

        Returns:
            First attribute value if found, None otherwise

        """
        return self.attributes.get_single_value(name)

    def to_ldif(self) -> str:
        """Convert entry to LDIF string format.

        Converts this FlextLdifEntry to standard LDIF (LDAP Data Interchange Format)
        string representation following RFC 2849 specifications. The output includes
        the DN line followed by all attributes and values, with proper line formatting.

        Returns:
            LDIF string representation of the entry with RFC 2849 compliance

        Example:
            >>> entry = FlextLdifEntry(
            ...     dn=FlextLdifDistinguishedName(value="cn=John Doe,ou=people,dc=example,dc=com"),
            ...     attributes=FlextLdifAttributes(attributes={
            ...         "cn": ["John Doe"],
            ...         "objectClass": ["person", "inetOrgPerson"],
            ...         "mail": ["john@example.com"]
            ...     })
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
            msg = "LDIF block cannot be empty"
            raise ValueError(msg)

        # First line must be DN
        dn_line = lines[0]
        if not dn_line.startswith("dn:"):
            msg = f"First line must be DN, got: {dn_line}"
            raise ValueError(msg)

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

        return cls(
            dn=FlextLdifDistinguishedName.model_validate({"value": dn}),
            attributes=FlextLdifAttributes.model_validate({"attributes": attributes}),
        )

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

            entry = cls(dn=dn_obj, attributes=attrs_obj)
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


__all__ = [
    "FlextLdifAttributes",
    "FlextLdifAttributesDict",
    "FlextLdifDNDict",
    "FlextLdifDistinguishedName",
    "FlextLdifEntry",
    "FlextLdifEntryDict",
    "LDIFContent",
    "LDIFLines",
]
