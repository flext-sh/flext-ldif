#!/usr/bin/env python3
"""Example 6: Custom Quirks.

Demonstrates:
- Creating custom server quirks
- Registering custom quirks with registry
- Extending RFC parsers for custom LDAP servers
- Protocol-based quirk interface
"""

from __future__ import annotations

from flext_core import FlextResult
from flext_ldif.quirks.registry import QuirkRegistryService
from flext_ldif.rfc.rfc_schema_parser import RfcSchemaParserService


class CustomLdapSchemaQuirk:
    """Custom LDAP server schema quirk example.

    Follows the same protocol as built-in quirks:
    - server_type: Unique identifier for server
    - priority: Lower number = higher priority (10=high, 15=medium, 20=low)
    - can_handle_attribute(): Check if quirk can handle attribute
    - parse_attribute(): Parse attribute to RFC format
    - can_handle_objectclass(): Check if quirk can handle objectClass
    - parse_objectclass(): Parse objectClass to RFC format
    """

    server_type: str = "my_custom_ldap"
    priority: int = 15  # Medium priority

    def can_handle_attribute(self, definition: str) -> bool:
        """Check if this quirk can handle the attribute definition."""
        # Custom logic to detect if this is our server's format
        return "X-CUSTOM-" in definition

    def parse_attribute(self, definition: str) -> FlextResult[dict]:
        """Parse custom attribute format to RFC 4512 format."""
        try:
            # Custom parsing logic
            if "X-CUSTOM-" in definition:
                # Extract attribute name and custom syntax
                parts = definition.split()
                name = None
                for i, part in enumerate(parts):
                    if part == "NAME":
                        name = parts[i + 1].strip("'")
                        break

                if name:
                    # Convert to RFC 4512 format
                    rfc_attr = {
                        "name": name,
                        "syntax": "1.3.6.1.4.1.1466.115.121.1.15",  # DirectoryString
                        "description": f"Custom {name} attribute",
                    }
                    return FlextResult[dict].ok(rfc_attr)

            return FlextResult[dict].fail("Not a custom attribute format")
        except Exception as e:
            return FlextResult[dict].fail(f"Parse error: {e}")

    def can_handle_objectclass(self, definition: str) -> bool:
        """Check if this quirk can handle the objectClass definition."""
        return "X-CUSTOM-CLASS-" in definition

    def parse_objectclass(self, definition: str) -> FlextResult[dict]:
        """Parse custom objectClass format to RFC 4512 format."""
        try:
            if "X-CUSTOM-CLASS-" in definition:
                parts = definition.split()
                name = None
                for i, part in enumerate(parts):
                    if part == "NAME":
                        name = parts[i + 1].strip("'")
                        break

                if name:
                    rfc_class = {
                        "name": name,
                        "description": f"Custom {name} objectClass",
                        "structural": True,
                    }
                    return FlextResult[dict].ok(rfc_class)

            return FlextResult[dict].fail("Not a custom objectClass format")
        except Exception as e:
            return FlextResult[dict].fail(f"Parse error: {e}")


def main() -> None:
    """Custom quirks example."""
    # Initialize standard quirk registry
    quirk_registry = QuirkRegistryService()

    # Create and register custom quirk
    CustomLdapSchemaQuirk()

    # Register custom quirk
    # Note: In practice, you'd extend QuirkRegistryService to support
    # dynamic quirk registration, or modify the registry's __init__

    # Use custom quirk with RFC parser
    custom_schema = """
dn: cn=schema
objectClass: top
objectClass: ldapSubentry
objectClass: subschema
cn: schema
attributeTypes: ( 1.2.3.4.5 NAME 'customAttr' DESC 'Custom attribute' X-CUSTOM-MARKER SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
"""

    # Parse with custom quirk
    parser = RfcSchemaParserService(
        params={"content": custom_schema},
        quirk_registry=quirk_registry,  # MANDATORY parameter
        server_type="my_custom_ldap",  # Uses our custom quirk
    )

    result = parser.execute()

    if result.is_success:
        result.unwrap()


if __name__ == "__main__":
    main()
