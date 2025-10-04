"""FLEXT LDIF Specifications - Technology Detection Specifications.

Specification pattern implementations for detecting LDIF technology types.
Extends flext-core FlextModels with LDIF-specific detection patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextModels, FlextTypes
from pydantic import ConfigDict, Field


class FlextLdifSpecifications:
    """LDIF-specific technology specifications extending FlextModels.

    Contains specification pattern implementations for detecting
    different LDIF technology types and formats.
    """

    class TechnologySpecification(FlextModels.Value):
        """Base specification for detecting LDIF technology and format types.

        Uses Specification pattern to encapsulate business rules for:
        - OID format detection (Oracle Internet Directory)
        - OUD quirks detection (Oracle Unified Directory)
        - Standard LDIF format detection

        This enables strategy pattern through composition rather than inheritance.
        """

        model_config = ConfigDict(
            validate_assignment=True,
            extra="forbid",
            hide_input_in_errors=True,
        )

        name: str = Field(
            ...,
            description="Technology name (e.g., 'OID', 'OUD', 'Standard')",
        )

        patterns: FlextTypes.StringList = Field(
            default_factory=list,
            description="Regex patterns that indicate this technology",
        )

        attribute_markers: FlextTypes.StringList = Field(
            default_factory=list,
            description="Attribute names that indicate this technology",
        )

        syntax_markers: FlextTypes.StringList = Field(
            default_factory=list,
            description="Syntax patterns that indicate this technology",
        )

        @classmethod
        def is_satisfied_by(cls, data: FlextTypes.Dict) -> bool:
            """Check if data satisfies this specification.

            Args:
                data: Dictionary containing data to check against specification

            Returns:
                True if data matches this technology specification

            """
            return False  # Override in subclasses

    class OidSpecification(TechnologySpecification):
        """Specification for detecting Oracle Internet Directory (OID) format.

        OID format characteristics:
        - Uses numeric OIDs instead of attribute names
        - Custom syntax for ACIs (orclaci, orclacientry)
        - Specific schema attribute patterns
        """

        model_config = ConfigDict(
            validate_assignment=True,
            extra="forbid",
            hide_input_in_errors=True,
        )

        def __init__(self, **data: object) -> None:
            """Initialize OID specification with detection patterns."""
            super().__init__(
                name="OID",
                patterns=[
                    r"orclaci:",
                    r"orclacientry:",
                    r"^\d+\.\d+\.\d+\.\d+",  # Numeric OID pattern
                    r"orclguid",
                    r"orclobjectguid",
                ],
                attribute_markers=[
                    "orclaci",
                    "orclacientry",
                    "orclguid",
                    "orclobjectguid",
                    "orclentryid",
                ],
                syntax_markers=[
                    "OID syntax",
                    "Oracle OID",
                ],
                **data,
            )

        @classmethod
        def is_satisfied_by(cls, data: FlextTypes.Dict) -> bool:
            """Check if data uses OID format.

            Args:
                data: Dictionary with 'attributes', 'dn', or 'content' to check

            Returns:
                True if data appears to be in OID format

            """
            # Check for OID-specific attributes
            attributes = data.get("attributes", {})
            if isinstance(attributes, dict):
                oid_attrs = {"orclaci", "orclacientry", "orclguid", "orclobjectguid"}
                if any(attr in attributes for attr in oid_attrs):
                    return True

            # Check DN for OID patterns
            dn = data.get("dn", "")
            if isinstance(dn, str) and "orcl" in dn.lower():
                return True

            # Check content for OID patterns
            content = data.get("content", "")
            return isinstance(content, str) and any(
                marker in content for marker in ["orclaci:", "orclacientry:"]
            )

    class OudSpecification(TechnologySpecification):
        """Specification for detecting Oracle Unified Directory (OUD) quirks.

        OUD quirks characteristics:
        - Specific attribute handling differences
        - Custom schema extensions
        - Migration-specific attributes
        """

        model_config = ConfigDict(
            validate_assignment=True,
            extra="forbid",
            hide_input_in_errors=True,
        )

        def __init__(self, **data: object) -> None:
            """Initialize OUD specification with detection patterns."""
            super().__init__(
                name="OUD",
                patterns=[
                    r"ds-sync-",
                    r"ds-cfg-",
                    r"oud-",
                ],
                attribute_markers=[
                    "ds-sync-hist",
                    "ds-cfg-enabled",
                    "ds-sync-generation-id",
                ],
                syntax_markers=[
                    "OUD syntax",
                    "Directory Server",
                ],
                **data,
            )

        @classmethod
        def is_satisfied_by(cls, data: FlextTypes.Dict) -> bool:
            """Check if data contains OUD quirks.

            Args:
                data: Dictionary with 'attributes', 'dn', or 'content' to check

            Returns:
                True if data contains OUD-specific patterns

            """
            # Check for OUD-specific attributes
            attributes = data.get("attributes", {})
            if isinstance(attributes, dict):
                oud_attrs = {"ds-sync-hist", "ds-cfg-enabled", "ds-sync-generation-id"}
                if any(attr in attributes for attr in oud_attrs):
                    return True

            # Check DN for OUD patterns
            dn = data.get("dn", "")
            if isinstance(dn, str) and any(
                marker in dn.lower() for marker in ["ds-sync", "ds-cfg"]
            ):
                return True

            # Check content for OUD patterns
            content = data.get("content", "")
            return isinstance(content, str) and any(
                marker in content for marker in ["ds-sync-", "ds-cfg-"]
            )

    class StandardLdifSpecification(TechnologySpecification):
        """Specification for detecting standard LDIF format.

        Standard LDIF characteristics:
        - RFC 2849 compliance
        - Standard attribute names (cn, ou, dc, etc.)
        - No vendor-specific extensions
        """

        model_config = ConfigDict(
            validate_assignment=True,
            extra="forbid",
            hide_input_in_errors=True,
        )

        def __init__(self, **data: object) -> None:
            """Initialize standard LDIF specification with detection patterns."""
            super().__init__(
                name="Standard",
                patterns=[
                    r"^dn:",
                    r"^changetype:",
                    r"^add:",
                    r"^delete:",
                    r"^modify:",
                ],
                attribute_markers=[
                    "objectClass",
                    "cn",
                    "ou",
                    "dc",
                    "dn",
                    "sn",
                    "givenName",
                    "mail",
                    "uid",
                    "userPassword",
                ],
                syntax_markers=[
                    "RFC 2849",
                    "Standard LDIF",
                ],
                **data,
            )

        @classmethod
        def is_satisfied_by(cls, data: FlextTypes.Dict) -> bool:
            """Check if data is in standard LDIF format.

            Args:
                data: Dictionary with 'attributes', 'dn', or 'content' to check

            Returns:
                True if data appears to be in standard LDIF format

            """
            # Check for standard attributes
            attributes = data.get("attributes", {})
            if isinstance(attributes, dict):
                standard_attrs = {
                    "objectclass",
                    "cn",
                    "ou",
                    "dc",
                    "dn",
                    "sn",
                    "givenname",
                    "mail",
                    "uid",
                    "userpassword",
                }
                if any(attr.lower() in standard_attrs for attr in attributes):
                    return True

            # Check DN for standard patterns
            dn = data.get("dn", "")
            if isinstance(dn, str) and any(
                component in dn.lower() for component in ["cn=", "ou=", "dc="]
            ):
                return True

            # Default to standard if no other patterns match
            return True
