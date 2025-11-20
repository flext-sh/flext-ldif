"""LDIF Validation Utilities - Pure Validation Functions.

Stateless validation functions for Entry model validators.
NO hard-coded server logic - only RFC compliance and format validation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import base64
import re


class FlextLdifUtilitiesValidation:
    """Pure validation functions for Entry model validators.

    Architecture:
    - Stateless pure functions (no side effects)
    - Return (bool, violations) tuples
    - ZERO server-specific logic (only RFC validation)
    - Used by Entry.validate_server_specific_rules()

    Purpose: Enable dynamic validation via DI-injected rules.
    """

    @staticmethod
    def validate_encoding(
        value: object,
        allowed_encodings: list[str],
    ) -> tuple[bool, list[str]]:
        """Validate string encoding.

        Args:
            value: Value to validate (must be string)
            allowed_encodings: List of allowed encodings (e.g., ["utf-8", "iso-8859-1"])

        Returns:
            (is_valid, violations) tuple

        """
        violations: list[str] = []

        if not isinstance(value, str):
            violations.append(f"Value is not a string: {type(value)}")
            return (False, violations)

        # Try each allowed encoding
        valid_encoding_found = False
        for encoding in allowed_encodings:
            try:
                # Try to encode with this encoding
                value.encode(encoding)
                valid_encoding_found = True
                break
            except (UnicodeEncodeError, LookupError):
                continue

        if not valid_encoding_found:
            violations.append(
                f"Value cannot be encoded with allowed encodings: {allowed_encodings}",
            )

        return (len(violations) == 0, violations)

    @staticmethod
    def validate_base64(value: object) -> tuple[bool, list[str]]:
        """Validate base64 format.

        Args:
            value: Value to validate (must be string)

        Returns:
            (is_valid, violations) tuple

        """
        violations: list[str] = []

        if not isinstance(value, str):
            violations.append(f"Value is not a string: {type(value)}")
            return (False, violations)

        # RFC 4648 § 4: Base64 alphabet
        base64_pattern = re.compile(r"^[A-Za-z0-9+/]*={0,2}$")

        if not base64_pattern.match(value):
            violations.append("Value contains invalid base64 characters (RFC 4648 § 4)")

        # Check padding (RFC 4648 § 4: padding with =)
        if "=" in value:
            # Padding must be at the end
            if not value.endswith("=") and not value.endswith("=="):
                violations.append("Base64 padding must be at the end")

            # Check if padding is correct (length % 4 == 0 after padding)
            if len(value) % 4 != 0:
                violations.append(
                    f"Invalid base64 padding: length {len(value)} is not multiple of 4",
                )

        # Try to decode to verify validity
        if not violations:
            try:
                base64.b64decode(value, validate=True)
            except Exception as e:
                violations.append(f"Base64 decode failed: {e}")

        return (len(violations) == 0, violations)

    @staticmethod
    def validate_dn(value: str) -> bool:
        """Validate DN format (RFC 4514 simplified).

        Args:
            value: DN string to validate

        Returns:
            True if valid DN format

        """
        if not isinstance(value, str) or not value.strip():
            return False

        # RFC 4514 § 2.3: DN = RDN *( "," RDN )
        # RDN = attributeTypeAndValue *( "+" attributeTypeAndValue )
        # attributeTypeAndValue = attributeType "=" attributeValue

        # Simplified pattern: attribute=value[,attribute=value]*
        # Allow spaces, handle escaping minimally
        components = [comp.strip() for comp in value.split(",") if comp.strip()]

        if not components:
            return False

        # Each component must have "=" (attribute=value)
        for comp in components:
            if "=" not in comp:
                return False

            # Check for valid attribute name (alphanumeric, hyphens, dots)
            attr_name = comp.split("=")[0].strip()
            if not re.match(r"^[a-zA-Z][a-zA-Z0-9.-]*$", attr_name):
                return False

        return True
