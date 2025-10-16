"""DN Case Registry - Tracks canonical DN case during quirk conversions.

This module provides the DnCaseRegistry class that maintains a mapping of
Distinguished Names (DNs) to their canonical case representation. This is
critical when converting between quirks with different case sensitivity:

- OID: Case-insensitive DNs (cn=Test and CN=test are equivalent)
- OUD: Case-sensitive DNs (requires consistent case across all references)

The registry ensures that when converting from OID to OUD, all DN references
(in entries, ACLs, group memberships) use the same canonical case.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_core import FlextModels, FlextResult, FlextTypes
from pydantic import ConfigDict

from flext_ldif.typings import FlextLdifTypes

type DN = str


class DnCaseRegistry(FlextModels.Value):
    """Registry for tracking canonical DN case during conversions.

    This class maintains a mapping of DNs in normalized form (lowercase, no spaces)
    to their canonical case representation. It's used during quirk conversions to
    ensure DN case consistency, especially when converting to OUD.

    Examples:
        >>> registry = DnCaseRegistry()
        >>>
        >>> # Register canonical case
        >>> canonical = registry.register_dn("CN=Admin, DC=Example, DC=Com")
        >>> # Returns: "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"
        >>>
        >>> # Get canonical case for variant
        >>> registry.get_canonical_dn("cn=ADMIN,dc=example,dc=com")
        >>> # Returns: "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"
        >>>
        >>> # Validate for OUD (no case conflicts)
        >>> result = registry.validate_oud_consistency()
        >>> # Returns: FlextResult[bool]

    Attributes:
        _registry: Dict mapping normalized DN → canonical DN
        _case_variants: Dict tracking all case variants seen for each normalized DN

    """

    # Allow mutation for internal state management
    model_config = ConfigDict(frozen=False)

    def __init__(self) -> None:
        """Initialize empty DN case registry."""
        super().__init__()
        self._registry: dict[str, str] = {}
        self._case_variants: dict[str, set[str]] = {}

    def _normalize_dn(self, dn: str) -> str:
        """Normalize DN for case-insensitive comparison.

        Normalization rules:
        - Convert to lowercase
        - Remove all spaces
        - Preserve structure (commas, equals)

        Args:
            dn: Distinguished Name to normalize

        Returns:
            Normalized DN string

        Examples:
            >>> registry._normalize_dn("CN=Test, DC=Example, DC=Com")
            'cn=test,dc=example,dc=com'
            >>> registry._normalize_dn("cn = REDACTED_LDAP_BIND_PASSWORD , dc = com")
            'cn=REDACTED_LDAP_BIND_PASSWORD,dc=com'

        """
        return dn.lower().replace(" ", "")

    def register_dn(self, dn: str, *, force: bool = False) -> str:
        """Register DN and return its canonical case.

        If this is the first time seeing this DN (normalized), it becomes
        the canonical case. If seen before, returns the existing canonical case.

        Args:
            dn: Distinguished Name to register
            force: If True, override existing canonical case with this one

        Returns:
            Canonical case DN string

        Examples:
            >>> registry = DnCaseRegistry()
            >>> registry.register_dn(
            ...     "CN=Admin,DC=Com"
            ... )  # First seen - becomes canonical
            'CN=Admin,DC=Com'
            >>> registry.register_dn("cn=REDACTED_LDAP_BIND_PASSWORD,dc=com")  # Returns existing canonical
            'CN=Admin,DC=Com'
            >>> registry.register_dn(
            ...     "cn=ADMIN,dc=COM", force=True
            ... )  # Force new canonical
            'cn=ADMIN,dc=COM'

        """
        normalized = self._normalize_dn(dn)

        # Track this case variant
        if normalized not in self._case_variants:
            self._case_variants[normalized] = set()
        self._case_variants[normalized].add(dn)

        # Register or return canonical case
        if normalized not in self._registry or force:
            self._registry[normalized] = dn

        return self._registry[normalized]

    def get_canonical_dn(self, dn: str) -> str | None:
        """Get canonical case for a DN (case-insensitive lookup).

        Args:
            dn: Distinguished Name to lookup

        Returns:
            Canonical case DN string, or None if not registered

        Examples:
            >>> registry = DnCaseRegistry()
            >>> registry.register_dn("CN=Admin,DC=Com")
            >>> registry.get_canonical_dn("cn=ADMIN,dc=com")
            'CN=Admin,DC=Com'
            >>> registry.get_canonical_dn("cn=Unknown,dc=com")
            None

        """
        normalized = self._normalize_dn(dn)
        return self._registry.get(normalized)

    def has_dn(self, dn: str) -> bool:
        """Check if DN is registered (case-insensitive).

        Args:
            dn: Distinguished Name to check

        Returns:
            True if DN is registered, False otherwise

        Examples:
            >>> registry = DnCaseRegistry()
            >>> registry.register_dn("CN=Admin,DC=Com")
            >>> registry.has_dn("cn=REDACTED_LDAP_BIND_PASSWORD,dc=com")
            True
            >>> registry.has_dn("cn=Other,dc=com")
            False

        """
        normalized = self._normalize_dn(dn)
        return normalized in self._registry

    def get_case_variants(self, dn: str) -> set[str]:
        """Get all case variants seen for a DN.

        Args:
            dn: Distinguished Name to get variants for

        Returns:
            Set of all case variants seen (including canonical)

        Examples:
            >>> registry = DnCaseRegistry()
            >>> registry.register_dn("CN=Admin,DC=Com")
            >>> registry.register_dn("cn=REDACTED_LDAP_BIND_PASSWORD,dc=com")
            >>> registry.register_dn("cn=ADMIN,dc=COM")
            >>> registry.get_case_variants("cn=REDACTED_LDAP_BIND_PASSWORD,dc=com")
            {'CN=Admin,DC=Com', 'cn=REDACTED_LDAP_BIND_PASSWORD,dc=com', 'cn=ADMIN,dc=COM'}

        """
        normalized = self._normalize_dn(dn)
        return self._case_variants.get(normalized, set())

    def validate_oud_consistency(self) -> FlextResult[bool]:
        """Validate DN case consistency for OUD conversion.

        OUD requires that all references to the same DN use the exact same case.
        This method checks if any DNs have multiple case variants, which would
        cause problems when converting to OUD.

        Returns:
            FlextResult[bool]:
                - Success with True if all DNs have consistent case
                - Success with False if inconsistencies found (with warnings in metadata)
                - Failure if validation cannot be performed

        Examples:
            >>> registry = DnCaseRegistry()
            >>> registry.register_dn("cn=REDACTED_LDAP_BIND_PASSWORD,dc=com")
            >>> result = registry.validate_oud_consistency()
            >>> result.unwrap()  # True - only one case variant

            >>> registry.register_dn("CN=Admin,DC=Com")  # Different case
            >>> result = registry.validate_oud_consistency()
            >>> result.is_success  # True but with warnings
            >>> result.unwrap()  # False - multiple case variants

        """
        inconsistencies: list[FlextTypes.Dict] = []

        for normalized_dn, variants in self._case_variants.items():
            if len(variants) > 1:
                canonical = self._registry[normalized_dn]
                inconsistencies.append(
                    {
                        "normalized_dn": normalized_dn,
                        "canonical_case": canonical,
                        "variants": list(variants),
                        "variant_count": len(variants),
                    }
                )

        if inconsistencies:
            warning_msg = (
                f"Found {len(inconsistencies)} DNs with case inconsistencies. "
                "These will be normalized to canonical case for OUD. "
                f"Example: {inconsistencies[0]['canonical_case']} has "
                f"{inconsistencies[0]['variant_count']} variants."
            )
            result = FlextResult[bool].ok(False)
            result.metadata = {
                "inconsistencies": inconsistencies,
                "warning": warning_msg,
            }
            return result

        return FlextResult[bool].ok(True)

    def normalize_dn_references(
        self,
        data: FlextLdifTypes.Dict,
        dn_fields: FlextTypes.StringList | None = None,
    ) -> FlextResult[FlextLdifTypes.Dict]:
        """Normalize DN references in data to use canonical case.

        This method searches through a dictionary and normalizes any DN values
        to use their canonical case from the registry. Useful for normalizing
        ACL "by" clauses, group memberships, etc.

        Args:
            data: Dictionary containing potential DN references
            dn_fields: List of field names that contain DNs (e.g., ["dn", "member", "uniqueMember"])
                      If None, uses default DN fields

        Returns:
            FlextResult containing normalized data dictionary

        Examples:
            >>> registry = DnCaseRegistry()
            >>> registry.register_dn("cn=REDACTED_LDAP_BIND_PASSWORD,dc=com")
            >>>
            >>> entry = {"dn": "CN=Admin,DC=Com", "member": ["cn=ADMIN,dc=com"]}
            >>> result = registry.normalize_dn_references(entry, ["dn", "member"])
            >>> normalized = result.unwrap()
            >>> normalized
            {'dn': 'cn=REDACTED_LDAP_BIND_PASSWORD,dc=com', 'member': ['cn=REDACTED_LDAP_BIND_PASSWORD,dc=com']}

        """
        if dn_fields is None:
            # Default DN fields to normalize
            dn_fields = [
                "dn",
                "member",
                "uniqueMember",
                "owner",
                "seeAlso",
                "secretary",
                "manager",
                "roleOccupant",
                "by",  # ACL by clause
            ]

        try:
            normalized_data = data.copy()

            for field in dn_fields:
                if field not in normalized_data:
                    continue

                value = normalized_data[field]

                # Handle string DN
                if isinstance(value, str):
                    canonical = self.get_canonical_dn(value)
                    if canonical is not None:
                        normalized_data[field] = canonical

                # Handle list of DNs
                elif isinstance(value, list):
                    normalized_list = []
                    for item in value:
                        if isinstance(item, str):
                            canonical = self.get_canonical_dn(item)
                            normalized_list.append(
                                canonical if canonical is not None else item
                            )
                        else:
                            normalized_list.append(item)
                    normalized_data[field] = normalized_list

            return FlextResult[FlextLdifTypes.Dict].ok(normalized_data)

        except Exception as e:
            return FlextResult[FlextLdifTypes.Dict].fail(
                f"Failed to normalize DN references: {e}"
            )

    def clear(self) -> None:
        """Clear all DN registrations.

        Useful when starting a new conversion to avoid DN pollution
        from previous conversions.

        Examples:
            >>> registry = DnCaseRegistry()
            >>> registry.register_dn("cn=REDACTED_LDAP_BIND_PASSWORD,dc=com")
            >>> registry.has_dn("cn=REDACTED_LDAP_BIND_PASSWORD,dc=com")
            True
            >>> registry.clear()
            >>> registry.has_dn("cn=REDACTED_LDAP_BIND_PASSWORD,dc=com")
            False

        """
        self._registry.clear()
        self._case_variants.clear()

    def get_stats(self) -> dict[str, int]:
        """Get registry statistics.

        Returns:
            Dictionary with registry statistics

        Examples:
            >>> registry = DnCaseRegistry()
            >>> registry.register_dn("cn=REDACTED_LDAP_BIND_PASSWORD,dc=com")
            >>> registry.register_dn("CN=Admin,DC=Com")
            >>> registry.get_stats()
            {
                'total_dns': 1,
                'total_variants': 2,
                'dns_with_multiple_variants': 1
            }

        """
        total_variants = sum(len(variants) for variants in self._case_variants.values())
        multiple_variants = sum(
            1 for variants in self._case_variants.values() if len(variants) > 1
        )

        return {
            "total_dns": len(self._registry),
            "total_variants": total_variants,
            "dns_with_multiple_variants": multiple_variants,
        }


__all__ = ["DN", "DnCaseRegistry"]
