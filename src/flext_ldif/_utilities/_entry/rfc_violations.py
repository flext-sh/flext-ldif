"""Entry RFC violations collection and context.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from flext_cli import u

from flext_ldif import c

if TYPE_CHECKING:
    from flext_ldif import p, t


class FlextLdifUtilitiesEntryRfcViolations:
    """RFC violation tracking and context utilities for LDIF entries."""

    logger: ClassVar[p.Logger] = u.fetch_logger(__name__)

    @classmethod
    def collect_rfc_violations(
        cls, entry: p.Ldif.Entry
    ) -> tuple[str, t.MutableSequenceOf[str]]:
        """Collect an entry's RFC 2849/4512/4514 violations without rejecting it.

        Returns:
            The DN value used as context and the violation descriptions.

        """
        if entry.dn is None:
            return ("<None>", ["RFC 2849 § 2: DN is required"])
        dn_value = entry.dn.value
        return (
            dn_value,
            [
                *cls.validate_dn_format(dn_value),
                *cls.validate_attributes_required(entry),
                *cls.validate_attribute_descriptions(entry),
                *cls.validate_objectclass(entry, dn_value),
                *cls.validate_naming_attribute(entry, dn_value),
                *cls.validate_binary_options(entry),
                *cls.validate_attribute_syntax(entry),
                *cls.validate_changetype(entry),
            ],
        )

    @staticmethod
    def rfc_violation_context(
        entry: p.Ldif.Entry,
        dn_value: str,
        total_violations: int,
        previous: t.StrMapping,
    ) -> t.MutableStrMapping:
        """Return the validation context recorded with an entry's RFC findings.

        Returns:
            The previous context extended with this validation's facts.

        """
        context = c.Ldif.RfcValidationContext
        return {
            **previous,
            context.VALIDATOR_KEY: context.VALIDATOR_NAME,
            c.Ldif.DictKeys.DN: dn_value,
            context.ATTRIBUTE_COUNT_KEY: str(
                len(entry.attributes.attributes) if entry.attributes is not None else 0
            ),
            context.TOTAL_VIOLATIONS_KEY: str(total_violations),
        }


__all__: list[str] = ["FlextLdifUtilitiesEntryRfcViolations"]
