"""LDIF entry multi-criteria matching utilities.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Callable, Iterable

from flext_ldif import c, p, t
from flext_ldif._models import FlextLdifModelsSettings


class FlextLdifEntryCriteria:
    """Evaluate configured entry criteria in a single pass."""

    @staticmethod
    def _membership_criterion(
        configured: t.StrSequence | None,
        present: Iterable[str],
        aggregate: Callable[[Iterable[bool]], bool],
    ) -> bool | None:
        """Evaluate one case-insensitive set-membership criterion when configured.

        Args:
            configured: The configured member names, or None to skip.
            present: The present member names carried by the entry.
            aggregate: The membership aggregation (``all`` or ``any``).

        Returns:
            The resulting ``bool | None``.
        """
        if not configured:
            return None
        present_lower = {value.lower() for value in present}
        return aggregate(value.lower() in present_lower for value in configured)

    @staticmethod
    def _schema_criterion(
        entry: p.Ldif.Entry,
        resolved_config: FlextLdifModelsSettings.EntryCriteriaConfig,
    ) -> bool | None:
        """Evaluate the schema-entry criterion when configured.

        Returns:
            The resulting ``bool | None``.
        """
        from flext_ldif._utilities import FlextLdifEntryMatching

        if resolved_config.is_schema is None:
            return None
        return FlextLdifEntryMatching.detects_schema_entry(entry) == (
            resolved_config.is_schema
        )

    @classmethod
    def _objectclass_criterion(
        cls,
        entry: p.Ldif.Entry,
        resolved_config: FlextLdifModelsSettings.EntryCriteriaConfig,
    ) -> bool | None:
        """Evaluate the objectClass criterion when configured.

        Returns:
            The resulting ``bool | None``.
        """
        from flext_ldif._utilities import FlextLdifEntryAccess

        if not resolved_config.objectclasses:
            return None
        entry_ocs: t.StrSequence = FlextLdifEntryAccess.resolve_objectclass_names(entry)
        matched = cls._membership_criterion(
            resolved_config.objectclasses,
            entry_ocs,
            any if resolved_config.objectclass_mode == "any" else all,
        )
        return bool(matched)

    @classmethod
    def _attrs_criterion(
        cls,
        configured_attrs: t.StrSequence | None,
        entry: p.Ldif.Entry,
        aggregate: Callable[[Iterable[bool]], bool],
    ) -> bool | None:
        """Evaluate one attribute-membership criterion when configured.

        Args:
            configured_attrs: The configured attribute names, or None to skip.
            entry: The parsed entry carrying the attribute set.
            aggregate: The membership aggregation (``all`` or ``any``).

        Returns:
            The resulting ``bool | None``.
        """
        if not entry.attributes:
            return False if configured_attrs else None
        return cls._membership_criterion(
            configured_attrs,
            entry.attributes.attributes,
            aggregate,
        )

    @classmethod
    def _required_attrs_criterion(
        cls,
        entry: p.Ldif.Entry,
        resolved_config: FlextLdifModelsSettings.EntryCriteriaConfig,
    ) -> bool | None:
        """Evaluate the required-attributes criterion when configured.

        Returns:
            The resulting ``bool | None``.
        """
        return cls._attrs_criterion(
            resolved_config.required_attrs,
            entry,
            all,
        )

    @classmethod
    def _any_attrs_criterion(
        cls,
        entry: p.Ldif.Entry,
        resolved_config: FlextLdifModelsSettings.EntryCriteriaConfig,
    ) -> bool | None:
        """Evaluate the any-attribute criterion when configured.

        Returns:
            The resulting ``bool | None``.
        """
        return cls._attrs_criterion(
            resolved_config.any_attrs,
            entry,
            any,
        )

    @staticmethod
    def _dn_pattern_criterion(
        entry: p.Ldif.Entry,
        resolved_config: FlextLdifModelsSettings.EntryCriteriaConfig,
    ) -> bool | None:
        """Evaluate the DN pattern criterion when configured.

        Returns:
            The resulting ``bool | None``.
        """
        if not resolved_config.dn_pattern:
            return None
        dn_value = str(entry.dn) if entry.dn else ""
        return bool(
            c.Ldif.compile_pattern(
                resolved_config.dn_pattern,
                ignorecase=True,
            ).search(dn_value),
        )

    @staticmethod
    def matches_criteria(
        entry: p.Ldif.Entry,
        settings: FlextLdifModelsSettings.EntryCriteriaConfig | None = None,
        **kwargs: str | float | bool | None,
    ) -> bool:
        """Check multiple entry criteria in one call.

        Returns:
            The resulting ``bool``.
        """
        resolved_config = (
            settings
            if settings is not None
            else FlextLdifModelsSettings.EntryCriteriaConfig.model_validate(kwargs)
        )
        checks: t.MutableSequenceOf[bool] = []
        for criterion in (
            FlextLdifEntryCriteria._schema_criterion(entry, resolved_config),
            FlextLdifEntryCriteria._objectclass_criterion(entry, resolved_config),
            FlextLdifEntryCriteria._required_attrs_criterion(entry, resolved_config),
            FlextLdifEntryCriteria._any_attrs_criterion(entry, resolved_config),
            FlextLdifEntryCriteria._dn_pattern_criterion(entry, resolved_config),
        ):
            if criterion is not None:
                checks.append(criterion)
        return all(checks)


__all__: list[str] = ["FlextLdifEntryCriteria"]
