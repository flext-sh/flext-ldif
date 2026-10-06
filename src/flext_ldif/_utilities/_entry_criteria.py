"""LDIF entry multi-criteria matching utilities.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Callable, Iterable

from flext_ldif import c, p, t
from flext_ldif._models.settings import FlextLdifModelsSettings
from flext_ldif._utilities._entry_access import FlextLdifEntryAccess
from flext_ldif._utilities._entry_matching import FlextLdifEntryMatching


class FlextLdifEntryCriteria:
    """Evaluate configured entry criteria in a single pass."""

    @staticmethod
    def _schema_criterion(
        entry: p.Ldif.Entry,
        resolved_config: FlextLdifModelsSettings.EntryCriteriaConfig,
    ) -> bool | None:
        """Evaluate the schema-entry criterion when configured.

        Returns:
            The resulting ``bool | None``.
        """
        if resolved_config.is_schema is None:
            return None
        return FlextLdifEntryMatching.is_schema_entry(entry) == (
            resolved_config.is_schema
        )

    @staticmethod
    def _objectclass_criterion(
        entry: p.Ldif.Entry,
        resolved_config: FlextLdifModelsSettings.EntryCriteriaConfig,
    ) -> bool | None:
        """Evaluate the objectClass criterion when configured.

        Returns:
            The resulting ``bool | None``.
        """
        if not resolved_config.objectclasses:
            return None
        entry_ocs: t.StrSequence = FlextLdifEntryAccess.get_objectclass_names(entry)
        entry_ocs_lower = {oc.lower() for oc in entry_ocs}
        matching = [
            oc for oc in resolved_config.objectclasses if oc.lower() in entry_ocs_lower
        ]
        return (
            bool(matching)
            if resolved_config.objectclass_mode == "any"
            else len(matching) == len(resolved_config.objectclasses)
        )

    @staticmethod
    def _attrs_criterion(
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
        if not configured_attrs:
            return None
        if not entry.attributes:
            return False
        entry_attrs_lower = {k.lower() for k in entry.attributes.attributes}
        return aggregate(a.lower() in entry_attrs_lower for a in configured_attrs)

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
