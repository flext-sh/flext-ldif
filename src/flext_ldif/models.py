"""LDIF Domain Models - Unified Model Aggregation Layer.

Facade that groups all LDIF model classes for the ``FlextLdifModels``
namespace.  Every nested class uses real MRO inheritance from its
internal ``models`` definition — no ``TypeAlias`` for classes.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Annotated, ClassVar

from flext_cli import FlextCliModels

from flext_core import FlextUtilities as u
from flext_ldif import t
from flext_ldif._models import (
    FlextLdifModelsBases,
    FlextLdifModelsCollections,
    FlextLdifModelsDomainEntry,
    FlextLdifModelsDomainEntryChangeOperationValue,
    FlextLdifModelsDomainEntryControl,
    FlextLdifModelsDomainEntryStatistics,
    FlextLdifModelsDomainsEntries,
    FlextLdifModelsEvents,
    FlextLdifModelsProcessing,
    FlextLdifModelsResults,
    FlextLdifModelsSettings,
    FlextLdifNamespace,
)


class FlextLdifModels(FlextCliModels):
    """LDIF domain models — flat façade with MRO class inheritance.

    Architecture: Domain layer helper
    All nested classes inherit via MRO from their ``models`` implementations.
    Types live in ``typings.py``, constants in ``constants.py``.
    """

    # ENFORCE-042: FlextLdifModelsSettings carries FlextSettings.model_config
    # typed as pydantic_settings.SettingsConfigDict (a distinct TypedDict from
    # flext-core's ConfigDict). mypy flags the cross-TypedDict override as
    # [misc]; the class is a namespace holder never instantiated, so only one
    # model_config resolves at runtime via the MRO — no behavioral conflict.
    class Ldif(
        FlextLdifModelsDomainsEntries,
        FlextLdifModelsDomainEntry,
        FlextLdifModelsSettings,
        FlextLdifModelsEvents,
        FlextLdifModelsResults,
        FlextLdifModelsCollections,
        FlextLdifModelsProcessing,
        FlextLdifModelsBases,
        FlextLdifModelsDomainEntryChangeOperationValue,
        FlextLdifModelsDomainEntryControl,
        FlextLdifModelsDomainEntryStatistics,
        FlextLdifNamespace,
    ):
        """LDIF namespace for cross-project access."""

        # =================================================================
        # COMPOSITE MODELS — defined here, not in models
        # =================================================================

        class Stats(FlextCliModels.BaseModel):
            """Write statistics for batch content operations."""

            model_config: ClassVar[FlextCliModels.ConfigDict] = (
                FlextCliModels.ConfigDict(validate_default=True)
            )
            total_entries: Annotated[t.NonNegativeInt, u.Field()] = 0
            successful: Annotated[t.NonNegativeInt, u.Field()] = 0
            failed: Annotated[t.NonNegativeInt, u.Field()] = 0

        class OidAclMetadataConfig(FlextCliModels.BaseModel):
            """Configuration model for OID ACL metadata parsing."""

            acl_line: Annotated[str, u.Field()] = ""
            oid_subject_type: Annotated[str, u.Field()] = ""
            rfc_subject_type: Annotated[str, u.Field()] = ""
            oid_subject_value: Annotated[str, u.Field()] = ""
            perms_dict: Annotated[t.MutableBoolMapping, u.Field()] = u.Field(
                default_factory=dict[str, bool],
            )
            target_dn: Annotated[str, u.Field()] = "entry"
            target_attrs: t.MutableSequenceOf[str] = u.Field(default_factory=list[str])
            acl_filter: Annotated[str, u.Field()] = ""
            acl_constraint: Annotated[str, u.Field()] = ""
            bindmode: Annotated[str, u.Field()] = ""
            deny_group_override: Annotated[bool, u.Field()] = False
            append_to_all: Annotated[bool, u.Field()] = False
            bind_ip_filter: Annotated[str, u.Field()] = ""
            constrain_to_added_object: Annotated[str, u.Field()] = ""

    # Top-level facade aliases: the api-freeze contract requires
    # ``flext_ldif.m.X`` and ``flext_ldif.FlextLdifModels.X`` to be the same
    # object for every published model.
    type Entry = Ldif.Entry


m = FlextLdifModels

__all__: list[str] = ["FlextLdifModels", "m"]
