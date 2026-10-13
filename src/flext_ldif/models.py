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
from flext_ldif._models._base_parts import FlextLdifModelsBasesParts
from flext_ldif._models.acl_convert import FlextLdifModelsAclConvert
from flext_ldif._models.base import FlextLdifModelsBases
from flext_ldif._models.collections import FlextLdifModelsCollections
from flext_ldif._models.config import FlextLdifNamespace
from flext_ldif._models.domain_acl import FlextLdifModelsDomainAcl
from flext_ldif._models.domain_attributes import FlextLdifModelsDomainAttributes
from flext_ldif._models.domain_dn import FlextLdifModelsDomainDN
from flext_ldif._models.domain_entries import FlextLdifModelsDomainsEntries
from flext_ldif._models.domain_entry import FlextLdifModelsDomainEntry
from flext_ldif._models.domain_entry_change import (
    FlextLdifModelsDomainEntryChangeOperation,
)
from flext_ldif._models.domain_entry_change_value import (
    FlextLdifModelsDomainEntryChangeOperationValue,
)
from flext_ldif._models.domain_entry_control import FlextLdifModelsDomainEntryControl
from flext_ldif._models.domain_entry_statistics import (
    FlextLdifModelsDomainEntryStatistics,
)
from flext_ldif._models.domain_metadata import FlextLdifModelsDomainMetadata
from flext_ldif._models.domain_schema import FlextLdifModelsDomainSchema
from flext_ldif._models.events import FlextLdifModelsEvents
from flext_ldif._models.processing import FlextLdifModelsProcessing
from flext_ldif._models.results import FlextLdifModelsResults
from flext_ldif._models.results_statistics import FlextLdifModelsResultsStatistics
from flext_ldif._models.settings import FlextLdifModelsSettings


class FlextLdifModels(FlextCliModels):
    """LDIF domain models — flat façade with MRO class inheritance.

    Architecture: Domain layer helper
    All nested classes inherit via MRO from their ``models`` implementations.
    Types live in ``typings.py``, constants in ``constants.py``.
    """

    # The composite namespace carries only ``m.BaseModel`` descendants whose
    # ``model_config`` is the models-facade ``ConfigDict``; the settings-derived
    # and value/control model classes stay reachable through their owning
    # aliases (``Ldif.Control`` / ``Ldif.ChangeOperationValue``) instead of
    # direct inheritance, which would clash on ``model_config``/``value``.
    class Ldif(
        FlextLdifModelsBases,
        FlextLdifModelsBasesParts,
        FlextLdifModelsCollections,
        FlextLdifNamespace,
        FlextLdifModelsDomainsEntries,
        FlextLdifModelsDomainEntry,
        FlextLdifModelsDomainEntryChangeOperation,
        FlextLdifModelsDomainMetadata,
        FlextLdifModelsAclConvert,
        FlextLdifModelsDomainAcl,
        FlextLdifModelsDomainAttributes,
        FlextLdifModelsDomainSchema,
        FlextLdifModelsDomainDN,
        FlextLdifModelsDomainEntryChangeOperationValue,
        FlextLdifModelsDomainEntryControl,
        FlextLdifModelsDomainEntryStatistics,
        FlextLdifModelsEvents,
        FlextLdifModelsProcessing,
        FlextLdifModelsResults,
        FlextLdifModelsResultsStatistics,
        FlextLdifModelsSettings,
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
