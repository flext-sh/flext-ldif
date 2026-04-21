"""LDIF Domain Models - Unified Model Aggregation Layer.

Facade that groups all LDIF model classes for the ``FlextLdifModels``
namespace.  Every nested class uses real MRO inheritance from its
internal ``_models`` definition — no ``TypeAlias`` for classes.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import (
    MutableSequence,
)
from typing import Annotated, ClassVar

from flext_cli import FlextCliModels, t, u

from flext_ldif import (
    FlextLdifModelsBases,
    FlextLdifModelsCollections,
    FlextLdifModelsDomainsEntries,
    FlextLdifModelsEvents,
    FlextLdifModelsMetadata,
    FlextLdifModelsProcessing,
    FlextLdifModelsResults,
    FlextLdifModelsSettings,
)


class FlextLdifModels(FlextCliModels):
    """LDIF domain models — flat façade with MRO class inheritance.

    Architecture: Domain layer helper
    All nested classes inherit via MRO from their ``_models`` implementations.
    Types live in ``typings.py``, constants in ``constants.py``.
    """

    class Ldif(
        FlextLdifModelsDomainsEntries,
        FlextLdifModelsMetadata,
        FlextLdifModelsSettings,
        FlextLdifModelsEvents,
        FlextLdifModelsResults,
        FlextLdifModelsCollections,
        FlextLdifModelsProcessing,
        FlextLdifModelsBases,
    ):
        """LDIF namespace for cross-project access."""

        # =================================================================
        # COMPOSITE MODELS — defined here, not in _models
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
            perms_dict: Annotated[
                t.MutableBoolMapping,
                u.Field(),
            ] = u.Field(default_factory=dict)
            target_dn: Annotated[str, u.Field()] = "entry"
            target_attrs: MutableSequence[str] = u.Field(default_factory=list)
            acl_filter: Annotated[str, u.Field()] = ""
            acl_constraint: Annotated[str, u.Field()] = ""
            bindmode: Annotated[str, u.Field()] = ""
            deny_group_override: Annotated[bool, u.Field()] = False
            append_to_all: Annotated[bool, u.Field()] = False
            bind_ip_filter: Annotated[str, u.Field()] = ""
            constrain_to_added_object: Annotated[str, u.Field()] = ""


m = FlextLdifModels

__all__: list[str] = ["FlextLdifModels", "m"]
