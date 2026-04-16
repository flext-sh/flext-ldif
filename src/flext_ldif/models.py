"""LDIF Domain Models - Unified Model Aggregation Layer.

Facade that groups all LDIF model classes for the ``FlextLdifModels``
namespace.  Every nested class uses real MRO inheritance from its
internal ``_models`` definition — no ``TypeAlias`` for classes.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import MutableSequence
from typing import Annotated, ClassVar

from pydantic import ConfigDict

from flext_cli import FlextCliModels
from flext_ldif import (
    FlextLdifModelsBases,
    FlextLdifModelsCollections,
    FlextLdifModelsDomainsEntries,
    FlextLdifModelsEvents,
    FlextLdifModelsMetadata,
    FlextLdifModelsProcessing,
    FlextLdifModelsResults,
    FlextLdifModelsSettings,
    m,
    t,
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

        class Stats(m.BaseModel):
            """Write statistics for batch content operations."""

            model_config: ClassVar[ConfigDict] = ConfigDict(validate_default=True)
            total_entries: Annotated[t.NonNegativeInt, m.Field()] = 0
            successful: Annotated[t.NonNegativeInt, m.Field()] = 0
            failed: Annotated[t.NonNegativeInt, m.Field()] = 0

        class OidAclMetadataConfig(m.BaseModel):
            """Configuration model for OID ACL metadata parsing."""

            acl_line: Annotated[str, m.Field()] = ""
            oid_subject_type: Annotated[str, m.Field()] = ""
            rfc_subject_type: Annotated[str, m.Field()] = ""
            oid_subject_value: Annotated[str, m.Field()] = ""
            perms_dict: Annotated[
                t.MutableBoolMapping,
                m.Field(),
            ] = m.Field(default_factory=dict)
            target_dn: Annotated[str, m.Field()] = "entry"
            target_attrs: MutableSequence[str] = m.Field(default_factory=list)
            acl_filter: Annotated[str, m.Field()] = ""
            acl_constraint: Annotated[str, m.Field()] = ""
            bindmode: Annotated[str, m.Field()] = ""
            deny_group_override: Annotated[bool, m.Field()] = False
            append_to_all: Annotated[bool, m.Field()] = False
            bind_ip_filter: Annotated[str, m.Field()] = ""
            constrain_to_added_object: Annotated[str, m.Field()] = ""


__all__: list[str] = ["FlextLdifModels", "m"]

m = FlextLdifModels
