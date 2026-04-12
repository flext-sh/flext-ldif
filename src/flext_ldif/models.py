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

from pydantic import BaseModel, ConfigDict, Field

from flext_core import FlextModels
from flext_ldif import (
    FlextLdifModelsBases,
    FlextLdifModelsCollections,
    FlextLdifModelsDomainsEntries,
    FlextLdifModelsEvents,
    FlextLdifModelsMetadata,
    FlextLdifModelsProcessing,
    FlextLdifModelsResults,
    FlextLdifModelsSettings,
    t,
)


class FlextLdifModels(FlextModels):
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

        class Stats(BaseModel):
            """Write statistics for batch content operations."""

            model_config: ClassVar[ConfigDict] = ConfigDict(validate_default=True)
            total_entries: Annotated[t.NonNegativeInt, Field()] = 0
            successful: Annotated[t.NonNegativeInt, Field()] = 0
            failed: Annotated[t.NonNegativeInt, Field()] = 0

        class OidAclMetadataConfig(BaseModel):
            """Configuration model for OID ACL metadata parsing."""

            acl_line: Annotated[str, Field()] = ""
            oid_subject_type: Annotated[str, Field()] = ""
            rfc_subject_type: Annotated[str, Field()] = ""
            oid_subject_value: Annotated[str, Field()] = ""
            perms_dict: Annotated[
                t.MutableBoolMapping,
                Field(),
            ] = Field(default_factory=dict)
            target_dn: Annotated[str, Field()] = "entry"
            target_attrs: MutableSequence[str] = Field(default_factory=list)
            acl_filter: Annotated[str, Field()] = ""
            acl_constraint: Annotated[str, Field()] = ""
            bindmode: Annotated[str, Field()] = ""
            deny_group_override: Annotated[bool, Field()] = False
            append_to_all: Annotated[bool, Field()] = False
            bind_ip_filter: Annotated[str, Field()] = ""
            constrain_to_added_object: Annotated[str, Field()] = ""


__all__: list[str] = ["FlextLdifModels", "m"]

m = FlextLdifModels
