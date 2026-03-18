"""Auto-generated centralized models."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime

from pydantic import BaseModel, RootModel

from flext_ldif.typings import t as ldif_t


class FlextAutoConstants:
    pass


class FlextAutoTypes:
    pass


class FlextAutoProtocols:
    pass


class FlextAutoUtilities:
    pass


class FlextAutoModels:
    pass


c = FlextAutoConstants
t = FlextAutoTypes
p = FlextAutoProtocols
u = FlextAutoUtilities
m = FlextAutoModels


class _RecursiveMetadata(
    RootModel[
        ldif_t.Scalar | list[ldif_t.Scalar] | Mapping[str, ldif_t.Scalar] | datetime
    ],
):
    pass


class _RecursiveContainer(
    RootModel[
        ldif_t.Scalar
        | BaseModel
        | list[ldif_t.Scalar]
        | Mapping[str, ldif_t.Scalar]
        | datetime
    ],
):
    pass
