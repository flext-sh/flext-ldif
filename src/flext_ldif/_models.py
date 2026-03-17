"""Auto-generated centralized models."""

from __future__ import annotations

from pydantic import BaseModel, RootModel


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
        _Scalar | list[_RecursiveMetadata] | Mapping[str, _RecursiveMetadata] | datetime
    ]
):
    pass


class _RecursiveContainer(
    RootModel[
        _Scalar
        | BaseModel
        | list[_RecursiveContainer]
        | Mapping[str, _RecursiveContainer]
        | datetime
    ]
):
    pass
