# from flext-ldif_docs/api-reference.md:1089
from __future__ import annotations


class Result:
    def __init__(self, success: bool, value=None) -> None:
        self.success = success
        self._value = value

    def unwrap(self):
        return self._value


class LdifApi:
    pass


class BoundService:
    pass


class FlextContainer:
    @staticmethod
    def get_global() -> FlextContainer:
        return FlextContainer()

    def bind(self, name: str, obj: BoundService) -> Result:
        return Result(True, obj)

    def resolve(self, name: str) -> Result:
        return Result(True, LdifApi())


def ldif() -> LdifApi:
    return LdifApi()


# Access global container
container = FlextContainer.get_global()

# Register LDIF API as service
api = ldif()
register_result = container.bind("ldif_api", api)

# Retrieve from container in other services
api_result = container.resolve("ldif_api")
if api_result.success:
    ldif_api = api_result.unwrap()```
### FlextLogger Integration

