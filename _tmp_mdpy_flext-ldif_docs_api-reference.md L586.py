# from flext-ldif/docs/api-reference.md:586
from __future__ import annotations


from flext_ldif import m, t


class Factory:
    """Factory for creating LDIF domain objects."""

    @staticmethod
    def create(
        data: m.Dict | str, attributes: t.MappingKV[str, t.StringList] | None = None
    ) -> Entry:
        """Create LDIF entry with validation."""

    @staticmethod
    def create_config(**kwargs) -> Config:
        """Create configuration with validation."""

    @staticmethod
    def create_person_entry(dn: str, cn: str, sn: str, **additional_attrs) -> Entry:
        """Create person entry with common attributes."""

    @staticmethod
    def create_group_entry(
        dn: str, cn: str, members: t.StringList, **additional_attrs
    ) -> Entry:
        """Create group entry with members."""```
**Example Usage**:

