"""RFC validation services."""

from __future__ import annotations

import struct
from collections.abc import Mapping
from typing import Self, override

from flext_core import d, r, t
from pydantic import Field

from flext_ldif import FlextLdifServiceBase, c, m
from flext_ldif._utilities.validation import FlextLdifUtilitiesValidation


class FlextLdifValidation(
    FlextLdifServiceBase[m.Ldif.ValidationServiceStatus],
):
    """FlextLdifValidation class."""

    attribute_names: list[str] = Field(default_factory=list)
    objectclass_names: list[str] = Field(default_factory=list)
    max_attr_value_length: int | None = Field(default=None)

    @override
    @d.track_operation("validation_service_check")
    def execute(
        self,
    ) -> r[m.Ldif.ValidationServiceStatus]:
        return r[m.Ldif.ValidationServiceStatus].ok(
            m.Ldif.ValidationServiceStatus(
                service="ValidationService",
                status="operational",
                rfc_compliance="RFC 2849, RFC 4512",
                validation_types=[
                    "attribute_name",
                    "objectclass_name",
                    "attribute_value",
                ],
            ),
        )

    @classmethod
    def builder(cls) -> Self:
        """Builder method."""
        return cls()

    def with_attribute_names(self, names: list[str]) -> Self:
        """With_attribute_names method."""
        return self.model_copy(update={"attribute_names": names})

    def with_objectclass_names(self, names: list[str]) -> Self:
        """With_objectclass_names method."""
        return self.model_copy(update={"objectclass_names": names})

    def with_max_attr_value_length(self, length: int) -> Self:
        """With_max_attr_value_length method."""
        return self.model_copy(update={"max_attr_value_length": length})

    @d.track_operation()
    def build(self) -> m.Ldif.ValidationBatchResult:
        """Build method."""
        result: dict[str, bool] = {}

        if self.attribute_names:
            attr_result = self.validate_attribute_names(self.attribute_names)
            if attr_result.is_success:
                result.update(attr_result.value)

        for name in self.objectclass_names:
            obj_result = self.validate_objectclass_name(name)
            if obj_result.is_success:
                result[name] = obj_result.value

        results_flags = m.Ldif.BooleanFlags(**result)
        return m.Ldif.ValidationBatchResult(results=results_flags)

    def validate_attribute_name(self, name: str) -> r[bool]:
        """Validate_attribute_name method."""
        try:
            return r[bool].ok(
                FlextLdifUtilitiesValidation.Rfc.is_valid_rfc4512_descriptor(name),
            )
        except (
            ValueError,
            KeyError,
            AttributeError,
            UnicodeDecodeError,
            struct.error,
        ) as e:
            return r[bool].fail(f"Failed to validate attribute name: {e}")

    def validate_objectclass_name(self, name: str) -> r[bool]:
        """Validate_objectclass_name method."""
        return self.validate_attribute_name(name)

    def validate_attribute_value(
        self,
        value: str,
        max_length: int | None = None,
    ) -> r[bool]:
        """Validate_attribute_value method."""
        try:
            if not value:
                return r[bool].ok(value=True)

            max_len = (
                max_length
                if max_length is not None
                else c.Ldif.ValidationRules.DEFAULT_MAX_ATTR_VALUE_LENGTH
            )
            if len(value) > max_len:
                return r[bool].ok(False)

            return r[bool].ok(
                FlextLdifUtilitiesValidation.Rfc.is_valid_rfc2849_attribute_value(
                    value,
                ),
            )
        except (ValueError, TypeError, AttributeError) as e:
            return r[bool].fail(f"Failed to validate attribute value: {e}")

    def validate_dn_component(
        self,
        attr: str,
        value: t.Scalar,
    ) -> r[bool]:
        """Validate_dn_component method."""
        try:
            if not isinstance(value, str):
                return r[bool].ok(False)
            if not FlextLdifUtilitiesValidation.Rfc.is_valid_rfc4512_descriptor(attr):
                return r[bool].ok(False)
            dn_value = value.replace(",", r"\,")
            return r[bool].ok(
                FlextLdifUtilitiesValidation.Rfc.is_valid_rfc4514_dn_component(
                    attr,
                    dn_value,
                ),
            )
        except (ValueError, TypeError, AttributeError) as e:
            return r[bool].fail(f"Failed to validate DN component: {e}")

    def validate_attribute_names(
        self,
        names: list[str],
    ) -> r[Mapping[str, bool]]:
        """Validate_attribute_names method."""
        try:
            validated_names: dict[str, bool] = {}

            for name in names:
                result = self.validate_attribute_name(name)
                if result.is_success:
                    validated_names[name] = result.value
                else:
                    validated_names[name] = False

            return r[dict[str, bool]].ok(validated_names)
        except (ValueError, TypeError, AttributeError) as e:
            return r[dict[str, bool]].fail(
                f"Failed to batch validate attribute names: {e}",
            )


__all__ = ["FlextLdifValidation"]
