"""LDIF Validation Service - RFC 2849/4512 Compliant Entry Validation."""

from __future__ import annotations

from typing import Self, override

from flext_core import d, r, t
from pydantic import Field

from flext_ldif._models.results import _BooleanFlags
from flext_ldif._utilities.attribute import FlextLdifUtilitiesAttribute
from flext_ldif.base import FlextLdifServiceBase
from flext_ldif.constants import c
from flext_ldif.models import m


class FlextLdifValidation(
    FlextLdifServiceBase[m.Ldif.LdifResults.ValidationServiceStatus],
):
    """RFC 2849/4512 Compliant LDIF Validation Service."""

    attribute_names: list[str] = Field(default_factory=list)
    objectclass_names: list[str] = Field(default_factory=list)
    max_attr_value_length: int | None = Field(default=None)

    @override
    @d.log_operation("validation_service_check")
    @d.track_performance()
    def execute(
        self,
    ) -> r[m.Ldif.LdifResults.ValidationServiceStatus]:
        """Execute validation service self-check."""
        return r[m.Ldif.LdifResults.ValidationServiceStatus].ok(
            m.Ldif.LdifResults.ValidationServiceStatus(
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
        """Create fluent builder for complex validation workflows."""
        return cls()

    def with_attribute_names(self, names: list[str]) -> Self:
        """Set attribute names to validate (fluent builder)."""
        return self.model_copy(update={"attribute_names": names})

    def with_objectclass_names(self, names: list[str]) -> Self:
        """Set objectClass names to validate (fluent builder)."""
        return self.model_copy(update={"objectclass_names": names})

    def with_max_attr_value_length(self, length: int) -> Self:
        """Set maximum attribute value length (fluent builder)."""
        return self.model_copy(update={"max_attr_value_length": length})

    @d.track_performance()
    def build(self) -> m.Ldif.ValidationBatchResult:
        """Execute validation and return unwrapped result (fluent terminal)."""
        result: dict[str, bool] = {}

        if self.attribute_names:
            attr_result = self.validate_attribute_names(self.attribute_names)
            if attr_result.is_success:
                result.update(attr_result.value)

        for name in self.objectclass_names:
            obj_result = self.validate_objectclass_name(name)
            if obj_result.is_success:
                result[name] = obj_result.value

        results_flags = _BooleanFlags(**result)
        return m.Ldif.ValidationBatchResult(results=results_flags)

    def validate_attribute_name(self, name: str) -> r[bool]:
        """Validate LDAP attribute name against RFC 4512 rules."""
        try:
            is_valid = FlextLdifUtilitiesAttribute.validate_attribute_name(name)
            return r[bool].ok(is_valid)

        except Exception as e:
            return r[bool].fail(f"Failed to validate attribute name: {e}")

    def validate_objectclass_name(self, name: str) -> r[bool]:
        """Validate LDAP object class name against RFC 4512 rules."""
        return self.validate_attribute_name(name)

    def validate_attribute_value(
        self,
        value: str,
        max_length: int | None = None,
    ) -> r[bool]:
        """Validate LDAP attribute value length and format."""
        try:
            if not value:
                return r[bool].ok(True)

            max_len = (
                max_length
                if max_length is not None
                else c.Ldif.ValidationRules.DEFAULT_MAX_ATTR_VALUE_LENGTH
            )
            if len(value) > max_len:
                return r[bool].ok(False)

            return r[bool].ok(True)

        except (ValueError, TypeError, AttributeError) as e:
            return r[bool].fail(f"Failed to validate attribute value: {e}")

    def validate_dn_component(
        self,
        attr: str,
        value: t.ScalarValue,
    ) -> r[bool]:
        """Validate DN component (attribute=value pair)."""
        try:
            attr_result = self.validate_attribute_name(attr)
            if attr_result.is_failure or not attr_result.value:
                return r[bool].ok(False)

            if not isinstance(value, str):
                return r[bool].ok(False)

            return r[bool].ok(True)

        except (ValueError, TypeError, AttributeError) as e:
            return r[bool].fail(f"Failed to validate DN component: {e}")

    def validate_attribute_names(
        self,
        names: list[str],
    ) -> r[dict[str, bool]]:
        """Batch validate multiple attribute names."""
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
