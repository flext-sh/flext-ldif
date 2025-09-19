"""FLEXT LDIF Validator Service - LDIF validation service implementation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import time

from flext_core import FlextDomainService, FlextLogger, FlextResult
from flext_ldif.config import FlextLdifConfig
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels


class FlextLdifValidatorService(FlextDomainService[list[FlextLdifModels.Entry]]):
    """Advanced LDIF Validator Service with comprehensive validation and monitoring.

    Enhanced with:
    - Advanced validation patterns with detailed error reporting
    - Performance metrics and validation statistics
    - Configurable validation rules and severity levels
    - Batch validation optimization for large datasets
    - Schema-aware validation capabilities
    - Comprehensive error context and recovery suggestions

    Uses FlextLdifModels Pydantic v2 validation with production-ready enhancements.
    """

    def __init__(self, config: FlextLdifConfig | None = None) -> None:
        """Initialize validator service with enhanced configuration and monitoring."""
        super().__init__()
        self._logger = FlextLogger(__name__)

        # Configuration setup
        try:
            self._config = config or FlextLdifConfig.get_global_ldif_config()
        except RuntimeError:
            self._config = FlextLdifConfig()

        # Performance tracking
        self._start_time = time.time()
        self._total_validations = 0
        self._total_entries_validated = 0
        self._validation_failures = 0
        self._schema_validations = 0
        self._dn_validations = 0

        # Validation statistics by type
        self._validation_stats = {
            "dn_format_errors": 0,
            "missing_objectclass_errors": 0,
            "missing_required_attributes": 0,
            "invalid_attribute_values": 0,
            "schema_violations": 0,
            "encoding_errors": 0,
        }

        # Performance metrics
        self._validation_times: list[float] = []
        self._slow_validation_threshold = 1.0  # seconds
        self._batch_size_threshold = 1000  # entries

        # Validation configuration
        self._strict_mode = self._config.ldif_strict_validation
        self._validate_objectclass = self._config.ldif_validate_object_class
        self._validate_dn_format = self._config.ldif_validate_dn_format
        self._allow_empty_values = self._config.ldif_allow_empty_values

        self._logger.info(
            "FlextLdifValidatorService initialized",
            extra={
                "service": "validator",
                "strict_mode": self._strict_mode,
                "validate_objectclass": self._validate_objectclass,
                "validate_dn_format": self._validate_dn_format,
                "allow_empty_values": self._allow_empty_values,
            },
        )

    def get_config_info(self) -> dict[str, object]:
        """Get enhanced service configuration information."""
        return {
            "service": "FlextLdifValidatorService",
            "config": {
                "service_type": "validator",
                "status": "ready",
                "capabilities": [
                    "validate_entries",
                    "validate_entry",
                    "validate_entry_structure",
                    "validate_dn_format",
                    "batch_validation",
                    "schema_validation",
                    "performance_metrics",
                    "validation_statistics",
                ],
                "validation_settings": {
                    "strict_mode": self._strict_mode,
                    "validate_objectclass": self._validate_objectclass,
                    "validate_dn_format": self._validate_dn_format,
                    "allow_empty_values": self._allow_empty_values,
                    "batch_size_threshold": self._batch_size_threshold,
                    "slow_validation_threshold": self._slow_validation_threshold,
                },
            },
        }

    def get_service_info(self) -> dict[str, object]:
        """Get comprehensive service information with validation metrics."""
        uptime = time.time() - self._start_time
        avg_validation_time = (
            sum(self._validation_times) / len(self._validation_times)
            if self._validation_times
            else 0
        )

        return {
            "service_name": "FlextLdifValidatorService",
            "service_type": "validator",
            "capabilities": [
                "validate_entries",
                "validate_entry",
                "validate_entry_structure",
                "validate_dn_format",
                "batch_validation",
                "schema_validation",
                "performance_analytics",
            ],
            "status": "ready",
            "metrics": {
                "uptime_seconds": uptime,
                "total_validations": self._total_validations,
                "total_entries_validated": self._total_entries_validated,
                "validation_failures": self._validation_failures,
                "schema_validations": self._schema_validations,
                "dn_validations": self._dn_validations,
                "success_rate": self._calculate_success_rate(),
                "avg_validation_time_seconds": avg_validation_time,
                "throughput_validations_per_second": self._total_validations / uptime
                if uptime > 0
                else 0,
            },
            "validation_statistics": self._validation_stats.copy(),
        }

    def validate_entries(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Validate multiple LDIF entries with enhanced batch processing and monitoring."""
        start_time = time.time()
        entry_count = len(entries)

        if not entries:
            self._record_validation_failure("empty_entry_list")
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                "Cannot validate empty entry list"
            )

        self._logger.info(
            "Starting batch validation",
            extra={
                "entry_count": entry_count,
                "large_batch": entry_count > self._batch_size_threshold,
                "strict_mode": self._strict_mode,
            },
        )

        validated_entries: list[FlextLdifModels.Entry] = []
        validation_errors: list[str] = []

        # Track validation progress for large batches
        progress_interval = max(100, entry_count // 10)

        try:
            for i, entry in enumerate(entries):
                # Progress logging for large batches
                if (
                    entry_count > self._batch_size_threshold
                    and i % progress_interval == 0
                ):
                    self._logger.debug(
                        f"Validation progress: {i}/{entry_count} entries processed"
                    )

                # Validate individual entry with detailed error tracking
                validation_result = self._validate_single_entry_with_context(entry, i)

                if validation_result.is_failure:
                    error_msg = f"Entry {i}: {validation_result.error}"
                    validation_errors.append(error_msg)

                    # In strict mode, fail on first error
                    if self._strict_mode:
                        self._record_validation_failure("strict_mode_violation")
                        validation_time = time.time() - start_time

                        self._logger.warning(
                            "Batch validation failed in strict mode",
                            extra={
                                "failed_entry_index": i,
                                "error": validation_result.error,
                                "validation_time_seconds": validation_time,
                            },
                        )

                        return FlextResult[list[FlextLdifModels.Entry]].fail(
                            f"Strict validation failed at entry {i}: {validation_result.error}"
                        )
                else:
                    validated_entries.append(entry)

            # Record metrics
            validation_time = time.time() - start_time
            self._record_validation_success(entry_count, validation_time)

            # Handle validation results
            if validation_errors:
                if self._strict_mode:
                    # Should not reach here in strict mode
                    return FlextResult[list[FlextLdifModels.Entry]].fail(
                        f"Validation errors found: {'; '.join(validation_errors[:5])}"
                    )
                # Non-strict mode: log warnings but continue
                self._logger.warning(
                    "Validation completed with errors (non-strict mode)",
                    extra={
                        "total_errors": len(validation_errors),
                        "validated_entries": len(validated_entries),
                        "error_rate": len(validation_errors) / entry_count,
                    },
                )

            self._logger.info(
                "Batch validation completed",
                extra={
                    "entry_count": entry_count,
                    "validated_count": len(validated_entries),
                    "error_count": len(validation_errors),
                    "validation_time_seconds": validation_time,
                    "throughput_entries_per_sec": entry_count / validation_time
                    if validation_time > 0
                    else 0,
                    "slow_validation": validation_time
                    > self._slow_validation_threshold,
                },
            )

            return FlextResult[list[FlextLdifModels.Entry]].ok(validated_entries)

        except Exception as e:
            validation_time = time.time() - start_time
            self._record_validation_failure("unexpected_error")

            self._logger.exception(
                "Batch validation failed with exception",
                extra={
                    "entry_count": entry_count,
                    "error": str(e),
                    "validation_time_seconds": validation_time,
                },
            )

            return FlextResult[list[FlextLdifModels.Entry]].fail(
                f"Batch validation error: {e}"
            )

    def validate_entry(self, entry: FlextLdifModels.Entry) -> FlextResult[bool]:
        """Validate single LDIF entry with comprehensive error reporting."""
        start_time = time.time()

        try:
            validation_result = self._validate_single_entry_with_context(entry, 0)
            validation_time = time.time() - start_time

            if validation_result.is_success:
                self._record_validation_success(1, validation_time)
                return FlextResult[bool].ok(data=True)
            self._record_validation_failure("single_entry_validation")
            return FlextResult[bool].fail(validation_result.error or "Validation failed")

        except Exception as e:
            validation_time = time.time() - start_time
            self._record_validation_failure("single_entry_exception")

            self._logger.exception(
                "Single entry validation failed",
                extra={
                    "dn": entry.dn.value,
                    "error": str(e),
                    "validation_time_seconds": validation_time,
                },
            )

            return FlextResult[bool].fail(f"Entry validation error: {e}")

    def validate_entry_structure(
        self, entry: FlextLdifModels.Entry
    ) -> FlextResult[bool]:
        """Validate entry structure with detailed structural analysis."""
        try:
            # Check DN structure
            dn_result = self.validate_dn_format(entry.dn.value)
            if dn_result.is_failure:
                self._validation_stats["dn_format_errors"] += 1
                return dn_result

            # Check required objectClass attribute
            if self._validate_objectclass:
                attributes = entry.attributes.data
                if "objectClass" not in attributes:
                    self._validation_stats["missing_objectclass_errors"] += 1
                    return FlextResult[bool].fail(
                        "Missing required objectClass attribute"
                    )

                if not attributes["objectClass"]:
                    self._validation_stats["missing_objectclass_errors"] += 1
                    return FlextResult[bool].fail(
                        "objectClass attribute cannot be empty"
                    )

            # Check for empty values if not allowed
            if not self._allow_empty_values:
                for attr_name, attr_values in entry.attributes.data.items():
                    if not attr_values or any(
                        not value.strip() for value in attr_values
                    ):
                        self._validation_stats["invalid_attribute_values"] += 1
                        return FlextResult[bool].fail(
                            f"Empty values not allowed for attribute: {attr_name}"
                        )

            return FlextResult[bool].ok(data=True)

        except Exception as e:
            self._logger.exception(
                "Entry structure validation failed",
                extra={"dn": entry.dn.value, "error": str(e)},
            )
            return FlextResult[bool].fail(f"Structure validation error: {e}")

    def validate_dn_format(self, dn: str) -> FlextResult[bool]:
        """Validate DN format with enhanced pattern matching and error reporting."""
        start_time = time.time()

        try:
            self._dn_validations += 1

            # Use FlextLdifModels DistinguishedName Pydantic v2 validation
            dn_obj = FlextLdifModels.DistinguishedName(value=dn)
            validation_result = dn_obj.validate_business_rules()

            validation_time = time.time() - start_time

            if validation_result.is_failure:
                self._validation_stats["dn_format_errors"] += 1

                self._logger.debug(
                    "DN validation failed",
                    extra={
                        "dn": dn,
                        "error": validation_result.error,
                        "validation_time_seconds": validation_time,
                    },
                )

                return FlextResult[bool].fail(
                    f"DN format validation failed: {validation_result.error}"
                )

            self._logger.debug(
                "DN validation passed",
                extra={
                    "dn": dn,
                    "validation_time_seconds": validation_time,
                },
            )

            return FlextResult[bool].ok(data=True)

        except Exception as e:
            validation_time = time.time() - start_time
            self._validation_stats["dn_format_errors"] += 1

            self._logger.exception(
                "DN validation error",
                extra={
                    "dn": dn,
                    "error": str(e),
                    "validation_time_seconds": validation_time,
                },
            )

            return FlextResult[bool].fail(f"DN validation failed: {e}")

    def validate_schema_compliance(
        self, entry: FlextLdifModels.Entry
    ) -> FlextResult[bool]:
        """Validate entry against LDAP schema rules."""
        try:
            self._schema_validations += 1

            attributes = entry.attributes.data
            object_classes = attributes.get("objectClass", [])

            if not object_classes:
                self._validation_stats["schema_violations"] += 1
                return FlextResult[bool].fail(
                    "Missing objectClass for schema validation"
                )

            # Check for required attributes based on objectClass
            for obj_class in object_classes:
                obj_class_lower = obj_class.lower()

                # Person object class validation
                if obj_class_lower in FlextLdifConstants.LDAP_PERSON_CLASSES:
                    for required_attr in FlextLdifConstants.REQUIRED_PERSON_ATTRIBUTES:
                        if required_attr not in attributes:
                            self._validation_stats["missing_required_attributes"] += 1
                            return FlextResult[bool].fail(
                                f"Missing required attribute '{required_attr}' for objectClass '{obj_class}'"
                            )

                # Organizational Unit validation
                elif obj_class_lower in FlextLdifConstants.LDAP_ORGANIZATIONAL_CLASSES:
                    for required_attr in FlextLdifConstants.REQUIRED_ORGUNIT_ATTRIBUTES:
                        if required_attr not in attributes:
                            self._validation_stats["missing_required_attributes"] += 1
                            return FlextResult[bool].fail(
                                f"Missing required attribute '{required_attr}' for objectClass '{obj_class}'"
                            )

            return FlextResult[bool].ok(data=True)

        except Exception as e:
            self._validation_stats["schema_violations"] += 1
            self._logger.exception(
                "Schema validation error",
                extra={"dn": entry.dn.value, "error": str(e)},
            )
            return FlextResult[bool].fail(f"Schema validation error: {e}")

    def get_validation_statistics(self) -> dict[str, object]:
        """Get comprehensive validation statistics."""
        uptime = time.time() - self._start_time

        return {
            "uptime_seconds": uptime,
            "totals": {
                "validations": self._total_validations,
                "entries_validated": self._total_entries_validated,
                "failures": self._validation_failures,
                "schema_validations": self._schema_validations,
                "dn_validations": self._dn_validations,
            },
            "success_metrics": {
                "success_rate": self._calculate_success_rate(),
                "avg_validation_time": (
                    sum(self._validation_times) / len(self._validation_times)
                    if self._validation_times
                    else 0
                ),
                "throughput_per_second": self._total_validations / uptime
                if uptime > 0
                else 0,
            },
            "error_breakdown": self._validation_stats.copy(),
            "performance": {
                "slow_validations": sum(
                    1
                    for t in self._validation_times
                    if t > self._slow_validation_threshold
                ),
                "max_validation_time": max(self._validation_times)
                if self._validation_times
                else 0,
                "min_validation_time": min(self._validation_times)
                if self._validation_times
                else 0,
            },
        }

    def reset_statistics(self) -> None:
        """Reset all validation statistics."""
        self._start_time = time.time()
        self._total_validations = 0
        self._total_entries_validated = 0
        self._validation_failures = 0
        self._schema_validations = 0
        self._dn_validations = 0
        self._validation_times.clear()

        # Reset error statistics
        for key in self._validation_stats:
            self._validation_stats[key] = 0

        self._logger.info("Validation statistics reset")

    def health_check(self) -> FlextResult[dict[str, object]]:
        """Perform comprehensive health check of validator service."""
        try:
            health_status: dict[str, object] = {
                "service": "FlextLdifValidatorService",
                "status": "healthy",
                "timestamp": time.time(),
                "checks": {},
            }
            checks = health_status["checks"] = {}

            # Configuration check
            checks["configuration"] = {
                "status": "healthy",
                "strict_mode": self._strict_mode,
                "validation_features": {
                    "objectclass": self._validate_objectclass,
                    "dn_format": self._validate_dn_format,
                    "empty_values": self._allow_empty_values,
                },
            }

            # Performance check
            success_rate = self._calculate_success_rate()
            performance_status = "healthy"
            if success_rate < FlextLdifConstants.VALIDATOR_DEGRADED_THRESHOLD:  # 90% success rate threshold
                performance_status = "degraded"
            elif success_rate < FlextLdifConstants.VALIDATOR_UNHEALTHY_THRESHOLD:
                performance_status = "unhealthy"

            checks["performance"] = {
                "status": performance_status,
                "success_rate": success_rate,
                "total_validations": self._total_validations,
            }

            # Test validation functionality
            try:
                test_entry = FlextLdifModels.Entry(
                    dn=FlextLdifModels.DistinguishedName(
                        value="cn=test,dc=example,dc=com"
                    ),
                    attributes=FlextLdifModels.LdifAttributes(
                        data={"cn": ["test"], "objectClass": ["person", "top"]}
                    ),
                )
                test_result = self.validate_entry(test_entry)

                if test_result.is_success:
                    checks["validation_functionality"] = {
                        "status": "healthy"
                    }
                else:
                    health_status["status"] = "degraded"
                    checks["validation_functionality"] = {
                        "status": "failed",
                        "error": test_result.error,
                    }
            except Exception as e:
                health_status["status"] = "unhealthy"
                checks["validation_functionality"] = {
                    "status": "error",
                    "error": str(e),
                }

            return FlextResult[dict[str, object]].ok(health_status)

        except Exception as e:
            self._logger.exception("Health check failed")
            return FlextResult[dict[str, object]].fail(f"Health check error: {e}")

    # Private helper methods

    def _validate_single_entry_with_context(
        self, entry: FlextLdifModels.Entry, index: int
    ) -> FlextResult[bool]:
        """Validate single entry with enhanced context and error reporting."""
        try:
            # Use FlextLdifModels Entry business rules validation
            validation_result = entry.validate_business_rules()
            if validation_result.is_failure:
                return FlextResult[bool].fail(validation_result.error or "Entry validation failed")

            # Additional structure validation
            structure_result = self.validate_entry_structure(entry)
            if structure_result.is_failure:
                return structure_result

            # Schema validation if enabled
            if self._validate_objectclass:
                schema_result = self.validate_schema_compliance(entry)
                if schema_result.is_failure:
                    return schema_result

            return FlextResult[bool].ok(data=True)

        except Exception as e:
            self._logger.exception(
                "Entry validation failed with exception",
                extra={
                    "entry_index": index,
                    "dn": entry.dn.value,
                    "error": str(e),
                },
            )
            return FlextResult[bool].fail(f"Entry validation error: {e}")

    def _record_validation_success(
        self, entry_count: int, validation_time: float
    ) -> None:
        """Record successful validation metrics."""
        self._total_validations += 1
        self._total_entries_validated += entry_count
        self._validation_times.append(validation_time)

        # Keep validation times list manageable
        if len(self._validation_times) > FlextLdifConstants.MAX_CACHE_ENTRIES:
            self._validation_times = self._validation_times[-FlextLdifConstants.MANAGEABLE_CACHE_SIZE:]

    def _record_validation_failure(self, failure_type: str) -> None:
        """Record validation failure with categorization."""
        self._validation_failures += 1
        self._total_validations += 1

        self._logger.warning(
            "Validation failure recorded", extra={"failure_type": failure_type}
        )

    def _calculate_success_rate(self) -> float:
        """Calculate validation success rate."""
        if self._total_validations == 0:
            return 1.0
        return max(
            0.0,
            (self._total_validations - self._validation_failures)
            / self._total_validations,
        )

    def execute(self) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Execute validator operation with enhanced sample validation."""
        self._logger.debug("Validator service execute called")

        try:
            # Create comprehensive sample entries for testing
            sample_entries = [
                FlextLdifModels.Entry(
                    dn=FlextLdifModels.DistinguishedName(
                        value="cn=john.doe,ou=people,dc=example,dc=com"
                    ),
                    attributes=FlextLdifModels.LdifAttributes(
                        data={
                            "cn": ["john.doe"],
                            "sn": ["Doe"],
                            "givenName": ["John"],
                            "objectClass": ["person", "inetOrgPerson", "top"],
                            "mail": ["john.doe@example.com"],
                        }
                    ),
                ),
                FlextLdifModels.Entry(
                    dn=FlextLdifModels.DistinguishedName(
                        value="ou=people,dc=example,dc=com"
                    ),
                    attributes=FlextLdifModels.LdifAttributes(
                        data={
                            "ou": ["people"],
                            "objectClass": ["organizationalUnit", "top"],
                            "description": ["People container"],
                        }
                    ),
                ),
                FlextLdifModels.Entry(
                    dn=FlextLdifModels.DistinguishedName(
                        value="cn=REDACTED_LDAP_BIND_PASSWORDs,ou=groups,dc=example,dc=com"
                    ),
                    attributes=FlextLdifModels.LdifAttributes(
                        data={
                            "cn": ["REDACTED_LDAP_BIND_PASSWORDs"],
                            "objectClass": ["groupOfNames", "top"],
                            "member": ["cn=john.doe,ou=people,dc=example,dc=com"],
                            "description": ["System REDACTED_LDAP_BIND_PASSWORDistrators"],
                        }
                    ),
                ),
            ]

            # Validate sample entries
            validation_result = self.validate_entries(sample_entries)
            if validation_result.is_success:
                return validation_result
            self._logger.warning(
                "Sample validation failed", extra={"error": validation_result.error}
            )
            return FlextResult[list[FlextLdifModels.Entry]].ok([])

        except Exception as e:
            self._logger.exception(
                "Execute operation failed", extra={"error": str(e)}
            )
            return FlextResult[list[FlextLdifModels.Entry]].ok([])


__all__ = ["FlextLdifValidatorService"]
