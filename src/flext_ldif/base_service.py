"""FLEXT LDIF Base Service - Common functionality for all LDIF services.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import time
from abc import abstractmethod

from flext_core import FlextDomainService, FlextLogger, FlextResult
from flext_ldif.config import FlextLdifConfig
from flext_ldif.constants import FlextLdifConstants


class FlextLdifBaseService(FlextDomainService[object]):
    """Base service with common functionality for all LDIF services.

    Provides shared implementations for:
    - Success rate calculation
    - Operation tracking
    - Performance metrics
    - Configuration management
    """

    def __init__(self, service_name: str, config: FlextLdifConfig | None = None) -> None:
        """Initialize base service with common attributes.

        Args:
            service_name: Name of the specific service
            config: Optional configuration instance

        """
        super().__init__()
        self._service_name = service_name
        self._logger = FlextLogger(__name__)

        # Configuration
        if config is None:
            try:
                self._config = FlextLdifConfig.get_global_ldif_config()
            except RuntimeError:
                self._config = FlextLdifConfig()
        else:
            self._config = config

        # Common metrics
        self._start_time = time.time()
        self._total_operations = 0
        self._operation_failures = 0
        self._operation_times: list[float] = []

    def _calculate_success_rate(self) -> float:
        """Calculate operation success rate.

        Returns:
            Success rate as a float between 0.0 and 1.0

        """
        if self._total_operations == 0:
            return 1.0
        return max(
            0.0,
            (self._total_operations - self._operation_failures) / self._total_operations
        )

    def _record_operation_success(self, operation_time: float) -> None:
        """Record successful operation metrics.

        Args:
            operation_time: Time taken for the operation in seconds

        """
        self._total_operations += 1
        self._operation_times.append(operation_time)

        # Keep operation times list manageable
        if len(self._operation_times) > FlextLdifConstants.MAX_CACHE_ENTRIES:
            self._operation_times = self._operation_times[
                -FlextLdifConstants.MANAGEABLE_CACHE_SIZE:
            ]

    def _record_operation_failure(self, failure_type: str) -> None:
        """Record operation failure with categorization.

        Args:
            failure_type: Type of failure for logging

        """
        self._operation_failures += 1
        self._total_operations += 1

        self._logger.warning(
            f"{self._service_name} operation failure",
            extra={"failure_type": failure_type},
        )

    def get_config_info(self) -> dict[str, object]:
        """Get service configuration information.

        Returns:
            Dictionary containing configuration details

        """
        return {
            "service": self._service_name,
            "config": {
                "service_type": self._service_name.lower().replace("flextldif", "").replace("service", ""),
                "status": "ready",
            },
        }

    def get_service_metrics(self) -> dict[str, object]:
        """Get service performance metrics.

        Returns:
            Dictionary containing performance metrics

        """
        uptime = time.time() - self._start_time
        avg_operation_time = (
            sum(self._operation_times) / len(self._operation_times)
            if self._operation_times
            else 0
        )

        return {
            "uptime_seconds": uptime,
            "total_operations": self._total_operations,
            "operation_failures": self._operation_failures,
            "success_rate": self._calculate_success_rate(),
            "avg_operation_time_seconds": avg_operation_time,
            "throughput_operations_per_second": (
                self._total_operations / uptime if uptime > 0 else 0
            ),
        }

    @abstractmethod
    def execute(self) -> FlextResult[object]:
        """Execute service operation.

        Must be implemented by each specific service.

        Returns:
            FlextResult containing operation result

        """
        msg = "Each service must implement execute method"
        raise NotImplementedError(msg)


__all__ = ["FlextLdifBaseService"]
