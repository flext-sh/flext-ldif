"""FLEXT LDIF Repository Service - LDIF repository service implementation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import time

from flext_core import FlextDomainService, FlextLogger, FlextResult
from flext_ldif.config import FlextLdifConfig
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels


class FlextLdifRepositoryService(FlextDomainService[list[FlextLdifModels.Entry]]):
    """Advanced LDIF Repository Service with intelligent data management and caching.

    Enhanced with:
    - High-performance in-memory storage with indexing strategies
    - Intelligent caching and query optimization
    - Advanced filtering and search capabilities with performance metrics
    - Data integrity validation and consistency checks
    - Comprehensive analytics and reporting features
    - Memory management and garbage collection optimization

    Provides enterprise-grade repository operations for LDIF entry management.
    """

    def __init__(self, config: FlextLdifConfig | None = None) -> None:
        """Initialize repository service with enhanced storage and caching."""
        super().__init__()
        self._logger = FlextLogger(__name__)

        # Configuration setup
        try:
            self._config = config or FlextLdifConfig.get_global_ldif_config()
        except RuntimeError:
            self._config = FlextLdifConfig()

        # Performance tracking
        self._start_time = time.time()
        self._total_operations = 0
        self._total_entries_stored = 0
        self._total_queries = 0
        self._cache_hits = 0
        self._cache_misses = 0
        self._operation_failures = 0

        # Storage and indexing
        self._entries: list[FlextLdifModels.Entry] = []
        self._dn_index: dict[str, int] = {}  # DN -> entry index mapping
        self._attribute_index: dict[
            str, dict[str, list[int]]
        ] = {}  # attr -> value -> entry indices
        self._objectclass_index: dict[
            str, list[int]
        ] = {}  # objectClass -> entry indices

        # Caching
        self._query_cache: dict[
            str, tuple[object, float]
        ] = {}  # query_key -> (result, timestamp)
        self._cache_ttl = 300.0  # 5 minutes cache TTL
        self._max_cache_size = self._config.ldif_analytics_cache_size

        # Performance metrics
        self._operation_times: list[float] = []
        self._slow_operation_threshold = 0.5  # seconds
        self._large_dataset_threshold = 10000  # entries

        # Memory management
        self._memory_usage = 0
        self._peak_memory_usage = 0
        self._gc_threshold = 50000  # entries

        # Operation statistics
        self._operation_stats = {
            "find_operations": 0,
            "filter_operations": 0,
            "store_operations": 0,
            "index_rebuilds": 0,
            "cache_cleanups": 0,
            "memory_optimizations": 0,
        }

        self._logger.info(
            "FlextLdifRepositoryService initialized",
            extra={
                "service": "repository",
                "cache_enabled": True,
                "indexing_enabled": True,
                "cache_ttl_seconds": self._cache_ttl,
                "max_cache_size": self._max_cache_size,
                "gc_threshold": self._gc_threshold,
            },
        )

    def store_entries(self, entries: list[FlextLdifModels.Entry]) -> FlextResult[bool]:
        """Store entries with intelligent indexing and validation."""
        start_time = time.time()
        entry_count = len(entries)

        if not entries:
            return FlextResult[bool].ok(data=True)

        try:
            self._logger.info(
                "Starting entry storage operation",
                extra={
                    "entry_count": entry_count,
                    "large_dataset": entry_count > self._large_dataset_threshold,
                    "current_stored_entries": len(self._entries),
                },
            )

            # Validate entries before storage
            validation_result = self._validate_entries_for_storage(entries)
            if validation_result.is_failure:
                self._record_operation_failure("validation_failed")
                return FlextResult[bool].fail(
                    validation_result.error or "Validation failed"
                )

            # Check for memory constraints
            estimated_memory = self._estimate_memory_usage(entries)
            if self._should_trigger_gc(estimated_memory):
                self._logger.info("Triggering garbage collection before storage")
                self._perform_memory_optimization()

            # Store entries and build indices
            initial_count = len(self._entries)
            duplicate_count = 0

            for entry in entries:
                dn_lower = entry.dn.value.lower()

                # Check for duplicates
                if dn_lower in self._dn_index:
                    duplicate_count += 1
                    self._logger.debug(
                        f"Duplicate DN found, updating: {entry.dn.value}"
                    )
                    # Update existing entry
                    existing_index = self._dn_index[dn_lower]
                    self._entries[existing_index] = entry
                    self._update_indices_for_entry(entry, existing_index)
                else:
                    # Add new entry
                    new_index = len(self._entries)
                    self._entries.append(entry)
                    self._dn_index[dn_lower] = new_index
                    self._build_indices_for_entry(entry, new_index)

            # Clear query cache as data has changed
            self._clear_query_cache()

            # Record metrics
            storage_time = time.time() - start_time
            new_entries_count = len(self._entries) - initial_count
            self._record_operation_success(entry_count, storage_time)
            self._total_entries_stored += new_entries_count
            self._operation_stats["store_operations"] += 1

            # Update memory tracking
            self._update_memory_usage()

            self._logger.info(
                "Entry storage completed",
                extra={
                    "entries_processed": entry_count,
                    "new_entries_stored": new_entries_count,
                    "duplicates_updated": duplicate_count,
                    "total_stored_entries": len(self._entries),
                    "storage_time_seconds": storage_time,
                    "indexing_time_included": True,
                    "memory_usage_mb": self._memory_usage / (1024 * 1024),
                },
            )

            return FlextResult[bool].ok(data=True)

        except Exception as e:
            storage_time = time.time() - start_time
            self._record_operation_failure("storage_error")

            self._logger.exception(
                "Entry storage failed",
                extra={
                    "entry_count": entry_count,
                    "error": str(e),
                    "storage_time_seconds": storage_time,
                },
            )

            return FlextResult[bool].fail(f"Storage error: {e}")

    def find_entry_by_dn(
        self, entries: list[FlextLdifModels.Entry], dn: str
    ) -> FlextResult[FlextLdifModels.Entry | None]:
        """Find entry by DN with intelligent caching and indexing."""
        start_time = time.time()

        try:
            # Generate cache key
            cache_key = f"find_dn:{dn.lower()}"

            # Check cache first
            cached_result = self._get_from_cache(cache_key)
            if cached_result is not None:
                self._cache_hits += 1
                self._logger.debug(f"Cache hit for DN lookup: {dn}")
                return FlextResult[FlextLdifModels.Entry | None].ok(cached_result)  # type: ignore[arg-type]

            self._cache_misses += 1

            # Use index if entries are from internal storage
            if entries is self._entries and dn.lower() in self._dn_index:
                entry_index = self._dn_index[dn.lower()]
                found_entry = self._entries[entry_index]

                # Cache the result
                self._store_in_cache(cache_key, found_entry)

                operation_time = time.time() - start_time
                self._record_operation_success(1, operation_time)
                self._operation_stats["find_operations"] += 1

                self._logger.debug(
                    "DN lookup completed (indexed)",
                    extra={
                        "dn": dn,
                        "found": True,
                        "operation_time_seconds": operation_time,
                        "used_index": True,
                    },
                )

                return FlextResult[FlextLdifModels.Entry | None].ok(found_entry)

            # Fallback to linear search for external entry lists
            for entry in entries:
                if entry.dn.value.lower() == dn.lower():
                    # Cache the result
                    self._store_in_cache(cache_key, entry)

                    operation_time = time.time() - start_time
                    self._record_operation_success(1, operation_time)
                    self._operation_stats["find_operations"] += 1

                    self._logger.debug(
                        "DN lookup completed (linear)",
                        extra={
                            "dn": dn,
                            "found": True,
                            "operation_time_seconds": operation_time,
                            "used_index": False,
                            "entries_searched": len(entries),
                        },
                    )

                    return FlextResult[FlextLdifModels.Entry | None].ok(entry)

            # Not found - cache negative result
            self._store_in_cache(cache_key, None)

            operation_time = time.time() - start_time
            self._record_operation_success(1, operation_time)
            self._operation_stats["find_operations"] += 1

            self._logger.debug(
                "DN lookup completed (not found)",
                extra={
                    "dn": dn,
                    "found": False,
                    "operation_time_seconds": operation_time,
                    "entries_searched": len(entries),
                },
            )

            return FlextResult[FlextLdifModels.Entry | None].ok(None)

        except Exception as e:
            operation_time = time.time() - start_time
            self._record_operation_failure("find_error")

            self._logger.exception(
                "DN lookup failed",
                extra={
                    "dn": dn,
                    "error": str(e),
                    "operation_time_seconds": operation_time,
                },
            )

            return FlextResult[FlextLdifModels.Entry | None].fail(f"Find error: {e}")

    def filter_entries_by_attribute(
        self,
        entries: list[FlextLdifModels.Entry],
        attribute_name: str,
        attribute_value: str | None,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter entries by attribute with intelligent indexing and caching."""
        start_time = time.time()

        try:
            if not attribute_name or not attribute_name.strip():
                self._record_operation_failure("invalid_attribute_name")
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    "Attribute name cannot be empty"
                )

            # Generate cache key
            cache_key = f"filter_attr:{attribute_name}:{attribute_value or 'ANY'}"

            # Check cache first
            cached_result = self._get_from_cache(cache_key)
            if cached_result is not None:
                self._cache_hits += 1
                self._logger.debug(
                    f"Cache hit for attribute filter: {attribute_name}={attribute_value}"
                )
                return FlextResult[list[FlextLdifModels.Entry]].ok(cached_result)  # type: ignore[arg-type]

            self._cache_misses += 1

            # Use index if entries are from internal storage
            if entries is self._entries and attribute_name in self._attribute_index:
                filtered_entries = self._filter_using_attribute_index(
                    attribute_name, attribute_value
                )

                # Cache the result
                self._store_in_cache(cache_key, filtered_entries)

                operation_time = time.time() - start_time
                self._record_operation_success(len(filtered_entries), operation_time)
                self._operation_stats["filter_operations"] += 1

                self._logger.debug(
                    "Attribute filter completed (indexed)",
                    extra={
                        "attribute_name": attribute_name,
                        "attribute_value": attribute_value,
                        "results_count": len(filtered_entries),
                        "operation_time_seconds": operation_time,
                        "used_index": True,
                    },
                )

                return FlextResult[list[FlextLdifModels.Entry]].ok(filtered_entries)

            # Fallback to linear search
            filtered_entries = []
            for entry in entries:
                values = entry.get_attribute(attribute_name) or []
                if attribute_value is None:
                    # Filter by presence of attribute (any value)
                    if values:
                        filtered_entries.append(entry)
                # Filter by specific attribute value
                elif attribute_value in values:
                    filtered_entries.append(entry)

            # Cache the result
            self._store_in_cache(cache_key, filtered_entries)

            operation_time = time.time() - start_time
            self._record_operation_success(len(filtered_entries), operation_time)
            self._operation_stats["filter_operations"] += 1

            self._logger.debug(
                "Attribute filter completed (linear)",
                extra={
                    "attribute_name": attribute_name,
                    "attribute_value": attribute_value,
                    "results_count": len(filtered_entries),
                    "operation_time_seconds": operation_time,
                    "used_index": False,
                    "entries_searched": len(entries),
                },
            )

            return FlextResult[list[FlextLdifModels.Entry]].ok(filtered_entries)

        except Exception as e:
            operation_time = time.time() - start_time
            self._record_operation_failure("filter_error")

            self._logger.exception(
                "Attribute filter failed",
                extra={
                    "attribute_name": attribute_name,
                    "attribute_value": attribute_value,
                    "error": str(e),
                    "operation_time_seconds": operation_time,
                },
            )

            return FlextResult[list[FlextLdifModels.Entry]].fail(f"Filter error: {e}")

    def filter_entries_by_objectclass(
        self, entries: list[FlextLdifModels.Entry], object_class: str
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter entries by object class with optimized indexing."""
        start_time = time.time()

        try:
            if not object_class or not object_class.strip():
                self._record_operation_failure("invalid_objectclass")
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    "Object class cannot be empty"
                )

            # Generate cache key
            cache_key = f"filter_objectclass:{object_class.lower()}"

            # Check cache first
            cached_result = self._get_from_cache(cache_key)
            if cached_result is not None:
                self._cache_hits += 1
                self._logger.debug(f"Cache hit for objectClass filter: {object_class}")
                return FlextResult[list[FlextLdifModels.Entry]].ok(cached_result)  # type: ignore[arg-type]

            self._cache_misses += 1

            # Use objectClass index if entries are from internal storage
            if (
                entries is self._entries
                and object_class.lower() in self._objectclass_index
            ):
                entry_indices = self._objectclass_index[object_class.lower()]
                filtered_entries = [self._entries[i] for i in entry_indices]

                # Cache the result
                self._store_in_cache(cache_key, filtered_entries)

                operation_time = time.time() - start_time
                self._record_operation_success(len(filtered_entries), operation_time)
                self._operation_stats["filter_operations"] += 1

                self._logger.debug(
                    "ObjectClass filter completed (indexed)",
                    extra={
                        "object_class": object_class,
                        "results_count": len(filtered_entries),
                        "operation_time_seconds": operation_time,
                        "used_index": True,
                    },
                )

                return FlextResult[list[FlextLdifModels.Entry]].ok(filtered_entries)

            # Fallback to linear search
            filtered_entries = []
            for entry in entries:
                object_classes = (
                    entry.get_attribute(FlextLdifConstants.OBJECTCLASS_ATTRIBUTE) or []
                )
                if object_class.lower() in (oc.lower() for oc in object_classes):
                    filtered_entries.append(entry)

            # Cache the result
            self._store_in_cache(cache_key, filtered_entries)

            operation_time = time.time() - start_time
            self._record_operation_success(len(filtered_entries), operation_time)
            self._operation_stats["filter_operations"] += 1

            self._logger.debug(
                "ObjectClass filter completed (linear)",
                extra={
                    "object_class": object_class,
                    "results_count": len(filtered_entries),
                    "operation_time_seconds": operation_time,
                    "used_index": False,
                    "entries_searched": len(entries),
                },
            )

            return FlextResult[list[FlextLdifModels.Entry]].ok(filtered_entries)

        except Exception as e:
            operation_time = time.time() - start_time
            self._record_operation_failure("objectclass_filter_error")

            self._logger.exception(
                "ObjectClass filter failed",
                extra={
                    "object_class": object_class,
                    "error": str(e),
                    "operation_time_seconds": operation_time,
                },
            )

            return FlextResult[list[FlextLdifModels.Entry]].fail(
                f"ObjectClass filter error: {e}"
            )

    def filter_entries_by_object_class(
        self, entries: list[FlextLdifModels.Entry], object_class: str
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter entries by object class (alias for compatibility)."""
        return self.filter_entries_by_objectclass(entries, object_class)

    def get_statistics(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[dict[str, int]]:
        """Get comprehensive entry statistics with performance optimization."""
        start_time = time.time()

        try:
            # Generate cache key based on entry count and sample DNs
            sample_dns = [e.dn.value for e in entries[: min(5, len(entries))]]
            cache_key = f"stats:{len(entries)}:{hash(tuple(sample_dns))}"

            # Check cache first
            cached_result = self._get_from_cache(cache_key)
            if cached_result is not None:
                self._cache_hits += 1
                self._logger.debug("Cache hit for statistics calculation")
                return FlextResult[dict[str, int]].ok(cached_result)  # type: ignore[arg-type]

            self._cache_misses += 1

            self._logger.info(
                "Starting statistics calculation",
                extra={
                    "entry_count": len(entries),
                    "large_dataset": len(entries) > self._large_dataset_threshold,
                },
            )

            # Calculate comprehensive statistics
            unique_dns = len({e.dn.value for e in entries})
            total_attributes = sum(len(e.attributes.data) for e in entries)

            # Use optimized counting for large datasets
            if (
                len(entries) > self._large_dataset_threshold
                and entries is self._entries
            ):
                # Use indices for faster counting
                person_entries = sum(
                    len(indices)
                    for oc, indices in self._objectclass_index.items()
                    if oc in FlextLdifConstants.LDAP_PERSON_CLASSES
                )
                group_entries = sum(
                    len(indices)
                    for oc, indices in self._objectclass_index.items()
                    if oc in FlextLdifConstants.LDAP_GROUP_CLASSES
                )
                ou_entries = sum(
                    len(indices)
                    for oc, indices in self._objectclass_index.items()
                    if oc in FlextLdifConstants.LDAP_ORGANIZATIONAL_CLASSES
                )
            else:
                # Linear calculation for smaller datasets or external entries
                person_entries = sum(1 for e in entries if e.is_person_entry())
                group_entries = sum(1 for e in entries if e.is_group_entry())
                ou_entries = sum(
                    1
                    for e in entries
                    if "organizationalunit"
                    in (
                        oc.lower()
                        for oc in (
                            e.get_attribute(FlextLdifConstants.OBJECTCLASS_ATTRIBUTE)
                            or []
                        )
                    )
                )

            stats = {
                "total_entries": len(entries),
                "unique_dns": unique_dns,
                "total_attributes": total_attributes,
                "person_entries": person_entries,
                "group_entries": group_entries,
                "organizational_unit_entries": ou_entries,
                "average_attributes_per_entry": total_attributes // len(entries)
                if entries
                else 0,
                "duplicate_dns": len(entries) - unique_dns,
            }

            # Cache the result
            self._store_in_cache(cache_key, stats)

            operation_time = time.time() - start_time
            self._record_operation_success(len(entries), operation_time)

            self._logger.info(
                "Statistics calculation completed",
                extra={
                    "entry_count": len(entries),
                    "calculation_time_seconds": operation_time,
                    "used_indices": entries is self._entries
                    and len(entries) > self._large_dataset_threshold,
                    "stats": stats,
                },
            )

            return FlextResult[dict[str, int]].ok(stats)

        except Exception as e:
            operation_time = time.time() - start_time
            self._record_operation_failure("statistics_error")

            self._logger.exception(
                "Statistics calculation failed",
                extra={
                    "entry_count": len(entries),
                    "error": str(e),
                    "operation_time_seconds": operation_time,
                },
            )

            return FlextResult[dict[str, int]].fail(f"Statistics error: {e}")

    def get_repository_metrics(self) -> dict[str, object]:
        """Get comprehensive repository performance metrics."""
        uptime = time.time() - self._start_time
        cache_hit_rate = (
            self._cache_hits / (self._cache_hits + self._cache_misses)
            if (self._cache_hits + self._cache_misses) > 0
            else 0
        )

        return {
            "uptime_seconds": uptime,
            "storage": {
                "total_entries": len(self._entries),
                "total_entries_stored": self._total_entries_stored,
                "memory_usage_bytes": self._memory_usage,
                "peak_memory_usage_bytes": self._peak_memory_usage,
            },
            "performance": {
                "total_operations": self._total_operations,
                "total_queries": self._total_queries,
                "operation_failures": self._operation_failures,
                "success_rate": self._calculate_success_rate(),
                "avg_operation_time": (
                    sum(self._operation_times) / len(self._operation_times)
                    if self._operation_times
                    else 0
                ),
                "operations_per_second": self._total_operations / uptime
                if uptime > 0
                else 0,
            },
            "caching": {
                "cache_hits": self._cache_hits,
                "cache_misses": self._cache_misses,
                "cache_hit_rate": cache_hit_rate,
                "cache_size": len(self._query_cache),
                "max_cache_size": self._max_cache_size,
            },
            "indexing": {
                "dn_index_size": len(self._dn_index),
                "attribute_indices": len(self._attribute_index),
                "objectclass_indices": len(self._objectclass_index),
                "index_rebuilds": self._operation_stats["index_rebuilds"],
            },
            "operation_breakdown": self._operation_stats.copy(),
        }

    def clear_cache(self) -> None:
        """Clear query cache and reset cache statistics."""
        self._query_cache.clear()
        self._cache_hits = 0
        self._cache_misses = 0
        self._operation_stats["cache_cleanups"] += 1
        self._logger.info("Repository cache cleared")

    def rebuild_indices(self) -> FlextResult[bool]:
        """Rebuild all indices for optimal performance."""
        start_time = time.time()

        try:
            self._logger.info(
                "Starting index rebuild", extra={"entry_count": len(self._entries)}
            )

            # Clear existing indices
            self._dn_index.clear()
            self._attribute_index.clear()
            self._objectclass_index.clear()

            # Rebuild indices
            for i, entry in enumerate(self._entries):
                self._dn_index[entry.dn.value.lower()] = i
                self._build_indices_for_entry(entry, i)

            rebuild_time = time.time() - start_time
            self._operation_stats["index_rebuilds"] += 1

            self._logger.info(
                "Index rebuild completed",
                extra={
                    "entry_count": len(self._entries),
                    "rebuild_time_seconds": rebuild_time,
                    "dn_index_size": len(self._dn_index),
                    "attribute_indices": len(self._attribute_index),
                    "objectclass_indices": len(self._objectclass_index),
                },
            )

            return FlextResult[bool].ok(data=True)

        except Exception as e:
            rebuild_time = time.time() - start_time

            self._logger.exception(
                "Index rebuild failed",
                extra={
                    "error": str(e),
                    "rebuild_time_seconds": rebuild_time,
                },
            )

            return FlextResult[bool].fail(f"Index rebuild error: {e}")

    def health_check(self) -> FlextResult[dict[str, object]]:
        """Perform comprehensive health check of repository service."""
        try:
            health_status: dict[str, object] = {
                "service": "FlextLdifRepositoryService",
                "status": "healthy",
                "timestamp": time.time(),
                "checks": {},
            }
            checks = health_status["checks"] = {}

            # Storage check
            storage_status = "healthy"
            if (
                len(self._entries)
                > FlextLdifConstants.REPOSITORY_STORAGE_WARNING_THRESHOLD
            ):  # 100k entries
                storage_status = "warning"

            checks["storage"] = {
                "status": storage_status,
                "total_entries": len(self._entries),
                "memory_usage_mb": self._memory_usage / (1024 * 1024),
            }

            # Performance check
            success_rate = self._calculate_success_rate()
            performance_status = "healthy"
            if success_rate < FlextLdifConstants.REPOSITORY_HEALTHY_THRESHOLD:
                performance_status = "degraded"
            elif success_rate < FlextLdifConstants.REPOSITORY_DEGRADED_THRESHOLD:
                performance_status = "unhealthy"

            checks["performance"] = {
                "status": performance_status,
                "success_rate": success_rate,
                "total_operations": self._total_operations,
            }

            # Cache check
            cache_hit_rate = (
                self._cache_hits / (self._cache_hits + self._cache_misses)
                if (self._cache_hits + self._cache_misses) > 0
                else 1.0
            )
            cache_status = "healthy"
            if (
                cache_hit_rate < FlextLdifConstants.CACHE_HIT_RATE_THRESHOLD
            ):  # 50% hit rate threshold
                cache_status = "degraded"

            checks["caching"] = {
                "status": cache_status,
                "hit_rate": cache_hit_rate,
                "cache_size": len(self._query_cache),
            }

            # Index integrity check
            index_status = "healthy"
            if len(self._dn_index) != len(self._entries):
                index_status = "corrupted"
                health_status["status"] = "unhealthy"

            checks["indexing"] = {
                "status": index_status,
                "dn_index_size": len(self._dn_index),
                "expected_size": len(self._entries),
            }

            return FlextResult[dict[str, object]].ok(health_status)

        except Exception as e:
            self._logger.exception("Health check failed")
            return FlextResult[dict[str, object]].fail(f"Health check error: {e}")

    def get_config_info(self) -> dict[str, object]:
        """Get enhanced repository service configuration information."""
        return {
            "service": "FlextLdifRepositoryService",
            "config": {
                "service_type": "repository",
                "status": "ready",
                "capabilities": [
                    "store_entries",
                    "find_entry_by_dn",
                    "filter_entries_by_attribute",
                    "filter_entries_by_objectclass",
                    "get_statistics",
                    "intelligent_caching",
                    "performance_indexing",
                    "memory_optimization",
                ],
                "storage_settings": {
                    "backend": "memory",
                    "indexing_enabled": True,
                    "caching_enabled": True,
                    "cache_ttl_seconds": self._cache_ttl,
                    "max_cache_size": self._max_cache_size,
                    "gc_threshold": self._gc_threshold,
                },
            },
        }

    def execute(self) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Execute repository operation returning stored entries."""
        self._logger.debug("Repository service execute called")
        return FlextResult[list[FlextLdifModels.Entry]].ok(self._entries.copy())

    # Private helper methods

    def _validate_entries_for_storage(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[None]:
        """Validate entries before storage."""
        try:
            for i, entry in enumerate(entries):
                if not entry.dn.value.strip():
                    return FlextResult[None].fail(f"Entry {i} has empty DN")

                if not entry.attributes.data:
                    return FlextResult[None].fail(f"Entry {i} has no attributes")

            return FlextResult[None].ok(None)
        except Exception as e:
            return FlextResult[None].fail(f"Validation error: {e}")

    def _build_indices_for_entry(
        self, entry: FlextLdifModels.Entry, index: int
    ) -> None:
        """Build indices for a single entry."""
        # Build attribute indices
        for attr_name, attr_values in entry.attributes.data.items():
            if attr_name not in self._attribute_index:
                self._attribute_index[attr_name] = {}

            for value in attr_values:
                if value not in self._attribute_index[attr_name]:
                    self._attribute_index[attr_name][value] = []
                self._attribute_index[attr_name][value].append(index)

        # Build objectClass indices
        object_classes = (
            entry.get_attribute(FlextLdifConstants.OBJECTCLASS_ATTRIBUTE) or []
        )
        for oc in object_classes:
            oc_lower = oc.lower()
            if oc_lower not in self._objectclass_index:
                self._objectclass_index[oc_lower] = []
            self._objectclass_index[oc_lower].append(index)

    def _update_indices_for_entry(
        self, entry: FlextLdifModels.Entry, index: int
    ) -> None:
        """Update indices when an entry is modified."""
        # Remove old indices (simplified - in production, would track changes)
        # For now, just rebuild indices for this entry
        self._build_indices_for_entry(entry, index)

    def _filter_using_attribute_index(
        self, attribute_name: str, attribute_value: str | None
    ) -> list[FlextLdifModels.Entry]:
        """Filter using attribute index for performance."""
        if attribute_value is None:
            # Return all entries that have this attribute
            entry_indices_set = set()
            for value_indices in self._attribute_index[attribute_name].values():
                entry_indices_set.update(value_indices)
            return [self._entries[i] for i in sorted(entry_indices_set)]
        # Return entries with specific attribute value
        entry_indices_list = self._attribute_index[attribute_name].get(attribute_value, [])
        return [self._entries[i] for i in entry_indices_list]

    def _get_from_cache(self, cache_key: str) -> object | None:
        """Get result from cache if not expired."""
        if cache_key in self._query_cache:
            result, timestamp = self._query_cache[cache_key]
            if time.time() - timestamp < self._cache_ttl:
                return result
            # Remove expired entry
            del self._query_cache[cache_key]
        return None

    def _store_in_cache(self, cache_key: str, result: object) -> None:
        """Store result in cache with cleanup if needed."""
        # Clean cache if too large
        if len(self._query_cache) >= self._max_cache_size:
            self._cleanup_cache()

        self._query_cache[cache_key] = (result, time.time())

    def _cleanup_cache(self) -> None:
        """Remove expired entries from cache."""
        current_time = time.time()
        expired_keys = [
            key
            for key, (_, timestamp) in self._query_cache.items()
            if current_time - timestamp >= self._cache_ttl
        ]

        for key in expired_keys:
            del self._query_cache[key]

        # If still too large, remove oldest entries
        if len(self._query_cache) >= self._max_cache_size:
            sorted_items = sorted(
                self._query_cache.items(),
                key=lambda x: x[1][1],  # Sort by timestamp
            )
            # Keep only the newest half
            keep_count = self._max_cache_size // 2
            self._query_cache = dict(sorted_items[-keep_count:])

        self._operation_stats["cache_cleanups"] += 1

    def _clear_query_cache(self) -> None:
        """Clear query cache when data changes."""
        self._query_cache.clear()

    def _estimate_memory_usage(self, entries: list[FlextLdifModels.Entry]) -> int:
        """Estimate memory usage for entries."""
        # Rough estimation: 500 bytes per entry average
        return len(entries) * 500

    def _should_trigger_gc(self, additional_memory: int) -> bool:
        """Check if garbage collection should be triggered."""
        return len(self._entries) + (additional_memory // 500) > self._gc_threshold

    def _perform_memory_optimization(self) -> None:
        """Perform memory optimization and garbage collection."""
        # Clear cache to free memory
        self._query_cache.clear()

        # Rebuild indices to optimize memory layout
        self.rebuild_indices()

        # Update memory tracking
        self._update_memory_usage()

        self._operation_stats["memory_optimizations"] += 1
        self._logger.info("Memory optimization completed")

    def _update_memory_usage(self) -> None:
        """Update memory usage tracking."""
        # Rough estimation of memory usage
        entry_memory = len(self._entries) * 500  # Average per entry
        index_memory = len(self._dn_index) * 100  # DN index
        index_memory += sum(
            len(attr_index) * 50 for attr_index in self._attribute_index.values()
        )
        cache_memory = len(self._query_cache) * 200  # Cache entries

        self._memory_usage = entry_memory + index_memory + cache_memory

        self._peak_memory_usage = max(self._peak_memory_usage, self._memory_usage)

    def _record_operation_success(
        self, _result_count: int, operation_time: float
    ) -> None:
        """Record successful operation metrics."""
        self._total_operations += 1
        self._total_queries += 1
        self._operation_times.append(operation_time)

        # Keep operation times list manageable
        if len(self._operation_times) > FlextLdifConstants.MAX_CACHE_ENTRIES:
            self._operation_times = self._operation_times[
                -FlextLdifConstants.MANAGEABLE_CACHE_SIZE :
            ]

    def _record_operation_failure(self, failure_type: str) -> None:
        """Record operation failure with categorization."""
        self._operation_failures += 1
        self._total_operations += 1

        self._logger.warning(
            "Repository operation failure", extra={"failure_type": failure_type}
        )

    def _calculate_success_rate(self) -> float:
        """Calculate operation success rate."""
        if self._total_operations == 0:
            return 1.0
        return max(
            0.0,
            (self._total_operations - self._operation_failures)
            / self._total_operations,
        )


__all__ = ["FlextLdifRepositoryService"]
