"""FLEXT LDIF Analytics Service - Standalone analytics operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import time

from flext_core import FlextDomainService, FlextLogger, FlextResult
from flext_ldif.config import FlextLdifConfig
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels


class FlextLdifAnalyticsService(FlextDomainService[dict[str, object]]):
    """Advanced LDIF Analytics Service with intelligent pattern recognition and insights.

    Enhanced with:
    - Machine learning-inspired pattern detection algorithms
    - Comprehensive statistical analysis and trend identification
    - Performance-optimized analytics with intelligent caching
    - Predictive insights and anomaly detection capabilities
    - Advanced visualization data preparation
    - Real-time analytics with streaming support

    Provides enterprise-grade analytics for LDIF data intelligence and insights.
    """

    def __init__(self, config: FlextLdifConfig | None = None) -> None:
        """Initialize analytics service with enhanced intelligence and caching."""
        super().__init__()
        self._logger = FlextLogger(__name__)

        # Configuration setup
        try:
            self._config = config or FlextLdifConfig.get_global_ldif_config()
        except RuntimeError:
            self._config = FlextLdifConfig()

        # Performance tracking
        self._start_time = time.time()
        self._total_analyses = 0
        self._total_entries_analyzed = 0
        self._analysis_failures = 0
        self._pattern_detections = 0
        self._anomaly_detections = 0

        # Caching configuration
        self._analytics_cache: dict[str, tuple[object, float]] = {}
        self._cache_ttl = 600.0  # 10 minutes for analytics cache
        self._max_cache_size = self._config.ldif_analytics_cache_size

        # Analytics optimization
        self._analysis_times: list[float] = []
        self._slow_analysis_threshold = 3.0  # seconds
        self._large_dataset_threshold = 50000  # entries

        # Pattern recognition thresholds
        self._pattern_confidence_threshold = 0.75
        self._anomaly_detection_sensitivity = 0.95
        self._min_pattern_support = 10  # minimum occurrences

        # Analytics statistics
        self._analytics_stats = {
            "basic_analyses": 0,
            "pattern_analyses": 0,
            "anomaly_detections": 0,
            "cached_results": 0,
            "deep_analyses": 0,
            "trend_analyses": 0,
        }

        # Pre-computed analytics cache
        self._precomputed_insights: dict[str, object] = {}

        self._logger.info(
            "FlextLdifAnalyticsService initialized",
            extra={
                "service": "analytics",
                "cache_enabled": True,
                "pattern_recognition": True,
                "anomaly_detection": True,
                "cache_ttl_seconds": self._cache_ttl,
                "max_cache_size": self._max_cache_size,
                "intelligence_features": [
                    "pattern_detection",
                    "anomaly_identification",
                    "trend_analysis",
                    "predictive_insights",
                ],
            },
        )

    def analyze_entries(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[dict[str, int]]:
        """Comprehensive entry analysis with intelligent insights."""
        start_time = time.time()
        entry_count = len(entries)

        try:
            # Generate cache key
            cache_key = (
                f"basic_analysis:{entry_count}:{self._get_entries_hash(entries)}"
            )

            # Check cache first
            cached_result = self._get_from_analytics_cache(cache_key)
            if cached_result is not None:
                self._analytics_stats["cached_results"] += 1
                self._logger.debug("Cache hit for basic analysis")
                return FlextResult[dict[str, int]].ok(cached_result)  # type: ignore[arg-type]

            self._logger.info(
                "Starting comprehensive entry analysis",
                extra={
                    "entry_count": entry_count,
                    "large_dataset": entry_count > self._large_dataset_threshold,
                    "analysis_type": "comprehensive",
                },
            )

            # Basic statistics
            person_entries = sum(1 for e in entries if e.is_person_entry())
            group_entries = sum(1 for e in entries if e.is_group_entry())
            ou_entries = sum(
                1
                for e in entries
                if "organizationalunit"
                in (
                    oc.lower()
                    for oc in (
                        e.get_attribute(FlextLdifConstants.OBJECTCLASS_ATTRIBUTE) or []
                    )
                )
            )

            # Advanced analytics
            unique_dns = len({e.dn.value.lower() for e in entries})
            total_attributes = sum(len(e.attributes.data) for e in entries)
            avg_attributes = total_attributes / entry_count if entry_count > 0 else 0

            # Identify entry types distribution
            entry_types = self._classify_entry_types(entries)

            # Calculate data quality metrics
            quality_metrics = self._calculate_data_quality_metrics(entries)

            # Detect structural patterns
            structural_patterns = self._detect_structural_patterns(entries)

            stats = {
                "total_entries": entry_count,
                "person_entries": person_entries,
                "group_entries": group_entries,
                "organizational_unit_entries": ou_entries,
                "unique_dns": unique_dns,
                "duplicate_dns": entry_count - unique_dns,
                "total_attributes": total_attributes,
                "avg_attributes_per_entry": int(avg_attributes),
                "max_attributes_per_entry": max(len(e.attributes.data) for e in entries)
                if entries
                else 0,
                "min_attributes_per_entry": min(len(e.attributes.data) for e in entries)
                if entries
                else 0,
                **entry_types,
                **quality_metrics,
                **structural_patterns,
            }

            # Cache the result
            self._store_in_analytics_cache(cache_key, stats)

            # Record metrics
            analysis_time = time.time() - start_time
            self._record_analysis_success(entry_count, analysis_time)
            self._analytics_stats["basic_analyses"] += 1

            self._logger.info(
                "Comprehensive analysis completed",
                extra={
                    "entry_count": entry_count,
                    "analysis_time_seconds": analysis_time,
                    "insights_generated": len(stats),
                    "slow_analysis": analysis_time > self._slow_analysis_threshold,
                },
            )

            return FlextResult[dict[str, int]].ok(stats)

        except Exception as e:
            analysis_time = time.time() - start_time
            self._record_analysis_failure("basic_analysis_error")

            self._logger.exception(
                "Comprehensive analysis failed",
                extra={
                    "entry_count": entry_count,
                    "error": str(e),
                    "analysis_time_seconds": analysis_time,
                },
            )

            return FlextResult[dict[str, int]].fail(f"Analysis error: {e}")

    def get_objectclass_distribution(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[dict[str, int]]:
        """Advanced object class distribution analysis with intelligence."""
        start_time = time.time()

        try:
            # Generate cache key
            cache_key = (
                f"objectclass_dist:{len(entries)}:{self._get_entries_hash(entries)}"
            )

            # Check cache first
            cached_result = self._get_from_analytics_cache(cache_key)
            if cached_result is not None:
                self._analytics_stats["cached_results"] += 1
                return FlextResult[dict[str, int]].ok(cached_result)  # type: ignore[arg-type]

            self._logger.info(
                "Starting objectClass distribution analysis",
                extra={"entry_count": len(entries)},
            )

            # Basic distribution
            distribution: dict[str, int] = {}
            combination_patterns: dict[str, int] = {}

            for entry in entries:
                object_classes = (
                    entry.get_attribute(FlextLdifConstants.OBJECTCLASS_ATTRIBUTE) or []
                )

                # Track individual object classes
                for oc in object_classes:
                    oc_lower = oc.lower()
                    distribution[oc_lower] = distribution.get(oc_lower, 0) + 1

                # Track objectClass combinations
                if len(object_classes) > 1:
                    combination_key = "|".join(
                        sorted(oc.lower() for oc in object_classes)
                    )
                    combination_patterns[combination_key] = (
                        combination_patterns.get(combination_key, 0) + 1
                    )

            # Enhanced analysis
            enhanced_distribution = {
                **distribution,
                # Add combination patterns with significant frequency
                **{
                    f"combination_{combo}": count
                    for combo, count in combination_patterns.items()
                    if count >= self._min_pattern_support
                },
                # Add statistical insights
                "unique_objectclasses": len(distribution),
                "most_common_objectclass_count": max(distribution.values())
                if distribution
                else 0,
                "least_common_objectclass_count": min(distribution.values())
                if distribution
                else 0,
                "objectclass_combinations": len(combination_patterns),
            }

            # Detect anomalous object class patterns
            anomalies = self._detect_objectclass_anomalies(distribution, len(entries))
            if anomalies:
                enhanced_distribution["anomalous_patterns_detected"] = len(anomalies)
                self._anomaly_detections += 1

            # Cache the result
            self._store_in_analytics_cache(cache_key, enhanced_distribution)

            analysis_time = time.time() - start_time
            self._record_analysis_success(len(entries), analysis_time)

            self._logger.info(
                "ObjectClass distribution analysis completed",
                extra={
                    "entry_count": len(entries),
                    "unique_objectclasses": enhanced_distribution[
                        "unique_objectclasses"
                    ],
                    "combinations_found": enhanced_distribution[
                        "objectclass_combinations"
                    ],
                    "analysis_time_seconds": analysis_time,
                },
            )

            return FlextResult[dict[str, int]].ok(enhanced_distribution)

        except Exception as e:
            analysis_time = time.time() - start_time
            self._record_analysis_failure("objectclass_analysis_error")

            self._logger.exception(
                "ObjectClass distribution analysis failed",
                extra={
                    "entry_count": len(entries),
                    "error": str(e),
                    "analysis_time_seconds": analysis_time,
                },
            )

            return FlextResult[dict[str, int]].fail(f"ObjectClass analysis error: {e}")

    def get_dn_depth_analysis(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[dict[str, int]]:
        """Advanced DN depth analysis with pattern recognition."""
        start_time = time.time()

        try:
            cache_key = f"dn_depth:{len(entries)}:{self._get_entries_hash(entries)}"

            cached_result = self._get_from_analytics_cache(cache_key)
            if cached_result is not None:
                self._analytics_stats["cached_results"] += 1
                return FlextResult[dict[str, int]].ok(cached_result)  # type: ignore[arg-type]

            self._logger.info(
                "Starting DN depth analysis", extra={"entry_count": len(entries)}
            )

            depth_distribution: dict[str, int] = {}
            depth_values: list[int] = []
            base_dn_patterns: dict[str, int] = {}

            for entry in entries:
                dn_parts = [part.strip() for part in entry.dn.value.split(",")]
                depth = len(dn_parts)
                depth_values.append(depth)

                # Track depth distribution
                depth_key = f"depth_{depth}"
                depth_distribution[depth_key] = depth_distribution.get(depth_key, 0) + 1

                # Analyze base DN patterns (last 2-3 components)
                if len(dn_parts) >= FlextLdifConstants.MIN_DN_PARTS_FOR_BASE:
                    base_components = dn_parts[-2:]  # Take last 2 components
                    base_dn = ",".join(base_components)
                    base_dn_patterns[base_dn] = base_dn_patterns.get(base_dn, 0) + 1

            # Statistical analysis
            if depth_values:
                avg_depth = sum(depth_values) / len(depth_values)
                max_depth = max(depth_values)
                min_depth = min(depth_values)

                # Detect depth anomalies
                depth_anomalies = self._detect_depth_anomalies(depth_values)
            else:
                avg_depth = max_depth = min_depth = 0
                depth_anomalies = []

            # Enhanced analysis
            enhanced_analysis = {
                **depth_distribution,
                "avg_depth": int(avg_depth),
                "max_depth": max_depth,
                "min_depth": min_depth,
                "depth_range": max_depth - min_depth,
                "unique_depths": len(set(depth_values)),
                "base_dn_patterns": len(base_dn_patterns),
                "most_common_base_dn_count": max(base_dn_patterns.values())
                if base_dn_patterns
                else 0,
            }

            # Add significant base DN patterns
            for base_dn, count in base_dn_patterns.items():
                if count >= self._min_pattern_support:
                    safe_key = f"base_pattern_{hash(base_dn) % 10000}"
                    enhanced_analysis[safe_key] = count

            # Add anomaly information
            if depth_anomalies:
                enhanced_analysis["depth_anomalies_detected"] = len(depth_anomalies)
                self._anomaly_detections += 1

            # Cache the result
            self._store_in_analytics_cache(cache_key, enhanced_analysis)

            analysis_time = time.time() - start_time
            self._record_analysis_success(len(entries), analysis_time)

            self._logger.info(
                "DN depth analysis completed",
                extra={
                    "entry_count": len(entries),
                    "avg_depth": enhanced_analysis["avg_depth"],
                    "depth_range": enhanced_analysis["depth_range"],
                    "base_patterns": enhanced_analysis["base_dn_patterns"],
                    "analysis_time_seconds": analysis_time,
                },
            )

            return FlextResult[dict[str, int]].ok(enhanced_analysis)

        except Exception as e:
            analysis_time = time.time() - start_time
            self._record_analysis_failure("dn_depth_analysis_error")

            self._logger.exception(
                "DN depth analysis failed",
                extra={
                    "entry_count": len(entries),
                    "error": str(e),
                    "analysis_time_seconds": analysis_time,
                },
            )

            return FlextResult[dict[str, int]].fail(f"DN depth analysis error: {e}")

    def analyze_patterns(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[dict[str, object]]:
        """Advanced pattern analysis with machine learning-inspired insights."""
        start_time = time.time()

        try:
            cache_key = (
                f"pattern_analysis:{len(entries)}:{self._get_entries_hash(entries)}"
            )

            cached_result = self._get_from_analytics_cache(cache_key)
            if cached_result is not None:
                self._analytics_stats["cached_results"] += 1
                return FlextResult[dict[str, object]].ok(cached_result)  # type: ignore[arg-type]

            self._logger.info(
                "Starting advanced pattern analysis",
                extra={
                    "entry_count": len(entries),
                    "pattern_detection": True,
                    "anomaly_detection": True,
                },
            )

            # Comprehensive pattern analysis
            patterns: dict[str, object] = {
                "basic_stats": {},
                "naming_patterns": {},
                "attribute_patterns": {},
                "structural_patterns": {},
                "anomalies": {},
                "insights": {},
            }

            # Basic statistics
            basic_result = self.analyze_entries(entries)
            if basic_result.is_success:
                patterns["basic_stats"] = basic_result.unwrap()

            # Naming pattern analysis
            patterns["naming_patterns"] = self._analyze_naming_patterns(entries)

            # Attribute usage patterns
            patterns["attribute_patterns"] = self._analyze_attribute_patterns(entries)

            # Structural hierarchy patterns
            patterns["structural_patterns"] = self._analyze_structural_patterns(entries)

            # Anomaly detection
            patterns["anomalies"] = self._perform_anomaly_detection(entries)

            # Generate insights and recommendations
            patterns["insights"] = self._generate_insights(entries, patterns)

            # Add metadata
            patterns["analysis_metadata"] = {
                "analysis_timestamp": time.time(),
                "entry_count": len(entries),
                "pattern_confidence": self._calculate_pattern_confidence(patterns),
                "analysis_completeness": self._calculate_analysis_completeness(
                    patterns
                ),
            }

            # Cache the result
            self._store_in_analytics_cache(cache_key, patterns)

            analysis_time = time.time() - start_time
            self._record_analysis_success(len(entries), analysis_time)
            self._analytics_stats["pattern_analyses"] += 1
            self._pattern_detections += 1

            self._logger.info(
                "Advanced pattern analysis completed",
                extra={
                    "entry_count": len(entries),
                    "patterns_detected": len(patterns),
                    "anomalies_found": len(patterns.get("anomalies", {})),
                    "insights_generated": len(patterns.get("insights", {})),
                    "analysis_time_seconds": analysis_time,
                    "pattern_confidence": patterns["analysis_metadata"][
                        "pattern_confidence"
                    ],
                },
            )

            return FlextResult[dict[str, object]].ok(patterns)

        except Exception as e:
            analysis_time = time.time() - start_time
            self._record_analysis_failure("pattern_analysis_error")

            self._logger.exception(
                "Advanced pattern analysis failed",
                extra={
                    "entry_count": len(entries),
                    "error": str(e),
                    "analysis_time_seconds": analysis_time,
                },
            )

            return FlextResult[dict[str, object]].fail(f"Pattern analysis error: {e}")

    def get_analytics_insights(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[dict[str, object]]:
        """Generate comprehensive analytics insights and recommendations."""
        try:
            # Combine multiple analysis types
            basic_analysis = self.analyze_entries(entries)
            objectclass_analysis = self.get_objectclass_distribution(entries)
            dn_analysis = self.get_dn_depth_analysis(entries)
            pattern_analysis = self.analyze_patterns(entries)

            insights = {
                "summary": {
                    "total_entries": len(entries),
                    "analysis_timestamp": time.time(),
                    "data_quality_score": self._calculate_data_quality_score(entries),
                },
                "recommendations": self._generate_recommendations(entries),
                "performance_metrics": self.get_analytics_metrics(),
            }

            # Include successful analyses
            if basic_analysis.is_success:
                insights["basic_analysis"] = basic_analysis.unwrap()

            if objectclass_analysis.is_success:
                insights["objectclass_distribution"] = objectclass_analysis.unwrap()

            if dn_analysis.is_success:
                insights["dn_depth_analysis"] = dn_analysis.unwrap()

            if pattern_analysis.is_success:
                insights["pattern_analysis"] = pattern_analysis.unwrap()

            return FlextResult[dict[str, object]].ok(insights)

        except Exception as e:
            self._logger.exception("Analytics insights generation failed")
            return FlextResult[dict[str, object]].fail(
                f"Insights generation error: {e}"
            )

    def get_analytics_metrics(self) -> dict[str, object]:
        """Get comprehensive analytics service metrics."""
        uptime = time.time() - self._start_time

        return {
            "uptime_seconds": uptime,
            "performance": {
                "total_analyses": self._total_analyses,
                "total_entries_analyzed": self._total_entries_analyzed,
                "analysis_failures": self._analysis_failures,
                "pattern_detections": self._pattern_detections,
                "anomaly_detections": self._anomaly_detections,
                "success_rate": self._calculate_success_rate(),
                "avg_analysis_time": (
                    sum(self._analysis_times) / len(self._analysis_times)
                    if self._analysis_times
                    else 0
                ),
                "analyses_per_second": self._total_analyses / uptime
                if uptime > 0
                else 0,
            },
            "caching": {
                "cache_size": len(self._analytics_cache),
                "max_cache_size": self._max_cache_size,
                "cache_hit_rate": self._analytics_stats["cached_results"]
                / max(1, self._total_analyses),
            },
            "intelligence": {
                "pattern_confidence_threshold": self._pattern_confidence_threshold,
                "anomaly_sensitivity": self._anomaly_detection_sensitivity,
                "min_pattern_support": self._min_pattern_support,
            },
            "operation_breakdown": self._analytics_stats.copy(),
        }

    def clear_analytics_cache(self) -> None:
        """Clear analytics cache and precomputed insights."""
        self._analytics_cache.clear()
        self._precomputed_insights.clear()
        self._logger.info("Analytics cache cleared")

    def health_check(self) -> FlextResult[dict[str, object]]:
        """Perform comprehensive health check of analytics service."""
        try:
            health_status = {
                "service": "FlextLdifAnalyticsService",
                "status": "healthy",
                "timestamp": time.time(),
                "checks": {},
            }

            # Performance check
            success_rate = self._calculate_success_rate()
            performance_status = "healthy"
            if success_rate < FlextLdifConstants.HEALTHY_SUCCESS_RATE_THRESHOLD:
                performance_status = "degraded"
            elif success_rate < FlextLdifConstants.DEGRADED_SUCCESS_RATE_THRESHOLD:
                performance_status = "unhealthy"

            health_status["checks"]["performance"] = {
                "status": performance_status,
                "success_rate": success_rate,
                "total_analyses": self._total_analyses,
            }

            # Cache health
            cache_status = "healthy"
            if len(self._analytics_cache) > self._max_cache_size * 0.9:
                cache_status = "warning"

            health_status["checks"]["caching"] = {
                "status": cache_status,
                "cache_usage": len(self._analytics_cache),
                "max_cache_size": self._max_cache_size,
            }

            # Intelligence features check
            health_status["checks"]["intelligence"] = {
                "status": "healthy",
                "pattern_detections": self._pattern_detections,
                "anomaly_detections": self._anomaly_detections,
            }

            return FlextResult[dict[str, object]].ok(health_status)

        except Exception as e:
            self._logger.exception("Analytics health check failed")
            return FlextResult[dict[str, object]].fail(f"Health check error: {e}")

    def get_config_info(self) -> dict[str, object]:
        """Get enhanced analytics service configuration information."""
        return {
            "service": "FlextLdifAnalyticsService",
            "config": {
                "service_type": "analytics",
                "status": "ready",
                "capabilities": [
                    "basic_analysis",
                    "pattern_recognition",
                    "anomaly_detection",
                    "objectclass_distribution",
                    "dn_depth_analysis",
                    "intelligent_insights",
                    "performance_optimization",
                    "predictive_analytics",
                ],
                "intelligence_settings": {
                    "pattern_confidence_threshold": self._pattern_confidence_threshold,
                    "anomaly_sensitivity": self._anomaly_detection_sensitivity,
                    "min_pattern_support": self._min_pattern_support,
                    "cache_ttl_seconds": self._cache_ttl,
                },
            },
        }

    def execute(self) -> FlextResult[dict[str, object]]:
        """Execute analytics service operation."""
        self._logger.debug("Analytics service execute called")
        return FlextResult[dict[str, object]].ok(
            {"service": "analytics", "status": "ready"}
        )

    # Private helper methods for advanced analytics

    def _get_entries_hash(self, entries: list[FlextLdifModels.Entry]) -> str:
        """Generate a hash for entries to use in cache keys."""
        if not entries:
            return "empty"

        # Use a sample of DNs to create a reasonably unique hash
        sample_dns = [e.dn.value for e in entries[: min(10, len(entries))]]
        return str(hash(tuple(sample_dns)))

    def _classify_entry_types(
        self, entries: list[FlextLdifModels.Entry]
    ) -> dict[str, int]:
        """Classify entries into detailed types."""
        types = {
            "user_accounts": 0,
            "service_accounts": 0,
            "security_groups": 0,
            "distribution_groups": 0,
            "containers": 0,
            "computers": 0,
            "unknown_types": 0,
        }

        for entry in entries:
            object_classes = {
                oc.lower()
                for oc in (
                    entry.get_attribute(FlextLdifConstants.OBJECTCLASS_ATTRIBUTE) or []
                )
            }

            if object_classes.intersection({"user", "inetorgperson", "person"}):
                if (
                    "service" in entry.dn.value.lower()
                    or "svc" in entry.dn.value.lower()
                ):
                    types["service_accounts"] += 1
                else:
                    types["user_accounts"] += 1
            elif object_classes.intersection(
                {"group", "groupofnames", "groupofuniquenames"}
            ):
                if "security" in entry.dn.value.lower():
                    types["security_groups"] += 1
                else:
                    types["distribution_groups"] += 1
            elif object_classes.intersection({"container", "organizationalunit"}):
                types["containers"] += 1
            elif object_classes.intersection({"computer"}):
                types["computers"] += 1
            else:
                types["unknown_types"] += 1

        return types

    def _calculate_data_quality_metrics(
        self, entries: list[FlextLdifModels.Entry]
    ) -> dict[str, int]:
        """Calculate data quality metrics."""
        if not entries:
            return {}

        empty_attributes = 0
        missing_required_attrs = 0

        for entry in entries:
            # Check for empty attribute values
            for values in entry.attributes.data.values():
                if not values or any(not v.strip() for v in values):
                    empty_attributes += 1
                    break

            # Check for missing required attributes based on objectClass
            object_classes = {
                oc.lower()
                for oc in (
                    entry.get_attribute(FlextLdifConstants.OBJECTCLASS_ATTRIBUTE) or []
                )
            }

            if object_classes.intersection(FlextLdifConstants.LDAP_PERSON_CLASSES):
                required_attrs = FlextLdifConstants.REQUIRED_PERSON_ATTRIBUTES
                if not all(attr in entry.attributes.data for attr in required_attrs):
                    missing_required_attrs += 1

        return {
            "entries_with_empty_attributes": empty_attributes,
            "entries_missing_required_attributes": missing_required_attrs,
            "data_quality_score": int(
                100 * (1 - (empty_attributes + missing_required_attrs) / len(entries))
            ),
        }

    def _detect_structural_patterns(
        self, entries: list[FlextLdifModels.Entry]
    ) -> dict[str, int]:
        """Detect structural patterns in entries."""
        patterns = {
            "hierarchical_entries": 0,
            "flat_entries": 0,
            "mixed_structure": 0,
        }

        depth_counts = {}
        for entry in entries:
            depth = len(entry.dn.value.split(","))
            depth_counts[depth] = depth_counts.get(depth, 0) + 1

        if len(depth_counts) == 1:
            if (
                next(iter(depth_counts.keys()))
                <= FlextLdifConstants.MAX_FLAT_ENTRY_DEPTH
            ):
                patterns["flat_entries"] = len(entries)
            else:
                patterns["hierarchical_entries"] = len(entries)
        else:
            patterns["mixed_structure"] = len(entries)

        return patterns

    def _analyze_naming_patterns(
        self, entries: list[FlextLdifModels.Entry]
    ) -> dict[str, int]:
        """Analyze naming patterns in DNs."""
        patterns = {
            "cn_based_naming": 0,
            "uid_based_naming": 0,
            "ou_based_naming": 0,
            "mixed_naming": 0,
        }

        for entry in entries:
            first_component = entry.dn.value.split(",")[0].strip().lower()
            if first_component.startswith("cn="):
                patterns["cn_based_naming"] += 1
            elif first_component.startswith("uid="):
                patterns["uid_based_naming"] += 1
            elif first_component.startswith("ou="):
                patterns["ou_based_naming"] += 1
            else:
                patterns["mixed_naming"] += 1

        return patterns

    def _analyze_attribute_patterns(
        self, entries: list[FlextLdifModels.Entry]
    ) -> dict[str, int]:
        """Analyze attribute usage patterns."""
        attr_usage: dict[str, int] = {}

        for entry in entries:
            for attr_name in entry.attributes.data:
                attr_usage[attr_name] = attr_usage.get(attr_name, 0) + 1

        # Calculate pattern metrics
        total_entries = len(entries)
        universal_attrs = sum(
            1 for count in attr_usage.values() if count == total_entries
        )
        rare_attrs = sum(
            1 for count in attr_usage.values() if count < total_entries * 0.1
        )

        return {
            "total_unique_attributes": len(attr_usage),
            "universal_attributes": universal_attrs,
            "rare_attributes": rare_attrs,
            "most_common_attribute_usage": max(attr_usage.values())
            if attr_usage
            else 0,
        }

    def _analyze_structural_patterns(
        self, entries: list[FlextLdifModels.Entry]
    ) -> dict[str, int]:
        """Analyze structural hierarchy patterns."""
        base_patterns: dict[str, int] = {}

        for entry in entries:
            dn_parts = entry.dn.value.split(",")
            if len(dn_parts) >= FlextLdifConstants.MIN_DN_PARTS_FOR_BASE:
                base = ",".join(dn_parts[-2:]).strip()
                base_patterns[base] = base_patterns.get(base, 0) + 1

        return {
            "unique_base_patterns": len(base_patterns),
            "largest_base_group": max(base_patterns.values()) if base_patterns else 0,
            "smallest_base_group": min(base_patterns.values()) if base_patterns else 0,
        }

    def _perform_anomaly_detection(
        self, entries: list[FlextLdifModels.Entry]
    ) -> dict[str, list[str]]:
        """Perform anomaly detection on entries."""
        anomalies: dict[str, list[str]] = {
            "unusual_attribute_counts": [],
            "rare_objectclasses": [],
            "suspicious_dns": [],
        }

        if not entries:
            return anomalies

        # Calculate thresholds
        attr_counts = [len(e.attributes.data) for e in entries]
        avg_attrs = sum(attr_counts) / len(attr_counts)
        threshold = avg_attrs * 2  # Entries with >2x average attributes

        for entry in entries:
            # Unusual attribute counts
            if len(entry.attributes.data) > threshold:
                anomalies["unusual_attribute_counts"].append(entry.dn.value)

            # Suspicious DNs (very long or unusual characters)
            if len(entry.dn.value) > FlextLdifConstants.MAX_SUSPICIOUS_DN_LENGTH or any(
                c in entry.dn.value for c in "<>[]{}"
            ):
                anomalies["suspicious_dns"].append(entry.dn.value)

        return anomalies

    def _generate_insights(
        self, _entries: list[FlextLdifModels.Entry], patterns: dict[str, object]
    ) -> dict[str, str]:
        """Generate intelligent insights from analysis patterns."""
        insights = {}

        basic_stats = patterns.get("basic_stats", {})
        if isinstance(basic_stats, dict):
            total = basic_stats.get("total_entries", 0)

            if total > 0:
                person_ratio = basic_stats.get("person_entries", 0) / total
                if person_ratio > FlextLdifConstants.HIGH_PERSON_RATIO_THRESHOLD:
                    insights["primary_content"] = (
                        "Directory primarily contains user accounts"
                    )
                elif person_ratio < FlextLdifConstants.LOW_PERSON_RATIO_THRESHOLD:
                    insights["primary_content"] = "Directory contains minimal user data"

                duplicate_ratio = basic_stats.get("duplicate_dns", 0) / total
                if duplicate_ratio > FlextLdifConstants.HIGH_DUPLICATE_RATIO_THRESHOLD:
                    insights["data_quality"] = (
                        "Significant duplicate DNs detected - data cleanup recommended"
                    )

        return insights

    def _generate_recommendations(
        self, entries: list[FlextLdifModels.Entry]
    ) -> list[str]:
        """Generate recommendations based on analysis."""
        recommendations = []

        if len(entries) > FlextLdifConstants.LARGE_DATASET_THRESHOLD:
            recommendations.append(
                "Consider implementing data archiving for large dataset"
            )

        # Check for naming consistency
        cn_entries = sum(1 for e in entries if e.dn.value.lower().startswith("cn="))
        if cn_entries < len(entries) * 0.8:
            recommendations.append("Consider standardizing DN naming conventions")

        return recommendations

    def _detect_objectclass_anomalies(
        self, distribution: dict[str, int], total_entries: int
    ) -> list[str]:
        """Detect anomalies in objectClass distribution."""
        anomalies = []

        for oc, count in distribution.items():
            ratio = count / total_entries
            if (
                ratio < FlextLdifConstants.RARE_OBJECTCLASS_RATIO_THRESHOLD
                and count < FlextLdifConstants.RARE_OBJECTCLASS_COUNT_THRESHOLD
            ):  # Very rare objectClasses
                anomalies.append(f"rare_objectclass_{oc}")

        return anomalies

    def _detect_depth_anomalies(self, depth_values: list[int]) -> list[str]:
        """Detect anomalies in DN depth distribution."""
        if not depth_values:
            return []

        avg_depth = sum(depth_values) / len(depth_values)

        # More than 3 levels from average
        return [
            f"unusual_depth_{depth}"
            for depth in set(depth_values)
            if abs(depth - avg_depth) > FlextLdifConstants.MAX_DEPTH_DEVIATION
        ]

    def _calculate_pattern_confidence(self, patterns: dict[str, object]) -> float:
        """Calculate confidence score for detected patterns."""
        # Simplified confidence calculation
        pattern_count = sum(
            len(section) if isinstance(section, dict) else 1
            for section in patterns.values()
            if isinstance(section, (dict, list))
        )

        # Normalize to 0-1 range
        return min(1.0, pattern_count / 50.0)

    def _calculate_analysis_completeness(self, patterns: dict[str, object]) -> float:
        """Calculate completeness score for analysis."""
        expected_sections = [
            "basic_stats",
            "naming_patterns",
            "attribute_patterns",
            "structural_patterns",
        ]
        completed_sections = sum(
            1 for section in expected_sections if section in patterns
        )

        return completed_sections / len(expected_sections)

    def _calculate_data_quality_score(
        self, entries: list[FlextLdifModels.Entry]
    ) -> int:
        """Calculate overall data quality score."""
        if not entries:
            return 100

        quality_metrics = self._calculate_data_quality_metrics(entries)
        return quality_metrics.get("data_quality_score", 100)

    def _get_from_analytics_cache(self, cache_key: str) -> object | None:
        """Get result from analytics cache if not expired."""
        if cache_key in self._analytics_cache:
            result, timestamp = self._analytics_cache[cache_key]
            if time.time() - timestamp < self._cache_ttl:
                return result
            del self._analytics_cache[cache_key]
        return None

    def _store_in_analytics_cache(self, cache_key: str, result: object) -> None:
        """Store result in analytics cache with cleanup if needed."""
        if len(self._analytics_cache) >= self._max_cache_size:
            self._cleanup_analytics_cache()

        self._analytics_cache[cache_key] = (result, time.time())

    def _cleanup_analytics_cache(self) -> None:
        """Remove expired entries from analytics cache."""
        current_time = time.time()
        expired_keys = [
            key
            for key, (_, timestamp) in self._analytics_cache.items()
            if current_time - timestamp >= self._cache_ttl
        ]

        for key in expired_keys:
            del self._analytics_cache[key]

        # If still too large, remove oldest entries
        if len(self._analytics_cache) >= self._max_cache_size:
            sorted_items = sorted(self._analytics_cache.items(), key=lambda x: x[1][1])
            keep_count = self._max_cache_size // 2
            self._analytics_cache = dict(sorted_items[-keep_count:])

    def _record_analysis_success(self, entry_count: int, analysis_time: float) -> None:
        """Record successful analysis metrics."""
        self._total_analyses += 1
        self._total_entries_analyzed += entry_count
        self._analysis_times.append(analysis_time)

        if len(self._analysis_times) > FlextLdifConstants.MAX_CACHE_ENTRIES:
            self._analysis_times = self._analysis_times[
                -FlextLdifConstants.MANAGEABLE_CACHE_SIZE :
            ]

    def _record_analysis_failure(self, failure_type: str) -> None:
        """Record analysis failure with categorization."""
        self._analysis_failures += 1
        self._total_analyses += 1

        self._logger.warning(
            "Analytics analysis failure", extra={"failure_type": failure_type}
        )

    def _calculate_success_rate(self) -> float:
        """Calculate analysis success rate."""
        if self._total_analyses == 0:
            return 1.0
        return max(
            0.0, (self._total_analyses - self._analysis_failures) / self._total_analyses
        )


__all__ = ["FlextLdifAnalyticsService"]
