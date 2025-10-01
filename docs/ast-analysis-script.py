#!/usr/bin/env python3
"""FLEXT-LDIF AST Analysis Script.

This script performs comprehensive AST (Abstract Syntax Tree) analysis of the
flext-ldif project to examine profound impact, library usage patterns, and
performance characteristics.

Author: FLEXT Development Team
Version: 1.0.0
Date: 2025-01-27
"""

import ast
import logging
from collections import Counter
from pathlib import Path
from typing import TypedDict

# Configure logging
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")


class ModuleAnalysis(TypedDict, total=False):
    """Type definition for module analysis results."""

    file: str
    imports: list[dict[str, object]]
    classes: list[dict[str, object]]
    functions: list[dict[str, object]]
    calls: list[dict[str, object]]
    complexity: int
    lines_of_code: int
    ast_nodes: int
    error: str  # Optional error field


class LibraryAnalysis(TypedDict, total=False):
    """Type definition for library usage analysis results."""

    file: str
    flext_core_usage: list[dict[str, object]]
    pydantic_usage: list[dict[str, object]]
    standard_lib_usage: list[dict[str, object]]
    external_calls: list[dict[str, object]]
    performance_impact: dict[str, object]
    memory_impact: dict[str, object]
    dependency_graph: list[dict[str, object]]
    error: str  # Optional error field


class CallGraphAnalysis(TypedDict, total=False):
    """Type definition for call graph analysis results."""

    file: str
    internal_calls: list[dict[str, object]]
    external_calls: list[dict[str, object]]
    method_chains: list[dict[str, object]]
    dependency_chain: list[dict[str, object]]
    complexity_score: int
    error: str  # Optional error field


class AggregateStatistics(TypedDict):
    """Type definition for aggregate statistics."""

    total_complexity: int
    total_lines_of_code: int
    total_ast_nodes: int
    total_function_calls: int
    total_classes: int
    total_functions: int


class LibraryUsageSummary(TypedDict):
    """Type definition for library usage summary."""

    flext_core_usage: Counter[str]
    pydantic_usage: Counter[str]
    standard_lib_usage: Counter[str]


class PerformanceSummary(TypedDict):
    """Type definition for performance summary."""

    high_impact_operations: Counter[str]
    medium_impact_operations: Counter[str]
    low_impact_operations: Counter[str]


class CallGraphSummary(TypedDict):
    """Type definition for call graph summary."""

    internal_calls: Counter[str]
    external_calls: Counter[str]
    method_chains: Counter[str]


class ComprehensiveReport(TypedDict):
    """Type definition for comprehensive analysis report."""

    source_directory: str
    total_files: int
    module_analyses: dict[str, dict[str, object]]
    aggregate_statistics: AggregateStatistics
    library_usage_summary: LibraryUsageSummary
    performance_summary: PerformanceSummary
    call_graph_summary: CallGraphSummary
    recommendations: list[str]


class ASTAnalyzer:
    """Comprehensive AST analyzer for Python modules.

    This class provides deep analysis capabilities for examining:
    - Module complexity and structure
    - Library usage patterns and their impact
    - Performance-critical operations
    - Call graph relationships
    - Dependency analysis

    Attributes:
        analysis_results (Dict[str, object]): Storage for analysis results
        performance_critical_ops (List[str]): List of performance-critical operations
        library_usage_patterns (Dict[str, int]): Library usage frequency tracking

    """

    def __init__(self) -> None:
        """Initialize the AST analyzer with default configuration."""
        self.analysis_results: dict[str, object] = {}
        self.performance_critical_ops: list[str] = [
            "read_text",
            "write_text",
            "read",
            "write",  # File I/O operations
            "compile",
            "search",
            "match",  # Regex operations
            "encode",
            "decode",  # Encoding operations
            "split",
            "join",
            "strip",  # String operations
            "len",
            "sum",
            "max",
            "min",  # Collection operations
        ]
        self.library_usage_patterns: dict[str, int] = Counter()

    def analyze_module_ast(self, file_path: str | Path) -> ModuleAnalysis:
        """Perform deep AST analysis of a single Python module.

        This method analyzes the module's structure, imports, classes, functions,
        and performance characteristics using Python's AST module.

        Args:
            file_path (Union[str, Path]): Path to the Python file to analyze

        Returns:
            Dict[str, object]: Comprehensive analysis results including:
                - file: File path
                - imports: List of import statements
                - classes: List of class definitions
                - functions: List of function definitions
                - calls: List of function calls
                - complexity: Complexity metrics
                - lines_of_code: Total lines of code

        Raises:
            FileNotFoundError: If the file doesn't exist
            SyntaxError: If the file contains invalid Python syntax

        Example:
            >>> analyzer = ASTAnalyzer()
            >>> results = analyzer.analyze_module_ast("src/api.py")
            >>> print(f"Complexity: {results['complexity']}")

        """
        try:
            with Path(file_path).open(encoding="utf-8") as f:
                content = f.read()

            tree = ast.parse(content)

            analysis: ModuleAnalysis = {
                "file": str(file_path),
                "imports": [],
                "classes": [],
                "functions": [],
                "calls": [],
                "complexity": 0,
                "lines_of_code": len(content.splitlines()),
                "ast_nodes": len(list(ast.walk(tree))),
            }

            # Walk through all AST nodes to extract information
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    # Handle 'import module' statements
                    for alias in node.names:
                        analysis["imports"].append(
                            {
                                "type": "import",
                                "module": alias.name,
                                "alias": alias.asname,
                                "line": node.lineno,
                            }
                        )

                elif isinstance(node, ast.ImportFrom):
                    # Handle 'from module import name' statements
                    module = node.module or ""
                    for alias in node.names:
                        analysis["imports"].append(
                            {
                                "type": "from_import",
                                "module": module,
                                "name": alias.name,
                                "alias": alias.asname,
                                "line": node.lineno,
                            }
                        )

                elif isinstance(node, ast.ClassDef):
                    # Extract class information
                    analysis["classes"].append(
                        {
                            "name": node.name,
                            "bases": [
                                base.id if isinstance(base, ast.Name) else str(base)
                                for base in node.bases
                            ],
                            "methods": len(
                                [n for n in node.body if isinstance(n, ast.FunctionDef)]
                            ),
                            "line": node.lineno,
                            "decorators": [
                                d.id if isinstance(d, ast.Name) else str(d)
                                for d in node.decorator_list
                            ],
                        }
                    )

                elif isinstance(node, ast.FunctionDef):
                    # Extract function information
                    analysis["functions"].append(
                        {
                            "name": node.name,
                            "args": len(node.args.args),
                            "line": node.lineno,
                            "decorators": [
                                d.id if isinstance(d, ast.Name) else str(d)
                                for d in node.decorator_list
                            ],
                            "is_async": isinstance(node, ast.AsyncFunctionDef),
                        }
                    )

                elif isinstance(node, ast.Call):
                    # Extract function call information
                    call_info = self._extract_call_info(node)
                    if call_info:
                        analysis["calls"].append(call_info)

            # Calculate complexity score
            analysis["complexity"] = self._calculate_complexity_score(analysis)

            return analysis

        except Exception as e:
            return {"error": str(e), "file": str(file_path)}

    def _extract_call_info(self, node: ast.Call) -> dict[str, object] | None:
        """Extract detailed information from a function call node.

        Args:
            node (ast.Call): The AST call node to analyze

        Returns:
            Optional[Dict[str, object]]: Call information or None if extraction fails

        """
        try:
            if isinstance(node.func, ast.Name):
                # Direct function call: function_name()
                return {
                    "function": node.func.id,
                    "line": node.lineno,
                    "args_count": len(node.args),
                    "type": "direct_call",
                }
            if isinstance(node.func, ast.Attribute) and isinstance(
                node.func.value, ast.Name
            ):
                # Method call: object.method()
                return {
                    "function": f"{node.func.value.id}.{node.func.attr}",
                    "object": node.func.value.id,
                    "method": node.func.attr,
                    "line": node.lineno,
                    "args_count": len(node.args),
                    "type": "method_call",
                    "is_performance_critical": node.func.attr
                    in self.performance_critical_ops,
                }
        except Exception as e:
            # Ignore parsing errors for individual nodes - this is intentional
            # Log the exception for debugging purposes
            logger.warning("Failed to parse node: %s", e)
        return None

    def _calculate_complexity_score(self, analysis: ModuleAnalysis) -> int:
        """Calculate a complexity score based on various metrics.

        The complexity score is calculated using:
        - Number of classes (weight: 5)
        - Number of functions (weight: 3)
        - Number of function calls (weight: 1)
        - Number of imports (weight: 2)

        Args:
            analysis (Dict[str, object]): Analysis results to score

        Returns:
            int: Calculated complexity score

        """
        return (
            len(analysis.get("classes", [])) * 5
            + len(analysis.get("functions", [])) * 3
            + len(analysis.get("calls", [])) * 1
            + len(analysis.get("imports", [])) * 2
        )

    def analyze_library_usage(self, file_path: str | Path) -> LibraryAnalysis:
        """Analyze library usage patterns and their profound impact.

        This method focuses on understanding how different libraries are used
        and their impact on the module's functionality and performance.

        Args:
            file_path (Union[str, Path]): Path to the Python file to analyze

        Returns:
            Dict[str, object]: Library usage analysis including:
                - flext_core_usage: Flext-core library usage
                - pydantic_usage: Pydantic library usage
                - standard_lib_usage: Standard library usage
                - external_calls: External library calls
                - performance_impact: Performance-critical operations

        Example:
            >>> analyzer = ASTAnalyzer()
            >>> lib_analysis = analyzer.analyze_library_usage("src/processor.py")
            >>> print(f"Flext-core usage: {len(lib_analysis['flext_core_usage'])}")

        """
        try:
            with Path(file_path).open(encoding="utf-8") as f:
                content = f.read()

            tree = ast.parse(content)

            analysis: LibraryAnalysis = {
                "file": str(file_path),
                "flext_core_usage": [],
                "pydantic_usage": [],
                "standard_lib_usage": [],
                "external_calls": [],
                "performance_impact": {},
                "memory_impact": {},
                "dependency_graph": [],
            }

            # Analyze imports and their usage patterns
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    module = node.module or ""

                    # Categorize imports by library type
                    if module.startswith("flext_core"):
                        for alias in node.names:
                            analysis["flext_core_usage"].append(
                                {
                                    "module": module,
                                    "name": alias.name,
                                    "alias": alias.asname,
                                    "line": node.lineno,
                                    "impact_level": self._assess_flext_core_impact(
                                        alias.name
                                    ),
                                }
                            )
                    elif module.startswith("pydantic"):
                        for alias in node.names:
                            analysis["pydantic_usage"].append(
                                {
                                    "module": module,
                                    "name": alias.name,
                                    "alias": alias.asname,
                                    "line": node.lineno,
                                    "impact_level": self._assess_pydantic_impact(
                                        alias.name
                                    ),
                                }
                            )
                    elif module in {
                        "os",
                        "re",
                        "pathlib",
                        "datetime",
                        "typing",
                        "collections",
                    }:
                        for alias in node.names:
                            analysis["standard_lib_usage"].append(
                                {
                                    "module": module,
                                    "name": alias.name,
                                    "alias": alias.asname,
                                    "line": node.lineno,
                                    "impact_level": self._assess_standard_lib_impact(
                                        alias.name
                                    ),
                                }
                            )

                elif isinstance(node, ast.Call):
                    # Analyze function calls for performance impact
                    call_analysis = self._analyze_call_performance(node)
                    if call_analysis:
                        analysis["performance_impact"].update(call_analysis)

            return analysis

        except Exception as e:
            return {"error": str(e), "file": str(file_path)}

    def _assess_flext_core_impact(self, component_name: str) -> str:
        """Assess the impact level of flext-core components.

        Args:
            component_name (str): Name of the flext-core component

        Returns:
            str: Impact level ('high', 'medium', 'low')

        """
        high_impact = ["FlextResult", "FlextService", "FlextContainer"]
        medium_impact = ["FlextLogger", "FlextConfig", "FlextModels"]

        if component_name in high_impact:
            return "high"
        if component_name in medium_impact:
            return "medium"
        return "low"

    def _assess_pydantic_impact(self, component_name: str) -> str:
        """Assess the impact level of Pydantic components.

        Args:
            component_name (str): Name of the Pydantic component

        Returns:
            str: Impact level ('high', 'medium', 'low')

        """
        high_impact = ["BaseModel", "Field"]
        medium_impact = ["field_validator", "model_validator"]

        if component_name in high_impact:
            return "high"
        if component_name in medium_impact:
            return "medium"
        return "low"

    def _assess_standard_lib_impact(self, component_name: str) -> str:
        """Assess the impact level of standard library components.

        Args:
            component_name (str): Name of the standard library component

        Returns:
            str: Impact level ('high', 'medium', 'low')

        """
        high_impact = ["Path", "datetime", "re"]
        medium_impact = ["os", "typing"]

        if component_name in high_impact:
            return "high"
        if component_name in medium_impact:
            return "medium"
        return "low"

    def _analyze_call_performance(self, node: ast.Call) -> dict[str, object] | None:
        """Analyze the performance impact of a function call.

        Args:
            node (ast.Call): The AST call node to analyze

        Returns:
            Optional[Dict[str, object]]: Performance analysis or None

        """
        if isinstance(node.func, ast.Attribute) and isinstance(
            node.func.value, ast.Name
        ):
            obj_name = node.func.value.id
            method_name = node.func.attr

            # Categorize performance impact
            if method_name in {"read_text", "write_text", "read", "write"}:
                return {
                    f"{obj_name}.{method_name}": {
                        "line": node.lineno,
                        "type": "file_io",
                        "impact": "high",
                        "description": "File I/O operation - high performance impact",
                    }
                }
            if method_name in {"compile", "search", "match"}:
                return {
                    f"{obj_name}.{method_name}": {
                        "line": node.lineno,
                        "type": "regex",
                        "impact": "medium",
                        "description": "Regex operation - medium performance impact",
                    }
                }
            if method_name in {"encode", "decode"}:
                return {
                    f"{obj_name}.{method_name}": {
                        "line": node.lineno,
                        "type": "encoding",
                        "impact": "medium",
                        "description": "Encoding operation - medium performance impact",
                    }
                }

        return None

    def analyze_call_graph(self, file_path: str | Path) -> CallGraphAnalysis:
        """Analyze call graph relationships and dependencies.

        This method examines the relationships between different function calls
        and their impact on code complexity and maintainability.

        Args:
            file_path (Union[str, Path]): Path to the Python file to analyze

        Returns:
            Dict[str, object]: Call graph analysis including:
                - internal_calls: Self-referential method calls
                - external_calls: External library calls
                - method_chains: Complex method chaining
                - complexity_score: Calculated complexity score

        Example:
            >>> analyzer = ASTAnalyzer()
            >>> call_graph = analyzer.analyze_call_graph("src/api.py")
            >>> print(f"Internal calls: {len(call_graph['internal_calls'])}")

        """
        try:
            with Path(file_path).open(encoding="utf-8") as f:
                content = f.read()

            tree = ast.parse(content)

            analysis: CallGraphAnalysis = {
                "file": str(file_path),
                "internal_calls": [],
                "external_calls": [],
                "method_chains": [],
                "dependency_chain": [],
                "complexity_score": 0,
            }

            # Analyze method calls and their relationships
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    call_info = self._extract_call_graph_info(node)
                    if call_info:
                        # Categorize calls as internal or external
                        if call_info.get("is_internal", False):
                            analysis["internal_calls"].append(call_info)
                        else:
                            analysis["external_calls"].append(call_info)

                        # Check for method chains
                        if self._is_method_chain(node):
                            analysis["method_chains"].append(
                                {
                                    "chain": call_info.get("function", "unknown"),
                                    "line": node.lineno,
                                    "complexity": "high",
                                }
                            )

            # Calculate complexity score
            analysis["complexity_score"] = (
                len(analysis["internal_calls"]) * 1
                + len(analysis["external_calls"]) * 2
                + len(analysis["method_chains"]) * 3
            )

            return analysis

        except Exception as e:
            return {"error": str(e), "file": str(file_path)}

    def _extract_call_graph_info(self, node: ast.Call) -> dict[str, object] | None:
        """Extract call graph information from an AST call node.

        Args:
            node (ast.Call): The AST call node to analyze

        Returns:
            Optional[Dict[str, object]]: Call graph information or None

        """
        try:
            if isinstance(node.func, ast.Attribute):
                # Method call on object
                if isinstance(node.func.value, ast.Name):
                    obj_name = node.func.value.id
                    method_name = node.func.attr

                    return {
                        "type": "method_call",
                        "object": obj_name,
                        "method": method_name,
                        "function": f"{obj_name}.{method_name}",
                        "line": node.lineno,
                        "args_count": len(node.args),
                        "is_internal": obj_name.startswith(("self", "_")),
                    }
            elif isinstance(node.func, ast.Name):
                # Direct function call
                func_name = node.func.id
                return {
                    "type": "function_call",
                    "function": func_name,
                    "line": node.lineno,
                    "args_count": len(node.args),
                    "is_internal": func_name.startswith("_"),
                }
        except Exception as e:
            # Ignore parsing errors for individual nodes - this is intentional
            # Log the exception for debugging purposes
            logger.warning("Failed to parse node: %s", e)
        return None

    def _is_method_chain(self, node: ast.Call) -> bool:
        """Check if a call node represents a method chain.

        Args:
            node (ast.Call): The AST call node to check

        Returns:
            bool: True if the call is part of a method chain

        """
        # Simple heuristic: check if the function is an attribute access
        # and if the value is another call
        if isinstance(node.func, ast.Attribute) and hasattr(node.func.value, "value"):
            value = getattr(node.func.value, "value", None)
            return isinstance(value, ast.Call)
        return False

    def generate_comprehensive_report(
        self, source_directory: str | Path
    ) -> ComprehensiveReport:
        """Generate a comprehensive analysis report for all Python files in a directory.

        This method analyzes all Python files in the specified directory and
        generates a comprehensive report with aggregate statistics and insights.

        Args:
            source_directory (Union[str, Path]): Directory containing Python files

        Returns:
            Dict[str, object]: Comprehensive analysis report including:
                - module_analyses: Individual module analyses
                - aggregate_statistics: Overall project statistics
                - library_usage_summary: Library usage patterns
                - performance_summary: Performance characteristics
                - recommendations: Analysis recommendations

        Example:
            >>> analyzer = ASTAnalyzer()
            >>> report = analyzer.generate_comprehensive_report("src/")
            >>> print(
            ...     f"Total complexity: "
            ...     f"{report['aggregate_statistics']['total_complexity']}"
            ... )

        """
        source_path = Path(source_directory)
        python_files = list(source_path.rglob("*.py"))

        report: ComprehensiveReport = {
            "source_directory": str(source_path),
            "total_files": len(python_files),
            "module_analyses": {},
            "aggregate_statistics": {
                "total_complexity": 0,
                "total_lines_of_code": 0,
                "total_ast_nodes": 0,
                "total_function_calls": 0,
                "total_classes": 0,
                "total_functions": 0,
            },
            "library_usage_summary": {
                "flext_core_usage": Counter(),
                "pydantic_usage": Counter(),
                "standard_lib_usage": Counter(),
            },
            "performance_summary": {
                "high_impact_operations": Counter(),
                "medium_impact_operations": Counter(),
                "low_impact_operations": Counter(),
            },
            "call_graph_summary": {
                "internal_calls": Counter(),
                "external_calls": Counter(),
                "method_chains": Counter(),
            },
            "recommendations": [],
        }

        # Analyze each Python file
        for file_path in python_files:
            # Perform comprehensive analysis
            module_analysis = self.analyze_module_ast(file_path)
            library_analysis = self.analyze_library_usage(file_path)
            call_graph_analysis = self.analyze_call_graph(file_path)

            # Store individual analysis
            report["module_analyses"][file_path.name] = {
                "module_analysis": module_analysis,
                "library_analysis": library_analysis,
                "call_graph_analysis": call_graph_analysis,
            }

            # Update aggregate statistics
            if "error" not in module_analysis:
                report["aggregate_statistics"][
                    "total_complexity"
                ] += module_analysis.get("complexity", 0)
                report["aggregate_statistics"][
                    "total_lines_of_code"
                ] += module_analysis.get("lines_of_code", 0)
                report["aggregate_statistics"][
                    "total_ast_nodes"
                ] += module_analysis.get("ast_nodes", 0)
                report["aggregate_statistics"]["total_function_calls"] += len(
                    module_analysis.get("calls", [])
                )
                report["aggregate_statistics"]["total_classes"] += len(
                    module_analysis.get("classes", [])
                )
                report["aggregate_statistics"]["total_functions"] += len(
                    module_analysis.get("functions", [])
                )

            # Update library usage summary
            if "error" not in library_analysis:
                for usage in library_analysis.get("flext_core_usage", []):
                    report["library_usage_summary"]["flext_core_usage"][
                        f"{usage['module']}.{usage['name']}"
                    ] += 1

                for usage in library_analysis.get("pydantic_usage", []):
                    report["library_usage_summary"]["pydantic_usage"][
                        f"{usage['module']}.{usage['name']}"
                    ] += 1

                for usage in library_analysis.get("standard_lib_usage", []):
                    report["library_usage_summary"]["standard_lib_usage"][
                        f"{usage['module']}.{usage['name']}"
                    ] += 1

            # Update performance summary
            if "error" not in library_analysis:
                performance_impact = library_analysis.get("performance_impact", {})
                for call, details in performance_impact.items():
                    if isinstance(details, dict) and "impact" in details:
                        impact_level = details["impact"]
                        if impact_level == "high":
                            report["performance_summary"]["high_impact_operations"][
                                call
                            ] += 1
                        elif impact_level == "medium":
                            report["performance_summary"]["medium_impact_operations"][
                                call
                            ] += 1
                    else:
                        report["performance_summary"]["low_impact_operations"][
                            call
                        ] += 1

            # Update call graph summary
            if "error" not in call_graph_analysis:
                internal_calls = call_graph_analysis.get("internal_calls", [])
                for call in internal_calls:
                    if isinstance(call, dict) and "function" in call:
                        function_value = call["function"]
                        if isinstance(function_value, str):
                            function_name = function_value
                        else:
                            function_name = str(function_value)
                        report["call_graph_summary"]["internal_calls"][
                            function_name
                        ] += 1

                external_calls = call_graph_analysis.get("external_calls", [])
                for call in external_calls:
                    if isinstance(call, dict) and "function" in call:
                        function_value = call["function"]
                        if isinstance(function_value, str):
                            function_name = function_value
                        else:
                            function_name = str(function_value)
                        report["call_graph_summary"]["external_calls"][
                            function_name
                        ] += 1

        # Generate recommendations
        report["recommendations"] = self._generate_recommendations(report)

        return report

    def _generate_recommendations(self, report: ComprehensiveReport) -> list[str]:
        """Generate recommendations based on the analysis results.

        Args:
            report (Dict[str, object]): The comprehensive analysis report

        Returns:
            List[str]: List of recommendations

        """
        recommendations: list[str] = []

        # Analyze complexity distribution
        total_complexity = report["aggregate_statistics"]["total_complexity"]
        high_complexity_threshold = 1000
        if total_complexity > high_complexity_threshold:
            recommendations.append(
                "Consider refactoring modules with high complexity scores"
            )

        # Analyze library usage patterns
        flext_core_usage = report["library_usage_summary"]["flext_core_usage"]
        min_flext_core_usage = 5
        if len(flext_core_usage) < min_flext_core_usage:
            recommendations.append(
                "Consider increasing flext-core integration for better consistency"
            )

        # Analyze performance characteristics
        high_impact_ops = report["performance_summary"]["high_impact_operations"]
        max_high_impact_ops = 10
        if len(high_impact_ops) > max_high_impact_ops:
            recommendations.append(
                "Review high-impact operations for optimization opportunities"
            )

        # Analyze call patterns
        internal_calls = report["call_graph_summary"]["internal_calls"]
        external_calls = report["call_graph_summary"]["external_calls"]
        if len(external_calls) > len(internal_calls) * 2:
            recommendations.append(
                "Consider reducing external dependencies for better maintainability"
            )

        return recommendations


def main() -> None:
    """Main function to run the AST analysis.

    This function demonstrates how to use the ASTAnalyzer class to perform
    comprehensive analysis of the flext-ldif project.
    """
    # Initialize analyzer
    analyzer = ASTAnalyzer()

    # Analyze the source directory
    source_dir = Path("src")
    if not source_dir.exists():
        return

    # Generate comprehensive report
    report = analyzer.generate_comprehensive_report(source_dir)

    # Print summary

    # Print library usage summary
    for _component, _count in report["library_usage_summary"][
        "flext_core_usage"
    ].most_common(5):
        pass

    for _component, _count in report["library_usage_summary"][
        "pydantic_usage"
    ].most_common(5):
        pass

    # Print performance summary
    for _operation, _count in report["performance_summary"][
        "high_impact_operations"
    ].most_common(5):
        pass

    # Print recommendations
    for _i, _recommendation in enumerate(report["recommendations"], 1):
        pass


if __name__ == "__main__":
    main()
