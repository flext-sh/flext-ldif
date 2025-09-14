# FLEXT Ecosystem Integration Examples

**Version**: 0.9.0 | **Updated**: September 17, 2025

This document provides practical examples of integrating FLEXT-LDIF with other components of the FLEXT ecosystem, demonstrating real-world usage patterns and best practices.

## Integration with flext-core

### FlextContainer Service Registration

```python
from flext_core import FlextContainer, FlextResult, FlextLogger
from flext_ldif import FlextLDIFAPI, FlextLDIFModels

def bootstrap_ldif_services() -> FlextResult[None]:
    """Bootstrap LDIF services in the global container."""
    container = FlextContainer.get_global()
    logger = FlextLogger(__name__)

    # Register configuration
    config = FlextLDIFModels.Config(
        max_entries=100000,
        strict_validation=True,
        encoding='utf-8'
    )

    config_result = container.register("ldif_config", config)
    if config_result.is_failure:
        logger.error("Failed to register LDIF configuration", extra={
            'error': config_result.error,
            'service': 'ldif_bootstrap'
        })
        return config_result

    # Register LDIF API
    api = FlextLDIFAPI(config=config)
    api_result = container.register("ldif_api", api)

    if api_result.is_failure:
        logger.error("Failed to register LDIF API", extra={
            'error': api_result.error,
            'service': 'ldif_bootstrap'
        })
        return api_result

    logger.info("LDIF services registered successfully", extra={
        'services': ['ldif_config', 'ldif_api'],
        'service': 'ldif_bootstrap'
    })

    return FlextResult[None].ok(None)

class LdifDependentService:
    """Service that depends on LDIF functionality."""

    def __init__(self) -> None:
        self._logger = FlextLogger(__name__)
        self._container = FlextContainer.get_global()

    def get_ldif_api(self) -> FlextResult[FlextLDIFAPI]:
        """Retrieve LDIF API from container."""
        api_result = self._container.get("ldif_api")
        if api_result.is_failure:
            self._logger.error("LDIF API not available", extra={
                'error': api_result.error,
                'service': 'ldif_dependent'
            })

        return api_result

    def process_directory_data(self, ldif_content: str) -> FlextResult[dict]:
        """Process directory data using containerized LDIF API."""
        api_result = self.get_ldif_api()
        if api_result.is_failure:
            return FlextResult[dict].fail(api_result.error)

        api = api_result.unwrap()

        return (
            api.parse_string(ldif_content)
            .flat_map(api.validate_entries)
            .flat_map(api.filter_persons)
            .flat_map(lambda persons: api.get_entry_statistics(persons)
                      .map(lambda stats: {
                          'person_count': len(persons),
                          'statistics': stats
                      }))
            .map_error(lambda error: f"Directory processing failed: {error}")
        )

# Usage example
def example_container_integration():
    """Example of container-based service integration."""
    # Bootstrap services
    bootstrap_result = bootstrap_ldif_services()
    if bootstrap_result.is_failure:
        print(f"Bootstrap failed: {bootstrap_result.error}")
        return

    # Use dependent service
    dependent_service = LdifDependentService()

    sample_ldif = """dn: cn=John Doe,ou=People,dc=company,dc=com
cn: John Doe
sn: Doe
objectClass: person
mail: john.doe@company.com
"""

    result = dependent_service.process_directory_data(sample_ldif)
    if result.is_success:
        data = result.unwrap()
        print(f"Processed {data['person_count']} persons")
        print(f"Statistics: {data['statistics']}")
```

### Railway-Oriented Integration

```python
from flext_core import FlextResult
from flext_ldif import FlextLDIFAPI
from pathlib import Path

def comprehensive_directory_processing(
    input_file: Path,
    output_file: Path,
    validation_rules: dict
) -> FlextResult[dict]:
    """Comprehensive directory processing using railway patterns."""
    api = FlextLDIFAPI()

    return (
        # Parse input file
        api.parse_file(input_file)
        .map(lambda entries: {
            'entries': entries,
            'stage': 'parsed',
            'count': len(entries)
        })

        # Apply validation
        .flat_map(lambda data:
            api.validate_entries(data['entries'])
            .map(lambda _: {**data, 'stage': 'validated'}))

        # Apply custom business rules
        .flat_map(lambda data:
            apply_business_rules(data['entries'], validation_rules)
            .map(lambda validated_entries: {
                **data,
                'entries': validated_entries,
                'stage': 'business_validated'
            }))

        # Filter and categorize
        .flat_map(lambda data:
            categorize_entries(api, data['entries'])
            .map(lambda categories: {
                **data,
                'categories': categories,
                'stage': 'categorized'
            }))

        # Generate output
        .flat_map(lambda data:
            api.write_file(data['entries'], output_file)
            .map(lambda _: {
                **data,
                'output_file': str(output_file),
                'stage': 'completed'
            }))

        # Generate final report
        .map(generate_processing_report)

        # Handle errors with context
        .map_error(lambda error:
            f"Directory processing failed at stage {error}: {input_file}")
    )

def apply_business_rules(entries: list, rules: dict) -> FlextResult[list]:
    """Apply custom business validation rules."""
    valid_entries = []
    validation_errors = []

    for entry in entries:
        if validate_entry_against_rules(entry, rules):
            valid_entries.append(entry)
        else:
            validation_errors.append(entry.dn)

    if validation_errors and rules.get('strict_mode', False):
        return FlextResult[list].fail(
            f"Business rule validation failed for {len(validation_errors)} entries"
        )

    return FlextResult[list].ok(valid_entries)

def validate_entry_against_rules(entry, rules: dict) -> bool:
    """Validate individual entry against business rules."""
    # Example business rules
    if rules.get('require_email_domain') and entry.is_person():
        emails = entry.get_attribute_values('mail')
        required_domain = rules['require_email_domain']
        if not any(email.endswith(f'@{required_domain}') for email in emails):
            return False

    if rules.get('require_department') and entry.is_person():
        departments = entry.get_attribute_values('department')
        if not departments:
            return False

    return True

def categorize_entries(api: FlextLDIFAPI, entries: list) -> FlextResult[dict]:
    """Categorize entries by type."""
    try:
        categories = {}

        # Get persons
        persons_result = api.filter_persons(entries)
        if persons_result.is_success:
            categories['persons'] = persons_result.unwrap()

        # Get groups
        groups_result = api.filter_groups(entries)
        if groups_result.is_success:
            categories['groups'] = groups_result.unwrap()

        # Get organizational units
        ou_result = api.filter_by_objectclass(entries, "organizationalUnit")
        if ou_result.is_success:
            categories['organizational_units'] = ou_result.unwrap()

        return FlextResult[dict].ok(categories)
    except Exception as e:
        return FlextResult[dict].fail(f"Categorization failed: {e}")

def generate_processing_report(data: dict) -> dict:
    """Generate comprehensive processing report."""
    categories = data.get('categories', {})

    return {
        'processing_summary': {
            'input_entries': data['count'],
            'output_file': data['output_file'],
            'processing_stage': data['stage']
        },
        'categorization': {
            'persons': len(categories.get('persons', [])),
            'groups': len(categories.get('groups', [])),
            'organizational_units': len(categories.get('organizational_units', []))
        },
        'status': 'completed'
    }
```

## Integration with flext-api

### REST API Endpoints

```python
from flext_api import FlextAPIService, APIEndpoint
from flext_core import FlextResult
from flext_ldif import FlextLDIFAPI
from typing import Any

class LdifAPIService(FlextAPIService):
    """REST API service for LDIF operations."""

    def __init__(self) -> None:
        super().__init__()
        self._ldif_api = FlextLDIFAPI()

    @APIEndpoint(method="POST", path="/ldif/parse")
    def parse_ldif_endpoint(self, request_data: dict) -> FlextResult[dict]:
        """API endpoint for parsing LDIF content."""
        ldif_content = request_data.get('ldif_content')
        if not ldif_content:
            return FlextResult[dict].fail("Missing ldif_content in request")

        return (
            self._ldif_api.parse_string(ldif_content)
            .map(self._serialize_entries_response)
            .map_error(lambda error: f"Parse operation failed: {error}")
        )

    @APIEndpoint(method="POST", path="/ldif/validate")
    def validate_ldif_endpoint(self, request_data: dict) -> FlextResult[dict]:
        """API endpoint for validating LDIF entries."""
        ldif_content = request_data.get('ldif_content')
        strict_validation = request_data.get('strict_validation', False)

        if not ldif_content:
            return FlextResult[dict].fail("Missing ldif_content in request")

        # Configure validation
        config = self._ldif_api._config
        if strict_validation != config.strict_validation:
            from flext_ldif import FlextLDIFModels
            validation_config = FlextLDIFModels.Config(
                **config.model_dump(),
                strict_validation=strict_validation
            )
            validation_api = FlextLDIFAPI(config=validation_config)
        else:
            validation_api = self._ldif_api

        return (
            validation_api.parse_string(ldif_content)
            .flat_map(validation_api.validate_entries)
            .map(lambda is_valid: {
                'status': 'success',
                'validation_result': is_valid,
                'message': 'Validation completed successfully'
            })
            .map_error(lambda error: f"Validation failed: {error}")
        )

    @APIEndpoint(method="POST", path="/ldif/filter")
    def filter_ldif_endpoint(self, request_data: dict) -> FlextResult[dict]:
        """API endpoint for filtering LDIF entries."""
        ldif_content = request_data.get('ldif_content')
        filter_type = request_data.get('filter_type', 'persons')

        if not ldif_content:
            return FlextResult[dict].fail("Missing ldif_content in request")

        return (
            self._ldif_api.parse_string(ldif_content)
            .flat_map(lambda entries: self._apply_filter(entries, filter_type))
            .map(self._serialize_entries_response)
            .map_error(lambda error: f"Filter operation failed: {error}")
        )

    @APIEndpoint(method="POST", path="/ldif/analyze")
    def analyze_ldif_endpoint(self, request_data: dict) -> FlextResult[dict]:
        """API endpoint for analyzing LDIF content."""
        ldif_content = request_data.get('ldif_content')

        if not ldif_content:
            return FlextResult[dict].fail("Missing ldif_content in request")

        return (
            self._ldif_api.parse_string(ldif_content)
            .flat_map(self._generate_comprehensive_analysis)
            .map_error(lambda error: f"Analysis failed: {error}")
        )

    def _apply_filter(self, entries: list, filter_type: str) -> FlextResult[list]:
        """Apply specified filter to entries."""
        filter_methods = {
            'persons': self._ldif_api.filter_persons,
            'groups': self._ldif_api.filter_groups,
            'organizational_units': lambda entries: self._ldif_api.filter_by_objectclass(entries, "organizationalUnit")
        }

        filter_method = filter_methods.get(filter_type)
        if not filter_method:
            return FlextResult[list].fail(f"Unknown filter type: {filter_type}")

        return filter_method(entries)

    def _serialize_entries_response(self, entries: list) -> dict:
        """Serialize entries for API response."""
        return {
            'status': 'success',
            'entry_count': len(entries),
            'entries': [
                {
                    'dn': entry.dn,
                    'object_classes': entry.get_object_classes(),
                    'attributes': {
                        key: values[:3]  # Limit attribute values for API response
                        for key, values in entry.attributes.items()
                    },
                    'is_person': entry.is_person(),
                    'is_group': entry.is_group()
                }
                for entry in entries[:100]  # Limit response size
            ],
            'has_more': len(entries) > 100
        }

    def _generate_comprehensive_analysis(self, entries: list) -> FlextResult[dict]:
        """Generate comprehensive analysis of LDIF entries."""
        try:
            # Basic statistics
            stats_result = self._ldif_api.get_entry_statistics(entries)
            stats = stats_result.unwrap() if stats_result.is_success else {}

            # Entry type analysis
            persons = self._ldif_api.filter_persons(entries).unwrap_or([])
            groups = self._ldif_api.filter_groups(entries).unwrap_or([])

            # Attribute analysis
            all_attributes = set()
            attribute_usage = {}

            for entry in entries:
                for attr_name in entry.attributes.keys():
                    all_attributes.add(attr_name)
                    attribute_usage[attr_name] = attribute_usage.get(attr_name, 0) + 1

            return FlextResult[dict].ok({
                'status': 'success',
                'analysis': {
                    'total_entries': len(entries),
                    'entry_types': {
                        'persons': len(persons),
                        'groups': len(groups),
                        'other': len(entries) - len(persons) - len(groups)
                    },
                    'object_class_distribution': stats,
                    'attribute_analysis': {
                        'total_attributes': len(all_attributes),
                        'most_common_attributes': sorted(
                            attribute_usage.items(),
                            key=lambda x: x[1],
                            reverse=True
                        )[:10]
                    }
                }
            })
        except Exception as e:
            return FlextResult[dict].fail(f"Analysis generation failed: {e}")

# API usage example
def create_ldif_api_service() -> LdifAPIService:
    """Create and configure LDIF API service."""
    service = LdifAPIService()

    # Additional endpoint configuration could go here
    return service

# Example API client usage
def example_api_client_usage():
    """Example of using the LDIF API endpoints."""
    import requests
    import json

    # Sample LDIF data for testing
    sample_request = {
        'ldif_content': """dn: cn=John Doe,ou=People,dc=company,dc=com
cn: John Doe
sn: Doe
objectClass: person
objectClass: employee
mail: john.doe@company.com

dn: cn=Developers,ou=Groups,dc=company,dc=com
cn: Developers
objectClass: groupOfNames
member: cn=John Doe,ou=People,dc=company,dc=com
"""
    }

    # Parse LDIF
    parse_response = requests.post(
        'http://api.flext.com/ldif/parse',
        json=sample_request,
        headers={'Content-Type': 'application/json'}
    )

    if parse_response.status_code == 200:
        parse_data = parse_response.json()
        print(f"Parsed {parse_data['entry_count']} entries")

    # Analyze LDIF
    analyze_response = requests.post(
        'http://api.flext.com/ldif/analyze',
        json=sample_request,
        headers={'Content-Type': 'application/json'}
    )

    if analyze_response.status_code == 200:
        analysis_data = analyze_response.json()
        print(f"Analysis: {analysis_data['analysis']}")
```

## Integration with flext-cli

### Command Line Interface Integration

```python
from flext_cli import FlextCLIService, CLICommand, CLIOption
from flext_core import FlextResult
from flext_ldif import FlextLDIFAPI, FlextLDIFModels
from pathlib import Path
import json

class LdifCLIService(FlextCLIService):
    """CLI service for LDIF operations."""

    def __init__(self) -> None:
        super().__init__()
        self._ldif_api = FlextLDIFAPI()

    @CLICommand(name="parse", help="Parse LDIF file and display information")
    @CLIOption("--input", "-i", required=True, help="Input LDIF file path")
    @CLIOption("--output", "-o", help="Output file for parsed data (JSON)")
    @CLIOption("--format", default="summary", help="Output format: summary, json, detailed")
    def parse_command(self, input: str, output: str = None, format: str = "summary") -> FlextResult[None]:
        """Parse LDIF file with various output options."""
        input_path = Path(input)

        if not input_path.exists():
            return FlextResult[None].fail(f"Input file not found: {input}")

        return (
            self._ldif_api.parse_file(input_path)
            .flat_map(lambda entries: self._format_parse_output(entries, format, output))
        )

    @CLICommand(name="validate", help="Validate LDIF file against RFC 2849")
    @CLIOption("--input", "-i", required=True, help="Input LDIF file path")
    @CLIOption("--strict", is_flag=True, help="Enable strict validation mode")
    @CLIOption("--report", help="Generate validation report file")
    def validate_command(self, input: str, strict: bool = False, report: str = None) -> FlextResult[None]:
        """Validate LDIF file with detailed reporting."""
        input_path = Path(input)

        # Configure validation
        config = FlextLDIFModels.Config(
            strict_validation=strict,
            ignore_unknown_attributes=not strict
        )
        validation_api = FlextLDIFAPI(config=config)

        return (
            validation_api.parse_file(input_path)
            .flat_map(validation_api.validate_entries)
            .flat_map(lambda is_valid: self._generate_validation_report(
                input_path, is_valid, strict, report))
        )

    @CLICommand(name="filter", help="Filter LDIF entries by type")
    @CLIOption("--input", "-i", required=True, help="Input LDIF file path")
    @CLIOption("--output", "-o", required=True, help="Output LDIF file path")
    @CLIOption("--type", default="persons", help="Filter type: persons, groups, ou")
    @CLIOption("--count", is_flag=True, help="Show count only, don't write file")
    def filter_command(self, input: str, output: str, type: str = "persons", count: bool = False) -> FlextResult[None]:
        """Filter LDIF entries by specified type."""
        input_path = Path(input)
        output_path = Path(output)

        return (
            self._ldif_api.parse_file(input_path)
            .flat_map(lambda entries: self._apply_cli_filter(entries, type))
            .flat_map(lambda filtered: self._handle_filter_output(
                filtered, output_path, count, type))
        )

    @CLICommand(name="analyze", help="Analyze LDIF file structure and content")
    @CLIOption("--input", "-i", required=True, help="Input LDIF file path")
    @CLIOption("--detailed", is_flag=True, help="Show detailed analysis")
    @CLIOption("--export", help="Export analysis to JSON file")
    def analyze_command(self, input: str, detailed: bool = False, export: str = None) -> FlextResult[None]:
        """Analyze LDIF file structure and generate statistics."""
        input_path = Path(input)

        return (
            self._ldif_api.parse_file(input_path)
            .flat_map(lambda entries: self._generate_analysis(entries, detailed))
            .flat_map(lambda analysis: self._output_analysis(analysis, export))
        )

    @CLICommand(name="convert", help="Convert between LDIF formats")
    @CLIOption("--input", "-i", required=True, help="Input LDIF file path")
    @CLIOption("--output", "-o", required=True, help="Output file path")
    @CLIOption("--normalize", is_flag=True, help="Normalize entry formatting")
    @CLIOption("--encoding", default="utf-8", help="Output encoding")
    def convert_command(self, input: str, output: str, normalize: bool = False, encoding: str = "utf-8") -> FlextResult[None]:
        """Convert LDIF file with optional normalization."""
        input_path = Path(input)
        output_path = Path(output)

        config = FlextLDIFModels.Config(encoding=encoding)
        convert_api = FlextLDIFAPI(config=config)

        return (
            convert_api.parse_file(input_path)
            .flat_map(lambda entries: self._apply_normalization(entries) if normalize else FlextResult[list].ok(entries))
            .flat_map(lambda entries: convert_api.write_file(entries, output_path))
            .map(lambda _: self._log_conversion_success(input_path, output_path, normalize))
        )

    def _format_parse_output(self, entries: list, format: str, output_file: str = None) -> FlextResult[None]:
        """Format and output parsing results."""
        try:
            if format == "summary":
                output_text = self._create_summary_output(entries)
            elif format == "json":
                output_text = self._create_json_output(entries)
            elif format == "detailed":
                output_text = self._create_detailed_output(entries)
            else:
                return FlextResult[None].fail(f"Unknown output format: {format}")

            if output_file:
                Path(output_file).write_text(output_text, encoding='utf-8')
                print(f"Output written to: {output_file}")
            else:
                print(output_text)

            return FlextResult[None].ok(None)
        except Exception as e:
            return FlextResult[None].fail(f"Output formatting failed: {e}")

    def _create_summary_output(self, entries: list) -> str:
        """Create summary output for entries."""
        stats_result = self._ldif_api.get_entry_statistics(entries)
        stats = stats_result.unwrap() if stats_result.is_success else {}

        output_lines = [
            f"LDIF Parse Summary",
            f"==================",
            f"Total entries: {len(entries)}",
            f"",
            f"Object Class Distribution:"
        ]

        for obj_class, count in sorted(stats.items()):
            output_lines.append(f"  {obj_class}: {count}")

        # Entry type summary
        persons = self._ldif_api.filter_persons(entries).unwrap_or([])
        groups = self._ldif_api.filter_groups(entries).unwrap_or([])

        output_lines.extend([
            f"",
            f"Entry Types:",
            f"  Persons: {len(persons)}",
            f"  Groups: {len(groups)}",
            f"  Other: {len(entries) - len(persons) - len(groups)}"
        ])

        return "\n".join(output_lines)

    def _create_json_output(self, entries: list) -> str:
        """Create JSON output for entries."""
        data = {
            'total_entries': len(entries),
            'entries': [
                {
                    'dn': entry.dn,
                    'object_classes': entry.get_object_classes(),
                    'attribute_count': len(entry.attributes),
                    'is_person': entry.is_person(),
                    'is_group': entry.is_group()
                }
                for entry in entries
            ]
        }

        return json.dumps(data, indent=2)

    def _create_detailed_output(self, entries: list) -> str:
        """Create detailed output for entries."""
        output_lines = [f"LDIF Detailed Analysis", f"====================="]

        for i, entry in enumerate(entries, 1):
            output_lines.extend([
                f"",
                f"Entry {i}: {entry.dn}",
                f"Object Classes: {', '.join(entry.get_object_classes())}",
                f"Attributes ({len(entry.attributes)}):"
            ])

            for attr_name, attr_values in entry.attributes.items():
                values_preview = attr_values[:3]  # Show first 3 values
                more_indicator = f" (+{len(attr_values)-3} more)" if len(attr_values) > 3 else ""
                output_lines.append(f"  {attr_name}: {values_preview}{more_indicator}")

        return "\n".join(output_lines)

    def _apply_cli_filter(self, entries: list, filter_type: str) -> FlextResult[list]:
        """Apply CLI filter to entries."""
        filter_methods = {
            'persons': self._ldif_api.filter_persons,
            'groups': self._ldif_api.filter_groups,
            'ou': lambda entries: self._ldif_api.filter_by_objectclass(entries, "organizationalUnit")
        }

        filter_method = filter_methods.get(filter_type)
        if not filter_method:
            return FlextResult[list].fail(f"Unknown filter type: {filter_type}")

        return filter_method(entries)

    def _handle_filter_output(self, filtered_entries: list, output_path: Path, count_only: bool, filter_type: str) -> FlextResult[None]:
        """Handle filter command output."""
        if count_only:
            print(f"Found {len(filtered_entries)} {filter_type} entries")
            return FlextResult[None].ok(None)

        return (
            self._ldif_api.write_file(filtered_entries, output_path)
            .map(lambda _: print(f"Filtered {len(filtered_entries)} {filter_type} entries to {output_path}"))
        )

    def _generate_analysis(self, entries: list, detailed: bool) -> FlextResult[dict]:
        """Generate comprehensive analysis."""
        try:
            stats_result = self._ldif_api.get_entry_statistics(entries)
            stats = stats_result.unwrap() if stats_result.is_success else {}

            analysis = {
                'total_entries': len(entries),
                'object_class_distribution': stats,
                'entry_types': self._analyze_entry_types(entries)
            }

            if detailed:
                analysis.update({
                    'attribute_analysis': self._analyze_attributes(entries),
                    'dn_analysis': self._analyze_dns(entries)
                })

            return FlextResult[dict].ok(analysis)
        except Exception as e:
            return FlextResult[dict].fail(f"Analysis generation failed: {e}")

    def _analyze_entry_types(self, entries: list) -> dict:
        """Analyze entry types."""
        persons = self._ldif_api.filter_persons(entries).unwrap_or([])
        groups = self._ldif_api.filter_groups(entries).unwrap_or([])

        return {
            'persons': len(persons),
            'groups': len(groups),
            'other': len(entries) - len(persons) - len(groups)
        }

    def _analyze_attributes(self, entries: list) -> dict:
        """Analyze attribute usage."""
        attribute_counts = {}
        all_attributes = set()

        for entry in entries:
            for attr_name in entry.attributes.keys():
                all_attributes.add(attr_name)
                attribute_counts[attr_name] = attribute_counts.get(attr_name, 0) + 1

        return {
            'total_unique_attributes': len(all_attributes),
            'most_common': sorted(attribute_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        }

    def _analyze_dns(self, entries: list) -> dict:
        """Analyze DN structure."""
        dn_depths = [len(entry.dn.split(',')) for entry in entries]

        return {
            'average_depth': sum(dn_depths) / len(dn_depths) if dn_depths else 0,
            'max_depth': max(dn_depths) if dn_depths else 0,
            'min_depth': min(dn_depths) if dn_depths else 0
        }

    def _output_analysis(self, analysis: dict, export_file: str = None) -> FlextResult[None]:
        """Output analysis results."""
        try:
            # Console output
            print("LDIF Analysis Results")
            print("====================")
            print(f"Total entries: {analysis['total_entries']}")
            print(f"Entry types: {analysis['entry_types']}")
            print(f"Object classes: {len(analysis['object_class_distribution'])}")

            if 'attribute_analysis' in analysis:
                attr_analysis = analysis['attribute_analysis']
                print(f"Unique attributes: {attr_analysis['total_unique_attributes']}")
                print("Most common attributes:")
                for attr, count in attr_analysis['most_common'][:5]:
                    print(f"  {attr}: {count}")

            # Export to file if requested
            if export_file:
                export_path = Path(export_file)
                export_path.write_text(json.dumps(analysis, indent=2), encoding='utf-8')
                print(f"Analysis exported to: {export_file}")

            return FlextResult[None].ok(None)
        except Exception as e:
            return FlextResult[None].fail(f"Analysis output failed: {e}")

# CLI usage examples
def create_ldif_cli() -> LdifCLIService:
    """Create LDIF CLI service."""
    return LdifCLIService()

# Example CLI commands (would be run from command line):
# flext-ldif parse -i directory.ldif --format summary
# flext-ldif validate -i directory.ldif --strict --report validation_report.json
# flext-ldif filter -i directory.ldif -o persons.ldif --type persons
# flext-ldif analyze -i directory.ldif --detailed --export analysis.json
# flext-ldif convert -i input.ldif -o output.ldif --normalize --encoding utf-8
```

These integration examples demonstrate how FLEXT-LDIF seamlessly integrates with other FLEXT ecosystem components while maintaining consistent patterns and providing practical, production-ready functionality.