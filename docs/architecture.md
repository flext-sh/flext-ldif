# FLEXT-LDIF Architecture

**Version**: 0.9.9 RC | **Updated**: September 17, 2025

This document describes the architectural patterns and design decisions of FLEXT-LDIF, focusing on its service-oriented architecture and integration with FLEXT ecosystem patterns.

## Architectural Principles

### Service-Oriented Architecture

FLEXT-LDIF implements a service-oriented architecture with clear separation of concerns:

- **Single Responsibility**: Each service handles one aspect of LDIF processing
- **Dependency Injection**: Services are managed through FlextContainer
- **Railway-Oriented Programming**: All operations return FlextResult for composable error handling
- **Type Safety**: Complete type annotations with Pydantic v2 models

### FLEXT Integration Patterns

The library integrates deeply with FLEXT ecosystem patterns:

- **FlextResult**: Monadic error handling eliminates exceptions in business logic
- **FlextContainer**: Global dependency injection container for service management
- **FlextLogger**: Structured logging with context propagation
- **Domain Models**: Pydantic-based models following DDD patterns

## System Overview

```mermaid
graph TB
    subgraph "Application Layer"
        API[FlextLdifAPI<br/>Unified Interface]
    end

    subgraph "Service Layer"
        Parser[ParserService<br/>RFC 2849 Parsing]
        Validator[ValidatorService<br/>Entry Validation]
        Writer[WriterService<br/>LDIF Generation]
        Repository[RepositoryService<br/>Data Operations]
        Analytics[AnalyticsService<br/>Statistics]
    end

    subgraph "Domain Layer"
        Models[FlextLdifModels<br/>Domain Entities]
        Entry[Entry Model]
        DN[Distinguished Name]
        Config[Configuration]
    end

    subgraph "Infrastructure Layer"
        Container[FlextContainer<br/>DI Container]
        Logger[FlextLogger<br/>Structured Logging]
        Result[FlextResult<br/>Error Handling]
    end

    API --> Parser
    API --> Validator
    API --> Writer
    API --> Repository
    API --> Analytics

    Parser --> Models
    Validator --> Models
    Writer --> Models
    Repository --> Models
    Analytics --> Models

    Models --> Entry
    Models --> DN
    Models --> Config

    Parser --> Container
    Parser --> Logger
    Parser --> Result

    Validator --> Container
    Validator --> Logger
    Validator --> Result
```

## Core Components

### FlextLdifAPI - Application Service

The main entry point providing a unified interface to all LDIF operations:

```python
class FlextLdifAPI:
    """Unified LDIF Processing API with nested operation handlers."""

    def __init__(self, config: FlextLdifModels.Config | None = None) -> None:
        self._logger = FlextLogger(__name__)
        self._container = FlextContainer.get_global()
        self._config = config or FlextLdifModels.Config()

        # Nested operation handlers
        self._operations = self.Operations(self)
        self._filters = self.Filters(self)
        self._analytics = self.Analytics(self)
```

**Key Features**:

- Unified interface hiding service complexity
- Nested operation handlers for logical organization
- Dependency injection through FlextContainer
- Configuration management with defaults

### Service Architecture

#### ParserService - LDIF Parsing

Handles RFC 2849 compliant LDIF parsing:

```python
class FlextLdifParserService:
    """RFC 2849 compliant LDIF parser."""

    def parse_string(self, content: str) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Parse LDIF string content into structured entries."""
        # Implementation uses ldif3 library internally
        # Returns FlextResult for composable error handling
```

**Responsibilities**:

- Parse LDIF strings and files into structured entries
- Handle line folding, base64 decoding, and comments
- Validate LDIF format during parsing
- Provide detailed error information for invalid LDIF

#### ValidatorService - Entry Validation

Provides comprehensive LDIF entry validation:

```python
class FlextLdifValidatorService:
    """LDIF entry validation service."""

    def validate_entries(self, entries: list[FlextLdifModels.Entry]) -> FlextResult[bool]:
        """Validate LDIF entries against business rules."""
        # Validates DN structure, attribute formats, object classes
        # Configurable validation rules
```

**Responsibilities**:

- Validate DN structure and syntax
- Check attribute value formats and constraints
- Verify object class requirements
- Apply configurable business rules

#### WriterService - LDIF Generation

Generates RFC 2849 compliant LDIF output:

```python
class FlextLdifWriterService:
    """LDIF writer service for generating compliant output."""

    def write_entries(self, entries: list[FlextLdifModels.Entry]) -> FlextResult[str]:
        """Generate LDIF string from structured entries."""
        # Handles line folding, base64 encoding when necessary
        # Ensures RFC 2849 compliance
```

**Responsibilities**:

- Convert structured entries back to LDIF format
- Handle line folding for long attribute values
- Apply base64 encoding when required by RFC 2849
- Maintain consistent formatting

## Data Flow Architecture

### Processing Pipeline

```mermaid
sequenceDiagram
    participant Client
    participant API as FlextLdifAPI
    participant Parser as ParserService
    participant Validator as ValidatorService
    participant Repository as RepositoryService
    participant Writer as WriterService

    Client->>API: parse_file(path)
    API->>Parser: parse_file(path)
    Parser-->>API: FlextResult[entries]
    API-->>Client: FlextResult[entries]

    Client->>API: validate_entries(entries)
    API->>Validator: validate_entries(entries)
    Validator-->>API: FlextResult[bool]
    API-->>Client: FlextResult[bool]

    Client->>API: filter_persons(entries)
    API->>Repository: filter_by_objectclass(entries, "person")
    Repository-->>API: FlextResult[filtered_entries]
    API-->>Client: FlextResult[filtered_entries]

    Client->>API: write_file(entries, path)
    API->>Writer: write_entries(entries)
    Writer-->>API: FlextResult[ldif_string]
    API->>Writer: save_to_file(ldif_string, path)
    Writer-->>API: FlextResult[bool]
    API-->>Client: FlextResult[bool]
```

### Railway-Oriented Error Handling

All operations use FlextResult for composable error handling:

```python
def process_ldif_pipeline(file_path: Path) -> FlextResult[dict]:
    """Complete LDIF processing pipeline using railway patterns."""
    api = FlextLdifAPI()

    return (
        # Parse the LDIF file
        api.parse_file(file_path)

        # Validate all entries (continue with original entries on success)
        .flat_map(lambda entries:
            api.validate_entries(entries).map(lambda _: entries))

        # Filter valid entries
        .flat_map(lambda entries:
            api.filter_valid_entries(entries))

        # Generate statistics
        .flat_map(lambda entries:
            api.get_entry_statistics(entries))

        # Handle errors with context
        .map_error(lambda error:
            f"Processing failed for {file_path}: {error}")
    )
```

## Domain Model Architecture

### FlextLdifModels - Domain Entities

Centralized domain models following DDD patterns:

```python
class FlextLdifModels:
    """Consolidated LDIF domain models."""

    class Entry(BaseModel):
        """LDIF entry domain entity."""
        dn: str = Field(..., description="Distinguished Name")
        attributes: dict[str, list[str]] = Field(
            default_factory=dict,
            description="Entry attributes"
        )

        def get_object_classes(self) -> list[str]:
            """Get object class values."""
            return self.attributes.get('objectClass', [])

    class Config(BaseModel):
        """LDIF processing configuration."""
        max_entries: int | None = None
        strict_validation: bool = False
        ignore_unknown_attributes: bool = True
        encoding: str = "utf-8"

    class Factory:
        """Factory for creating domain entities."""

        @staticmethod
        def create_entry(dn: str, attributes: dict[str, list[str]]) -> Entry:
            """Create LDIF entry with validation."""
            return FlextLdifModels.Entry(dn=dn, attributes=attributes)
```

### Type Safety Implementation

Complete type annotations using Python 3.13+ features:

```python
# Type aliases for Python 3.13+ generic syntax
if TYPE_CHECKING:
    type FlextResultEntries = FlextResult[list[FlextLdifModels.Entry]]
    type FlextResultStr = FlextResult[str]
    type FlextResultBool = FlextResult[bool]
else:
    FlextResultEntries = FlextResult
    FlextResultStr = FlextResult
    FlextResultBool = FlextResult
```

## Configuration Architecture

### Hierarchical Configuration

Configuration follows a hierarchical pattern:

1. **Default Configuration**: Built-in defaults in FlextLdifModels.Config
2. **Global Configuration**: Managed through FlextLdifConfig
3. **Instance Configuration**: Per-API instance configuration
4. **Operation Configuration**: Per-operation overrides

### Configuration Integration

```python
# Global configuration
from flext_ldif import initialize_ldif_config, get_ldif_config

initialize_ldif_config({
    'max_entries': 50000,
    'strict_validation': True
})

# Instance configuration
config = FlextLdifModels.Config(
    max_entries=10000,  # Override global setting
    encoding='utf-8'
)

api = FlextLdifAPI(config=config)
```

## Current Implementation Status

### What's Implemented (v0.9.9)

**✅ Core Architecture**:

- Service-oriented design with clear separation
- FlextLdifAPI unified interface with nested handlers
- Complete FlextResult integration
- Dependency injection through FlextContainer

**✅ Service Layer**:

- All five services implemented and functional
- RFC 2849 compliant parsing and writing
- Basic validation and filtering capabilities
- Statistics and analytics generation

**✅ Domain Layer**:

- Pydantic v2 models with complete type annotations
- Entry and DN models working properly
- Factory pattern for model creation
- Configuration management system

**✅ Integration Layer**:

- FlextContainer dependency injection
- FlextLogger structured logging
- Complete type safety with MyPy compliance

### Known Limitations

**Memory Architecture**:

- Loads entire LDIF files into memory
- No streaming architecture for large files (>100MB)
- Single-threaded processing

**Performance Characteristics**:

- Suitable for files up to 100MB
- Processing speed depends on entry complexity
- No async/await support for concurrent operations

**Feature Completeness**:

- Basic LDIF operations implemented
- Advanced enterprise features are planned
- Limited to standard LDIF operations

## Design Decisions

### Why Service-Oriented Architecture

1. **Clear Separation**: Each service has well-defined responsibilities
2. **Testability**: Services can be tested independently
3. **FLEXT Integration**: Aligns with ecosystem patterns
4. **Maintainability**: Easy to understand and modify components

### Why Railway-Oriented Programming

1. **Explicit Error Handling**: No hidden exceptions in business logic
2. **Composability**: Operations chain naturally with clear error propagation
3. **FLEXT Consistency**: Matches patterns used across ecosystem
4. **Type Safety**: Errors and success values are explicitly typed

### Why Memory-Bound Processing

**Current Decision**: Prioritize correctness and integration over performance

**Rationale**:

- Simpler implementation and testing
- Adequate for current use cases (<100MB files)
- Provides stable foundation for future streaming enhancements
- Allows focus on FLEXT integration patterns

## Testing Architecture

### Service Testing Strategy

Each service is tested independently with clear boundaries:

```python
def test_parser_service_rfc_compliance():
    """Test RFC 2849 compliance in parser service."""
    parser = FlextLdifParserService()

    # Test various RFC 2849 scenarios
    result = parser.parse_string(sample_ldif)
    assert result.is_success

    entries = result.unwrap()
    assert len(entries) == expected_count
    assert entries[0].dn == expected_dn
```

### Integration Testing

Tests complete workflows through the unified API:

```python
def test_complete_ldif_workflow():
    """Test end-to-end LDIF processing workflow."""
    api = FlextLdifAPI()

    # Test complete pipeline with real LDIF data
    result = (
        api.parse_file(test_ldif_path)
        .flat_map(api.validate_entries)
        .flat_map(lambda entries: api.filter_persons(entries))
        .flat_map(lambda persons: api.write_file(persons, output_path))
    )

    assert result.is_success
```

---

This architecture provides a solid foundation for LDIF processing within the FLEXT ecosystem while maintaining clear separation of concerns and integration with established patterns.
