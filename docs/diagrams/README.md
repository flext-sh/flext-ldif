# FLEXT-LDIF Architecture Diagrams

<!-- TOC START -->

- [Diagram Overview](#diagram-overview)
  - [C4 Model Structure](#c4-model-structure)
  - [Diagram Categories](#diagram-categories)
- [Rendering Diagrams](#rendering-diagrams)
  - [Prerequisites](#prerequisites)
  - [Rendering Commands](#rendering-commands)
  - [VS Code Integration](#vs-code-integration)
  - [Automated Rendering](#automated-rendering)
- [Diagram Standards](#diagram-standards)
  - [C4 Model Compliance](#c4-model-compliance)
  - [Naming Conventions](#naming-conventions)
  - [Style Guidelines](#style-guidelines)
  - [Content Standards](#content-standards)
- [Maintenance Guidelines](#maintenance-guidelines)
  - [Version Control](#version-control)
  - [Review Process](#review-process)
  - [Tooling Integration](#tooling-integration)
- [Related Documentation](#related-documentation)

<!-- TOC END -->

**Version**: 0.9.9 | **Framework**: PlantUML + C4 Model | **Updated**: October 10, 2025

This directory contains architecture diagrams for FLEXT-LDIF using modern diagramming practices and tools.

## Diagram Overview

### C4 Model Structure

Following the [C4 Model](https://c4model.com/) for visualising software architecture:

| Level       | Diagram        | Purpose                   | Scope                        |
| ----------- | -------------- | ------------------------- | ---------------------------- |
| **Level 1** | System Context | System in its environment | External systems and users   |
| **Level 2** | Container      | High-level components     | Applications and data stores |
| **Level 3** | Component      | Component relationships   | Services and libraries       |
| **Level 4** | Code           | Implementation details    | Classes and relationships    |

### Diagram Categories

#### 📋 System Context Diagrams

- **system-context.puml**: C4 Level 1 - System in its environment
- Shows external systems, users, and high-level interactions

#### 🏗️ Architecture Diagrams

- **container-architecture.puml**: C4 Level 2 - Container architecture
- **component-architecture.puml**: C4 Level 3 - Component relationships
- **data-flow-architecture.puml**: Data flow and processing pipeline

#### 🔒 Security & Quality Diagrams

- **security-architecture.puml**: Security architecture and threat model
- **quality-attributes.puml**: Quality attributes and cross-cutting concerns

## Rendering Diagrams

### Prerequisites

```bash
# Install PlantUML
sudo apt-get install plantuml  # Ubuntu/Debian
brew install plantuml          # macOS
```

### Rendering Commands

```bash
# Render single diagram
plantuml system-context.puml

# Render all diagrams
plantuml *.puml

# Render to specific format
plantuml -tpng system-context.puml  # PNG output
plantuml -tsvg system-context.puml  # SVG output
plantuml -tpdf system-context.puml  # PDF output
```

### VS Code Integration

Install the PlantUML extension for live preview:

```json
{
  "plantuml.server": "http://localhost:8080",
  "plantuml.render": "PlantUMLServer"
}
```

### Automated Rendering

Add to CI/CD pipeline:

```yaml
# .github/workflows/diagrams.yml
name: Render Architecture Diagrams
on:
  push:
    paths:
      - "docs/diagrams/*.puml"
jobs:
  render:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: cloudbees/plantuml-github-action@master
        with:
          args: -v docs/diagrams/*.puml
```

## Diagram Standards

### C4 Model Compliance

All diagrams follow C4 Model conventions:

```plantuml
@startuml
!include https://raw.githubusercontent.com/plantuml-stdlib/C4-PlantUML/master/C4_Context.puml

' Use appropriate C4 include
' Person() for users
' System() for systems
' System_Ext() for external systems
' Container() for containers
' Component() for components

@enduml
```

### Naming Conventions

- **Files**: `kebab-case.puml` (e.g., `system-context.puml`)
- **Elements**: `PascalCase` for component names
- **Descriptions**: Clear, concise descriptions
- **Relationships**: `Rel()` with descriptive labels

### Style Guidelines

```plantuml
' Consistent styling
skinparam backgroundColor #FEFEFE
skinparam packageBackgroundColor #E6F3FF
skinparam packageBorderColor #0066CC

' Use titles
title FLEXT-LDIF System Context Diagram

' Include version information
note right : Version: 0.9.9
```

### Content Standards

- **Accuracy**: Diagrams must reflect actual implementation
- **Consistency**: Use consistent terminology across diagrams
- **Completeness**: Show all relevant components and relationships
- **Clarity**: Keep diagrams readable and well-organized

## Maintenance Guidelines

### Version Control

- Diagrams are versioned with the codebase
- Update diagrams when architecture changes
- Include diagram changes in PR descriptions

### Review Process

- Architecture diagrams reviewed by technical leads
- Changes require approval from architecture team
- Automated rendering validates syntax

### Tooling Integration

```python
# docs/diagrams/generate.py - Automated diagram generation
import os
from pathlib import Path

def generate_diagrams():
    """Generate all diagrams from code annotations."""
    diagram_dir = Path("docs/diagrams")

    # Generate component diagrams from code
    # Generate data flow from service interactions
    # Generate deployment diagrams from infrastructure
```

## Related Documentation

- **../architecture-overview.md**: Comprehensive architecture documentation
- **../adr/**: Architecture Decision Records
- **../../README.md**: Project overview and usage

______________________________________________________________________

**FLEXT-LDIF Architecture Diagrams**: Visual documentation using C4 Model and PlantUML for comprehensive system understanding.
