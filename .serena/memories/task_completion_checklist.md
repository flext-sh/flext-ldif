# FLEXT-LDIF Task Completion Checklist

## MANDATORY Quality Gates (Execute ALWAYS)

### 1. Pre-Commit Validation

```bash
# CRITICAL: Run these commands before ANY commit
make validate                 # Complete validation pipeline
make check                    # Quick validation (lint + type)

# Individual checks if validate fails
make lint                     # Fix linting issues
make type-check               # Fix type errors
make security                 # Address security issues
make test                     # Ensure tests pass
```

### 2. Code Quality Verification

```bash
# Verify no prohibited patterns
grep -r "import click\|import rich\|from rich" src/  # NO direct CLI imports
grep -r "try:.*except.*return.*default" src/        # NO fallback patterns
grep -r "^def [^_].*:" src/ --exclude-dir=tests | grep -v "class"  # NO loose functions

# Check unified class structure
for file in $(find src/ -name "*.py" -not -path "*/tests/*"); do
    class_count=$(grep -c "^class " "$file" 2>/dev/null || echo 0)
    if [ "$class_count" -gt 1 ]; then
        echo "❌ CRITICAL: Multiple classes in $file"
        exit 1
    fi
done
```

### 3. LDIF Foundation Validation

```bash
# Verify LDIF abstraction boundaries
echo "=== LDIF FOUNDATION VALIDATION ==="

# Check for forbidden custom LDIF parsing
find ../flext-* -name "*.py" -exec grep -l "ldif.*parse\|parse.*ldif" {} \; 2>/dev/null | grep -v "flext-ldif" && echo "❌ CRITICAL: Custom LDIF parsing found" && exit 1

# Check for forbidden LDIF3 direct imports
find ../flext-* -name "*.py" -exec grep -l "import ldif3\|from ldif3" {} \; 2>/dev/null | grep -v "flext-ldif" && echo "❌ CRITICAL: Direct LDIF3 imports found" && exit 1

# Verify flext-ldif APIs are available
PYTHONPATH=src python -c "
from flext_ldif import FlextLdifAPI, FlextLdifModels, FlextLdifExceptions
api = FlextLdifAPI()
models = FlextLdifModels.Factory
exceptions = FlextLdifExceptions.builder()
print('✅ LDIF Foundation APIs available')
"
```

### 4. Test Coverage Validation

```bash
# Run tests with coverage
make test                     # Should achieve 90%+ coverage
pytest tests/ --cov=src/flext_ldif --cov-report=term-missing --cov-fail-under=90

# Verify enterprise LDIF processing pipeline
PYTHONPATH=src python -c "
import tempfile
from pathlib import Path
from flext_ldif import FlextLdifAPI

# Test enterprise LDIF processing pipeline
api = FlextLdifAPI()
sample_ldif = '''dn: cn=test,dc=example,dc=com
cn: test
objectClass: person
'''

with tempfile.NamedTemporaryFile(mode='w', suffix='.ldif', delete=False) as f:
    f.write(sample_ldif)
    temp_path = Path(f.name)

try:
    result = api.parse_file(temp_path)
    assert result.is_success, f'LDIF parsing failed: {result.error}'
    print('✅ Enterprise LDIF processing pipeline working')
finally:
    temp_path.unlink()
"
```

### 5. Pattern Implementation Validation

```bash
# Validate advanced patterns
PYTHONPATH=src python -c "from flext_ldif.exceptions import ExceptionBuilder; print('✅ Builder Pattern implemented')"
PYTHONPATH=src python -c "from flext_ldif.cli import FlextLdifCli; print('✅ Template Method Pattern implemented')"
PYTHONPATH=src python -c "from flext_ldif.core import ExceptionHandlingStrategy; print('✅ Strategy Pattern implemented')"
```

## BLOQUEADORES ABSOLUTOS

- ❌ Qualquer erro de lint = CORRIGIR antes de continuar
- ❌ Testes falhando = CORRIGIR antes de continuar
- ❌ Build quebrado = CORRIGIR antes de continuar
- ❌ Arquivos críticos modificados = REVERTER
- ❌ Imports circulares = REFATORAR
- ❌ Código duplicado = REUTILIZAR existente
- ❌ Custom LDIF parsing encontrado = ELIMINAR imediatamente

## Success Criteria

- ✅ All quality gates pass (lint, type, security, test)
- ✅ 90%+ test coverage maintained
- ✅ No prohibited patterns detected
- ✅ LDIF foundation boundaries maintained
- ✅ Enterprise LDIF processing pipeline working
- ✅ Advanced patterns implemented and validated

## Emergency Procedures

If quality gates fail:

1. **STOP** all development work
2. **IDENTIFY** the specific failure
3. **FIX** the issue completely
4. **RE-RUN** quality gates
5. **VERIFY** all criteria met before proceeding

## Documentation Requirements

- Update README.md if API changes
- Update examples if behavior changes
- Update CLAUDE.md if patterns change
- NO inflated claims without evidence
