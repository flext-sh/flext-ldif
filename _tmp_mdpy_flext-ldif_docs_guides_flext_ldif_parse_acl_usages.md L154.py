# from flext-ldif/docs/guides/flext_ldif_parse_acl_usages.md:154
from __future__ import annotations


def _transform_categories(
    self, categorized: t.MappingKV[str, t.SequenceOf[m.Dict]]
) -> p.Result[Mapping[str, t.SequenceOf[m.Dict]]]:
    """Transform ACL entries using OID→OUD pipeline.

    Uses parse()
    """
    # Lines 668-771: Complete ACL transformation logic
    for entry in categorized.get("acl", []):
        for acl_attr in ["orclaci", "orclentrylevelaci"]:
            parse_result = oid_acl.parse(f"{acl_attr}: {acl_value}")
            # ↑ Uses parse() to parse OID format```
**Lines Affected**: 100+ lines for ACL transformation logic

______________________________________________________________________

## 4. TEST COVERAGE

### Unit Test Files Using parse()

| File                                 | Location                                     | Test Count   |
| ------------------------------------ | -------------------------------------------- | ------------ |
| `tests_acl.py`                       | `/tests/unit/servers/tests_acl.py`            | 20+ tests    |
| `tests_acl_conversion.py`            | `/tests/unit/servers/tests_acl_conversion.py` | 15+ tests    |
| `test_acl_service.py`                | `/tests/unit/test_acl_service.py`            | 10+ tests    |
| `test_acl_utils.py`                  | `/tests/unit/test_acl_utils.py`              | 5+ tests     |
| `test_acl_service_operations.py.bak` | Backup file                                  | Legacy tests |

### Test Pattern

