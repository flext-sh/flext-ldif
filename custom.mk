# Private project handlers for flext-ldif.
# Strict extension: only `_custom_<verb>_<what>` handlers and `(pre|post)-<verb>[-<what>]`
# hooks. Public targets, toolchain vars, .DEFAULT_GOAL, includes, and help are
# invalid (base.mk owns those). Each handler maps to `make <verb> WHAT=<what>`.
.PHONY: _custom_test_parse _custom_test_validate _custom_test_config _custom_test_operations
_custom_test_parse: ## make test WHAT=parse — LDIF parsing tests
	$(Q)PYTHONPATH=$(SRC_DIR) $(POETRY) run pytest $(TESTS_DIR) -k "parse" -q
_custom_test_validate: ## make test WHAT=validate — LDIF validation tests
	$(Q)PYTHONPATH=$(SRC_DIR) $(POETRY) run pytest $(TESTS_DIR) -k "validate" -q
_custom_test_config: ## make test WHAT=config — LDIF configuration tests
	$(Q)PYTHONPATH=$(SRC_DIR) $(POETRY) run pytest $(TESTS_DIR) -k "config" -q
_custom_test_operations: ## make test WHAT=operations — LDIF operations tests
	$(Q)PYTHONPATH=$(SRC_DIR) $(POETRY) run pytest $(TESTS_DIR) -k "operation" -q
