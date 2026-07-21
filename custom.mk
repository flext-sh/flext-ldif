.PHONY: ldif-parse ldif-validate ldif-config ldif-operations
.PHONY: test-unit test-integration build shell
ldif-parse: ## Test LDIF parsing
	$(Q)PYTHONPATH=$(SRC_DIR) $(POETRY) run pytest $(TESTS_DIR) -k "parse" -q
ldif-validate: ## Test LDIF validation
	$(Q)PYTHONPATH=$(SRC_DIR) $(POETRY) run pytest $(TESTS_DIR) -k "validate" -q
ldif-config: ## Test LDIF configuration
	$(Q)PYTHONPATH=$(SRC_DIR) $(POETRY) run pytest $(TESTS_DIR) -k "config" -q
ldif-operations: ## Test LDIF operations
	$(Q)PYTHONPATH=$(SRC_DIR) $(POETRY) run pytest $(TESTS_DIR) -k "operation" -q
.DEFAULT_GOAL := help
