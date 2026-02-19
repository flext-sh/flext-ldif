# flext-ldif - LDIF Processing Library
PROJECT_NAME := flext-ldif
ifneq ("$(wildcard ../base.mk)", "")
include ../base.mk
else
include base.mk
endif

# === PROJECT-SPECIFIC TARGETS ===
.PHONY: ldif-parse ldif-validate ldif-config ldif-operations
.PHONY: test-unit test-integration build docs docs-serve shell

ldif-parse: ## Test LDIF parsing
	$(Q)PYTHONPATH=$(SRC_DIR) $(POETRY) run pytest $(TESTS_DIR) -k "parse" -q

ldif-validate: ## Test LDIF validation
	$(Q)PYTHONPATH=$(SRC_DIR) $(POETRY) run pytest $(TESTS_DIR) -k "validate" -q

ldif-config: ## Test LDIF configuration
	$(Q)PYTHONPATH=$(SRC_DIR) $(POETRY) run pytest $(TESTS_DIR) -k "config" -q

ldif-operations: ## Test LDIF operations
	$(Q)PYTHONPATH=$(SRC_DIR) $(POETRY) run pytest $(TESTS_DIR) -k "operation" -q

docs: ## Build documentation
	$(Q)$(POETRY) run mkdocs build

docs-serve: ## Serve documentation
	$(Q)$(POETRY) run mkdocs serve

.DEFAULT_GOAL := help
