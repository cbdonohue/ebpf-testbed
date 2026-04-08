# Makefile — ebpf-testbed
# Targets: help, lint, test, clean

PYTHON     := python3
PYTEST     := $(PYTHON) -m pytest
CLANG_FMT  := clang-format
BPF_SRCS   := $(shell find src -name "*.bpf.c")
PY_SRCS    := $(shell find src tests -name "*.py")

.PHONY: help lint test clean

## help: Show this help message
help:
	@echo ""
	@echo "ebpf-testbed — available make targets:"
	@echo ""
	@grep -E '^## ' Makefile | sed 's/## /  /'
	@echo ""

## lint: Check C source formatting with clang-format
lint:
	@echo "[lint] Checking .bpf.c files with clang-format..."
	@which $(CLANG_FMT) > /dev/null 2>&1 || \
		(echo "ERROR: clang-format not found. Install with: apt install clang-format" && exit 1)
	@fail=0; \
	for f in $(BPF_SRCS); do \
		diff=$$( $(CLANG_FMT) --style=LLVM "$$f" | diff - "$$f" ); \
		if [ -n "$$diff" ]; then \
			echo "  FAIL: $$f needs formatting"; \
			fail=1; \
		else \
			echo "  OK:   $$f"; \
		fi; \
	done; \
	if [ $$fail -eq 1 ]; then \
		echo ""; \
		echo "Run 'clang-format --style=LLVM -i <file>' to fix."; \
		exit 1; \
	fi
	@echo "[lint] All files pass."

## test: Run the test suite (no root or BCC required)
test:
	@echo "[test] Running test suite..."
	$(PYTEST) tests/ -v

## clean: Remove Python cache files and any build artifacts
clean:
	@echo "[clean] Removing build artifacts and caches..."
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type f -name "*.pyo" -delete 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.o" -delete 2>/dev/null || true
	find . -type f -name "*.ll" -delete 2>/dev/null || true
	@echo "[clean] Done."
