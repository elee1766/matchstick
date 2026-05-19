#!/bin/bash
# Generate code coverage report for matchstick tests.
# Requires: gcov, lcov, genhtml
set -e
cd "$(dirname "$0")/.."

CACHE_DIR="/home/a/.cache/nim"
COV_DIR="coverage"

echo "=== Cleaning old coverage data ==="
rm -rf "$COV_DIR"
find "$CACHE_DIR" -name "*.gcda" -delete 2>/dev/null || true

echo "=== Building and running unit tests with coverage ==="
for t in tests/test_*.nim; do
  echo "--- $(basename $t) ---"
  nim c --passC:--coverage --passL:--coverage --hints:off --warnings:off -r "$t" 2>&1 | grep -E "\[OK\]|\[FAILED\]|Error" || true
done

echo ""
echo "=== Building and running integration tests with coverage ==="
for t in tests/integration/test_*.nim; do
  echo "--- $(basename $t) ---"
  nim c --passC:--coverage --passL:--coverage --hints:off --warnings:off -r "$t" 2>&1 | grep -E "\[OK\]|\[FAILED\]|Error" || true
done

echo ""
echo "=== Collecting coverage ==="
mkdir -p "$COV_DIR"

lcov --capture --directory "$CACHE_DIR" --output-file "$COV_DIR/all.info" --quiet 2>/dev/null

# Filter to only our source files
lcov --extract "$COV_DIR/all.info" "*/src/*.nim.c" --output-file "$COV_DIR/src.info" --quiet 2>/dev/null

echo ""
echo "=== Coverage summary ==="
lcov --summary "$COV_DIR/src.info" 2>&1 | grep -E "lines|functions"

echo ""
echo "=== Per-file coverage ==="
lcov --list "$COV_DIR/src.info" 2>&1 | grep -E "@m.*\.nim\.c|Total"

# Generate HTML if genhtml is available
if command -v genhtml &>/dev/null; then
  genhtml "$COV_DIR/src.info" --output-directory "$COV_DIR/html" --quiet 2>/dev/null
  echo ""
  echo "HTML report: $COV_DIR/html/index.html"
fi
