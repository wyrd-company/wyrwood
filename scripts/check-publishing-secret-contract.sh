#!/usr/bin/env bash
# ---
# relationships: {}
# ---

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

assert_reference() {
  local file="$1"
  local reference="$2"

  if ! git grep -Fq -e "$reference" -- "$file"
  then
    echo "$file must reference $reference" >&2
    exit 1
  fi
}

assert_exact_line() {
  local file="$1"
  local expected="$2"

  if ! grep -Fqx -- "$expected" "$file"
  then
    echo "$file must contain the exact binding: $expected" >&2
    exit 1
  fi
}

legacy_package_prefix="REPO_WYRD_FOO_APP_"
legacy_scan_status=0
git grep -n -E -e "${legacy_package_prefix}(CLIENT_ID|PRIVATE_KEY)" || \
  legacy_scan_status=$?
case "$legacy_scan_status" in
  0)
    echo "Legacy package publisher secret names are forbidden." >&2
    exit 1
    ;;
  1) ;;
  *)
    echo "Legacy package publisher secret scan failed." >&2
    exit "$legacy_scan_status"
    ;;
esac

assert_exact_line \
  .github/workflows/submit-package.yml \
  '          app-client-id: ${{ secrets.REPO_WYRD_FOO_PUBLISHER_APP_ID }}'
assert_exact_line \
  .github/workflows/submit-package.yml \
  '          app-private-key: ${{ secrets.REPO_WYRD_FOO_PUBLISHER_PRIVATE_KEY }}'
assert_reference README.md '`REPO_WYRD_FOO_PUBLISHER_APP_ID`'
assert_reference README.md '`REPO_WYRD_FOO_PUBLISHER_PRIVATE_KEY`'

assert_exact_line \
  .github/workflows/publish-docs.yml \
  '          app-id: ${{ secrets.WYRD_TOOLS_DOCS_PUBLISHER_APP_ID }}'
assert_exact_line \
  .github/workflows/publish-docs.yml \
  '          private-key: ${{ secrets.WYRD_TOOLS_DOCS_PUBLISHER_PRIVATE_KEY }}'
assert_reference README.md '`WYRD_TOOLS_DOCS_PUBLISHER_APP_ID`'
assert_reference README.md '`WYRD_TOOLS_DOCS_PUBLISHER_PRIVATE_KEY`'
