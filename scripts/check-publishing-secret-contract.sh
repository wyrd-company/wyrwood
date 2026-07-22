#!/usr/bin/env bash
# ---
# relationships: {}
# ---

set -euo pipefail

assert_reference() {
  local file="$1"
  local reference="$2"

  if ! git grep -Fq -e "$reference" -- "$file"
  then
    echo "$file must reference $reference" >&2
    exit 1
  fi
}

legacy_package_prefix="REPO_WYRD_FOO_APP_"
if git grep -n -E -e "${legacy_package_prefix}(CLIENT_ID|PRIVATE_KEY)"
then
  echo "Legacy package publisher secret names are forbidden." >&2
  exit 1
fi

assert_reference \
  .github/workflows/submit-package.yml \
  'secrets.REPO_WYRD_FOO_PUBLISHER_APP_ID'
assert_reference \
  .github/workflows/submit-package.yml \
  'secrets.REPO_WYRD_FOO_PUBLISHER_PRIVATE_KEY'
assert_reference README.md '`REPO_WYRD_FOO_PUBLISHER_APP_ID`'
assert_reference README.md '`REPO_WYRD_FOO_PUBLISHER_PRIVATE_KEY`'

assert_reference \
  .github/workflows/publish-docs.yml \
  'secrets.WYRD_TOOLS_DOCS_PUBLISHER_APP_ID'
assert_reference \
  .github/workflows/publish-docs.yml \
  'secrets.WYRD_TOOLS_DOCS_PUBLISHER_PRIVATE_KEY'
assert_reference README.md '`WYRD_TOOLS_DOCS_PUBLISHER_APP_ID`'
assert_reference README.md '`WYRD_TOOLS_DOCS_PUBLISHER_PRIVATE_KEY`'
