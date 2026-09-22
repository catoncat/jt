#!/bin/sh
set -eu

JT_BIN="${JT_BIN:-jt}"
ENVCHAIN_BIN="${ENVCHAIN_BIN:-envchain}"
export ENVCHAIN_KEYCHAIN_DIR="${ENVCHAIN_KEYCHAIN_DIR:-$HOME/Library/Keychains/envchain-scopes}"

if [ "$#" -eq 0 ]; then
  echo "usage: migrate-envchain.sh NAMESPACE..." >&2
  exit 2
fi

for namespace in "$@"; do
  keys=$("$ENVCHAIN_BIN" --list "$namespace" 2>/dev/null | sed '/^--noecho$/d;/^$/d' || true)
  for key in $keys; do
    name="$namespace/$key"
    add_output=$("$ENVCHAIN_BIN" "$namespace" printenv "$key" | "$JT_BIN" add "$name")
    ref=$(printf '%s\n' "$add_output" | awk '{print $NF}')
    old_hash=$("$ENVCHAIN_BIN" "$namespace" printenv "$key" | tr -d '\n' | shasum -a 256 | awk '{print $1}')
    new_hash=$("$JT_BIN" resolve "$ref" --env JT_SECRET --exec sh -c 'printf %s "$JT_SECRET" | shasum -a 256' | awk '{print $1}')
    if [ "$old_hash" != "$new_hash" ]; then
      printf '%s\n' "mismatch name=$name ref=$ref; envchain entry was kept" >&2
      exit 1
    fi
    printf '%s\n' "migrated name=$name ref=$ref hash=match"
    "$ENVCHAIN_BIN" --unset "$namespace" "$key"
  done
done
