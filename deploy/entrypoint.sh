#!/bin/sh
# Restores the database from the Litestream replica when the volume is empty,
# then runs the server under Litestream so every write is replicated.
set -eu
DB="${ESEC_SERVER_DB_PATH:-/data/esec-vault.db}"
export ESEC_SERVER_DB_PATH="$DB"
# fly storage create provides BUCKET_NAME and AWS credentials. Use those
# directly unless an operator configured a different replica explicitly.
if [ -z "${LITESTREAM_BUCKET:-}" ] && [ -n "${BUCKET_NAME:-}" ]; then
  export LITESTREAM_BUCKET="$BUCKET_NAME"
  export LITESTREAM_ENDPOINT="${LITESTREAM_ENDPOINT:-fly.storage.tigris.dev}"
  export LITESTREAM_REGION="${LITESTREAM_REGION:-auto}"
fi
if [ -n "${LITESTREAM_BUCKET:-}" ]; then
  litestream restore -config /etc/litestream.yml -if-db-not-exists -if-replica-exists "$DB"
  exec litestream replicate -config /etc/litestream.yml -exec "esec-vault-server"
fi
if [ "${ESEC_SERVER_REQUIRE_BACKUP:-false}" = true ]; then
  echo "Backup is required: configure LITESTREAM_BUCKET or a Fly Tigris bucket" >&2
  exit 1
fi
echo "LITESTREAM_BUCKET is not set: running without continuous backup" >&2
exec esec-vault-server
