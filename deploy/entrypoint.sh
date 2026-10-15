#!/bin/sh
# Restores the database from the Litestream replica when the volume is empty,
# then runs the server under Litestream so every write is replicated.
set -eu
DB="${ESEC_SERVER_DB_PATH:-/data/esec-vault.db}"
export ESEC_SERVER_DB_PATH="$DB"
if [ -n "${LITESTREAM_BUCKET:-}" ]; then
  litestream restore -config /etc/litestream.yml -if-db-not-exists -if-replica-exists "$DB"
  exec litestream replicate -config /etc/litestream.yml -exec "esec-vault-server"
fi
echo "LITESTREAM_BUCKET is not set: running without continuous backup" >&2
exec esec-vault-server
