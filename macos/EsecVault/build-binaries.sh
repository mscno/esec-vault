#!/bin/sh
set -eu
cd "$(dirname "$0")"
dest="$1"
mkdir -p "$dest"
swift build -c release
cp .build/release/EsecVault "$dest/EsecVault"
mkdir -p "$dest/../Resources"
cp Resources/AppIcon.icns "$dest/../Resources/AppIcon.icns"
cd ../..
commit=$(git rev-parse --short HEAD)
stamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)
go build -ldflags "-X main.version=${ESEC_VERSION:-dev} -X main.commit=$commit -X main.date=$stamp" -o "$dest/esec-vault" ./cmd/esec-vault
go build -o "$dest/age-plugin-passkey" ./cmd/age-plugin-passkey
if [ -n "${EXPANDED_CODE_SIGN_IDENTITY:-}" ]; then
  codesign --force --sign "$EXPANDED_CODE_SIGN_IDENTITY" --options runtime "$dest/esec-vault" "$dest/age-plugin-passkey"
fi
