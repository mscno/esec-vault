#!/bin/sh
# Builds EsecVault.app: a menu bar app with a window, no Dock icon.
# Usage: ./bundle.sh [install]   (install copies it to ~/Applications)
set -eu
cd "$(dirname "$0")"
if [ -n "${ESEC_APPLE_TEAM_ID:-}" ]; then
  : "${ESEC_PASSKEY_RP:?Set ESEC_PASSKEY_RP to the passkey associated domain}"
  xcodebuild -quiet clean build -project EsecVault.xcodeproj -scheme EsecVault -configuration Release \
    -destination "platform=macOS,arch=$(uname -m)" \
    -allowProvisioningUpdates -allowProvisioningDeviceRegistration DEVELOPMENT_TEAM="$ESEC_APPLE_TEAM_ID" \
    ESEC_PASSKEY_RP="$ESEC_PASSKEY_RP" SYMROOT="$PWD/.build/native-app"
  mkdir -p build
  rm -rf "build/EsecVault.app"
  cp -R ".build/native-app/Release/EsecVault.app" build/
  if [ "${1:-}" = install ]; then
    mkdir -p "$HOME/Applications"
    rm -rf "$HOME/Applications/EsecVault.app"
    cp -R "build/EsecVault.app" "$HOME/Applications/"
    rm -rf "$HOME/Applications/esec Vault.app"
    mkdir -p "$HOME/go/bin"
    if [ ! -e "$HOME/go/bin/age-plugin-passkey" ] && [ ! -L "$HOME/go/bin/age-plugin-passkey" ]; then
      ln -s "$HOME/Applications/EsecVault.app/Contents/MacOS/age-plugin-passkey" "$HOME/go/bin/age-plugin-passkey"
    fi
  fi
  exit 0
fi
swift build -c release
app="build/EsecVault.app"
rm -rf "$app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
cp .build/release/EsecVault "$app/Contents/MacOS/EsecVault"
cp Resources/AppIcon.icns "$app/Contents/Resources/AppIcon.icns"
root="$PWD/../.."
appbin="$PWD/$app/Contents/MacOS"
(cd "$root" && go build -ldflags "-X main.version=dev -X main.commit=$(git rev-parse --short HEAD) -X main.date=$(date -u +%Y-%m-%dT%H:%M:%SZ)" -o "$appbin/esec-vault" ./cmd/esec-vault)
(cd "$root" && go build -o "$appbin/age-plugin-passkey" ./cmd/age-plugin-passkey)
cat > "$app/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key><string>com.mscno.esec-vault</string>
  <key>CFBundleName</key><string>EsecVault</string>
  <key>CFBundleDisplayName</key><string>EsecVault</string>
  <key>CFBundleIconFile</key><string>AppIcon.icns</string>
  <key>CFBundleExecutable</key><string>EsecVault</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>0.1</string>
  <key>LSMinimumSystemVersion</key><string>14.0</string>
  <key>LSUIElement</key><true/>
</dict>
</plist>
PLIST
codesign --force --sign - "$app/Contents/MacOS/esec-vault" "$app/Contents/MacOS/age-plugin-passkey"
codesign --force --sign - --options runtime "$app"
echo "Built $app"
if [ "${1:-}" = install ]; then
  mkdir -p "$HOME/Applications"
  rm -rf "$HOME/Applications/EsecVault.app"
  cp -R "$app" "$HOME/Applications/"
  rm -rf "$HOME/Applications/esec Vault.app"
  echo "Installed to ~/Applications/EsecVault.app"
fi
