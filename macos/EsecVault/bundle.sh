#!/bin/sh
# Builds esec Vault.app: a menu bar app with a window, no Dock icon.
# Usage: ./bundle.sh [install]   (install copies it to ~/Applications)
set -eu
cd "$(dirname "$0")"
swift build -c release
app="build/esec Vault.app"
rm -rf "$app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
cp .build/release/EsecVault "$app/Contents/MacOS/EsecVault"
cat > "$app/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key><string>com.mscno.esec-vault</string>
  <key>CFBundleName</key><string>esec Vault</string>
  <key>CFBundleExecutable</key><string>EsecVault</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>0.1</string>
  <key>LSMinimumSystemVersion</key><string>14.0</string>
  <key>LSUIElement</key><true/>
</dict>
</plist>
PLIST
codesign --force --sign - --options runtime "$app"
echo "Built $app"
if [ "${1:-}" = install ]; then
  mkdir -p "$HOME/Applications"
  rm -rf "$HOME/Applications/esec Vault.app"
  cp -R "$app" "$HOME/Applications/"
  echo "Installed to ~/Applications/esec Vault.app"
fi
