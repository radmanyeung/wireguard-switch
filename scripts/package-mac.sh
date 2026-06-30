#!/bin/zsh
set -euo pipefail

configuration="Release"
for arg in "$@"; do
  case "$arg" in
    -c=*|--configuration=*)
      configuration="${arg#*=}"
      ;;
    -c|--configuration)
      echo "Use -c=Release or --configuration=Release."
      exit 2
      ;;
    *)
      echo "Unknown argument: $arg"
      echo "Usage: scripts/package-mac.sh [-c=Release]"
      exit 2
      ;;
  esac
done

script_dir="$(cd "$(dirname "$0")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
project="$repo_root/src/WireguardSplitTunnel.MacApp/WireguardSplitTunnel.MacApp.csproj"
readme="$repo_root/docs/README-Mac.txt"
deps_script="$repo_root/scripts/check-mac-deps.sh"
rid="osx-arm64"
build_root="$repo_root/.build/mac-package"
publish_dir="$build_root/publish"
app_dir="$build_root/WireguardSplitTunnel.app"
release_dir="$build_root/wireguard-split-tunnel-mac-arm64"
zip_path="$build_root/wireguard-split-tunnel-mac-arm64.zip"

if ! command -v dotnet >/dev/null 2>&1; then
  echo "dotnet SDK is required to build the macOS package."
  exit 1
fi

if [ ! -f "$project" ]; then
  echo "Project not found: $project"
  exit 1
fi

if [ ! -f "$readme" ]; then
  echo "README not found: $readme"
  exit 1
fi

app_version="$(dotnet msbuild "$project" -getProperty:Version | tail -n 1 | tr -d '\r')"
if [ -z "$app_version" ]; then
  echo "Unable to resolve app version from project metadata."
  exit 1
fi

rm -rf "$build_root"
mkdir -p "$publish_dir" "$app_dir/Contents/MacOS" "$app_dir/Contents/Resources" "$release_dir"

echo "Publishing self-contained $rid app..."
dotnet publish "$project" \
  -c "$configuration" \
  -r "$rid" \
  --self-contained true \
  -p:PublishSingleFile=false \
  -p:PublishReadyToRun=false \
  -o "$publish_dir"

cp -R "$publish_dir"/. "$app_dir/Contents/MacOS/"
chmod +x "$app_dir/Contents/MacOS/WireguardSplitTunnel"

cat > "$app_dir/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key>
  <string>en</string>
  <key>CFBundleExecutable</key>
  <string>WireguardSplitTunnel</string>
  <key>CFBundleIdentifier</key>
  <string>com.wireguardsplittunnel.app</string>
  <key>CFBundleName</key>
  <string>WireGuard Split Tunnel</string>
  <key>CFBundleDisplayName</key>
  <string>WireGuard Split Tunnel</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>$app_version</string>
  <key>CFBundleVersion</key>
  <string>$app_version</string>
  <key>LSMinimumSystemVersion</key>
  <string>13.0</string>
  <key>NSHighResolutionCapable</key>
  <true/>
</dict>
</plist>
PLIST

cp "$deps_script" "$release_dir/check-mac-deps.sh"
chmod +x "$release_dir/check-mac-deps.sh"
cp "$readme" "$release_dir/README-Mac.txt"
cp -R "$app_dir" "$release_dir/WireguardSplitTunnel.app"

if command -v codesign >/dev/null 2>&1; then
  echo "Applying ad-hoc codesign..."
  codesign --force --deep --sign - "$release_dir/WireguardSplitTunnel.app" || {
    echo "WARNING: ad-hoc codesign failed; package will remain unsigned."
  }
fi

rm -f "$zip_path"
/usr/bin/ditto -c -k --sequesterRsrc --keepParent "$release_dir" "$zip_path"

echo ""
echo "Package complete:"
echo "  App: $release_dir/WireguardSplitTunnel.app"
echo "  Zip: $zip_path"

