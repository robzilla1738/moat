#!/usr/bin/env bash
# Signed, notarized, stapled release of Moat.app (with its embedded content-filter system extension).
#
# This script REQUIRES Robert's Apple Developer credentials. It never fakes signing: if anything is missing it
# stops. Contributors can build unsigned (see macos/README.md); forks need their own Developer ID and profiles.
#
# Required environment:
#   MOAT_TEAM_ID            Apple Developer Team ID (10 chars)
#   MOAT_BUNDLE_PREFIX      e.g. com.coursondigital
#   MOAT_SIGN_IDENTITY      "Developer ID Application: <Name> (<TEAM>)" present in the login keychain
#   MOAT_APP_PROFILE        name of the Developer ID provisioning profile for <prefix>.moat
#   MOAT_FILTER_PROFILE     name of the Developer ID provisioning profile for <prefix>.moat.filter
#                           (both must include content-filter-provider-systemextension)
#   MOAT_NOTARY_PROFILE     notarytool keychain profile (xcrun notarytool store-credentials ...)
# Output: macos/build/release/Moat-<version>.dmg and its sha256 for the Homebrew cask.
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
missing=()
for v in MOAT_TEAM_ID MOAT_BUNDLE_PREFIX MOAT_SIGN_IDENTITY MOAT_APP_PROFILE MOAT_FILTER_PROFILE MOAT_NOTARY_PROFILE; do
  [[ -n "${!v:-}" ]] || missing+=("$v")
done
if (( ${#missing[@]} )); then
  echo "Refusing to build a release: missing ${missing[*]}." >&2
  echo "Signing and notarization need a real Developer ID; an unsigned build is not a release." >&2
  exit 2
fi
if ! security find-identity -v -p codesigning | grep -q "$MOAT_SIGN_IDENTITY"; then
  echo "Signing identity not found in keychain: $MOAT_SIGN_IDENTITY" >&2
  exit 2
fi

version="$(sed -n 's/^MARKETING_VERSION = //p' "$here/Moat/Config/Moat.xcconfig")"
out="$here/build/release"
rm -rf "$out" && mkdir -p "$out"

"$here/scripts/build-ffi.sh" --universal
(cd "$here/Moat" && xcodegen generate)

xcodebuild -project "$here/Moat/Moat.xcodeproj" -scheme Moat -configuration Release \
  -archivePath "$out/Moat.xcarchive" archive \
  ARCHS="arm64 x86_64" ONLY_ACTIVE_ARCH=NO \
  DEVELOPMENT_TEAM="$MOAT_TEAM_ID" MOAT_BUNDLE_PREFIX="$MOAT_BUNDLE_PREFIX" \
  CODE_SIGN_STYLE=Manual CODE_SIGN_IDENTITY="$MOAT_SIGN_IDENTITY" OTHER_CODE_SIGN_FLAGS="--timestamp --options=runtime"

cat > "$out/ExportOptions.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>method</key><string>developer-id</string>
  <key>teamID</key><string>$MOAT_TEAM_ID</string>
  <key>signingStyle</key><string>manual</string>
  <key>signingCertificate</key><string>Developer ID Application</string>
  <key>provisioningProfiles</key><dict>
    <key>$MOAT_BUNDLE_PREFIX.moat</key><string>$MOAT_APP_PROFILE</string>
    <key>$MOAT_BUNDLE_PREFIX.moat.filter</key><string>$MOAT_FILTER_PROFILE</string>
  </dict>
</dict></plist>
PLIST
xcodebuild -exportArchive -archivePath "$out/Moat.xcarchive" -exportOptionsPlist "$out/ExportOptions.plist" -exportPath "$out/export"
app="$out/export/Moat.app"

echo "== verifying signatures"
codesign --verify --deep --strict --verbose=2 "$app"
codesign -d --entitlements - "$app/Contents/Library/SystemExtensions/"*.systemextension

echo "== notarizing"
ditto -c -k --keepParent "$app" "$out/Moat.zip"
xcrun notarytool submit "$out/Moat.zip" --keychain-profile "$MOAT_NOTARY_PROFILE" --wait
xcrun stapler staple "$app"
spctl --assess --type execute --verbose "$app"

echo "== dmg"
dmg="$out/Moat-$version.dmg"
hdiutil create -volname "Moat $version" -srcfolder "$app" -ov -format UDZO "$dmg"
codesign --sign "$MOAT_SIGN_IDENTITY" --timestamp "$dmg"
xcrun notarytool submit "$dmg" --keychain-profile "$MOAT_NOTARY_PROFILE" --wait
xcrun stapler staple "$dmg"
sha="$(shasum -a 256 "$dmg" | cut -d' ' -f1)"
echo "$sha  $(basename "$dmg")" > "$dmg.sha256"
echo "Release ready: $dmg"
echo "sha256: $sha  (put this and version $version into macos/Casks/moat.rb.template -> your tap's Casks/moat.rb)"
