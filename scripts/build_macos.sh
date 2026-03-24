#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
RELEASE_DIR="$PROJECT_DIR/target/release"

# Configuration from environment variables
# SIGNING_IDENTITY - Developer ID Application certificate name or SHA-1 hash
# APPLE_TEAM_ID    - Apple Developer Team ID
# BUNDLE_ID        - App bundle identifier (e.g., net.gnarlylabs.envz)
SIGNING_IDENTITY="${SIGNING_IDENTITY:-${1:-}}"
APPLE_TEAM_ID="${APPLE_TEAM_ID:-}"
BUNDLE_ID="${BUNDLE_ID:-}"

# Replace placeholders in entitlements.plist
ENTITLEMENTS="$PROJECT_DIR/entitlements.plist"
ENTITLEMENTS_TEMP="$RELEASE_DIR/entitlements.plist"

# Replace placeholders in Info.plist (stored in a temp dir, NOT next to the binary,
# because codesign auto-discovers Info.plist adjacent to the binary and embeds a
# reference — deleting it afterwards would invalidate the signature)
INFO_PLIST="$PROJECT_DIR/bundle/Info.plist"
INFO_PLIST_TEMP="$(mktemp -d)/Info.plist"

echo "==> Building release binary..."
cd "$PROJECT_DIR"
cargo build --release

mkdir -p "$RELEASE_DIR"

if [ -n "$APPLE_TEAM_ID" ] && [ -n "$BUNDLE_ID" ]; then
    echo "==> Preparing entitlements (Team: $APPLE_TEAM_ID, Bundle: $BUNDLE_ID)..."
    sed -e "s/TEAM_ID_PLACEHOLDER/$APPLE_TEAM_ID/g" \
        -e "s/BUNDLE_ID_PLACEHOLDER/$BUNDLE_ID/g" \
        "$ENTITLEMENTS" > "$ENTITLEMENTS_TEMP"

    sed -e "s/BUNDLE_ID_PLACEHOLDER/$BUNDLE_ID/g" \
        "$INFO_PLIST" > "$INFO_PLIST_TEMP"
else
    echo "==> Using entitlements as-is (no APPLE_TEAM_ID / BUNDLE_ID set)..."
    cp "$ENTITLEMENTS" "$ENTITLEMENTS_TEMP"
    cp "$INFO_PLIST" "$INFO_PLIST_TEMP"
fi

if [ -n "$SIGNING_IDENTITY" ]; then
    echo "==> Signing with: $SIGNING_IDENTITY"
    codesign -f -s "$SIGNING_IDENTITY" --options runtime --timestamp --entitlements "$ENTITLEMENTS_TEMP" "$RELEASE_DIR/envz"

    echo "==> Verifying..."
    codesign -dvv "$RELEASE_DIR/envz" 2>&1 | grep -E "Authority|Identifier"
else
    echo "==> Ad-hoc signing with entitlements (required for keychain access)..."
    codesign -f -s - --entitlements "$ENTITLEMENTS_TEMP" "$RELEASE_DIR/envz"
fi

# Clean up temp files
rm -f "$ENTITLEMENTS_TEMP" "$INFO_PLIST_TEMP"

echo ""
echo "==> Done! Binary at: $RELEASE_DIR/envz"
echo ""
echo "To install:"
echo "  sudo cp '$RELEASE_DIR/envz' /usr/local/bin/"
