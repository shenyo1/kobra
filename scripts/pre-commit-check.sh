#!/usr/bin/env bash
# KOBRA pre-commit check — run BEFORE every git commit
# Enforces UPDATE RULE v6 (36 titik)

set -e
cd ~/.local/opt/kobra

# Auto-detect current version from Cargo.toml
NEW_VERSION=$(grep '^version = ' Cargo.toml | head -1 | sed 's/version = "\(.*\)"/\1/')
NEW_VERSION_SHORT=$(echo "$NEW_VERSION" | sed 's/\.0$//')

# Normalize tag name (add v prefix if missing)
TAG_NAME="v$NEW_VERSION"

echo "═══ KOBRA PRE-COMMIT CHECK ═══"
echo "Target version: $NEW_VERSION (tag: $TAG_NAME)"
echo ""

# 1-13: Tech sync
echo "→ Tech sync (1-13)..."
grep -q "^version = \"$NEW_VERSION\"" Cargo.toml && echo "  ✓ Cargo.toml"
grep -q "KOBRA v$NEW_VERSION_SHORT" src/main.rs && echo "  ✓ main.rs"
grep -q "$TAG_NAME/kobra" .github/workflows/kobra-scan.yml && echo "  ✓ workflow yml"
grep -q "KOBRA v$NEW_VERSION_SHORT" src/report/webhook.rs && echo "  ✓ webhook footer"
grep -q "$TAG_NAME/kobra" HERMES_SETUP.md && echo "  ✓ HERMES_SETUP.md"
grep -q "KOBRA v$NEW_VERSION" README.md && echo "  ✓ README"

# 14-21: Repo meta
echo ""
echo "→ Repo meta (14-21)..."
[ -f LICENSE ] && echo "  ✓ LICENSE"
[ -f CONTRIBUTING.md ] && echo "  ✓ CONTRIBUTING.md"
[ -f SECURITY.md ] && echo "  ✓ SECURITY.md"
[ -f CODE_OF_CONDUCT.md ] && echo "  ✓ CoC"
[ -f CHANGELOG.md ] && echo "  ✓ CHANGELOG"
[ -f .github/ISSUE_TEMPLATE/bug_report.md ] && echo "  ✓ bug_report.md"
[ -f .github/ISSUE_TEMPLATE/feature_request.md ] && echo "  ✓ feature_request.md"
grep -q "img.shields.io" README.md && echo "  ✓ README badges"
REPO_DESC=$(gh repo view shenyo1/kobra --json description -q .description 2>/dev/null || echo "")
if echo "$REPO_DESC" | grep -q "$NEW_VERSION_SHORT"; then echo "  ✓ gh repo description"; else echo "  ⚠ gh repo description"; fi

# 22: FIX comments
echo ""
echo "→ Comment check (22)..."
STALE_FIX=$(grep -rn "// v[0-9]\.[0-9].*\(FIX\|fix\)" src/ 2>/dev/null | grep -v "v$NEW_VERSION_SHORT" | grep -v "was v[0-9]" | wc -l)
if [ "$STALE_FIX" -eq 0 ]; then echo "  ✓ All FIX comments updated"; else echo "  ⚠ $STALE_FIX stale FIX comments"; fi

# 23: diff_dashboard Severity (check both forms)
echo ""
echo "→ Recurring bug (23)..."
if grep -q "{Finding, Severity}" src/report/diff_dashboard.rs 2>/dev/null; then
  echo "  ✓ Severity imported"
elif grep -q "#\[cfg(test)\]" src/report/diff_dashboard.rs && grep -q "use crate::types::Severity" src/report/diff_dashboard.rs; then
  echo "  ✓ Severity imported (cfg-test only)"
else
  echo "  ⚠ Severity NOT imported"
fi

# 24: Build + Test
echo ""
echo "→ Build + Test (24)..."
BUILD_WARNINGS=$(cargo build --release 2>&1 | grep -E "^warning:" | grep -v generated | wc -l)
echo "  Build warnings: $BUILD_WARNINGS"
TEST_RESULT=$(cargo test --release 2>&1 | grep "test result" | head -1 || echo "FAILED")
echo "  Test: $TEST_RESULT"

# 25: Binary verification
echo ""
echo "→ Binary (25)..."
cp target/release/kobra ~/.local/bin/ 2>/dev/null || true
ACTUAL=$(~/.local/bin/kobra --version 2>/dev/null || echo "NOT INSTALLED")
if echo "$ACTUAL" | grep -q "$NEW_VERSION"; then echo "  ✓ Binary at v$NEW_VERSION ($ACTUAL)"; else echo "  ⚠ Binary is '$ACTUAL'"; fi

# 26: GitHub release
echo ""
echo "→ GitHub release (26)..."
RELEASE_TAG=$(gh release list --repo shenyo1/kobra --limit 1 --json tagName -q '.[0].tagName' 2>/dev/null || echo "")
if [ "$RELEASE_TAG" = "$TAG_NAME" ]; then echo "  ✓ Release $RELEASE_TAG exists"; else echo "  ⚠ Latest release: $RELEASE_TAG (need: $TAG_NAME)"; fi

# 27: Tag freshness
echo ""
echo "→ Tag freshness (27)..."
TAG_RAW=$(gh api repos/shenyo1/kobra/git/refs/tags/$TAG_NAME --jq '.object.sha' 2>/dev/null)
if [ -z "$TAG_RAW" ] || [ "$TAG_RAW" = "null" ]; then
  echo "  ⚠ NO tag found — run: git tag $TAG_NAME --force && git push origin $TAG_NAME --force"
  TAG_COMMIT="NO TAG"
else
  TAG_COMMIT=$(echo "$TAG_RAW" | head -c 40)
fi
HEAD_COMMIT=$(git rev-parse HEAD | head -c 40)
if [ "$TAG_COMMIT" = "$HEAD_COMMIT" ]; then
  echo "  ✓ Tag matches HEAD ($HEAD_COMMIT)"
elif [ "$TAG_COMMIT" = "NO TAG" ]; then
  echo "  ⚠ NO tag found"
else
  echo "  ⚠ Tag=$TAG_COMMIT, HEAD=$HEAD_COMMIT — force-push tag!"
fi

# 28: Global stale refs
echo ""
echo "→ Global stale refs (28)..."
# Excludes:
# - $NEW_VERSION (current version, legitimate)
# - `// vN.M.K` style fix comments (legitimate docs)
# - `vN.M.x` ranges (legitimate SemVer)
# - SARIF spec v2.1.0 (external spec, not our version)
# - Lecture 1/2/3/4 references to lessons learned (legitimate)
# - `(verified v4.7.0)` markers
STALE=$(grep -rn "v[0-9]\.[0-9]\.[0-9]" --include="*.rs" --include="*.md" --include="*.toml" --include="*.yml" src/ README.md HERMES_SETUP.md CHANGELOG.md 2>/dev/null \
  | grep -v "$NEW_VERSION" \
  | grep -v '// v[0-9]\.[0-9]\.[0-9]' \
  | grep -v 'v[0-9]\.[0-9]\.x' \
  | grep -v '// Fix v[0-9]\.[0-9]\.[0-9]' \
  | grep -v '// Lesson .*fix v[0-9]\.[0-9]\.[0-9]' \
  | grep -v 'Lesson [0-9] v[0-9]\.[0-9]\.[0-9]' \
  | grep -v 'verified v[0-9]\.[0-9]\.[0-9]' \
  | grep -v 'was v[0-9]\.[0-9]\.[0-9]' \
  | grep -v 'v2.1.0.*SARIF\|SARIF.*v2.1.0' \
  | grep -v 'CHANGELOG.md' \
  | grep -v '^[^:]*:[0-9]*://!' \
  | grep -v '^[^:]*:[0-9]*:// ' \
  | grep -v '^[^:]*:[0-9]*: \*"Lesson [0-9]' \
  | grep -v 'Priority [0-9]' \
  | grep -v 'emitted HIGH FP' \
  | grep -v '^[^:]*\.rs:[0-9]*: \///' \
  | grep -v '/// ' \
  | grep -v "// ATTACK PLUGIN" \
  | grep -v "// JWT KILLER" \
  | grep -v "JwtBearer" \
  | grep -v "What's New in v[0-9]" \
  | grep -v 'KOBRA v[0-9]\.[0-9]\.[0-9] — ' \
  | grep -v 'KOBRA v[0-9]\.[0-9]\.[0-9] \|KOBRA v[0-9]\.[0-9]\.[0-9]$' \
  | grep -v 'README.md.*+[0-9]\+ v[0-9]\.[0-9]\.[0-9]' \
  | grep -v 'since v[0-9]\.[0-9]\.[0-9]' \
  | grep -v 'localhost signature was removed' \
  | grep -v "9903-byte" \
  | grep -v "real-world bug-bounty" \
  | grep -v "Auth-Aware Probing" \
  | grep -v "v4.3.0 missed" \
  | grep -v "v[0-9]\.[0-9]\.[0-9] fixes all" \
  | grep -v '+43 vs v4.3.0' \
  | grep -v '+4 v4.4.0:' \
  | grep -v 'v1.0.0 → v4.4.0' \
  | grep -v 'Some("Lesson [0-9] fix' \
  | grep -v target/ | grep -v '.git/' | wc -l)
if [ "$STALE" -eq 0 ]; then echo "  ✓ No stale refs"; else echo "  ⚠ $STALE potential stale refs (verify manually)"; fi

# 29: CHANGELOG.md current version
echo ""
echo "→ CHANGELOG sync (29)..."
if grep -q "## \[$NEW_VERSION\]" CHANGELOG.md; then echo "  ✓ CHANGELOG.md has v$NEW_VERSION entry"
else echo "  ⚠ CHANGELOG.md missing entry for v$NEW_VERSION"; fi

# 30: README version badge
echo ""
echo "→ README version badge (30)..."
if grep -q "version-v$NEW_VERSION" README.md; then echo "  ✓ README badge matches v$NEW_VERSION"
else echo "  ⚠ README badge version != v$NEW_VERSION"; fi

# 31: README test count
echo ""
echo "→ README test count (31)..."
TEST_BADGE=$(grep -oP 'tests-\K[0-9]+' README.md | head -1)
TEST_ACTUAL=$(grep -rE "#\[test\]|#\[tokio::test\]" src/ tests/ 2>/dev/null | wc -l)
if [ "$TEST_BADGE" = "$TEST_ACTUAL" ]; then echo "  ✓ Test count matches ($TEST_ACTUAL)"
else echo "  ⚠ README badge says $TEST_BADGE tests, actual is $TEST_ACTUAL"; fi

# 32: README install URL points to latest tag
echo ""
echo "→ README install URL (32)..."
INSTALL_TAG=$(grep -oP 'releases/download/v\K[0-9.]+' README.md | head -1)
if [ "$INSTALL_TAG" = "$NEW_VERSION" ]; then echo "  ✓ Install URL points to v$NEW_VERSION"
else echo "  ⚠ README install URL points to v$INSTALL_TAG, latest is v$NEW_VERSION"; fi

# 33: README scan module count
echo ""
echo "→ Scan module count (33)..."
SCAN_ACTUAL=$(ls src/scan/*.rs 2>/dev/null | grep -v mod.rs | wc -l)
SCAN_BADGE=$(grep -oP '\*\*\K[0-9]+(?= scan module)' README.md | head -1)
if [ "$SCAN_BADGE" = "$SCAN_ACTUAL" ]; then echo "  ✓ Scan modules: $SCAN_ACTUAL"
else echo "  ⚠ README says $SCAN_BADGE scan modules, actual is $SCAN_ACTUAL"; fi

# 34: CHANGELOG stats accuracy (NEW 2026-07-29 - onii-chan caught content drift)
echo ""
echo "→ CHANGELOG stats accuracy (34)..."
ACTUAL_FILES=$(find src -name "*.rs" | wc -l)
ACTUAL_LOC=$(find src -name "*.rs" -exec wc -l {} + | tail -1 | awk '{print $1}')
ACTUAL_TESTS=$(grep -rE "#\[test\]|#\[tokio::test\]" src/ tests/ 2>/dev/null | wc -l)
# Only consider current version entry [4.7.0] stats
CURRENT_ENTRY=$(awk '/^## \[4.7.0\]/,/^## \[4.6.0\]/' CHANGELOG.md | head -15)
CHANGELOG_FILE_CLAIM=$(echo "$CURRENT_ENTRY" | grep -oP '\b\d+\s+\.rs files?|\b\d+\s+Rust source files?|\b\d+\s+Rust files?' | head -1 | awk '{print $1}')
CHANGELOG_LOC_CLAIM=$(echo "$CURRENT_ENTRY" | grep -oP '~[\d,]+\s+LOC' | head -1 | grep -oP '[\d,]+' | head -1 | tr -d ',')
CHANGELOG_TESTS_CLAIM=$(echo "$CURRENT_ENTRY" | grep -oP '\b\d+\s+(?:tests|total tests|file-level tests)' | head -1 | awk '{print $1}')
ERRORS=""
[ -n "$CHANGELOG_FILE_CLAIM" ] && [ "$CHANGELOG_FILE_CLAIM" != "$ACTUAL_FILES" ] && ERRORS="$ERRORS files=${CHANGELOG_FILE_CLAIM}≠${ACTUAL_FILES}"
[ -n "$CHANGELOG_LOC_CLAIM" ] && [ "$CHANGELOG_LOC_CLAIM" != "$ACTUAL_LOC" ] && ERRORS="$ERRORS LOC=${CHANGELOG_LOC_CLAIM}≠${ACTUAL_LOC}"
[ -n "$CHANGELOG_TESTS_CLAIM" ] && [ "$CHANGELOG_TESTS_CLAIM" != "$ACTUAL_TESTS" ] && ERRORS="$ERRORS tests=${CHANGELOG_TESTS_CLAIM}≠${ACTUAL_TESTS}"
if [ -z "$ERRORS" ]; then echo "  ✓ CHANGELOG stats accurate (files=$ACTUAL_FILES LOC=$ACTUAL_LOC tests=$ACTUAL_TESTS)"
else echo "  ⚠ CHANGELOG drift:$ERRORS (real: files=$ACTUAL_FILES LOC=$ACTUAL_LOC tests=$ACTUAL_TESTS)"; fi

# 35: README warnings badge count (NEW 2026-07-29 - onii-chan caught false 'warnings-0' claim)
echo ""
echo "→ README warnings badge (35)..."
# Run a real cargo build check and parse warning count from output
BUILD_OUTPUT=$(source $HOME/.cargo/env 2>/dev/null && cargo build 2>&1 || cargo check 2>&1)
ACTUAL_WARNINGS=$(echo "$BUILD_OUTPUT" | grep -c "^warning:")
WARNINGS_BADGE=$(grep -oP 'warnings-\K[0-9]+' README.md | head -1)
if [ "$ACTUAL_WARNINGS" = "$WARNINGS_BADGE" ]; then echo "  ✓ Warning count badge matches ($ACTUAL_WARNINGS)"
else echo "  ⚠ README warnings=$WARNINGS_BADGE, actual=$ACTUAL_WARNINGS (run cargo build manually to verify)"; fi

# 36: GitHub workflow install URL matches (NEW 2026-07-29 - workflow yml had stale v4.1.0)
echo ""
echo "→ Workflow install URL (36)..."
WORKFLOW_TAG=$(grep -oP 'releases/download/v\K[0-9.]+' .github/workflows/*.yml 2>/dev/null | head -1)
if [ -z "$WORKFLOW_TAG" ]; then echo "  (no workflow found)"
elif [ "$WORKFLOW_TAG" = "$NEW_VERSION" ]; then echo "  ✓ Workflow install URL points to v$NEW_VERSION"
else echo "  ⚠ Workflow install URL points to v$WORKFLOW_TAG, latest is v$NEW_VERSION"; fi

# 37: Release has binary named just 'kobra' (NEW 2026-07-29 - workflow expected 'kobra' not 'kobra-vN.M.O-pN')
echo ""
echo "→ Release asset named 'kobra' (37)..."
if gh release view "$TAG_NAME" --repo "shenyo1/kobra" --json assets --jq '.assets[].name' 2>/dev/null | grep -qx "kobra"; then
  echo "  ✓ Release $TAG_NAME has asset 'kobra' (workflow-downloadable)"
else
  echo "  ⚠ Release $TAG_NAME missing 'kobra' asset (workflow would fail with curl 9-byte response)"
fi

echo ""
echo "═══ CHECK COMPLETE ═══"