# Ultra Dex2C-VMP — Project Overview

Android on-device APK protector with two modes:
- **Dex2C** — Java bytecode → C++ → OLLVM obfuscation
- **VMP** — Java bytecode → randomised custom opcodes → private C VM interpreter

Package: `com.dex2c.mega`  
Source module: `Ultra Dex2C-VMP/`

---

## User Preferences

- Never leave stale/dead code — delete removed methods completely.
- When fixing VMP stripping, use Tier1DexPatcher (same path as dex2c), never the shell-DEX-swap approach.
- Always read this file at the start of every session.

---

## ⚡ How to Dispatch a Cloud Build (READ THIS EVERY SESSION)

The build runs on GitHub Actions at:
**`https://github.com/Matrixzat/cloud-workflow-engine`**  
Workflow file: `.github/workflows/build.yml`

**GitHub PAT:** stored in the git remote URL — extract it at runtime, never hardcode it:
```bash
PAT=$(git -C /home/runner/workspace remote get-url origin | grep -oP 'x-access-token:\K[^@]+')
```

### Steps — run these exact shell commands:

**Step 1 — Zip source:**
```bash
cd /home/runner/workspace
zip -r /tmp/source.zip "Ultra Dex2C-VMP/" -x "*.git*" -x "*/build/*" -x "*/.gradle/*" -q
```

**Step 2 — Create staging release + upload ZIP + dispatch (all in one block):**
```bash
PAT=$(git -C /home/runner/workspace remote get-url origin | grep -oP 'x-access-token:\K[^@]+')
REPO="Matrixzat/cloud-workflow-engine"
JOB_ID="ultra-dex2cvmp-$(date +%s)"
TAG="build-queue-$JOB_ID"

# Create release
RELEASE=$(curl -s -X POST \
  -H "Authorization: Bearer $PAT" \
  -H "Accept: application/vnd.github+json" \
  "https://api.github.com/repos/$REPO/releases" \
  -d "{\"tag_name\":\"$TAG\",\"name\":\"Build Queue\",\"draft\":false,\"prerelease\":true}")
RELEASE_ID=$(echo "$RELEASE" | jq -r '.id')
UPLOAD_URL=$(echo "$RELEASE" | jq -r '.upload_url' | sed 's/{.*//')

# Upload ZIP as asset
ASSET=$(curl -s -X POST \
  -H "Authorization: Bearer $PAT" \
  -H "Content-Type: application/zip" \
  "${UPLOAD_URL}?name=source.zip" \
  --data-binary @/tmp/source.zip)
ASSET_ID=$(echo "$ASSET" | jq -r '.id')

# Dispatch workflow
HTTP=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
  -H "Authorization: Bearer $PAT" \
  -H "Accept: application/vnd.github+json" \
  "https://api.github.com/repos/$REPO/actions/workflows/build.yml/dispatches" \
  -d "{\"ref\":\"main\",\"inputs\":{\"app_name\":\"Ultra Dex2C-VMP\",\"package_name\":\"com.ultra.dex2cvmp\",\"job_id\":\"$JOB_ID\",\"asset_id\":\"$ASSET_ID\",\"build_mode\":\"debug\"}}")

echo "DISPATCH=$HTTP  job_id=$JOB_ID  asset_id=$ASSET_ID"
```

**HTTP 204 = success.** The built APK artifact will be named `apk-{JOB_ID}` and kept for 1 day.

### Workflow inputs reference (`build.yml`):
| Input | Required | Notes |
|---|---|---|
| `app_name` | yes | Display name |
| `package_name` | yes | e.g. `com.dex2c.mega` |
| `job_id` | yes | Unique ID — artifact named `apk-{job_id}` |
| `asset_id` | no | GitHub Release asset ID (source ZIP) |
| `source_branch` | no | Alternative to asset_id |
| `build_mode` | no | `debug` / `release` (default: release) |
| `flutter_version` | no | Only for Flutter projects |

---

## Push to GitHub

```bash
cd /home/runner/workspace && git add -A && git commit -m "message" && git push origin main
```

Remote already has the PAT embedded — `git push` works directly.
