# HoneyBox-FW — firmware release channel

Cloud side of the HoneyBox watch's **online OTA** channel. The phone app
(`honeybox-apk/HoneyBox`) reads `manifest.json` from this repository, verifies
its **Ed25519** signature, downloads the referenced `*.hbfw` package from the
matching GitHub Release and only then hands it to the watch's BLE DFU service.

Design document: `固件在线OTA与安全升级方案.md` in the firmware repository.

---

## Layout

| Path | Purpose |
|---|---|
| `manifest.json` | Current signed release manifest (`fw-stable` branch) |
| `manifest.sig` | Detached Ed25519 signature over **the exact bytes** of `manifest.json` |
| `pubkeys.json` | Public keys the app ships with (`kid` → base64) |
| `verify_release.py` | Standalone verifier (used by CI and by hand) |
| `.github/workflows/verify-manifest.yml` | Fails a push whose manifest does not verify |
| Releases (`fw-v*` tags) | The actual `app-bank0-*.hbfw` / `watch-ui-nor-*.hbfw` assets |

The app fetches the manifest from, in parallel, first answer wins:

```
https://cdn.jsdelivr.net/gh/gypso-ai/HoneyBox-FW@fw-stable/manifest.json
https://raw.githubusercontent.com/gypso-ai/HoneyBox-FW/fw-stable/manifest.json
https://gitee.com/gypso-ai/HoneyBox-FW/raw/fw-stable/manifest.json   (optional mirror)
```

Package assets are **not** in the git tree (they are 0.6–1.5 MB binaries), so
they are always fetched from:

```
https://github.com/gypso-ai/HoneyBox-FW/releases/download/<tag>/<pkgFile>
```

`<tag>` is the `tag` field of the manifest, e.g. `fw-v0.12.1`.

## Publishing

Nothing here is edited by hand. From the firmware workspace:

```powershell
# package + sign into applications/bin/fw-release, then verify it
.\applications\scripts\publish-firmware.ps1 -Channel stable

# upload the assets and move fw-stable to the new manifest
$env:GH_TOKEN = '<classic PAT with repo scope>'
.\applications\scripts\publish-firmware.ps1 -Channel stable -Upload
```

## Verifying manually

```bash
pip install cryptography
python verify_release.py --dir .                 # signature only
python verify_release.py --dir . --assets <dir>  # + sha256 / package structure
```

## Security model (read this before changing anything)

* The **manifest signature is the only trust anchor.** AES-256-GCM around the
  packages is obfuscation; its PSK ships inside the APK.
* `releaseSeq` is a monotonic `u32` shared across channels. The phone remembers
  the highest value it accepted and refuses anything lower — that is the
  downgrade / replay guard. **Never** publish a manifest with a lower
  `releaseSeq`, even to fix a mistake; publish a new one.
* The private signing key is **not** in this repository. Losing it means
  shipping a new app build that trusts a new `kid`; treat it like a release
  signing key and back it up offline.
* Anyone can download these files. Do not put anything confidential in the
  manifest, the release notes or the asset names.
