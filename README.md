# NieFigger-Core

Independent Android ROOT sing-box-extended builds for NieFigger Hub.

The initial source snapshot is [VladBox 82df12d](https://github.com/niedigger4237/VladBox/commit/82df12d2de0e4cb012da4f28cd1ac3a9d1365953). This repository contains the pinned upstream revisions, nine sing-box patches, Firefox 148 uTLS replacement and validation tests. It does not build or sign APKs and does not depend on the VladBox branch layout.

## Build and publish

1. Open **Actions → Patched ROOT Core → Run workflow** on this repository's default branch.
2. Leave **Publish validated core-only prerelease** unchecked for a validation-only build.
3. Enable it to publish validated ARM64, ARMv7 and x86_64 binaries. The build runs the Firefox ClientHello, fingerprint mapping and Flow Metadata tests.
4. Releases use `core-v1-<source commit>` and include per-ABI binaries, SHA256SUMS and build-info.txt. They are separate core-only prereleases.

The app selects only compatible Patched channel assets and checks GitHub's SHA-256 digest before installation. Bundled is the recovery option. Upstream and Custom do not guarantee app patches.

## Compatibility and updates

Compatibility generation 1 corresponds to the ROOT core/helper and Flow Metadata contract in the initial app snapshot. A change to that contract needs a new release prefix coordinated with the app. Keep the embedded APK core and this repository synchronized when changing patches. Review and pin new upstream commits before building; there is no automatic upstream upgrade.

## Source and licensing

- [sing-box-extended](https://github.com/shtorm-7/sing-box-extended)
- [utls-lx](https://github.com/Leadaxe/utls-lx)
- VladBox/NekoBox patches, with the original license notice in LICENSE.

The exact upstream commits and corresponding build scripts are in `buildScript/lib/core/get_source_env.sh`. To reconstruct the source of a release, check out its tagged commit and execute the source preparation script. Preserve the upstream licenses and notices.

Local Linux x86_64 build: Go 1.26.4 and Android NDK, configured with ANDROID_HOME/ANDROID_NDK_HOME.

```sh
bash buildScript/lib/core/get_source.sh
bash buildScript/lib/core/build_root_core.sh
```
