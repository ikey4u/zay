# Vendored dependencies

Pinned git submodules. Do not float on `main` / `testing` tips in CI or releases.

| Path | Upstream | Pinned commit |
|------|----------|---------------|
| `vendor/Easytier` | https://github.com/EasyTier/Easytier | `40c857748fc6ad5b07e2dafee10b516dc9df21cd` |
| `vendor/sing-box` | https://github.com/sagernet/sing-box (`testing`) | `115dbec2cd676e13e9dba7f6e23b932608ace339` (v1.14.0-beta.5) |

The gitlink in the parent repo is the source of truth; bump only deliberately after testing.

## Clone / update

```bash
git clone --recurse-submodules https://github.com/ikey4u/zay.git
# or after a normal clone:
git submodule update --init --recursive
```

Bump a pin only after testing desktop + iOS against the new commit:

```bash
cd vendor/Easytier   # or vendor/sing-box
git fetch
git checkout <commit>
cd ../..
git add vendor/Easytier   # records the new gitlink
# also update the table above
```

## Consumers

- **Desktop (`zay`)**: Cargo `easytier` / `easytier-core` path deps; `build.rs` compiles `sing-box` from `vendor/sing-box` (requires Go).
- **iOS (`client/ios`)**: Rust path dep on EasyTier; `Scripts/build-libbox.sh` builds Libbox from `vendor/sing-box`.
