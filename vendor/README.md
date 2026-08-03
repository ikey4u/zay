# Vendored dependencies

Pinned **commits** via gitlinks in the parent repo. There is no `branch =` in `.gitmodules`, so `git submodule update --remote` will not float you onto upstream tips.

| Path | Upstream | Pinned commit |
|------|----------|---------------|
| `vendor/Easytier` | https://github.com/EasyTier/Easytier | `40c857748fc6ad5b07e2dafee10b516dc9df21cd` |
| `vendor/sing-box` | https://github.com/sagernet/sing-box | `115dbec2cd676e13e9dba7f6e23b932608ace339` (v1.14.0-beta.5) |

Verify:

```bash
git ls-tree HEAD vendor/Easytier vendor/sing-box
# 160000 commit <sha>  vendor/...
```

## Clone / update

```bash
git clone --recurse-submodules https://github.com/ikey4u/zay.git
# or after a normal clone:
git submodule update --init --recursive
```

Do **not** run `git submodule update --remote` for release builds. Bump a pin only after testing desktop + iOS:

```bash
cd vendor/Easytier   # or vendor/sing-box
git fetch
git checkout --detach <commit>
cd ../..
git add vendor/Easytier   # records the new gitlink SHA
# update the table above
```

## Consumers

- **Desktop (`zay`)**: Cargo `easytier` / `easytier-core` path deps; `build.rs` compiles `sing-box` from `vendor/sing-box` (requires Go).
- **iOS (`client/ios`)**: Rust path dep on EasyTier; `Scripts/build-libbox.sh` builds Libbox from `vendor/sing-box`.
