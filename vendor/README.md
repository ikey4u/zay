# Vendored dependencies

Pinned **commits** via gitlinks in the parent repo. There is no `branch =` in `.gitmodules`, so `git submodule update --remote` will not float you onto upstream tips.

| Path | Upstream | Pinned commit |
|------|----------|---------------|
| `vendor/Easytier` | https://github.com/EasyTier/Easytier | `40c857748fc6ad5b07e2dafee10b516dc9df21cd` |

Verify:

```bash
git ls-tree HEAD vendor/Easytier
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
cd vendor/Easytier
git fetch
git checkout --detach <commit>
cd ../..
git add vendor/Easytier   # records the new gitlink SHA
# update the table above
```

## Formatting

Use the repository formatter instead of invoking a vendored workspace directly:

```bash
./scripts/fmt.sh
./scripts/fmt.sh --check
```

The script explicitly formats only the `zay`, `singbox`, and `zay-ios`
packages. Do not use `cargo fmt --all`: cargo-fmt defines that flag to include
local path dependencies even when they are listed in `workspace.exclude`, so
it will rewrite `vendor/Easytier`. Repository automation is instructed through
the root `AGENTS.md` to use the safe script and to leave submodules untouched.
Formatting a vendored dependency should be done only in its upstream
repository as a separate, intentional change.

## Consumers

- **Desktop (`zay`)**: Cargo `easytier` / `easytier-core` path dependencies.
- **iOS (`client/ios`)**: Rust path dependency on EasyTier.

The native sing-box implementation lives in `crates/singbox`. The pinned Go
source used only for migration reference and opt-in differential tests is kept
outside the shipped dependency tree under `inner/sing-box`; it is not built or
embedded by zay.
