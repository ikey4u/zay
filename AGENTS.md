# Repository instructions

## Rust formatting

- Never run `cargo fmt --all` in this repository. Cargo-fmt's `--all` includes
  local path dependencies and rewrites the pinned `vendor/Easytier` submodule
  even though it is listed in `workspace.exclude`.
- Use `./scripts/fmt.sh` to format zay-owned Rust packages.
- Use `./scripts/fmt.sh --check` to verify formatting.
- Do not run `cargo fmt`, `cargo-fmt`, or `rustfmt` with an input or manifest
  under `vendor/Easytier` unless the user explicitly requests an intentional
  EasyTier source change.
- Preserve pre-existing submodule changes; never clean or reset them without
  explicit user approval.
