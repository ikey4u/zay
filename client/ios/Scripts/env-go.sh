#!/usr/bin/env bash
# Optional local Go toolchain (e.g. extracted to ~/sdk/go).
# Do not hardcode personal home directories here — use $HOME / PATH only.

if [[ -n "${GOROOT:-}" && -x "${GOROOT}/bin/go" ]]; then
  export PATH="${GOROOT}/bin:${PATH}"
elif [[ -x "${HOME}/sdk/go/bin/go" ]]; then
  export PATH="${HOME}/sdk/go/bin:${PATH}"
elif [[ -x "${HOME}/go/bin/go" ]]; then
  export PATH="${HOME}/go/bin:${PATH}"
fi
