# Zay for macOS

This directory contains the macOS-only process-attribution companion for the
portable Zay Rust core. It is intentionally separate from proxy, routing, Mesh,
Linux and Windows code.

## Architecture

1. `ZayProcessFilter` is a Network Extension system extension based on
   `NEFilterDataProvider`. It observes new socket flows, records the audit-token
   process identity, and always returns `allow`. It does not implement proxying,
   routing, DNS or TUN.
2. Events are appended as versioned NDJSON to the shared App Group file:
   `Library/Application Support/Zay/attribution/flows.jsonl`.
3. The Rust macOS adapter tails that file, correlates each event with a TUN
   flow, and falls back to the existing native socket-table resolver whenever
   the extension is absent or has no match.
4. On Linux and Windows the adapter is not compiled. Those platforms can add
   their own producer behind the same `ProcessResolver` interface.

The event file rotates at 8 MB. Set `ZAY_PROCESS_ATTRIBUTION_FILE` to override
its location for integration tests.

## Generate and build without signing

```sh
./Scripts/generate-project.sh
xcodebuild -project ZayMac.xcodeproj -scheme ZayMac \
  -configuration Debug CODE_SIGNING_ALLOWED=NO build
```

An unsigned build verifies source and project structure but cannot install or
activate the extension.

## Signing setup

1. Copy `project.local.yml.example` to `project.local.yml` and set the Team ID.
2. Register `dev.zay.macos`, `dev.zay.macos.process-filter`, and the App Group
   `group.dev.zay.macos` in the Apple Developer portal.
3. Enable System Extension and Network Extension / Content Filter capabilities.
4. Create provisioning profiles authorizing the entitlements in both targets.
5. Regenerate the project, sign both targets with the same Team ID, archive, and
   notarize the containing app for Developer ID distribution.

The user must approve the system extension and content-filter configuration on
first installation unless an MDM policy pre-approves them.
