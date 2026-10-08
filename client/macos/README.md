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
   `Library/Application Support/Zay/attribution/flows.jsonl`. The extension
   runs as root, so the file lives in root's App Group container; the adapter
   looks in the current user's container first and root's second.
3. The Rust macOS adapter tails that file, correlates each event with a TUN
   flow, and falls back to the existing native socket-table resolver whenever
   the extension is absent or has no match.
   - The file is only read when it is owned by root or by the user running
     zay and is not writable by group or others.
   - An event that names both the destination and the source port of a flow
     is used for 60 seconds. An event that names only one of them is used for
     3 seconds, and only while every such event points at the same process.
   - `signing_identifier` is empty unless the running code passes signature
     validation and is signed by a team or by Apple. Ad-hoc signed binaries
     choose their own identifier, so `package_name` rules never match them.
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

To activate a signed development build, quit the running app, copy the complete
`Zay.app` into `/Applications`, and open that copy before choosing Install and
Enable. Replace the app as a whole after rebuilding; do not merge old contents.
The embedded bundle is
`Contents/Library/SystemExtensions/dev.zay.macos.process-filter.systemextension`.
Keep its product name equal to its bundle identifier so macOS can discover it.
The Swift module name stays `ZayProcessFilter` for the provider class reference.

## Signing setup

1. Copy `project.local.yml.example` to `project.local.yml` and set the Team ID.
2. Register `dev.zay.macos`, `dev.zay.macos.process-filter`, and the App Group
   `group.dev.zay.macos` in the Apple Developer portal.
3. Enable System Extension and Network Extension / Content Filter capabilities.
4. Use Apple Development signing with automatic provisioning for local builds.
   Both targets use `content-filter-provider`, including when the provider is
   packaged as a system extension. Sign both targets with the same Team ID.
5. Regenerate the project after changing `project.local.yml`, then build in Xcode.

### Provisioning profile entitlement mismatch

If Xcode reports that a Mac Team Provisioning Profile does not match
`com.apple.developer.networking.networkextension`, check both targets' entitlement
files. Development builds must request `content-filter-provider`.
`content-filter-provider-systemextension` is for Developer ID distribution;
using it with a development profile causes this mismatch.

If the error persists with the development value, check that Network Extensions
is enabled for both App IDs and refresh the development profiles in Xcode.

### Developer ID distribution

The checked-in entitlements are for development and development-signed archives.
For direct distribution, both the app and the system extension need Developer ID
profiles and the `content-filter-provider-systemextension` entitlement value in
their distribution signatures. A Release build alone does not switch signing
identities or entitlement values.

For Xcode 26 and earlier, follow Apple's
[Exporting a Developer ID Network Extension](https://developer.apple.com/forums/thread/737894)
instructions: copy the archived app, extract each component's signed entitlements,
change the Network Extension value in those copies, replace both embedded profiles
with Developer ID profiles, and re-sign the extension before the containing app.
Then notarize the app. Keep the source entitlement files set to the development
value. Apple reports that Xcode 27 adds support for this conversion during export.

The user must approve the system extension and content-filter configuration on
first installation unless an MDM policy pre-approves them.
