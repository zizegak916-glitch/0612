# iOS client

Native SwiftUI client targeting iOS 16+. Open `IPBatchInspector.xcodeproj` in Xcode 16 or newer.

The app uses URLSession over the current iOS system route, iOS Keychain for explicitly saved subscription URLs, bounded in-memory subscription handling and a finite `beginBackgroundTask` allowance for a user-started task. It does not include Network Extension/VPN entitlements and cannot run an unlimited background system service.

The subscription parser supports the same major families as the reference CLI. Node ports are represented in `NodeEndpoint` for display only and are never passed into DNS or connection code.
