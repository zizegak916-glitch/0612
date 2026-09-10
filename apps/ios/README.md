# iOS client · 6.0.0-alpha.2

Native SwiftUI client targeting iOS 16+. Open `IPBatchInspector.xcodeproj` in Xcode 16 or newer.

The app uses URLSession over the current iOS default route, Keychain for explicitly saved subscription URLs, bounded in-memory subscription handling and finite `beginBackgroundTask` time for a user-started job. It has no Network Extension/VPN entitlement, proxy switcher or subscription-node connection path, and cannot run an unlimited background system service.

The subscription parser recognizes the major URI/Base64/Clash YAML families. A public IP literal directly present in a node server field can be investigated. Domain A/AAAA results are shown separately as DNS infrastructure observations and are never counted as node or exit IPs. Node ports are display metadata only.

AI checks are anonymous current-route HTTP observations. Country code, ASN and risk metadata never produce a supported/unsupported verdict.
