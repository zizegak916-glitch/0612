import Foundation
import Security

enum KeychainStore {
    private static let service = "com.fool.ipbatch.subscriptions"
    private static let namesKey = "savedSubscriptionNames"

    static func names() -> [String] {
        (UserDefaults.standard.array(forKey: namesKey) as? [String] ?? []).prefix(20).map { $0 }
    }

    static func save(name: String, url: String) throws {
        let clean = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !clean.isEmpty, clean.count <= 80 else { throw NetworkError.policy("Name must contain 1–80 characters.") }
        var names = names()
        guard names.contains(clean) || names.count < 20 else { throw NetworkError.policy("At most 20 subscriptions may be saved.") }
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: clean]
        SecItemDelete(query as CFDictionary)
        var insert = query
        insert[kSecValueData as String] = Data(url.utf8)
        insert[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let status = SecItemAdd(insert as CFDictionary, nil)
        guard status == errSecSuccess else { throw NSError(domain: NSOSStatusErrorDomain, code: Int(status)) }
        if !names.contains(clean) { names.append(clean); UserDefaults.standard.set(names, forKey: namesKey) }
    }

    static func load(name: String) throws -> String {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: name,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var value: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &value)
        guard status == errSecSuccess, let data = value as? Data, let url = String(data: data, encoding: .utf8) else { throw NSError(domain: NSOSStatusErrorDomain, code: Int(status)) }
        return url
    }

    static func delete(name: String) {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: name]
        SecItemDelete(query as CFDictionary)
        UserDefaults.standard.set(names().filter { $0 != name }, forKey: namesKey)
    }

    static func redactedLabel(name: String) -> String {
        guard let url = try? load(name: name), let parts = URLComponents(string: url) else { return "\(name) · unavailable" }
        return "\(name) · \(parts.scheme ?? "sn")://\(parts.host ?? "subscription")"
    }
}
