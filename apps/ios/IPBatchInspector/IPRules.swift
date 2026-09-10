import Darwin
import Foundation
import Network

enum IPRules {
    static func isLiteral(_ value: String) -> Bool {
        IPv4Address(value) != nil || IPv6Address(value) != nil
    }

    static func isPublic(_ value: String) -> Bool {
        if let address = IPv4Address(value) {
            let bytes = [UInt8](address.rawValue)
            guard bytes.count == 4 else { return false }
            let a = bytes[0], b = bytes[1]
            if a == 0 || a == 10 || a == 127 || a >= 224 { return false }
            if a == 100 && (64...127).contains(b) { return false }
            if a == 169 && b == 254 { return false }
            if a == 172 && (16...31).contains(b) { return false }
            if a == 192 && (b == 168 || b == 0) { return false }
            if a == 192 && b == 0 && bytes[2] == 2 { return false }
            if a == 198 && (b == 18 || b == 19 || (b == 51 && bytes[2] == 100)) { return false }
            if a == 203 && b == 0 && bytes[2] == 113 { return false }
            return true
        }
        if let address = IPv6Address(value) {
            let bytes = [UInt8](address.rawValue)
            guard bytes.count == 16 else { return false }
            if bytes.allSatisfy({ $0 == 0 }) { return false }
            if bytes.dropLast().allSatisfy({ $0 == 0 }) && bytes.last == 1 { return false }
            if bytes[0] == 0xff || (bytes[0] & 0xfe) == 0xfc { return false }
            if bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80 { return false }
            if bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] == 0x0d && bytes[3] == 0xb8 { return false }
            return true
        }
        return false
    }

    static func resolve(_ host: String) throws -> [String] {
        if IPv4Address(host) != nil || IPv6Address(host) != nil { return [host] }
        var hints = addrinfo(
            ai_flags: AI_ADDRCONFIG,
            ai_family: AF_UNSPEC,
            ai_socktype: 0,
            ai_protocol: 0,
            ai_addrlen: 0,
            ai_canonname: nil,
            ai_addr: nil,
            ai_next: nil
        )
        var result: UnsafeMutablePointer<addrinfo>?
        let status = getaddrinfo(host, nil, &hints, &result)
        guard status == 0 else { throw NSError(domain: "IPRules", code: Int(status), userInfo: [NSLocalizedDescriptionKey: String(cString: gai_strerror(status))]) }
        defer { if result != nil { freeaddrinfo(result) } }
        var values: [String] = []
        var cursor = result
        while let info = cursor?.pointee {
            var buffer = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            if getnameinfo(info.ai_addr, info.ai_addrlen, &buffer, socklen_t(buffer.count), nil, 0, NI_NUMERICHOST) == 0 {
                let value = String(cString: buffer)
                if !values.contains(value) { values.append(value) }
            }
            cursor = info.ai_next
        }
        return values
    }

    static func validateSubscriptionURL(_ url: URL, allowPrivate: Bool) throws {
        guard ["http", "https"].contains(url.scheme?.lowercased() ?? ""), let host = url.host else {
            throw NetworkError.policy("Subscription URL must use HTTP or HTTPS and include a host.")
        }
        guard url.user == nil, url.password == nil else { throw NetworkError.policy("URL userinfo is rejected.") }
        let addresses = try resolve(host)
        let publicAnswers = addresses.filter(isPublic)
        let privateAnswers = addresses.filter { !isPublic($0) }
        if !publicAnswers.isEmpty && !privateAnswers.isEmpty { throw NetworkError.policy("Mixed public/private DNS answers are rejected as a rebinding risk.") }
        let isPrivate = !privateAnswers.isEmpty
        if isPrivate && !allowPrivate { throw NetworkError.policy("Private/local subscription requires explicit opt-in.") }
        if url.scheme?.lowercased() == "http" && !isPrivate { throw NetworkError.policy("Public subscriptions require HTTPS.") }
    }
}
