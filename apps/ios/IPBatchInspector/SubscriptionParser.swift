import Foundation

enum SubscriptionParser {
    private static let supported = ["ss", "ssr", "vmess", "vless", "trojan", "hysteria", "hysteria2", "hy2", "tuic", "socks", "socks4", "socks5", "http", "https"]

    static func parse(_ input: String) -> ([NodeEndpoint], [String], [String]) {
        var text = input.trimmingCharacters(in: .whitespacesAndNewlines)
        var warnings: [String] = []
        if let decoded = decodeBase64(text), decoded.contains("://") || decoded.lowercased().contains("proxies:") {
            text = decoded
        }
        var nodes = parseYAML(text)
        var providerURLs: [String] = []
        let providerPattern = #"(?i)(?:^|[, {])url\s*:\s*['\"]?(https?://[^\s,'\"}]+)"#
        for match in matches(providerPattern, text) where match.count > 1 {
            if !providerURLs.contains(match[1]) { providerURLs.append(match[1]) }
        }
        let pattern = #"(?i)(?:ssr?|vmess|vless|trojan|hysteria2?|hy2|tuic|socks5?|https?)://[^\s<>'\"]+"#
        for match in matches(pattern, text) {
            if let node = parseURI(match[0]) { nodes.append(node) }
        }
        var seen = Set<String>()
        nodes = nodes.filter { seen.insert("\($0.protocolName)|\($0.host.lowercased())|\($0.port ?? 0)").inserted }
        if nodes.count > 1500 {
            nodes = Array(nodes.prefix(1500))
            warnings.append("Node list was truncated at 1,500 entries.")
        }
        if nodes.isEmpty { warnings.append("No supported node endpoint was found.") }
        return (nodes, Array(providerURLs.prefix(20)), warnings)
    }

    private static func parseYAML(_ text: String) -> [NodeEndpoint] {
        var nodes: [NodeEndpoint] = []
        var inProxies = false
        var sectionIndent = -1
        var item: [String: String] = [:]
        func flush() {
            guard let type = item["type"], supported.contains(type.lowercased()), let host = item["server"], !host.isEmpty else { item = [:]; return }
            nodes.append(NodeEndpoint(protocolName: type.lowercased() == "hy2" ? "hysteria2" : type.lowercased(), name: item["name"] ?? "", host: host, port: Int(item["port"] ?? ""), chain: item["dialer-proxy"] ?? ""))
            item = [:]
        }
        for raw in text.components(separatedBy: .newlines) {
            let line = stripComment(raw)
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard !trimmed.isEmpty else { continue }
            let indent = line.prefix { $0 == " " }.count
            if trimmed.lowercased() == "proxies:" { flush(); inProxies = true; sectionIndent = indent; continue }
            if inProxies && indent <= sectionIndent && !trimmed.hasPrefix("-") { flush(); inProxies = false }
            guard inProxies else { continue }
            if trimmed.hasPrefix("- {") {
                flush()
                let body = trimmed.dropFirst(3).dropLast(trimmed.hasSuffix("}") ? 1 : 0)
                for field in body.split(separator: ",") { addField(String(field), to: &item) }
                flush()
            } else if trimmed.hasPrefix("- ") {
                flush(); addField(String(trimmed.dropFirst(2)), to: &item)
            } else { addField(trimmed, to: &item) }
        }
        flush()
        return nodes
    }

    private static func addField(_ line: String, to item: inout [String: String]) {
        guard let colon = line.firstIndex(of: ":") else { return }
        let key = String(line[..<colon]).trimmingCharacters(in: .whitespaces).lowercased()
        guard ["name", "type", "server", "port", "dialer-proxy"].contains(key) else { return }
        item[key] = unquote(String(line[line.index(after: colon)...]))
    }

    private static func parseURI(_ token: String) -> NodeEndpoint? {
        guard let divider = token.range(of: "://") else { return nil }
        var scheme = String(token[..<divider.lowerBound]).lowercased()
        let body = String(token[divider.upperBound...]).trimmingCharacters(in: CharacterSet(charactersIn: ",;])}"))
        if scheme == "hy2" { scheme = "hysteria2" }
        if scheme == "vmess", let decoded = decodeBase64(body.components(separatedBy: CharacterSet(charactersIn: "?#")).first ?? ""), let data = decoded.data(using: .utf8), let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any], let host = json["add"] as? String {
            return NodeEndpoint(protocolName: scheme, name: json["ps"] as? String ?? "", host: host, port: Int(String(describing: json["port"] ?? "")), chain: "")
        }
        if scheme == "ssr", let decoded = decodeBase64(body.components(separatedBy: "#").first ?? "") {
            let head = decoded.components(separatedBy: "/?").first ?? decoded
            let fields = head.split(separator: ":", maxSplits: 5).map(String.init)
            if fields.count >= 2 { return NodeEndpoint(protocolName: scheme, name: "", host: fields[0], port: Int(fields[1]), chain: "") }
        }
        var authority = body
        if scheme == "ss" && !body.contains("@"), let decoded = decodeBase64(body.components(separatedBy: CharacterSet(charactersIn: "?#")).first ?? "") { authority = decoded }
        guard supported.contains(scheme), let url = URL(string: "\(scheme)://\(authority)"), let host = url.host else { return nil }
        if ["http", "https"].contains(scheme) && url.user == nil { return nil }
        return NodeEndpoint(protocolName: scheme, name: url.fragment?.removingPercentEncoding ?? "", host: host, port: url.port, chain: "")
    }

    private static func matches(_ pattern: String, _ text: String) -> [[String]] {
        guard let regex = try? NSRegularExpression(pattern: pattern, options: [.anchorsMatchLines]) else { return [] }
        return regex.matches(in: text, range: NSRange(text.startIndex..., in: text)).map { match in
            (0..<match.numberOfRanges).map { index in
                guard let range = Range(match.range(at: index), in: text) else { return "" }
                return String(text[range])
            }
        }
    }

    private static func decodeBase64(_ value: String) -> String? {
        var compact = value.components(separatedBy: .whitespacesAndNewlines).joined().replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        compact += String(repeating: "=", count: (4 - compact.count % 4) % 4)
        guard let data = Data(base64Encoded: compact), let text = String(data: data, encoding: .utf8) else { return nil }
        return text
    }

    private static func stripComment(_ line: String) -> String {
        var quote: Character?
        for index in line.indices {
            let character = line[index]
            if character == "\"" || character == "'" { quote = quote == character ? nil : (quote == nil ? character : quote) }
            if character == "#" && quote == nil && (index == line.startIndex || line[line.index(before: index)].isWhitespace) { return String(line[..<index]) }
        }
        return line
    }

    private static func unquote(_ value: String) -> String {
        let clean = value.trimmingCharacters(in: .whitespacesAndNewlines)
        if clean.count >= 2, let first = clean.first, first == clean.last, first == "\"" || first == "'" { return String(clean.dropFirst().dropLast()) }
        return clean
    }
}
