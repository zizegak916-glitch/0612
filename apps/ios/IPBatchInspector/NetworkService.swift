import Foundation
import Network

enum NetworkError: LocalizedError {
    case policy(String)
    case response(String)

    var errorDescription: String? {
        switch self {
        case .policy(let text), .response(let text): return text
        }
    }
}

private final class SafeTextLoader: NSObject, URLSessionDataDelegate, URLSessionTaskDelegate {
    private let allowPrivate: Bool
    private let maximumBytes = 5 * 1024 * 1024
    private var data = Data()
    private var response: HTTPURLResponse?
    private var continuation: CheckedContinuation<(Data, HTTPURLResponse), Error>?
    private var session: URLSession?
    private var redirectCount = 0

    init(allowPrivate: Bool) { self.allowPrivate = allowPrivate }

    func load(_ url: URL) async throws -> (Data, HTTPURLResponse) {
        try IPRules.validateSubscriptionURL(url, allowPrivate: allowPrivate)
        return try await withCheckedThrowingContinuation { continuation in
            self.continuation = continuation
            let configuration = URLSessionConfiguration.ephemeral
            configuration.timeoutIntervalForRequest = 15
            configuration.timeoutIntervalForResource = 30
            configuration.httpAdditionalHeaders = ["User-Agent": "IPBatchInspector/4.1"]
            let session = URLSession(configuration: configuration, delegate: self, delegateQueue: nil)
            self.session = session
            session.dataTask(with: url).resume()
        }
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        redirectCount += 1
        guard redirectCount <= 4 else { completionHandler(nil); finish(.failure(NetworkError.policy("Subscription exceeded four redirects."))); return }
        guard task.countOfBytesReceived < 5 * 1024 * 1024, let url = request.url else { completionHandler(nil); return }
        do { try IPRules.validateSubscriptionURL(url, allowPrivate: allowPrivate); completionHandler(request) }
        catch { completionHandler(nil); finish(.failure(error)) }
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse, completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
        guard let http = response as? HTTPURLResponse else { completionHandler(.cancel); finish(.failure(NetworkError.response("Non-HTTP response."))); return }
        guard (200..<300).contains(http.statusCode) else { completionHandler(.cancel); finish(.failure(NetworkError.response("Subscription returned HTTP \(http.statusCode)."))); return }
        if response.expectedContentLength > Int64(maximumBytes) { completionHandler(.cancel); finish(.failure(NetworkError.policy("Subscription exceeds 5 MiB."))); return }
        self.response = http
        completionHandler(.allow)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive chunk: Data) {
        data.append(chunk)
        if data.count > maximumBytes { dataTask.cancel(); finish(.failure(NetworkError.policy("Subscription exceeds 5 MiB."))) }
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        if let error { finish(.failure(error)); return }
        guard let response else { finish(.failure(NetworkError.response("Missing HTTP response."))); return }
        if let finalURL = response.url {
            do { try IPRules.validateSubscriptionURL(finalURL, allowPrivate: allowPrivate) }
            catch { finish(.failure(error)); return }
        }
        finish(.success((data, response)))
    }

    private func finish(_ result: Result<(Data, HTTPURLResponse), Error>) {
        guard let continuation else { return }
        self.continuation = nil
        continuation.resume(with: result)
        session?.finishTasksAndInvalidate()
        session = nil
    }
}

enum NetworkService {
    private static let userAgent = "IPBatchInspector/4.1"
    private static let iso = ISO8601DateFormatter()

    static func inspectSubscription(_ text: String, allowPrivate: Bool) async throws -> SubscriptionResult {
        let normalized = try unwrapSubscriptionURL(text)
        var candidates = [normalized]
        if let alternate = alternateFormatURL(normalized) { candidates.append(alternate) }
        var payload: Data?
        var lastError: Error?
        var usedFormatFallback = false
        for (index, candidate) in candidates.enumerated() {
            do {
                let loader = SafeTextLoader(allowPrivate: allowPrivate)
                payload = try await loader.load(candidate).0
                usedFormatFallback = index > 0
                break
            } catch { lastError = error }
        }
        guard let data = payload else { throw lastError ?? NetworkError.response("Subscription download failed.") }
        guard let content = String(data: data, encoding: .utf8) else { throw NetworkError.response("Subscription is not UTF-8 text.") }
        var (nodes, providers, warnings) = SubscriptionParser.parse(content)
        if usedFormatFallback { warnings.append("Primary fsl format failed; alternate fsl64/fslyaml format was used with the original query preserved.") }
        var providerResults: [ProviderLoad] = []
        await withTaskGroup(of: ProviderLoad.self) { group in
            for (index, provider) in providers.prefix(20).enumerated() {
                group.addTask {
                    guard let providerURL = URL(string: provider) else { return ProviderLoad(index: index, nodes: [], warnings: [], error: "invalid URL") }
                    do {
                        let providerLoader = SafeTextLoader(allowPrivate: allowPrivate)
                        let (providerData, _) = try await providerLoader.load(providerURL)
                        guard let providerText = String(data: providerData, encoding: .utf8) else { return ProviderLoad(index: index, nodes: [], warnings: [], error: "not UTF-8") }
                        let parsed = SubscriptionParser.parse(providerText)
                        return ProviderLoad(index: index, nodes: parsed.0, warnings: parsed.2, error: nil)
                    } catch { return ProviderLoad(index: index, nodes: [], warnings: [], error: error.localizedDescription) }
                }
            }
            for await item in group { providerResults.append(item) }
        }
        for item in providerResults.sorted(by: { $0.index < $1.index }) {
            nodes.append(contentsOf: item.nodes); warnings.append(contentsOf: item.warnings)
            if let error = item.error { warnings.append("Provider download failed: \(error)") }
        }
        var seenNodes = Set<String>()
        nodes = Array(nodes.filter { seenNodes.insert("\($0.protocolName)|\($0.host)|\($0.port ?? 0)").inserted }.prefix(1500))
        let uniqueHosts = Array(Set(nodes.map(\.host))).sorted()
        var hostAnswers: [String: [String]] = [:]
        for start in stride(from: 0, to: uniqueHosts.count, by: 32) {
            let end = min(start + 32, uniqueHosts.count)
            await withTaskGroup(of: HostResolution.self) { group in
                for host in uniqueHosts[start..<end] {
                    group.addTask {
                        do {
                            // A node port is intentionally not passed to DNS or any connection API.
                            return HostResolution(host: host, addresses: try IPRules.resolve(host), error: nil)
                        } catch { return HostResolution(host: host, addresses: [], error: error.localizedDescription) }
                    }
                }
                for await item in group {
                    hostAnswers[item.host] = item.addresses
                    if let error = item.error { warnings.append("DNS failed for \(item.host): \(error)") }
                }
            }
        }
        var publicIPs: [String] = []
        var local: [String] = []
        for node in nodes {
            for address in hostAnswers[node.host] ?? [] {
                if IPRules.isPublic(address) {
                    if !publicIPs.contains(address) && publicIPs.count < 500 { publicIPs.append(address) }
                } else if !local.contains(address) { local.append(address) }
            }
        }
        let counts = Dictionary(grouping: nodes, by: \.protocolName).mapValues(\.count)
        let intelligence = await scanIPs(publicIPs.joined(separator: "\n"))
        return SubscriptionResult(nodeCount: nodes.count, protocolCounts: counts, nodes: nodes, publicIPs: publicIPs, localOrReserved: local, intelligence: intelligence, warnings: warnings, rawContentPersisted: false, networkBoundary: "Downloaded subscription/provider text, used OS DNS and queried public-IP intelligence only; no node port was connected.")
    }

    static func detectExit() async -> [[String: String]] {
        let endpoints = [
            ("ipify-v4", "https://api.ipify.org?format=json"),
            ("ipify-dual", "https://api64.ipify.org?format=json"),
            ("icanhazip", "https://icanhazip.com/")
        ]
        var indexed: [(Int, [String: String])] = []
        await withTaskGroup(of: (Int, [String: String]).self) { group in
            for (index, endpoint) in endpoints.enumerated() {
                group.addTask { (index, await exitEvidence(name: endpoint.0, address: endpoint.1)) }
            }
            for await item in group { indexed.append(item) }
        }
        return indexed.sorted { $0.0 < $1.0 }.map { $0.1 }
    }

    static func scanIPs(_ values: String) async -> [IPResult] {
        let tokens = values.components(separatedBy: CharacterSet(charactersIn: " ,;\n\t")).filter { !$0.isEmpty }
        var unique: [String] = []
        for token in tokens where IPRules.isPublic(token) && !unique.contains(token) && unique.count < 500 { unique.append(token) }
        var indexed: [(Int, IPResult)] = []
        for start in stride(from: 0, to: unique.count, by: 4) {
            let end = min(start + 4, unique.count)
            await withTaskGroup(of: (Int, IPResult).self) { group in
                for index in start..<end {
                    group.addTask { (index, await scanOne(unique[index])) }
                }
                for await item in group { indexed.append(item) }
            }
        }
        return indexed.sorted { $0.0 < $1.0 }.map { $0.1 }
    }

    private static func scanOne(_ ip: String) async -> IPResult {
        let queryIP = ip.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? ip
        let pathIP = ip.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? ip
        let sources = [
            ("ipapi.is", "https://api.ipapi.is/?q=\(queryIP)"),
            ("proxycheck.io", "https://proxycheck.io/v2/\(pathIP)?vpn=1&asn=1&risk=1&seen=1"),
            ("GeoJS", "https://get.geojs.io/v1/ip/geo/\(pathIP).json"),
            ("RDAP", "https://rdap.org/ip/\(pathIP)"),
            ("RIPEstat", "https://stat.ripe.net/data/routing-status/data.json?resource=\(queryIP)")
        ]
        var indexed: [(Int, SourceEvidence)] = []
        await withTaskGroup(of: (Int, SourceEvidence).self) { group in
            for (index, source) in sources.enumerated() {
                group.addTask {
                    if source.0 == "RDAP" { await ProviderRateGate.shared.waitForRdap() }
                    return (index, await sourceEvidence(source: source.0, address: source.1, targetIP: ip))
                }
            }
            for await item in group { indexed.append(item) }
        }
        var result = IPResult(ip: ip, status: "failed")
        result.evidence = indexed.sorted { $0.0 < $1.0 }.map { $0.1 }
        finalize(&result)
        return result
    }

    private static func sourceEvidence(source: String, address: String, targetIP: String) async -> SourceEvidence {
        let started = Date()
        do {
            let object = try await fetchObject(address)
            var fields: [String: String] = [:]
            if source == "ipapi.is" {
                if truthy(object["error"]) { throw NetworkError.response(string(object["message"]).isEmpty ? "Provider rejected query." : string(object["message"])) }
                let returned = string(object["ip"])
                if !returned.isEmpty && !sameIP(returned, targetIP) { throw NetworkError.response("Provider returned a different target IP.") }
                let location = object["location"] as? [String: Any] ?? object
                let asn = object["asn"] as? [String: Any] ?? [:]
                fields["country"] = string(location["country"])
                fields["country_code"] = string(location["country_code"] ?? location["countryCode"])
                let flatASN: Any? = object["asn"] is [String: Any] ? nil : object["asn"]
                fields["asn"] = formatASN(asn["asn"] ?? flatASN)
                fields["organization"] = string(asn["org"] ?? asn["name"])
                for key in ["is_proxy", "is_vpn", "is_tor", "is_datacenter", "is_abuser"] where object[key] != nil {
                    fields[key] = truthy(object[key]) ? "true" : "false"
                }
            } else if source == "proxycheck.io" {
                guard string(object["status"]).lowercased() == "ok" else { throw NetworkError.response(string(object["message"]).isEmpty ? "Provider status was not ok." : string(object["message"])) }
                let item = targetObject(object, targetIP) ?? [:]
                if item.isEmpty { throw NetworkError.response("Response did not contain the target IP.") }
                fields["country"] = string(item["country"])
                fields["country_code"] = string(item["isocode"] ?? item["country_code"])
                fields["asn"] = formatASN(item["asn"])
                fields["organization"] = string(item["organisation"] ?? item["provider"])
                fields["proxy"] = string(item["proxy"])
                fields["type"] = string(item["type"])
                fields["risk"] = string(item["risk"])
                fields["last_seen"] = string(item["last_seen"] ?? item["last seen"])
            } else if source == "GeoJS" {
                let returned = string(object["ip"])
                if !returned.isEmpty && !sameIP(returned, targetIP) { throw NetworkError.response("Provider returned a different target IP.") }
                fields["country"] = string(object["country"])
                fields["country_code"] = string(object["country_code"])
                fields["asn"] = formatASN(object["asn"])
                fields["organization"] = string(object["organization_name"] ?? object["organization"])
            } else if source == "RDAP" {
                fields["range"] = "\(string(object["startAddress"])) - \(string(object["endAddress"]))"
                fields["registration_name"] = string(object["name"] ?? object["handle"])
                fields["registration_country"] = string(object["country"])
            } else if let data = object["data"] as? [String: Any], let last = data["last_seen"] as? [String: Any] {
                fields["prefix"] = string(last["prefix"])
                fields["origin_asn"] = formatASN(last["origin"])
                fields["last_seen"] = string(last["time"])
            }
            fields = fields.filter { !$0.value.isEmpty }
            return SourceEvidence(source: source, ok: true, elapsedMilliseconds: Int(Date().timeIntervalSince(started) * 1000), checkedAt: iso.string(from: Date()), fields: fields, error: nil)
        } catch {
            return SourceEvidence(source: source, ok: false, elapsedMilliseconds: Int(Date().timeIntervalSince(started) * 1000), checkedAt: iso.string(from: Date()), fields: [:], error: error.localizedDescription)
        }
    }

    private static func finalize(_ result: inout IPResult) {
        let successful = result.evidence.filter(\.ok)
        guard !successful.isEmpty else { result.confidence = "none: no provider returned usable evidence"; return }
        let country = consensus(successful, field: "country", aliases: [])
        let countryCode = consensus(successful, field: "country_code", aliases: [])
        let asn = consensus(successful, field: "asn", aliases: ["origin_asn"])
        let organization = consensus(successful, field: "organization", aliases: [])
        result.country = country.value; result.countryCode = countryCode.value.uppercased()
        result.asn = formatASN(asn.value); result.organization = organization.value
        for item in [("country", country), ("country_code", countryCode), ("asn", asn), ("organization", organization)] {
            if !item.1.summary.isEmpty { result.consensus[item.0] = item.1.summary }
            if let conflict = item.1.conflict { result.conflicts.append("\(item.0): \(conflict)") }
        }
        for evidence in successful {
            if let risk = Int(evidence.fields["risk"] ?? "") { result.riskScores[evidence.source] = max(0, min(100, risk)) }
        }
        for flag in ["proxy", "vpn", "tor", "datacenter", "abuser"] {
            var positive: [String] = [], negative: [String] = [], unknown: [String] = []
            for evidence in successful {
                guard let observation = signal(evidence, flag: flag) else { unknown.append(evidence.source); continue }
                if observation { positive.append(evidence.source) } else { negative.append(evidence.source) }
            }
            let state: String
            if !positive.isEmpty && !negative.isEmpty { state = "disputed" }
            else if positive.count >= 2 || (flag == "tor" && !positive.isEmpty) { state = "confirmed" }
            else if !positive.isEmpty { state = "reported" }
            else if !negative.isEmpty { state = "not_reported" }
            else { state = "unknown" }
            result.signals[flag] = "\(state); positive=\(positive); negative=\(negative); unknown=\(unknown)"
            if state == "disputed" { result.conflicts.append("\(flag): true from \(positive), false from \(negative)") }
        }
        let importantConflict = result.conflicts.contains { $0.hasPrefix("country_code:") || $0.hasPrefix("asn:") }
        let keyFieldsConfirmed = countryCode.agree >= 2 && asn.agree >= 2
        result.confidence = successful.count >= 3 && !importantConflict && keyFieldsConfirmed
            ? "high: at least three sources; country and ASN each agree across two or more sources"
            : successful.count >= 2 ? "medium: multiple sources; review conflicts" : "low: one usable source"
        result.status = successful.count >= 2 ? "ok" : "partial"
    }

    private static func consensus(_ evidence: [SourceEvidence], field: String, aliases: [String]) -> (value: String, summary: String, conflict: String?, agree: Int) {
        var counts: [String: Int] = [:]
        var display: [String: String] = [:]
        var sources: [String: [String]] = [:]
        var order: [String] = []
        for item in evidence {
            let raw = ([field] + aliases).compactMap { item.fields[$0] }.first { !$0.isEmpty } ?? ""
            guard !raw.isEmpty else { continue }
            let key = (field == "country_code" || field == "asn") ? raw.uppercased() : raw.lowercased()
            if counts[key] == nil { order.append(key); display[key] = raw }
            counts[key, default: 0] += 1; sources[key, default: []].append(item.source)
        }
        guard let winner = order.max(by: { counts[$0, default: 0] < counts[$1, default: 0] }) else { return ("", "", nil, 0) }
        let value = display[winner] ?? ""
        let summary = "\(value); agree=\(counts[winner, default: 0])/\(order.reduce(0) { $0 + counts[$1, default: 0] }); sources=\(sources[winner] ?? [])"
        let conflict = order.count > 1 ? order.map { "\(display[$0] ?? $0)=\(sources[$0] ?? [])" }.joined(separator: " | ") : nil
        return (value, summary, conflict, counts[winner, default: 0])
    }

    private static func signal(_ evidence: SourceEvidence, flag: String) -> Bool? {
        if evidence.source == "ipapi.is", let value = evidence.fields["is_\(flag)"] { return truthy(value) }
        if evidence.source == "proxycheck.io" {
            if flag == "proxy", let value = evidence.fields["proxy"] { return truthy(value) }
            if ["vpn", "tor"].contains(flag), let type = evidence.fields["type"] { return type.lowercased().contains(flag) }
        }
        return nil
    }

    private static func exitEvidence(name: String, address: String) async -> [String: String] {
        do {
            var request = URLRequest(url: URL(string: address)!)
            request.setValue(userAgent, forHTTPHeaderField: "User-Agent")
            let (data, response) = try await URLSession.shared.data(for: request)
            let http = response as? HTTPURLResponse
            var value = String(decoding: data.prefix(4096), as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
            if let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] { value = object["ip"] as? String ?? value }
            return ["source": name, "ip": value, "http": String(http?.statusCode ?? 0), "checked_at": iso.string(from: Date()), "meaning": "current iOS process route"]
        } catch { return ["source": name, "error": error.localizedDescription, "checked_at": iso.string(from: Date())] }
    }

    private static func targetObject(_ object: [String: Any], _ target: String) -> [String: Any]? {
        for (key, value) in object where sameIP(key, target) {
            if let item = value as? [String: Any] { return item }
        }
        return nil
    }

    private static func sameIP(_ one: String, _ two: String) -> Bool {
        if let first = IPv4Address(one), let second = IPv4Address(two) { return first.rawValue == second.rawValue }
        if let first = IPv6Address(one), let second = IPv6Address(two) { return first.rawValue == second.rawValue }
        return false
    }

    private static func truthy(_ value: Any?) -> Bool {
        let text = string(value).lowercased()
        return ["true", "yes", "1"].contains(text)
    }

    private static func formatASN(_ value: Any?) -> String {
        let text = string(value).uppercased()
        guard !text.isEmpty else { return "" }
        let digits = text.filter(\.isNumber)
        return digits.isEmpty ? text : "AS\(digits)"
    }

    static func testAIEntrances() async -> [EntranceResult] {
        let endpoints = [
            ("ChatGPT web", "web", "https://chatgpt.com/"), ("OpenAI API", "api", "https://api.openai.com/v1/models"),
            ("Claude web", "web", "https://claude.ai/"), ("Anthropic API", "api", "https://api.anthropic.com/v1/models"),
            ("Gemini web", "web", "https://gemini.google.com/"), ("Gemini API", "api", "https://generativelanguage.googleapis.com/v1beta/models"),
            ("Grok web", "web", "https://grok.com/"), ("xAI API", "api", "https://api.x.ai/v1/models"),
            ("Google AI Studio", "web", "https://aistudio.google.com/"), ("Microsoft Copilot", "web", "https://copilot.microsoft.com/"),
            ("Perplexity", "web", "https://www.perplexity.ai/")
        ]
        var indexed: [(Int, EntranceResult)] = []
        await withTaskGroup(of: (Int, EntranceResult).self) { group in
            for (index, endpoint) in endpoints.enumerated() {
                group.addTask { (index, await entranceEvidence(name: endpoint.0, kind: endpoint.1, address: endpoint.2)) }
            }
            for await item in group { indexed.append(item) }
        }
        return indexed.sorted { $0.0 < $1.0 }.map { $0.1 }
    }

    private static func entranceEvidence(name: String, kind: String, address: String) async -> EntranceResult {
        do {
            var request = URLRequest(url: URL(string: address)!)
            request.setValue(userAgent, forHTTPHeaderField: "User-Agent")
            request.setValue("text/html,application/json", forHTTPHeaderField: "Accept")
            let (data, response) = try await URLSession.shared.data(for: request)
            let code = (response as? HTTPURLResponse)?.statusCode ?? 0
            let body = String(decoding: data.prefix(32768), as: UTF8.self).lowercased()
            let explicitRegion = body.contains("not available in your country") || body.contains("unsupported country") || body.contains("not available in your region")
            let status: String
            let detail: String
            if explicitRegion { status = "region-blocked"; detail = "Response explicitly reported an unsupported country/region." }
            else if (200..<400).contains(code) { status = "reachable"; detail = "Public entrance returned a normal response." }
            else if kind == "api" && [400, 401, 403].contains(code) { status = "reachable-auth-required"; detail = "API entrance responded; no credential was sent." }
            else if code == 403 { status = "restricted-or-challenged"; detail = "403 may be policy, WAF, anti-bot or IP reputation; not a proven geo-block." }
            else { status = "failed"; detail = "HTTP \(code)" }
            return EntranceResult(name: name, kind: kind, host: URL(string: address)!.host ?? "", httpCode: code, status: status, detail: detail, checkedAt: iso.string(from: Date()))
        } catch {
            return EntranceResult(name: name, kind: kind, host: URL(string: address)!.host ?? "", httpCode: nil, status: "network-error", detail: error.localizedDescription, checkedAt: iso.string(from: Date()))
        }
    }

    private static func unwrapSubscriptionURL(_ value: String) throws -> URL {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.lowercased().hasPrefix("sn://subscription"), let wrapper = URLComponents(string: trimmed) {
            for item in wrapper.queryItems ?? [] where ["url", "target", "subscription"].contains(item.name.lowercased()) {
                if let candidate = item.value, let url = URL(string: candidate), ["http", "https"].contains(url.scheme?.lowercased() ?? "") { return url }
            }
            throw NetworkError.policy("sn://subscription must contain an explicit HTTP(S) URL.")
        }
        guard let url = URL(string: trimmed) else { throw NetworkError.policy("Invalid subscription URL.") }
        return url
    }

    private static func alternateFormatURL(_ url: URL) -> URL? {
        let original = url.absoluteString
        guard let regex = try? NSRegularExpression(pattern: #"(?i)(^|/)(fsl64|fslyaml)(?=/|\?|#|$)"#),
              let match = regex.firstMatch(in: original, range: NSRange(original.startIndex..., in: original)),
              let formatRange = Range(match.range(at: 2), in: original) else { return nil }
        let current = original[formatRange].lowercased()
        let replacement = current == "fsl64" ? "fslyaml" : "fsl64"
        return URL(string: original.replacingCharacters(in: formatRange, with: replacement))
    }

    private static func fetchObject(_ address: String) async throws -> [String: Any] {
        var request = URLRequest(url: URL(string: address)!)
        request.setValue(userAgent, forHTTPHeaderField: "User-Agent")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode), data.count <= 2 * 1024 * 1024 else { throw NetworkError.response("Invalid or oversized provider response.") }
        guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw NetworkError.response("Provider did not return a JSON object.") }
        return object
    }

    private static func string(_ value: Any?) -> String {
        guard let value, !(value is NSNull) else { return "" }
        return String(describing: value)
    }
}

private actor ProviderRateGate {
    static let shared = ProviderRateGate()
    private var nextRdapStart = Date.distantPast

    func waitForRdap() async {
        let now = Date()
        let scheduled = max(now, nextRdapStart)
        nextRdapStart = scheduled.addingTimeInterval(1.05)
        let delay = scheduled.timeIntervalSince(now)
        if delay > 0 { try? await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000)) }
    }
}

private struct ProviderLoad: Sendable {
    let index: Int
    let nodes: [NodeEndpoint]
    let warnings: [String]
    let error: String?
}

private struct HostResolution: Sendable {
    let host: String
    let addresses: [String]
    let error: String?
}
