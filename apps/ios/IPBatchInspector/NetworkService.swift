import Foundation

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
            configuration.httpAdditionalHeaders = ["User-Agent": "IPBatchInspector/4.0"]
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
    private static let userAgent = "IPBatchInspector/4.0"
    private static let iso = ISO8601DateFormatter()

    static func inspectSubscription(_ text: String, allowPrivate: Bool) async throws -> SubscriptionResult {
        let normalized = try unwrapSubscriptionURL(text)
        let loader = SafeTextLoader(allowPrivate: allowPrivate)
        let (data, _) = try await loader.load(normalized)
        guard let content = String(data: data, encoding: .utf8) else { throw NetworkError.response("Subscription is not UTF-8 text.") }
        var (nodes, providers, warnings) = SubscriptionParser.parse(content)
        for provider in providers.prefix(20) {
            guard let providerURL = URL(string: provider) else { continue }
            do {
                let providerLoader = SafeTextLoader(allowPrivate: allowPrivate)
                let (providerData, _) = try await providerLoader.load(providerURL)
                if let providerText = String(data: providerData, encoding: .utf8) {
                    let parsed = SubscriptionParser.parse(providerText)
                    nodes.append(contentsOf: parsed.0)
                    warnings.append(contentsOf: parsed.2)
                }
            } catch { warnings.append("Provider download failed: \(error.localizedDescription)") }
        }
        var seenNodes = Set<String>()
        nodes = Array(nodes.filter { seenNodes.insert("\($0.protocolName)|\($0.host)|\($0.port ?? 0)").inserted }.prefix(1500))
        var publicIPs: [String] = []
        var local: [String] = []
        for node in nodes {
            do {
                // Node port is intentionally not passed to DNS or any connection API.
                for address in try IPRules.resolve(node.host) {
                    if IPRules.isPublic(address) {
                        if !publicIPs.contains(address) && publicIPs.count < 500 { publicIPs.append(address) }
                    } else if !local.contains(address) { local.append(address) }
                }
            } catch { warnings.append("DNS failed for \(node.host): \(error.localizedDescription)") }
        }
        let counts = Dictionary(grouping: nodes, by: \.protocolName).mapValues(\.count)
        return SubscriptionResult(nodeCount: nodes.count, protocolCounts: counts, nodes: nodes, publicIPs: publicIPs, localOrReserved: local, warnings: warnings, rawContentPersisted: false, networkBoundary: "Downloaded subscription/provider text and used OS DNS only; no node port was connected.")
    }

    static func detectExit() async -> [[String: String]] {
        let endpoints = [
            ("ipify-v4", "https://api.ipify.org?format=json"),
            ("ipify-dual", "https://api64.ipify.org?format=json"),
            ("icanhazip", "https://icanhazip.com/")
        ]
        var rows: [[String: String]] = []
        for (name, address) in endpoints {
            do {
                var request = URLRequest(url: URL(string: address)!)
                request.setValue(userAgent, forHTTPHeaderField: "User-Agent")
                let (data, response) = try await URLSession.shared.data(for: request)
                let http = response as? HTTPURLResponse
                var value = String(decoding: data.prefix(4096), as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
                if let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] { value = object["ip"] as? String ?? value }
                rows.append(["source": name, "ip": value, "http": String(http?.statusCode ?? 0), "checked_at": iso.string(from: Date()), "meaning": "current iOS process route"])
            } catch { rows.append(["source": name, "error": error.localizedDescription, "checked_at": iso.string(from: Date())]) }
        }
        return rows
    }

    static func scanIPs(_ values: String) async -> [IPResult] {
        let tokens = values.components(separatedBy: CharacterSet(charactersIn: " ,;\n\t")).filter { !$0.isEmpty }
        var unique: [String] = []
        for token in tokens where IPRules.isPublic(token) && !unique.contains(token) && unique.count < 500 { unique.append(token) }
        var output: [IPResult] = []
        for ip in unique {
            var result = IPResult(ip: ip, status: "failed")
            let sources = [
                ("ipapi.is", "https://api.ipapi.is/?q=\(ip.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? ip)"),
                ("GeoJS", "https://get.geojs.io/v1/ip/geo/\(ip.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? ip).json"),
                ("RDAP", "https://rdap.org/ip/\(ip.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? ip)")
            ]
            for (source, address) in sources {
                let started = Date()
                do {
                    let object = try await fetchObject(address)
                    var fields: [String: String] = [:]
                    if source == "ipapi.is" {
                        let location = object["location"] as? [String: Any] ?? object
                        let asn = object["asn"] as? [String: Any] ?? [:]
                        fields["country"] = string(location["country"])
                        fields["country_code"] = string(location["country_code"])
                        fields["asn"] = string(asn["asn"])
                        fields["organization"] = string(asn["org"] ?? asn["name"])
                    } else if source == "GeoJS" {
                        fields["country"] = string(object["country"])
                        fields["country_code"] = string(object["country_code"])
                        fields["asn"] = string(object["asn"])
                        fields["organization"] = string(object["organization_name"] ?? object["organization"])
                    } else {
                        fields["range"] = "\(string(object["startAddress"])) - \(string(object["endAddress"]))"
                        fields["registration_name"] = string(object["name"] ?? object["handle"])
                    }
                    fields = fields.filter { !$0.value.isEmpty }
                    result.evidence.append(SourceEvidence(source: source, ok: true, elapsedMilliseconds: Int(Date().timeIntervalSince(started) * 1000), checkedAt: iso.string(from: Date()), fields: fields, error: nil))
                    if result.country.isEmpty { result.country = fields["country"] ?? "" }
                    if result.countryCode.isEmpty { result.countryCode = fields["country_code"] ?? "" }
                    if result.asn.isEmpty { result.asn = fields["asn"] ?? "" }
                    if result.organization.isEmpty { result.organization = fields["organization"] ?? "" }
                    result.status = "ok"
                } catch {
                    result.evidence.append(SourceEvidence(source: source, ok: false, elapsedMilliseconds: Int(Date().timeIntervalSince(started) * 1000), checkedAt: iso.string(from: Date()), fields: [:], error: error.localizedDescription))
                }
            }
            output.append(result)
        }
        return output
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
        var results: [EntranceResult] = []
        for (name, kind, address) in endpoints {
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
                results.append(EntranceResult(name: name, kind: kind, host: URL(string: address)!.host ?? "", httpCode: code, status: status, detail: detail, checkedAt: iso.string(from: Date())))
            } catch { results.append(EntranceResult(name: name, kind: kind, host: URL(string: address)!.host ?? "", httpCode: nil, status: "network-error", detail: error.localizedDescription, checkedAt: iso.string(from: Date()))) }
        }
        return results
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
