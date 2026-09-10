import SwiftUI

struct ContentView: View {
    @StateObject private var model = AppModel()
    @State private var ipText = "1.1.1.1\n8.8.8.8"
    @State private var subscriptionURL = ""
    @State private var allowPrivate = false
    @State private var saveName = ""
    @State private var detailIP = "1.1.1.1"

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                TabView {
                    batchTab.tabItem { Label("Batch IP", systemImage: "list.bullet.rectangle") }
                    subscriptionTab.tabItem { Label("Subscription", systemImage: "link") }
                    routeTab.tabItem { Label("Exit & AI", systemImage: "network") }
                    advancedTab.tabItem { Label("Advanced", systemImage: "shield.lefthalf.filled") }
                    savedTab.tabItem { Label("Saved", systemImage: "key") }
                }
                Divider()
                ScrollView([.horizontal, .vertical]) {
                    Text(model.output).font(.system(.caption, design: .monospaced)).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .topLeading).padding()
                }
                .frame(minHeight: 220)
                .background(Color(.secondarySystemBackground))
            }
            .navigationTitle("IPBatchInspector")
            .toolbar { if model.isRunning { ProgressView() } }
        }
    }

    private var batchTab: some View {
        Form {
            Section("IPv4 / IPv6 (max 500 public addresses)") {
                TextEditor(text: $ipText).font(.system(.body, design: .monospaced)).frame(minHeight: 130)
                Button("Run evidence scan") { model.scanIPs(ipText) }.disabled(model.isRunning)
            }
            Section("Truth boundary") { Text("Location and risk databases can be wrong or stale. Source, time, latency, fields and errors remain in the output.") }
        }
    }

    private var subscriptionTab: some View {
        Form {
            Section("Subscription URL") {
                TextField("https://…", text: $subscriptionURL).textInputAutocapitalization(.never).keyboardType(.URL)
                Toggle("Allow local/private subscription", isOn: $allowPrivate)
                Button("Inspect without connecting nodes") { model.inspectSubscription(subscriptionURL, allowPrivate: allowPrivate) }.disabled(model.isRunning || subscriptionURL.isEmpty)
            }
            Section("Save in iOS Keychain") {
                TextField("Display name", text: $saveName)
                Button("Save URL securely") { model.save(name: saveName, url: subscriptionURL) }.disabled(saveName.isEmpty || subscriptionURL.isEmpty)
            }
            Section("Network boundary") { Text("Only public IP literals directly exposed in server fields are investigated. Domain DNS answers are listed as infrastructure observations, never as node or exit IPs. Hidden relay, landing and chain exits are unobservable; node ports are never connected.") }
        }
    }

    private var routeTab: some View {
        Form {
            Button("Detect current exit IP") { model.detectExit() }.disabled(model.isRunning)
            Button("Record AI entrance responses") { model.testAI() }.disabled(model.isRunning)
            Text("These requests use only the current iOS route and send no account, Cookie, API key or prompt. HTTP evidence, IP geolocation, provider policy and a manual logged-in conversation are separate facts; no supported/unsupported verdict is inferred.")
        }
    }

    private var savedTab: some View {
        List {
            ForEach(model.savedNames, id: \.self) { name in
                Button(KeychainStore.redactedLabel(name: name)) {
                    if let value = try? KeychainStore.load(name: name) { subscriptionURL = value }
                }
            }
            .onDelete { offsets in offsets.map { model.savedNames[$0] }.forEach { model.delete(name: $0) } }
        }
    }

    private var advancedTab: some View {
        Form {
            Section("Single-IP detailed investigation") {
                TextField("One public IPv4 or IPv6", text: $detailIP).textInputAutocapitalization(.never)
                Button("Investigate public records + TLS certificate") { model.detailedInvestigation(detailIP) }
                    .disabled(model.isRunning || detailIP.isEmpty)
                Text("Queries RDAP, RIPEstat, Shodan InternetDB, GreyNoise and PTR, then actively connects only to TLS 443. Private/reserved IPs are rejected.")
            }
            Section("iOS background boundary") {
                Text("User-started investigation requests iOS background execution time, but iOS may suspend or terminate long jobs. This app contains no VPN tunnel, proxy switcher or subscription-node connection path.")
            }
        }
    }
}
