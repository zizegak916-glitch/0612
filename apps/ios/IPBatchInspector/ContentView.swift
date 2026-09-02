import SwiftUI

struct ContentView: View {
    @StateObject private var model = AppModel()
    @State private var ipText = "1.1.1.1\n8.8.8.8"
    @State private var subscriptionURL = ""
    @State private var allowPrivate = false
    @State private var saveName = ""

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                TabView {
                    batchTab.tabItem { Label("Batch IP", systemImage: "list.bullet.rectangle") }
                    subscriptionTab.tabItem { Label("Subscription", systemImage: "link") }
                    routeTab.tabItem { Label("Exit & AI", systemImage: "network") }
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
            Section("Network boundary") { Text("Only subscription/provider downloads, OS DNS and public-IP intelligence are permitted. Node ports are never connected.") }
        }
    }

    private var routeTab: some View {
        Form {
            Button("Detect current exit IP") { model.detectExit() }.disabled(model.isRunning)
            Button("Test AI public entrances") { model.testAI() }.disabled(model.isRunning)
            Text("These requests use the current iOS system route and send no account, Cookie, API key or prompt. A response does not prove logged-in model availability.")
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
}
