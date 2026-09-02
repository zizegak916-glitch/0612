import SwiftUI
import UIKit

@MainActor
final class AppModel: ObservableObject {
    @Published var output = "Ready. Subscription nodes are never connected."
    @Published var isRunning = false
    @Published var savedNames = KeychainStore.names()

    func scanIPs(_ text: String) {
        run("Scanning public IPs…") { JSONRender.string(await NetworkService.scanIPs(text)) }
    }

    func detectExit() {
        run("Detecting the current iOS process exit…") { JSONRender.string(await NetworkService.detectExit()) }
    }

    func testAI() {
        run("Testing public AI entrances…") { JSONRender.string(await NetworkService.testAIEntrances()) }
    }

    func inspectSubscription(_ url: String, allowPrivate: Bool) {
        run("Downloading, parsing and resolving…") { JSONRender.string(try await NetworkService.inspectSubscription(url, allowPrivate: allowPrivate)) }
    }

    func save(name: String, url: String) {
        do {
            try KeychainStore.save(name: name, url: url)
            savedNames = KeychainStore.names()
            output = "Saved '\(name)' in iOS Keychain."
        } catch { output = "Save failed: \(error.localizedDescription)" }
    }

    func delete(name: String) {
        KeychainStore.delete(name: name)
        savedNames = KeychainStore.names()
    }

    private func run(_ message: String, operation: @escaping () async throws -> String) {
        guard !isRunning else { return }
        isRunning = true
        output = message
        let task = UIApplication.shared.beginBackgroundTask(withName: "IPBatchInspector user task")
        Task {
            defer {
                if task != .invalid { UIApplication.shared.endBackgroundTask(task) }
                isRunning = false
            }
            do { output = try await operation() }
            catch { output = "Error: \(error.localizedDescription)" }
        }
    }
}
