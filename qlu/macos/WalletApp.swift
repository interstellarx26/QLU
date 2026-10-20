// QLU's local development wallet. No network client, embedded browser, or telemetry.
// Signing and encrypted storage stay in the existing Python wallet foundation.
import AppKit
import SwiftUI
import CoreImage.CIFilterBuiltins
import UniformTypeIdentifiers

private enum Palette {
    static let ink = Color(red: 0.047, green: 0.086, blue: 0.118)
    static let panel = Color(red: 0.078, green: 0.125, blue: 0.157)
    static let border = Color.white.opacity(0.10)
    static let mint = Color(red: 0.65, green: 0.91, blue: 0.78)
    static let ivory = Color(red: 0.94, green: 0.95, blue: 0.91)
    static let muted = Color(red: 0.60, green: 0.67, blue: 0.69)
    static let amber = Color(red: 0.97, green: 0.77, blue: 0.46)
}

private struct BridgeFailure: Error {
    let code: String
    let message: String
    let txid: String?
    static let unavailable = BridgeFailure(
        code: "unavailable",
        message: "The local wallet service is unavailable. Close and reopen QLU Wallet.",
        txid: nil)
}

/// A single serial pipe, never a shell. Every response must fit one bounded JSON line.
private final class WalletBridge: @unchecked Sendable {
    private let queue = DispatchQueue(label: "com.vibexhq.qlu.private-wallet")
    private let guardLock = NSLock()
    private var process: Process?
    private var input: FileHandle?
    private var output: FileHandle?
    private var sequence = 0
    private var activeRequest: Int?
    private var stopped = false
    private let root: URL?

    init() {
        if let path = Bundle.main.object(forInfoDictionaryKey: "QLUProjectRoot") as? String,
           path.hasPrefix("/") {
            root = URL(fileURLWithPath: path, isDirectory: true)
        } else {
            root = nil
        }
    }

    private func launch() throws {
        if process != nil { return }
        guard let root, !stopped else { throw BridgeFailure.unavailable }
        let executable = root.appendingPathComponent(".local/recovery-venv/bin/python")
        guard FileManager.default.isExecutableFile(atPath: executable.path) else {
            throw BridgeFailure.unavailable
        }
        let child = Process()
        let incoming = Pipe()
        let outgoing = Pipe()
        child.executableURL = executable
        child.arguments = [root.appendingPathComponent("qlu/wallet_app.py").path, "--stdio"]
        child.currentDirectoryURL = root
        child.standardInput = incoming
        child.standardOutput = outgoing
        child.standardError = FileHandle.nullDevice
        // Preserve the local build's runtime configuration. Secrets never enter argv/env.
        child.environment = ProcessInfo.processInfo.environment
        try child.run()
        process = child
        input = incoming.fileHandleForWriting
        output = outgoing.fileHandleForReading
    }

    func request(_ command: String, _ params: [String: Any] = [:],
                 completion: @escaping (Result<[String: Any], BridgeFailure>) -> Void) {
        queue.async { [self] in
            do {
                try launch()
                sequence += 1
                let id = sequence
                guardLock.lock()
                activeRequest = id
                guardLock.unlock()
                DispatchQueue.global().asyncAfter(deadline: .now() + 120) { [weak self] in
                    guard let self else { return }
                    self.guardLock.lock()
                    let expired = self.activeRequest == id
                    self.guardLock.unlock()
                    // Quitting can wait on node cleanup. Never interrupt that cleanup.
                    if expired && command != "quit" { self.terminate() }
                }
                defer {
                    guardLock.lock()
                    activeRequest = nil
                    guardLock.unlock()
                }
                let payload: [String: Any] = ["id": id, "command": command, "params": params]
                var data = try JSONSerialization.data(withJSONObject: payload)
                guard data.count < 65_536 else { throw BridgeFailure.unavailable }
                data.append(0x0A)
                try input?.write(contentsOf: data)
                var line = Data()
                while true {
                    guard let byte = try output?.read(upToCount: 1), !byte.isEmpty else {
                        throw BridgeFailure.unavailable
                    }
                    if byte[0] == 0x0A { break }
                    guard line.count < 65_536 else { throw BridgeFailure.unavailable }
                    line.append(byte)
                }
                guard let envelope = try JSONSerialization.jsonObject(with: line) as? [String: Any],
                      let returnedID = envelope["id"] as? Int, returnedID == id,
                      let ok = envelope["ok"] as? Bool else { throw BridgeFailure.unavailable }
                if ok, let result = envelope["result"] as? [String: Any] {
                    DispatchQueue.main.async { completion(.success(result)) }
                } else if !ok, let error = envelope["error"] as? [String: Any],
                          let code = error["code"] as? String,
                          let message = error["message"] as? String, message.count <= 512 {
                    // The backend supplies fixed safe messages, never raw exception strings.
                    let failure = BridgeFailure(code: code, message: message,
                                                txid: error["txid"] as? String)
                    DispatchQueue.main.async { completion(.failure(failure)) }
                } else {
                    throw BridgeFailure.unavailable
                }
            } catch {
                terminate()
                let failure: BridgeFailure
                if command == "confirm_send" || command == "faucet" {
                    failure = BridgeFailure(code: "payment_unknown",
                        message: "The wallet service stopped responding after payment authorization. The payment may have been submitted. Do not repeat it.",
                        txid: nil)
                } else {
                    failure = .unavailable
                }
                DispatchQueue.main.async { completion(.failure(failure)) }
            }
        }
    }

    func terminate() {
        guardLock.lock()
        stopped = true
        let child = process
        guardLock.unlock()
        if child?.isRunning == true { child?.terminate() }
        try? input?.close()
    }

    func shutdown(completion: @escaping (Result<Void, BridgeFailure>) -> Void) {
        request("quit") { [weak self] result in
            switch result {
            case .success(let result) where result["closed"] as? Bool == true:
                self?.terminate()
                completion(.success(()))
            case .failure(let failure):
                completion(.failure(failure))
            default:
                completion(.failure(.unavailable))
            }
        }
    }
}

private struct WalletState {
    var walletOpen = false
    var locked = true
    var backupVerified = false
    var address: String?
    var walletPath: String?
    var networkRunning = false
    var balance: String?
    var immatureBalance: String?
    var recentPayment: [String: Any]?

    init(_ value: [String: Any] = [:]) {
        walletOpen = value["wallet_open"] as? Bool ?? false
        locked = value["locked"] as? Bool ?? true
        backupVerified = value["backup_verified"] as? Bool ?? false
        address = value["address"] as? String
        walletPath = value["wallet_path"] as? String
        networkRunning = value["network_running"] as? Bool ?? false
        balance = value["balance"] as? String
        immatureBalance = value["immature_balance"] as? String
        recentPayment = value["recent_payment"] as? [String: Any]
    }
}

private enum Destination: String, CaseIterable {
    case wallet = "Wallet", receive = "Receive", send = "Send", backup = "Backup"
    var symbol: String {
        switch self {
        case .wallet: return "square.grid.2x2"
        case .receive: return "arrow.down.left"
        case .send: return "arrow.up.right"
        case .backup: return "shield.lefthalf.filled"
        }
    }
}

private enum WalletSheet: String, Identifiable {
    case create, recover, unlock, open
    var id: String { rawValue }
}

@MainActor
private final class WalletModel: ObservableObject {
    @Published var state = WalletState()
    @Published var destination = Destination.wallet
    @Published var sheet: WalletSheet?
    @Published var busy = false
    @Published var busyMessage = ""
    @Published var notice: String?
    @Published var error: String?
    @Published var pendingTXID: String?
    @Published var paymentUncertain = false
    @Published var wallets: [[String: String]] = []
    @Published var passphrase = ""
    @Published var confirmation = ""
    @Published var recoveryInput = ""
    @Published var recoveryCode = ""
    @Published var backupPath = ""
    @Published var restorePath = ""
    @Published var recipient = ""
    @Published var amount = ""
    @Published var preview: [String: Any]?
    @Published var privacyLocked = false
    @Published var cleanupWaiting = false
    @Published var codeAcknowledged = false
    private let bridge = WalletBridge()
    private var polling: Timer?
    private var panelIsOpen = false
    private var lockAfterPanel = false
    private var privacyGeneration = 0
    private var quitting = false
    private var quitAttempt = 0
    private var backendClosed = false

    var isLocked: Bool { state.locked || privacyLocked }
    var canUseWallet: Bool { state.walletOpen && !isLocked && state.backupVerified }
    var passphraseValid: Bool {
        passphrase.count >= 15 && passphrase.utf8.count <= 1024 && passphrase == confirmation
    }

    init() {
        refreshStatus()
        loadWallets()
        startPolling()
    }

    private func startPolling() {
        polling?.invalidate()
        polling = Timer.scheduledTimer(withTimeInterval: 5, repeats: true) { [weak self] _ in
            Task { @MainActor in
                guard let self, !self.busy, !self.quitting else { return }
                self.refreshStatus()
            }
        }
    }

    private func perform(_ command: String, params: [String: Any] = [:], message: String,
                         completion: @escaping ([String: Any]) -> Void) {
        guard !busy, !quitting else { return }
        busy = true
        busyMessage = message
        error = nil
        notice = nil
        bridge.request(command, params) { [weak self] result in
            guard let self, !self.quitting else { return }
            self.busy = false
            self.busyMessage = ""
            switch result {
            case .success(let result): completion(result)
            case .failure(let failure):
                self.error = failure.message
                if failure.code == "payment_pending" || failure.code == "payment_unknown" {
                    self.paymentUncertain = true
                    self.pendingTXID = failure.txid
                    self.preview = nil
                    self.error = "Confirmation is uncertain. Keep this transaction ID if available; do not repeat this payment."
                }
                self.refreshStatus()
            }
        }
    }

    private func apply(_ result: [String: Any]) {
        let wasLocked = state.locked
        state = WalletState(result)
        if state.recentPayment?["status"] as? String == "pending" {
            paymentUncertain = true
            pendingTXID = state.recentPayment?["txid"] as? String
        }
        // A public status poll must not erase a passphrase currently being entered
        // into the unlock/create sheet. Only a new lock transition clears inputs.
        if state.locked && !wasLocked { clearSecrets() }
        if state.locked {
            recoveryCode = ""
            preview = nil
        }
        // An unlock-producing request may finish after the app lost focus. Keep
        // the UI covered and serialize a lock after that result as a backstop,
        // including first-time create/restore before walletOpen becomes true.
        if state.walletOpen && !state.locked && !NSApplication.shared.isActive && !quitting {
            lock()
        }
    }

    private func clearSecrets() {
        passphrase = ""
        confirmation = ""
        recoveryInput = ""
        recoveryCode = ""
        preview = nil
    }

    func refreshStatus() {
        bridge.request("status") { [weak self] result in
            guard let self, !self.quitting else { return }
            switch result {
            case .success(let state): self.apply(state)
            case .failure(let failure):
                if !self.paymentUncertain { self.error = failure.message }
            }
        }
    }

    func loadWallets() {
        bridge.request("wallets") { [weak self] result in
            if case .success(let value) = result {
                self?.wallets = value["wallets"] as? [[String: String]] ?? []
            }
        }
    }

    func present(_ kind: WalletSheet) {
        clearSecrets()
        error = nil
        sheet = kind
        if kind == .open { loadWallets() }
    }

    func dismissSheet() {
        sheet = nil
        passphrase = ""
        confirmation = ""
        recoveryInput = ""
    }

    func create() {
        let parameters = ["passphrase": passphrase, "confirmation": confirmation]
        passphrase = ""
        confirmation = ""
        perform("create", params: parameters, message: "Creating your encrypted wallet…") { [weak self] result in
            guard let self else { return }
            self.apply(result)
            self.dismissSheet()
            self.destination = .backup
            self.backupPath = ""
            self.codeAcknowledged = false
            self.notice = "Your wallet is created. Save and verify its backup to finish."
            self.loadWallets()
        }
    }

    func restore() {
        let parameters = ["backup_path": restorePath, "code": recoveryInput,
                          "passphrase": passphrase, "confirmation": confirmation]
        passphrase = ""
        confirmation = ""
        recoveryInput = ""
        perform("restore", params: parameters, message: "Restoring into a new encrypted wallet…") { [weak self] result in
            guard let self else { return }
            self.apply(result)
            self.dismissSheet()
            self.destination = .wallet
            self.notice = "Wallet recovered. Your existing wallet files were preserved."
            self.loadWallets()
        }
    }

    func openWallet(_ path: String) {
        clearSecrets()
        perform("open", params: ["path": path], message: "Opening your wallet…") { [weak self] result in
            guard let self else { return }
            self.apply(result)
            self.dismissSheet()
            self.destination = .wallet
            self.backupPath = ""
            self.codeAcknowledged = false
            self.notice = "Wallet opened and locked. Unlock it, then verify your saved backup."
        }
    }

    func unlock() {
        let parameters = ["passphrase": passphrase]
        passphrase = ""
        let generation = privacyGeneration
        perform("unlock", params: parameters, message: "Unlocking your wallet…") { [weak self] result in
            guard let self else { return }
            self.apply(result)
            if self.privacyGeneration == generation && NSApplication.shared.isActive {
                self.privacyLocked = false
            }
            self.dismissSheet()
            if !self.state.backupVerified { self.destination = .backup }
        }
    }

    func lock() {
        privacyGeneration += 1
        let generation = privacyGeneration
        privacyLocked = true
        clearSecrets()
        sheet = nil
        bridge.request("lock") { [weak self] result in
            guard let self else { return }
            if case .success(let state) = result {
                self.apply(state)
                if self.privacyGeneration == generation && self.state.locked {
                    self.privacyLocked = false
                }
            }
        }
    }

    func resignActive() {
        guard !quitting && !cleanupWaiting else {
            clearSecrets()
            return
        }
        if panelIsOpen {
            lockAfterPanel = true
        } else {
            lock()
        }
    }

    private func finishPanel() {
        panelIsOpen = false
        if lockAfterPanel || !NSApplication.shared.isActive {
            lockAfterPanel = false
            lock()
        }
    }

    func chooseBackup(toRestore: Bool) {
        let panel = NSOpenPanel()
        panel.title = "Choose your encrypted QLU backup"
        panel.allowedContentTypes = [.json]
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panelIsOpen = true
        let accepted = panel.runModal() == .OK
        if accepted, let url = panel.url {
            if toRestore { restorePath = url.path } else { backupPath = url.path }
        }
        finishPanel()
    }

    func chooseWallet() {
        let panel = NSOpenPanel()
        panel.title = "Open an encrypted QLU wallet"
        panel.allowedContentTypes = [.json]
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panelIsOpen = true
        let accepted = panel.runModal() == .OK
        let path = accepted ? panel.url?.path : nil
        finishPanel()
        if let path { openWallet(path) }
    }

    func createBackup() {
        let panel = NSSavePanel()
        panel.title = "Save an encrypted QLU backup"
        panel.nameFieldStringValue = "QLU-backup-\(Int(Date().timeIntervalSince1970)).json"
        panel.allowedContentTypes = [.json]
        panel.canCreateDirectories = true
        panel.message = "Keep a copy somewhere safe. Your separate recovery code is needed to use it."
        panelIsOpen = true
        let accepted = panel.runModal() == .OK
        let path = accepted ? panel.url?.path : nil
        finishPanel()
        guard let path, !isLocked else { return }
        let generation = privacyGeneration
        perform("backup_create", params: ["backup_path": path], message: "Saving your encrypted backup…") { [weak self] result in
            guard let self else { return }
            self.backupPath = result["backup_path"] as? String ?? path
            self.codeAcknowledged = false
            if generation == self.privacyGeneration, !self.isLocked {
                self.recoveryCode = result["code"] as? String ?? ""
            } else {
                self.notice = "Backup saved, but its code was hidden when the app locked. Unlock and create a new backup."
            }
        }
    }

    func acknowledgeCode() {
        recoveryCode = ""
        codeAcknowledged = true
        recoveryInput = ""
    }

    func verifyBackup() {
        let parameters = ["backup_path": backupPath, "code": recoveryInput]
        recoveryInput = ""
        perform("backup_verify", params: parameters, message: "Checking the saved backup and your code…") { [weak self] result in
            guard let self else { return }
            self.apply(result)
            self.codeAcknowledged = false
            self.notice = "Backup verified. You’re ready to receive and send private test QLU."
            self.destination = .wallet
        }
    }

    func networkToggle() {
        let command = state.networkRunning ? "network_stop" : "network_start"
        let message = state.networkRunning ? "Stopping your private network…" : "Starting your private network…"
        perform(command, message: message) { [weak self] result in self?.apply(result) }
    }

    func refresh() {
        perform("refresh", message: "Checking the private network…") { [weak self] result in
            self?.apply(result)
        }
    }

    func faucet() {
        guard !paymentUncertain else { return }
        perform("faucet", message: "Adding test QLU and confirming it on four nodes…") { [weak self] result in
            if let state = result["state"] as? [String: Any] { self?.apply(state) }
            self?.notice = "Test QLU added. These coins have no monetary value."
        }
    }

    func prepareSend() {
        guard !paymentUncertain else { return }
        perform("prepare_send", params: ["recipient": recipient, "amount": amount],
                message: "Preparing your payment for review…") { [weak self] result in
            self?.preview = result
        }
    }

    func cancelSend() {
        preview = nil
        bridge.request("cancel_send") { [weak self] result in
            if case .success(let state) = result { self?.apply(state) }
        }
    }

    func confirmSend() {
        guard let id = preview?["preview_id"] as? String else { return }
        preview = nil
        perform("confirm_send", params: ["preview_id": id],
                message: "Signing and confirming your exact payment…") { [weak self] result in
            if let state = result["state"] as? [String: Any] { self?.apply(state) }
            self?.recipient = ""
            self?.amount = ""
            self?.pendingTXID = nil
            self?.paymentUncertain = false
            self?.notice = "Payment confirmed on all four private nodes."
            self?.destination = .wallet
        }
    }

    func copyAddress() {
        guard canUseWallet, let address = state.address else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(address, forType: .string)
        notice = "Receiving address copied."
    }

    func shutdown(completion: @escaping (Bool) -> Void) {
        if backendClosed { completion(true); return }
        guard !quitting else { return }
        quitting = true
        cleanupWaiting = true
        quitAttempt += 1
        let attempt = quitAttempt
        polling?.invalidate()
        clearSecrets()
        sheet = nil
        privacyLocked = true
        bridge.shutdown { [weak self] result in
            guard let self else { return }
            if case .success = result { self.backendClosed = true }
            guard self.quitting && self.quitAttempt == attempt else {
                if self.backendClosed {
                    self.notice = "Your private nodes have stopped. You can now close QLU Wallet."
                }
                return
            }
            self.quitting = false
            switch result {
            case .success: completion(true)
            case .failure(let failure):
                self.cleanupWaiting = false
                self.error = failure.message
                self.bridge.request("status") { [weak self] result in
                    guard let self else { return }
                    if case .success(let state) = result {
                        self.apply(state)
                        if self.state.locked { self.privacyLocked = false }
                    }
                }
                self.startPolling()
                completion(false)
            }
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 45) { [weak self] in
            guard let self, self.quitting, self.quitAttempt == attempt else { return }
            self.quitting = false
            self.error = "The private network is taking longer to stop. Your wallet is locked. Leave the app open while cleanup finishes, then try closing it again."
            // Keep the pipe and cleanup process alive. Do not enqueue status polls
            // behind a stalled quit or terminate a process that owns local nodes.
            completion(false)
        }
    }
}

private struct PrimaryButtonStyle: ButtonStyle {
    @Environment(\.isEnabled) private var isEnabled
    var prominent = true
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: 14, weight: .semibold))
            .padding(.horizontal, 18)
            .padding(.vertical, 12)
            .foregroundStyle(prominent ? Palette.ink : Palette.ivory)
            .background(prominent ? Palette.mint : Color.white.opacity(0.07))
            .clipShape(RoundedRectangle(cornerRadius: 10))
            .opacity(!isEnabled ? 0.38 : (configuration.isPressed ? 0.7 : 1))
    }
}

private struct Card<Content: View>: View {
    @ViewBuilder let content: Content
    var body: some View {
        VStack(alignment: .leading, spacing: 18) { content }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(24)
            .background(Palette.panel)
            .clipShape(RoundedRectangle(cornerRadius: 18))
            .overlay(RoundedRectangle(cornerRadius: 18).stroke(Palette.border, lineWidth: 1))
    }
}

private struct FieldLabel: View {
    let text: String
    var body: some View {
        Text(text).font(.system(size: 13, weight: .medium)).foregroundStyle(Palette.ivory)
    }
}

private extension View {
    func walletField() -> some View {
        self.textFieldStyle(.plain)
            .font(.system(size: 15))
            .padding(13)
            .background(Palette.ink)
            .clipShape(RoundedRectangle(cornerRadius: 9))
            .overlay(RoundedRectangle(cornerRadius: 9).stroke(Palette.border, lineWidth: 1))
    }
}

private struct RootView: View {
    @EnvironmentObject var model: WalletModel
    var body: some View {
        HStack(spacing: 0) {
            sidebar
            VStack(spacing: 0) {
                topbar
                ScrollView {
                    VStack(alignment: .leading, spacing: 23) {
                        if let error = model.error {
                            message(error, symbol: "exclamationmark.circle", color: Palette.amber)
                        }
                        if let notice = model.notice {
                            message(notice, symbol: "checkmark.circle", color: Palette.mint)
                        }
                        if model.busy {
                            HStack(spacing: 12) {
                                ProgressView().controlSize(.small)
                                Text(model.busyMessage).font(.system(size: 13))
                            }.foregroundStyle(Palette.muted)
                        }
                        if !model.state.walletOpen {
                            WelcomeView()
                        } else {
                            switch model.destination {
                            case .wallet: DashboardView()
                            case .receive: ReceiveView()
                            case .send: SendView()
                            case .backup: BackupView()
                            }
                        }
                        Text("PRIVATE DEVELOPMENT NETWORK  ·  TEST COINS HAVE NO MONETARY VALUE")
                            .font(.system(size: 9, weight: .semibold, design: .monospaced))
                            .tracking(1.0)
                            .foregroundStyle(Palette.muted.opacity(0.8))
                            .padding(.top, 6)
                    }
                    .padding(32)
                    .frame(maxWidth: 930, alignment: .leading)
                    .frame(maxWidth: .infinity)
                }
                .scrollIndicators(.hidden)
            }
        }
        .background(Palette.ink)
        .foregroundStyle(Palette.ivory)
        .tint(Palette.mint)
        .preferredColorScheme(.dark)
        .frame(minWidth: 900, minHeight: 680)
        .disabled(model.cleanupWaiting)
        .sheet(item: $model.sheet, onDismiss: { model.dismissSheet() }) { kind in
            WalletSheetView(kind: kind)
                .environmentObject(model)
        }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didResignActiveNotification)) { _ in
            model.resignActive()
        }
        // Hiding does not consistently emit didResignActive in every activation
        // environment. Treat an explicit hide as a separate privacy boundary.
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didHideNotification)) { _ in
            model.lock()
        }
        .onReceive(NotificationCenter.default.publisher(for: NSWindow.didMiniaturizeNotification)) { notification in
            guard let window = notification.object as? NSWindow,
                  window.title == "QLU Wallet" else { return }
            model.lock()
        }
        .onReceive(NSWorkspace.shared.notificationCenter.publisher(for: NSWorkspace.willSleepNotification)) { _ in
            model.lock()
        }
    }

    private var sidebar: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 12) {
                ZStack {
                    RoundedRectangle(cornerRadius: 13).fill(Palette.mint).frame(width: 42, height: 42)
                    Text("Q").font(.system(size: 28, weight: .bold, design: .rounded)).foregroundStyle(Palette.ink)
                }
                VStack(alignment: .leading, spacing: 2) {
                    Text("QLU").font(.system(size: 24, weight: .bold, design: .rounded)).tracking(2)
                    Text("YOUR WALLET").font(.system(size: 8, weight: .semibold)).tracking(2).foregroundStyle(Palette.muted)
                }
            }.padding(.bottom, 46)
            ForEach(Destination.allCases, id: \.self) { item in
                Button {
                    if model.preview != nil { model.cancelSend() }
                    model.destination = item
                } label: {
                    HStack(spacing: 13) {
                        Image(systemName: item.symbol).frame(width: 20)
                        Text(item.rawValue)
                        Spacer()
                        if model.destination == item { Circle().fill(Palette.mint).frame(width: 5, height: 5) }
                    }
                    .font(.system(size: 14, weight: model.destination == item ? .semibold : .regular))
                    .foregroundStyle(model.destination == item ? Palette.ivory : Palette.muted)
                    .padding(.horizontal, 15).padding(.vertical, 14)
                    .background(model.destination == item ? Color.white.opacity(0.065) : Color.clear)
                    .clipShape(RoundedRectangle(cornerRadius: 11))
                }
                .buttonStyle(.plain)
                .accessibilityIdentifier("nav-\(item.rawValue.lowercased())")
                .padding(.bottom, 6)
                .disabled(model.busy)
            }
            Spacer()
            VStack(alignment: .leading, spacing: 11) {
                HStack(spacing: 7) {
                    Circle().fill(model.state.networkRunning ? Palette.mint : Palette.muted).frame(width: 6, height: 6)
                    Text("Private network").font(.system(size: 12, weight: .medium))
                }
                Text("A small beginning.\nBuilt with care.")
                    .font(.system(size: 12)).lineSpacing(4).foregroundStyle(Palette.muted)
            }.padding(.horizontal, 12)
        }
        .padding(.horizontal, 20).padding(.top, 35).padding(.bottom, 30)
        .frame(width: 210)
        .background(Color.black.opacity(0.16))
        .overlay(alignment: .trailing) { Rectangle().fill(Palette.border).frame(width: 1) }
    }

    private var topbar: some View {
        HStack {
            Text(model.state.walletOpen ? model.destination.rawValue : "Welcome home")
                .font(.system(size: 14, weight: .medium))
            Spacer()
            if model.state.walletOpen {
                Label(model.isLocked ? "Locked" : "Unlocked", systemImage: model.isLocked ? "lock.fill" : "lock.open")
                    .font(.system(size: 12))
                    .foregroundStyle(model.isLocked ? Palette.muted : Palette.mint)
                Button(model.isLocked ? "Unlock" : "Lock") {
                    if model.isLocked { model.present(.unlock) } else { model.lock() }
                }
                .buttonStyle(PrimaryButtonStyle(prominent: false))
                .accessibilityIdentifier("wallet-lock-toggle")
                .disabled(model.busy)
            }
            Text("PRIVATE V1").font(.system(size: 9, weight: .bold)).tracking(1)
                .foregroundStyle(Palette.mint).padding(.horizontal, 10).padding(.vertical, 7)
                .overlay(Capsule().stroke(Palette.mint.opacity(0.3), lineWidth: 1))
        }.padding(.horizontal, 32).padding(.vertical, 20)
            .overlay(alignment: .bottom) { Rectangle().fill(Palette.border).frame(height: 1) }
    }

    private func message(_ text: String, symbol: String, color: Color) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: symbol)
            Text(text).textSelection(.enabled)
            Spacer(minLength: 0)
        }
        .font(.system(size: 13)).foregroundStyle(color)
        .padding(14).background(color.opacity(0.07)).clipShape(RoundedRectangle(cornerRadius: 10))
    }
}

private struct ScreenHeading: View {
    let eyebrow: String
    let title: String
    let subtitle: String
    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(eyebrow.uppercased()).font(.system(size: 10, weight: .bold)).tracking(2).foregroundStyle(Palette.mint)
            Text(title).font(.system(size: 32, weight: .semibold, design: .rounded))
            Text(subtitle).font(.system(size: 14)).lineSpacing(4).foregroundStyle(Palette.muted)
        }
    }
}

private struct WelcomeView: View {
    @EnvironmentObject var model: WalletModel
    var body: some View {
        VStack(alignment: .leading, spacing: 26) {
            ScreenHeading(eyebrow: "A simpler way to begin", title: "Your QLU, close at hand.",
                          subtitle: "Create a wallet, keep a backup, and try your first payment.\nEverything here stays on your private test network.")
            HStack(alignment: .top, spacing: 16) {
                Card {
                    Image(systemName: "sparkle").font(.system(size: 26)).foregroundStyle(Palette.mint)
                    Text("Start fresh").font(.system(size: 21, weight: .semibold))
                    Text("Create an encrypted wallet with a passphrase you choose.")
                        .foregroundStyle(Palette.muted).font(.system(size: 13)).frame(minHeight: 42, alignment: .top)
                    Button("Create a wallet") { model.present(.create) }
                        .buttonStyle(PrimaryButtonStyle()).accessibilityIdentifier("create-wallet")
                }
                Card {
                    Image(systemName: "arrow.counterclockwise").font(.system(size: 26)).foregroundStyle(Palette.mint)
                    Text("Welcome back").font(.system(size: 21, weight: .semibold))
                    Text("Bring your encrypted backup and separate recovery code.")
                        .foregroundStyle(Palette.muted).font(.system(size: 13)).frame(minHeight: 42, alignment: .top)
                    Button("Recover a wallet") { model.present(.recover) }
                        .buttonStyle(PrimaryButtonStyle(prominent: false)).accessibilityIdentifier("recover-wallet")
                }
            }
            Button { model.present(.open) } label: {
                Label("Open a wallet already on this Mac", systemImage: "folder")
                    .font(.system(size: 13)).foregroundStyle(Palette.muted)
            }.buttonStyle(.plain).accessibilityIdentifier("open-wallet")
            Card {
                Label("Your keys stay on this Mac", systemImage: "lock.shield")
                    .font(.system(size: 14, weight: .medium))
                Text("QLU encrypts your wallet locally. Your backup and recovery code restore access; VibexHQ cannot reset it for you.")
                    .font(.system(size: 13)).foregroundStyle(Palette.muted).lineSpacing(4)
            }
        }.disabled(model.busy)
    }
}

private struct WalletGate<Content: View>: View {
    @EnvironmentObject var model: WalletModel
    @ViewBuilder let content: Content
    var body: some View {
        if model.isLocked {
            Card {
                Label("Your wallet is locked", systemImage: "lock.fill").font(.system(size: 20, weight: .semibold))
                Text("Unlock to continue. Your wallet also locks after five minutes without a key operation and when you leave the app.")
                    .font(.system(size: 14)).foregroundStyle(Palette.muted).lineSpacing(4)
                Button("Unlock wallet") { model.present(.unlock) }.buttonStyle(PrimaryButtonStyle())
                    .accessibilityIdentifier("unlock-wallet")
            }
        } else if !model.state.backupVerified {
            Card {
                Label("Finish your backup first", systemImage: "shield.lefthalf.filled").font(.system(size: 20, weight: .semibold))
                Text("Verify your saved backup and recovery code before receiving or sending QLU.")
                    .font(.system(size: 14)).foregroundStyle(Palette.muted)
                Button("Go to backup") { model.destination = .backup }.buttonStyle(PrimaryButtonStyle())
            }
        } else {
            content
        }
    }
}

private struct DashboardView: View {
    @EnvironmentObject var model: WalletModel
    var body: some View {
        VStack(alignment: .leading, spacing: 23) {
            ScreenHeading(eyebrow: "Your everyday wallet", title: "A clear view of your QLU.",
                          subtitle: "Try a payment. Learn the flow. Keep control of your keys.")
            WalletGate {
                Card {
                    HStack {
                        Text("AVAILABLE BALANCE").font(.system(size: 10, weight: .semibold)).tracking(1.5).foregroundStyle(Palette.muted)
                        Spacer()
                        Button { model.refresh() } label: { Image(systemName: "arrow.clockwise") }
                            .buttonStyle(.plain).accessibilityLabel("Refresh balance")
                            .disabled(!model.state.networkRunning)
                    }
                    HStack(alignment: .firstTextBaseline, spacing: 10) {
                        Text(model.state.balance ?? "—").font(.system(size: 39, weight: .medium, design: .rounded)).monospacedDigit()
                        Text("QLU").font(.system(size: 17, weight: .medium)).foregroundStyle(Palette.muted)
                    }
                    if let immature = model.state.immatureBalance, immature != "0.00000000" {
                        Text("\(immature) QLU waiting to mature").font(.system(size: 12)).foregroundStyle(Palette.muted)
                    }
                    HStack(spacing: 12) {
                        Button { model.destination = .send } label: { Label("Send", systemImage: "arrow.up.right") }
                            .buttonStyle(PrimaryButtonStyle())
                        Button { model.destination = .receive } label: { Label("Receive", systemImage: "arrow.down.left") }
                            .buttonStyle(PrimaryButtonStyle(prominent: false))
                        Spacer()
                        Text("TEST COINS").font(.system(size: 9, weight: .bold)).tracking(1).foregroundStyle(Palette.muted)
                    }
                }
                if let payment = model.state.recentPayment {
                    Card {
                        HStack {
                            Label("Latest payment", systemImage: payment["status"] as? String == "pending" ? "clock" : "checkmark.circle")
                                .foregroundStyle(payment["status"] as? String == "pending" ? Palette.amber : Palette.mint)
                            Spacer()
                            Text("\(payment["amount"] as? String ?? "—") QLU").fontWeight(.semibold)
                        }.font(.system(size: 14))
                        Text(payment["txid"] as? String ?? "").font(.system(size: 10, design: .monospaced))
                            .foregroundStyle(Palette.muted).textSelection(.enabled)
                        Text(payment["status"] as? String == "pending"
                             ? "Confirmation not yet verified. Do not repeat this payment."
                             : "Confirmed on \(payment["confirmed_nodes"] as? Int ?? 0) private nodes")
                            .font(.system(size: 12)).foregroundStyle(Palette.muted)
                    }
                }
            }
            Card {
                HStack {
                    VStack(alignment: .leading, spacing: 7) {
                        Text("Your private network").font(.system(size: 16, weight: .semibold))
                        Text(model.state.networkRunning ? "Four local nodes are running." : "Start the local network to check balances and make payments.")
                            .font(.system(size: 12)).foregroundStyle(Palette.muted)
                    }
                    Spacer()
                    Button(model.state.networkRunning ? "Stop network" : "Start network") { model.networkToggle() }
                        .buttonStyle(PrimaryButtonStyle(prominent: false)).accessibilityIdentifier("network-toggle")
                }
                if model.canUseWallet && model.state.networkRunning {
                    Button("Add 1 test QLU") { model.faucet() }
                        .buttonStyle(PrimaryButtonStyle(prominent: false)).accessibilityIdentifier("test-faucet")
                        .disabled(model.paymentUncertain)
                }
            }
            HStack {
                Button("Switch wallet") { model.present(.open) }
                Text("·").foregroundStyle(Palette.muted)
                Button("Create another") { model.present(.create) }
                Text("·").foregroundStyle(Palette.muted)
                Button("Recover") { model.present(.recover) }
            }.buttonStyle(.plain).font(.system(size: 12)).foregroundStyle(Palette.muted)
        }.disabled(model.busy)
    }
}

private struct ReceiveView: View {
    @EnvironmentObject var model: WalletModel
    var body: some View {
        VStack(alignment: .leading, spacing: 23) {
            ScreenHeading(eyebrow: "Make a connection", title: "Receive QLU.",
                          subtitle: "Share this address with another wallet on your private QLU network.")
            WalletGate {
                Card {
                    HStack(alignment: .center, spacing: 28) {
                        if let address = model.state.address, let qr = qrImage(address) {
                            Image(nsImage: qr).interpolation(.none).resizable().frame(width: 164, height: 164)
                                .padding(16).background(Color.white).clipShape(RoundedRectangle(cornerRadius: 14))
                                .accessibilityLabel("QR code for your QLU receiving address")
                        }
                        VStack(alignment: .leading, spacing: 16) {
                            Text("Your receiving address").font(.system(size: 17, weight: .semibold))
                            Text(model.state.address ?? "Address unavailable")
                                .font(.system(size: 12, design: .monospaced)).lineSpacing(4)
                                .textSelection(.enabled).accessibilityIdentifier("receive-address")
                            Button { model.copyAddress() } label: { Label("Copy address", systemImage: "doc.on.doc") }
                                .buttonStyle(PrimaryButtonStyle()).accessibilityIdentifier("copy-address")
                        }
                    }
                    Text("Only send private qludev QLU to this address. This prototype uses one receiving address per wallet.")
                        .font(.system(size: 12)).foregroundStyle(Palette.muted).lineSpacing(4)
                }
            }
        }.disabled(model.busy)
    }

    private func qrImage(_ value: String) -> NSImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(value.utf8)
        filter.correctionLevel = "M"
        guard let image = filter.outputImage,
              let cgImage = CIContext().createCGImage(image, from: image.extent) else { return nil }
        return NSImage(cgImage: cgImage, size: NSSize(width: image.extent.width, height: image.extent.height))
    }
}

private struct SendView: View {
    @EnvironmentObject var model: WalletModel
    var body: some View {
        VStack(alignment: .leading, spacing: 23) {
            ScreenHeading(eyebrow: "A little QLU, on its way", title: "Send with confidence.",
                          subtitle: "You’ll review the recipient, amount, and fee before anything is signed.")
            WalletGate {
                if model.paymentUncertain {
                    Card {
                        Text("Check your previous payment first").font(.system(size: 19, weight: .semibold))
                        Text("Confirmation is uncertain. Keep its transaction ID if available; do not repeat this payment.")
                            .foregroundStyle(Palette.amber)
                        if let txid = model.pendingTXID {
                            Text(txid).font(.system(size: 11, design: .monospaced)).textSelection(.enabled)
                        }
                        Text("The private network needs a confirmation check before another payment.")
                            .font(.system(size: 12)).foregroundStyle(Palette.muted)
                    }
                } else if let preview = model.preview {
                    Card {
                        Label("Review your payment", systemImage: "checkmark.shield").font(.system(size: 20, weight: .semibold))
                        Text("TO").font(.system(size: 10, weight: .bold)).tracking(1).foregroundStyle(Palette.muted)
                        Text(preview["recipient"] as? String ?? "")
                            .font(.system(size: 12, design: .monospaced)).textSelection(.enabled)
                        Divider().overlay(Palette.border)
                        reviewLine("Amount", preview["amount"])
                        reviewLine("Network fee", preview["fee"])
                        reviewLine("Total", preview["total"], bold: true)
                        Text("This review expires after two minutes. Confirming signs and submits this exact payment.")
                            .font(.system(size: 12)).foregroundStyle(Palette.muted)
                        HStack(spacing: 12) {
                            Button("Confirm and send") { model.confirmSend() }
                                .buttonStyle(PrimaryButtonStyle()).accessibilityIdentifier("confirm-send")
                            Button("Cancel") { model.cancelSend() }.buttonStyle(PrimaryButtonStyle(prominent: false))
                        }
                    }
                } else {
                    Card {
                        VStack(alignment: .leading, spacing: 8) {
                            FieldLabel(text: "Recipient address")
                            TextField("qlud1…", text: $model.recipient).walletField()
                                .accessibilityIdentifier("send-recipient")
                            Text("For now, use the full private-network address. Contacts come later.")
                                .font(.system(size: 11)).foregroundStyle(Palette.muted)
                        }
                        VStack(alignment: .leading, spacing: 8) {
                            FieldLabel(text: "Amount in QLU")
                            TextField("0.00000000", text: $model.amount).walletField()
                                .accessibilityIdentifier("send-amount")
                        }
                        HStack {
                            Text("Available: \(model.state.balance ?? "—") QLU")
                                .font(.system(size: 12)).foregroundStyle(Palette.muted)
                            Spacer()
                            Button("Review payment") { model.prepareSend() }
                                .buttonStyle(PrimaryButtonStyle()).accessibilityIdentifier("review-send")
                                .disabled(model.recipient.isEmpty || model.amount.isEmpty || !model.state.networkRunning)
                        }
                        if !model.state.networkRunning {
                            Text("Start your private network from Wallet to send a payment.")
                                .font(.system(size: 12)).foregroundStyle(Palette.amber)
                        }
                    }
                }
            }
        }.disabled(model.busy)
    }

    private func reviewLine(_ title: String, _ value: Any?, bold: Bool = false) -> some View {
        HStack {
            Text(title).foregroundStyle(bold ? Palette.ivory : Palette.muted)
            Spacer()
            Text("\(value as? String ?? "—") QLU").monospacedDigit()
        }.font(.system(size: bold ? 17 : 14, weight: bold ? .semibold : .regular))
    }
}

private struct BackupView: View {
    @EnvironmentObject var model: WalletModel
    var body: some View {
        VStack(alignment: .leading, spacing: 23) {
            ScreenHeading(eyebrow: "Your way back in", title: "A backup you can trust.",
                          subtitle: "You need two things to recover: your encrypted backup file\nand its separate recovery code.")
            if model.isLocked {
                WalletGate { EmptyView() }
            } else if !model.recoveryCode.isEmpty {
                Card {
                    Label("Write down your recovery code", systemImage: "key.horizontal")
                        .font(.system(size: 19, weight: .semibold))
                    Text("Keep it offline and separate from your backup file. Do not send it in chat. Leaving this app hides the code and locks your wallet.")
                        .font(.system(size: 13)).foregroundStyle(Palette.muted).lineSpacing(4)
                    Text(model.recoveryCode)
                        .font(.system(size: 17, weight: .medium, design: .monospaced)).lineSpacing(10)
                        .textSelection(.disabled).privacySensitive()
                        .padding(20).frame(maxWidth: .infinity, alignment: .leading)
                        .background(Palette.ink).clipShape(RoundedRectangle(cornerRadius: 10))
                        .accessibilityLabel("Private recovery code")
                    Text("Saved backup: \(URL(fileURLWithPath: model.backupPath).lastPathComponent)")
                        .font(.system(size: 12)).foregroundStyle(Palette.muted)
                    Button("I saved my code") { model.acknowledgeCode() }
                        .buttonStyle(PrimaryButtonStyle()).accessibilityIdentifier("acknowledge-code")
                }
            } else {
                if model.state.backupVerified {
                    messageVerified
                }
                Card {
                    HStack(alignment: .top) {
                        VStack(alignment: .leading, spacing: 8) {
                            Text("1  Save your backup").font(.system(size: 18, weight: .semibold))
                            Text("An encrypted file, protected by its own recovery code.")
                                .font(.system(size: 13)).foregroundStyle(Palette.muted)
                        }
                        Spacer()
                        Button("Save new backup") { model.createBackup() }
                            .buttonStyle(PrimaryButtonStyle(prominent: !model.codeAcknowledged))
                            .accessibilityIdentifier("save-backup")
                    }
                }
                Card {
                    Text("2  Check that it works").font(.system(size: 18, weight: .semibold))
                    Text("Choose your saved backup, then enter the code you wrote down. We’ll verify it restores this wallet.")
                        .font(.system(size: 13)).foregroundStyle(Palette.muted).lineSpacing(4)
                    HStack {
                        Image(systemName: "doc.zipper").foregroundStyle(Palette.mint)
                        Text(model.backupPath.isEmpty ? "No backup selected" : URL(fileURLWithPath: model.backupPath).lastPathComponent)
                            .font(.system(size: 12)).lineLimit(1).truncationMode(.middle)
                        Spacer()
                        Button("Choose file") { model.chooseBackup(toRestore: false) }
                            .buttonStyle(PrimaryButtonStyle(prominent: false)).accessibilityIdentifier("choose-verify-backup")
                    }
                    SecureField("Separate recovery code", text: $model.recoveryInput).walletField()
                        .accessibilityIdentifier("verify-recovery-code")
                    Button("Verify backup") { model.verifyBackup() }
                        .buttonStyle(PrimaryButtonStyle()).accessibilityIdentifier("verify-backup")
                        .disabled(model.backupPath.isEmpty || model.recoveryInput.isEmpty)
                }
            }
        }.disabled(model.busy)
    }

    private var messageVerified: some View {
        Label("Your backup was verified for this session.", systemImage: "checkmark.shield.fill")
            .font(.system(size: 13)).foregroundStyle(Palette.mint)
    }
}

private struct WalletSheetView: View {
    @EnvironmentObject var model: WalletModel
    let kind: WalletSheet
    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            HStack {
                Text(title).font(.system(size: 25, weight: .semibold, design: .rounded))
                Spacer()
                Button { model.dismissSheet() } label: { Image(systemName: "xmark") }
                    .buttonStyle(.plain).accessibilityLabel("Close")
                    .disabled(model.busy)
            }
            if let error = model.error {
                Text(error).font(.system(size: 13)).foregroundStyle(Palette.amber)
            }
            switch kind {
            case .create:
                Text("Choose a passphrase with at least 15 characters. Keep it private. Four unrelated words can be easier to remember.")
                    .font(.system(size: 13)).foregroundStyle(Palette.muted).lineSpacing(4)
                passphraseFields
                Text("We’ll guide you through saving a separate recovery backup next.")
                    .font(.system(size: 12)).foregroundStyle(Palette.muted)
                Button("Create encrypted wallet") { model.create() }
                    .buttonStyle(PrimaryButtonStyle()).disabled(!model.passphraseValid)
                    .accessibilityIdentifier("submit-create")
            case .recover:
                Text("Recover into a new encrypted wallet. Your existing wallet files stay intact.")
                    .font(.system(size: 13)).foregroundStyle(Palette.muted)
                HStack {
                    Text(model.restorePath.isEmpty ? "Choose your encrypted backup" : URL(fileURLWithPath: model.restorePath).lastPathComponent)
                        .font(.system(size: 12)).lineLimit(1).truncationMode(.middle)
                    Spacer()
                    Button("Choose file") { model.chooseBackup(toRestore: true) }
                        .buttonStyle(PrimaryButtonStyle(prominent: false)).accessibilityIdentifier("choose-restore-backup")
                }
                SecureField("Separate recovery code", text: $model.recoveryInput).walletField()
                    .accessibilityIdentifier("restore-code")
                Text("Choose a new passphrase for this wallet. It can differ from the old one.")
                    .font(.system(size: 12)).foregroundStyle(Palette.muted)
                passphraseFields
                Button("Recover wallet") { model.restore() }
                    .buttonStyle(PrimaryButtonStyle())
                    .disabled(!model.passphraseValid || model.restorePath.isEmpty || model.recoveryInput.isEmpty)
                    .accessibilityIdentifier("submit-restore")
            case .unlock:
                Text("Enter this wallet’s passphrase. It stays on this Mac.")
                    .font(.system(size: 13)).foregroundStyle(Palette.muted)
                SecureField("Wallet passphrase", text: $model.passphrase).walletField()
                    .accessibilityIdentifier("unlock-passphrase")
                    .onSubmit { if !model.passphrase.isEmpty && !model.busy { model.unlock() } }
                Button("Unlock wallet") { model.unlock() }
                    .buttonStyle(PrimaryButtonStyle()).disabled(model.passphrase.isEmpty)
                    .keyboardShortcut(.defaultAction).accessibilityIdentifier("submit-unlock")
            case .open:
                Text("Existing wallets open locked. You’ll verify their backup again in this session.")
                    .font(.system(size: 13)).foregroundStyle(Palette.muted)
                if !model.wallets.isEmpty {
                    ScrollView {
                        VStack(spacing: 8) {
                            ForEach(Array(model.wallets.enumerated()), id: \.offset) { _, wallet in
                                if let path = wallet["path"] {
                                    Button { model.openWallet(path) } label: {
                                        HStack {
                                            Image(systemName: "lock.doc")
                                            Text(wallet["name"] ?? URL(fileURLWithPath: path).lastPathComponent)
                                                .lineLimit(1).truncationMode(.middle)
                                            Spacer()
                                            Image(systemName: "chevron.right")
                                        }.font(.system(size: 13)).padding(14).background(Palette.panel)
                                            .clipShape(RoundedRectangle(cornerRadius: 9))
                                    }.buttonStyle(.plain)
                                }
                            }
                        }
                    }.frame(maxHeight: 220)
                }
                Button("Choose another wallet file") { model.chooseWallet() }
                    .buttonStyle(PrimaryButtonStyle(prominent: false)).accessibilityIdentifier("choose-wallet-file")
            }
            if model.busy {
                HStack(spacing: 10) {
                    ProgressView().controlSize(.small)
                    Text(model.busyMessage).font(.system(size: 12)).foregroundStyle(Palette.muted)
                }
            }
        }
        .padding(30).frame(width: 500)
        .background(Palette.ink).foregroundStyle(Palette.ivory)
        .preferredColorScheme(.dark).tint(Palette.mint)
        .disabled(model.busy)
        .interactiveDismissDisabled(model.busy)
    }

    private var title: String {
        switch kind {
        case .create: return "Make it yours."
        case .recover: return "Welcome back."
        case .unlock: return "Unlock your wallet."
        case .open: return "Choose your wallet."
        }
    }

    private var passphraseFields: some View {
        VStack(alignment: .leading, spacing: 10) {
            SecureField("New passphrase · at least 15 characters", text: $model.passphrase).walletField()
                .accessibilityIdentifier("new-passphrase")
            SecureField("Repeat passphrase exactly", text: $model.confirmation).walletField()
                .accessibilityIdentifier("confirm-passphrase")
            if !model.confirmation.isEmpty && model.passphrase != model.confirmation {
                Text("The passphrases don’t match yet. Spaces and capitalization matter.")
                    .font(.system(size: 11)).foregroundStyle(Palette.amber)
            }
        }
    }
}

@MainActor
private final class AppDelegate: NSObject, NSApplicationDelegate {
    weak var model: WalletModel?
    private var terminationInProgress = false
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard let model else { return .terminateNow }
        guard !terminationInProgress else { return .terminateLater }
        terminationInProgress = true
        model.shutdown { [weak self] shouldClose in
            guard let self, self.terminationInProgress else { return }
            self.terminationInProgress = false
            sender.reply(toApplicationShouldTerminate: shouldClose)
        }
        return .terminateLater
    }
}

@main
struct QLUWalletApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @StateObject private var model = WalletModel()
    var body: some Scene {
        Window("QLU Wallet", id: "main") {
            RootView().environmentObject(model)
                .onAppear {
                    delegate.model = model
                    NSApplication.shared.activate(ignoringOtherApps: true)
                }
        }
        .defaultSize(width: 1060, height: 780)
        .windowResizability(.contentMinSize)
        .commands {
            CommandGroup(replacing: .newItem) {}
            CommandMenu("Wallet") {
                Button("Lock Wallet") { model.lock() }
                    .keyboardShortcut("l", modifiers: [.command, .shift])
                    .disabled(!model.state.walletOpen || model.isLocked)
                Button("Refresh Balance") { model.refresh() }
                    .keyboardShortcut("r", modifiers: .command)
                    .disabled(model.busy || !model.state.networkRunning)
            }
        }
    }
}
