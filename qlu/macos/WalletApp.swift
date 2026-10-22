// QLU's local development wallet. No network client, embedded browser, or telemetry.
// Signing and encrypted storage stay in the existing Python wallet foundation.
import AppKit
import SwiftUI
import CoreImage.CIFilterBuiltins
import UniformTypeIdentifiers

private enum Palette {
    static let ink = Color(red: 7/255, green: 10/255, blue: 9/255)
    static let panel = Color(red: 16/255, green: 32/255, blue: 25/255)
    static let border = Color(red: 208/255, green: 182/255, blue: 129/255).opacity(0.18)
    static let gold = Color(red: 208/255, green: 182/255, blue: 129/255)
    static let ivory = Color(red: 243/255, green: 240/255, blue: 233/255)
    static let muted = Color(red: 170/255, green: 181/255, blue: 172/255)
    static let amber = Color(red: 0.97, green: 0.77, blue: 0.46)
}

struct BridgeFailure: Error {
    let code: String
    let message: String
    let txid: String?
    static let unavailable = BridgeFailure(
        code: "unavailable",
        message: "The local wallet service is unavailable. Close and reopen QLU Wallet.",
        txid: nil)
}

protocol WalletBridgeClient {
    func request(_ command: String, _ params: [String: Any],
                 completion: @escaping (Result<[String: Any], BridgeFailure>) -> Void)
    func shutdown(completion: @escaping (Result<Void, BridgeFailure>) -> Void)
}

extension WalletBridgeClient {
    func request(_ command: String,
                 completion: @escaping (Result<[String: Any], BridgeFailure>) -> Void) {
        request(command, [:], completion: completion)
    }
}

/// A single serial pipe, never a shell. Every response must fit one bounded JSON line.
final class WalletBridge: WalletBridgeClient, @unchecked Sendable {
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
                let failure = Self.transportFailure(for: command)
                DispatchQueue.main.async { completion(.failure(failure)) }
            }
        }
    }

    static func transportFailure(for command: String) -> BridgeFailure {
        if command == "confirm_send" || command == "confirm_resume" || command == "faucet" {
            return BridgeFailure(code: "payment_unknown",
                message: "The wallet service stopped responding after payment authorization. The payment may have been submitted. Do not repeat it.",
                txid: nil)
        }
        return .unavailable
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

struct WalletState {
    var walletOpen = false
    var locked = true
    var backupVerified = false
    var backupVerificationStatus = "unchecked"
    var address: String?
    var walletPath: String?
    var networkRunning = false
    var networkHealthy = false
    var balance: String?
    var immatureBalance: String?
    var recentPayment: [String: Any]?
    var paymentHistory: [[String: Any]] = []
    var historyLoaded = false
    var historyCount = 0
    var paymentBlocked = false
    var pendingPayment: [String: Any]?

    init(_ value: [String: Any] = [:]) {
        walletOpen = value["wallet_open"] as? Bool ?? false
        locked = value["locked"] as? Bool ?? true
        backupVerified = value["backup_verified"] as? Bool ?? false
        backupVerificationStatus = value["backup_verification_status"] as? String ?? "unchecked"
        address = value["address"] as? String
        walletPath = value["wallet_path"] as? String
        networkRunning = value["network_running"] as? Bool ?? false
        networkHealthy = value["network_healthy"] as? Bool ?? false
        balance = value["balance"] as? String
        immatureBalance = value["immature_balance"] as? String
        recentPayment = value["recent_payment"] as? [String: Any]
        paymentHistory = value["payment_history"] as? [[String: Any]] ?? []
        historyLoaded = value["history_loaded"] as? Bool ?? false
        historyCount = value["history_count"] as? Int ?? 0
        paymentBlocked = value["payment_blocked"] as? Bool ?? false
        pendingPayment = value["pending_payment"] as? [String: Any]
    }
}

enum Destination: String, CaseIterable {
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

enum WalletSheet: String, Identifiable {
    case create, recover, unlock, open
    var id: String { rawValue }
}

@MainActor
final class WalletModel: ObservableObject {
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
    @Published var incomingTransaction = ""
    @Published var preview: [String: Any]?
    @Published var privacyLocked = false
    @Published var cleanupWaiting = false
    @Published var codeAcknowledged = false
    @Published private(set) var pendingBackupPath: String?
    @Published private(set) var recoveryCodeWasHidden = false
    @Published private(set) var recoveryCodeCovered = false
    private let bridge: any WalletBridgeClient
    private let isApplicationActive: @MainActor () -> Bool
    private var polling: Timer?
    private var panelIsOpen = false
    private var focusGeneration = 0
    private var privacyGeneration = 0
    private var walletGeneration = 0
    private var quitting = false
    private var quitAttempt = 0
    private var backendClosed = false

    var isLocked: Bool { state.locked || privacyLocked }
    var hasRecoveryCode: Bool { !isLocked && !recoveryCode.isEmpty }
    var isRecoveryCodeVisible: Bool {
        hasRecoveryCode && !recoveryCodeCovered && isApplicationActive()
    }
    var canUseWallet: Bool { state.walletOpen && !isLocked && state.backupVerified }
    var canSubmitPayment: Bool {
        canUseWallet && state.networkRunning && state.networkHealthy && !paymentUncertain
    }
    func canReviewResume(_ operationID: String) -> Bool {
        guard canUseWallet, state.networkRunning, state.historyLoaded else { return false }
        return resumeRecord(operationID) != nil
    }
    private func resumeRecord(_ operationID: String) -> [String: Any]? {
        let entries = state.paymentHistory + (state.pendingPayment.map { [$0] } ?? [])
        return entries.first {
            $0["operation_id"] as? String == operationID && $0["resume_available"] as? Bool == true
                && $0["status"] as? String == "pending" && $0["kind"] as? String != "receive"
        }
    }
    private var resumePreviewMatchesHistory: Bool {
        guard let preview, preview["resume_id"] is String,
              let operation = preview["operation_id"] as? String,
              let record = resumeRecord(operation) else { return false }
        return ["txid", "recipient", "amount", "fee"].allSatisfy {
            preview[$0] as? String == record[$0] as? String
        }
    }
    var canConfirmResume: Bool {
        canUseWallet && state.networkRunning && state.networkHealthy && resumePreviewMatchesHistory
    }

    var passphraseValid: Bool {
        passphrase.count >= 15 && passphrase.utf8.count <= 1024 && passphrase == confirmation
    }

    init(bridge: any WalletBridgeClient = WalletBridge(),
         isApplicationActive: @escaping @MainActor () -> Bool = { NSApplication.shared.isActive },
         startServices: Bool = true) {
        self.bridge = bridge
        self.isApplicationActive = isApplicationActive
        if startServices {
            refreshStatus()
            loadWallets()
            startPolling()
        }
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
        let wallet = walletGeneration
        bridge.request(command, params) { [weak self] result in
            guard let self, !self.quitting else { return }
            self.busy = false
            self.busyMessage = ""
            guard wallet == self.walletGeneration else { return }
            switch result {
            case .success(let result): completion(result)
            case .failure(let failure):
                if self.handleWalletIdentityFailure(failure) {
                    self.refreshStatus()
                    return
                }
                self.error = failure.message
                self.applyNetworkFailure(failure)
                if ["payment_conflicted", "resume_unavailable", "resume_invalid"].contains(failure.code) {
                    self.preview = nil
                }
                if failure.code == "payment_pending" || failure.code == "payment_unknown" {
                    self.paymentUncertain = true
                    // Resume already knows the original transaction. A broken
                    // pipe cannot supply a new ID and must not erase that reference.
                    self.pendingTXID = failure.txid ?? self.pendingTXID
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
        if !state.networkRunning || !state.networkHealthy {
            invalidateNetworkCheck()
        }
        if state.historyLoaded {
            paymentUncertain = state.paymentBlocked
            pendingTXID = state.pendingPayment?["txid"] as? String
                ?? state.paymentHistory.first(where: {
                    $0["status"] as? String == "pending" && $0["kind"] as? String != "receive"
                })?["txid"] as? String
            if paymentUncertain && !resumePreviewMatchesHistory { preview = nil }
            if preview?["resume_id"] != nil && !resumePreviewMatchesHistory { preview = nil }
        } else if state.recentPayment?["status"] as? String == "pending",
                  state.recentPayment?["kind"] as? String != "receive" {
            paymentUncertain = true
            pendingTXID = state.recentPayment?["txid"] as? String
        }
        // A public status poll must not erase a passphrase currently being entered
        // into the unlock/create sheet. Only a new lock transition clears inputs.
        if state.locked && !wasLocked { clearSecrets() }
        if state.locked {
            hideRecoveryCode()
            preview = nil
        }
    }

    @discardableResult
    private func handleWalletIdentityFailure(_ failure: BridgeFailure) -> Bool {
        guard failure.code == "wallet_changed" else { return false }
        // A changed selection is no longer the wallet shown on screen. Invalidate
        // pending callbacks before removing its public data and approvals.
        privacyGeneration += 1
        focusGeneration += 1
        privacyLocked = true
        resetBackupFlow()
        clearSecrets()
        recoveryCodeCovered = true
        state = WalletState(["network_running": state.networkRunning])
        paymentUncertain = false
        pendingTXID = nil
        backupPath = ""
        restorePath = ""
        recipient = ""
        amount = ""
        sheet = nil
        destination = .wallet
        notice = nil
        error = "The selected wallet file changed. Wallet access is closed. Open the wallet file again to check its own identity and payment history."
        return true
    }

    private func invalidateNetworkCheck() {
        state.networkHealthy = false
        state.balance = nil
        state.immatureBalance = nil
        preview = nil
    }

    private func applyNetworkFailure(_ failure: BridgeFailure) {
        let failures: Set<String> = [
            "unavailable", "network_error", "network_stopped", "start_failed", "cleanup_failed",
            "network_identity", "balance_failed", "stale_payment", "faucet_failed",
            "payment_rejected", "incoming_unavailable", "payment_pending", "payment_unknown",
            "wallet_failed", "internal_error", "history_unavailable", "insufficient_funds",
        ]
        if failures.contains(failure.code) { invalidateNetworkCheck() }
    }

    private func applyAccessResult(_ result: [String: Any], generation: Int) {
        // Create, restore and unlock can finish after an explicit lock or sleep.
        // Cover first and serialize another lock even if an older lock reply has
        // already arrived. Ordinary focus changes do not change this generation.
        if generation != privacyGeneration {
            privacyLocked = true
            apply(result)
            lock()
        } else {
            apply(result)
            privacyLocked = false
            if recoveryCodeCovered && isApplicationActive() { becomeActive() }
        }
    }

    private func clearSecrets() {
        passphrase = ""
        confirmation = ""
        recoveryInput = ""
        incomingTransaction = ""
        hideRecoveryCode()
        preview = nil
    }

    private func hideRecoveryCode() {
        if !recoveryCode.isEmpty && !codeAcknowledged {
            recoveryCodeWasHidden = true
            notice = hiddenCodeMessage
        }
        recoveryCode = ""
    }

    private func resetBackupFlow() {
        walletGeneration += 1
        pendingBackupPath = nil
        hideRecoveryCode()
        codeAcknowledged = false
        recoveryCodeWasHidden = false
    }

    private var hiddenCodeMessage: String {
        "The recovery code was hidden when the wallet locked or this step closed. If you did not write it down, save a new backup with a new filename."
    }

    func refreshStatus() {
        let generation = privacyGeneration
        let wallet = walletGeneration
        bridge.request("status") { [weak self] result in
            guard let self, !self.quitting, generation == self.privacyGeneration,
                  wallet == self.walletGeneration else { return }
            switch result {
            case .success(let state): self.apply(state)
            case .failure(let failure):
                if self.handleWalletIdentityFailure(failure) { return }
                self.applyNetworkFailure(failure)
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

    func sheetDidDismiss() {
        // Ordinary credential sheets do not own the recovery-code overlay.
        // A stale binding reset or dismissal must never erase a new code.
        guard sheet == nil else { return }
        passphrase = ""
        confirmation = ""
        recoveryInput = ""
    }

    func create() {
        resetBackupFlow()
        let generation = privacyGeneration
        let parameters = ["passphrase": passphrase, "confirmation": confirmation]
        passphrase = ""
        confirmation = ""
        perform("create", params: parameters, message: "Creating your encrypted wallet…") { [weak self] result in
            guard let self else { return }
            self.applyAccessResult(result, generation: generation)
            self.dismissSheet()
            self.destination = .backup
            self.backupPath = ""
            self.codeAcknowledged = false
            self.notice = "Your wallet is created. Save and verify its backup to finish."
            self.loadWallets()
        }
    }

    func restore() {
        resetBackupFlow()
        let generation = privacyGeneration
        let parameters = ["backup_path": restorePath, "code": recoveryInput,
                          "passphrase": passphrase, "confirmation": confirmation]
        passphrase = ""
        confirmation = ""
        recoveryInput = ""
        perform("restore", params: parameters, message: "Restoring into a new encrypted wallet…") { [weak self] result in
            guard let self else { return }
            self.applyAccessResult(result, generation: generation)
            self.dismissSheet()
            self.destination = .wallet
            self.notice = "Wallet recovered. Your existing wallet files were preserved."
            self.loadWallets()
        }
    }

    func openWallet(_ path: String) {
        resetBackupFlow()
        clearSecrets()
        perform("open", params: ["path": path], message: "Opening your wallet…") { [weak self] result in
            guard let self else { return }
            self.apply(result)
            self.dismissSheet()
            self.destination = .wallet
            self.backupPath = ""
            self.codeAcknowledged = false
            self.notice = "Wallet opened and locked. Enter your passphrase to continue."
        }
    }

    func unlock() {
        let parameters = ["passphrase": passphrase]
        passphrase = ""
        let generation = privacyGeneration
        perform("unlock", params: parameters, message: "Unlocking your wallet…") { [weak self] result in
            guard let self else { return }
            self.applyAccessResult(result, generation: generation)
            self.dismissSheet()
            if !self.isLocked {
                if self.state.backupVerified {
                    self.destination = .wallet
                    self.notice = "Wallet unlocked. Your earlier backup verification is remembered on this Mac."
                } else {
                    self.destination = .backup
                    self.notice = self.state.backupVerificationStatus == "unavailable"
                        ? "Your saved verification could not be checked. Verify your backup again."
                        : "Verify your saved backup once to remember the check on this Mac."
                }
            }
            if self.pendingBackupPath != nil && !self.isLocked {
                self.destination = .backup
                self.notice = "Your backup has not been saved yet. Choose Create backup and show code to continue."
            } else if self.recoveryCodeWasHidden && !self.isLocked {
                self.destination = .backup
                self.notice = self.hiddenCodeMessage
            }
        }
    }

    func lock() {
        privacyGeneration += 1
        privacyLocked = true
        clearSecrets()
        sheet = nil
        let wallet = walletGeneration
        bridge.request("lock") { [weak self] result in
            guard let self, !self.quitting, wallet == self.walletGeneration else { return }
            if case .failure(let failure) = result {
                self.handleWalletIdentityFailure(failure)
            }
            if case .success(let state) = result {
                self.apply(state)
                // Stay locally locked until a new, explicit access request
                // succeeds. A stale public status cannot reopen the wallet.
            }
        }
    }

    func resignActive() {
        focusGeneration += 1
        recoveryCodeCovered = true
        guard !quitting && !cleanupWaiting else {
            clearSecrets()
            return
        }
    }

    func becomeActive() {
        guard !quitting, !cleanupWaiting, !panelIsOpen, isApplicationActive() else { return }
        focusGeneration += 1
        let focus = focusGeneration
        let generation = privacyGeneration
        let wallet = walletGeneration
        recoveryCodeCovered = true
        // A fresh public status check observes the backend's real idle deadline;
        // it does not unlock the wallet or extend that deadline.
        bridge.request("status") { [weak self] result in
            guard let self, !self.quitting, !self.cleanupWaiting,
                  self.isApplicationActive(), focus == self.focusGeneration,
                  generation == self.privacyGeneration, wallet == self.walletGeneration else { return }
            switch result {
            case .success(let state):
                self.apply(state)
                self.recoveryCodeCovered = false
            case .failure(let failure):
                // Without an authoritative status result, keep the secret covered.
                if self.handleWalletIdentityFailure(failure) { return }
                self.applyNetworkFailure(failure)
                self.error = failure.message
            }
        }
    }

    func beginFilePanel() {
        panelIsOpen = true
    }

    private func finishPanel() {
        panelIsOpen = false
        // A native file panel may consume the activation notification. Recheck
        // on its return so a valid code is not left covered indefinitely.
        if recoveryCodeCovered && isApplicationActive() {
            becomeActive()
        }
    }

    func chooseBackup(toRestore: Bool) {
        let panel = NSOpenPanel()
        panel.title = "Choose your encrypted QLU backup"
        panel.allowedContentTypes = [.json]
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        beginFilePanel()
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
        beginFilePanel()
        let accepted = panel.runModal() == .OK
        let path = accepted ? panel.url?.path : nil
        finishPanel()
        if let path { openWallet(path) }
    }

    func createBackup() {
        guard !busy, !quitting else { return }
        let panel = NSSavePanel()
        panel.title = "Save an encrypted QLU backup"
        panel.nameFieldStringValue = "QLU-backup-\(Int(Date().timeIntervalSince1970)).json"
        panel.allowedContentTypes = [.json]
        panel.canCreateDirectories = true
        panel.directoryURL = FileManager.default.urls(for: .downloadsDirectory, in: .userDomainMask).first
        panel.message = "After saving, QLU will show a new recovery code. Write down the whole code before choosing I saved my code."
        beginFilePanel()
        let accepted = panel.runModal() == .OK
        let path = accepted ? panel.url?.path : nil
        finishBackupSelection(path)
    }

    func finishBackupSelection(_ path: String?) {
        finishPanel()
        pendingBackupPath = path
        guard path != nil else { return }
        destination = .backup
        if isLocked {
            notice = "Your backup has not been saved yet. The wallet locked while the Save window was open. Unlock it, then choose Create backup and show code."
            return
        }
        if !isApplicationActive() {
            notice = "Your backup has not been saved yet. Return to QLU, then choose Create backup and show code."
            return
        }
        continueBackup()
    }

    func cancelPendingBackup() {
        pendingBackupPath = nil
        notice = "Backup cancelled. No new backup was saved."
    }

    func continueBackup() {
        guard !busy, !quitting, let path = pendingBackupPath else { return }
        guard !isLocked, isApplicationActive() else {
            notice = "Unlock your wallet in QLU to create this backup and see its recovery code."
            return
        }
        // Consume before submitting: never automatically retry a path that may
        // already have been written. The backend still refuses all overwrites.
        pendingBackupPath = nil
        let generation = privacyGeneration
        let wallet = walletGeneration
        perform("backup_create", params: ["backup_path": path], message: "Saving your encrypted backup…") { [weak self] result in
            guard let self, wallet == self.walletGeneration else { return }
            self.backupPath = result["backup_path"] as? String ?? path
            self.codeAcknowledged = false
            if generation == self.privacyGeneration, !self.isLocked,
               let code = result["code"] as? String, code.hasPrefix("QLU1-") {
                self.recoveryCode = code
                if !self.isApplicationActive() { self.recoveryCodeCovered = true }
                self.recoveryCodeWasHidden = false
                self.destination = .backup
                self.sheet = nil
            } else {
                self.recoveryCodeWasHidden = true
                self.notice = "Backup saved, but the wallet locked before its recovery code could be shown. Unlock and save a new backup with a new filename."
            }
        }
    }

    func acknowledgeCode() {
        codeAcknowledged = true
        recoveryCodeWasHidden = false
        recoveryCode = ""
        sheet = nil
        recoveryInput = ""
    }

    func verifyBackup() {
        guard recoveryInput.trimmingCharacters(in: .whitespacesAndNewlines)
            .uppercased().hasPrefix("QLU1-") else {
            recoveryInput = ""
            error = "Use the separate recovery code beginning QLU1-, shown after saving your backup. Your wallet passphrase cannot verify a backup."
            return
        }
        let parameters = ["backup_path": backupPath, "code": recoveryInput]
        recoveryInput = ""
        perform("backup_verify", params: parameters, message: "Checking the saved backup and your code…") { [weak self] result in
            guard let self else { return }
            self.apply(result)
            self.codeAcknowledged = false
            self.recoveryCodeWasHidden = false
            self.notice = "Backup verified and remembered on this Mac. Next time, just unlock with your passphrase."
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
        guard canSubmitPayment else { return }
        let operationID = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
        perform("faucet", params: ["operation_id": operationID], message: "Adding test QLU and confirming it on four nodes…") { [weak self] result in
            if let state = result["state"] as? [String: Any] { self?.apply(state) }
            self?.notice = self?.paymentUncertain == true
                ? "Test funding needs a status check. Do not request it again yet."
                : (self?.state.networkHealthy == true ? "Test QLU added. These coins have no monetary value."
                   : "Test funding saved. Refresh to check its current confirmation and balance.")
        }
    }

    func recoverPayments() {
        preview = nil
        perform("recover_payments", message: "Checking saved payments on all four private nodes…") { [weak self] result in
            guard let self else { return }
            self.apply(result)
            self.notice = self.paymentUncertain
                ? "A saved payment is still uncertain. Sending remains paused; no replacement payment was made."
                : "Saved payment statuses checked. No replacement payment was made."
        }
    }

    func prepareSend() {
        guard canSubmitPayment else { return }
        let generation = privacyGeneration
        let wallet = walletGeneration
        perform("prepare_send", params: ["recipient": recipient, "amount": amount],
                message: "Preparing your payment for review…") { [weak self] result in
            guard let self, self.canSubmitPayment, generation == self.privacyGeneration,
                  wallet == self.walletGeneration else { return }
            self.preview = result
        }
    }

    func prepareResume(_ operationID: String) {
        guard canReviewResume(operationID) else { return }
        preview = nil
        let generation = privacyGeneration
        let wallet = walletGeneration
        perform("prepare_resume", params: ["operation_id": operationID],
                message: "Checking the original saved payment for review…") { [weak self] result in
            guard let self, generation == self.privacyGeneration, wallet == self.walletGeneration else { return }
            if let state = result["state"] as? [String: Any] { self.apply(state) }
            guard self.canReviewResume(operationID), self.state.networkHealthy,
                  result["operation_id"] as? String == operationID, result["resume_id"] is String else { return }
            self.preview = result.filter { $0.key != "state" }
            guard self.resumePreviewMatchesHistory else { self.preview = nil; return }
            self.destination = .send
        }
    }

    func confirmResume() {
        guard canConfirmResume else { preview = nil; return }
        guard let id = preview?["resume_id"] as? String else { return }
        preview = nil
        perform("confirm_resume", params: ["resume_id": id],
                message: "Resuming the exact original payment…") { [weak self] result in
            guard let self else { return }
            if let state = result["state"] as? [String: Any] { self.apply(state) }
            self.notice = self.paymentUncertain
                ? "The original payment still needs a status check. No replacement payment was created."
                : "Original payment status saved. No replacement payment or additional fee was created."
            self.destination = .wallet
        }
    }

    func verifyIncoming() {
        guard canUseWallet, state.networkRunning else { return }
        let txid = incomingTransaction.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard txid.count == 64, txid.allSatisfy({ "0123456789abcdef".contains($0) }) else {
            error = "Enter the complete 64-character transaction ID from the sender."
            return
        }
        preview = nil
        let generation = walletGeneration
        perform("verify_received", params: ["txid": txid], message: "Verifying the incoming payment on four private nodes…") { [weak self] result in
            guard let self, generation == self.walletGeneration else { return }
            if let state = result["state"] as? [String: Any] { self.apply(state) }
            self.incomingTransaction = ""
            self.notice = "Payment checked and saved in your history. No new payment was made."
            self.destination = .wallet
        }
    }

    func cancelSend() {
        preview = nil
        let wallet = walletGeneration
        let generation = privacyGeneration
        bridge.request("cancel_send") { [weak self] result in
            guard let self, wallet == self.walletGeneration, generation == self.privacyGeneration else { return }
            if case .success(let state) = result { self.apply(state) }
        }
    }

    func confirmSend() {
        guard canSubmitPayment else { preview = nil; return }
        guard let id = preview?["preview_id"] as? String else { return }
        preview = nil
        perform("confirm_send", params: ["preview_id": id],
                message: "Signing and confirming your exact payment…") { [weak self] result in
            if let state = result["state"] as? [String: Any] { self?.apply(state) }
            self?.recipient = ""
            self?.amount = ""
            self?.notice = self?.paymentUncertain == true
                ? "Your payment needs a status check. Do not repeat it."
                : (self?.state.networkHealthy == true ? "Payment confirmed on all four private nodes."
                   : "Payment saved. Refresh to check its current confirmation and balance.")
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
        resetBackupFlow()
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
            .background(prominent ? Palette.gold : Color.white.opacity(0.07))
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
        ZStack {
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
                                message(notice, symbol: "checkmark.circle", color: Palette.gold)
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
            .tint(Palette.gold)
            .preferredColorScheme(.dark)
            .frame(minWidth: 900, minHeight: 680)
            .disabled(model.cleanupWaiting || model.hasRecoveryCode)
            .accessibilityHidden(model.hasRecoveryCode)
            if model.hasRecoveryCode {
                GeometryReader { geometry in
                    ZStack {
                        Color.black.opacity(0.65).ignoresSafeArea()
                        ScrollView {
                            if model.isRecoveryCodeVisible {
                                RecoveryCodeView().environmentObject(model)
                            } else {
                                VStack(alignment: .leading, spacing: 20) {
                                    Label("Your recovery code is covered", systemImage: "eye.slash")
                                        .font(.system(size: 23, weight: .semibold))
                                    Text("Return to QLU to view it. Switching apps keeps your wallet unlocked until its five-minute timer expires.")
                                        .foregroundStyle(Palette.muted)
                                    if let error = model.error {
                                        Text(error).foregroundStyle(Palette.amber)
                                    }
                                    Button("Check wallet and show code") { model.becomeActive() }
                                        .buttonStyle(PrimaryButtonStyle())
                                }
                                .padding(30).foregroundStyle(Palette.ivory)
                            }
                        }
                        .frame(width: min(560, geometry.size.width - 48),
                               height: min(610, geometry.size.height - 48))
                        .background(Palette.ink)
                        .clipShape(RoundedRectangle(cornerRadius: 18))
                        .overlay(RoundedRectangle(cornerRadius: 18).stroke(Palette.border))
                        .shadow(color: .black.opacity(0.4), radius: 24)
                        .accessibilityIdentifier("recovery-code-dialog")
                    }
                    .frame(width: geometry.size.width, height: geometry.size.height)
                }
                .zIndex(1)
            }
        }
        .sheet(item: $model.sheet, onDismiss: { model.sheetDidDismiss() }) { kind in
            WalletSheetView(kind: kind)
                .environmentObject(model)
        }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didResignActiveNotification)) { _ in
            model.resignActive()
        }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            model.becomeActive()
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
        .onReceive(NSWorkspace.shared.notificationCenter.publisher(for: NSWorkspace.screensDidSleepNotification)) { _ in
            model.lock()
        }
        .onReceive(NSWorkspace.shared.notificationCenter.publisher(for: NSWorkspace.sessionDidResignActiveNotification)) { _ in
            model.lock()
        }
    }

    private var sidebar: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 12) {
                ZStack {
                    RoundedRectangle(cornerRadius: 13).fill(Palette.gold).frame(width: 42, height: 42)
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
                        if model.destination == item { Circle().fill(Palette.gold).frame(width: 5, height: 5) }
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
                    Circle().fill(model.state.networkHealthy ? Palette.gold : Palette.muted).frame(width: 6, height: 6)
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
                    .foregroundStyle(model.isLocked ? Palette.muted : Palette.gold)
                Button(model.isLocked ? "Unlock" : "Lock") {
                    if model.isLocked { model.present(.unlock) } else { model.lock() }
                }
                .buttonStyle(PrimaryButtonStyle(prominent: false))
                .accessibilityIdentifier("wallet-lock-toggle")
                .disabled(model.busy)
            }
            Text("PRIVATE V1").font(.system(size: 9, weight: .bold)).tracking(1)
                .foregroundStyle(Palette.gold).padding(.horizontal, 10).padding(.vertical, 7)
                .overlay(Capsule().stroke(Palette.gold.opacity(0.3), lineWidth: 1))
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
            Text(eyebrow.uppercased()).font(.system(size: 10, weight: .bold)).tracking(2).foregroundStyle(Palette.gold)
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
                    Image(systemName: "sparkle").font(.system(size: 26)).foregroundStyle(Palette.gold)
                    Text("Start fresh").font(.system(size: 21, weight: .semibold))
                    Text("Create an encrypted wallet with a passphrase you choose.")
                        .foregroundStyle(Palette.muted).font(.system(size: 13)).frame(minHeight: 42, alignment: .top)
                    Button("Create a wallet") { model.present(.create) }
                        .buttonStyle(PrimaryButtonStyle()).accessibilityIdentifier("create-wallet")
                }
                Card {
                    Image(systemName: "arrow.counterclockwise").font(.system(size: 26)).foregroundStyle(Palette.gold)
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
                Text("Unlock to continue. Switching apps keeps your wallet unlocked. It locks after five minutes without a key operation, or when you hide it, minimize it, or put your Mac to sleep.")
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
                PaymentHistoryView()
            }
            Card {
                HStack {
                    VStack(alignment: .leading, spacing: 7) {
                        Text("Your private network").font(.system(size: 16, weight: .semibold))
                        Text(model.state.networkRunning
                             ? (model.state.networkHealthy ? "All four private nodes agreed at the last check." : "The network needs checking. Refresh before making a payment.")
                             : "Start the local network to check balances and make payments.")
                            .font(.system(size: 12)).foregroundStyle(Palette.muted)
                    }
                    Spacer()
                    Button(model.state.networkRunning ? "Stop network" : "Start network") { model.networkToggle() }
                        .buttonStyle(PrimaryButtonStyle(prominent: false)).accessibilityIdentifier("network-toggle")
                }
                if model.canUseWallet && model.state.networkRunning {
                    Button("Add 1 test QLU") { model.faucet() }
                        .buttonStyle(PrimaryButtonStyle(prominent: false)).accessibilityIdentifier("test-faucet")
                        .disabled(!model.canSubmitPayment)
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

enum PaymentPresentation {
    static func isSelfTransfer(_ payment: [String: Any]) -> Bool {
        payment["is_self_transfer"] as? Bool == true
    }

    static func title(_ payment: [String: Any]) -> String {
        switch payment["direction"] as? String {
        case "received": return "Received"
        case "funding": return "Test funding"
        case "self": return "Transfer to yourself"
        case "sent": return "Sent"
        default: return payment["kind"] as? String == "funding" ? "Test funding" : "Payment"
        }
    }

    static func statusLabel(_ payment: [String: Any], networkRunning: Bool, networkHealthy: Bool) -> String {
        switch payment["status"] as? String {
        case "confirmed":
            if !networkRunning { return "Confirmed at last check · network stopped" }
            return networkHealthy ? "Confirmed at last check on all four private nodes"
                : "Saved confirmation · network needs checking"
        case "conflicted":
            if !networkRunning { return "Conflict saved at last check · network stopped" }
            return networkHealthy ? "Conflicted at last check · another payment spent these coins"
                : "Saved conflict · network needs checking"
        case "not_sent": return "Not sent · interrupted before broadcast"
        default: return payment["kind"] as? String == "receive"
            ? "Needs checking · incoming confirmation unavailable"
            : "Needs checking · do not repeat this payment"
        }
    }
}

private struct PaymentHistoryView: View {
    @EnvironmentObject var model: WalletModel
    var body: some View {
        Card {
            HStack {
                Text("Payment history").font(.system(size: 18, weight: .semibold))
                Spacer()
                Button("Check payment status") { model.recoverPayments() }
                    .buttonStyle(PrimaryButtonStyle(prominent: false))
                    .disabled(!model.state.networkRunning || !model.state.historyLoaded)
                    .accessibilityIdentifier("recover-payments")
            }
            Text("Saved on this Mac. To add an incoming payment, use Receive and check its transaction ID.")
                .font(.system(size: 12)).foregroundStyle(Palette.muted)
            if model.paymentUncertain {
                Text("A payment needs checking. New payments are paused to avoid paying twice.")
                    .font(.system(size: 13)).foregroundStyle(Palette.amber)
                if let txid = model.pendingTXID {
                    Text(txid).font(.system(size: 10, design: .monospaced)).textSelection(.enabled)
                }
            }
            if model.state.paymentHistory.isEmpty {
                Text("Your next payment will appear here and stay after restarting QLU.")
                    .font(.system(size: 13)).foregroundStyle(Palette.muted)
            }
            ForEach(Array(model.state.paymentHistory.enumerated()), id: \.offset) { _, payment in
                Divider().overlay(Palette.border)
                HStack {
                    Text(PaymentPresentation.title(payment))
                    Spacer()
                    Text("\(payment["amount"] as? String ?? "—") QLU").fontWeight(.semibold)
                }.font(.system(size: 14))
                Text(PaymentPresentation.statusLabel(payment, networkRunning: model.state.networkRunning,
                                                     networkHealthy: model.state.networkHealthy)).font(.system(size: 12))
                    .foregroundStyle(["pending", "conflicted"].contains(payment["status"] as? String ?? "") ? Palette.amber : Palette.muted)
                if let created = payment["created_at"] as? Double {
                    Text(Date(timeIntervalSince1970: created).formatted(date: .abbreviated, time: .shortened))
                        .font(.system(size: 11)).foregroundStyle(Palette.muted)
                }
                if let recipient = payment["recipient"] as? String {
                    Text("To: \(recipient)").font(.system(size: 10, design: .monospaced))
                        .foregroundStyle(Palette.muted).textSelection(.enabled)
                }
                if let txid = payment["txid"] as? String {
                    Text(txid).font(.system(size: 10, design: .monospaced))
                        .foregroundStyle(Palette.muted).textSelection(.enabled)
                }
                if payment["resume_available"] as? Bool == true,
                   let operation = payment["operation_id"] as? String {
                    Button("Review original payment") { model.prepareResume(operation) }
                        .buttonStyle(PrimaryButtonStyle(prominent: false))
                        .disabled(!model.canReviewResume(operation))
                        .accessibilityIdentifier("review-original-payment")
                }
                if payment["status"] as? String == "conflicted",
                   let conflict = payment["conflict"] as? [String: Any], let txid = conflict["txid"] as? String {
                    Text("Other payment: \(txid)").font(.system(size: 10, design: .monospaced))
                        .foregroundStyle(Palette.muted).textSelection(.enabled)
                    Text("This original payment will not be submitted again automatically. Check your current balance before making a separate payment.")
                        .font(.system(size: 11)).foregroundStyle(Palette.muted)
                }
                if payment["kind"] as? String == "receive" {
                    Text("No receiving fee charged to this wallet.")
                        .font(.system(size: 11)).foregroundStyle(Palette.muted)
                } else {
                    Text("Fee: \(payment["fee"] as? String ?? "—") QLU")
                        .font(.system(size: 11)).foregroundStyle(Palette.muted)
                    if payment["direction"] as? String == "self" && payment["status"] as? String != "conflicted" {
                        Text("The amount stays in this wallet. Only the fee leaves your balance when confirmed.")
                            .font(.system(size: 11)).foregroundStyle(Palette.gold)
                    }
                }
            }
            if model.state.historyCount > model.state.paymentHistory.count {
                Text("Showing the latest \(model.state.paymentHistory.count) of \(model.state.historyCount) saved records.")
                    .font(.system(size: 12)).foregroundStyle(Palette.muted)
            }
        }
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
                Card {
                    Text("Check an incoming payment").font(.system(size: 18, weight: .semibold))
                    Text("Ask the sender for the transaction ID. QLU checks that the confirmed payment reached this wallet, then saves it in history.")
                        .font(.system(size: 13)).foregroundStyle(Palette.muted).lineSpacing(4)
                    TextField("Transaction ID · 64 characters", text: $model.incomingTransaction).walletField()
                        .accessibilityIdentifier("incoming-txid")
                    Button("Check received payment") { model.verifyIncoming() }
                        .buttonStyle(PrimaryButtonStyle()).accessibilityIdentifier("verify-received")
                        .disabled(model.incomingTransaction.isEmpty || !model.state.networkRunning)
                    if !model.state.networkRunning {
                        Text("Start your private network from Wallet to check a payment.")
                            .font(.system(size: 12)).foregroundStyle(Palette.amber)
                    }
                    Text("This only checks the payment. It never sends funds or repeats the sender’s payment.")
                        .font(.system(size: 11)).foregroundStyle(Palette.muted)
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
                if let preview = model.preview, preview["resume_id"] is String {
                    Card {
                        Label(preview["kind"] as? String == "funding" ? "Resume original test funding" : "Resume your original payment", systemImage: "arrow.clockwise")
                            .font(.system(size: 20, weight: .semibold))
                        Text("ORIGINAL TRANSACTION ID").font(.system(size: 10, weight: .bold))
                            .tracking(1).foregroundStyle(Palette.muted)
                        Text(preview["txid"] as? String ?? "")
                            .font(.system(size: 11, design: .monospaced)).textSelection(.enabled)
                        Text("TO").font(.system(size: 10, weight: .bold)).tracking(1).foregroundStyle(Palette.muted)
                        Text(preview["recipient"] as? String ?? "")
                            .font(.system(size: 12, design: .monospaced)).textSelection(.enabled)
                        Divider().overlay(Palette.border)
                        if preview["kind"] as? String == "funding" {
                            reviewLine("QLU added to this wallet", preview["wallet_credit"] ?? preview["amount"])
                            reviewLine("Original fee paid by the test faucet", preview["fee"])
                            reviewLine("Leaves this wallet", preview["wallet_debit"], bold: true)
                        } else {
                            reviewLine(PaymentPresentation.isSelfTransfer(preview) ? "Amount moved within this wallet" : "Original amount", preview["amount"])
                            reviewLine("Original network fee", preview["fee"])
                            reviewLine("Balance decreases by", preview["wallet_debit"], bold: true)
                        }
                        Text("This sends the exact transaction you already approved. It does not create a second payment or add another fee. Confirmation is checked again before resuming.")
                            .font(.system(size: 13)).foregroundStyle(Palette.gold)
                        Text("This review expires after two minutes.")
                            .font(.system(size: 12)).foregroundStyle(Palette.muted)
                        HStack(spacing: 12) {
                            Button("Resume original payment") { model.confirmResume() }
                                .buttonStyle(PrimaryButtonStyle()).accessibilityIdentifier("confirm-resume")
                                .disabled(!model.canConfirmResume)
                            Button("Cancel") { model.cancelSend() }
                                .buttonStyle(PrimaryButtonStyle(prominent: false))
                        }
                    }
                } else if model.paymentUncertain {
                    Card {
                        Text("Check your previous payment first").font(.system(size: 19, weight: .semibold))
                        Text("Confirmation is uncertain. Keep its transaction ID if available; do not repeat this payment.")
                            .foregroundStyle(Palette.amber)
                        if let txid = model.pendingTXID {
                            Text(txid).font(.system(size: 11, design: .monospaced)).textSelection(.enabled)
                        }
                        Text("The private network needs a confirmation check before another payment.")
                            .font(.system(size: 12)).foregroundStyle(Palette.muted)
                        if let payment = model.state.pendingPayment,
                           payment["resume_available"] as? Bool == true,
                           let operation = payment["operation_id"] as? String {
                            Button("Review original payment") { model.prepareResume(operation) }
                                .buttonStyle(PrimaryButtonStyle())
                                .disabled(!model.canReviewResume(operation))
                                .accessibilityIdentifier("review-pending-original")
                        }
                        Button("Check payment status") { model.recoverPayments() }
                            .buttonStyle(PrimaryButtonStyle())
                            .disabled(!model.state.networkRunning || !model.state.historyLoaded)
                    }
                } else if let preview = model.preview {
                    Card {
                        Label(PaymentPresentation.isSelfTransfer(preview) ? "Transfer to yourself" : "Review your payment",
                              systemImage: "checkmark.shield").font(.system(size: 20, weight: .semibold))
                        Text("TO").font(.system(size: 10, weight: .bold)).tracking(1).foregroundStyle(Palette.muted)
                        Text(preview["recipient"] as? String ?? "")
                            .font(.system(size: 12, design: .monospaced)).textSelection(.enabled)
                        Divider().overlay(Palette.border)
                        reviewLine(PaymentPresentation.isSelfTransfer(preview) ? "Amount moved within this wallet" : "Recipient receives", preview["amount"])
                        reviewLine("Network fee", preview["fee"])
                        if PaymentPresentation.isSelfTransfer(preview) {
                            reviewLine("Required available balance", preview["total"])
                            reviewLine("Balance decreases by", preview["wallet_debit"], bold: true)
                            Text("You are sending to this wallet’s own address. The amount stays yours; only the network fee leaves your balance.")
                                .font(.system(size: 13)).foregroundStyle(Palette.gold)
                        } else {
                            reviewLine("Total leaving this wallet", preview["wallet_debit"] ?? preview["total"], bold: true)
                        }
                        Text("This review expires after two minutes. Confirming signs and submits this exact payment.")
                            .font(.system(size: 12)).foregroundStyle(Palette.muted)
                        HStack(spacing: 12) {
                            Button("Confirm and send") { model.confirmSend() }
                                .buttonStyle(PrimaryButtonStyle()).accessibilityIdentifier("confirm-send")
                                .disabled(!model.canSubmitPayment)
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
                                .disabled(model.recipient.isEmpty || model.amount.isEmpty || !model.canSubmitPayment)
                        }
                        if !model.state.networkRunning {
                            Text("Start your private network from Wallet to send a payment.")
                                .font(.system(size: 12)).foregroundStyle(Palette.amber)
                        } else if !model.state.networkHealthy {
                            Button("Check network before reviewing") { model.refresh() }
                                .buttonStyle(PrimaryButtonStyle(prominent: false))
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
            } else if let path = model.pendingBackupPath {
                Card {
                    Label("Finish saving your backup", systemImage: "doc.badge.plus")
                        .font(.system(size: 19, weight: .semibold))
                    Text("Your file has not been saved yet. Continue below, then write down the new recovery code before leaving QLU.")
                        .font(.system(size: 13)).foregroundStyle(Palette.muted).lineSpacing(4)
                    Text("Chosen filename: \(URL(fileURLWithPath: path).lastPathComponent)")
                        .font(.system(size: 12)).foregroundStyle(Palette.muted)
                    HStack {
                        Button("Create backup and show code") { model.continueBackup() }
                            .buttonStyle(PrimaryButtonStyle()).accessibilityIdentifier("continue-backup")
                        Button("Cancel") { model.cancelPendingBackup() }
                            .buttonStyle(PrimaryButtonStyle(prominent: false))
                    }
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
                        Image(systemName: "doc.zipper").foregroundStyle(Palette.gold)
                        Text(model.backupPath.isEmpty ? "No backup selected" : URL(fileURLWithPath: model.backupPath).lastPathComponent)
                            .font(.system(size: 12)).lineLimit(1).truncationMode(.middle)
                        Spacer()
                        Button("Choose file") { model.chooseBackup(toRestore: false) }
                            .buttonStyle(PrimaryButtonStyle(prominent: false)).accessibilityIdentifier("choose-verify-backup")
                    }
                    Text("Use the code beginning QLU1-, not the passphrase you use to unlock your wallet.")
                        .font(.system(size: 12)).foregroundStyle(Palette.muted)
                    SecureField("Recovery code · QLU1-…", text: $model.recoveryInput).walletField()
                        .accessibilityIdentifier("verify-recovery-code")
                    Button("Verify backup") { model.verifyBackup() }
                        .buttonStyle(PrimaryButtonStyle()).accessibilityIdentifier("verify-backup")
                        .disabled(model.backupPath.isEmpty || model.recoveryInput.isEmpty)
                }
            }
        }.disabled(model.busy)
    }

    private var messageVerified: some View {
        Label("Your earlier backup check is remembered on this Mac. Keep the backup and recovery code safe for recovery.", systemImage: "checkmark.shield.fill")
            .font(.system(size: 13)).foregroundStyle(Palette.gold)
    }
}

private struct RecoveryCodeView: View {
    @EnvironmentObject var model: WalletModel
    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            Text("Write down your recovery code.")
                .font(.system(size: 25, weight: .semibold, design: .rounded))
            Text("This is your separate recovery code. It is different from the passphrase you use to unlock QLU.")
                .font(.system(size: 14)).foregroundStyle(Palette.muted).lineSpacing(4)
            Text(model.recoveryCode)
                .font(.system(size: 17, weight: .medium, design: .monospaced)).lineSpacing(10)
                .fixedSize(horizontal: false, vertical: true)
                .textSelection(.disabled).privacySensitive()
                .padding(20).frame(maxWidth: .infinity, alignment: .leading)
                .background(Palette.panel).clipShape(RoundedRectangle(cornerRadius: 10))
                .accessibilityLabel("Private recovery code")
            Text("Write down the entire code, including QLU1- and every hyphen. Keep it on paper, separate from your backup file. Switching apps temporarily covers the code. Locking the wallet clears it.")
                .font(.system(size: 13)).foregroundStyle(Palette.muted).lineSpacing(4)
            Text("Saved backup: \(URL(fileURLWithPath: model.backupPath).lastPathComponent)")
                .font(.system(size: 12)).foregroundStyle(Palette.muted)
            Button("I saved my code") { model.acknowledgeCode() }
                .buttonStyle(PrimaryButtonStyle()).accessibilityIdentifier("acknowledge-code")
        }
        .padding(30).frame(maxWidth: .infinity, alignment: .leading)
        .foregroundStyle(Palette.ivory).tint(Palette.gold)
        .preferredColorScheme(.dark)
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
                Text("Existing wallets open locked. After you enter your passphrase, QLU checks any saved backup verification.")
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
        .preferredColorScheme(.dark).tint(Palette.gold)
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

#if !QLU_WALLET_TESTS
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
#endif
