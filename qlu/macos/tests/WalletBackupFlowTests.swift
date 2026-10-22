// Deterministic native-model regression tests. No app, wallet, or node is opened.
import Foundation

private struct TestFailure: Error {
    let message: String
}

private func expect(_ condition: @autoclosure () -> Bool, _ message: String) throws {
    if !condition() { throw TestFailure(message: message) }
}

private final class FakeBridge: WalletBridgeClient {
    struct Request {
        let command: String
        let parameters: [String: Any]
        let completion: (Result<[String: Any], BridgeFailure>) -> Void
    }
    private(set) var requests: [Request] = []
    private(set) var history: [String] = []
    private var shutdownCompletion: ((Result<Void, BridgeFailure>) -> Void)?

    func request(_ command: String, _ params: [String: Any],
                 completion: @escaping (Result<[String: Any], BridgeFailure>) -> Void) {
        history.append(command)
        requests.append(Request(command: command, parameters: params, completion: completion))
    }

    func shutdown(completion: @escaping (Result<Void, BridgeFailure>) -> Void) {
        shutdownCompletion = completion
    }

    func count(_ command: String) -> Int { history.filter { $0 == command }.count }

    func succeed(_ command: String, _ result: [String: Any]) throws {
        guard let index = requests.firstIndex(where: { $0.command == command }) else {
            throw TestFailure(message: "Expected request was not queued: \(command)")
        }
        let request = requests.remove(at: index)
        request.completion(.success(result))
    }

    func fail(_ command: String, _ failure: BridgeFailure = .unavailable) throws {
        guard let index = requests.firstIndex(where: { $0.command == command }) else {
            throw TestFailure(message: "Expected request was not queued: \(command)")
        }
        let request = requests.remove(at: index)
        request.completion(.failure(failure))
    }

    func finishShutdown() throws {
        guard let completion = shutdownCompletion else {
            throw TestFailure(message: "Shutdown was not requested")
        }
        shutdownCompletion = nil
        completion(.success(()))
    }
}

private final class Activity {
    var active = true
}

@MainActor
private final class Fixture {
    // These strings are deliberately invalid recovery material, never real credentials.
    static let path = "/synthetic/backup.json"
    static let code = "QLU1-UI-TEST-NOT-A-REAL-RECOVERY-CODE"
    let bridge = FakeBridge()
    let activity = Activity()
    let model: WalletModel

    init() {
        let activity = activity
        model = WalletModel(bridge: bridge, isApplicationActive: { activity.active },
                            startServices: false)
        model.state = WalletState(Self.state())
    }

    static func state(locked: Bool = false, path: String = "/synthetic/first.vault.json") -> [String: Any] {
        ["wallet_open": true, "locked": locked, "backup_verified": false,
         "wallet_path": path, "network_running": false]
    }

    func selectBackup() {
        model.beginFilePanel()
        model.finishBackupSelection(Self.path)
    }

    func completeBackup() throws {
        try bridge.succeed("backup_create", ["backup_path": Self.path, "code": Self.code])
    }

    func lockDuringPanel() {
        model.beginFilePanel()
        model.lock()
        model.finishBackupSelection(Self.path)
    }

    func unlockAfterInterruption() throws {
        try bridge.succeed("lock", Self.state(locked: true))
        model.passphrase = "Synthetic test input only"
        model.unlock()
        try bridge.succeed("unlock", Self.state())
    }

    func expectNoCode(_ context: String) throws {
        try expect(model.recoveryCode.isEmpty, "\(context): recoveryCode must be empty")
        try expect(!model.isRecoveryCodeVisible, "\(context): recovery overlay must be hidden")
    }

    func expectMissingCodeNotice() throws {
        let notice = model.notice?.lowercased() ?? ""
        try expect(notice.contains("code") && notice.contains("backup"),
                   "An unavailable recovery code must have an explanatory backup notice")
    }
}

@main
private struct WalletBackupFlowTests {
    @MainActor
    static func main() {
        let tests: [(String, () throws -> Void)] = [
            ("active save presents recovery code", testActiveSave),
            ("acknowledgment clears recovery code", testAcknowledge),
            ("manual lock during panel preserves selection without saving", testLockedPanel),
            ("inactive panel stages destination without locking", testInactivePanel),
            ("focus return during panel permits normal save", testPanelFocusReturn),
            ("cancelled panel creates no pending backup", testCancelledPanel),
            ("focus change during cancelled panel does not lock", testFocusCancelledPanel),
            ("unlock requires explicit backup continuation", testExplicitContinuation),
            ("cancelling pending selection prevents creation", testCancelPending),
            ("wallet replacement clears pending selection", testPendingWalletReplacement),
            ("quit clears pending selection", testPendingQuit),
            ("late save after lock hides recovery code", testLateSaveAfterLock),
            ("late save while inactive retains covered recovery code", testLateSaveInactive),
            ("late save after hard lock and unlock stays hidden", testLateSaveAfterReturn),
            ("late save after wallet switch is ignored", testLateSaveAfterWalletSwitch),
            ("explicit lock explains missing recovery code", testCodeLockNotice),
            ("idle lock hides recovery code overlay", testIdleLock),
            ("wallet passphrase is rejected as a recovery code", testPassphraseConfusion),
            ("unlock retains guidance after an unrecorded code is hidden", testHiddenCodeAfterUnlock),
            ("old sheet binding reset and dismissal preserve recovery overlay", testDelayedSheetDismissal),
            ("ordinary sheet dismissal preserves recovery overlay", testOrdinarySheetDismissal),
            ("wallet replacement clears hidden-code state", testHiddenCodeWalletReplacement),
            ("recovery overlay is visible only while unlocked", testRecoveryOverlayVisibility),
            ("successful verification clears hidden-code guidance", testVerificationAfterHiddenCode),
            ("focus switch covers code without locking", testFocusSwitch),
            ("failed foreground check keeps recovery code covered", testForegroundStatusFailure),
            ("old foreground check cannot reveal recovery code", testStaleForegroundCheck),
            ("foreground idle-lock response clears recovery code", testForegroundIdleLock),
            ("foreground status cannot undo manual lock", testForegroundManualLock),
            ("old foreground status cannot replace another wallet", testForegroundWalletSwitch),
            ("unlock-producing replies cannot undo a newer lock", testLateUnlockProducingReply),
            ("focus change during access does not lock the wallet", testFocusChangeDuringAccess),
            ("uncertain payment blocks repeat send and funding", testUncertainPayment),
            ("uncertain funding clears review and blocks new payments", testUncertainFaucet),
            ("payment uncertainty survives status lock and unlock", testPersistentPaymentUncertainty),
            ("restarted wallet loads pending history and blocks new payments", testReloadedPendingHistory),
            ("status recovery clears only an authoritative resolved journal", testJournalRecovery),
            ("late confirmation does not override an uncertain journal", testConfirmationKeepsJournalBlock),
            ("funding requests carry unique durable operation identifiers", testFundingIdentifiers),
            ("remembered verification opens wallet after passphrase only", testRememberedVerification),
            ("missing or invalid verification requires a new backup check", testMissingVerification),
            ("remembered verification cannot bypass a later real lock", testRememberedVerificationAfterLock),
            ("failed verification persistence never announces success", testVerificationSaveFailure),
            ("incoming check validates transaction ID before requesting", testIncomingValidation),
            ("incoming check is read-only and loads durable result", testIncomingVerification),
            ("pending incoming history never blocks outgoing payments", testIncomingPendingDoesNotBlock),
            ("missing network proof clears balances without gating offline wallet", testNetworkProofRequired),
            ("network failure clears stale balances and review until successful refresh", testFailedNetworkRefresh),
            ("failed recovery preserves the unresolved payment reference", testFailedRecoveryKeepsPending),
            ("confirmed payment survives failed balance check without current-proof claim", testConfirmedPaymentWithoutHealthyNetwork),
            ("late prepared payment cannot survive a newer manual lock", testLatePreparedPaymentAfterLock),
            ("insufficient funds clears availability while input errors preserve it", testFreshAvailabilityFailure),
            ("fresh conflict proof resolves uncertainty without resubmitting", testConflictResolutionState),
            ("conflicted operation error discards its original review", testConflictedReplayError),
            ("saved conflict needs a network check and reorg restores pending", testSavedConflictRevalidation),
            ("changed wallet selection immediately clears private and public screen state", testWalletChangedUnlock),
            ("old status cannot restore a changed wallet selection", testWalletChangedStaleStatus),
            ("identity failure invalidates an in-flight payment review", testWalletChangedLateReview),
            ("foreground identity failure clears covered recovery material", testWalletChangedForeground),
            ("old lock acknowledgment cannot restore a changed wallet selection", testWalletChangedLateLock),
            ("explicitly reopened wallet loads its own pending payment guard", testWalletChangedExplicitReopen),
            ("resume review keeps ordinary payments blocked and exposes original intent", testResumeReview),
            ("unchanged status preserves only the same eligible resume review", testResumeStatusPreservation),
            ("resume confirmation is explicit single-use and never creates a send", testResumeConfirmation),
            ("legacy locked and stopped states cannot request resume", testResumeGates),
            ("late resume review after lock or wallet change is ignored", testLateResumeReview),
            ("uncertain resume retains original transaction without automatic retry", testResumeUncertain),
            ("resume transport loss preserves original transaction and prevents retry", testResumeTransportLoss),
            ("resume proof failure clears review and leaves payment blocked", testResumeProofFailure),
            ("test-funding resume presents credit without wallet debit", testResumeFunding),
        ]
        var failed = 0
        for (name, test) in tests {
            do {
                try test()
                print("PASS: \(name)")
            } catch let failure as TestFailure {
                failed += 1
                print("FAIL: \(name): \(failure.message)")
            } catch {
                failed += 1
                // Never render unknown error values or request/response payloads.
                print("FAIL: \(name): unexpected test error")
            }
        }
        print("Native backup model: \(tests.count - failed) passed; \(failed) failed.")
        exit(failed == 0 ? 0 : 1)
    }

    @MainActor
    static func testIncomingValidation() throws {
        let f = Fixture()
        var state = Fixture.state()
        state["backup_verified"] = true
        state["network_running"] = true
        f.model.state = WalletState(state)
        f.model.incomingTransaction = "not a transaction"
        f.model.verifyIncoming()
        try expect(f.bridge.count("verify_received") == 0, "Malformed ID cannot reach verification")
        try expect(f.model.error?.contains("64-character") == true, "Explain complete transaction ID")
        f.model.state = WalletState(Fixture.state(locked: true))
        f.model.incomingTransaction = String(repeating: "a", count: 64)
        f.model.verifyIncoming()
        try expect(f.bridge.count("verify_received") == 0, "Locked wallet cannot request incoming check")
    }

    @MainActor
    static func testIncomingVerification() throws {
        let f = Fixture()
        var state = Fixture.state()
        state["backup_verified"] = true
        state["network_running"] = true
        state["history_loaded"] = true
        state["payment_blocked"] = false
        f.model.state = WalletState(state)
        f.model.destination = .receive
        f.model.incomingTransaction = String(repeating: "A", count: 64)
        f.model.verifyIncoming()
        try expect(f.bridge.count("verify_received") == 1, "Incoming check uses the readonly command")
        try expect(f.bridge.requests.last?.parameters["txid"] as? String == String(repeating: "a", count: 64),
                   "UI normalizes pasted hexadecimal IDs")
        state["payment_history"] = [["kind": "receive", "direction": "received", "status": "confirmed",
                                    "amount": "0.10000000", "txid": String(repeating: "a", count: 64)]]
        try f.bridge.succeed("verify_received", ["state": state])
        try expect(f.model.destination == .wallet && f.model.state.paymentHistory.count == 1,
                   "Confirmed receipt appears in wallet history")
        try expect(f.bridge.count("confirm_send") == 0 && f.bridge.count("faucet") == 0,
                   "Checking incoming cannot spend or fund")
        try expect(f.model.incomingTransaction.isEmpty, "Successful check clears pasted transaction")
    }

    @MainActor
    static func testIncomingPendingDoesNotBlock() throws {
        let f = Fixture()
        var state = Fixture.state()
        state["backup_verified"] = true
        state["history_loaded"] = true
        state["payment_blocked"] = false
        state["payment_history"] = [["kind": "receive", "direction": "received", "status": "pending",
                                    "txid": String(repeating: "a", count: 64)]]
        f.model.refreshStatus()
        try f.bridge.succeed("status", state)
        try expect(!f.model.paymentUncertain && f.model.pendingTXID == nil,
                   "Incoming uncertainty must not be presented as an unresolved send")
        try expect(PaymentPresentation.title(["direction": "received"]) == "Received", "Incoming label")
        try expect(PaymentPresentation.title(["direction": "self"]) == "Transfer to yourself", "Self-transfer label")
        try expect(PaymentPresentation.isSelfTransfer(["is_self_transfer": true]), "Explicit reviewed self-transfer")
    }

    @MainActor
    static func testRememberedVerification() throws {
        let f = Fixture()
        f.model.state = WalletState(Fixture.state(locked: true))
        f.model.destination = .backup
        f.model.passphrase = "Synthetic test input only"
        f.model.unlock()
        var state = Fixture.state()
        state["backup_verified"] = true
        state["backup_verification_status"] = "remembered"
        try f.bridge.succeed("unlock", state)
        try expect(f.model.canUseWallet, "Authenticated remembered check should allow wallet access")
        try expect(f.model.destination == .wallet, "Unlock should leave backup setup and open wallet")
        try expect(f.model.notice?.contains("remembered") == true, "Explain remembered verification")
        try expect(f.bridge.count("backup_verify") == 0, "Normal unlock must not ask for recovery materials")
        try expect(f.model.recoveryInput.isEmpty && f.model.passphrase.isEmpty, "Credential inputs are cleared")
    }

    @MainActor
    static func testMissingVerification() throws {
        for status in ["required", "unavailable"] {
            let f = Fixture()
            f.model.state = WalletState(Fixture.state(locked: true))
            f.model.passphrase = "Synthetic test input only"
            f.model.unlock()
            var state = Fixture.state()
            state["backup_verification_status"] = status
            try f.bridge.succeed("unlock", state)
            try expect(!f.model.canUseWallet, "Unverified backup must keep receive/send gated")
            try expect(f.model.destination == .backup, "Missing check should open backup setup")
            try expect(f.model.notice?.contains("Verify") == true, "Explain verification is required")
        }
    }

    @MainActor
    static func testRememberedVerificationAfterLock() throws {
        let f = Fixture()
        f.model.passphrase = "Synthetic test input only"
        f.model.unlock()
        f.model.lock()
        var state = Fixture.state()
        state["backup_verified"] = true
        state["backup_verification_status"] = "remembered"
        try f.bridge.succeed("unlock", state)
        try expect(f.model.isLocked && !f.model.canUseWallet, "Old unlock cannot undo later real lock")
        try expect(f.model.notice?.contains("Wallet unlocked") != true, "Stale reply must not claim access")
    }

    @MainActor
    static func testVerificationSaveFailure() throws {
        let f = Fixture()
        f.model.backupPath = Fixture.path
        f.model.recoveryInput = Fixture.code
        f.model.verifyBackup()
        try f.bridge.fail("backup_verify", BridgeFailure(code: "verification_save_failed",
            message: "Your backup check could not be remembered safely.", txid: nil))
        try expect(!f.model.state.backupVerified, "Failed persistence must not mark verified")
        try expect(f.model.notice?.contains("remembered") != true, "No success notice on failed save")
        try expect(f.model.recoveryInput.isEmpty, "Failed request must clear recovery code input")
    }

    @MainActor
    static func testActiveSave() throws {
        let f = Fixture()
        f.selectBackup()
        try expect(f.bridge.count("backup_create") == 1, "Save must queue one backup_create")
        try expect(f.bridge.requests.first?.parameters["backup_path"] as? String == Fixture.path,
                   "Save must use the selected backup_path")
        try f.completeBackup()
        try expect(f.model.backupPath == Fixture.path, "Successful save must select its backup_path")
        try expect(f.model.recoveryCode == Fixture.code, "Successful active save must expose its code")
        try expect(f.model.isRecoveryCodeVisible, "Successful save must present the recovery overlay")
        try expect(f.model.sheet == nil, "Recovery overlay must not use the sheet binding")
        try expect(f.model.pendingBackupPath == nil, "Completed selection must be consumed")
        try expect(!f.model.codeAcknowledged, "Fresh code must require acknowledgment")
    }

    @MainActor
    static func testAcknowledge() throws {
        let f = Fixture()
        f.selectBackup()
        try f.completeBackup()
        f.model.acknowledgeCode()
        try f.expectNoCode("Acknowledgment")
        try expect(f.model.codeAcknowledged, "Acknowledgment must be recorded")
        try expect(!f.model.recoveryCodeWasHidden, "Acknowledgment must not leave hidden-code state")
        try expect(f.model.backupPath == Fixture.path, "Acknowledgment must retain saved backup path")
    }

    @MainActor
    static func testLockedPanel() throws {
        let f = Fixture()
        f.lockDuringPanel()
        try expect(f.model.pendingBackupPath == Fixture.path, "Locked selection must survive")
        try expect(f.model.isLocked, "Locked selection must retain the privacy lock")
        try expect(f.bridge.count("backup_create") == 0, "Locked panel must not save")
        try f.expectNoCode("Locked panel")
    }

    @MainActor
    static func testInactivePanel() throws {
        let f = Fixture()
        f.model.beginFilePanel()
        f.activity.active = false
        f.model.resignActive()
        f.model.finishBackupSelection(Fixture.path)
        try expect(f.model.pendingBackupPath == Fixture.path, "Inactive selection must survive")
        try expect(f.bridge.count("backup_create") == 0, "Inactive panel must not save")
        try expect(!f.model.isLocked, "Inactive panel must not lock")
        try expect(f.bridge.count("lock") == 0, "Inactive panel must not request a backend lock")
        f.activity.active = true
        f.model.becomeActive()
        try f.bridge.succeed("status", Fixture.state())
        try expect(f.bridge.count("backup_create") == 0, "Returning must not submit a staged save implicitly")
        f.model.continueBackup()
        try f.completeBackup()
        try expect(f.model.isRecoveryCodeVisible, "Explicit continuation after focus return must show code")
    }

    @MainActor
    static func testPanelFocusReturn() throws {
        let f = Fixture()
        f.model.beginFilePanel()
        f.activity.active = false
        f.model.resignActive()
        f.activity.active = true
        f.model.becomeActive()
        f.model.finishBackupSelection(Fixture.path)
        try f.bridge.succeed("status", Fixture.state())
        try expect(f.bridge.count("lock") == 0, "Panel focus return must not lock")
        try expect(f.bridge.count("backup_create") == 1, "Active panel selection must save normally")
        try f.completeBackup()
        try expect(f.model.isRecoveryCodeVisible, "Normal save after focus return must show code")
    }

    @MainActor
    static func testCancelledPanel() throws {
        let f = Fixture()
        f.model.beginFilePanel()
        f.model.finishBackupSelection(nil)
        try expect(f.model.pendingBackupPath == nil, "Cancelled panel must have no pending selection")
        try expect(f.bridge.count("backup_create") == 0, "Cancelled panel must not save")
    }

    @MainActor
    static func testFocusCancelledPanel() throws {
        let f = Fixture()
        f.model.beginFilePanel()
        f.activity.active = false
        f.model.resignActive()
        f.activity.active = true
        f.model.finishBackupSelection(nil)
        try expect(f.model.pendingBackupPath == nil, "Cancelled interrupted panel must not retain path")
        try expect(f.bridge.count("backup_create") == 0, "Cancelled interrupted panel must not save")
        try expect(!f.model.isLocked, "Ordinary focus switch and cancellation must not lock")
        try expect(f.bridge.count("lock") == 0, "Focus switch must not send a lock request")
    }

    @MainActor
    static func testExplicitContinuation() throws {
        let f = Fixture()
        f.lockDuringPanel()
        f.model.continueBackup()
        try expect(f.bridge.count("backup_create") == 0, "Locked continuation must not save")
        try f.unlockAfterInterruption()
        try expect(!f.model.isLocked, "Foreground unlock must succeed")
        try expect(f.model.pendingBackupPath == Fixture.path, "Unlock must retain selected path")
        try expect(f.bridge.count("backup_create") == 0, "Unlock alone must never create a backup")
        f.model.continueBackup()
        f.model.continueBackup()
        try expect(f.bridge.count("backup_create") == 1, "Repeated continuation must create only once")
        try expect(f.model.pendingBackupPath == nil, "Started save must consume pending selection")
        try f.completeBackup()
        try expect(f.model.isRecoveryCodeVisible, "Explicit resumed save must show recovery overlay")
    }

    @MainActor
    static func testCancelPending() throws {
        let f = Fixture()
        f.lockDuringPanel()
        f.model.cancelPendingBackup()
        try f.unlockAfterInterruption()
        f.model.continueBackup()
        try expect(f.model.pendingBackupPath == nil, "Cancellation must clear pending path")
        try expect(f.bridge.count("backup_create") == 0, "Cancelled selection must not be reused")
    }

    @MainActor
    static func testPendingWalletReplacement() throws {
        for operation in ["create", "open", "restore"] {
            let f = Fixture()
            f.lockDuringPanel()
            try f.unlockAfterInterruption()
            switch operation {
            case "create": f.model.create()
            case "open": f.model.openWallet("/synthetic/second.vault.json")
            default: f.model.restore()
            }
            try expect(f.model.pendingBackupPath == nil, "Wallet replacement must clear pending path")
            try expect(f.bridge.count("backup_create") == 0, "Wallet replacement must not create a backup")
        }
    }

    @MainActor
    static func testPendingQuit() throws {
        let f = Fixture()
        f.lockDuringPanel()
        var completed = false
        f.model.shutdown { completed = $0 }
        try expect(f.model.pendingBackupPath == nil, "Quit must clear pending path")
        try f.bridge.finishShutdown()
        try expect(completed, "Successful shutdown must acknowledge completion")
    }

    @MainActor
    static func testLateSaveAfterLock() throws {
        let f = Fixture()
        f.selectBackup()
        f.model.lock()
        try f.completeBackup()
        try f.expectNoCode("Late locked save")
        try expect(f.model.pendingBackupPath == nil, "Already-started save must not be retried implicitly")
        try f.expectMissingCodeNotice()
    }

    @MainActor
    static func testLateSaveInactive() throws {
        let f = Fixture()
        f.selectBackup()
        f.activity.active = false
        // The callback must check focus itself, even before a resign-active notification.
        try f.completeBackup()
        try expect(f.model.recoveryCode == Fixture.code, "Background save must retain its code")
        try expect(f.model.hasRecoveryCode, "Background save must report retained recovery material")
        try expect(!f.model.isRecoveryCodeVisible, "Background callback must not display its code")
        try expect(f.model.recoveryCodeCovered, "Background callback must cover its code")
        try expect(!f.model.isLocked, "Background callback must not lock the wallet")
        f.activity.active = true
        f.model.becomeActive()
        try expect(!f.model.isRecoveryCodeVisible, "Returning must first check backend lock status")
        try f.bridge.succeed("status", Fixture.state())
        try expect(f.model.isRecoveryCodeVisible, "Fresh unlocked foreground status must reveal retained code")
    }

    @MainActor
    static func testLateSaveAfterReturn() throws {
        let f = Fixture()
        f.selectBackup()
        f.model.lock()
        try f.bridge.succeed("lock", Fixture.state(locked: true))
        // Even an independently observed unlocked state cannot revive an old code request.
        f.model.state = WalletState(Fixture.state())
        f.model.privacyLocked = false
        try f.completeBackup()
        try f.expectNoCode("Earlier privacy generation")
        try f.expectMissingCodeNotice()
    }

    @MainActor
    static func testLateSaveAfterWalletSwitch() throws {
        let f = Fixture()
        f.selectBackup()
        f.model.openWallet("/synthetic/second.vault.json")
        try f.completeBackup()
        try f.expectNoCode("Different wallet")
        try expect(f.model.backupPath != Fixture.path, "Late callback must not replace new wallet backup path")
    }

    @MainActor
    static func testCodeLockNotice() throws {
        let f = Fixture()
        f.selectBackup()
        try f.completeBackup()
        f.model.lock()
        try f.expectNoCode("Explicit lock")
        try f.expectMissingCodeNotice()
        try expect(!f.model.codeAcknowledged, "Lock must not acknowledge an unseen code")
    }

    @MainActor
    static func testIdleLock() throws {
        let f = Fixture()
        f.selectBackup()
        try f.completeBackup()
        f.model.refreshStatus()
        try f.bridge.succeed("status", Fixture.state(locked: true))
        try f.expectNoCode("Idle lock")
        try f.expectMissingCodeNotice()
    }

    @MainActor
    static func testPassphraseConfusion() throws {
        let f = Fixture()
        f.model.backupPath = Fixture.path
        f.model.recoveryInput = "Synthetic wallet passphrase input"
        f.model.verifyBackup()
        try expect(f.bridge.count("backup_verify") == 0,
                   "Non-recovery input must not be sent to backup verification")
        try expect(f.model.recoveryInput.isEmpty, "Rejected recovery input must be cleared")
        try expect(!f.model.isLocked, "Local input guidance must not lock the wallet")
        let error = f.model.error?.lowercased() ?? ""
        try expect(error.contains("qlu1-") && error.contains("passphrase"),
                   "Input guidance must explain recovery code versus wallet passphrase")
    }

    @MainActor
    static func testHiddenCodeAfterUnlock() throws {
        let f = Fixture()
        f.selectBackup()
        try f.completeBackup()
        f.model.lock()
        try expect(f.model.recoveryCodeWasHidden, "Lock must remember an unrecorded code was hidden")
        try expect(f.model.pendingBackupPath == nil, "Saved backup must have no pending selection")
        try f.unlockAfterInterruption()
        try f.expectNoCode("Unlock after hidden code")
        try expect(f.model.recoveryCodeWasHidden, "Unlock must retain hidden-code state")
        try expect(f.model.notice?.lowercased().contains("new backup") == true,
                   "Unlock must explain how to replace the hidden recovery code")
        try expect(f.bridge.count("backup_create") == 1, "Unlock must not silently create a replacement")
    }

    @MainActor
    static func testDelayedSheetDismissal() throws {
        let f = Fixture()
        f.lockDuringPanel()
        f.model.sheet = .unlock
        try f.unlockAfterInterruption()
        try expect(f.model.sheet == nil, "Unlock must dismiss its own sheet")
        f.model.continueBackup()
        try f.completeBackup()
        // SwiftUI may reset the old unlock sheet's binding and then deliver its
        // dismissal callback after the backup response has made the code visible.
        f.model.sheet = nil
        f.model.sheetDidDismiss()
        try expect(f.model.isRecoveryCodeVisible, "Old binding reset must preserve recovery overlay")
        try expect(f.model.recoveryCode == Fixture.code, "Old dismissal must preserve the newer code")
        try expect(!f.model.recoveryCodeWasHidden, "Old dismissal must not mark new code hidden")
        f.model.dismissSheet()
        try expect(f.model.isRecoveryCodeVisible, "Repeated old dismissal must preserve recovery overlay")
    }

    @MainActor
    static func testOrdinarySheetDismissal() throws {
        let f = Fixture()
        f.selectBackup()
        try f.completeBackup()
        f.model.dismissSheet()
        f.model.sheetDidDismiss()
        try expect(f.model.recoveryCode == Fixture.code, "Ordinary dismissal must not clear recovery code")
        try expect(f.model.isRecoveryCodeVisible, "Ordinary dismissal must retain recovery overlay")
        try expect(!f.model.recoveryCodeWasHidden, "Ordinary dismissal must not record hidden code")
        try expect(!f.model.codeAcknowledged, "Dismissal must not acknowledge the code")
    }

    @MainActor
    static func testHiddenCodeWalletReplacement() throws {
        for operation in ["create", "open", "restore"] {
            let f = Fixture()
            f.selectBackup()
            try f.completeBackup()
            f.model.lock()
            try expect(f.model.recoveryCodeWasHidden, "Locking visible code must record hidden code")
            switch operation {
            case "create": f.model.create()
            case "open": f.model.openWallet("/synthetic/second.vault.json")
            default: f.model.restore()
            }
            try expect(!f.model.recoveryCodeWasHidden,
                       "New wallet flow must not inherit another wallet's hidden-code state")
        }
    }

    @MainActor
    static func testRecoveryOverlayVisibility() throws {
        let f = Fixture()
        try expect(!f.model.isRecoveryCodeVisible, "Empty recovery code must not show an overlay")
        f.selectBackup()
        try f.completeBackup()
        try expect(f.model.isRecoveryCodeVisible, "Unlocked nonempty code must show the overlay")
        // Exercise both lock sources independently, without using code clearing
        // as a substitute for the view's own visibility guard.
        f.model.state.locked = true
        try expect(!f.model.isRecoveryCodeVisible, "Backend lock must hide the overlay")
        f.model.state.locked = false
        f.model.privacyLocked = true
        try expect(!f.model.isRecoveryCodeVisible, "Immediate privacy lock must hide the overlay")
        f.model.privacyLocked = false
        try expect(f.model.isRecoveryCodeVisible, "Unlocked nonempty code must remain visible")
        f.model.acknowledgeCode()
        try f.expectNoCode("Explicit acknowledgment")
    }

    @MainActor
    static func testVerificationAfterHiddenCode() throws {
        let f = Fixture()
        f.selectBackup()
        try f.completeBackup()
        f.model.lock()
        try f.unlockAfterInterruption()
        f.model.recoveryInput = Fixture.code
        f.model.verifyBackup()
        var verified = Fixture.state()
        verified["backup_verified"] = true
        try f.bridge.succeed("backup_verify", verified)
        try expect(!f.model.recoveryCodeWasHidden,
                   "A verified recorded code must clear missing-code guidance")
        f.model.lock()
        try f.unlockAfterInterruption()
        try expect(f.model.notice?.contains("new backup") != true,
                   "Later unlock must not ask to replace a successfully verified backup")
    }

    @MainActor
    static func testFocusSwitch() throws {
        let f = Fixture()
        f.selectBackup()
        try f.completeBackup()
        f.activity.active = false
        f.model.resignActive()
        try expect(!f.model.isLocked, "Ordinary focus loss must keep the wallet unlocked")
        try expect(f.bridge.count("lock") == 0, "Ordinary focus loss must not request locking")
        try expect(f.model.recoveryCode == Fixture.code, "Focus loss must retain recovery code")
        try expect(f.model.recoveryCodeCovered, "Focus loss must cover recovery code")
        try expect(!f.model.isRecoveryCodeVisible, "Inactive code must not be visible")
        f.model.refreshStatus()
        try f.bridge.succeed("status", Fixture.state())
        try expect(!f.model.isRecoveryCodeVisible, "Background status polling must not reveal code")
        f.activity.active = true
        f.model.becomeActive()
        try expect(!f.model.isRecoveryCodeVisible, "Focus return must await a fresh backend check")
        try f.bridge.succeed("status", Fixture.state())
        try expect(!f.model.isLocked, "Fresh unlocked status must preserve the unlocked wallet")
        try expect(f.model.isRecoveryCodeVisible, "Fresh foreground status must reveal retained code")
        try expect(!f.model.recoveryCodeWasHidden, "Temporary cover must not require a replacement backup")
    }

    @MainActor
    static func testForegroundStatusFailure() throws {
        let f = Fixture()
        f.selectBackup()
        try f.completeBackup()
        f.activity.active = false
        f.model.resignActive()
        f.activity.active = true
        f.model.becomeActive()
        try f.bridge.fail("status")
        try expect(!f.model.isRecoveryCodeVisible, "Failed status check must not reveal code")
        try expect(f.model.recoveryCodeCovered, "Failed status check must preserve cover")
        try expect(f.model.recoveryCode == Fixture.code, "Failed status check must retain pending code")
    }

    @MainActor
    static func testStaleForegroundCheck() throws {
        let f = Fixture()
        f.selectBackup()
        try f.completeBackup()
        for _ in 0..<2 {
            f.activity.active = false
            f.model.resignActive()
            f.activity.active = true
            f.model.becomeActive()
        }
        try f.bridge.succeed("status", Fixture.state())
        try expect(!f.model.isRecoveryCodeVisible, "Earlier focus generation must not reveal code")
        try f.bridge.succeed("status", Fixture.state())
        try expect(f.model.isRecoveryCodeVisible, "Current foreground check must reveal code")
    }

    @MainActor
    static func testForegroundIdleLock() throws {
        let f = Fixture()
        f.selectBackup()
        try f.completeBackup()
        f.activity.active = false
        f.model.resignActive()
        f.activity.active = true
        f.model.becomeActive()
        try f.bridge.succeed("status", Fixture.state(locked: true))
        try f.expectNoCode("Foreground idle-lock status")
        try expect(f.model.isLocked, "Foreground check must honor actual idle lock")
        try expect(f.model.recoveryCodeWasHidden, "Actual idle lock must record unavailable recovery code")
        try f.expectMissingCodeNotice()
    }

    @MainActor
    static func testForegroundManualLock() throws {
        let f = Fixture()
        f.selectBackup()
        try f.completeBackup()
        f.activity.active = false
        f.model.resignActive()
        f.activity.active = true
        f.model.becomeActive()
        f.model.lock()
        try f.bridge.succeed("lock", Fixture.state(locked: true))
        try f.bridge.succeed("status", Fixture.state())
        try expect(f.model.isLocked, "Stale foreground check must not undo a manual lock")
        try f.expectNoCode("Manual lock before foreground reply")
    }

    @MainActor
    static func testForegroundWalletSwitch() throws {
        let f = Fixture()
        f.selectBackup()
        try f.completeBackup()
        f.activity.active = false
        f.model.resignActive()
        f.activity.active = true
        f.model.becomeActive()
        let next = "/synthetic/second.vault.json"
        f.model.openWallet(next)
        try f.bridge.succeed("open", Fixture.state(locked: true, path: next))
        try f.bridge.succeed("status", Fixture.state())
        try expect(f.model.state.walletPath == next, "Old foreground reply must not restore another wallet state")
        try expect(f.model.isLocked, "Old foreground reply must not unlock the replacement wallet")
        try f.expectNoCode("Wallet switch before foreground reply")
    }

    @MainActor
    static func testLateUnlockProducingReply() throws {
        for operation in ["create", "restore", "unlock"] {
            let f = Fixture()
            f.model.passphrase = "Synthetic test input only"
            f.model.confirmation = "Synthetic test input only"
            switch operation {
            case "create": f.model.create()
            case "restore": f.model.restore()
            default:
                f.model.state.locked = true
                f.model.unlock()
            }
            f.model.lock()
            try f.bridge.succeed("lock", Fixture.state(locked: true))
            try f.bridge.succeed(operation, Fixture.state())
            try expect(f.model.isLocked, "Older unlock-producing reply must not undo a newer lock")
            try f.expectNoCode("Late unlock-producing reply")
        }
    }

    @MainActor
    static func testFocusChangeDuringAccess() throws {
        for operation in ["create", "restore", "unlock"] {
            let f = Fixture()
            f.model.passphrase = "Synthetic test input only"
            f.model.confirmation = "Synthetic test input only"
            switch operation {
            case "create": f.model.create()
            case "restore": f.model.restore()
            default:
                f.model.state.locked = true
                f.model.unlock()
            }
            f.activity.active = false
            f.model.resignActive()
            try f.bridge.succeed(operation, Fixture.state())
            try expect(!f.model.isLocked, "Focus change must not invalidate an authorized access reply")
            try expect(f.bridge.count("lock") == 0, "Background access reply must not request locking")
            f.activity.active = true
            f.model.becomeActive()
            try f.bridge.succeed("status", Fixture.state())
            try expect(!f.model.isLocked, "Foreground return must preserve the authorized access")
        }
    }

    @MainActor
    static func preparePayment(_ f: Fixture) throws {
        f.model.state.backupVerified = true
        f.model.state.networkRunning = true
        f.model.state.networkHealthy = true
        f.model.recipient = "synthetic private test recipient"
        f.model.amount = "0.1"
        f.model.prepareSend()
        try f.bridge.succeed("prepare_send", [
            "preview_id": "synthetic-review-id", "recipient": f.model.recipient,
            "amount": "0.10000000", "fee": "0.00100000", "total": "0.10100000",
        ])
        try expect(f.model.preview != nil, "Prepared payment must expose a review")
    }

    @MainActor
    static func expectUncertain(_ f: Fixture, txid: String?) throws {
        try expect(f.model.paymentUncertain, "Uncertain response must prevent another payment")
        try expect(f.model.pendingTXID == txid, "Uncertain response must retain the available transaction ID")
        try expect(f.model.preview == nil, "Uncertain response must clear the review")
        try expect(!f.model.busy, "Uncertain response must finish its pending request")
    }

    @MainActor
    static func testUncertainPayment() throws {
        for code in ["payment_pending", "payment_unknown"] {
            for txid in [String(repeating: "a", count: 64), nil] as [String?] {
                let f = Fixture()
                try preparePayment(f)
                f.model.confirmSend()
                try f.bridge.fail("confirm_send", BridgeFailure(
                    code: code, message: "Synthetic uncertain payment response", txid: txid))
                try expectUncertain(f, txid: txid)
                try expect(f.model.error?.contains("do not repeat") == true,
                           "Uncertain response must give no-repeat guidance")
                // The UI selects its uncertainty card before the review/form.
                // Exercise the existing model guards and consumed preview too.
                f.model.prepareSend()
                f.model.confirmSend()
                f.model.faucet()
                try expect(f.bridge.count("prepare_send") == 1, "Uncertainty must prevent a second review")
                try expect(f.bridge.count("confirm_send") == 1, "Consumed review must not be sent again")
                try expect(f.bridge.count("faucet") == 0, "Uncertainty must prevent additional funding")
            }
        }
    }

    @MainActor
    static func testUncertainFaucet() throws {
        for code in ["payment_pending", "payment_unknown"] {
            let f = Fixture()
            try preparePayment(f)
            // A prepared review can remain while navigating back to Dashboard.
            f.model.faucet()
            let txid: String? = code == "payment_pending" ? String(repeating: "b", count: 64) : nil
            try f.bridge.fail("faucet", BridgeFailure(
                code: code, message: "Synthetic uncertain funding response", txid: txid))
            try expectUncertain(f, txid: txid)
            f.model.faucet()
            f.model.prepareSend()
            f.model.confirmSend()
            try expect(f.bridge.count("faucet") == 1, "Uncertain funding must not be retried")
            try expect(f.bridge.count("prepare_send") == 1, "Uncertain funding must prevent a new review")
            try expect(f.bridge.count("confirm_send") == 0, "Uncertain funding must invalidate an existing review")
        }
    }

    @MainActor
    static func testPersistentPaymentUncertainty() throws {
        for code in ["payment_pending", "payment_unknown"] {
            let f = Fixture()
            try preparePayment(f)
            f.model.confirmSend()
            let txid: String? = code == "payment_pending" ? String(repeating: "c", count: 64) : nil
            try f.bridge.fail("confirm_send", BridgeFailure(
                code: code, message: "Synthetic uncertain payment response", txid: txid))
            // Error handling queues a public status request. A normal status
            // response is not independent proof that an uncertain payment failed.
            try f.bridge.succeed("status", Fixture.state())
            try expectUncertain(f, txid: txid)
            f.model.lock()
            try f.bridge.succeed("lock", Fixture.state(locked: true))
            try expectUncertain(f, txid: txid)
            f.model.passphrase = "Synthetic test input only"
            f.model.unlock()
            try f.bridge.succeed("unlock", Fixture.state())
            try expectUncertain(f, txid: txid)
            f.model.prepareSend()
            f.model.confirmSend()
            f.model.faucet()
            try expect(f.bridge.count("prepare_send") == 1, "Unlock must not reenable uncertain payment review")
            try expect(f.bridge.count("confirm_send") == 1, "Unlock must not reenable uncertain payment confirmation")
            try expect(f.bridge.count("faucet") == 0, "Unlock must not reenable funding after uncertainty")
        }
    }

    @MainActor
    static func historyState(pending: Bool) -> [String: Any] {
        var state = Fixture.state()
        state["backup_verified"] = true
        state["network_running"] = true
        state["network_healthy"] = true
        state["history_loaded"] = true
        state["history_count"] = 1
        state["payment_blocked"] = pending
        state["payment_history"] = [["operation_id": String(repeating: "a", count: 32),
            "txid": String(repeating: "d", count: 64), "kind": "send", "amount": "0.10000000",
            "status": pending ? "pending" : "confirmed"]]
        return state
    }

    @MainActor
    static func testReloadedPendingHistory() throws {
        let f = Fixture()
        f.model.refreshStatus()
        try f.bridge.succeed("status", historyState(pending: true))
        try expectUncertain(f, txid: String(repeating: "d", count: 64))
        try expect(f.model.state.paymentHistory.count == 1, "Saved history must load in a new model")
        f.model.prepareSend()
        f.model.faucet()
        try expect(f.bridge.count("prepare_send") == 0 && f.bridge.count("faucet") == 0,
                   "Loaded journal must block both new payment paths")
    }

    @MainActor
    static func testJournalRecovery() throws {
        let f = Fixture()
        f.model.refreshStatus()
        try f.bridge.succeed("status", historyState(pending: true))
        f.model.recoverPayments()
        try f.bridge.succeed("recover_payments", historyState(pending: true))
        try expect(f.model.paymentUncertain, "An absent transaction must remain blocked")
        f.model.recoverPayments()
        try f.bridge.succeed("recover_payments", historyState(pending: false))
        try expect(!f.model.paymentUncertain && f.model.pendingTXID == nil,
                   "Confirmed journal recovery must clear uncertainty")
        try expect(f.bridge.count("confirm_send") == 0 && f.bridge.count("faucet") == 0,
                   "Checking status must not issue another payment")
        try expect(f.model.state.paymentHistory.count == 1, "Recovery must retain payment history")
    }

    @MainActor
    static func testConfirmationKeepsJournalBlock() throws {
        for command in ["confirm_send", "faucet"] {
            let f = Fixture()
            try preparePayment(f)
            if command == "confirm_send" { f.model.confirmSend() } else { f.model.faucet() }
            try f.bridge.succeed(command, ["state": historyState(pending: true)])
            try expect(f.model.paymentUncertain, "A success receipt must not override a newer pending chain check")
            try expect(f.model.notice?.contains("status check") == true,
                       "The message must reflect the latest uncertain state")
        }
    }

    @MainActor
    static func testFundingIdentifiers() throws {
        let f = Fixture()
        f.model.state.backupVerified = true
        f.model.state.networkRunning = true
        f.model.state.networkHealthy = true
        f.model.faucet()
        let first = f.bridge.requests.first(where: { $0.command == "faucet" })?.parameters["operation_id"] as? String
        try expect(first?.range(of: "^[0-9a-f]{32}$", options: .regularExpression) != nil,
                   "Funding must send an explicit persistent idempotency token")
        try f.bridge.succeed("faucet", ["state": historyState(pending: false)])
        f.model.faucet()
        let second = f.bridge.requests.first(where: { $0.command == "faucet" })?.parameters["operation_id"] as? String
        try expect(second != first, "A separate user-authorized funding request must have a fresh token")
    }

    @MainActor
    static func testNetworkProofRequired() throws {
        let f = Fixture()
        var state = historyState(pending: false)
        state.removeValue(forKey: "network_healthy")
        state["balance"] = "12.00000000"
        state["immature_balance"] = "3.00000000"
        f.model.refreshStatus()
        try f.bridge.succeed("status", state)
        try expect(f.model.canUseWallet, "An unlocked verified wallet remains usable offline")
        try expect(!f.model.canSubmitPayment, "Missing network proof must prevent outgoing authorization")
        try expect(f.model.state.balance == nil && f.model.state.immatureBalance == nil,
                   "Unverified cached balances must not be shown as available")
        f.model.prepareSend()
        f.model.faucet()
        try expect(f.bridge.count("prepare_send") == 0 && f.bridge.count("faucet") == 0,
                   "No outgoing requests are allowed before a successful network check")
        let payment: [String: Any] = ["kind": "send", "status": "confirmed"]
        try expect(PaymentPresentation.statusLabel(payment, networkRunning: true, networkHealthy: false)
            == "Saved confirmation · network needs checking", "Degraded network must identify saved confirmation")
        try expect(PaymentPresentation.statusLabel(payment, networkRunning: false, networkHealthy: false)
            == "Confirmed at last check · network stopped", "Stopped network must not claim current confirmation")
    }

    @MainActor
    static func testFailedNetworkRefresh() throws {
        for code in ["network_identity", "balance_failed", "unavailable"] {
            let f = Fixture()
            try preparePayment(f)
            f.model.state.balance = "12.00000000"
            f.model.state.immatureBalance = "3.00000000"
            f.model.refresh()
            try f.bridge.fail("refresh", BridgeFailure(code: code, message: "Synthetic network failure", txid: nil))
            try expect(!f.model.state.networkHealthy && !f.model.canSubmitPayment,
                       "Failed check must immediately suspend outgoing authorization")
            try expect(f.model.state.balance == nil && f.model.state.immatureBalance == nil && f.model.preview == nil,
                       "Failed check must erase cached balances and the prepared review")
            try expect(f.model.canUseWallet, "Network failure must preserve offline wallet access")
            f.model.prepareSend()
            f.model.confirmSend()
            f.model.faucet()
            try expect(f.bridge.count("prepare_send") == 1 && f.bridge.count("confirm_send") == 0
                       && f.bridge.count("faucet") == 0, "Failed check cannot trigger another payment")
            var degraded = historyState(pending: false)
            degraded["network_healthy"] = false
            degraded["balance"] = "12.00000000"
            try f.bridge.succeed("status", degraded)
            try expect(f.model.state.balance == nil && !f.model.canSubmitPayment,
                       "Unhealthy status cannot revive a cached balance")
            f.model.refresh()
            var recovered = historyState(pending: false)
            recovered["balance"] = "1.00000000"
            try f.bridge.succeed("refresh", recovered)
            try expect(f.model.canSubmitPayment && f.model.state.balance == "1.00000000",
                       "Successful check restores availability")
            try expect(f.model.preview == nil, "Recovery still requires a fresh payment review")
        }
    }

    @MainActor
    static func testFailedRecoveryKeepsPending() throws {
        let f = Fixture()
        f.model.refreshStatus()
        try f.bridge.succeed("status", historyState(pending: true))
        f.model.recoverPayments()
        try f.bridge.fail("recover_payments", BridgeFailure(code: "network_identity", message: "Synthetic missing node", txid: nil))
        try expectUncertain(f, txid: String(repeating: "d", count: 64))
        try f.bridge.fail("status")
        try expectUncertain(f, txid: String(repeating: "d", count: 64))
        try expect(!f.model.state.networkHealthy && f.model.state.paymentHistory.count == 1,
                   "Unavailable service must retain the payment journal while clearing network proof")
    }

    @MainActor
    static func testConfirmedPaymentWithoutHealthyNetwork() throws {
        for command in ["confirm_send", "faucet"] {
            let f = Fixture()
            try preparePayment(f)
            if command == "confirm_send" { f.model.confirmSend() } else { f.model.faucet() }
            var state = historyState(pending: false)
            state["network_healthy"] = false
            state["balance"] = "12.00000000"
            try f.bridge.succeed(command, ["state": state])
            try expect(!f.model.canSubmitPayment && f.model.state.balance == nil,
                       "Saved confirmation cannot substitute for a successful balance check")
            try expect(f.model.state.paymentHistory.count == 1 && !f.model.paymentUncertain,
                       "A confirmed durable receipt is retained independently of current network health")
            try expect(f.model.notice?.contains("Refresh") == true,
                       "Success with failed balance check must explain the remaining check")
        }
    }

    @MainActor
    static func testLatePreparedPaymentAfterLock() throws {
        let f = Fixture()
        f.model.state.backupVerified = true
        f.model.state.networkRunning = true
        f.model.state.networkHealthy = true
        f.model.recipient = "synthetic recipient"
        f.model.amount = "0.1"
        f.model.prepareSend()
        f.model.lock()
        try f.bridge.succeed("prepare_send", ["preview_id": "synthetic-review-id"])
        try expect(f.model.preview == nil && f.model.isLocked,
                   "A callback from before a manual lock must not restore its discarded review")
        try f.bridge.succeed("lock", Fixture.state(locked: true))
        f.model.confirmSend()
        try expect(f.bridge.count("confirm_send") == 0, "Discarded review cannot be authorized")
    }

    @MainActor
    static func testFreshAvailabilityFailure() throws {
        for code in ["insufficient_funds", "invalid_amount", "invalid_address"] {
            let f = Fixture()
            f.model.state.backupVerified = true
            f.model.state.networkRunning = true
            f.model.state.networkHealthy = true
            f.model.state.balance = "1.00000000"
            f.model.state.immatureBalance = "2.00000000"
            f.model.recipient = "synthetic recipient"
            f.model.amount = "0.1"
            f.model.prepareSend()
            try f.bridge.fail("prepare_send", BridgeFailure(code: code, message: "Synthetic preparation failure", txid: nil))
            try expect(f.model.preview == nil, "Failed preparation cannot expose a payment review")
            if code == "insufficient_funds" {
                try expect(!f.model.state.networkHealthy && !f.model.canSubmitPayment,
                           "Disproved availability must require a fresh network check")
                try expect(f.model.state.balance == nil && f.model.state.immatureBalance == nil,
                           "A competing spend must not leave the previous available balance displayed")
            } else {
                try expect(f.model.state.networkHealthy && f.model.canSubmitPayment,
                           "Harmless input validation must preserve the prior network check")
                try expect(f.model.state.balance == "1.00000000" && f.model.state.immatureBalance == "2.00000000",
                           "Invalid amount or address does not disprove a checked balance")
            }
            try expect(f.bridge.count("confirm_send") == 0 && f.bridge.count("faucet") == 0,
                       "Preparation failure must not submit or fund a payment")
        }
    }

    @MainActor
    static func conflictState(healthy: Bool = true) -> [String: Any] {
        var state = historyState(pending: false)
        state["network_healthy"] = healthy
        state["payment_history"] = [["operation_id": String(repeating: "a", count: 32),
            "txid": String(repeating: "d", count: 64), "kind": "send", "direction": "sent",
            "amount": "0.10000000", "fee": "0.00100000", "status": "conflicted", "confirmed_nodes": 4,
            "conflict": ["txid": String(repeating: "e", count: 64), "block": String(repeating: "f", count: 64),
                         "height": 123, "input": ["txid": String(repeating: "b", count: 64), "vout": 0]]]]
        return state
    }

    @MainActor
    static func testConflictResolutionState() throws {
        let f = Fixture()
        f.model.refreshStatus()
        try f.bridge.succeed("status", historyState(pending: true))
        f.model.recoverPayments()
        try f.bridge.succeed("recover_payments", conflictState())
        try expect(!f.model.paymentUncertain && f.model.pendingTXID == nil && f.model.canSubmitPayment,
                   "Fresh verified conflict permits a separate explicitly reviewed payment")
        try expect(f.model.preview == nil, "Resolving conflict must not recreate the original review")
        try expect(f.bridge.count("prepare_send") == 0 && f.bridge.count("confirm_send") == 0
                   && f.bridge.count("faucet") == 0, "Conflict checks never initiate another payment")
        let payment = f.model.state.paymentHistory[0]
        try expect(PaymentPresentation.statusLabel(payment, networkRunning: true, networkHealthy: true)
            == "Conflicted at last check · another payment spent these coins", "Conflict wording must describe the checked spend")
        try expect(PaymentPresentation.statusLabel(payment, networkRunning: true, networkHealthy: false)
            == "Saved conflict · network needs checking", "Saved conflict cannot claim fresh chain proof")
        try expect(PaymentPresentation.statusLabel(payment, networkRunning: false, networkHealthy: false)
            == "Conflict saved at last check · network stopped", "Offline conflict must retain last-check wording")
    }

    @MainActor
    static func testConflictedReplayError() throws {
        let f = Fixture()
        try preparePayment(f)
        f.model.confirmSend()
        try f.bridge.fail("confirm_send", BridgeFailure(code: "payment_conflicted",
            message: "At the last check, another confirmed payment spent these coins. This original payment will not be submitted again.", txid: nil))
        try expect(f.model.preview == nil && f.model.error?.contains("will not be submitted again") == true,
                   "Original operation replay must show its explicit conflict and discard review")
        try f.bridge.succeed("status", conflictState())
        f.model.confirmSend()
        try expect(f.bridge.count("confirm_send") == 1 && f.bridge.count("faucet") == 0,
                   "A resolved conflict must never retry the old authorization")
    }

    @MainActor
    static func testSavedConflictRevalidation() throws {
        let f = Fixture()
        f.model.refreshStatus()
        try f.bridge.succeed("status", conflictState(healthy: false))
        try expect(!f.model.canSubmitPayment, "Restarted cached conflict alone cannot permit a payment")
        f.model.prepareSend()
        f.model.faucet()
        try expect(f.bridge.count("prepare_send") == 0 && f.bridge.count("faucet") == 0,
                   "Saved conflict waits for a fresh network check")
        f.model.recoverPayments()
        try f.bridge.succeed("recover_payments", historyState(pending: true))
        try expectUncertain(f, txid: String(repeating: "d", count: 64))
        try expect(!f.model.canSubmitPayment, "A reorg that removes conflict proof must restore the outgoing guard")
    }
    private static let changedWalletFailure = BridgeFailure(
        code: "wallet_changed", message: "Synthetic changed selection", txid: nil)

    @MainActor
    static func expectSelectionCleared(_ f: Fixture) throws {
        try expect(!f.model.state.walletOpen && f.model.isLocked,
                   "Changed selection must return to the locked welcome screen")
        try expect(f.model.state.walletPath == nil && f.model.state.address == nil,
                   "Changed selection must remove the previous path and receiving address")
        try expect(f.model.state.balance == nil && f.model.state.immatureBalance == nil,
                   "Changed selection must remove cached balances")
        try expect(f.model.state.paymentHistory.isEmpty && f.model.state.recentPayment == nil,
                   "Changed selection must remove the previous wallet history")
        try expect(!f.model.state.backupVerified && !f.model.state.historyLoaded,
                   "Changed selection must clear verification and loaded-history status")
        try expect(f.model.preview == nil && !f.model.canSubmitPayment,
                   "Changed selection must invalidate payment approval")
        try expect(f.model.pendingTXID == nil && !f.model.paymentUncertain,
                   "An unselected wallet must not display another wallet's pending reference")
        try expect(f.model.passphrase.isEmpty && f.model.confirmation.isEmpty && f.model.recoveryInput.isEmpty,
                   "Changed selection must remove credential inputs")
        try expect(f.model.backupPath.isEmpty && f.model.restorePath.isEmpty && f.model.pendingBackupPath == nil,
                   "Changed selection must remove backup selections")
        try expect(f.model.recipient.isEmpty && f.model.amount.isEmpty && f.model.incomingTransaction.isEmpty,
                   "Changed selection must remove payment form inputs")
        try expect(f.model.sheet == nil && f.model.destination == .wallet,
                   "Changed selection must dismiss the unlock sheet and return home")
        try f.expectNoCode("Changed wallet selection")
        try expect(f.model.error?.contains("Open the wallet file again") == true,
                   "Changed selection must explain the required explicit reopen")
    }

    @MainActor
    static func testWalletChangedUnlock() throws {
        let f = Fixture()
        try preparePayment(f)
        f.model.state.address = "synthetic previous address"
        f.model.state.balance = "1.00000000"
        f.model.state.immatureBalance = "2.00000000"
        f.model.state.historyLoaded = true
        f.model.state.paymentHistory = [["txid": "synthetic prior payment"]]
        f.model.state.recentPayment = ["txid": "synthetic prior payment"]
        f.model.pendingTXID = "synthetic pending reference"
        f.model.paymentUncertain = true
        f.model.backupPath = Fixture.path
        f.model.restorePath = Fixture.path
        f.model.recoveryInput = Fixture.code
        f.model.recoveryCode = Fixture.code
        f.model.incomingTransaction = "synthetic incoming identifier"
        f.model.sheet = .unlock
        f.model.state.locked = true
        f.model.passphrase = "Synthetic test input only"
        f.model.confirmation = "Synthetic test input only"
        f.model.unlock()
        try f.bridge.fail("unlock", changedWalletFailure)
        try expectSelectionCleared(f)
        try expect(f.bridge.count("status") == 1,
                   "Changed unlock selection must request the authoritative empty state")
        try f.bridge.succeed("status", ["wallet_open": false, "locked": true, "network_running": true])
        try expectSelectionCleared(f)
        try expect(f.bridge.count("confirm_send") == 0 && f.bridge.count("faucet") == 0,
                   "Selection cleanup must never authorize a payment")
    }

    @MainActor
    static func testWalletChangedStaleStatus() throws {
        let f = Fixture()
        f.model.refreshStatus()
        f.model.state.locked = true
        f.model.sheet = .unlock
        f.model.passphrase = "Synthetic test input only"
        f.model.unlock()
        try f.bridge.fail("unlock", changedWalletFailure)
        var stale = Fixture.state()
        stale["backup_verified"] = true
        stale["address"] = "synthetic previous address"
        stale["balance"] = "99.00000000"
        stale["network_running"] = true
        stale["network_healthy"] = true
        try f.bridge.succeed("status", stale)
        try expectSelectionCleared(f)
        try f.bridge.succeed("status", ["wallet_open": false, "locked": true])
        try expectSelectionCleared(f)
    }

    @MainActor
    static func testWalletChangedLateReview() throws {
        let f = Fixture()
        f.model.state.backupVerified = true
        f.model.state.networkRunning = true
        f.model.state.networkHealthy = true
        f.model.refreshStatus()
        f.model.recipient = "synthetic recipient"
        f.model.amount = "0.1"
        f.model.prepareSend()
        try f.bridge.fail("status", changedWalletFailure)
        try f.bridge.succeed("prepare_send", ["preview_id": "old review", "amount": "0.1"])
        try expectSelectionCleared(f)
        try expect(!f.model.busy, "Discarded prior selection reply must release the busy indicator")
    }

    @MainActor
    static func testWalletChangedForeground() throws {
        let f = Fixture()
        f.selectBackup()
        try f.completeBackup()
        f.activity.active = false
        f.model.resignActive()
        f.activity.active = true
        f.model.becomeActive()
        try f.bridge.fail("status", changedWalletFailure)
        try expectSelectionCleared(f)
        try expect(f.bridge.count("lock") == 0,
                   "An already-cleared backend selection does not require a new lock request")
    }

    @MainActor
    static func testWalletChangedLateLock() throws {
        let f = Fixture()
        f.model.lock()
        f.model.refreshStatus()
        try f.bridge.fail("status", changedWalletFailure)
        try f.bridge.succeed("lock", Fixture.state(locked: true))
        try expectSelectionCleared(f)
    }

    @MainActor
    static func testWalletChangedExplicitReopen() throws {
        let f = Fixture()
        f.model.refreshStatus()
        try f.bridge.fail("status", changedWalletFailure)
        let nextPath = "/synthetic/second.vault.json"
        f.model.openWallet(nextPath)
        try f.bridge.succeed("open", Fixture.state(locked: true, path: nextPath))
        f.model.passphrase = "Synthetic test input only"
        f.model.unlock()
        var next = Fixture.state(path: nextPath)
        let txid = String(repeating: "bc", count: 32)
        next["backup_verified"] = true
        next["history_loaded"] = true
        next["payment_blocked"] = true
        next["payment_history"] = [["kind": "send", "status": "pending", "txid": txid]]
        next["pending_payment"] = ["kind": "send", "status": "pending", "txid": txid]
        try f.bridge.succeed("unlock", next)
        try expect(f.model.state.walletPath == nextPath && !f.model.isLocked,
                   "Only explicit reopen and unlock may adopt a different selection")
        try expect(f.model.paymentUncertain && f.model.pendingTXID == txid,
                   "Explicit reopen must load the new wallet's unresolved payment")
        try expect(!f.model.canSubmitPayment && f.model.preview == nil,
                   "New wallet pending history must prohibit a new approval")
    }

    private static let resumeOperation = String(repeating: "a", count: 32)
    private static let resumeIdentifier = String(repeating: "e", count: 32)
    private static let resumeTransaction = String(repeating: "b", count: 64)

    @MainActor
    static func resumeState(available: Bool = true, status: String = "pending", kind: String = "send") -> [String: Any] {
        var state = Fixture.state()
        let payment: [String: Any] = [
            "operation_id": resumeOperation, "kind": kind, "status": status,
            "resume_available": available, "txid": resumeTransaction,
            "recipient": "synthetic original recipient", "amount": "0.10000000", "fee": "0.00100000",
        ]
        state["backup_verified"] = true
        state["network_running"] = true
        state["network_healthy"] = true
        state["history_loaded"] = true
        state["payment_blocked"] = status == "pending"
        state["payment_history"] = [payment]
        if status == "pending" { state["pending_payment"] = payment }
        return state
    }

    @MainActor
    static func resumeReview(kind: String = "send") -> [String: Any] {
        ["resume_id": resumeIdentifier, "operation_id": resumeOperation, "kind": kind,
         "txid": resumeTransaction, "recipient": "synthetic original recipient",
         "amount": "0.10000000", "fee": "0.00100000", "expires_in": 120,
         "wallet_debit": kind == "funding" ? "0.00000000" : "0.10100000",
         "wallet_credit": kind == "funding" ? "0.10000000" : "0.00000000",
         "state": resumeState(kind: kind)]
    }

    @MainActor
    static func preparedResume(_ f: Fixture, kind: String = "send") throws {
        f.model.state = WalletState(resumeState(kind: kind))
        f.model.paymentUncertain = true
        f.model.pendingTXID = resumeTransaction
        f.model.prepareResume(resumeOperation)
        try f.bridge.succeed("prepare_resume", resumeReview(kind: kind))
        try expect(f.model.preview?["resume_id"] as? String == resumeIdentifier,
                   "Fresh resume proof must expose a review of the original operation")
    }

    @MainActor
    static func testResumeReview() throws {
        let f = Fixture()
        try preparedResume(f)
        try expect(f.model.canConfirmResume, "Original pending payment may be explicitly resumed after review")
        try expect(!f.model.canSubmitPayment && f.model.paymentUncertain,
                   "Resume review must not unlock ordinary duplicate payment attempts")
        try expect(f.model.preview?["txid"] as? String == resumeTransaction,
                   "Review must retain the original transaction identifier")
        try expect(f.model.destination == .send, "Resume review must open the payment review screen")
        try expect(f.bridge.count("confirm_resume") == 0 && f.bridge.count("confirm_send") == 0,
                   "Preparing a review must never submit or sign a payment")
        f.model.faucet()
        f.model.prepareSend()
        try expect(f.bridge.count("faucet") == 0 && f.bridge.count("prepare_send") == 0,
                   "Ordinary actions remain gated while the original payment is pending")
    }

    @MainActor
    static func testResumeStatusPreservation() throws {
        let f = Fixture()
        try preparedResume(f)
        f.model.refreshStatus()
        try f.bridge.succeed("status", resumeState())
        try expect(f.model.canConfirmResume && f.model.preview != nil,
                   "An unchanged pending status must not erase the explicit resume review")
        for status in ["confirmed", "conflicted", "pending"] {
            try preparedResume(f)
            f.model.refreshStatus()
            try f.bridge.succeed("status", resumeState(available: false, status: status))
            try expect(f.model.preview == nil && !f.model.canConfirmResume,
                       "Changed eligibility must remove the old resume approval")
        }
    }

    @MainActor
    static func testResumeConfirmation() throws {
        let f = Fixture()
        try preparedResume(f)
        f.model.confirmResume()
        try expect(f.model.preview == nil, "Resume approval must be consumed before submission")
        try expect(f.bridge.requests.first(where: { $0.command == "confirm_resume" })?.parameters["resume_id"] as? String == resumeIdentifier,
                   "Only the explicit one-use resume identifier crosses the bridge")
        f.model.confirmResume()
        try expect(f.bridge.count("confirm_resume") == 1, "Repeated clicks must not reuse a consumed review")
        try f.bridge.succeed("confirm_resume", ["payment": ["txid": resumeTransaction],
                                               "state": resumeState(available: false, status: "confirmed")])
        try expect(!f.model.paymentUncertain && f.model.preview == nil,
                   "Confirmed original payment must resolve the journal gate")
        try expect(f.bridge.count("confirm_send") == 0 && f.bridge.count("faucet") == 0,
                   "Resume completion must not create an additional payment")
    }

    @MainActor
    static func testResumeGates() throws {
        for condition in ["legacy", "locked", "stopped", "backup", "incoming"] {
            let f = Fixture()
            var state = resumeState(available: condition != "legacy", kind: condition == "incoming" ? "receive" : "send")
            if condition == "locked" { state["locked"] = true }
            if condition == "stopped" { state["network_running"] = false }
            if condition == "backup" { state["backup_verified"] = false }
            f.model.state = WalletState(state)
            f.model.prepareResume(resumeOperation)
            try expect(f.bridge.count("prepare_resume") == 0,
                       "Ineligible local wallet states must not request resume")
        }
    }

    @MainActor
    static func testLateResumeReview() throws {
        for changed in [false, true] {
            let f = Fixture()
            f.model.state = WalletState(resumeState())
            f.model.paymentUncertain = true
            f.model.prepareResume(resumeOperation)
            if changed {
                f.model.refreshStatus()
                try f.bridge.fail("status", changedWalletFailure)
            } else {
                f.model.lock()
                try f.bridge.succeed("lock", Fixture.state(locked: true))
            }
            try f.bridge.succeed("prepare_resume", resumeReview())
            try expect(f.model.preview == nil && !f.model.canConfirmResume,
                       "Late proof cannot restore approval after locking or changing wallet identity")
        }
    }

    @MainActor
    static func testResumeUncertain() throws {
        let f = Fixture()
        try preparedResume(f)
        f.model.confirmResume()
        try f.bridge.fail("confirm_resume", BridgeFailure(code: "payment_pending", message: "Synthetic pending", txid: resumeTransaction))
        try expect(f.model.paymentUncertain && f.model.pendingTXID == resumeTransaction,
                   "Uncertain resume must retain the original unresolved transaction")
        try expect(f.model.preview == nil && !f.model.canConfirmResume,
                   "Uncertain resume must require another explicit review")
        try f.bridge.succeed("status", resumeState())
        try expect(f.bridge.count("confirm_resume") == 1 && f.bridge.count("prepare_resume") == 1,
                   "Status recovery must not automatically repeat the resume")
    }

    @MainActor
    static func testResumeProofFailure() throws {
        let f = Fixture()
        try preparedResume(f)
        f.model.confirmResume()
        try f.bridge.fail("confirm_resume", BridgeFailure(code: "stale_payment", message: "Synthetic stale proof", txid: nil))
        try expect(f.model.preview == nil && !f.model.state.networkHealthy,
                   "Stale resume proof must invalidate approval and cached health")
        try expect(f.model.paymentUncertain && !f.model.canSubmitPayment,
                   "Resume failure must leave the original duplicate-payment guard in place")
    }

    @MainActor
    static func testResumeTransportLoss() throws {
        for command in ["confirm_send", "confirm_resume", "faucet"] {
            try expect(WalletBridge.transportFailure(for: command).code == "payment_unknown",
                       "Transport loss after payment authorization must report uncertain submission")
        }
        for command in ["prepare_resume", "prepare_send", "status", "recover_payments"] {
            try expect(WalletBridge.transportFailure(for: command).code == "unavailable",
                       "Read-only or preparation transport loss must not invent a payment submission")
        }
        let f = Fixture()
        try preparedResume(f)
        f.model.confirmResume()
        try f.bridge.fail("confirm_resume", WalletBridge.transportFailure(for: "confirm_resume"))
        try f.bridge.fail("status", .unavailable)
        try expect(f.model.paymentUncertain && f.model.pendingTXID == resumeTransaction,
                   "A dead bridge must retain the original transaction ID without relying on a status reply")
        try expect(f.model.preview == nil && !f.model.canSubmitPayment && !f.model.canConfirmResume,
                   "Transport loss must consume approval and keep new payments blocked")
        f.model.confirmResume()
        try expect(f.bridge.count("confirm_resume") == 1 && f.bridge.count("confirm_send") == 0,
                   "Transport loss must not automatically repeat or replace the original payment")
        let fresh = Fixture()
        try preparePayment(fresh)
        fresh.model.confirmSend()
        try fresh.bridge.fail("confirm_send", WalletBridge.transportFailure(for: "confirm_send"))
        try fresh.bridge.fail("status", .unavailable)
        try expect(fresh.model.paymentUncertain && fresh.model.pendingTXID == nil,
                   "A fresh send with no returned transaction ID must remain uncertain without inventing an ID")
        try expect(!fresh.model.canSubmitPayment,
                   "An unknown fresh payment must keep the duplicate-payment guard in place")
    }

    @MainActor
    static func testResumeFunding() throws {
        let f = Fixture()
        try preparedResume(f, kind: "funding")
        try expect(f.model.preview?["kind"] as? String == "funding",
                   "Funding review must retain its distinct direction")
        try expect(f.model.preview?["wallet_debit"] as? String == "0.00000000"
                   && f.model.preview?["wallet_credit"] as? String == "0.10000000",
                   "Original test funding credits this wallet without a wallet debit")
        try expect(f.model.canConfirmResume, "Original test funding may use its existing signed outbox")
    }

}
