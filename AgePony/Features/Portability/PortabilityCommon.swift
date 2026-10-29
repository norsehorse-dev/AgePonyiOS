//
//  PortabilityCommon.swift
//  AgePony
//
//  Pieces shared by Send keys, Receive keys and the paper backup screens (5.0.1).
//
//  OwnerCheck asks the owner to prove it's them before a key leaves the vault, with the
//  same rule as Android's rememberSensitiveConfirm: the app password when it is the only
//  way in (duress set, or no OS lock), otherwise Face ID / Touch ID / the passcode, and the
//  app password when the phone can do neither.
//
//  5.1.0 (E6): `authenticate(_:reason:)` is the same check for the in-app prompts
//  (decrypt, re-encrypt, sign, reveal). In Face ID only mode, when Face ID can't run
//  (nothing enrolled, locked out) it asks for the app password; the passcode stays closed.
//
//  5.1.1: `authenticate` follows `confirm`'s rule, so a password-only vault asks for
//  the app password, never the passcode (L-11). In Face ID only mode, a face or finger
//  enrolled since the vault opened also goes to the app password, with a note (M-3).
//

import SwiftUI
import UIKit
import AgePonyCore

// MARK: - Owner check

@Observable
final class OwnerCheck {

    struct Pending: Identifiable {
        let id = UUID()
        let title: String
        /// Shown above the title, for why the password is asked (5.1.1, M-3).
        var note: String? = nil
        let run: () -> Void
    }

    /// Set while the password sheet is up.
    var pending: Pending?
    /// Why the check failed, for an alert.
    var error: String?
    /// The caller of `authenticate` waiting on the password sheet.
    @ObservationIgnored private var waiting: CheckedContinuation<Bool, Never>?

    /// The in-app prompt (E6): Face ID, Touch ID or the passcode as the lock
    /// mode allows, and in Face ID only mode the app password when Face ID can't
    /// run. Throws what `BiometricGate.authenticate` throws; closing the password
    /// sheet throws `userCancelled`.
    func authenticate(_ vault: Vault, reason: String) async throws {
        // The same rule as `confirm` (5.1.1, L-11): when the password is the only
        // way in, the passcode doesn't stand in for it here either.
        if vault.passwordIsOnlyUnlock {
            guard await askPassword(title: reason, note: nil) else { throw BiometricGateError.userCancelled }
            return
        }
        do {
            try await BiometricGate.authenticate(reason: reason)
        } catch BiometricGateError.unavailable {
            guard BiometricGate.biometryOnly, vault.hasAppPassword else { throw BiometricGateError.unavailable }
            guard await askPassword(title: reason, note: Self.enrolmentNote(vault)) else {
                throw BiometricGateError.userCancelled
            }
        }
    }

    /// The "Face ID changed" note when the prompt just failed for that (5.1.1, M-3).
    private static func enrolmentNote(_ vault: Vault) -> String? {
        guard BiometricGate.takeEnrolmentChangeNotice() else { return nil }
        return BiometricGate.enrolmentChangedText(noun: (vault.unlockSecretKind ?? .password).displayNoun)
    }

    private func askPassword(title: String, note: String?) async -> Bool {
        finishWaiting(false)
        return await withCheckedContinuation { continuation in
            waiting = continuation
            pending = Pending(title: title, note: note, run: { [weak self] in self?.finishWaiting(true) })
        }
    }

    /// Resume a waiting `authenticate`, once. The sheet's dismissal calls this
    /// with false, which does nothing after a success.
    func finishWaiting(_ confirmed: Bool) {
        let continuation = waiting
        waiting = nil
        continuation?.resume(returning: confirmed)
    }

    func confirm(_ vault: Vault, title: String, then run: @escaping () -> Void) {
        if vault.hasAppPassword && vault.passwordIsOnlyUnlock {
            pending = Pending(title: title, run: run)
            return
        }
        Task {
            do {
                try await BiometricGate.authenticate(reason: title)
                run()
            } catch BiometricGateError.unavailable {
                if vault.hasAppPassword {
                    pending = Pending(title: title, note: Self.enrolmentNote(vault), run: run)
                } else {
                    run()
                }
            } catch BiometricGateError.userCancelled {
                // Backed out: nothing happens.
            } catch BiometricGateError.failed(let message) {
                error = message
            } catch {
                self.error = UserMessage.text(for: error, fallback: BiometricGate.didNotConfirmText)
            }
        }
    }
}

extension View {
    /// The password sheet and the error alert that go with an OwnerCheck.
    func ownerCheck(_ check: OwnerCheck, vault: Vault) -> some View {
        modifier(OwnerCheckModifier(check: check, vault: vault))
    }
}

private struct OwnerCheckModifier: ViewModifier {
    @Bindable var check: OwnerCheck
    let vault: Vault

    func body(content: Content) -> some View {
        content
            .sheet(item: $check.pending, onDismiss: { check.finishWaiting(false) }) { pending in
                OwnerPasswordSheet(vault: vault, title: pending.title, note: pending.note) {
                    check.pending = nil
                    pending.run()
                }
            }
            .alert(
                "Couldn't confirm it's you",
                isPresented: Binding(get: { check.error != nil }, set: { if !$0 { check.error = nil } })
            ) {
                Button("OK", role: .cancel) { check.error = nil }
            } message: {
                Text(check.error ?? "")
            }
    }
}

/// Asks for the app password or PIN. Uses the lock screen's attempt counter and backoff.
private struct OwnerPasswordSheet: View {
    let vault: Vault
    let title: String
    let note: String?
    let onSuccess: () -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var secret = ""
    @State private var checking = false
    @State private var message: String?

    private var noun: String { (vault.unlockSecretKind ?? .password).displayNoun }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Group {
                        if vault.unlockSecretKind == .pin {
                            SecureField("PIN", text: $secret)
                                .keyboardType(.numberPad)
                        } else {
                            SecureField("Password", text: $secret)
                        }
                    }
                    .textContentType(.password)
                    .onSubmit(check)
                } footer: {
                    if let message { StatusText(message) }
                    else if let note {
                        VStack(alignment: .leading, spacing: 8) {
                            Text(note)
                            Text(title)
                        }
                    }
                    else { Text(title) }
                }
            }
            .textCase(nil)
            .navigationTitle("Confirm your \(noun)")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Continue", action: check)
                        .disabled(secret.isEmpty || checking)
                }
            }
        }
    }

    private func check() {
        guard !secret.isEmpty, !checking else { return }
        let entered = secret
        secret = ""
        checking = true
        Task {
            defer { checking = false }
            do {
                if try await vault.verifyAppPassword(entered) {
                    onSuccess()
                } else {
                    message = String(localized: "Wrong \(noun).")
                }
            } catch VaultError.lockedOut(let millis) {
                message = UserMessage.lockout(millis: millis)
            } catch {
                message = UserMessage.text(for: error, fallback: String(localized: "Couldn't check the \(noun)."))
            }
        }
    }
}

// MARK: - Rows

/// A tick-box line.
struct CheckLine: View {
    let label: Text
    let checked: Bool
    var enabled: Bool = true
    let onToggle: () -> Void

    /// A label from the string catalog.
    init(label: LocalizedStringKey, checked: Bool, enabled: Bool = true, onToggle: @escaping () -> Void) {
        self.label = Text(label)
        self.checked = checked
        self.enabled = enabled
        self.onToggle = onToggle
    }

    /// A label shown as is, such as a key's name.
    @_disfavoredOverload
    init<S: StringProtocol>(label: S, checked: Bool, enabled: Bool = true, onToggle: @escaping () -> Void) {
        self.label = Text(label)
        self.checked = checked
        self.enabled = enabled
        self.onToggle = onToggle
    }

    var body: some View {
        Button(action: onToggle) {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Image(systemName: checked && enabled ? "checkmark.square.fill" : "square")
                    .foregroundStyle(enabled ? AgePonyColors.accent : .secondary)
                label
                    .foregroundStyle(enabled ? .primary : .secondary)
                    .multilineTextAlignment(.leading)
                Spacer(minLength: 0)
            }
        }
        .buttonStyle(.plain)
        .disabled(!enabled)
        .accessibilityAddTraits(checked && enabled ? .isSelected : [])
    }
}

/// One line under a preview entry; warnings get a warning icon.
struct PreviewNote: Hashable {
    let text: String
    let warning: Bool
}

/// One identity, recipient or signer in the receive preview (audit M-6): name, type and
/// key, notes, and a tick box.
struct PreviewRow: View {
    let title: String
    let detail: String
    let notes: [PreviewNote]
    let checked: Bool
    let enabled: Bool
    let onToggle: () -> Void

    var body: some View {
        Button(action: onToggle) {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Image(systemName: checked && enabled ? "checkmark.square.fill" : "square")
                    .foregroundStyle(enabled ? AgePonyColors.accent : .secondary)
                VStack(alignment: .leading, spacing: 4) {
                    Text(title).font(AgePonyTypography.body)
                    Text(detail)
                        .font(AgePonyTypography.footnote)
                        .foregroundStyle(.secondary)
                    ForEach(notes, id: \.self) { n in
                        if n.warning {
                            Label {
                                Text(n.text)
                            } icon: {
                                Image(systemName: "exclamationmark.triangle.fill")
                                    .foregroundStyle(AgePonyColors.warning)
                            }
                            .font(AgePonyTypography.footnote)
                        } else {
                            Text(n.text)
                                .font(AgePonyTypography.footnote)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
                Spacer(minLength: 0)
            }
            .multilineTextAlignment(.leading)
        }
        .buttonStyle(.plain)
        .disabled(!enabled)
    }
}

/// A short code in large type, for comparing across two screens.
struct BigCode: View {
    let code: String
    /// Base point size; scales with Dynamic Type like the title style.
    @ScaledMetric private var size: CGFloat

    init(code: String, size: CGFloat = 26) {
        self.code = code
        _size = ScaledMetric(wrappedValue: size, relativeTo: .title)
    }

    var body: some View {
        Text(verbatim: code)
            .font(.system(size: size, weight: .semibold, design: .monospaced))
            .frame(maxWidth: .infinity)
            .textSelection(.disabled)
            .accessibilityLabel(code.map { String($0) }.joined(separator: " "))
    }
}

/// A QR code rendered off the main thread, on a white card so it scans in dark mode.
struct AsyncQRImage: View {
    let content: String
    var correctionLevel: String = "M"
    var side: CGFloat = 300

    @State private var image: UIImage?

    var body: some View {
        Group {
            if let image {
                Image(uiImage: image)
                    .interpolation(.none)
                    .resizable()
                    .scaledToFit()
            } else {
                ProgressView()
            }
        }
        .frame(width: side, height: side)
        .padding(12)
        .background(.white)
        .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
        .frame(maxWidth: .infinity)
        .task(id: content) {
            let value = content
            let level = correctionLevel
            image = await withCheckedContinuation { cont in
                DispatchQueue.global(qos: .userInitiated).async {
                    cont.resume(returning: QRCodeView.generate(value, correctionLevel: level))
                }
            }
        }
    }
}

/// A `yyyy-MM-dd` stamp for file names.
func portabilityDateStamp(_ date: Date = Date()) -> String {
    let f = DateFormatter()
    f.locale = Locale(identifier: "en_US_POSIX")
    f.dateFormat = "yyyy-MM-dd"
    return f.string(from: date)
}

/// A file name piece from a key name.
func portabilitySafeFileName(_ name: String) -> String {
    let allowed = Set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
    let mapped = String(name.map { allowed.contains($0) ? $0 : "-" })
    let trimmed = mapped.trimmingCharacters(in: CharacterSet(charactersIn: "-"))
    let cut = String(trimmed.prefix(40))
    return cut.isEmpty ? "key" : cut
}

/// A private folder in tmp for files that hold keys (a transfer, a paper backup PDF),
/// excluded from backups, written with complete file protection. The caller deletes it.
enum PortabilityTemp {
    static func write(_ data: Data, named name: String) throws -> URL {
        var dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("AgePonyKeys-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try? dir.setResourceValues(values)
        let url = dir.appendingPathComponent(name)
        try data.write(to: url, options: [.atomic, .completeFileProtection])
        return url
    }

    /// Delete the folder `write` made for `url`.
    static func remove(_ url: URL?) {
        guard let url else { return }
        try? FileManager.default.removeItem(at: url.deletingLastPathComponent())
    }
}
