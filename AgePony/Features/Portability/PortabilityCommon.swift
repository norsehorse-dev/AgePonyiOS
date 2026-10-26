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

import SwiftUI
import UIKit
import AgePonyCore

// MARK: - Owner check

@Observable
final class OwnerCheck {

    struct Pending: Identifiable {
        let id = UUID()
        let title: String
        let run: () -> Void
    }

    /// Set while the password sheet is up.
    var pending: Pending?
    /// Why the check failed, for an alert.
    var error: String?

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
                    pending = Pending(title: title, run: run)
                } else {
                    run()
                }
            } catch BiometricGateError.userCancelled {
                // Backed out: nothing happens.
            } catch BiometricGateError.failed(let message) {
                error = message
            } catch {
                self.error = error.localizedDescription
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
            .sheet(item: $check.pending) { pending in
                OwnerPasswordSheet(vault: vault, title: pending.title) {
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
    let onSuccess: () -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var secret = ""
    @State private var checking = false
    @State private var message: String?

    private var noun: String { vault.unlockSecretKind == .pin ? "PIN" : "password" }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    SecureField(noun == "PIN" ? "PIN" : "Password", text: $secret)
                        .textContentType(.password)
                        .keyboardType(vault.unlockSecretKind == .pin ? .numberPad : .default)
                        .onSubmit(check)
                } footer: {
                    if let message { Text(message).foregroundStyle(.red) }
                    else { Text(title) }
                }
            }
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
                    message = "Wrong \(noun)."
                }
            } catch VaultError.lockedOut(let millis) {
                message = UnlockAttempts.lockoutMessage(millis: millis)
            } catch {
                message = "Couldn't check the \(noun)."
            }
        }
    }
}

// MARK: - Rows

/// A tick-box line.
struct CheckLine: View {
    let label: String
    let checked: Bool
    var enabled: Bool = true
    let onToggle: () -> Void

    var body: some View {
        Button(action: onToggle) {
            HStack(alignment: .firstTextBaseline, spacing: 10) {
                Image(systemName: checked && enabled ? "checkmark.square.fill" : "square")
                    .foregroundStyle(enabled ? AgePonyColors.tealCore : .secondary)
                Text(label)
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

/// One line under a preview entry; warnings show in red.
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
            HStack(alignment: .top, spacing: 10) {
                Image(systemName: checked && enabled ? "checkmark.square.fill" : "square")
                    .foregroundStyle(enabled ? AgePonyColors.tealCore : .secondary)
                    .padding(.top, 2)
                VStack(alignment: .leading, spacing: 3) {
                    Text(title).font(AgePonyTypography.bodyEmph)
                    Text(detail)
                        .font(AgePonyTypography.monoCaption)
                        .foregroundStyle(.secondary)
                    ForEach(notes, id: \.self) { n in
                        Text(n.text)
                            .font(AgePonyTypography.caption)
                            .foregroundStyle(n.warning ? Color.red : Color.secondary)
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
    var size: CGFloat = 26

    var body: some View {
        Text(code)
            .font(.system(size: size, weight: .bold, design: .monospaced))
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
