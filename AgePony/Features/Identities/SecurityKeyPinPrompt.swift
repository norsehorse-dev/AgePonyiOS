//
//  SecurityKeyPinPrompt.swift
//  AgePony — security-key PIN entry
//
//  A small sheet shown only when a tapped security key reports that it needs its
//  FIDO2 PIN (CTAP error 0x36). Used by both enrolment (GenerateIdentityView)
//  and signing (SignFileView). The parent owns presentation and drives the
//  enrol / sign retry; this view just collects the PIN and reflects an in-flight
//  tap or a wrong-PIN error.
//

import SwiftUI

struct SecurityKeyPinPrompt: View {

    /// Non-nil after a wrong PIN, shown in red.
    let errorText: String?
    /// True while a tap is in progress (disables editing, shows a spinner).
    let submitting: Bool
    let onSubmit: (String) -> Void
    let onCancel: () -> Void

    @State private var pin: String = ""

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    SecureField("PIN", text: $pin)
                        .textContentType(.password)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                        .disabled(submitting)
                } header: {
                    Text("Security key PIN")
                } footer: {
                    if let errorText {
                        Text(errorText).foregroundStyle(.red)
                    } else {
                        Text("Your key's own FIDO2 PIN — the one set on the key itself, not your phone passcode.")
                    }
                }
            }
            .navigationTitle("Enter PIN")
            .navigationBarTitleDisplayMode(.inline)
            .interactiveDismissDisabled(submitting)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel", action: onCancel).disabled(submitting)
                }
                ToolbarItem(placement: .confirmationAction) {
                    if submitting {
                        ProgressView()
                    } else {
                        Button("Continue") { onSubmit(pin) }
                            .disabled(pin.isEmpty)
                    }
                }
            }
        }
    }
}
