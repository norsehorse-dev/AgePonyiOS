//
//  VerifiedBadge.swift
//  AgePony
//
//  Visual badge for a verification outcome, mirroring the verified-signer
//  badge in PGPony. Three states:
//
//    • trusted: valid and signed by one of your identities or trusted signers (green)
//    • valid, unknown: cryptographically valid, key not in the vault (orange)
//    • invalid: bad signature, wrong namespace, or not a signature (red)
//

import SwiftUI

struct VerifiedBadge: View {

    let result: FileVerificationResult

    /// Rows for a Form section: the verdict (icon and word in the status
    /// colour), what it means, then the signer's key (5.1.0, UI plan U4).
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label {
                Text(title)
                    .font(AgePonyTypography.headline)
            } icon: {
                Image(systemName: iconName)
                    .foregroundStyle(tint)
            }
            Text(subtitle)
                .font(AgePonyTypography.subheadline)
                .foregroundStyle(.secondary)
        }
        .padding(.vertical, 4)

        if keyDetail != nil, let kt = result.signerKeyType {
            LabeledContent("Key type", value: kt)
        }
        if let detail = keyDetail {
            LabeledContent("Fingerprint") {
                Text(detail)
                    .font(AgePonyTypography.monoSmall)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
        }
    }

    // MARK: - State mapping

    private var iconName: String { result.trust.iconName }
    private var tint: Color { result.trust.tint }
    private var title: String { result.trust.title }

    private var subtitle: String {
        switch result.trust {
        case .trusted(let name, let isOwn):
            if isOwn {
                return String(localized: "Signed by your identity \"\(name)\". The file hasn't changed since it was signed.")
            }
            return String(localized: "Signed by \"\(name)\". The file hasn't changed since it was signed.")
        case .validUnknownKey:
            if let name = result.untrustedSignerName {
                return String(localized: "The signature is valid and the key is your trusted signer \"\(name)\", but this signature doesn't meet that entry. \(result.untrustedReason ?? "")")
            }
            return String(localized: "The signature is mathematically valid, but the signing key isn't one of your identities or trusted signers. Add it as a trusted signer to recognize this signer next time.")
        case .invalid(let reason):
            return reason
        }
    }

    private var keyDetail: String? {
        switch result.trust {
        case .invalid: return nil
        default:       return result.signerFingerprint
        }
    }
}

// MARK: - Shared mapping

/// One place where a trust outcome becomes an icon, a colour and a word.
///
/// Two screens show signatures now -- the standalone verify flow, and decrypt,
/// where a signed bundle's verdict appears alongside the decrypted file. They must
/// not be able to drift into disagreeing about what red means.
extension SignatureTrust {
    var iconName: String {
        switch self {
        case .trusted:         return "checkmark.seal.fill"
        case .validUnknownKey: return "checkmark.shield"
        case .invalid:         return "xmark.seal.fill"
        }
    }

    var tint: Color {
        switch self {
        case .trusted:         return AgePonyColors.success
        case .validUnknownKey: return AgePonyColors.warning
        case .invalid:         return AgePonyColors.destructive
        }
    }

    var title: String {
        switch self {
        case .trusted:         return String(localized: "Verified")
        case .validUnknownKey: return String(localized: "Valid, unknown signer")
        case .invalid:         return String(localized: "Not verified")
        }
    }

    /// A failed signature: its one-line summary takes the red too, not just the
    /// icon (5.1.1, L-3).
    var isFailure: Bool {
        if case .invalid = self { return true }
        return false
    }

    /// One line, for use beside something else rather than as the headline.
    var summaryLine: String {
        switch self {
        case .trusted(let name, let isOwn):
            if isOwn {
                return String(localized: "Signed by you (\(name))")
            }
            return String(localized: "Signed by \(name)")
        case .validUnknownKey:
            return String(localized: "Signed, but by a key you don't know")
        case .invalid:
            return String(localized: "Signature didn't check out")
        }
    }
}

/// A one-row signature verdict, for screens whose headline is something else
/// (the decrypted file). Goes inside a Form section.
struct CompactVerifiedBadge: View {

    let result: FileVerificationResult

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Label {
                if result.trust.isFailure {
                    Text(result.trust.summaryLine)
                        .foregroundStyle(result.trust.tint)
                        .fontWeight(.semibold)
                } else {
                    Text(result.trust.summaryLine)
                }
            } icon: {
                Image(systemName: result.trust.iconName)
                    .foregroundStyle(result.trust.tint)
            }
            if case .invalid(let reason) = result.trust {
                Text(reason)
                    .font(AgePonyTypography.footnote)
                    .foregroundStyle(.secondary)
            } else if let name = result.untrustedSignerName {
                Text("Your trusted signer \"\(name)\" doesn't vouch for this one. \(result.untrustedReason ?? "")")
                    .font(AgePonyTypography.footnote)
                    .foregroundStyle(.secondary)
            } else if let fingerprint = result.signerFingerprint {
                Text(fingerprint)
                    .font(AgePonyTypography.monoCaption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
            if let note = result.note {
                Text(note)
                    .font(AgePonyTypography.footnote)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(.vertical, 4)
    }
}

// MARK: - Decrypt headline

/// The headline over a decrypted result. A failed signature changes it, so a
/// forged file never sits under a plain green "Decrypted" (5.1.1, L-3).
enum DecryptHeadline {

    static func text(for signature: FileVerificationResult?) -> String {
        if signature?.trust.isFailure == true {
            return String(localized: "Decrypted, signature failed")
        }
        return String(localized: "Decrypted")
    }

    static func kind(for signature: FileVerificationResult?) -> StatusText.Kind {
        signature?.trust.isFailure == true ? .failure : .success
    }
}

/// `DecryptHeadline` as a status line.
struct DecryptHeadlineText: View {

    let signature: FileVerificationResult?

    var body: some View {
        StatusText(DecryptHeadline.text(for: signature), kind: DecryptHeadline.kind(for: signature), verdict: true)
    }
}
