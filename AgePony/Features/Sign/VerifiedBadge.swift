//
//  VerifiedBadge.swift
//  AgePony
//
//  Visual badge for a verification outcome, mirroring the verified-signer
//  badge in PGPony. Three states:
//
//    • trusted        — valid + signed by a known identity/recipient (teal)
//    • valid, unknown — cryptographically valid, key not in the vault (amber)
//    • invalid        — bad signature / wrong namespace / not a signature
//                       (the brand's "danger" magenta, kept off red on purpose)
//

import SwiftUI

struct VerifiedBadge: View {

    let result: FileVerificationResult

    var body: some View {
        VStack(spacing: 14) {
            Image(systemName: iconName)
                .font(.system(size: 56, weight: .regular))
                .foregroundStyle(tint)

            Text(title)
                .font(AgePonyTypography.title)
                .multilineTextAlignment(.center)

            Text(subtitle)
                .font(AgePonyTypography.footnote)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 32)

            if let detail = keyDetail {
                VStack(spacing: 4) {
                    if let kt = result.signerKeyType {
                        Text(kt)
                            .font(AgePonyTypography.caption)
                            .foregroundStyle(.secondary)
                    }
                    Text(detail)
                        .font(AgePonyTypography.monoCaption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .padding(.horizontal, 32)
                }
                .padding(.top, 4)
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
            return isOwn
                ? "Signed by your identity \"\(name)\". The file hasn't changed since it was signed."
                : "Signed by \"\(name)\". The file hasn't changed since it was signed."
        case .validUnknownKey:
            return "The signature is mathematically valid, but the signing key isn't one of your identities or saved recipients. Add it as a recipient to recognize this signer next time."
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
        case .trusted:         return AgePonyColors.tealCore
        case .validUnknownKey: return .orange
        case .invalid:         return AgePonyColors.destructive
        }
    }

    var title: String {
        switch self {
        case .trusted:         return "Verified"
        case .validUnknownKey: return "Valid, unknown signer"
        case .invalid:         return "Not verified"
        }
    }

    /// One line, for use beside something else rather than as the headline.
    var summaryLine: String {
        switch self {
        case .trusted(let name, let isOwn):
            return isOwn ? "Signed by you (\(name))" : "Signed by \(name)"
        case .validUnknownKey:
            return "Signed, but by a key you don't know"
        case .invalid:
            return "Signature didn't check out"
        }
    }
}

/// A one-line signature verdict, for screens whose headline is something else.
struct CompactVerifiedBadge: View {

    let result: FileVerificationResult

    var body: some View {
        VStack(spacing: 4) {
            Label(result.trust.summaryLine, systemImage: result.trust.iconName)
                .font(AgePonyTypography.footnote)
                .foregroundStyle(result.trust.tint)
                .multilineTextAlignment(.center)
            if case .invalid(let reason) = result.trust {
                Text(reason)
                    .font(AgePonyTypography.caption)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            } else if let fingerprint = result.signerFingerprint {
                Text(fingerprint)
                    .font(AgePonyTypography.monoCaption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
        }
        .padding(.horizontal, 32)
    }
}
