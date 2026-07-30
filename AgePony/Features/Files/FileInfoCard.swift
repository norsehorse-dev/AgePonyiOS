//
//  FileInfoCard.swift
//  AgePony
//
//  The summary view shown at the top of the Decrypt flow before the user
//  authorizes the decrypt. Renders what AgeFileInspector returned so the
//  user can verify: "this file is for me, and it's the size I expected,
//  and there are no surprise recipients".
//

import SwiftUI

struct FileInfoCard: View {

    let filename: String
    let summary: AgeFileSummary

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Image(systemName: "doc.text")
                    .foregroundStyle(AgePonyColors.tealCore)
                Text(filename)
                    .font(AgePonyTypography.bodyEmph)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }

            HStack(spacing: 16) {
                metaLabel(title: "Size", value: sizeString)
                metaLabel(title: "Format", value: summary.armored ? "PEM-armored" : "Binary")
                metaLabel(title: "Recipients", value: "\(summary.stanzas.count)")
                Spacer()
            }

            Divider()

            VStack(alignment: .leading, spacing: 10) {
                ForEach(summary.stanzas) { stanza in
                    stanzaRow(stanza)
                }
            }
        }
        .padding(16)
        .background(
            RoundedRectangle(cornerRadius: 14, style: .continuous)
                .fill(AgePonyColors.tealCore.opacity(0.06))
                .overlay(
                    RoundedRectangle(cornerRadius: 14, style: .continuous)
                        .strokeBorder(AgePonyColors.tealCore.opacity(0.18), lineWidth: 1)
                )
        )
    }

    private func metaLabel(title: String, value: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(title)
                .font(AgePonyTypography.caption)
                .foregroundStyle(.secondary)
            Text(value)
                .font(AgePonyTypography.footnote)
                .foregroundStyle(AgePonyColors.tealInk)
        }
    }

    private func stanzaRow(_ s: StanzaSummary) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Image(systemName: iconName(for: s.kind))
                .font(.system(size: 14, weight: .regular))
                .foregroundStyle(AgePonyColors.tealCore)
                .frame(width: 18, alignment: .center)

            VStack(alignment: .leading, spacing: 2) {
                Text(s.kind.displayLabel)
                    .font(AgePonyTypography.footnote)
                    .foregroundStyle(AgePonyColors.tealInk)
                if let factor = s.scryptWorkFactor {
                    // What this file costs to open — a property of the file,
                    // not of this device's setting.
                    Text(ScryptMemory.describe(workFactor: factor)
                         + (ScryptMemory.fits(workFactor: factor)
                            ? "" : " · may not fit in memory right now"))
                        .font(AgePonyTypography.caption)
                        .foregroundStyle(ScryptMemory.fits(workFactor: factor)
                                         ? Color.secondary : Color.orange)
                } else if let matched = s.matchedIdentityName {
                    Text("matches your identity \"\(matched)\"")
                        .font(AgePonyTypography.caption)
                        .foregroundStyle(AgePonyColors.tealCore)
                } else if let tag = s.sshTag {
                    Text("tag: \(tag)")
                        .font(AgePonyTypography.monoCaption)
                        .foregroundStyle(.secondary)
                }
            }

            Spacer()
        }
    }

    private func iconName(for kind: StanzaSummary.Kind) -> String {
        switch kind {
        case .x25519:      return "key.fill"
        case .sshEd25519:  return "lock.shield"
        case .sshRSA:      return "lock.shield"
        case .scrypt:      return "lock.rectangle"
        case .postQuantum: return "atom"
        case .unknown:     return "questionmark.circle"
        }
    }

    private var sizeString: String {
        ByteCountFormatter.string(fromByteCount: Int64(summary.byteCount), countStyle: .file)
    }
}
