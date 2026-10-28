//
//  FileInfoSection.swift
//  AgePony
//
//  What AgeFileInspector found in an age file or armored block, as Form rows
//  (5.1.0, UI plan U4): name, size and format, then one row per recipient
//  stanza, so the person can check "this file is for me, it's the size I
//  expected, and there are no surprise recipients" before decrypting.
//
//  Used by Decrypt, Inspect and Re-encrypt for files and by Decrypt text. It
//  is two Form sections, so it goes directly inside a Form.
//

import SwiftUI

struct FileInfoSection: View {

    /// The file's name, or nil for pasted text.
    let filename: String?
    let summary: AgeFileSummary

    var body: some View {
        Section {
            if let filename {
                LabeledContent("Name") {
                    Text(filename)
                        .font(AgePonyTypography.monoSmall)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
            }
            LabeledContent("Size", value: sizeString)
            if summary.armored {
                LabeledContent("Format", value: String(localized: "PEM-armored"))
            } else {
                LabeledContent("Format", value: String(localized: "Binary"))
            }
        } header: {
            if filename == nil {
                Text("Details")
            } else {
                Text("File")
            }
        }

        Section {
            ForEach(summary.stanzas) { stanza in
                stanzaRow(stanza)
            }
        } header: {
            Text("Recipients")
        }
    }

    private func stanzaRow(_ s: StanzaSummary) -> some View {
        Label {
            VStack(alignment: .leading, spacing: 4) {
                Text(s.kind.displayLabel)
                if let factor = s.scryptWorkFactor {
                    // What this file costs to open: a property of the file,
                    // not of this device's setting.
                    if ScryptMemory.fits(workFactor: factor) {
                        Text(ScryptMemory.describe(workFactor: factor))
                            .font(AgePonyTypography.footnote)
                            .foregroundStyle(.secondary)
                    } else {
                        StatusText("\(ScryptMemory.describe(workFactor: factor)). It may not fit in memory right now.", kind: .warning)
                            .font(AgePonyTypography.footnote)
                    }
                } else if let matched = s.matchedIdentityName {
                    StatusText("Matches your identity \"\(matched)\"", kind: .success)
                        .font(AgePonyTypography.footnote)
                } else if let tag = s.sshTag {
                    HStack(spacing: 4) {
                        Text("Tag")
                            .font(AgePonyTypography.footnote)
                        Text(tag)
                            .font(AgePonyTypography.monoCaption)
                    }
                    .foregroundStyle(.secondary)
                }
            }
        } icon: {
            Image(systemName: iconName(for: s.kind))
                .foregroundStyle(.secondary)
        }
    }

    private func iconName(for kind: StanzaSummary.Kind) -> String {
        switch kind {
        case .x25519:      return "key"
        case .sshEd25519:  return "lock.shield"
        case .sshRSA:      return "lock.shield"
        case .scrypt:      return "lock.rectangle"
        case .postQuantum: return "atom"
        case .yubikey:     return "key"
        case .tag:         return "cpu"
        case .tagPQ:       return "cpu"
        case .signature:   return "signature"
        case .unknown:     return "questionmark.circle"
        }
    }

    private var sizeString: String {
        ByteCountFormatter.string(fromByteCount: Int64(summary.byteCount), countStyle: .file)
    }
}
