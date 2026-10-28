//
//  IdentitiesView.swift
//  AgePony
//
//  Top-level content for the Identities tab. Segmented control switches
//  between the user's own identities (private keys they hold) and
//  recipients (public keys others have given them). Two short labels, so a
//  segmented control still fits in translation (5.1.0, U4); a third choice
//  would move it to a menu.
//
//  The Recipients half is backed by RecipientListView and AddRecipientView. The "+" toolbar item branches by segment:
//  on Identities it presents AddIdentityView, on Recipients it presents
//  AddRecipientView.
//

import SwiftUI

struct IdentitiesView: View {

    let vault: Vault

    @State private var segment: Segment = .identities
    @State private var showingAddIdentity: Bool = false
    @State private var showingAddRecipient: Bool = false

    enum Segment: String, CaseIterable, Identifiable {
        case identities
        case recipients
        var id: String { rawValue }

        var label: LocalizedStringResource {
            switch self {
            case .identities: return "My identities"
            case .recipients: return "Recipients"
            }
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            Picker("Show", selection: $segment) {
                ForEach(Segment.allCases) { s in
                    Text(s.label).tag(s)
                }
            }
            .pickerStyle(.segmented)
            .padding(.horizontal, 16)
            .padding(.top, 8)
            .padding(.bottom, 12)

            switch segment {
            case .identities:
                IdentityListView(vault: vault, onAdd: { showingAddIdentity = true })
            case .recipients:
                RecipientListView(vault: vault, onAdd: { showingAddRecipient = true })
            }
        }
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button {
                    switch segment {
                    case .identities: showingAddIdentity = true
                    case .recipients: showingAddRecipient = true
                    }
                } label: {
                    switch segment {
                    case .identities: Label("Add identity", systemImage: "plus")
                    case .recipients: Label("Add recipient", systemImage: "plus")
                    }
                }
            }
        }
        .sheet(isPresented: $showingAddIdentity) {
            NavigationStack {
                AddIdentityView(vault: vault, onDone: { showingAddIdentity = false })
                    .toolbar {
                        ToolbarItem(placement: .cancellationAction) {
                            Button("Cancel") { showingAddIdentity = false }
                        }
                    }
            }
        }
        .sheet(isPresented: $showingAddRecipient) {
            NavigationStack {
                AddRecipientView(vault: vault, onDone: { showingAddRecipient = false })
            }
        }
    }
}
