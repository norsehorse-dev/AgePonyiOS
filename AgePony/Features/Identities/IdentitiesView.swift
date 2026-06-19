//
//  IdentitiesView.swift
//  AgePony
//
//  Top-level content for the Identities tab. Segmented control switches
//  between the user's own identities (private keys they hold) and
//  recipients (public keys others have given them).
//
//  In 1e the Recipients half is real — backed by RecipientListView and
//  the new AddRecipientView. The "+" toolbar item branches by segment:
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
        case identities = "My Identities"
        case recipients = "Recipients"
        var id: String { rawValue }
    }

    var body: some View {
        VStack(spacing: 0) {
            Picker("", selection: $segment) {
                ForEach(Segment.allCases) { s in
                    Text(s.rawValue).tag(s)
                }
            }
            .pickerStyle(.segmented)
            .padding(.horizontal, 16)
            .padding(.top, 8)
            .padding(.bottom, 12)

            switch segment {
            case .identities:
                IdentityListView(vault: vault)
            case .recipients:
                RecipientListView(vault: vault)
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
                    Image(systemName: "plus")
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
