//
//  NetworkSettingsView.swift
//  AgePony
//
//  Proxy settings for the one network call AgePony makes: the GitHub key fetch
//  under Add Recipient (4.0.0). Off (direct) or a custom HTTP proxy. iOS
//  URLSession cannot route SOCKS, so this is HTTP-proxy only. Reached from
//  Settings.
//

import SwiftUI
import AgePonyCore

struct NetworkSettingsView: View {

    let vault: Vault

    enum Choice: String, CaseIterable, Identifiable {
        case off, custom
        var id: String { rawValue }
    }

    @State private var choice: Choice
    @State private var host: String
    @State private var port: String
    @State private var username: String
    @State private var password: String

    init(vault: Vault) {
        self.vault = vault
        let c = vault.proxyConfig
        _choice   = State(initialValue: c.mode == .off ? .off : .custom)
        _host     = State(initialValue: c.host)
        _port     = State(initialValue: c.port == 0 ? "" : String(c.port))
        _username = State(initialValue: c.username ?? "")
        _password = State(initialValue: c.password ?? "")
    }

    var body: some View {
        Form {
            Section {
                Picker("Route key fetch through", selection: $choice) {
                    Text("Off (direct)").tag(Choice.off)
                    Text("HTTP proxy").tag(Choice.custom)
                }
                .onChange(of: choice) { _, _ in save() }
            } header: {
                Text("Network")
            } footer: {
                Text("Routes the one network call, the GitHub key fetch, through an HTTP proxy. Everything else in AgePony is already offline.")
            }

            if choice == .custom {
                Section {
                    TextField("Host", text: $host)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .onChange(of: host) { _, _ in save() }
                    TextField("Port", text: $port)
                        .keyboardType(.numberPad)
                        .onChange(of: port) { _, _ in save() }
                    TextField("Username (optional)", text: $username)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .onChange(of: username) { _, _ in save() }
                    SecureField("Password (optional)", text: $password)
                        .onChange(of: password) { _, _ in save() }
                } header: {
                    Text("HTTP proxy")
                } footer: {
                    Text("Your own HTTP or HTTPS proxy. A username and password are sent as proxy authentication if the proxy asks for them. If the proxy is unreachable the fetch fails rather than falling back to a direct connection. iOS cannot route a SOCKS proxy, so reaching Tor here means pointing at an HTTP proxy that fronts it.")
                }
            }
        }
        .textCase(nil)
        .navigationTitle("Network")
        .navigationBarTitleDisplayMode(.inline)
    }

    private func save() {
        let config: ProxyConfig
        switch choice {
        case .off:
            config = .direct
        case .custom:
            config = ProxyConfig(
                mode: .http,
                host: host.trimmingCharacters(in: .whitespaces),
                port: Int(port) ?? 0,
                username: username.isEmpty ? nil : username,
                password: password.isEmpty ? nil : password
            )
        }
        vault.proxyConfig = config
    }
}
