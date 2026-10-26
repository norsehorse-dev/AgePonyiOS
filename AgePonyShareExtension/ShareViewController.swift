//
//  ShareViewController.swift
//  AgePonyShareExtension
//
//  Hotfix 6 on 1g: reverses the order of completeRequest and openURL.
//
//  Previous hotfixes (1-5) all tried: perform openURL first, then call
//  completeRequest (with various delays and via different APIs). None
//  of those caused AgePony to actually launch. iOS appears to defer
//  URL launches while a share extension is still presenting — the
//  launch is queued but not executed, and is discarded when the
//  extension tears down.
//
//  The pattern that production iOS 17/18 share extensions converged
//  on: completeRequest FIRST, then in its completion handler (which
//  fires AFTER the extension UI dismisses) perform openURL via the
//  responder chain. By that point iOS has shifted contexts and is
//  willing to route the URL to the host app.
//
//  Self is captured strongly in the completion closure so the
//  responder chain doesn't collapse out from under us before the
//  openURL fires.
//

import UIKit
import UniformTypeIdentifiers

class ShareViewController: UIViewController {

    private let appURLScheme = "agepony"

    override func viewDidLoad() {
        super.viewDidLoad()
        setupBackground()
        setupSpinner()
    }

    override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)
        Task { await processSharedItems() }
    }

    // MARK: - UI

    private func setupBackground() {
        let layer = CAGradientLayer()
        layer.colors = [
            UIColor(red: 0x38/255, green: 0xCF/255, blue: 0xE8/255, alpha: 1).cgColor,
            UIColor(red: 0x14/255, green: 0xB8/255, blue: 0xB0/255, alpha: 1).cgColor,
            UIColor(red: 0x0E/255, green: 0x7D/255, blue: 0x7A/255, alpha: 1).cgColor
        ]
        layer.startPoint = CGPoint(x: 0, y: 0)
        layer.endPoint = CGPoint(x: 1, y: 1)
        layer.frame = view.bounds
        view.layer.insertSublayer(layer, at: 0)
        layer.needsDisplayOnBoundsChange = true
        layer.actions = ["bounds": NSNull()]
        gradientLayer = layer
    }

    private var gradientLayer: CAGradientLayer?

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        gradientLayer?.frame = view.bounds
    }

    private func setupSpinner() {
        let stack = UIStackView()
        stack.axis = .vertical
        stack.spacing = 16
        stack.alignment = .center
        stack.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(stack)

        NSLayoutConstraint.activate([
            stack.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            stack.centerYAnchor.constraint(equalTo: view.centerYAnchor)
        ])

        let spinner = UIActivityIndicatorView(style: .large)
        spinner.color = .white
        spinner.startAnimating()
        stack.addArrangedSubview(spinner)

        // Renamed from "Opening AgePony…" to avoid confusion with
        // AgePony's own launch screen (which looks visually similar).
        let label = UILabel()
        label.text = "Preparing share…"
        label.textColor = .white
        label.font = .systemFont(ofSize: 17, weight: .medium)
        stack.addArrangedSubview(label)
    }

    // MARK: - Payload extraction + redirect

    private func processSharedItems() async {
        do {
            let payload = try await extractPayload()
            let url = try buildShareURL(for: payload)

            await MainActor.run {
                self.completeAndLaunch(url: url)
            }
        } catch {
            await MainActor.run {
                showError(error)
            }
        }
    }

    /// completeRequest first, then in its completion handler — after
    /// iOS has dismissed the extension UI and shifted contexts —
    /// perform openURL via the responder chain. This is the order that
    /// production iOS 17/18 share extensions use successfully.
    ///
    /// Note: we capture `self` strongly in the completion closure so
    /// the responder chain remains valid for the brief moment between
    /// extension dismissal and process teardown.
    private func completeAndLaunch(url: URL) {
        guard let context = self.extensionContext else { return }

        context.completeRequest(returningItems: []) { _ in
            // This closure fires on the main thread after iOS has
            // dismissed the extension UI. The extension process is
            // still alive at this point; the responder chain rooted
            // at self should still resolve.
            self.performResponderChainOpenURL(url)
        }
    }

    /// Walk the responder chain to the host UIApplication and ask it to open
    /// `url`. iOS 18 stopped honouring the old `openURL:` selector, so the
    /// current `openURL:options:completionHandler:` is tried first. If neither
    /// launches AgePony, the payload stays staged and the app picks it up the
    /// next time it comes to the front (5.0.1).
    @discardableResult
    private func performResponderChainOpenURL(_ url: URL) -> Bool {
        let modern = sel_registerName("openURL:options:completionHandler:")
        let legacy = sel_registerName("openURL:")
        var responder: UIResponder? = self
        while let r = responder {
            if r.responds(to: modern) {
                typealias OpenFn = @convention(c) (AnyObject, Selector, NSURL, NSDictionary, Any?) -> Void
                let fn = unsafeBitCast(r.method(for: modern), to: OpenFn.self)
                fn(r, modern, url as NSURL, NSDictionary(), nil)
                return true
            }
            if r.responds(to: legacy) {
                _ = r.perform(legacy, with: url)
                return true
            }
            responder = r.next
        }
        return false
    }

    private func buildShareURL(for payload: SharedPayload) throws -> URL {
        var components = URLComponents()
        components.scheme = appURLScheme
        components.host = "share"
        components.queryItems = [URLQueryItem(name: "token", value: payload.token)]
        guard let url = components.url else {
            throw ShareError.urlConstructionFailed
        }
        return url
    }

    /// Stage the first usable attachment. A file (anything that came with a file
    /// URL, or isn't text) is copied file to file; text from a text-only share
    /// goes in the manifest. Direction comes from the content, not the name.
    private func extractPayload() async throws -> SharedPayload {
        guard let extensionItem = extensionContext?.inputItems.first as? NSExtensionItem,
              let attachments = extensionItem.attachments,
              !attachments.isEmpty else {
            throw ShareError.noInput
        }

        for provider in attachments {
            let isFile = provider.hasItemConformingToTypeIdentifier(UTType.fileURL.identifier)
                || provider.hasItemConformingToTypeIdentifier("org.age-encryption.age")
            let isText = provider.hasItemConformingToTypeIdentifier(UTType.plainText.identifier)
                || provider.hasItemConformingToTypeIdentifier(UTType.text.identifier)

            if isText && !isFile, let text = try? await loadText(from: provider) {
                return try SharedContainer.writeTextPayload(text: text)
            }
            if let type = fileTypeIdentifier(of: provider) {
                return try await stageFile(from: provider, typeIdentifier: type)
            }
        }

        throw ShareError.unsupportedInput
    }

    /// The registered type to ask for as a file: the age UTI if offered, else
    /// the first type that is data.
    private func fileTypeIdentifier(of provider: NSItemProvider) -> String? {
        if provider.hasItemConformingToTypeIdentifier("org.age-encryption.age") { return "org.age-encryption.age" }
        return provider.registeredTypeIdentifiers.first { id in
            guard let t = UTType(id) else { return false }
            return t.conforms(to: .data) && !t.conforms(to: .url)
        }
    }

    /// Copy the shared file into the App Group without reading it into memory
    /// (L-25). `loadFileRepresentation` hands over a file that is deleted when
    /// its handler returns, so the copy happens inside the handler.
    private func stageFile(from provider: NSItemProvider, typeIdentifier: String) async throws -> SharedPayload {
        try await withCheckedThrowingContinuation { continuation in
            _ = provider.loadFileRepresentation(forTypeIdentifier: typeIdentifier) { url, error in
                guard let url else {
                    continuation.resume(throwing: error ?? ShareError.unsupportedInput)
                    return
                }
                do {
                    let name = provider.suggestedName.map { name -> String in
                        // suggestedName can drop the extension; keep the file's own.
                        let ext = url.pathExtension
                        return ext.isEmpty || (name as NSString).pathExtension.lowercased() == ext.lowercased()
                            ? name : name + "." + ext
                    } ?? url.lastPathComponent
                    continuation.resume(returning: try SharedContainer.writeFilePayload(
                        sourceFileURL: url, originalFilename: name))
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    /// Text shares are capped: anything bigger belongs in a file.
    private static let maxTextBytes = 4 * 1024 * 1024

    private func loadText(from provider: NSItemProvider) async throws -> String {
        let type = provider.hasItemConformingToTypeIdentifier(UTType.plainText.identifier)
            ? UTType.plainText.identifier : UTType.text.identifier
        return try await withCheckedThrowingContinuation { continuation in
            provider.loadItem(forTypeIdentifier: type, options: nil) { item, error in
                if let error = error {
                    continuation.resume(throwing: error)
                    return
                }
                if let text = item as? String {
                    continuation.resume(returning: text)
                    return
                }
                if let attr = item as? NSAttributedString {
                    continuation.resume(returning: attr.string)
                    return
                }
                if let data = item as? Data, data.count <= Self.maxTextBytes {
                    continuation.resume(returning: String(decoding: data, as: UTF8.self))
                    return
                }
                continuation.resume(throwing: ShareError.unsupportedInput)
            }
        }
    }

    // MARK: - Errors

    private enum ShareError: Error {
        case noInput
        case unsupportedInput
        case urlConstructionFailed
    }

    private func showError(_ error: Error) {
        let message: String
        if let e = error as? ShareError {
            switch e {
            case .noInput:               message = "Nothing was shared."
            case .unsupportedInput:      message = "AgePony can't accept that kind of share."
            case .urlConstructionFailed: message = "Couldn't construct the AgePony URL."
            }
        } else if let e = error as? SharedContainerError {
            switch e {
            case .containerUnavailable:  message = "App Group container is unavailable. Reinstall may be required."
            case .writeFailed(let m):    message = "Couldn't write the shared payload: \(m)"
            case .readFailed(let m):     message = "Couldn't read the shared payload: \(m)"
            case .malformedManifest:     message = "Shared payload is malformed."
            case .unknownToken:          message = "Shared payload not found."
            }
        } else {
            message = error.localizedDescription
        }

        let alert = UIAlertController(title: "Share failed", message: message, preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: "OK", style: .default) { [weak self] _ in
            self?.extensionContext?.completeRequest(returningItems: [], completionHandler: nil)
        })
        present(alert, animated: true)
    }
}
