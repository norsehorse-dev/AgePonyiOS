//
//  TempFileCleanup.swift
//  AgePony
//
//  Sweeps leftover files from the app's temporary directory (4.0.0). Large-file
//  encrypt/decrypt flows write their output to the temporary directory and
//  normally clean it up, but an interrupted run or a share that was never
//  completed can leave files behind. The Settings "Clear temporary files" button
//  reclaims that space on demand.
//

import Foundation

enum TempFileCleanup {

    /// Remove every item in the app's temporary directory. Returns the number of
    /// bytes freed. Identities, recipients, and notes live in Application Support
    /// and the Keychain, not here, so they are never touched.
    @discardableResult
    static func sweepAll() -> Int64 {
        let fm = FileManager.default
        let tmp = fm.temporaryDirectory
        var freed: Int64 = 0
        guard let items = try? fm.contentsOfDirectory(
            at: tmp,
            includingPropertiesForKeys: [.totalFileAllocatedSizeKey]
        ) else {
            return 0
        }
        for url in items {
            let size = (try? url.resourceValues(forKeys: [.totalFileAllocatedSizeKey]))?
                .totalFileAllocatedSize ?? 0
            if (try? fm.removeItem(at: url)) != nil {
                freed += Int64(size)
            }
        }
        return freed
    }

    /// Remove the folders that hold key material on its way out (a key transfer, a paper
    /// backup PDF, 5.0.1). Run on lock, so a file the user never shared doesn't outlive
    /// the session.
    static func sweepKeyFiles() {
        sweep(prefixes: ["AgePonyKeys-"])
    }

    /// Folders that can hold plaintext: decrypt output and FileSigner output
    /// (`AgePonyShare-`), batch output, flattened packages, Shortcuts staging, and
    /// exported signers (5.1.1, M-2).
    static let sessionPrefixes = [
        "AgePonyShare-",
        "AgePonyBatch-",
        "AgePonyFlatten-",
        "AgePonyIntent-",
        "AgePonySigners-",
    ]

    /// Remove the `sessionPrefixes` folders. Run at launch, for what a killed run
    /// left behind, and on lock, once the screens that showed them have closed
    /// (5.1.1, M-2). Shares in `IncomingShare` are left to SharedContainer.
    ///
    /// The lock sweep passes `includingIntents: false`: a Shortcut can run while
    /// the app is in the background, and its own cleanup removes its folder.
    static func sweepSessionFiles(includingIntents: Bool = true) {
        sweep(prefixes: includingIntents ? sessionPrefixes : sessionPrefixes.filter { $0 != "AgePonyIntent-" })
    }

    /// Remove the items directly in `directory` (the app's tmp by default) whose
    /// name starts with one of `prefixes`. Nothing else is touched.
    static func sweep(prefixes: [String], in directory: URL? = nil) {
        let fm = FileManager.default
        let dir = directory ?? fm.temporaryDirectory
        guard let items = try? fm.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil) else {
            return
        }
        for url in items {
            let name = url.lastPathComponent
            if prefixes.contains(where: { name.hasPrefix($0) }) {
                try? fm.removeItem(at: url)
            }
        }
    }
}
