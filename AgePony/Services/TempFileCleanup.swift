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
        let fm = FileManager.default
        guard let items = try? fm.contentsOfDirectory(at: fm.temporaryDirectory, includingPropertiesForKeys: nil) else {
            return
        }
        for url in items where url.lastPathComponent.hasPrefix("AgePonyKeys-") {
            try? fm.removeItem(at: url)
        }
    }
}
