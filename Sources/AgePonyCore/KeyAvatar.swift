//
//  KeyAvatar.swift
//  AgePonyCore
//
//  Deterministic avatar derivation for an identity or recipient. age keys are
//  opaque `age1...` strings, so two entries are hard to tell apart at a glance.
//  The avatar gives each a stable visual fingerprint: initials from the name,
//  on a two-tone disc whose hue is derived from the key material. Same key, same
//  hue, every time; a rename keeps the hue; two keys that share initials still
//  differ by hue.
//
//  This is the pure derivation (hue + initials); the SwiftUI drawing lives in
//  the app's `KeyAvatarView`. The algorithm mirrors Android's `KeyAvatar.kt`
//  (32-bit FNV-1a over the seed, hue = hash % 360), so for key types whose
//  stored bytes are identical across platforms (X25519, post-quantum, YubiKey),
//  the same key draws the same hue on iOS and Android.
//

import Foundation

public enum KeyAvatar {

    /// Hue in degrees [0, 360) derived from a stable per-key seed. Use the
    /// base64 of the public key material as the seed to match Android.
    public static func hue(seed: String) -> Int {
        Int(fnv1a(seed) % 360)
    }

    /// Up to two initials from the display name (whitespace-split, uppercased).
    /// Mirrors the Android/desktop rule.
    public static func initials(name: String) -> String {
        let words = name.split(whereSeparator: { $0.isWhitespace }).map(String.init)
        switch words.count {
        case 0:  return "?"
        case 1:  return String(words[0].prefix(2)).uppercased()
        default: return (String(words[0].prefix(1)) + String(words[1].prefix(1))).uppercased()
        }
    }

    /// 32-bit FNV-1a over the seed's UTF-8 bytes. Deterministic.
    static func fnv1a(_ s: String) -> UInt32 {
        var h: UInt32 = 2166136261
        for b in s.utf8 {
            h ^= UInt32(b)
            h = h &* 16777619
        }
        return h
    }
}
