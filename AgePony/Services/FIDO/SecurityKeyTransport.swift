//
//  SecurityKeyTransport.swift
//  AgePony — FIDO security-key transport (app target, device-bound)
//
//  Drives an external FIDO2 security key (YubiKey 5 NFC, Token2, ...) over
//  CoreNFC using raw CTAP2-over-NFC APDUs. This is the I/O layer under the pure
//  CTAP2 / CBOR / COSE code in AgePonyCore; it cannot be unit-tested in the
//  package because it needs CoreNFC and a physical key.
//
//  REQUIRED app configuration (without these the tag is never delivered):
//    • Capability "Near Field Communication Tag Reading" on the app target
//      (adds the com.apple.developer.nfc.readersession.formats entitlement).
//    • Info.plist: NFCReaderUsageDescription (the scan-sheet prompt string).
//    • Info.plist: com.apple.developer.nfc.readersession.iso7816.select-identifiers
//      must contain the FIDO applet AID  A0000006472F0001 .  CoreNFC auto-selects
//      it on tap, so the applet is already selected when we get the tag.
//
//  CTAP2-over-NFC framing (FIDO CTAP §8.3):
//    NFCCTAP_MSG        80 10 00 00 <ctap message> Le   — send a request
//    NFCCTAP_GETRESPONSE 80 11 00 00 Le               — poll while processing
//  Status words: 9000 = done (data = [status byte][CBOR]); 9100 = keepalive,
//  poll again. A non-zero CTAP status byte is a device error.
//

import Foundation
#if canImport(CoreNFC)
import CoreNFC

/// FIDO2 / U2F applet AID, used both for the Info.plist select-identifiers list
/// and to confirm CoreNFC selected the right applet.
public let fidoAppletAID = "A0000006472F0001"

public enum SecurityKeyError: Error, LocalizedError {
    case nfcUnavailable
    case wrongAppletSelected(String?)
    case notAnISO7816Tag
    case emptyResponse
    case apduFailed(sw1: UInt8, sw2: UInt8)
    case keepaliveTimedOut
    case ctapError(UInt8)
    case pinAgreementNotP256
    case cancelled

    public var errorDescription: String? {
        switch self {
        case .nfcUnavailable:
            return "NFC isn't available on this device."
        case .wrongAppletSelected(let aid):
            return "The tapped key didn't expose a FIDO applet (got \(aid ?? "none"))."
        case .notAnISO7816Tag:
            return "That tag isn't a security key."
        case .emptyResponse:
            return "The security key returned no data."
        case .apduFailed(let sw1, let sw2):
            return String(format: "The security key reported APDU error %02X%02X.", sw1, sw2)
        case .keepaliveTimedOut:
            return "The security key took too long to respond."
        case .ctapError(let code):
            return SecurityKeyError.ctapMessage(code)
        case .pinAgreementNotP256:
            return "The key returned an unexpected key-agreement type."
        case .cancelled:
            return "Cancelled."
        }
    }

    /// The key is telling us a PIN is required to proceed (CTAP2 PIN_REQUIRED).
    /// The UI uses this to present the PIN prompt and retry.
    public var indicatesPinRequired: Bool {
        if case .ctapError(0x36) = self { return true }
        return false
    }

    /// The supplied PIN was wrong (CTAP2 PIN_INVALID) — re-prompt with an error.
    public var indicatesWrongPin: Bool {
        if case .ctapError(0x31) = self { return true }
        return false
    }

    private static func ctapMessage(_ code: UInt8) -> String {
        switch code {
        case 0x19: return "The operation was denied on the key."
        case 0x27: return "A credential already exists on this key for AgePony."
        case 0x2E: return "This key has no matching credential — is it the right key?"
        case 0x31: return "The PIN was incorrect."
        case 0x32: return "The key's PIN is blocked. Reset the key's FIDO PIN to recover."
        case 0x33: return "PIN authentication failed. Try again."
        case 0x34: return "Too many PIN attempts. Remove and re-tap the key, then try again."
        case 0x35: return "This key has no PIN set."
        case 0x36: return "This key requires its PIN."
        case 0x38: return "The PIN session expired. Try again."
        default:   return String(format: "The security key reported CTAP error 0x%02X.", code)
        }
    }
}

/// A connected channel to a security key. Lives only for the duration of one
/// tap; `sendCTAP` issues one CTAP2 request and returns the CBOR payload.
@available(iOS 13.0, *)
public final class SecurityKeyChannel {
    private let tag: NFCISO7816Tag
    private let maxKeepalivePolls = 60

    init(tag: NFCISO7816Tag) {
        self.tag = tag
    }

    /// Send one CTAP2 request (command byte + CBOR, as built by CTAP2) and
    /// return the response CBOR (status byte stripped). Handles the 9100
    /// keepalive loop. Throws SecurityKeyError on a bad status word or a
    /// non-zero CTAP status byte.
    public func sendCTAP(_ request: Data) async throws -> Data {
        // NFCCTAP_MSG: 80 10 00 00 <request> Le(extended)
        var (data, sw1, sw2) = try await exchange(
            ins: 0x10, data: request
        )

        var polls = 0
        while sw1 == 0x91 && sw2 == 0x00 {
            polls += 1
            if polls > maxKeepalivePolls { throw SecurityKeyError.keepaliveTimedOut }
            // NFCCTAP_GETRESPONSE: 80 11 00 00 Le(extended), no data.
            (data, sw1, sw2) = try await exchange(ins: 0x11, data: Data())
        }

        guard sw1 == 0x90 && sw2 == 0x00 else {
            throw SecurityKeyError.apduFailed(sw1: sw1, sw2: sw2)
        }
        guard let status = data.first else { throw SecurityKeyError.emptyResponse }
        guard status == 0x00 else { throw SecurityKeyError.ctapError(status) }
        return Data(data.dropFirst())
    }

    /// One APDU exchange, with a single automatic retry on a transient NFC
    /// transceive glitch. A dropped tag response (the "Tag response error"
    /// CoreNFC reports when a single transceive fails while the key is still in
    /// the field) very often succeeds immediately on a second attempt — common
    /// on the extra round-trips a PIN/UV operation adds. Non-transient errors
    /// and bad status words propagate unchanged.
    private func exchange(ins: UInt8, data: Data) async throws -> (Data, UInt8, UInt8) {
        do {
            return try await transceive(ins: ins, data: data)
        } catch let e as NFCReaderError where SecurityKeyChannel.isTransientTransceiveError(e) {
            // Let the field settle briefly, then try once more.
            try? await Task.sleep(nanoseconds: 60_000_000)
            return try await transceive(ins: ins, data: data)
        }
    }

    private static func isTransientTransceiveError(_ e: NFCReaderError) -> Bool {
        switch e.code {
        case .readerTransceiveErrorTagResponseError,
             .readerTransceiveErrorTagConnectionLost:
            return true
        default:
            return false
        }
    }

    private func transceive(ins: UInt8, data: Data) async throws -> (Data, UInt8, UInt8) {
        let apdu = NFCISO7816APDU(
            instructionClass: 0x80,
            instructionCode: ins,
            p1Parameter: 0x00,
            p2Parameter: 0x00,
            data: data,
            expectedResponseLength: 65536
        )
        return try await withCheckedThrowingContinuation { cont in
            tag.sendCommand(apdu: apdu) { respData, s1, s2, error in
                if let error = error {
                    cont.resume(throwing: error)
                } else {
                    cont.resume(returning: (respData, s1, s2))
                }
            }
        }
    }
}

/// One-shot NFC session: present the scan sheet, wait for a security key tap,
/// run `body` against the connected channel, then close the session.
@available(iOS 13.0, *)
public final class SecurityKeyTransport: NSObject, NFCTagReaderSessionDelegate {

    private var session: NFCTagReaderSession?
    private var connectContinuation: CheckedContinuation<NFCISO7816Tag, Error>?
    private let alertMessage: String
    private let queue = DispatchQueue(label: "app.agepony.securitykey.nfc")

    private init(alertMessage: String) {
        self.alertMessage = alertMessage
    }

    public static func run<T>(
        alertMessage: String,
        body: @escaping (SecurityKeyChannel) async throws -> T
    ) async throws -> T {
        guard NFCTagReaderSession.readingAvailable else {
            throw SecurityKeyError.nfcUnavailable
        }
        let transport = SecurityKeyTransport(alertMessage: alertMessage)
        let tag = try await transport.beginAndConnect()
        do {
            let channel = SecurityKeyChannel(tag: tag)
            let result = try await body(channel)
            transport.end(message: nil)
            return result
        } catch {
            transport.end(error: error)
            throw error
        }
    }

    private func beginAndConnect() async throws -> NFCISO7816Tag {
        try await withCheckedThrowingContinuation { cont in
            self.connectContinuation = cont
            let session = NFCTagReaderSession(pollingOption: .iso14443, delegate: self, queue: queue)
            session?.alertMessage = alertMessage
            self.session = session
            session?.begin()
        }
    }

    private func end(message: String?) {
        if let message = message { session?.alertMessage = message }
        session?.invalidate()
        session = nil
    }

    private func end(error: Error) {
        session?.invalidate(errorMessage: (error as? LocalizedError)?.errorDescription ?? "Failed.")
        session = nil
    }

    // MARK: NFCTagReaderSessionDelegate

    public func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {}

    public func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
        if let cont = connectContinuation {
            connectContinuation = nil
            let readerError = error as? NFCReaderError
            if readerError?.code == .readerSessionInvalidationErrorUserCanceled {
                cont.resume(throwing: SecurityKeyError.cancelled)
            } else {
                cont.resume(throwing: error)
            }
        }
    }

    public func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        guard let first = tags.first, case let .iso7816(iso) = first else {
            session.invalidate(errorMessage: "That isn't a security key.")
            resumeConnect(throwing: SecurityKeyError.notAnISO7816Tag)
            return
        }
        session.connect(to: first) { [weak self] error in
            guard let self = self else { return }
            if let error = error {
                session.invalidate(errorMessage: "Couldn't connect to the key.")
                self.resumeConnect(throwing: error)
                return
            }
            // CoreNFC auto-selected the AID from select-identifiers; confirm it.
            let aid = iso.initialSelectedAID
            guard aid.uppercased() == fidoAppletAID.uppercased() else {
                session.invalidate(errorMessage: "That key has no FIDO applet.")
                self.resumeConnect(throwing: SecurityKeyError.wrongAppletSelected(aid))
                return
            }
            self.resumeConnect(returning: iso)
        }
    }

    private func resumeConnect(returning tag: NFCISO7816Tag) {
        guard let cont = connectContinuation else { return }
        connectContinuation = nil
        cont.resume(returning: tag)
    }

    private func resumeConnect(throwing error: Error) {
        guard let cont = connectContinuation else { return }
        connectContinuation = nil
        cont.resume(throwing: error)
    }
}
#endif
