import XCTest
@testable import AgePonyCore

final class BlowfishTests: XCTestCase {
    /// Standard Blowfish key schedule = `initState + expand0State(key)`.
    /// Matches OpenBSD's `blf_key()`.
    private func standardKeySchedule(_ key: Data) -> BlowfishState {
        var state = BlowfishState()
        Blowfish.expand0State(&state, key: key)
        return state
    }

    /// Encipher a single 8-byte block as a convenience for KAT checks.
    private func encryptBlock(_ state: BlowfishState, plaintext: Data) -> Data {
        precondition(plaintext.count == 8)
        var l: UInt32 = (UInt32(plaintext[0]) << 24) | (UInt32(plaintext[1]) << 16)
                      | (UInt32(plaintext[2]) <<  8) |  UInt32(plaintext[3])
        var r: UInt32 = (UInt32(plaintext[4]) << 24) | (UInt32(plaintext[5]) << 16)
                      | (UInt32(plaintext[6]) <<  8) |  UInt32(plaintext[7])
        Blowfish.encipher(state, &l, &r)
        var out = Data(count: 8)
        out[0] = UInt8((l >> 24) & 0xff); out[1] = UInt8((l >> 16) & 0xff)
        out[2] = UInt8((l >>  8) & 0xff); out[3] = UInt8( l        & 0xff)
        out[4] = UInt8((r >> 24) & 0xff); out[5] = UInt8((r >> 16) & 0xff)
        out[6] = UInt8((r >>  8) & 0xff); out[7] = UInt8( r        & 0xff)
        return out
    }

    /// Eric Young variable-key KAT: key=zeros_8, plaintext=zeros_8 → ciphertext = 4ef997456198dd78
    func testKAT_allZeros() {
        let key = Data(repeating: 0, count: 8)
        let pt  = Data(repeating: 0, count: 8)
        let state = standardKeySchedule(key)
        let ct = encryptBlock(state, plaintext: pt)
        XCTAssertEqual(ct.map { String(format: "%02x", $0) }.joined(),
                       "4ef997456198dd78")
    }

    /// streamToWord reads 4 BE bytes from data, wrapping around when offset exceeds count.
    func testStreamToWord_wraparound() {
        let data = Data([0x01, 0x02, 0x03])
        var offset = 0
        let word = Blowfish.streamToWord(data, offset: &offset)
        // bytes: 01 02 03 01 (wrap to first byte for the 4th)
        XCTAssertEqual(word, 0x01020301)
        // offset advanced 4 times: 0→1, 1→2, 2→3→(wrap to 0)→1
        XCTAssertEqual(offset, 1)
    }

    func testStreamToWord_basic() {
        let data = Data([0xde, 0xad, 0xbe, 0xef, 0x55])
        var offset = 0
        let w1 = Blowfish.streamToWord(data, offset: &offset)
        XCTAssertEqual(w1, 0xdeadbeef)
        XCTAssertEqual(offset, 4)
    }

    /// State should start identical to the pi constants after init.
    func testInitState_matchesPiConstants() {
        let state = BlowfishState()
        XCTAssertEqual(state.P[0], 0x243f6a88)
        XCTAssertEqual(state.P[17], 0x8979fb1b)
        XCTAssertEqual(state.S[0][0], 0xd1310ba6)
        XCTAssertEqual(state.S[3][255], 0x3ac372e6)
        XCTAssertEqual(state.P.count, 18)
        XCTAssertEqual(state.S.count, 4)
        for box in state.S { XCTAssertEqual(box.count, 256) }
    }
}
