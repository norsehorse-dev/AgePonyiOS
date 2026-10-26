# AgePony 5.0.1 for iPhone

This catches the iPhone app up with AgePony 5.0.1 on Android in one release, so both carry
the same number and the same formats. iPhone skips 5.0.0: everything from both Android
releases is here at once. That means keys in hardware, keys you can move to another phone or
put on paper, signed files that plain age can read, and every fix from the security audit of
both apps. None of it breaks the age format or your existing files, keys or vault.

## Added

- **Hardware decryption keys.** Identities > Generate new identity > Hardware key makes a P-256 key
  inside this iPhone's Secure Enclave. It's published as an age 1.3 `age1tag1...` recipient,
  so the age command line (1.3 or later) can encrypt to your phone with no plugin. The
  quantum-safe form, `age1tagpq1...`, adds ML-KEM-768 held in your vault on top of the
  hardware half. You can require Face ID for each decrypt. The private key can't be shown,
  sent or backed up, and it's gone if the iPhone is erased or replaced.
- **Encrypt to age 1.3 tag recipients.** Paste an `age1tag1...` or `age1tagpq1...` key as a
  recipient, which covers newer age-plugin-yubikey, age-plugin-se and age-plugin-tpm keys.
- **Decrypt with a YubiKey.** Import the `AGE-PLUGIN-YUBIKEY-1...` line from
  age-plugin-yubikey and tap the YubiKey once so AgePony can read the key in that slot.
  After that, files encrypted to it (older `piv-p256` and newer `p256tag`) decrypt over NFC
  with a tap, plus the PIN when the slot asks for it.
- **Move keys to another phone.** Settings > Send keys / Receive keys, between iPhones or
  between an iPhone and Android. The receiving phone shows a one-time post-quantum key as a
  QR code, the sending phone encrypts your identities, recipients and trusted signers to it,
  and both screens show the same short code so you can check you scanned the right phone.
  On the same Wi-Fi (or one phone on the other's hotspot) the keys go straight across.
  The QR code carries the receiving phone's address, so nothing scans the network, and only
  encrypted data crosses it. Without shared Wi-Fi there's a file route instead. Before
  anything is imported, both phones show a transfer code over exactly what was sent, and
  Import stays off until you confirm they match. Trusted signers have to be ticked one by
  one, and nothing you receive becomes your active key on its own. Hardware keys stay on
  the phone they were made on.
- **Paper backup.** Open an age identity and tap Paper backup for a printable PDF with a QR
  code and the text. By default the page is protected with a passphrase and is itself an
  ordinary age file, so it restores in AgePony (Settings > Restore from a paper backup) or
  with `age -d` on a computer.
- **Passphrase work without unlocking.** The lock screen has Continue without unlocking for
  encrypting or decrypting text with a passphrase and decrypting passphrase files. The vault
  stays locked. A share that arrives while AgePony is locked gets the same option.
- **Also encrypt to.** Settings can tick a saved recipient on every encrypt by default, so a
  file you encrypt to this iPhone's hardware key can still be opened if the phone is lost.

## Changed

- **Signed files are plain age files.** Sign-and-encrypt to a key used to wrap the file and
  its signature together, so `age -d` gave back the wrapper instead of your file. The
  signature now travels in an extra, encrypted stanza in the age header that plain age
  ignores. It covers the file and who it was encrypted to, so a signed file can't be
  re-addressed and still show as signed. Passphrase files keep the wrapper, now in a form
  whose signature also covers the file name. Files signed by earlier versions still verify,
  with a note on what their signature doesn't cover. Files signed on Android 5.0.1 verify
  here and the other way round.
- **Saved recipients aren't trusted signers any more.** A signature verifies as trusted only
  when the key is one of your identities or a trusted signer you added.
- **Software keys are tried before hardware keys,** so a file you can open with a normal key
  opens with it, and a YubiKey tap is only asked for when nothing else can open the file.
- **Help and Security pages** cover hardware keys, moving keys, paper backups and the duress
  password.

## Fixed

- **Duress password could be skipped.** With a duress password set, the lock screen still
  offered Face ID, which opened the real vault. Setting a duress password now makes the
  vault password-only. Face ID comes back if you remove it.
- **The vault was in iPhone backups.** An iCloud or computer backup held the
  password-wrapped vault key, which could be guessed at offline. The vault is now kept out
  of backups, and the password key is tied to a secret that never leaves this iPhone.
- **"No lock" with a password kept an unprotected copy of the key.** With No lock and an
  app password, a copy of the vault key sat in the Keychain with nothing in front of it.
  The password is now the only way in, as Settings said.
- **Password and PIN are harder to guess.** Wrong attempts now cost a wait: 30 seconds after
  5 tries, doubling up to an hour, and it survives restarts. There's an optional setting to
  erase the vault after 10 wrong attempts. New PINs need at least 6 digits and new passwords
  at least 8 characters. Existing shorter ones keep working.
- **Auto-lock** now counts time correctly while the phone sleeps and locks when the screen
  locks.
- **App switcher and screen recording.** Sheets showing keys or decrypted text could show in
  the app switcher. The privacy cover now sits above everything, and the screen is covered
  while it's being recorded or mirrored.
- **Setup on an iPhone with no passcode** stopped on "KeychainError error 0". It now says
  why Face ID can't be used and offers an AgePony password or PIN instead.
- **Security-key signatures require a touch,** as OpenSSH does.
- **Stricter file parsing.** AgePony reads age headers as strictly as the reference age tool
  and refuses crafted files that tried to exhaust memory or hang the app.
- **Shared files are cleaned up.** Copies made by the share extension and decrypted files
  that were never saved are deleted, and the duress wipe clears them too.
- Smaller fixes: proxy passwords moved to the Keychain. Weakening the lock asks you to
  confirm first. Autocorrect no longer learns from notes and text you encrypt, and
  third-party keyboards are blocked in the app. Paper backups warn about short passphrases.

Everything still runs on your device. No tracking, no ads.
