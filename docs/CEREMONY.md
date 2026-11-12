# Ceremony checklist

Five custodians. Threshold 3. One dealer. One witness. Follow this page in order. The witness reads each step aloud. The dealer types only what this page says. Anyone in the room may say stop. A stop ends the ceremony. Do not resume a stopped ceremony on the same secret. Generate a new secret, or destroy the partial shares and start this page again from the beginning.

This page is 3 of 5, every weight 1. Do not pass `--weight` or `--quorum`. A policy that uses either one is `docs/CEREMONY-POLICY.md`. Do not mix the two pages. Do not copy a flag from that page onto this command.

This checklist accepts the limits in `THREAT_MODEL.md`. It does not remove them. The dealer machine sees the secret. The tests are not an audit. `shamirs` 0.7.0 is pinned and unaudited. A YubiKey write cannot be undone.

## Roles

Write these names on paper before the day. Do not change them in the room.

| Role | Duty | Must not |
| --- | --- | --- |
| Witness | Reads this page. Watches the screen. Holds the paper record. | Type. Hold a share. Be a custodian. |
| Dealer | Types the commands the witness reads. | Hold a share afterward. Leave with the secret. |
| Custodian 1 through 5 | Receives one share and leaves with only that share. | Hold a second share. Learn another custodian's password or PIN. |

The witness and the dealer are not custodians. If a named person is absent, stop.

## Roster, filled before the day

Copy this table onto paper. The witness brings the paper. It does not go into a ticket, a chat, or a photo.

| Item | Value |
| --- | --- |
| Secret name, not the secret | |
| Why this secret exists | |
| Custodian 1, city, share form (YubiKey or file) | |
| Custodian 2, city, share form | |
| Custodian 3, city, share form | |
| Custodian 4, city, share form | |
| Custodian 5, city, share form | |
| Sealed copy A location | |
| Sealed copy B location | |
| `agree` binary hash the group agreed to run | |
| Object id, the same on every YubiKey | `5fff21` |

Object ids below `5fff20` are refused unless `--force` is passed. Do not pass `--force` to reach a certificate slot. `5fff21` is the object this checklist uses. One object per key. One share per key.

A file share is allowed only if that row was marked "file" before the day. Do not convert a YubiKey row to a file in the room.

## Days before

Each YubiKey custodian does this alone, on their own token, before they travel.

1. Confirm the token is the one they will carry. Run `agree devices` with only that token plugged in. Write the serial on their row of the roster. Unplug it.
2. Change the PIV PIN. It must not be `123456`. The PIV PIN is not the FIDO2 PIN.
3. Change the PIV PUK. It must not be `12345678`. Store the PUK somewhere that is not the same envelope as the share. A lost PUK plus a blocked PIN means that share is dead. That is acceptable. Three other shares still open the secret.
4. Change the management key. It must not be the factory 24 bytes. Firmware 5.7 and later uses AES-192. Older firmware uses 3DES. The length is 24 bytes either way, entered as 48 hex characters. Store the new management key with the PUK, not with the share.
5. Do not put the PIN, PUK, or management key in a password manager that the other custodians can read.

The witness confirms, on the day, that every YubiKey row has a serial and that nobody is using the factory PIN. The witness does not collect the PINs.

## Room

1. One machine. No network. Wireless off. No phone in the room. No camera.
2. The witness and the dealer are both present before the secret is brought in.
3. The `agree` binary is the one whose hash is on the roster. The witness reads the hash from the paper. The dealer computes it and shows the screen. If they differ, stop.
4. Run `agree` with no arguments, or `agree split --help`, only to confirm it starts. Do not pass `--debug`.
5. If the process prints `could not disable core dumps`, stop. `split` and `restore` exit with `mlock failed` if the data key cannot be locked. That happens before any prompt and before the secret is read. If you see that error, stop. Do not continue on this machine.
6. Custodians enter one at a time only when their step says so. They do not watch another custodian's PIN or password.

## Confirm the secret

1. The dealer shows that this secret opens the data it is supposed to open. Use the check the group named before the day. Do not invent one in the room.
2. The secret is a file on this machine, mode `0600`, named on the roster. It is not in a chat and not on a command line.
3. The witness watches the dealer run `shasum -a 256` on that file, or the group's agreed fingerprint command. Both write the fingerprint on the paper. They will compare it after the test restore.

## List the tokens

Do this with one YubiKey plugged in at a time. Unplug it before the next.

```bash
agree devices
```

The witness checks that the printed serial matches that custodian's row. A line looks like `yubikey:SERIAL  version …  reader …`. If two keys are plugged in, unplug one. Do not guess which serial is which.

No PIN is required for this command. Nothing is written.

## Split

The dealer types this command and no other. Substitute the real serials from the roster. Keep file shares first and YubiKey shares last. If every share is a YubiKey, there are five `--share yubikey:SERIAL/5fff21` arguments and no file arguments.

Do not add `--key-file`. Do not add `--management-key`. Do not add `--debug`. Do not add `--force` unless a stopped earlier attempt left an object and the witness has agreed that this is a new split overwriting that object.

```bash
agree split \
  --threshold 3 \
  --sealed sealed.bin \
  --share yubikey:SERIAL1/5fff21 \
  --share yubikey:SERIAL2/5fff21 \
  --share yubikey:SERIAL3/5fff21 \
  --share yubikey:SERIAL4/5fff21 \
  --share yubikey:SERIAL5/5fff21 \
  --protect \
  < secret-file
```

For a row marked file, that one `--share` is a new file name instead of `yubikey:`. Example: `--share custodian3.share`. Do not point two shares at the same path. Do not point a share at `sealed.bin`.

What the tool will do, in order:

1. Warn if the threshold is 1. This checklist uses 3. There must be no such warning.
2. Ask for each YubiKey, one at a time: insert that serial, press Enter, enter that key's PIN, enter that key's management key twice. An empty management key uses the factory key. Do not leave it empty. The witness stops the ceremony if the dealer accepts an empty management key.
3. Ask for a password per share. For a YubiKey share, the custodian presses Enter for an empty password. The PIN is the binding. For a file share, that custodian types a long password, confirms it, and writes it only on paper they keep. They do not say it aloud. They do not reuse another custodian's password.
4. Read the secret from stdin only after those prompts finish.
5. Write the shares, then the sealed file.
6. Print a summary on stderr. It includes the share count, the threshold, the key size, the group id, and the sealed path. It does not include the secret.

The witness copies the group id onto the paper. Every custodian copies that same group id onto their label. If the summary does not say threshold 3 and 5 shares, stop. Do not use those shares.

If the command fails after any YubiKey was written, stop. Those objects are live shares of a split you are discarding. Do not mix them with a later split. Overwrite them only as destruction, with a new split and `--force`, or leave them and treat that token as burned for this secret. File shares from the failed command are removed by the tool. A YubiKey object is not.

## Check each share

Each custodian, one at a time:

1. Confirms the file mode of a file share is `0600`, or that their YubiKey is the one just written.
2. Reads the share header far enough to see the group id. They do not need to understand the body.
3. Confirms the group id matches the paper.
4. Labels the token or envelope with the group id, their name, and "1 of 5, threshold 3". The label does not contain the secret, the PIN, the password, or the management key.
5. Leaves the room with only their share. They do not photograph it.

The witness does not let two custodians leave together with two shares.

## Test restore

Still on the dealer machine. The secret file is still there. Pick custodians 1, 2, and 3. Any other trio is also valid. Do not restore with fewer than three.

Bring those three shares back. The other two stay out of the room.

```bash
agree restore \
  --sealed sealed.bin \
  --share SHARE1 \
  --share SHARE2 \
  --share SHARE3 \
  > restored.bin
```

`SHARE` is the file name or `yubikey:SERIAL/5fff21`. Stdout must be the redirect. If the tool refuses because stdout is a terminal, the redirect was missed. Stop and do not retry by printing the secret on the screen.

The tool asks for each YubiKey PIN when it needs it. It does not ask for the management key to read. A file share with a password is prompted on the terminal. An empty password for a protected file share is rejected.

The witness and the dealer then:

```bash
cmp secret-file restored.bin && shasum -a 256 restored.bin
```

`cmp` must print nothing and exit 0. The fingerprint must match the paper. If either check fails, stop. Do not distribute the shares from this split.

## Destroy the dealer copies

1. The witness watches the dealer overwrite `secret-file` and `restored.bin`, then remove them. On a magnetic disk with no snapshots, `shred -u` or three overwrites of the same blocks is enough. Disk destruction is not required.
2. On an SSD, or on APFS, that overwrite does not hit the old pages. Wear leveling and copy-on-write keep them. Shred is not the control there. Full-disk encryption is. FileVault must have been on before the secret was written. Power the machine off so the secret is not still in memory. Do not destroy the disk for this reason.
3. A snapshot defeats both. If Time Machine, an APFS local snapshot, or any other snapshot ran while the secret file existed, shredding the file does nothing to the snapshot. Delete that snapshot before anyone leaves, or the disk stays in the vault. Destruction is only for a disk that was not encrypted, or whose snapshot you cannot delete.
4. There is no `--key-file` to destroy. If one was passed despite this checklist, stop. That copy is a way in without the shares. Overwrite it the same way as the secret. A token that can generate the same bytes again is the same failure.
5. Shell history must not contain the secret or a management key. This checklist never puts them on a command line. The witness looks at the history. If they are there, stop. Overwrite is not available for a history line that was already synced. Treat that machine as the snapshot case in step 3.

## Sealed copies

1. Copy `sealed.bin` to location A and location B from the roster. These copies are not shares. They are useless without three shares. They must still exist on the day of a restore.
2. The witness confirms both copies have the same fingerprint as the dealer `sealed.bin` before the dealer copy is removed.
3. Remove the dealer `sealed.bin` only after both copies match. Overwrite it first, under the same rule as the secret. The sealed file is not the secret, but it is the ciphertext those shares open.
4. Do not store a sealed copy in the same safe as three shares.

## After the room

| Rule | Check |
| --- | --- |
| No custodian holds two shares | Witness |
| No site holds three shares | Witness, from the roster cities |
| Sealed copies are in two places, with the encrypted data and apart from three shares | Named owners of location A and B |
| PINs and file-share passwords are not in a shared note | Each custodian |
| Management keys are not in the share envelope | Each YubiKey custodian |
| The paper roster is stored with the witness, not with a share | Witness |

A successor does not receive a forwarded share. Succession is a new split after a restore, or a planned rotation while three current custodians are still available.

## Open, later

Three custodians, the witness, and a dealer. Not the same machine as the everyday laptop if that can be avoided. The same abort rules apply. If core dumps could not be disabled, or the command exits with `mlock failed`, stop and move to a machine where they do not.

```bash
agree restore \
  --sealed sealed.bin \
  --share SHARE1 \
  --share SHARE2 \
  --share SHARE3 \
  > restored-secret
```

Write down, on paper, why the secret was restored, which data was opened, and which three shares were used. Copy out only what the incident needs. Do not put the restored secret in a password manager, a ticket, or a sync folder.

Then overwrite and remove `restored-secret` under the same rule as the deal. If that machine was untrusted, or the secret was copied, rotate: new secret, re-encrypt the data, new split, destroy the old sealed copies only after the new split has passed its own test restore. Until that re-encryption, the old shares still open the old secret. Deleting share files is not rotation.

Any other trio works. One damaged extra share can make a larger set fail. On a recovery day, retry with a different set of exactly three.

## Stop conditions

Stop, do not improvise, if any of these happen:

- A named person is absent.
- The binary hash does not match the roster.
- Core dumps could not be disabled, or the command exits with `mlock failed`.
- Two YubiKeys are plugged in and the serials were not already written on the roster.
- Anyone proposes `--key-file`, `--management-key`, `--debug`, or `--force` without a burned object from a stopped attempt.
- The management-key prompt is answered empty.
- The summary is not 5 shares, threshold 3.
- A custodian's group id does not match the paper.
- `cmp` fails, or the restored fingerprint does not match.
- The command fails after a YubiKey write. Those objects are live. Start over with a new secret or a deliberate destruction, not a partial reuse.
- The secret or a management key appears on a command line or in a chat.

A stopped ceremony does not have a quorum. Destroy the partial shares you can destroy. Treat written YubiKey objects as live until overwritten by a finished new split or destroyed on purpose.
