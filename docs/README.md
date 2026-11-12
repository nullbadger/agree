# agree

`agree` splits a secret so that a quorum of shares can restore it, and a set that misses a quorum cannot. The secret may be any length: a signing key, a backup key, a passphrase file, or a larger blob. Split reads that secret only from stdin. Restore writes it only to stdout. The shares themselves stay small, small enough to write to a file, a raw device node, or a YubiKey PIV data object.

This is a break-glass tool. It does not sign, and it does not keep a quorum on later use of the secret. A set that meets every quorum reconstructs the original bytes on one machine. After that restore, those bytes are an ordinary secret again. The quorum exists only until someone reconstructs it, and only for as long as that reconstruction is wiped.

For a signing key that unlocks data which must otherwise stay inaccessible, use 3 of 5. Any two shares are not enough. Two shares can be lost, or two people can be unavailable, and the remaining three can still open it. A 2-of-5 split is a different policy: any pair owns the secret. Threshold 1 is not a quorum at all, and the tool warns when you ask for it. A weight, or a second quorum, is the same split with a different rule. It is described below. It is not what this paragraph recommends.

## What you are enforcing

Five people, threshold 3, means any three of them can reconstruct the secret. It does not mean a designated three, and it does not notify the other two. It also does not mean three files. A share file that is not wrapped to a person is just a file. Anyone who copies three unprotected share files meets the threshold without the people.

Optional per-share passwords, and writing a share onto a YubiKey, are how a share stays bound to a holder. They do not add a second approval system. They raise the cost of stealing a share.

## Quorums

`--threshold` is one quorum, and every share has weight 1. That is 3 of 5. Any three shares open it. It does not matter which three. The checklist for that policy is `docs/CEREMONY.md`.

A weight is how many Shamir points of that quorum's pad go into one share file. It is not a label checked after the fact. A second `--quorum` is a second pad. Both pads must be recovered. The checklist for a policy that uses weights or more than one quorum is `docs/CEREMONY-POLICY.md`. Do not mix the two checklists. Do not invent a third one in the room.

### The spec

```text
--quorum THRESHOLD:INDEX[=WEIGHT],INDEX[=WEIGHT],...
```

Repeat `--quorum` once per pad. The number before the colon is the weight that pad requires. The numbers after it are `--share` positions, starting at 1. A missing `=WEIGHT` means 1. There are no spaces.

```text
--quorum 1:1,2          share 1 weight 1, share 2 weight 1, need 1
--quorum 2:2=2,3        share 2 weight 2, share 3 weight 1, need 2
--quorum 1:1=2,2=1,3    share 1 weight 2, share 2 weight 1, share 3 weight 1, need 1
```

The index is the position in `--share`, not a YubiKey serial and not a Shamir x-coordinate. The first `--share` is 1. The same index in two `--quorum` flags is still one file, one password, and one YubiKey object. It counts in each quorum that lists it, at the weight written in that flag. The weight is not a property of the person. Share 2 can be weight 1 in quorum 1 and weight 2 in quorum 2.

Do not combine `--quorum` with `--threshold` or `--weight`. `--weight` is only the one-quorum form, repeated in `--share` order, one number per share. Omit `--weight` and every weight is 1.

These are rejected before the key file is opened and before any share is written:

| Spec | Why |
| --- | --- |
| `--threshold` together with `--quorum` | Two policies. |
| `--weight` together with `--quorum` | Weights belong in the spec. |
| `--weight` not once per `--share` | The pairing would be a guess. |
| Threshold 0, or weight 0 | Not a quorum, and not a share. |
| Threshold above the sum of weights in that quorum | The pad can never be recovered. |
| An index of 0, or an index past the last `--share` | Not a share. |
| The same index twice in one `--quorum` | One custodian, one weight, in that quorum. |
| A `--share` listed in no quorum | That file would not be a share. Do not emit it. |
| More than 32 quorums, or more than 255 points in one quorum | The field has 255 nonzero x-coordinates. A ceremony is smaller than 32 quorums. |

The summary lists members in custodian-index order, not the order they were typed. `--quorum 2:5,1=1,4=2` is the same policy as `--quorum 2:1=1,4=2,5`.

### One quorum

```text
agree split --threshold 2 \
  --share alice.share --weight 2 \
  --share bob.share --weight 1 \
  --share carol.share --weight 1
```

Alice's file holds two points. Bob's holds one. Carol's holds one. Alice alone restores the secret. Bob does not. Bob and Carol do. Split prints `warning: share 1 alone restores the secret`. That warning means the policy is threshold 1 for that person. Do not ignore it on a break-glass signing key.

`--threshold 3` and five `--share` flags, with no `--weight`, is the same bytes as five weights of 1. The summary stays `split 5 shares, threshold 3, key 32 bytes` and `any 3 shares restore the secret`.

### Two quorums

Two quorums are not two copies of the key. The data key is the XOR of one pad per quorum. Each pad is split under that quorum's threshold. A set that misses a quorum learns nothing about that pad, and therefore nothing about the key. One quorum deals the data key itself. There is no second pad.

```text
--share cfo.share --share ciso.share --share eng.share
--quorum 1:1,2
--quorum 2:2,3
```

```text
CFO    share 1    quorum 1 weight 1
CISO   share 2    quorum 1 weight 1, quorum 2 weight 1
Eng    share 3    quorum 2 weight 1

CFO                 quorum 2 missing
CISO                quorum 2 short
Eng                 quorum 1 missing
CFO + CISO          quorum 2 short
CISO + Eng          both met              restores
CFO + Eng           quorum 2 short
```

CISO's file holds one point of each pad. CFO never completes a restore: quorum 2 still needs CISO, and once CISO is present the engineer is the other point. A person who is in no restoring set is not a custodian. Fix that before the day. Do not discover it in the room.

### Different weights in different quorums

```text
--share ceo.share --share cfo.share --share coo.share
--share ciso.share --share eng.share
--quorum 2:1=2,2,3
--quorum 2:1=1,4=2,5
```

```text
share 1  CEO     quorum 1 weight 2, quorum 2 weight 1
share 2  CFO     quorum 1 weight 1
share 3  COO     quorum 1 weight 1
share 4  CISO    quorum 2 weight 2
share 5  Eng     quorum 2 weight 1
```

CEO's file holds two points of pad 1 and one point of pad 2. CISO's file holds two points of pad 2 and nothing of pad 1. The weight did not follow the person from one quorum to the other. It was written in that flag.

```text
CEO                 quorum 2 short          weight 1 of 2
CISO                quorum 1 missing
CEO + CISO          both met                restores
CEO + Eng           both met                restores
CFO + COO + CISO    both met                restores
CFO + COO           quorum 2 missing
CFO + COO + Eng     quorum 2 short          weight 1 of 2
CISO + Eng          quorum 1 missing
```

No share alone meets both quorums, so split does not print the alone warning. If it does, the policy on the command is not the policy on this page. Stop.

A lost CEO still leaves CFO, COO, and CISO. A lost CISO still leaves CEO and Eng. A lost CEO and a lost CISO leaves no restoring set. Those two tokens must not sit in one fire.

### YubiKey

The location does not change the policy. One object per custodian. The sealed secret stays a file. A PIV object holds at most 3063 bytes. The quorum does not raise that limit. It spends it on points. Each point is `1 + key-bytes`. The policy itself is a few dozen bytes, copied into every share. A password wrap adds 60 bytes. The ceremony leaves a YubiKey share unprotected, so that 60 is not in the object. The PIN is the binding.

A 3-of-5 share of a 32-byte key is 113 bytes. Custodian 1 on this page, three points, is 185 bytes. The same three points of a 1024-byte key are 3161 bytes, which is over the limit and refused. Two points of that key are 2134 bytes and still fit. The default key has room for dozens of points. A 1024-byte key has room for two.

```bash
agree split \
  --sealed sealed.bin \
  --share yubikey:11111111/5fff21 \
  --share yubikey:22222222/5fff21 \
  --share yubikey:33333333/5fff21 \
  --share yubikey:44444444/5fff21 \
  --share yubikey:55555555/5fff21 \
  --quorum 2:1=2,2,3 \
  --quorum 2:1=1,4=2,5 \
  --protect \
  < secret-file
```

Share 1 is `11111111`. Share 4 is `44444444`. The serial is not the index. Omit the serial only when one key is attached. Name it when the dealer will swap tokens. Do not pass `--management-key`. For a YubiKey share, the custodian presses Enter at the password prompt. The PIN is the binding. Do not write a second object to hold "the other weight". Both weights are already in the one object.

```bash
agree restore \
  --sealed sealed.bin \
  --share yubikey:11111111/5fff21 \
  --share yubikey:44444444/5fff21 \
  > restored.bin
```

That is CEO and CISO. Restore asks for each PIN. It does not ask for the management key. CFO and Eng do not restore: quorum 1 is met by nobody in that pair, and quorum 2 is short. Stdout stays empty. The error names the quorum.

This command is not the checklist. The checklist is `docs/CEREMONY-POLICY.md`. The dealer types the command on that page, with the serials from the roster, and no other.

### What split prints

A 3-of-5 split prints the threshold and `any 3 shares restore the secret`. Any other policy prints the share index next to each destination, then one line per quorum, members in index order:

```text
split 5 shares, key 32 bytes
group <32 hex characters>
sealed sealed.bin
share 1: yubikey:11111111/5fff21
share 2: yubikey:22222222/5fff21
share 3: yubikey:33333333/5fff21
share 4: yubikey:44444444/5fff21
share 5: yubikey:55555555/5fff21
quorum 1: threshold 2, share 1 weight 2, share 2 weight 1, share 3 weight 1
quorum 2: threshold 2, share 1 weight 1, share 4 weight 2, share 5 weight 1
every quorum must be met
```

The witness compares those two quorum lines to the paper. A match in the dealer's head is not a match. The summary does not print the secret or the data key.

A weight is still separable. After the password or the PIN unwraps a weight-2 share, those points can be peeled apart and handed to someone else. That is the same failure as copying a share. The file or the token raises the cost. It does not make the weight indivisible. Weight 0 is not a share. A witness is a person in the room.

The machine that runs `split` sees the whole secret. Two people should watch that ceremony, on a machine that is not the everyday laptop. Afterwards, overwrite the secret file if the disk is magnetic and has no snapshots. On an SSD or APFS, that overwrite misses the old pages, so the control is full-disk encryption and powering off, not shredding and not destroying the disk. A snapshot that ran while the secret existed has to be deleted. `agree` cannot make a trusted dealer unnecessary. For a one-time break-glass split, that is acceptable if it happens once and the secret does not stay online.

A restore also reconstructs the secret in the process that runs `agree restore`. That process is trusted for that hour. Hardware does not remove the combining step.

## The two artifacts

A split produces two different things.

The **sealed secret** is the ciphertext of the original secret, plus a short header. It is not a share. By itself it does not reveal the secret, and it is useless without the data key. Store it with the data you may someday need to open, in more than one place. Losing the sealed secret means the shares cannot restore anything, even if you still have all five. Replicate it freely. Protect its integrity, not its confidentiality: a substituted sealed file will not open under the original shares.

Each **share** holds the Shamir points for the quorums that custodian belongs to, a group id, the policy, and a commitment to the sealed bytes. The default key is 32 bytes. An unprotected 3-of-5 share of that key is about 110 bytes. A longer key makes a longer share, still one share per custodian. A 1024-byte key at weight 1 is about 1100 bytes unprotected, which still fits a YubiKey object. A high weight across several quorums can pass 3063 bytes, and that destination is refused. For 3 of 5, no person should hold two shares. No building, safe, backup account, or disk image should hold enough shares to meet every quorum.

```text
one quorum
secret  --encrypt-->  sealed secret              (arbitrary length, not a share)
                 \
                  +-- split data key -->  points inside share 1 .. share n

two quorums
secret  --encrypt-->  sealed secret
                 \
                  data key = pad 1 XOR pad 2
                  pad 1 --split-->  points for the shares in quorum 1
                  pad 2 --split-->  points for the shares in quorum 2
```

## How a split works

1. Read the secret from stdin, as a stream. It is never required to fit in a small buffer, and it is never read from a path. Empty secrets are valid. If `--key-file` is set, that source is read first. YubiKey prompts, if any, happen after the key is in hand and before the secret is read.
2. Take the data key. Omit `--key-file` and the operating system draws `--key-bytes` from its CSPRNG. Pass `--key-file` and those exact bytes are the key. Also draw a 16-byte group id and a 20-byte nonce prefix from the CSPRNG. The key length is a multiple of 32, from 32 to 1024. The default is 32. Each 32-byte piece is one encryption layer.
3. Encrypt the secret in 64 KiB chunks. Layer 1 encrypts the plaintext. Each later layer encrypts the previous layer's ciphertext. The layer number is part of the associated data, so a layer cannot be removed or reordered.
4. Hash every byte of the sealed output. That hash is the commitment.
5. Split the data key. One quorum is one Shamir deal, threshold equal to the weight that must be present, one or more points per custodian. Further quorums each get a random pad, and the last pad is set so the pads XOR to the data key. Each pad is dealt on its own. Custodian indexes are `1` through `n`, in `--share` order. A Shamir x-coordinate is not that index. A 64-byte key is still one share per custodian, not two, however many points that file holds.
6. If a share has a password, wrap that body with Argon2id and ChaCha20-Poly1305. The wrap is bound to the group, the index, the policy, and the commitment. A wrapped body moved onto another share does not decrypt.
7. Write the sealed secret, then the shares. File outputs are created mode `0600` and published by rename. If a later file share fails, file shares already published in that command are removed. A YubiKey or device write that already succeeded cannot be rolled back; the error names what was written.

The data key is locked with `mlock` while it exists and cleared on drop. `split` and `restore` refuse to run if that lock fails. The refusal happens before any prompt and before the secret is read. Core dumps are disabled when the operating system allows it. If that call fails, the tool warns and continues. Do not treat that warning as decorative on a dealer machine.

## External data key

`--key-bytes` is the length. `--key-file` is only the source. They are not alternatives. Omit the file and the operating system draws that many bytes. Pass it, and the file or pipe must contain that many bytes and then end. A short read or an extra byte is a refusal, before any prompt and before any share is written. The reader does not seek, and it does not trust a reported file size, so a pipe has the same rules as a regular file.

```bash
agree split \
  --threshold 2 \
  --key-bytes 64 \
  --key-file <(openssl rand 64) \
  --sealed sealed.bin \
  --share a.share \
  --share b.share \
  < secret.txt
```

`agree` does not run the generator. The shell does, and the tool only reads the pipe. Do not put the key or the secret in the command line. `ps` and shell history keep arguments. `openssl rand 64` is fine because the bytes are not in `argv`. A command that prints them into its arguments is not.

The path is not a `device:` or `yubikey:` location. Those are destinations. A process substitution is an ordinary path, usually `/dev/fd/N`, and that is what `--key-file` wants. The source must end. `/dev/urandom` does not, so it is rejected as longer than `--key-bytes`. `<(openssl rand 64)` ends. Stdin stays the secret. A path of `-` is a file named `-`, not the key.

A copy of those bytes is a way in that does not need the shares. Dice, a hardware RNG, or another machine are usable only if that record is destroyed after a test restore. A token that can produce the same bytes later makes the Shamir split optional. There is no passphrase derivation. A password you can type again is that same bypass.

The sealed file stores the length, not how the key was chosen. Restore cannot tell an external key from one the operating system drew, and it should not be able to.

## How a restore works

1. Read the shares. A share read stops at the end of the share format, so leftover bytes on a device are ignored.
2. Reject a short set before any secret bytes are written. The shares you present must meet every quorum. Duplicate indexes are rejected. More shares than were generated are rejected. Shares from two splits are rejected. A missing quorum is named. Stdout stays empty.
3. Unwrap password-protected shares. A missing or wrong password fails closed. It does not produce a different secret.
4. Read the sealed secret up to its final chunk, hash those bytes, and compare the hash to the commitment stored in the shares. A substituted or truncated sealed file fails here.
5. Recover each quorum's pad from the points in the shares you passed, XOR the pads, and decrypt the chunks. One quorum recovers the data key directly. The policy is covered by the authentication data, so a header that does not match the shares fails authentication instead of emitting garbage.
6. Write the restored bytes to stdout, and nowhere else. Stdout is refused when it is a terminal, so the secret has to be redirected or piped. Status text stays on stderr.

If you pass more shares than a quorum requires, and every one of them is intact, restore still succeeds. Shamir interpolation of extra consistent points yields the same pad. One damaged extra share can make that larger set fail even though some other set would have worked. On a recovery day, retry with a different set that meets every quorum and is no larger than it has to be.

A restore does not invalidate the shares. The same three people, or a different three, can open the secret again next year. If the restored secret is copied off the ceremony machine, the quorum is already broken for that secret. Generate a new secret, re-encrypt the data, and split again. Until the data is re-encrypted, the old shares still open the old secret. Deleting share files is not rotation.

## Cryptography

The secret is encrypted with XChaCha20-Poly1305, once per 32-byte key layer. The 24-byte nonce is a random 20-byte prefix plus a big-endian chunk counter. Layers of the same chunk reuse that nonce under different keys. Associated data for each layer is:

```text
"agree-sealed-v1" || group-id || key-bytes || policy || layer || chunk-counter || last-flag
```

The last chunk is marked. An empty secret is one final chunk of empty plaintext. A rearranged chunk, a chunk from another split, or a header whose policy does not match the shares, fails the Poly1305 tag.

Only the data key is split, or the pads that XOR to it. Its length is a multiple of 32, from 32 to 1024. The implementation is Shamir over GF(256), one polynomial per key byte, from the pinned `shamirs` 0.7.0 crate. Share x-coordinates start at 1, per quorum, and are not the custodian index. Fewer points than a quorum's threshold do not determine that pad. That property is information-theoretic for the pad, and therefore for the data key, if the crate's field arithmetic and randomness hold. The secret itself is then only as confidential as the authenticated encryption. This is not verifiable secret sharing. Custodians cannot prove their share lies on the polynomial without pooling enough shares to restore. A malicious dealer can keep a copy. The process control for that is the ceremony, not a claim the tool cannot make.

The commitment is SHA-256 over the exact sealed bytes that were written: header and chunk frames, and not any bytes that happen to follow them on a larger device. Every share stores that hash. Restore checks it before decryption, so a sealed file from another split is rejected even before the authenticator runs.

A share password is not a group password unless you type the same one for every share. Each protected share gets its own random 32-byte salt and 12-byte nonce. The password is stretched with Argon2id (`m = 64 MiB`, `t = 3`, `p = 1`, 32-byte output) and the Shamir share is encrypted with ChaCha20-Poly1305. Empty passwords are rejected. An absent password means the share is unprotected, not that the password is blank. Associated data for the wrap is:

```text
"agree-share-v1" || group-id || index || key-bytes || policy || commitment
```

Argon2id at these parameters is an interactive setting. It is not a substitute for a long passphrase. A short human password on two shares is an offline guessing problem for anyone who steals those two files. For a critical share, prefer a YubiKey or a device that is stored apart from a high-entropy password, and do not invent a short one.

## On-wire format

The revision byte is `1` for this tool. It is not a stable protocol that a later `agree` promises to read. A different binary may refuse these files. Keep the `agree` that created the shares next to the sealed secret. There is no migration path.

Sealed secret, magic `AGRS`:

```text
offset  size  field
0       4     magic "AGRS"
4       1     revision = 1
5       2     key size in bytes, big-endian, a multiple of 32
7       16    group id
23      20    nonce prefix
43      2     policy length, big-endian
45      P     policy
45+P          one or more chunks:
              1 byte  last flag (1 on the final chunk, 0 otherwise)
              4 bytes ciphertext length, big-endian
              N bytes ciphertext, including the 16-byte Poly1305 tag
```

The reader stops at the final chunk. Bytes after that are not part of the secret and are not hashed. A chunk longer than 64 KiB plus the tag is rejected. That bound is per chunk, not on the secret. The secret is many chunks.

Share, magic `AGRH`:

```text
offset  size  field
0       4     magic "AGRH"
4       1     revision = 1
5       1     custodian index, 1..=255, never 0
6       2     key size in bytes, big-endian, must match the sealed file
8       16    group id
24      32    SHA-256 commitment of the sealed bytes
56      1     flags; bit 0 means the body is password-protected
57      2     policy length, big-endian
59      P     policy, the same bytes as the sealed header
59+P    4     body length, big-endian
63+P          body
```

The policy is `count || quorum-count ||` then, for each quorum, `threshold || member-count ||` and for each member `custodian || weight`. Members are in custodian-index order. A policy that is not in that order is rejected.

An unprotected body starts with the custodian index. Then, for each quorum that custodian belongs to, `quorum-index || point-count ||` and that many points. A point is one Shamir x-coordinate, then one y-coordinate per data-key byte. A 32-byte key has 32 y-coordinates. A 64-byte key has 64. The x-coordinate is not the custodian index. A protected body is `salt[32] || nonce[12] || ciphertext` of that same body. Unknown flag bits are rejected. The reader does not read past the declared body, and a body larger than 8192 bytes is rejected.

## Locations

A location is where a share, the sealed secret, or the restored secret is read or written. The same syntax is used everywhere.

| Form | Meaning |
| --- | --- |
| `alice.share`, `~/keys/sealed.bin` | A file. Created mode `0600`. Not overwritten unless `--force`. `~` expands from `HOME`. |
| `device:/dev/rdisk4` | Write or read the bytes directly on an existing node. Requires `--force` to write. The node must already exist. The write starts at offset zero and does not truncate the device, so bytes after the format remain. The reader stops at the end of the format. |
| `yubikey:5fff21` | PIV data object `5fff21` on the only attached YubiKey. |
| `yubikey:12345678/5fff21` | The same object on the YubiKey with that decimal serial. |

A path and `device:` of that same path are the same destination. The sealed secret and a share cannot share a destination. Split and restore can both use more than one YubiKey serial. Omit the serial only when one key is attached. Name it when you will swap tokens.

`device:` is the arbitrary-length hardware path. A USB stick or a raw disk can hold a sealed secret of any size the node can store. `yubikey:` is a PIV object write. It is not a filesystem, and it is not `ykman`. `agree` speaks PC/SC itself.

## YubiKey

Writable PIV object ids are `5f0000` through `5fffff`. Ids below `5fff20` hold certificates, CHUID, admin data, and attestation. Those are refused unless you pass `--force`, because a casual write would destroy key material that has nothing to do with this split. Use `5fff20` through `5fffff` for shares. One object per custodian. A weight of 2 is two points in that one object, not a second object and not a second share. Do not also give that person another object. With 3 of 5, one person holding two shares still needs a third, but they are closer than the policy you wrote down. With two quorums, one person holding a restoring set has the secret.

A single PIV object holds at most 3063 bytes. That is the YubiKey 4/5 message buffer minus the object header. A 3-of-5 share fits, and so does the policy in `docs/CEREMONY-POLICY.md` at the default 32-byte key. A high weight on a 1024-byte key can pass 3063 bytes, and that destination is refused. A large sealed secret does not fit. Put shares on the keys and put the sealed secret on a file or a `device:` path. The restored secret is not written to a YubiKey: it is written only to stdout. If you point `--sealed` at a YubiKey and the payload is larger than 3063 bytes, the command fails before publishing shares. Check the size before the ceremony if the secret is large.

Writing requires the PIV PIN and the management key. Split can write each share to a different token. On a terminal it prints `Insert YubiKey SERIAL for LOCATION, then press Enter`, then asks for that key's PIN. If `--management-key` is omitted, it then asks for that key's management key. An empty answer uses the factory key and warns. A second object on a serial already unlocked in that command reuses both. Those prompts happen before stdin is read, so a missing terminal does not consume the secret. After the split, a key that is no longer attached is asked for again before it is written.

`--management-key` is 48 hex characters (24 bytes) and applies to every token in the command. Firmware 5.7 and later authenticates that value as AES-192. Older keys authenticate it as 3DES. `agree` reads the algorithm from the card. Use it only when every key shares that management key. It shows up in the process list. The prompt is how two keys get two management keys. Change the factory key, and record the new one somewhere that is not the same envelope as the share, before this is a production ceremony. A factory management key means anyone with the PIN and physical access can overwrite objects.

`agree devices` prints one line per attached device this build can open. No PIN is required, and nothing is written. A YubiKey line starts with `yubikey:` and the number after it is the serial. A reader that is not a YubiKey is skipped by that source. An empty list is not an error. A build without the `yubikey` feature omits that kind and still runs the command. `device:` paths are not listed; those are nodes you already have. A new kind is another source in the same list, not a second command.

Omit the serial (`yubikey:5fff21`) only when one key is attached. If more than one is attached, the command stops and lists the serials instead of guessing. Name the serial when you will swap tokens. Run `agree devices` with one key inserted at a time if you need to see which serial is which.

Reading a share needs the PIN only. Restore asks for each key separately, so a 2-of-6 restore can use two tokens with two PINs. The insert prompt is the same as split. A second object on a key you already unlocked in that command reuses the PIN. `--pin-stdin` is one PIN line per YubiKey share, in `--share` order, then one more line if `--sealed` is a YubiKey. Password lines come after those PIN lines. Keys named by serial must already be plugged in for `--pin-stdin`; swapping keys one at a time is the terminal flow. Split has no `--pin-stdin`, because stdin is the secret.

On Linux, PC/SC (`pcscd`) and `libpcsclite` must be installed. Static musl release builds are compiled with `--no-default-features` and do not link PC/SC. Those binaries reject `yubikey:` locations and tell you to use a build with the `yubikey` feature. A normal macOS build and a dynamically linked Linux build include it. There is no shell-out to `ykman`.

A YubiKey that is the only copy of a share dies with that YubiKey. That loss is survivable only when the remaining shares still meet every quorum. For 3 of 5, any three of the other four still open it. For the policy in `docs/CEREMONY-POLICY.md`, a lost custodian 1 still leaves custodians 2, 3, and 4. A lost custodian 1 and a lost custodian 4 leaves no restoring set. Keep a durable copy of each share on media you can still find in ten years, or accept that a dead token is a lost share. Do not put the reconstructed signing key back onto a YubiKey and call that the archive. The shares remain the archive.

## Passwords

On split, `--protect` prompts on the terminal once per share. An empty answer leaves that share unprotected. A non-empty answer must be confirmed. Stdin cannot also carry passwords: it is the secret. A split that needs a password, a YubiKey PIN, or a management key and has no terminal fails before reading the secret.

On restore, a protected share requires a password. If stderr is a terminal, only protected shares are prompted, and an empty answer is rejected. YubiKey PIN prompts happen first, one key at a time, because the share cannot be read without that PIN. `--password-stdin` then reads one line per share from stdin, in the order the shares were given, and the secret is written to stdout after those lines. An empty line is unprotected; a protected share with an empty line is rejected. Trailing newline characters are stripped. A password may contain spaces and may not be longer than 4096 bytes.

Do not put passwords on the command line. They would show up in the process list.

## Break-glass ceremony

The 3 of 5 procedure is `docs/CEREMONY.md`. A policy with a weight other than 1, or with more than one quorum, is `docs/CEREMONY-POLICY.md`. Follow that checklist to the letter. Do not improvise a shorter one from this page. Do not combine the two checklists.

The commands enforce the mechanical parts. The watching, the storage separation, and the wipe are still on you. Name the custodians in different places. For 3 of 5 the threshold is 3. Each custodian who will use a YubiKey brings one, with a PIN that is not the factory `123456`, and a management key that is not the factory key. Authenticate object ids out of band so nobody writes a share onto a certificate slot. The sealed secret must be reachable on the day a restoring set must open the data, and it must exist in more than one copy.

Deal, store, and open are in the checklist for the policy you wrote down before the day. Do not substitute the command summary below for that checklist. A file share is acceptable only if the file and the means to read it leave with one custodian. A YubiKey share is the token that person carries. The stderr summary prints the share count, the key size, the group id, the sealed path, and either the threshold or the quorum lines. It does not print the secret or the data key. Do not pass `--key-file`. A remaining copy of that key opens the sealed secret without a quorum.

For 3 of 5, no three shares in one site, and no custodian holds two. For any other policy, no site holds a restoring set, and no custodian holds two shares. The sealed secret is stored with the encrypted data and in a second location. Labels carry the group id, the custodian, and the weight of that share in each quorum it belongs to. They do not carry the secret. A successor does not receive a forwarded share. Succession is a new split after a restore, or a planned rotation while a restoring set of the current custodians is still available.

If the restore machine was untrusted, or the key was copied, rotate. New key, re-encrypt the data, new split, destroy the old sealed secret after the new one has been verified. Until that re-encryption, the old shares are still live.

## Commands

```text
agree split < secret
    --threshold <1-255>           # one quorum, every weight 1; omit if using --quorum
    [--weight <1-255>]            # repeat once per --share, or omit for weight 1
    [--quorum <SPEC>]             # THRESHOLD:INDEX[=WEIGHT],...; repeat; replaces --threshold
    --key-bytes <32,64,...,1024>  # length; default 32; each 32 bytes is one layer
    [--key-file <path>]           # source of exactly that many bytes; not a command
    --sealed <location>
    --share <location>            # repeat, this count is n; index 1 is the first
    [--protect]                   # terminal prompt; stdin is already the secret
    [--management-key <48 hex>]   # every key; omit to prompt once per YubiKey
    [--force]                     # overwrite files and YubiKey objects; required for device:
    [--debug]                     # echo the PIN and management key on this terminal

agree restore > secret
    --sealed <location>
    --share <location>            # repeat until every quorum is met
    [--password-stdin]            # one line per share, consumed before stdout is written
    [--pin-stdin]                 # one line per YubiKey share, before password lines
    [--management-key <48 hex>]

agree devices

agree man -o <dir> -f manpages|markdown
agree autocomplete -o <dir> -s bash|zsh|fish|elvish|powershell
```

Split reads the secret only from stdin. Restore writes the secret only to stdout, and refuses when stdout is a terminal. There is no `--secret` path and no `--output` path. Share and sealed locations are still files, `device:` nodes, or YubiKey objects. `--key-file` is not one of those destinations, and it is not read from stdin. Omit it to draw the key. Pass it only when the file or pipe is exactly `--key-bytes` long.

Passwords, the YubiKey PIN, and a per-key management key for `split` are prompted on the terminal, because stdin is the secret. Those prompts read `/dev/tty`, not the redirected stdin. `--debug` echoes the PIN and management key as they are typed and prints the captured values on stderr. Share passwords stay hidden. Do not use it on a shared or recorded terminal. `restore` may read passwords and the PIN from stdin with `--password-stdin` and `--pin-stdin`. Those lines are consumed before any secret byte is written to stdout.

Relative paths are resolved from the working directory. `~/` is resolved from `HOME`.

A successful split prints a summary on stderr. Restore writes nothing but the secret to stdout. `agree devices` writes one line per attached device to stdout, or nothing if none are attached. A YubiKey line is `yubikey:SERIAL`. Status and errors stay on stderr.

## Failure behavior

The tool is fail-closed on the secret. These cases do not write a restored secret:

| Condition | Result |
| --- | --- |
| A set that misses a quorum | Error before decryption. The missing quorum is named. Stdout stays empty. |
| Duplicate share index, or the same path twice | Rejected. |
| Shares from different splits, or a sealed file whose commitment does not match | Rejected. |
| Wrong share password, a damaged share, or a sealed chunk that fails authentication | Decryption or authentication failure. Stdout stays empty, including when an earlier chunk would have opened. |
| Truncated sealed secret, a format revision this binary does not write, unknown share flags | Rejected. There is no reader for any other revision. |
| Threshold 0, weight 0, a threshold above the weight of its quorum, a share in no quorum, a share listed twice in one quorum, `--threshold` or `--weight` combined with `--quorum`, more than 32 quorums, or more than 255 points in one quorum | Rejected before the key file is opened and before any share is written. |
| `--key-bytes` not a multiple of 32, or outside 32 to 1024 | Rejected before the key file is opened and before any share is written. |
| `mlock` fails | `split` and `restore` exit before prompts and before the secret is read. No share is written. |
| `--key-file` shorter or longer than `--key-bytes` | Rejected before prompts and before any share is written. |
| `--key-file` is `device:`, `yubikey:`, a share path, or the sealed path | Rejected. The path is not executed. |
| Existing file without `--force` | Left untouched. |
| `device:` write without `--force` | Rejected. The node is not written. |
| Stdout is a terminal on restore | Rejected. Pipe or redirect stdout. |
| YubiKey payload larger than 3063 bytes | Rejected. |
| Reserved YubiKey object without `--force` | Rejected, before the card is written. |
| Two YubiKey serials in one split | Allowed. Each key is prompted before the secret is read. |
| Second share destination fails | File shares already written by that command are removed. |

A YubiKey object or a device node that was written before a later failure cannot be unwritten by the rollback. The error is the record of that. Do not point a half-finished ceremony at a production token and then guess.

## What this will not do

It will not sign. Restoring a signing key gives you the key. Whatever you do with it afterwards is outside `agree`.

It will not run a command to generate the data key, and it will not derive that key from a passphrase. It will not notice if you kept a copy of `--key-file`. That copy is enough to open the sealed secret alone.

It will not keep the quorum after restore. A restoring set produces one copy of the secret. That copy is 1 of 1.

It will not expire shares, refresh them, or tell you who restored the secret. There is no audit log. If you need a record, write it down in the incident notes.

It will not prove a share is consistent without a test restore. There is no Feldman verification.

It will not fit an arbitrary sealed secret on a YubiKey. The 3063-byte object limit is a property of the card, not a setting.

It will not securely erase a disk, a terminal scrollback buffer, or an SSD page. Unlink is not a wipe. Overwriting a file does not hit the old pages on an SSD or on APFS. The checklist does not pretend that it does.

It has not had a third-party cryptographic audit. The tests cover the quorum matrix, tampered inputs, passwords, device framing, and the YubiKey checks that can be made without a card. That is an engineering bar, not an audit. The on-wire revision belongs to this binary. Residual risks and accepted ceremony limits are in `THREAT_MODEL.md`.

## Build

```bash
cargo test
cargo build --release
```

The default build includes YubiKey support and links PC/SC. A static musl build that cannot link `libpcsclite` uses `--no-default-features`. That binary still splits and restores files and `device:` paths. It rejects `yubikey:` locations.

```bash
cargo build --release --no-default-features
```
