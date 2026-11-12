//! Split and restore.
//!
//! The secret is streamed. Shares hold Shamir points of one pad per quorum,
//! plus a commitment to the sealed bytes. One quorum deals the data key
//! itself. Further quorums deal independent pads that XOR to that key. The
//! key length is a multiple of 32. Each 32-byte piece is one encryption
//! layer. A set that misses a quorum cannot produce a key that authenticates.

use {
    crate::{
        crypto::{
            validate_key_bytes,
            SecretCipher,
            ShareCipher,
            CHUNK_LEN,
        },
        error::Error,
        format::{
            commitment_eq,
            SealedHeader,
            SealedReader,
            SealedWriter,
            ShareRecord,
        },
        memory::DataKey,
        policy::Policy,
        secret::Password,
        store::create_private_file,
    },
    anyhow::{
        bail,
        Context,
        Result,
    },
    rand_core::{
        OsRng,
        RngCore,
    },
    shamirs::{
        Share as ShamirShare,
        Sharks,
    },
    std::{
        fs::{
            self,
            File,
        },
        io::{
            self,
            Read,
            Write,
        },
        path::PathBuf,
    },
    zeroize::Zeroize,
};

pub(crate) struct Engine {
    shares: ShareCipher,
    temp: PathBuf,
}

impl Engine {
    pub(crate) fn new(temp: PathBuf) -> Self {
        Self {
            shares: ShareCipher::new(),
            temp,
        }
    }

    pub(crate) fn split<R: Read, W: Write>(
        &self,
        secret: &mut R,
        sealed: &mut W,
        policy: &Policy,
        key_bytes: u16,
        passwords: &[Option<Password>],
        key: Option<DataKey>,
    ) -> Result<SplitOutput> {
        let count = u8::try_from(passwords.len()).context("too many shares")?;
        if policy.count() != count {
            bail!("password count does not match share count");
        }
        let key_len = validate_key_bytes(key_bytes)?;
        if let Some(provided) = &key {
            if provided.as_bytes().len() != key_len {
                bail!("provided key length does not match --key-bytes");
            }
        }
        let mut group = [0u8; 16];
        OsRng.fill_bytes(&mut group);
        let cipher = match key {
            | Some(key) => SecretCipher::from_key(key, group, policy.bytes()),
            | None => SecretCipher::generate(group, policy.bytes(), key_len)?,
        };
        let header = SealedHeader {
            key_bytes,
            group,
            nonce_prefix: *cipher.nonce_prefix(),
            policy: policy.clone(),
        };
        let mut writer = SealedWriter::new(&mut *sealed, &header)?;
        stream_encrypt(&cipher, secret, &mut writer)?;
        let commitment = writer.commitment();
        let pads = split_pads(cipher.key_bytes(), policy.quorums().len())?;
        let bundles = bundle_points(policy, &pads)?;
        let mut encoded = Vec::with_capacity(passwords.len());
        for (offset, (mut bundle, password)) in bundles.into_iter().zip(passwords).enumerate() {
            let index = u8::try_from(offset + 1).expect("count fits in u8");
            let mut body = encode_body(index, &bundle);
            for dealt in &mut bundle {
                for point in &mut dealt.points {
                    point.zeroize();
                }
            }
            let mut record = ShareRecord {
                index,
                key_bytes,
                group,
                commitment,
                password: password.is_some(),
                policy: policy.clone(),
                body: Vec::new(),
            };
            if let Some(password) = password {
                let aad = record.aad();
                record.body = self.shares.seal(&body, password, &aad)?;
                body.zeroize();
            } else {
                record.body = body;
            }
            encoded.push(record.encode()?);
        }
        Ok(SplitOutput {
            group,
            policy: policy.clone(),
            key_bytes,
            shares: encoded,
        })
    }

    pub(crate) fn restore<R: Read, W: Write>(
        &self,
        sealed: R,
        output: &mut W,
        encoded: &[Vec<u8>],
        passwords: &[Option<Password>],
    ) -> Result<()> {
        if encoded.len() != passwords.len() {
            bail!("password count does not match share count");
        }
        let records = decode_shares(encoded)?;
        let indexes = records.iter().map(|record| record.index).collect::<Vec<_>>();
        if let Some(short) = records[0].policy.shortfall(&indexes) {
            if records[0].policy.uniform_threshold().is_some() {
                return Err(Error::NeedShares {
                    need: short.need,
                    got: indexes.len(),
                }
                .into());
            }
            return Err(Error::NeedWeight {
                quorum: short.quorum,
                need: short.need,
                got: short.got,
            }
            .into());
        }
        let opened = Wipe(self.open_shares(&records, passwords)?);
        let staged = self.stage_sealed(sealed)?;
        if !commitment_eq(&staged.commitment, &records[0].commitment) {
            return Err(Error::WrongGroup.into());
        }
        if staged.header.group != records[0].group
            || staged.header.policy != records[0].policy
            || staged.header.key_bytes != records[0].key_bytes
        {
            return Err(Error::WrongGroup.into());
        }
        let key_len = validate_key_bytes(records[0].key_bytes)?;
        let key = combine(&records, &opened.0, key_len)?;
        let cipher = SecretCipher::open(
            key,
            staged.header.nonce_prefix,
            staged.header.group,
            staged.header.policy.bytes(),
        );
        decrypt_staged(&cipher, &staged, output)?;
        Ok(())
    }

    fn open_shares(&self, records: &[ShareRecord], passwords: &[Option<Password>]) -> Result<Vec<Vec<u8>>> {
        let mut opened = Vec::with_capacity(records.len());
        for (record, password) in records.iter().zip(passwords) {
            let body = if record.password {
                let password = password.as_ref().ok_or(Error::PasswordRequired)?;
                self.shares.open(&record.body, password, &record.aad())?
            } else {
                record.body.clone()
            };
            opened.push(body);
        }
        Ok(opened)
    }

    fn stage_sealed<R: Read>(&self, sealed: R) -> Result<StagedSealed> {
        let mut reader = SealedReader::open(sealed)?;
        let path = self.temp.join(temp_name());
        let mut file = create_private_file(&path)?;
        let mut saw_last = false;
        while let Some((last, ciphertext)) = reader.next_chunk()? {
            if saw_last {
                bail!("sealed secret has data after the final chunk");
            }
            write_frame(&mut file, last, &ciphertext)?;
            saw_last = last;
            if last {
                break;
            }
        }
        if !saw_last {
            bail!("sealed secret ended before the final chunk");
        }
        file.sync_all().ok();
        Ok(StagedSealed {
            path,
            header: reader.header.clone(),
            commitment: reader.commitment(),
        })
    }
}

pub(crate) struct SplitOutput {
    pub(crate) group: [u8; 16],
    pub(crate) policy: Policy,
    pub(crate) key_bytes: u16,
    pub(crate) shares: Vec<Vec<u8>>,
}

struct StagedSealed {
    path: PathBuf,
    header: SealedHeader,
    commitment: [u8; 32],
}

impl Drop for StagedSealed {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn stream_encrypt<R: Read, W: Write>(
    cipher: &SecretCipher,
    secret: &mut R,
    sealed: &mut SealedWriter<W>,
) -> Result<()> {
    let mut buf = vec![0u8; CHUNK_LEN];
    let mut pending: Option<Vec<u8>> = None;
    let mut counter = 0u32;
    loop {
        let read = secret.read(&mut buf).context("Failed to read secret")?;
        if read == 0 {
            let mut last = pending.take().unwrap_or_default();
            let ciphertext = cipher.encrypt_chunk(counter, true, &last)?;
            sealed.write_chunk(true, &ciphertext)?;
            last.zeroize();
            break;
        }
        if let Some(mut previous) = pending.take() {
            let ciphertext = cipher.encrypt_chunk(counter, false, &previous)?;
            sealed.write_chunk(false, &ciphertext)?;
            previous.zeroize();
            counter = counter.checked_add(1).context("secret is too large to seal")?;
        }
        pending = Some(buf[..read].to_vec());
        buf[..read].zeroize();
    }
    Ok(())
}

fn deal(key: &[u8], threshold: u8, count: usize) -> Result<Vec<Vec<u8>>> {
    if key.is_empty() || !key.len().is_multiple_of(32) {
        bail!("data key must be a multiple of 32 bytes");
    }
    let sharks = Sharks(threshold);
    let shares: Vec<ShamirShare> = sharks.dealer(key).take(count).collect();
    if shares.len() != count {
        bail!("share generation returned {} shares, expected {count}", shares.len());
    }
    let mut encoded = Vec::with_capacity(count);
    for (expected, share) in (1..=count).zip(&shares) {
        let bytes = Vec::<u8>::from(share);
        if bytes.first().copied() != Some(u8::try_from(expected).expect("index fits")) {
            bail!("generated share index does not match its position");
        }
        encoded.push(bytes);
    }
    Ok(encoded)
}

fn recover(shares: &[Vec<u8>], threshold: u8, key_len: usize) -> Result<DataKey> {
    let parsed = shares
        .iter()
        .map(|bytes| ShamirShare::try_from(bytes.as_slice()).map_err(|err| anyhow::anyhow!(err)))
        .collect::<Result<Vec<_>>>()?;
    let sharks = Sharks(threshold);
    let recovered = sharks.recover(parsed.iter()).map_err(|_| Error::AuthenticationFailed)?;
    if recovered.len() != key_len {
        return Err(Error::AuthenticationFailed.into());
    }
    Ok(DataKey::from_bytes(recovered.to_vec())?)
}

fn decode_shares(encoded: &[Vec<u8>]) -> Result<Vec<ShareRecord>> {
    if encoded.is_empty() {
        bail!("at least one share is required");
    }
    let mut records: Vec<ShareRecord> = Vec::with_capacity(encoded.len());
    let mut seen = Vec::new();
    for bytes in encoded {
        let record = ShareRecord::decode(bytes)?;
        if seen.contains(&record.index) {
            return Err(Error::DuplicateShare.into());
        }
        seen.push(record.index);
        if record.index > record.policy.count() {
            bail!("share index {} is not in this split", record.index);
        }
        if let Some(first) = records.first() {
            if record.group != first.group
                || record.policy != first.policy
                || record.key_bytes != first.key_bytes
                || !commitment_eq(&record.commitment, &first.commitment)
            {
                return Err(Error::WrongGroup.into());
            }
        }
        if records.len() >= usize::from(record.policy.count()) {
            bail!("received more shares than this secret was split into");
        }
        records.push(record);
    }
    Ok(records)
}

/// One quorum deals the data key. Further quorums deal pads that XOR to it.
fn split_pads(key: &[u8], n: usize) -> Result<Vec<DataKey>> {
    if n == 0 {
        bail!("at least one quorum is required");
    }
    if n == 1 {
        return Ok(vec![DataKey::from_bytes(key.to_vec())?]);
    }
    let mut acc = key.to_vec();
    let mut pads = Vec::with_capacity(n);
    for _ in 0..n - 1 {
        let mut pad = vec![0u8; key.len()];
        OsRng.fill_bytes(&mut pad);
        for (left, right) in acc.iter_mut().zip(&pad) {
            *left ^= *right;
        }
        match DataKey::from_bytes(pad) {
            | Ok(locked) => pads.push(locked),
            | Err(err) => {
                acc.zeroize();
                return Err(err.into());
            },
        }
    }
    pads.push(DataKey::from_bytes(acc)?);
    Ok(pads)
}

struct DealtQuorum {
    index: u8,
    points: Vec<Vec<u8>>,
}

fn bundle_points(policy: &Policy, pads: &[DataKey]) -> Result<Vec<Vec<DealtQuorum>>> {
    let mut bundles = Vec::with_capacity(usize::from(policy.count()));
    for _ in 0..policy.count() {
        bundles.push(Vec::new());
    }
    for (offset, (quorum, pad)) in policy.quorums().iter().zip(pads).enumerate() {
        let quorum_index = u8::try_from(offset + 1).expect("quorum count fits");
        let mut points = deal(pad.as_bytes(), quorum.threshold(), quorum.total_weight())?;
        for member in quorum.members() {
            let n = usize::from(member.weight());
            let taken = points.drain(..n).collect();
            bundles[usize::from(member.index() - 1)].push(DealtQuorum {
                index: quorum_index,
                points: taken,
            });
        }
        for point in &mut points {
            point.zeroize();
        }
    }
    Ok(bundles)
}

fn encode_body(index: u8, bundle: &[DealtQuorum]) -> Vec<u8> {
    let mut body = vec![index];
    for dealt in bundle {
        body.push(dealt.index);
        body.push(u8::try_from(dealt.points.len()).expect("weight fits in u8"));
        for point in &dealt.points {
            body.extend_from_slice(point);
        }
    }
    body
}

fn combine(records: &[ShareRecord], opened: &[Vec<u8>], key_len: usize) -> Result<DataKey> {
    let policy = &records[0].policy;
    let mut by_quorum = vec![Vec::new(); policy.quorums().len()];
    for (record, body) in records.iter().zip(opened) {
        for dealt in parse_points(body, record.index, key_len, policy)? {
            let slot = &mut by_quorum[usize::from(dealt.index - 1)];
            slot.extend(dealt.points);
        }
    }
    let mut pads = Vec::with_capacity(policy.quorums().len());
    let combined = (|| {
        for (quorum, points) in policy.quorums().iter().zip(&by_quorum) {
            distinct_points(points)?;
            pads.push(recover(points, quorum.threshold(), key_len)?);
        }
        xor_pads(pads)
    })();
    for points in &mut by_quorum {
        for point in points {
            point.zeroize();
        }
    }
    combined
}

fn parse_points(body: &[u8], index: u8, key_len: usize, policy: &Policy) -> Result<Vec<DealtQuorum>> {
    if body.first().copied() != Some(index) {
        return Err(Error::AuthenticationFailed.into());
    }
    let point_len = 1 + key_len;
    let mut rest = &body[1..];
    let mut parsed = Vec::new();
    for (quorum, weight) in policy.membership(index) {
        if rest.len() < 2 {
            return Err(Error::AuthenticationFailed.into());
        }
        let found_quorum = rest[0];
        let found_weight = rest[1];
        rest = &rest[2..];
        if found_quorum != quorum || found_weight != weight {
            return Err(Error::AuthenticationFailed.into());
        }
        let mut points = Vec::with_capacity(usize::from(weight));
        for _ in 0..weight {
            if rest.len() < point_len {
                return Err(Error::AuthenticationFailed.into());
            }
            let point = rest[..point_len].to_vec();
            if point[0] == 0 {
                return Err(Error::AuthenticationFailed.into());
            }
            points.push(point);
            rest = &rest[point_len..];
        }
        parsed.push(DealtQuorum { index: quorum, points });
    }
    if !rest.is_empty() {
        return Err(Error::AuthenticationFailed.into());
    }
    Ok(parsed)
}

fn distinct_points(points: &[Vec<u8>]) -> Result<()> {
    let mut seen = Vec::new();
    for point in points {
        let x = *point.first().ok_or(Error::AuthenticationFailed)?;
        if x == 0 || seen.contains(&x) {
            return Err(Error::AuthenticationFailed.into());
        }
        seen.push(x);
    }
    Ok(())
}

fn xor_pads(pads: Vec<DataKey>) -> Result<DataKey> {
    let Some(first) = pads.first() else {
        bail!("at least one quorum is required");
    };
    let mut acc = first.as_bytes().to_vec();
    for pad in pads.iter().skip(1) {
        for (left, right) in acc.iter_mut().zip(pad.as_bytes()) {
            *left ^= *right;
        }
    }
    Ok(DataKey::from_bytes(acc)?)
}

fn decrypt_staged<W: Write>(cipher: &SecretCipher, staged: &StagedSealed, output: &mut W) -> Result<()> {
    // Authenticate every chunk before any plaintext reaches the caller. A later
    // failure must not leave a prefix on stdout.
    let plain_path = staged.path.with_extension("plain");
    let _cleanup = RemoveOnDrop(plain_path.clone());
    let mut plain = create_private_file(&plain_path)?;
    decrypt_into(cipher, &staged.path, &mut plain)?;
    plain.sync_all().ok();
    drop(plain);
    let mut input = File::open(&plain_path).context("Failed to read restored secret")?;
    io::copy(&mut input, output).context("Failed to write restored secret")?;
    Ok(())
}

struct Wipe(Vec<Vec<u8>>);

impl Drop for Wipe {
    fn drop(&mut self) {
        for buf in &mut self.0 {
            buf.zeroize();
        }
    }
}

struct RemoveOnDrop(PathBuf);

impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn decrypt_into(cipher: &SecretCipher, staged: &PathBuf, plain: &mut File) -> Result<()> {
    let mut file = File::open(staged).context("Failed to read staged sealed secret")?;
    let mut counter = 0u32;
    let mut saw_last = false;
    loop {
        let Some((last, ciphertext)) = read_frame(&mut file)? else {
            break;
        };
        if saw_last {
            bail!("staged sealed secret is corrupt");
        }
        let mut plaintext = cipher.decrypt_chunk(counter, last, &ciphertext)?;
        plain.write_all(&plaintext).context("Failed to write restored secret")?;
        plaintext.zeroize();
        saw_last = last;
        if last {
            break;
        }
        counter = counter.checked_add(1).context("sealed secret is corrupt")?;
    }
    if !saw_last {
        bail!("staged sealed secret is corrupt");
    }
    Ok(())
}

fn write_frame(file: &mut File, last: bool, ciphertext: &[u8]) -> Result<()> {
    let len = u32::try_from(ciphertext.len()).context("sealed chunk is too large")?;
    file.write_all(&[u8::from(last)])?;
    file.write_all(&len.to_be_bytes())?;
    file.write_all(ciphertext)?;
    Ok(())
}

fn read_frame(file: &mut File) -> Result<Option<(bool, Vec<u8>)>> {
    let mut last = [0u8; 1];
    match file.read(&mut last)? {
        | 0 => return Ok(None),
        | 1 => {},
        | _ => unreachable!("one-byte read"),
    }
    let mut len_bytes = [0u8; 4];
    file.read_exact(&mut len_bytes)?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    if len > crate::format::MAX_CHUNK_CIPHERTEXT {
        bail!("sealed chunk is too large");
    }
    let mut ciphertext = vec![0u8; len];
    file.read_exact(&mut ciphertext)?;
    Ok(Some((last[0] == 1, ciphertext)))
}

fn temp_name() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    format!("agree-sealed-{}.tmp", crate::location::encode_hex(&bytes))
}

#[cfg(test)]
mod tests {
    use {
        super::Engine,
        crate::{
            format::ShareRecord,
            memory::DataKey,
            policy::Policy,
            secret::Password,
        },
        std::{
            fs,
            io::Cursor,
            path::PathBuf,
        },
    };

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let mut name = [0u8; 8];
            rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut name);
            let path = std::env::temp_dir().join(format!("agree-engine-{}", crate::location::encode_hex(&name)));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn engine(dir: &TempDir) -> Engine {
        Engine::new(dir.0.clone())
    }

    fn policy_of(threshold: u8, count: usize) -> Policy {
        Policy::uniform(threshold, u8::try_from(count).unwrap()).unwrap()
    }

    fn roundtrip(secret: &[u8], threshold: u8, passwords: &[Option<Password>]) {
        let dir = TempDir::new();
        let engine = engine(&dir);
        let mut sealed = Vec::new();
        let policy = policy_of(threshold, passwords.len());
        let split = engine
            .split(&mut Cursor::new(secret), &mut sealed, &policy, 32, passwords, None)
            .unwrap();
        assert_eq!(split.shares.len(), passwords.len());
        if secret.len() >= 16 {
            for share in &split.shares {
                assert!(!share.windows(secret.len()).any(|window| window == secret));
            }
        }
        let mut restored = Vec::new();
        engine
            .restore(Cursor::new(sealed), &mut restored, &split.shares, passwords)
            .unwrap();
        assert_eq!(restored, secret);
    }

    #[test]
    fn restores_empty_small_and_multichunk_secrets() {
        roundtrip(b"", 1, &[None]);
        roundtrip(b"signing-key", 2, &[None, None, None]);
        let mut large = vec![0u8; 70_000];
        large[0] = 1;
        large[65_000] = 2;
        large[69_999] = 3;
        roundtrip(&large, 3, &[None, None, None, None, None]);
    }

    #[test]
    fn password_and_threshold_are_enforced() {
        let dir = TempDir::new();
        let engine = engine(&dir);
        let password = Password::new("share-password".to_owned()).unwrap();
        let mut sealed = Vec::new();
        let passwords = [None, Some(password.clone()), None];
        let policy = policy_of(2, passwords.len());
        let split = engine
            .split(
                &mut Cursor::new(b"secret-bytes"),
                &mut sealed,
                &policy,
                32,
                &passwords,
                None,
            )
            .unwrap();
        let mut restored = Vec::new();
        assert!(engine
            .restore(Cursor::new(sealed.clone()), &mut restored, &split.shares[0..1], &[None])
            .is_err());
        let mut wrong = passwords.clone();
        wrong[1] = Some(Password::new("nope".to_owned()).unwrap());
        assert!(engine
            .restore(Cursor::new(sealed.clone()), &mut restored, &split.shares, &wrong)
            .is_err());
        engine
            .restore(
                Cursor::new(sealed.clone()),
                &mut restored,
                &split.shares[1..],
                &passwords[1..],
            )
            .unwrap();
        assert_eq!(restored, b"secret-bytes");
        sealed[20] ^= 0xff;
        restored.clear();
        assert!(engine
            .restore(Cursor::new(sealed), &mut restored, &split.shares, &passwords)
            .is_err());
    }

    fn split_of(secret: &[u8], threshold: u8, count: usize) -> (Vec<u8>, Vec<Vec<u8>>) {
        let dir = TempDir::new();
        let engine = engine(&dir);
        let passwords = vec![None; count];
        let mut sealed = Vec::new();
        let policy = policy_of(threshold, count);
        let split = engine
            .split(&mut Cursor::new(secret), &mut sealed, &policy, 32, &passwords, None)
            .unwrap();
        // Keep the temp dir alive until the split returns; staging files are inside the
        // sealed buffer.
        drop(engine);
        drop(dir);
        (sealed, split.shares)
    }

    fn restore_with(sealed: &[u8], shares: &[Vec<u8>]) -> Result<Vec<u8>, String> {
        let dir = TempDir::new();
        let engine = engine(&dir);
        let passwords = vec![None; shares.len()];
        let mut restored = Vec::new();
        match engine.restore(Cursor::new(sealed), &mut restored, shares, &passwords) {
            | Ok(()) => Ok(restored),
            | Err(err) => Err(err.to_string()),
        }
    }

    fn combinations(n: usize, k: usize) -> Vec<Vec<usize>> {
        let mut out = Vec::new();
        let mut chosen = Vec::new();
        fn walk(start: usize, n: usize, k: usize, chosen: &mut Vec<usize>, out: &mut Vec<Vec<usize>>) {
            if chosen.len() == k {
                out.push(chosen.clone());
                return;
            }
            for index in start..n {
                chosen.push(index);
                walk(index + 1, n, k, chosen, out);
                chosen.pop();
            }
        }
        walk(0, n, k, &mut chosen, &mut out);
        out
    }

    #[test]
    fn every_3_of_5_subset_restores_and_every_pair_fails() {
        let secret = b"break-glass signing key\0\xff";
        let (sealed, shares) = split_of(secret, 3, 5);
        assert_eq!(shares.len(), 5);
        for subset in combinations(5, 3) {
            let picked: Vec<_> = subset.into_iter().map(|index| shares[index].clone()).collect();
            assert_eq!(restore_with(&sealed, &picked).unwrap(), secret);
        }
        for subset in combinations(5, 2) {
            let picked: Vec<_> = subset.into_iter().map(|index| shares[index].clone()).collect();
            let err = restore_with(&sealed, &picked).unwrap_err();
            assert!(err.contains("need at least 3"), "{err}");
        }
        let mut reversed = shares.clone();
        reversed.reverse();
        assert_eq!(restore_with(&sealed, &reversed).unwrap(), secret);
        let mut too_many = shares.clone();
        too_many.push(shares[0].clone());
        let err = restore_with(&sealed, &too_many).unwrap_err();
        assert!(err.contains("duplicate share") || err.contains("more shares"), "{err}");
    }

    #[test]
    fn chunk_boundaries_and_binary_secrets_roundtrip() {
        for size in [0, 1, 64 * 1024 - 1, 64 * 1024, 64 * 1024 + 1, 128 * 1024 + 7] {
            let secret: Vec<u8> = (0..size).map(|index| (index % 251) as u8).collect();
            roundtrip(&secret, 3, &[None, None, None, None, None]);
        }
        roundtrip(&[0u8; 100], 2, &[None, None]);
        roundtrip(&[0xff; 100], 2, &[None, None]);
        roundtrip(b"AGRSAGRH", 1, &[None]);
    }

    #[test]
    fn distinct_passwords_and_swapped_bodies_fail_closed() {
        let dir = TempDir::new();
        let engine = engine(&dir);
        let passwords = [
            Some(Password::new("one".to_owned()).unwrap()),
            Some(Password::new("two".to_owned()).unwrap()),
            Some(Password::new("three".to_owned()).unwrap()),
            None,
            None,
        ];
        let secret = b"quorum secret";
        let mut sealed = Vec::new();
        let policy = policy_of(3, passwords.len());
        let split = engine
            .split(&mut Cursor::new(secret), &mut sealed, &policy, 32, &passwords, None)
            .unwrap();
        let mut restored = Vec::new();
        engine
            .restore(
                Cursor::new(sealed.clone()),
                &mut restored,
                &split.shares[0..3],
                &passwords[0..3],
            )
            .unwrap();
        assert_eq!(restored, secret);

        let mut swapped = split.shares.clone();
        swapped.swap(0, 1);
        let err = engine
            .restore(
                Cursor::new(sealed.clone()),
                &mut restored,
                &swapped[0..3],
                &passwords[0..3],
            )
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("decryption failed") || err.contains("authentication failed"),
            "{err}"
        );

        let err = engine
            .restore(Cursor::new(sealed.clone()), &mut restored, &split.shares[0..3], &[
                passwords[0].clone(),
                None,
                passwords[2].clone(),
            ])
            .unwrap_err()
            .to_string();
        assert!(err.contains("password protected"), "{err}");

        let err = engine
            .restore(Cursor::new(sealed), &mut restored, &split.shares, &passwords[0..4])
            .unwrap_err()
            .to_string();
        assert!(err.contains("password count"), "{err}");
    }

    #[test]
    fn tampered_unprotected_share_does_not_emit_a_secret() {
        let (sealed, mut shares) = split_of(b"do-not-emit", 2, 3);
        let last = shares[0].len() - 1;
        shares[0][last] ^= 0x5a;
        let err = restore_with(&sealed, &shares).unwrap_err();
        assert!(
            err.contains("authentication failed")
                || err.contains("does not belong")
                || err.contains("not an agree share"),
            "{err}"
        );
    }

    #[test]
    fn key_size_is_a_multiple_of_32_and_each_layer_is_required() {
        roundtrip_with_key(b"layered-secret", 2, 64, &[None, None]);
        let mut large = vec![7u8; 70_000];
        large[69_999] = 9;
        roundtrip_with_key(&large, 2, 96, &[None, None, None]);
        let dir = TempDir::new();
        let engine = engine(&dir);
        let one = policy_of(1, 1);
        let err = engine
            .split(&mut Cursor::new(b"x"), &mut Vec::new(), &one, 48, &[None], None)
            .err()
            .expect("48-byte key must fail")
            .to_string();
        assert!(err.contains("multiple of 32"), "{err}");
        let err = engine
            .split(&mut Cursor::new(b"x"), &mut Vec::new(), &one, 0, &[None], None)
            .err()
            .expect("empty key must fail")
            .to_string();
        assert!(err.contains("multiple of 32"), "{err}");
    }

    fn roundtrip_with_key(secret: &[u8], threshold: u8, key_bytes: u16, passwords: &[Option<Password>]) {
        let dir = TempDir::new();
        let engine = engine(&dir);
        let mut sealed = Vec::new();
        let policy = policy_of(threshold, passwords.len());
        let split = engine
            .split(
                &mut Cursor::new(secret),
                &mut sealed,
                &policy,
                key_bytes,
                passwords,
                None,
            )
            .unwrap();
        assert_eq!(split.key_bytes, key_bytes);
        let mut restored = Vec::new();
        engine
            .restore(Cursor::new(&sealed), &mut restored, &split.shares, passwords)
            .unwrap();
        assert_eq!(restored, secret);
        let mut short = split.shares.clone();
        // A 32-byte reconstruction cannot open a wider key. Damage the Shamir body
        // length so the share no longer carries the full key, and restore must
        // fail closed.
        let end = short[0].len();
        short[0][end - 1] ^= 0xff;
        assert!(engine
            .restore(Cursor::new(sealed), &mut Vec::new(), &short, passwords)
            .is_err());
    }

    #[test]
    fn rejects_invalid_schemes_and_foreign_shares() {
        let err = Policy::uniform(0, 1).unwrap_err().to_string();
        assert!(err.contains("greater than 0"), "{err}");
        let err = Policy::uniform(3, 2).unwrap_err().to_string();
        assert!(err.contains("exceeds"), "{err}");

        let (sealed_a, shares_a) = split_of(b"alpha", 2, 2);
        let (_sealed_b, shares_b) = split_of(b"beta", 2, 2);
        let mixed = vec![shares_a[0].clone(), shares_b[1].clone()];
        let err = restore_with(&sealed_a, &mixed).unwrap_err();
        assert!(err.contains("does not belong"), "{err}");
        assert!(restore_with(&sealed_a, &[]).unwrap_err().contains("at least one share"));
    }

    #[test]
    fn provided_key_is_the_key_that_is_split() {
        let dir = TempDir::new();
        let engine = engine(&dir);
        let mut raw = vec![0xA5u8; 64];
        raw[0] = 0x11;
        raw[63] = 0xee;
        let secret = b"external-key-secret";
        let mut sealed = Vec::new();
        let policy = policy_of(2, 2);
        let split = engine
            .split(
                &mut Cursor::new(&secret[..]),
                &mut sealed,
                &policy,
                64,
                &[None, None],
                Some(DataKey::from_bytes(raw.clone()).unwrap()),
            )
            .unwrap();
        let mut points = Vec::new();
        for bytes in &split.shares {
            let record = ShareRecord::decode(bytes).unwrap();
            let parsed = super::parse_points(&record.body, record.index, 64, &record.policy).unwrap();
            assert_eq!(parsed.len(), 1);
            points.extend(parsed.into_iter().flat_map(|dealt| dealt.points));
        }
        let recovered = super::recover(&points, 2, 64).unwrap();
        assert_eq!(recovered.as_bytes(), raw.as_slice());
        let mut restored = Vec::new();
        engine
            .restore(Cursor::new(&sealed), &mut restored, &split.shares, &[None, None])
            .unwrap();
        assert_eq!(restored, secret);

        let mut empty = Vec::new();
        let one = policy_of(1, 1);
        let err = engine
            .split(
                &mut Cursor::new(b"x"),
                &mut empty,
                &one,
                64,
                &[None],
                Some(DataKey::from_bytes(vec![1; 32]).unwrap()),
            )
            .err()
            .expect("a short provided key must fail")
            .to_string();
        assert!(err.contains("does not match"), "{err}");
        assert!(empty.is_empty(), "a rejected key must not start a sealed file");
    }

    #[test]
    fn weight_and_a_second_quorum_are_enforced() {
        let dir = TempDir::new();
        let engine = engine(&dir);
        let weighted = Policy::single(2, &[2, 1, 1]).unwrap();
        let mut sealed = Vec::new();
        let split = engine
            .split(
                &mut Cursor::new(b"weighted"),
                &mut sealed,
                &weighted,
                32,
                &[None, None, None],
                None,
            )
            .unwrap();
        let mut restored = Vec::new();
        engine
            .restore(Cursor::new(&sealed), &mut restored, &split.shares[0..1], &[None])
            .unwrap();
        assert_eq!(restored, b"weighted");
        let err = engine
            .restore(Cursor::new(&sealed), &mut Vec::new(), &split.shares[1..2], &[None])
            .unwrap_err()
            .to_string();
        assert!(err.contains("needs weight 2"), "{err}");
        restored.clear();
        engine
            .restore(Cursor::new(&sealed), &mut restored, &split.shares[1..], &[None, None])
            .unwrap();
        assert_eq!(restored, b"weighted");

        let specs = vec!["1:1,2".to_string(), "2:2,3,4".to_string()];
        let both = Policy::from_args(4, None, &[], &specs).unwrap();
        let mut sealed = Vec::new();
        let split = engine
            .split(
                &mut Cursor::new(b"both-quorums"),
                &mut sealed,
                &both,
                32,
                &[None, None, None, None],
                Some(DataKey::from_bytes(vec![0x5a; 32]).unwrap()),
            )
            .unwrap();
        let err = engine
            .restore(Cursor::new(&sealed), &mut Vec::new(), &split.shares[0..2], &[
                None, None,
            ])
            .unwrap_err()
            .to_string();
        assert!(err.contains("quorum 2"), "{err}");
        restored.clear();
        engine
            .restore(Cursor::new(&sealed), &mut restored, &split.shares[1..], &[
                None, None, None,
            ])
            .unwrap();
        assert_eq!(restored, b"both-quorums");
    }

    #[test]
    fn authentication_failure_does_not_emit_a_prefix() {
        let dir = TempDir::new();
        let policy = policy_of(1, 1);
        let cipher = crate::crypto::SecretCipher::generate([1u8; 16], policy.bytes(), 32).unwrap();
        let path = dir.0.join("staged");
        let mut file = crate::store::create_private_file(&path).unwrap();
        let first = cipher.encrypt_chunk(0, false, b"prefix-secret").unwrap();
        super::write_frame(&mut file, false, &first).unwrap();
        super::write_frame(&mut file, true, &[0u8; 32]).unwrap();
        drop(file);
        let staged = super::StagedSealed {
            path,
            header: crate::format::SealedHeader {
                key_bytes: 32,
                group: [1u8; 16],
                nonce_prefix: *cipher.nonce_prefix(),
                policy,
            },
            commitment: [0u8; 32],
        };
        let mut out = Vec::new();
        assert!(super::decrypt_staged(&cipher, &staged, &mut out).is_err());
        assert!(out.is_empty());
    }
}
