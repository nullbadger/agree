//! Who can restore.
//!
//! One quorum is a Shamir threshold. A weight is how many points of that deal
//! sit in one custodian's file. Further quorums are not further copies of the
//! data key: each quorum splits its own pad, and the pads XOR to the key. A
//! set that misses a quorum learns nothing about that pad.
//!
//! The bytes are canonical. Members are in custodian-index order, and a share
//! that is not in that order is rejected. Split writes these bytes into the
//! sealed header and into every share. The chunk authenticator binds them.

use anyhow::{
    bail,
    Context,
    Result,
};

/// Largest policy this binary will write or read. A ceremony is much smaller.
pub(crate) const MAX_POLICY_LEN: usize = 4096;
/// Enough for a ceremony. Not a second access-structure language.
pub(crate) const MAX_QUORUMS: usize = 32;

/// A shortfall in one quorum. `quorum` is 1-based, matching the summary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Shortfall {
    pub(crate) quorum: u8,
    pub(crate) need: u8,
    pub(crate) got: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Policy {
    bytes: Vec<u8>,
    count: u8,
    quorums: Vec<Quorum>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Quorum {
    threshold: u8,
    members: Vec<Member>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Member {
    index: u8,
    weight: u8,
}

impl Policy {
    pub(crate) fn count(&self) -> u8 {
        self.count
    }

    pub(crate) fn quorums(&self) -> &[Quorum] {
        &self.quorums
    }

    /// Exact bytes written into the sealed header, the shares, and the AAD.
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// One quorum, weight 1 for custodians `1..=count`. This is `--threshold`.
    pub(crate) fn uniform(threshold: u8, count: u8) -> Result<Self> {
        if count == 0 {
            bail!("threshold and share count must be greater than 0");
        }
        let weights = vec![1u8; usize::from(count)];
        Self::single(threshold, &weights)
    }

    /// One quorum. `weights` is in `--share` order.
    pub(crate) fn single(threshold: u8, weights: &[u8]) -> Result<Self> {
        let count = u8::try_from(weights.len()).context("too many shares")?;
        if count == 0 || threshold == 0 {
            bail!("threshold and share count must be greater than 0");
        }
        let members = weights
            .iter()
            .enumerate()
            .map(|(offset, weight)| {
                Member {
                    index: u8::try_from(offset + 1).expect("count fits in u8"),
                    weight: *weight,
                }
            })
            .collect();
        Self::build(count, vec![Quorum { threshold, members }])
    }

    pub(crate) fn from_args(
        share_count: usize,
        threshold: Option<u8>,
        weights: &[u8],
        quorums: &[String],
    ) -> Result<Self> {
        let count = u8::try_from(share_count).context("too many shares")?;
        if count == 0 {
            bail!("at least one share is required");
        }
        if !quorums.is_empty() {
            if threshold.is_some() {
                bail!("--threshold cannot be combined with --quorum");
            }
            if !weights.is_empty() {
                bail!("--weight cannot be combined with --quorum");
            }
            return Self::from_specs(count, quorums);
        }
        let threshold = threshold.context("--threshold is required")?;
        if weights.is_empty() {
            return Self::uniform(threshold, count);
        }
        if weights.len() != share_count {
            bail!("--weight must be given once per --share");
        }
        Self::single(threshold, weights)
    }

    /// `Some(threshold)` only for the `--threshold` case: one quorum, every
    /// weight 1.
    pub(crate) fn uniform_threshold(&self) -> Option<u8> {
        let [quorum] = self.quorums.as_slice() else {
            return None;
        };
        if quorum.members.len() != usize::from(self.count) {
            return None;
        }
        if quorum.members.iter().any(|member| member.weight != 1) {
            return None;
        }
        if quorum
            .members
            .iter()
            .enumerate()
            .any(|(offset, member)| member.index != u8::try_from(offset + 1).unwrap_or(0))
        {
            return None;
        }
        Some(quorum.threshold)
    }

    /// Quorums this custodian belongs to, in policy order. `(quorum index,
    /// weight)`, 1-based.
    pub(crate) fn membership(&self, index: u8) -> Vec<(u8, u8)> {
        self.quorums
            .iter()
            .enumerate()
            .filter_map(|(offset, quorum)| {
                quorum
                    .members
                    .iter()
                    .find(|member| member.index == index)
                    .map(|member| (u8::try_from(offset + 1).expect("quorum count fits"), member.weight))
            })
            .collect()
    }

    /// First quorum whose presented weight is short, if any.
    pub(crate) fn shortfall(&self, present: &[u8]) -> Option<Shortfall> {
        for (offset, quorum) in self.quorums.iter().enumerate() {
            let got = quorum.presented_weight(present);
            if got < u16::from(quorum.threshold) {
                return Some(Shortfall {
                    quorum: u8::try_from(offset + 1).expect("quorum count fits"),
                    need: quorum.threshold,
                    got: u8::try_from(got).expect("presented weight fits"),
                });
            }
        }
        None
    }

    /// Custodians who meet every quorum without anyone else.
    pub(crate) fn lone_custodians(&self) -> Vec<u8> {
        (1..=self.count)
            .filter(|index| self.shortfall(&[*index]).is_none())
            .collect()
    }

    pub(crate) fn describe(&self) -> String {
        let mut out = String::new();
        for (offset, quorum) in self.quorums.iter().enumerate() {
            let members = quorum
                .members
                .iter()
                .map(|member| format!("share {} weight {}", member.index, member.weight))
                .collect::<Vec<_>>()
                .join(", ");
            out.push_str(&format!(
                "quorum {}: threshold {}, {members}\n",
                offset + 1,
                quorum.threshold
            ));
        }
        out.push_str("every quorum must be met\n");
        out
    }

    fn from_specs(count: u8, specs: &[String]) -> Result<Self> {
        if specs.len() > MAX_QUORUMS {
            bail!("at most {MAX_QUORUMS} quorums");
        }
        let mut quorums = Vec::with_capacity(specs.len());
        for spec in specs {
            quorums.push(parse_spec(spec, count)?);
        }
        Self::build(count, quorums)
    }

    fn build(count: u8, quorums: Vec<Quorum>) -> Result<Self> {
        validate(count, &quorums)?;
        let bytes = render(count, &quorums)?;
        Ok(Self { bytes, count, quorums })
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_POLICY_LEN {
            bail!("policy is too large");
        }
        let (count, quorums) = parse(bytes)?;
        let built = Self::build(count, quorums)?;
        if built.bytes != bytes {
            bail!("invalid policy");
        }
        Ok(built)
    }
}

impl Quorum {
    pub(crate) fn threshold(&self) -> u8 {
        self.threshold
    }

    pub(crate) fn members(&self) -> &[Member] {
        &self.members
    }

    pub(crate) fn total_weight(&self) -> usize {
        self.members.iter().map(|member| usize::from(member.weight)).sum()
    }

    fn presented_weight(&self, present: &[u8]) -> u16 {
        self.members
            .iter()
            .filter(|member| present.contains(&member.index))
            .map(|member| u16::from(member.weight))
            .sum()
    }
}

impl Member {
    pub(crate) fn index(&self) -> u8 {
        self.index
    }

    pub(crate) fn weight(&self) -> u8 {
        self.weight
    }
}

fn validate(count: u8, quorums: &[Quorum]) -> Result<()> {
    if count == 0 || quorums.is_empty() {
        bail!("threshold and share count must be greater than 0");
    }
    if quorums.len() > MAX_QUORUMS {
        bail!("at most {MAX_QUORUMS} quorums");
    }
    let mut seen = vec![false; usize::from(count)];
    let uniform = quorums.len() == 1 && quorums[0].members.iter().all(|member| member.weight == 1);
    for (offset, quorum) in quorums.iter().enumerate() {
        let number = offset + 1;
        if quorum.threshold == 0 {
            bail!("threshold and share count must be greater than 0");
        }
        if quorum.members.is_empty() {
            bail!("quorum {number} has no shares");
        }
        let mut sum = 0u16;
        let mut previous = 0u8;
        for member in &quorum.members {
            if member.index == 0 || member.index > count {
                bail!("quorum index {} is not a share", member.index);
            }
            if member.weight == 0 {
                bail!("weight must be greater than 0");
            }
            if member.index <= previous {
                bail!("share {} is listed twice in one quorum", member.index);
            }
            previous = member.index;
            seen[usize::from(member.index - 1)] = true;
            sum = sum.saturating_add(u16::from(member.weight));
        }
        if sum > 255 {
            bail!("quorum {number} has too many points");
        }
        if u16::from(quorum.threshold) > sum {
            if uniform {
                bail!("threshold {} exceeds share count {count}", quorum.threshold);
            }
            bail!(
                "threshold {} exceeds the weight of quorum {number} ({sum})",
                quorum.threshold
            );
        }
    }
    if let Some(index) = seen.iter().position(|present| !present) {
        bail!("share {} is in no quorum", index + 1);
    }
    Ok(())
}

fn render(count: u8, quorums: &[Quorum]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    out.push(count);
    let n_quorums = u8::try_from(quorums.len()).context("too many quorums")?;
    out.push(n_quorums);
    for quorum in quorums {
        out.push(quorum.threshold);
        let n_members = u8::try_from(quorum.members.len()).context("too many shares in one quorum")?;
        out.push(n_members);
        for member in &quorum.members {
            out.push(member.index);
            out.push(member.weight);
        }
    }
    if out.len() > MAX_POLICY_LEN {
        bail!("policy is too large");
    }
    Ok(out)
}

fn parse(bytes: &[u8]) -> Result<(u8, Vec<Quorum>)> {
    if bytes.len() < 2 {
        bail!("invalid policy");
    }
    let count = bytes[0];
    let n_quorums = usize::from(bytes[1]);
    if count == 0 || n_quorums == 0 {
        bail!("invalid policy");
    }
    let mut rest = &bytes[2..];
    let mut quorums = Vec::with_capacity(n_quorums);
    for _ in 0..n_quorums {
        if rest.len() < 2 {
            bail!("invalid policy");
        }
        let threshold = rest[0];
        let n_members = usize::from(rest[1]);
        rest = &rest[2..];
        if n_members == 0 || rest.len() < n_members.saturating_mul(2) {
            bail!("invalid policy");
        }
        let mut members = Vec::with_capacity(n_members);
        for _ in 0..n_members {
            members.push(Member {
                index: rest[0],
                weight: rest[1],
            });
            rest = &rest[2..];
        }
        quorums.push(Quorum { threshold, members });
    }
    if !rest.is_empty() {
        bail!("invalid policy");
    }
    Ok((count, quorums))
}

fn parse_spec(spec: &str, count: u8) -> Result<Quorum> {
    let (threshold_text, members_text) = spec
        .split_once(':')
        .context("quorum spec must be THRESHOLD:INDEX[=WEIGHT],INDEX[=WEIGHT],...")?;
    if members_text.is_empty() {
        bail!("quorum spec must be THRESHOLD:INDEX[=WEIGHT],INDEX[=WEIGHT],...");
    }
    let threshold: u8 = threshold_text.parse().context("quorum threshold must be 1 to 255")?;
    let mut members = Vec::new();
    for part in members_text.split(',') {
        if part.is_empty() {
            bail!("quorum spec must be THRESHOLD:INDEX[=WEIGHT],INDEX[=WEIGHT],...");
        }
        let (index_text, weight) = match part.split_once('=') {
            | Some((index, weight_text)) => {
                let weight = weight_text.parse::<u8>().context("quorum weight must be 1 to 255")?;
                (index, weight)
            },
            | None => (part, 1u8),
        };
        let index = index_text
            .parse::<u8>()
            .context("quorum share index must be 1 to 255")?;
        if index == 0 || index > count {
            bail!("quorum index {index} is not a share");
        }
        if weight == 0 {
            bail!("weight must be greater than 0");
        }
        if members.iter().any(|member: &Member| member.index == index) {
            bail!("share {index} is listed twice in one quorum");
        }
        members.push(Member { index, weight });
    }
    members.sort_by_key(|member| member.index);
    Ok(Quorum { threshold, members })
}

#[cfg(test)]
mod tests {
    use super::Policy;

    #[test]
    fn uniform_bytes_roundtrip_and_a_short_set_is_named() {
        let policy = Policy::uniform(3, 5).unwrap();
        assert_eq!(policy.bytes(), &[5, 1, 3, 5, 1, 1, 2, 1, 3, 1, 4, 1, 5, 1]);
        assert_eq!(policy.uniform_threshold(), Some(3));
        assert!(Policy::decode(policy.bytes()).unwrap().bytes() == policy.bytes());
        let short = policy.shortfall(&[1, 2]).unwrap();
        assert_eq!(short.need, 3);
        assert_eq!(short.got, 2);
        assert!(policy.shortfall(&[1, 4, 5]).is_none());
        assert!(policy.lone_custodians().is_empty());
    }

    #[test]
    fn weight_and_a_second_quorum_are_the_access_structure() {
        let weighted = Policy::single(2, &[2, 1, 1]).unwrap();
        assert_eq!(weighted.uniform_threshold(), None);
        assert_eq!(weighted.lone_custodians(), vec![1]);
        assert!(weighted.shortfall(&[2]).is_some());
        assert!(weighted.shortfall(&[2, 3]).is_none());
        assert!(weighted.shortfall(&[1]).is_none());

        let specs = vec!["1:1,2".to_string(), "2:2=1,3,4".to_string()];
        let both = Policy::from_args(4, None, &[], &specs).unwrap();
        assert!(both.shortfall(&[1, 2]).is_some());
        assert!(both.shortfall(&[2, 3, 4]).is_none());
        assert_eq!(both.membership(2), vec![(1, 1), (2, 1)]);
        assert!(Policy::decode(both.bytes()).unwrap() == both);
    }

    #[test]
    fn rejects_a_policy_that_cannot_be_met_or_is_not_canonical() {
        let err = Policy::uniform(0, 1).unwrap_err().to_string();
        assert!(err.contains("greater than 0"), "{err}");
        let err = Policy::uniform(3, 2).unwrap_err().to_string();
        assert!(err.contains("exceeds"), "{err}");
        let err = Policy::from_args(2, Some(2), &[2], &[]).unwrap_err().to_string();
        assert!(err.contains("once per"), "{err}");
        let err = Policy::from_args(2, Some(1), &[], &["1:1".to_string()])
            .unwrap_err()
            .to_string();
        assert!(err.contains("cannot be combined"), "{err}");
        let err = Policy::from_args(2, None, &[], &["1:1".to_string()])
            .unwrap_err()
            .to_string();
        assert!(err.contains("no quorum"), "{err}");
        let mut bytes = Policy::uniform(1, 1).unwrap().bytes().to_vec();
        bytes.push(0);
        assert!(Policy::decode(&bytes).is_err());
    }
}
