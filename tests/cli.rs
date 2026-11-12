//! End-to-end coverage that does not open a YubiKey.
//! The secret is always piped to `split` and captured from `restore` stdout.
//! `device:` paths are ordinary files.

use std::{
    fs,
    io::{Read, Write},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

fn agree() -> Command {
    Command::new(env!("CARGO_BIN_EXE_agree"))
}

struct Temp(PathBuf);

impl Temp {
    fn new() -> Self {
        let mut name = [0u8; 8];
        fs::File::open("/dev/urandom")
            .expect("urandom")
            .read_exact(&mut name)
            .unwrap();
        let path = std::env::temp_dir().join(format!(
            "agree-cli-{}",
            name.iter().map(|byte| format!("{byte:02x}")).collect::<String>()
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn run_in(dir: &Path, args: &[&str], stdin: &[u8]) -> Output {
    let mut child = agree()
        .current_dir(dir)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(stdin).unwrap();
    child.wait_with_output().unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn assert_ok(output: &Output) {
    assert!(output.status.success(), "{}", stderr(output));
}

fn assert_err(output: &Output, needle: &str) {
    assert!(
        !output.status.success(),
        "expected failure containing {needle}, stderr={}",
        stderr(output)
    );
    assert!(
        stderr(output).contains(needle),
        "stderr did not contain {needle:?}: {}",
        stderr(output)
    );
}

fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

struct Ceremony {
    dir: Temp,
    secret: Vec<u8>,
}

impl Ceremony {
    fn split(secret: &[u8], threshold: &str, names: &[&str]) -> Self {
        let dir = Temp::new();
        let mut args = vec!["split", "--threshold", threshold, "--sealed", "sealed.bin"];
        for name in names {
            args.push("--share");
            args.push(name);
        }
        assert_ok(&run_in(&dir.0, &args, secret));
        Self {
            dir,
            secret: secret.to_vec(),
        }
    }

    fn restore(&self, shares: &[&str]) -> Vec<u8> {
        let mut args = vec!["restore", "--sealed", "sealed.bin"];
        for share in shares {
            args.push("--share");
            args.push(share);
        }
        let output = run_in(&self.dir.0, &args, b"");
        assert_ok(&output);
        assert_eq!(output.stdout, self.secret);
        assert!(
            stderr(&output).is_empty() || !stderr(&output).contains(std::str::from_utf8(&self.secret).unwrap_or(""))
        );
        output.stdout
    }
}

#[test]
fn three_of_five_quorum_restores_on_stdout() {
    let secret = b"break-glass signing key";
    let ceremony = Ceremony::split(secret, "3", &["a.share", "b.share", "c.share", "d.share", "e.share"]);
    for share in ["a.share", "b.share", "c.share", "d.share", "e.share"] {
        assert_eq!(mode(&ceremony.dir.path(share)), 0o600);
        let bytes = fs::read(ceremony.dir.path(share)).unwrap();
        assert!(!bytes.windows(secret.len()).any(|window| window == secret));
    }
    assert!(!fs::read(ceremony.dir.path("sealed.bin"))
        .unwrap()
        .windows(secret.len())
        .any(|window| window == secret));
    ceremony.restore(&["a.share", "c.share", "e.share"]);
    ceremony.restore(&["e.share", "d.share", "b.share", "a.share"]);
    let err = run_in(
        &ceremony.dir.0,
        &[
            "restore",
            "--sealed",
            "sealed.bin",
            "--share",
            "a.share",
            "--share",
            "b.share",
        ],
        b"",
    );
    assert_err(&err, "need at least 3");
    assert!(err.stdout.is_empty());
}

#[test]
fn device_paths_carry_a_binary_secret_to_stdout() {
    let mut secret = vec![0u8; 70_000];
    secret[0] = 0;
    secret[1] = 0xff;
    secret[65_535] = 7;
    secret[69_999] = 9;
    let dir = Temp::new();
    fs::write(dir.path("device-share"), b"old").unwrap();
    fs::write(dir.path("device-sealed"), b"old-sealed-bytes").unwrap();
    assert_ok(&run_in(
        &dir.0,
        &[
            "split",
            "--threshold",
            "2",
            "--sealed",
            &format!("device:{}", dir.path("device-sealed").display()),
            "--share",
            "plain.share",
            "--share",
            &format!("device:{}", dir.path("device-share").display()),
            "--force",
        ],
        &secret,
    ));
    let restored = run_in(
        &dir.0,
        &[
            "restore",
            "--sealed",
            &format!("device:{}", dir.path("device-sealed").display()),
            "--share",
            "plain.share",
            "--share",
            &format!("device:{}", dir.path("device-share").display()),
        ],
        b"",
    );
    assert_ok(&restored);
    assert_eq!(restored.stdout, secret);
}

#[test]
fn refuses_unsafe_or_ambiguous_invocations() {
    let dir = Temp::new();
    fs::write(dir.path("existing.share"), b"keep").unwrap();
    assert_err(
        &run_in(
            &dir.0,
            &[
                "split",
                "--threshold",
                "1",
                "--sealed",
                "sealed.bin",
                "--share",
                "existing.share",
            ],
            b"secret",
        ),
        "--force",
    );
    assert_eq!(fs::read(dir.path("existing.share")).unwrap(), b"keep");

    fs::write(dir.path("node"), b"x").unwrap();
    assert_err(
        &run_in(
            &dir.0,
            &[
                "split",
                "--threshold",
                "1",
                "--sealed",
                "sealed.bin",
                "--share",
                "device:node",
            ],
            b"secret",
        ),
        "--force",
    );
    assert_err(
        &run_in(
            &dir.0,
            &[
                "split",
                "--threshold",
                "1",
                "--sealed",
                "sealed.bin",
                "--share",
                "device:missing-node",
                "--force",
            ],
            b"secret",
        ),
        "does not exist",
    );
    assert_err(
        &run_in(
            &dir.0,
            &[
                "split",
                "--threshold",
                "2",
                "--sealed",
                "sealed.bin",
                "--share",
                "only.share",
            ],
            b"secret",
        ),
        "exceeds",
    );
    assert_err(
        &run_in(
            &dir.0,
            &[
                "split",
                "--threshold",
                "0",
                "--sealed",
                "sealed.bin",
                "--share",
                "only.share",
            ],
            b"secret",
        ),
        "greater than 0",
    );
    assert_err(
        &run_in(
            &dir.0,
            &[
                "split",
                "--threshold",
                "1",
                "--sealed",
                "same.share",
                "--share",
                "same.share",
            ],
            b"secret",
        ),
        "same destination",
    );
    assert_err(
        &run_in(
            &dir.0,
            &[
                "split",
                "--threshold",
                "1",
                "--sealed",
                "sealed.bin",
                "--share",
                "a.share",
                "--share",
                "a.share",
            ],
            b"secret",
        ),
        "duplicate destination",
    );
    assert_err(
        &run_in(
            &dir.0,
            &[
                "split",
                "--threshold",
                "1",
                "--sealed",
                "sealed.bin",
                "--share",
                "a.share",
                "--protect",
            ],
            b"secret",
        ),
        "terminal",
    );
    let help = run_in(&dir.0, &["split", "--help"], b"");
    assert_ok(&help);
    let text = String::from_utf8_lossy(&help.stdout);
    assert!(text.contains("stdin"));
    assert!(text.contains("--key-file"));
    assert!(!text.contains("--secret"));
    assert!(!text.contains("--output"));
}

#[test]
fn failed_second_share_rolls_back_the_first() {
    let dir = Temp::new();
    fs::create_dir(dir.path("blocked")).unwrap();
    let err = run_in(
        &dir.0,
        &[
            "split",
            "--threshold",
            "2",
            "--sealed",
            "sealed.bin",
            "--share",
            "first.share",
            "--share",
            "blocked",
        ],
        b"secret",
    );
    assert!(!err.status.success(), "{}", stderr(&err));
    assert!(!dir.path("first.share").exists(), "partial share set was left behind");
}

#[test]
fn force_replaces_and_mixed_or_damaged_shares_fail() {
    let dir = Temp::new();
    fs::write(dir.path("a.share"), b"old").unwrap();
    assert_ok(&run_in(
        &dir.0,
        &[
            "split",
            "--threshold",
            "1",
            "--sealed",
            "sealed.bin",
            "--share",
            "a.share",
            "--force",
        ],
        b"first",
    ));
    assert_ne!(fs::read(dir.path("a.share")).unwrap(), b"old");

    assert_ok(&run_in(
        &dir.0,
        &[
            "split",
            "--threshold",
            "2",
            "--sealed",
            "other-sealed.bin",
            "--share",
            "b.share",
            "--share",
            "c.share",
        ],
        b"other",
    ));
    assert_err(
        &run_in(
            &dir.0,
            &[
                "restore",
                "--sealed",
                "sealed.bin",
                "--share",
                "a.share",
                "--share",
                "c.share",
            ],
            b"",
        ),
        "does not belong",
    );
    assert_err(
        &run_in(
            &dir.0,
            &[
                "restore",
                "--sealed",
                "sealed.bin",
                "--share",
                "a.share",
                "--share",
                "a.share",
            ],
            b"",
        ),
        "duplicate",
    );

    let mut sealed = fs::read(dir.path("sealed.bin")).unwrap();
    sealed.push(0xff);
    fs::write(dir.path("sealed-junk.bin"), &sealed).unwrap();
    let junk = run_in(
        &dir.0,
        &["restore", "--sealed", "sealed-junk.bin", "--share", "a.share"],
        b"",
    );
    assert_ok(&junk);
    assert_eq!(junk.stdout, b"first");

    sealed[10] ^= 0x01;
    fs::write(dir.path("sealed-bad.bin"), &sealed).unwrap();
    let bad = run_in(
        &dir.0,
        &["restore", "--sealed", "sealed-bad.bin", "--share", "a.share"],
        b"",
    );
    assert!(!bad.status.success(), "{}", stderr(&bad));
    assert!(bad.stdout.is_empty());

    let mut share = fs::read(dir.path("a.share")).unwrap();
    let end = share.len() - 1;
    share[end] ^= 0x11;
    fs::write(dir.path("a-bad.share"), share).unwrap();
    let bad_share = run_in(
        &dir.0,
        &["restore", "--sealed", "sealed.bin", "--share", "a-bad.share"],
        b"",
    );
    assert!(!bad_share.status.success(), "{}", stderr(&bad_share));
    assert!(bad_share.stdout.is_empty());
    assert_err(
        &run_in(
            &dir.0,
            &["restore", "--sealed", "missing-sealed.bin", "--share", "a.share"],
            b"",
        ),
        "Failed to open",
    );
}

#[test]
fn threshold_one_warns_and_restore_stdout_is_only_the_secret() {
    let dir = Temp::new();
    let split = run_in(
        &dir.0,
        &[
            "split",
            "--threshold",
            "1",
            "--sealed",
            "sealed.bin",
            "--share",
            "a.share",
        ],
        b"tilde",
    );
    assert_ok(&split);
    assert!(stderr(&split).contains("threshold 1"), "{}", stderr(&split));
    let restored = run_in(
        &dir.0,
        &["restore", "--sealed", "sealed.bin", "--share", "a.share"],
        b"",
    );
    assert_ok(&restored);
    assert_eq!(restored.stdout, b"tilde");
}

#[test]
fn yubikey_arguments_that_fail_before_any_card_is_opened() {
    let dir = Temp::new();
    assert_err(
        &run_in(
            &dir.0,
            &[
                "split",
                "--threshold",
                "1",
                "--sealed",
                "sealed.bin",
                "--share",
                "yubikey:00ff",
            ],
            b"secret",
        ),
        "5f0000-5fffff",
    );
    let two_keys = run_in(
        &dir.0,
        &[
            "split",
            "--threshold",
            "1",
            "--sealed",
            "sealed.bin",
            "--share",
            "yubikey:1/5fff20",
            "--share",
            "yubikey:2/5fff21",
        ],
        b"secret",
    );
    assert_err(&two_keys, "terminal");
    assert!(
        !stderr(&two_keys).contains("only one YubiKey"),
        "split must accept more than one YubiKey serial"
    );
    assert!(
        !dir.path("sealed.bin").exists(),
        "split wrote a sealed file before the YubiKey prompt"
    );
    assert_err(
        &run_in(
            &dir.0,
            &[
                "split",
                "--threshold",
                "1",
                "--sealed",
                "sealed.bin",
                "--share",
                "yubikey:5fff20",
            ],
            b"secret",
        ),
        "terminal",
    );
    assert_err(
        &run_in(
            &dir.0,
            &[
                "split",
                "--threshold",
                "1",
                "--sealed",
                "sealed.bin",
                "--share",
                "yubikey:1/5fff20",
                "--share",
                "yubikey:2/5fff21",
                "--management-key",
                "zz",
            ],
            b"secret",
        ),
        "hex",
    );
    assert_err(
        &run_in(
            &dir.0,
            &[
                "split",
                "--threshold",
                "1",
                "--sealed",
                "sealed.bin",
                "--share",
                "yubikey:5fc105",
            ],
            b"secret",
        ),
        "reserved",
    );
    assert_err(
        &run_in(
            &dir.0,
            &[
                "restore",
                "--sealed",
                "sealed.bin",
                "--share",
                "yubikey:5fff20",
                "--pin-stdin",
                "--management-key",
                "zz",
            ],
            b"123456\n",
        ),
        "hex",
    );
    let omitted = run_in(
        &dir.0,
        &[
            "restore",
            "--sealed",
            "sealed.bin",
            "--share",
            "yubikey:5fff20",
            "--pin-stdin",
        ],
        b"123456789\n",
    );
    assert!(!omitted.status.success(), "{}", stderr(&omitted));
    let omitted_err = stderr(&omitted);
    assert!(
        omitted_err.contains("no YubiKey detected") || omitted_err.contains("PIN"),
        "stderr did not fail before a write: {omitted_err}"
    );
    assert!(omitted.stdout.is_empty());
    assert_err(
        &run_in(
            &dir.0,
            &[
                "restore",
                "--sealed",
                "sealed.bin",
                "--share",
                "yubikey:111/5fff20",
                "--share",
                "yubikey:222/5fff21",
                "--pin-stdin",
            ],
            b"123456789\n123456\n",
        ),
        "PIN",
    );
}

#[test]
fn devices_lists_attached_yubikeys_without_a_pin() {
    let dir = Temp::new();
    let output = run_in(&dir.0, &["devices"], b"");
    assert_ok(&output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    if stdout.is_empty() {
        assert!(stderr(&output).contains("no devices detected"), "{}", stderr(&output));
    } else {
        for line in stdout.lines() {
            assert!(line.starts_with("yubikey:"), "{line}");
            assert!(line.contains("version"), "{line}");
            assert!(line.contains("reader"), "{line}");
        }
    }
    let help = run_in(&dir.0, &["devices", "--help"], b"");
    assert_ok(&help);
    let text = String::from_utf8_lossy(&help.stdout);
    assert!(text.contains("hardware"));
}

#[test]
fn help_and_manuals_describe_stdin_and_stdout() {
    let dir = Temp::new();
    let split_help = run_in(&dir.0, &["split", "--help"], b"");
    assert_ok(&split_help);
    let split_text = String::from_utf8_lossy(&split_help.stdout);
    assert!(split_text.contains("stdin"));
    assert!(!split_text.contains("--secret"));
    let restore_help = run_in(&dir.0, &["restore", "--help"], b"");
    assert_ok(&restore_help);
    let restore_text = String::from_utf8_lossy(&restore_help.stdout);
    assert!(restore_text.contains("stdout"));
    assert!(!restore_text.contains("--output"));
    assert_ok(&run_in(&dir.0, &["man", "-o", "man", "-f", "manpages"], b""));
    assert_ok(&run_in(&dir.0, &["autocomplete", "-o", "complete", "-s", "bash"], b""));
    assert!(dir.path("man").read_dir().unwrap().next().is_some());
    assert!(dir.path("complete").read_dir().unwrap().next().is_some());
}

fn run_bash(dir: &Path, script: &str, stdin: &[u8]) -> Output {
    let mut child = Command::new("/bin/bash")
        .current_dir(dir)
        .env("AGREE", env!("CARGO_BIN_EXE_agree"))
        .arg("-c")
        .arg(script)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(stdin).unwrap();
    child.wait_with_output().unwrap()
}

fn assert_nothing_written(dir: &Temp) {
    assert!(!dir.path("a.share").exists(), "share was written after a refused key");
    assert!(!dir.path("b.share").exists(), "share was written after a refused key");
    assert!(
        !dir.path("sealed.bin").exists(),
        "sealed secret was written after a refused key"
    );
}

fn contains_slice(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|window| window == needle)
}

#[test]
fn split_refuses_when_mlock_is_unavailable() {
    let dir = Temp::new();
    let output = run_bash(
        &dir.0,
        "ulimit -l 0 && \"$AGREE\" split --threshold 1 --sealed sealed.bin --share a.share",
        b"secret",
    );
    assert_err(&output, "mlock failed");
    assert!(stderr(&output).contains("refusing to continue"), "{}", stderr(&output));
    assert_nothing_written(&dir);
}

#[test]
fn key_file_refuses_a_short_long_or_misplaced_source() {
    let dir = Temp::new();
    let key: Vec<u8> = (0u8..64).collect();
    fs::write(dir.path("key.bin"), &key).unwrap();
    fs::write(dir.path("short.key"), &key[..32]).unwrap();
    let mut long = key.clone();
    long.push(0xff);
    fs::write(dir.path("long.key"), &long).unwrap();

    let refuse = |key_bytes: &str, key_file: &str, needle: &str| {
        let err = run_in(
            &dir.0,
            &[
                "split",
                "--threshold",
                "2",
                "--key-bytes",
                key_bytes,
                "--key-file",
                key_file,
                "--sealed",
                "sealed.bin",
                "--share",
                "a.share",
                "--share",
                "b.share",
            ],
            b"do-not-seal",
        );
        assert_err(&err, needle);
        assert!(err.stdout.is_empty());
        assert_nothing_written(&dir);
    };

    refuse("64", "short.key", "exactly 64 bytes, got 32");
    refuse("64", "long.key", "exactly 64 bytes, got more");
    refuse("48", "missing.key", "multiple of 32");
    refuse("32", "device:/dev/null", "device:");
    refuse("32", "yubikey:5fff21", "yubikey:");
    refuse("32", "a.share", "cannot be a share");
    refuse("32", "sealed.bin", "sealed secret");
    refuse("32", "/dev/zero", "got more");

    let missing = run_in(
        &dir.0,
        &[
            "split",
            "--threshold",
            "2",
            "--key-bytes",
            "32",
            "--key-file",
            "missing.key",
            "--sealed",
            "sealed.bin",
            "--share",
            "a.share",
            "--share",
            "b.share",
        ],
        b"do-not-seal",
    );
    assert_err(&missing, "Failed to open");
    assert_nothing_written(&dir);
}

#[test]
fn key_file_of_64_bytes_restores() {
    let dir = Temp::new();
    let key: Vec<u8> = (0..64).map(|byte| 0xA0u8.wrapping_add(byte)).collect();
    let secret = b"external-key-secret";
    fs::write(dir.path("key.bin"), &key).unwrap();
    let split = run_in(
        &dir.0,
        &[
            "split",
            "--threshold",
            "2",
            "--key-bytes",
            "64",
            "--key-file",
            "key.bin",
            "--sealed",
            "sealed.bin",
            "--share",
            "a.share",
            "--share",
            "b.share",
        ],
        secret,
    );
    assert_ok(&split);
    assert!(stderr(&split).contains("key 64 bytes"), "{}", stderr(&split));
    assert!(!contains_slice(&split.stderr, secret));
    assert!(!contains_slice(&split.stderr, &key));
    for name in ["sealed.bin", "a.share", "b.share"] {
        let bytes = fs::read(dir.path(name)).unwrap();
        assert!(!contains_slice(&bytes, secret));
        assert!(!contains_slice(&bytes, &key));
    }
    let restored = run_in(
        &dir.0,
        &[
            "restore",
            "--sealed",
            "sealed.bin",
            "--share",
            "b.share",
            "--share",
            "a.share",
        ],
        b"",
    );
    assert_ok(&restored);
    assert_eq!(restored.stdout, secret);
}

#[test]
fn key_file_process_substitution_is_an_exact_pipe() {
    let dir = Temp::new();
    let key: Vec<u8> = (0u8..64).map(|byte| byte.wrapping_mul(3)).collect();
    let secret = b"pipe-secret";
    fs::write(dir.path("key.bin"), &key).unwrap();
    let mut long = key.clone();
    long.push(1);
    fs::write(dir.path("long.key"), &long).unwrap();

    let short = run_bash(
        &dir.0,
        "\"$AGREE\" split --threshold 2 --key-bytes 64 --key-file <(head -c 32 key.bin) --sealed sealed.bin --share \
         a.share --share b.share",
        secret,
    );
    assert_err(&short, "exactly 64 bytes, got 32");
    assert_nothing_written(&dir);

    let extra = run_bash(
        &dir.0,
        "\"$AGREE\" split --threshold 2 --key-bytes 64 --key-file <(cat long.key) --sealed sealed.bin --share a.share \
         --share b.share",
        secret,
    );
    assert_err(&extra, "exactly 64 bytes, got more");
    assert_nothing_written(&dir);

    let split = run_bash(
        &dir.0,
        "\"$AGREE\" split --threshold 2 --key-bytes 64 --key-file <(cat key.bin) --sealed sealed.bin --share a.share \
         --share b.share",
        secret,
    );
    assert_ok(&split);
    assert!(stderr(&split).contains("key 64 bytes"), "{}", stderr(&split));
    let restored = run_in(
        &dir.0,
        &[
            "restore",
            "--sealed",
            "sealed.bin",
            "--share",
            "a.share",
            "--share",
            "b.share",
        ],
        b"",
    );
    assert_ok(&restored);
    assert_eq!(restored.stdout, secret);
    for name in ["sealed.bin", "a.share", "b.share"] {
        assert!(!contains_slice(&fs::read(dir.path(name)).unwrap(), &key));
    }
}
