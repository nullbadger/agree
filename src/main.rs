#![deny(unsafe_code)]

mod args;
mod crypto;
mod devices;
mod engine;
mod error;
mod format;
mod hardware;
mod location;
mod memory;
mod policy;
mod prompt;
mod reference;
mod secret;
mod store;

use {
    crate::{
        args::{
            AutocompleteArgs,
            Command,
            ManArgs,
            RestoreArgs,
            SplitArgs,
        },
        crypto::read_key_file,
        engine::Engine,
        error::Error,
        format::{
            read_share_bytes,
            ShareRecord,
        },
        hardware::YubiKeyStore,
        location::{
            Location,
            Locator,
            YUBIKEY_OBJECT_MAX,
        },
        memory::{
            disable_core_dumps,
            require_mlock,
        },
        policy::Policy,
        prompt::{
            refuse_terminal_stdout,
            Console,
        },
        secret::Password,
        store::{
            create_private_file,
            DevicePublisher,
            FilePublisher,
            Overwrite,
        },
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
    std::{
        collections::HashMap,
        fs::{
            self,
            File,
            OpenOptions,
        },
        io::{
            self,
            IsTerminal,
            Read,
        },
        path::{
            Path,
            PathBuf,
        },
    },
    zeroize::Zeroize,
};

fn main() -> Result<()> {
    if !disable_core_dumps() {
        eprintln!("warning: could not disable core dumps");
    }
    App::run()
}

struct App;

impl App {
    fn run() -> Result<()> {
        let (cli, locator) = args::load()?;
        let console = Console::new(cli.debug);
        if cli.debug {
            eprintln!("warning: --debug prints the YubiKey PIN and management key on stderr");
        }
        match cli.command {
            | Command::Man(args) => render_manual(args),
            | Command::Autocomplete(args) => render_completion(args),
            | Command::Split(args) => split(&locator, &console, args),
            | Command::Restore(args) => restore(&locator, &console, args),
            | Command::Devices => devices(),
        }
    }
}

fn render_manual(args: ManArgs) -> Result<()> {
    fs::create_dir_all(&args.out).with_context(|| format!("Failed to create {}", args.out.display()))?;
    let builder = reference::ReferenceBuilder::new();
    match args.format.as_str() {
        | "manpages" => builder.build_manpages(&args.out)?,
        | "markdown" => builder.build_markdown(&args.out)?,
        | other => bail!("unknown format: {other}"),
    }
    Ok(())
}

fn render_completion(args: AutocompleteArgs) -> Result<()> {
    fs::create_dir_all(&args.out).with_context(|| format!("Failed to create {}", args.out.display()))?;
    reference::ReferenceBuilder::new().build_shell_completion(&args.out, &args.shell)
}

fn devices() -> Result<()> {
    let found = crate::devices::list()?;
    if found.is_empty() {
        eprintln!("no devices detected");
        return Ok(());
    }
    for device in found {
        println!("{device}");
    }
    Ok(())
}

fn split(locator: &Locator, console: &Console, args: SplitArgs) -> Result<()> {
    let key_len = crate::crypto::validate_key_bytes(args.key_bytes)?;
    let policy = Policy::from_args(args.share.len(), args.threshold, &args.weight, &args.quorum)?;
    // Before prompts, the key file, and stdin. A refused lock must not consume
    // the secret or ask for a PIN.
    require_mlock(key_len)?;
    warn_policy(&policy);
    let sealed = locator.parse(&args.sealed)?;
    let shares = parse_locations(locator, &args.share)?;
    if shares.iter().any(|share| same_place(share, &sealed)) {
        bail!("sealed secret and a share cannot use the same destination");
    }
    let overwrite = Overwrite::from_flag(args.force);
    // Reject a device:, yubikey:, or colliding path before destination checks.
    // Open the source after those checks and before any prompt, so a short or
    // long read fails before a YubiKey is touched, before stdin, and before
    // any share is written.
    let key_path = external_key_path(locator, &args, &sealed, &shares)?;
    ensure_destinations(std::iter::once(&sealed).chain(shares.iter()), overwrite)?;
    let provided_key = match key_path {
        | Some(path) => Some(read_key_file(&path, usize::from(args.key_bytes))?),
        | None => None,
    };
    let mut hardware_locations = shares.clone();
    hardware_locations.push(sealed.clone());
    let mut keys = SplitKeys::new(console, args.management_key.clone(), args.force);
    keys.prepare(&hardware_locations)?;
    let passwords = if args.protect {
        console.passwords(&share_labels(&shares), false)?
    } else {
        vec![None; shares.len()]
    };
    let engine = Engine::new(std::env::temp_dir());
    let mut secret = io::stdin();
    let staged = StagedFile::create()?;
    let mut staged_file = OpenOptions::new()
        .write(true)
        .open(&staged.path)
        .context("Failed to open staged sealed secret")?;
    let output = engine.split(
        &mut secret,
        &mut staged_file,
        &policy,
        args.key_bytes,
        &passwords,
        provided_key,
    )?;
    staged_file.sync_all().ok();
    drop(staged_file);
    if let Location::YubiKey { .. } = &sealed {
        let len = fs::metadata(&staged.path)?.len();
        if usize::try_from(len).unwrap_or(usize::MAX) > YUBIKEY_OBJECT_MAX {
            return Err(Error::YubiKeyTooLarge {
                len: len as usize,
                max: YUBIKEY_OBJECT_MAX,
            }
            .into());
        }
    }
    let mut published = Vec::new();
    let wrote = (|| -> Result<()> {
        for (location, bytes) in shares.iter().zip(&output.shares) {
            write_bytes(location, bytes, overwrite, &mut keys)?;
            if let Location::File(path) = location {
                published.push(path.clone());
            }
        }
        write_path(&sealed, &staged.path, overwrite, &mut keys)?;
        Ok(())
    })();
    if let Err(err) = wrote {
        for path in published {
            let _ = fs::remove_file(path);
        }
        return Err(err);
    }
    write_summary(&output.policy, output.key_bytes, &output.group, &sealed, &shares);
    Ok(())
}

fn warn_policy(policy: &Policy) {
    if policy.uniform_threshold() == Some(1) {
        eprintln!("warning: threshold 1 means any single share restores the secret");
        return;
    }
    for index in policy.lone_custodians() {
        eprintln!("warning: share {index} alone restores the secret");
    }
}

fn write_summary(policy: &Policy, key_bytes: u16, group: &[u8; 16], sealed: &Location, shares: &[Location]) {
    if let Some(threshold) = policy.uniform_threshold() {
        eprintln!(
            "split {} shares, threshold {}, key {} bytes\ngroup {}\nsealed {}\nany {} shares restore the secret",
            policy.count(),
            threshold,
            key_bytes,
            location::encode_hex(group),
            sealed,
            threshold
        );
        return;
    }
    eprintln!(
        "split {} shares, key {} bytes\ngroup {}\nsealed {}",
        policy.count(),
        key_bytes,
        location::encode_hex(group),
        sealed
    );
    for (offset, share) in shares.iter().enumerate() {
        eprintln!("share {}: {share}", offset + 1);
    }
    eprint!("{}", policy.describe());
}

/// Resolve `--key-file` without opening it.
///
/// The path is only a source of bytes. This tool does not execute it, and it
/// is not a `device:` or `yubikey:` destination. Opening happens later, after
/// destination checks and before prompts.
fn external_key_path(
    locator: &Locator,
    args: &SplitArgs,
    sealed: &Location,
    shares: &[Location],
) -> Result<Option<PathBuf>> {
    let Some(text) = &args.key_file else {
        return Ok(None);
    };
    let location = locator.parse(text)?;
    let Location::File(path) = &location else {
        bail!("--key-file must be a file path or a pipe, not a device: or yubikey: location");
    };
    if same_place(&location, sealed) || shares.iter().any(|share| same_place(share, &location)) {
        bail!("key file cannot be a share or the sealed secret");
    }
    Ok(Some(path.clone()))
}

fn restore(locator: &Locator, console: &Console, args: RestoreArgs) -> Result<()> {
    refuse_terminal_stdout()?;
    // Before share reads and PIN prompts. The largest key is the size that
    // must fit; a later, smaller key uses the same check again.
    require_mlock(crate::crypto::MAX_KEY_LEN)?;
    if let Some(value) = args.management_key.as_deref() {
        // Reading a share needs the PIN, not the management key. Reject a malformed
        // flag before prompting.
        crate::location::decode_hex(value).context("management key must be hex")?;
    }
    let sealed = locator.parse(&args.sealed)?;
    let shares = parse_locations(locator, &args.share)?;
    let mut keys = RestoreKeys::new(console, args.pin_stdin);
    let encoded = shares
        .iter()
        .map(|location| read_share(location, &mut keys))
        .collect::<Result<Vec<_>>>()?;
    let records = encoded
        .iter()
        .map(|bytes| ShareRecord::decode(bytes))
        .collect::<Result<Vec<_>>>()?;
    let passwords = passwords_for_restore(console, &records, &shares, args.password_stdin)?;
    let engine = Engine::new(std::env::temp_dir());
    let sealed_reader = open_read(&sealed, &mut keys)?;
    engine.restore(sealed_reader, &mut io::stdout(), &encoded, &passwords)?;
    Ok(())
}

fn passwords_for_restore(
    console: &Console,
    records: &[ShareRecord],
    shares: &[Location],
    from_stdin: bool,
) -> Result<Vec<Option<Password>>> {
    if !records.iter().any(|record| record.password) {
        return Ok(vec![None; records.len()]);
    }
    if from_stdin {
        let entered = console.passwords(&share_labels(shares), true)?;
        for (record, password) in records.iter().zip(&entered) {
            if record.password && password.is_none() {
                return Err(Error::PasswordRequired.into());
            }
        }
        return Ok(entered);
    }
    if !io::stderr().is_terminal() {
        bail!("a share is password protected; re-run with --password-stdin or a terminal");
    }
    let mut entered = Vec::with_capacity(records.len());
    for (record, label) in records.iter().zip(share_labels(shares)) {
        if record.password {
            entered.push(Some(console.required_password(&label)?));
        } else {
            entered.push(None);
        }
    }
    Ok(entered)
}

fn parse_locations(locator: &Locator, values: &[String]) -> Result<Vec<Location>> {
    let mut locations = Vec::with_capacity(values.len());
    for value in values {
        let location = locator.parse(value)?;
        if locations.iter().any(|existing| same_place(existing, &location)) {
            bail!("duplicate destination: {location}");
        }
        locations.push(location);
    }
    Ok(locations)
}

fn same_place(left: &Location, right: &Location) -> bool {
    match (left, right) {
        | (Location::File(left) | Location::Device(left), Location::File(right) | Location::Device(right)) => {
            left == right
        },
        | (
            Location::YubiKey {
                serial: left_serial,
                object: left_object,
            },
            Location::YubiKey {
                serial: right_serial,
                object: right_object,
            },
        ) => left_serial == right_serial && left_object == right_object,
        | (Location::File(_) | Location::Device(_), Location::YubiKey { .. })
        | (Location::YubiKey { .. }, Location::File(_) | Location::Device(_)) => false,
    }
}

fn share_labels(shares: &[Location]) -> Vec<String> {
    shares.iter().map(ToString::to_string).collect()
}

fn ensure_destinations<'a>(locations: impl Iterator<Item=&'a Location>, overwrite: Overwrite) -> Result<()> {
    for location in locations {
        match location {
            | Location::File(path) => FilePublisher::ensure_available(path, overwrite)?,
            | Location::Device(path) => DevicePublisher::ensure_available(path, overwrite)?,
            | Location::YubiKey { .. } => {},
        }
    }
    Ok(())
}

fn write_bytes(location: &Location, bytes: &[u8], overwrite: Overwrite, keys: &mut SplitKeys) -> Result<()> {
    match location {
        | Location::File(path) => FilePublisher::publish(path, bytes, overwrite),
        | Location::Device(path) => DevicePublisher::publish(path, bytes, overwrite),
        | Location::YubiKey { .. } => keys.write(location, bytes),
    }
}

fn write_path(location: &Location, source: &Path, overwrite: Overwrite, keys: &mut SplitKeys) -> Result<()> {
    match location {
        | Location::File(path) => FilePublisher::publish_from(path, source, overwrite),
        | Location::Device(path) => DevicePublisher::publish_from(path, source, overwrite),
        | Location::YubiKey { .. } => {
            let bytes = fs::read(source).context("Failed to read staged secret")?;
            keys.write(location, &bytes)
        },
    }
}

/// PINs and management keys for a split that may write several YubiKeys.
///
/// Credentials are collected, and existing objects are refused, before stdin is
/// read. A missing terminal therefore does not consume the secret. The write
/// phase asks for a key again only if that serial is no longer attached.
struct SplitKeys<'a> {
    console: &'a Console,
    management_key: Option<String>,
    force: bool,
    stores: HashMap<u32, YubiKeyStore>,
    /// Serial we last asked the operator to insert, so a second object on that
    /// key does not ask again during the same phase.
    prompted: Option<u32>,
}

impl<'a> SplitKeys<'a> {
    fn new(console: &'a Console, management_key: Option<String>, force: bool) -> Self {
        Self {
            console,
            management_key,
            force,
            stores: HashMap::new(),
            prompted: None,
        }
    }

    fn prepare(&mut self, locations: &[Location]) -> Result<()> {
        if !locations.iter().any(Location::is_yubikey) {
            return Ok(());
        }
        if let Some(value) = self.management_key.as_deref() {
            crate::hardware::validate_management_key(value)?;
        }
        self.reject_reserved(locations)?;
        if !io::stderr().is_terminal() {
            bail!("YubiKey PIN requires a terminal");
        }
        let mut claimed = HashMap::<(u32, u32), String>::new();
        for location in locations {
            let Location::YubiKey { object, .. } = location else {
                continue;
            };
            let serial = self.credentials_for(location)?;
            if let Some(previous) = claimed.insert((serial, *object), location.to_string()) {
                bail!("duplicate destination: {location} and {previous} are the same YubiKey object");
            }
            if !self.force && self.store(serial)?.exists(*object)? {
                bail!("YubiKey {serial} object {object:06x} already exists. Use --force to overwrite it.");
            }
        }
        self.prompted = None;
        Ok(())
    }

    fn write(&mut self, location: &Location, bytes: &[u8]) -> Result<()> {
        let Location::YubiKey { object, .. } = location else {
            bail!("internal error: not a YubiKey location");
        };
        let object = *object;
        let serial = self.credentials_for(location)?;
        self.ensure_inserted(serial, location)?;
        self.store(serial)?.write(object, bytes, self.force)
    }

    fn credentials_for(&mut self, location: &Location) -> Result<u32> {
        let serial = self.resolve_serial(location)?;
        if self.stores.contains_key(&serial) {
            return Ok(serial);
        }
        if self.prompted != Some(serial) {
            prompt::wait_for_key(&format!("Insert YubiKey {serial} for {location}, then press Enter"))?;
        }
        let pin = self.console.pin(false, &format!("YubiKey {serial}"))?;
        let mut management = self.management_for(serial)?;
        let opened = YubiKeyStore::open(Some(serial), pin, management.as_deref());
        if let Some(value) = management.as_mut() {
            value.zeroize();
        }
        self.stores.insert(serial, opened?);
        self.prompted = Some(serial);
        Ok(serial)
    }

    fn resolve_serial(&mut self, location: &Location) -> Result<u32> {
        let Location::YubiKey { serial, .. } = location else {
            bail!("internal error: not a YubiKey location");
        };
        if let Some(serial) = *serial {
            return Ok(serial);
        }
        let attached = crate::hardware::list_serials()?;
        if !attached.is_empty() {
            return location::resolve_unspecified_serial(&attached);
        }
        prompt::wait_for_key(&format!("Insert the YubiKey for {location}, then press Enter"))?;
        let serial = location::resolve_unspecified_serial(&crate::hardware::list_serials()?)?;
        self.prompted = Some(serial);
        Ok(serial)
    }

    fn management_for(&self, serial: u32) -> Result<Option<String>> {
        if let Some(value) = &self.management_key {
            self.console
                .reveal(&format!("management key for YubiKey {serial}"), value);
            return Ok(Some(value.clone()));
        }
        loop {
            let entered = self.console.management_key(&format!("YubiKey {serial}"))?;
            if let Some(value) = entered.as_deref() {
                if let Err(err) = crate::hardware::validate_management_key(value) {
                    eprintln!("{err}");
                    continue;
                }
            }
            return Ok(entered);
        }
    }

    fn ensure_inserted(&mut self, serial: u32, location: &Location) -> Result<()> {
        if self.prompted == Some(serial) || crate::hardware::serial_present(serial) {
            self.prompted = Some(serial);
            return Ok(());
        }
        prompt::wait_for_key(&format!("Insert YubiKey {serial} for {location}, then press Enter"))?;
        self.prompted = Some(serial);
        Ok(())
    }

    fn store(&self, serial: u32) -> Result<&YubiKeyStore> {
        self.stores
            .get(&serial)
            .context("internal error: YubiKey session was not opened")
    }

    fn reject_reserved(&self, locations: &[Location]) -> Result<()> {
        #[cfg(feature = "yubikey")]
        {
            for location in locations {
                if let Location::YubiKey { object, .. } = location {
                    location::ensure_object_allowed(*object, self.force)?;
                }
            }
        }
        #[cfg(not(feature = "yubikey"))]
        {
            let _ = (self, locations);
        }
        Ok(())
    }
}

impl Drop for SplitKeys<'_> {
    fn drop(&mut self) {
        if let Some(value) = self.management_key.as_mut() {
            value.zeroize();
        }
    }
}

fn read_share(location: &Location, keys: &mut RestoreKeys) -> Result<Vec<u8>> {
    match location {
        | Location::File(path) | Location::Device(path) => {
            let mut file = File::open(path).with_context(|| format!("Failed to open {location}"))?;
            read_share_bytes(&mut file).with_context(|| format!("Failed to read share {location}"))
        },
        | Location::YubiKey { .. } => {
            let bytes = keys.read(location)?;
            read_share_bytes(&mut bytes.as_slice()).context("YubiKey object is not an agree share")
        },
    }
}

fn open_read(location: &Location, keys: &mut RestoreKeys) -> Result<Box<dyn Read>> {
    match location {
        | Location::File(path) | Location::Device(path) => {
            let file = File::open(path).with_context(|| format!("Failed to open {location}"))?;
            Ok(Box::new(file))
        },
        | Location::YubiKey { .. } => {
            let bytes = keys.read(location)?;
            Ok(Box::new(io::Cursor::new(bytes)))
        },
    }
}

/// PINs for a restore that may touch several YubiKeys.
struct RestoreKeys<'a> {
    console: &'a Console,
    pin_stdin: bool,
    pins: std::collections::HashMap<u32, Vec<u8>>,
}

impl<'a> RestoreKeys<'a> {
    fn new(console: &'a Console, pin_stdin: bool) -> Self {
        Self {
            console,
            pin_stdin,
            pins: std::collections::HashMap::new(),
        }
    }

    fn read(&mut self, location: &Location) -> Result<Vec<u8>> {
        let Location::YubiKey { serial, object } = location else {
            bail!("internal error: not a YubiKey location");
        };
        let serial = match *serial {
            | Some(serial) => serial,
            | None => location::resolve_unspecified_serial(&crate::hardware::list_serials()?)?,
        };
        if !self.pin_stdin && !self.pins.contains_key(&serial) {
            prompt::wait_for_key(&format!("Insert YubiKey {serial} for {location}, then press Enter"))?;
        }
        let pin = self.pin_for(serial, location)?;
        crate::hardware::read_object(serial, &pin, *object)
    }

    fn pin_for(&mut self, serial: u32, location: &Location) -> Result<Vec<u8>> {
        if self.pin_stdin {
            return self.console.pin(true, &location.to_string());
        }
        if let Some(pin) = self.pins.get(&serial) {
            return Ok(pin.clone());
        }
        let pin = self.console.pin(false, &format!("YubiKey {serial}"))?;
        self.pins.insert(serial, pin.clone());
        Ok(pin)
    }
}

impl Drop for RestoreKeys<'_> {
    fn drop(&mut self) {
        for pin in self.pins.values_mut() {
            pin.zeroize();
        }
    }
}

struct StagedFile {
    path: PathBuf,
}

impl StagedFile {
    fn create() -> Result<Self> {
        let mut name = [0u8; 16];
        OsRng.fill_bytes(&mut name);
        let path = std::env::temp_dir().join(format!("agree-{}.tmp", location::encode_hex(&name)));
        create_private_file(&path)?;
        Ok(Self { path })
    }
}

impl Drop for StagedFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}
