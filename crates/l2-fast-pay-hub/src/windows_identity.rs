use std::io::Write;
use std::path::{Path, PathBuf};

use field::Address;
use rand::{RngCore, rngs::OsRng};
use sys::Account;
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
};
use zeroize::Zeroizing;

use crate::{HubError, HubResult};

const MAX_DPAPI_IDENTITY_BYTES: usize = 4096;
const DPAPI_IDENTITY_V3_SUFFIX: &str = ".v3";
const V3_PUBLIC_FILE: &str = "public.dpapi";
const V3_SIGNER_FILE: &str = "signer.dpapi";
const V3_JOURNAL_FILE: &str = "journal.dpapi";
const V3_STATE_FILE: &str = "state.dpapi";

/// Creates a new split user-bound DPAPI v3 identity. Signer, journal and state
/// keys are protected in separate blobs so read-only commands never decrypt a
/// signing key. Existing v2 or v3 identities are never overwritten.
pub fn create_dpapi_hub_identity(path: &Path) -> HubResult<String> {
    if path.exists() || dpapi_identity_v3_dir(path)?.exists() {
        return Err(HubError::State(
            "refusing to overwrite an existing DPAPI Hub identity".into(),
        ));
    }
    let identity = new_dpapi_hub_identity()?;
    let address = identity.address.clone();
    write_dpapi_hub_identity_v3(path, &identity)?;
    Ok(address)
}

#[cfg(test)]
fn create_dpapi_hub_identity_v2(path: &Path) -> HubResult<String> {
    if path.exists() || dpapi_identity_v3_dir(path)?.exists() {
        return Err(HubError::State(
            "refusing to overwrite an existing DPAPI Hub identity".into(),
        ));
    }
    let identity = new_dpapi_hub_identity()?;
    let clear = Zeroizing::new(format!(
        "format_version=2\nhub_secret_hex={}\njournal_key_hex={}\nstate_key_hex={}\n",
        identity.hub_secret_hex.as_str(),
        identity.journal_key_hex.as_str(),
        identity.state_key_hex.as_str()
    ));
    let encrypted = protect_dpapi_payload(clear.as_bytes())?;
    atomic_write_new_file(path, &encrypted, ".hpay-hub-identity-v2")?;
    Ok(identity.address)
}

fn new_dpapi_hub_identity() -> HubResult<DpapiHubIdentity> {
    let (hub_secret_hex, address) = random_valid_hub_secret()?;
    let journal_key_hex = random_key_hex();
    let state_key_hex = random_key_hex();
    Ok(DpapiHubIdentity {
        address,
        hub_secret_hex,
        journal_key_hex,
        state_key_hex,
    })
}

fn protect_dpapi_payload(clear: &[u8]) -> HubResult<Vec<u8>> {
    let input = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(clear.len())
            .map_err(|_| HubError::State("DPAPI Hub identity payload is too large".into()))?,
        pbData: clear.as_ptr().cast_mut(),
    };
    let mut protected = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    let ok = unsafe {
        CryptProtectData(
            &input,
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut protected,
        )
    };
    if ok == 0 || protected.pbData.is_null() {
        return Err(HubError::State(format!(
            "cannot encrypt DPAPI Hub identity: {}",
            std::io::Error::last_os_error()
        )));
    }
    let encrypted =
        unsafe { std::slice::from_raw_parts(protected.pbData, protected.cbData as usize).to_vec() };
    unsafe {
        LocalFree(protected.pbData.cast());
    }
    if encrypted.is_empty() || encrypted.len() > MAX_DPAPI_IDENTITY_BYTES {
        return Err(HubError::State(
            "encrypted DPAPI Hub identity size is invalid".into(),
        ));
    }
    Ok(encrypted)
}

fn atomic_write_new_file(path: &Path, encrypted: &[u8], prefix: &str) -> HubResult<()> {
    let parent = path
        .parent()
        .filter(|parent| parent.is_dir())
        .ok_or_else(|| HubError::State("DPAPI Hub identity directory does not exist".into()))?;
    let mut suffix = [0_u8; 12];
    OsRng.fill_bytes(&mut suffix);
    let temp = parent.join(format!("{prefix}-{}.tmp", hex::encode(suffix)));
    let write_result = (|| -> std::io::Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)?;
        file.write_all(encrypted)?;
        file.sync_all()?;
        std::fs::rename(&temp, path)?;
        Ok(())
    })();
    if let Err(error) = write_result {
        let _ = std::fs::remove_file(&temp);
        return Err(HubError::State(format!(
            "cannot atomically create DPAPI Hub identity: {error}"
        )));
    }
    Ok(())
}

fn dpapi_identity_v3_dir(path: &Path) -> HubResult<PathBuf> {
    let parent = path
        .parent()
        .filter(|parent| parent.is_dir())
        .ok_or_else(|| HubError::State("DPAPI Hub identity directory does not exist".into()))?;
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| HubError::State("DPAPI Hub identity path is invalid".into()))?;
    Ok(parent.join(format!("{file_name}{DPAPI_IDENTITY_V3_SUFFIX}")))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IdentityComponentKind {
    Public,
    Signer,
    Journal,
    State,
}

impl IdentityComponentKind {
    fn name(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Signer => "signer",
            Self::Journal => "journal",
            Self::State => "state",
        }
    }

    fn file_name(self) -> &'static str {
        match self {
            Self::Public => V3_PUBLIC_FILE,
            Self::Signer => V3_SIGNER_FILE,
            Self::Journal => V3_JOURNAL_FILE,
            Self::State => V3_STATE_FILE,
        }
    }
}

struct DpapiIdentityComponent {
    identity_id: String,
    address: String,
    kind: IdentityComponentKind,
    key_hex: Option<Zeroizing<String>>,
}

fn validate_lower_hex(value: &str, label: &str) -> HubResult<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(HubError::State(format!("{label} is invalid")));
    }
    Ok(())
}

fn validate_canonical_address(value: &str) -> HubResult<()> {
    let address = Address::from_readable(value)
        .map_err(|_| HubError::State("DPAPI v3 identity address is invalid".into()))?;
    if address.to_readable() != value {
        return Err(HubError::State(
            "DPAPI v3 identity address is not canonical".into(),
        ));
    }
    Ok(())
}

fn serialize_identity_component(
    identity_id: &str,
    address: &str,
    kind: IdentityComponentKind,
    key_hex: Option<&str>,
) -> HubResult<Zeroizing<String>> {
    validate_lower_hex(identity_id, "DPAPI v3 identity id")?;
    validate_canonical_address(address)?;
    match (kind, key_hex) {
        (IdentityComponentKind::Public, None) => Ok(Zeroizing::new(format!(
            "format_version=3\nidentity_id={identity_id}\naddress={address}\nkind={}\n",
            kind.name()
        ))),
        (IdentityComponentKind::Public, Some(_)) | (_, None) => Err(HubError::State(
            "DPAPI v3 identity component key presence is invalid".into(),
        )),
        (_, Some(key)) => {
            validate_lower_hex(key, "DPAPI v3 identity component key")?;
            Ok(Zeroizing::new(format!(
                "format_version=3\nidentity_id={identity_id}\naddress={address}\nkind={}\nkey_hex={key}\n",
                kind.name()
            )))
        }
    }
}

fn parse_identity_component(
    payload: &str,
    expected_kind: IdentityComponentKind,
) -> HubResult<DpapiIdentityComponent> {
    let mut format_version = None;
    let mut identity_id = None;
    let mut address = None;
    let mut kind = None;
    let mut key_hex = None;
    for line in payload.lines() {
        let (name, value) = line
            .split_once('=')
            .ok_or_else(|| HubError::State("DPAPI v3 identity line is malformed".into()))?;
        if value.is_empty() {
            return Err(HubError::State(
                "DPAPI v3 identity contains an empty field".into(),
            ));
        }
        match name {
            "format_version" => {
                if format_version.replace(value).is_some() {
                    return Err(HubError::State(
                        "DPAPI v3 identity contains a duplicate field".into(),
                    ));
                }
            }
            "identity_id" => {
                if identity_id.replace(value.to_owned()).is_some() {
                    return Err(HubError::State(
                        "DPAPI v3 identity contains a duplicate field".into(),
                    ));
                }
            }
            "address" => {
                if address.replace(value.to_owned()).is_some() {
                    return Err(HubError::State(
                        "DPAPI v3 identity contains a duplicate field".into(),
                    ));
                }
            }
            "kind" => {
                if kind.replace(value).is_some() {
                    return Err(HubError::State(
                        "DPAPI v3 identity contains a duplicate field".into(),
                    ));
                }
            }
            "key_hex" => {
                if key_hex.replace(Zeroizing::new(value.to_owned())).is_some() {
                    return Err(HubError::State(
                        "DPAPI v3 identity contains a duplicate field".into(),
                    ));
                }
            }
            _ => {
                return Err(HubError::State(
                    "DPAPI v3 identity contains an unknown field".into(),
                ));
            }
        }
    }
    if format_version != Some("3") {
        return Err(HubError::State(
            "DPAPI v3 identity format version is invalid".into(),
        ));
    }
    let identity_id =
        identity_id.ok_or_else(|| HubError::State("DPAPI v3 identity id is missing".into()))?;
    validate_lower_hex(&identity_id, "DPAPI v3 identity id")?;
    let address =
        address.ok_or_else(|| HubError::State("DPAPI v3 identity address is missing".into()))?;
    validate_canonical_address(&address)?;
    if kind != Some(expected_kind.name()) {
        return Err(HubError::State(
            "DPAPI v3 identity component kind is invalid".into(),
        ));
    }
    match (expected_kind, key_hex.as_deref()) {
        (IdentityComponentKind::Public, None) => {}
        (IdentityComponentKind::Public, Some(_)) | (_, None) => {
            return Err(HubError::State(
                "DPAPI v3 identity component key presence is invalid".into(),
            ));
        }
        (_, Some(key)) => validate_lower_hex(key, "DPAPI v3 identity component key")?,
    }
    Ok(DpapiIdentityComponent {
        identity_id,
        address,
        kind: expected_kind,
        key_hex,
    })
}

fn unprotect_dpapi_file(path: &Path) -> HubResult<Zeroizing<Vec<u8>>> {
    let encrypted = std::fs::read(path).map_err(|error| {
        HubError::State(format!("cannot read DPAPI identity component: {error}"))
    })?;
    if encrypted.is_empty() || encrypted.len() > MAX_DPAPI_IDENTITY_BYTES {
        return Err(HubError::State(
            "DPAPI identity component size is invalid".into(),
        ));
    }
    let input = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(encrypted.len())
            .map_err(|_| HubError::State("DPAPI identity component is too large".into()))?,
        pbData: encrypted.as_ptr().cast_mut(),
    };
    let mut plaintext = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    let ok = unsafe {
        CryptUnprotectData(
            &input,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut plaintext,
        )
    };
    if ok == 0 || plaintext.pbData.is_null() {
        return Err(HubError::State(format!(
            "cannot decrypt DPAPI identity component: {}",
            std::io::Error::last_os_error()
        )));
    }
    let clear = unsafe { std::slice::from_raw_parts(plaintext.pbData, plaintext.cbData as usize) };
    let clear = Zeroizing::new(clear.to_vec());
    unsafe {
        LocalFree(plaintext.pbData.cast());
    }
    Ok(clear)
}

fn load_dpapi_identity_component(
    directory: &Path,
    kind: IdentityComponentKind,
) -> HubResult<DpapiIdentityComponent> {
    let clear = unprotect_dpapi_file(&directory.join(kind.file_name()))?;
    let text = std::str::from_utf8(&clear)
        .map_err(|_| HubError::State("DPAPI v3 identity component is not UTF-8".into()))?;
    parse_identity_component(text, kind)
}

fn require_same_component_binding(
    public: &DpapiIdentityComponent,
    other: &DpapiIdentityComponent,
) -> HubResult<()> {
    if public.kind != IdentityComponentKind::Public
        || public.identity_id != other.identity_id
        || public.address != other.address
    {
        return Err(HubError::State(
            "DPAPI v3 identity components do not share the same binding".into(),
        ));
    }
    Ok(())
}

fn load_dpapi_hub_identity_v3_from_dir(directory: &Path) -> HubResult<DpapiHubIdentity> {
    let public = load_dpapi_identity_component(directory, IdentityComponentKind::Public)?;
    let signer = load_dpapi_identity_component(directory, IdentityComponentKind::Signer)?;
    let journal = load_dpapi_identity_component(directory, IdentityComponentKind::Journal)?;
    let state = load_dpapi_identity_component(directory, IdentityComponentKind::State)?;
    require_same_component_binding(&public, &signer)?;
    require_same_component_binding(&public, &journal)?;
    require_same_component_binding(&public, &state)?;
    let identity = DpapiHubIdentity {
        address: public.address,
        hub_secret_hex: signer
            .key_hex
            .ok_or_else(|| HubError::State("DPAPI v3 signer key is missing".into()))?,
        journal_key_hex: journal
            .key_hex
            .ok_or_else(|| HubError::State("DPAPI v3 journal key is missing".into()))?,
        state_key_hex: state
            .key_hex
            .ok_or_else(|| HubError::State("DPAPI v3 state key is missing".into()))?,
    };
    validate_independent_keys(
        &identity.hub_secret_hex,
        &identity.journal_key_hex,
        &identity.state_key_hex,
    )?;
    let account = Account::create_by(&identity.hub_secret_hex)
        .map_err(|error| HubError::State(format!("DPAPI v3 signer key is invalid: {error}")))?;
    if account.readable() != identity.address {
        return Err(HubError::State(
            "DPAPI v3 signer does not match the public identity".into(),
        ));
    }
    Ok(identity)
}

fn load_dpapi_hub_identity_v3(path: &Path) -> HubResult<DpapiHubIdentity> {
    load_dpapi_hub_identity_v3_from_dir(&dpapi_identity_v3_dir(path)?)
}

fn write_dpapi_hub_identity_v3(path: &Path, identity: &DpapiHubIdentity) -> HubResult<PathBuf> {
    let target = dpapi_identity_v3_dir(path)?;
    if target.exists() {
        return Err(HubError::State(
            "refusing to overwrite an existing DPAPI v3 Hub identity".into(),
        ));
    }
    validate_canonical_address(&identity.address)?;
    validate_independent_keys(
        &identity.hub_secret_hex,
        &identity.journal_key_hex,
        &identity.state_key_hex,
    )?;
    let parent = target
        .parent()
        .ok_or_else(|| HubError::State("DPAPI v3 identity directory is invalid".into()))?;
    let mut suffix = [0_u8; 12];
    OsRng.fill_bytes(&mut suffix);
    let temp = parent.join(format!(".hpay-hub-identity-v3-{}.tmp", hex::encode(suffix)));
    std::fs::create_dir(&temp).map_err(|error| {
        HubError::State(format!("cannot create DPAPI v3 staging directory: {error}"))
    })?;
    let result = (|| -> HubResult<()> {
        let identity_id = random_key_hex();
        let components = [
            (IdentityComponentKind::Public, None),
            (
                IdentityComponentKind::Signer,
                Some(identity.hub_secret_hex.as_str()),
            ),
            (
                IdentityComponentKind::Journal,
                Some(identity.journal_key_hex.as_str()),
            ),
            (
                IdentityComponentKind::State,
                Some(identity.state_key_hex.as_str()),
            ),
        ];
        for (kind, key) in components {
            let clear =
                serialize_identity_component(identity_id.as_str(), &identity.address, kind, key)?;
            let encrypted = protect_dpapi_payload(clear.as_bytes())?;
            atomic_write_new_file(
                &temp.join(kind.file_name()),
                &encrypted,
                ".hpay-identity-component",
            )?;
        }
        let staged = load_dpapi_hub_identity_v3_from_dir(&temp)?;
        if staged.address != identity.address
            || staged.hub_secret_hex != identity.hub_secret_hex
            || staged.journal_key_hex != identity.journal_key_hex
            || staged.state_key_hex != identity.state_key_hex
        {
            return Err(HubError::State(
                "DPAPI v3 staged identity verification failed".into(),
            ));
        }
        std::fs::rename(&temp, &target).map_err(|error| {
            HubError::State(format!(
                "cannot atomically install DPAPI v3 identity: {error}"
            ))
        })?;
        Ok(())
    })();
    if let Err(error) = result {
        let _ = std::fs::remove_dir_all(&temp);
        return Err(error);
    }
    Ok(target)
}

fn validate_independent_keys(secret: &str, journal: &str, state: &str) -> HubResult<()> {
    validate_lower_hex(secret, "DPAPI signer key")?;
    validate_lower_hex(journal, "DPAPI journal key")?;
    validate_lower_hex(state, "DPAPI state key")?;
    if secret == journal || secret == state || journal == state {
        return Err(HubError::State(
            "Hub signer, journal and state keys must be independent".into(),
        ));
    }
    Ok(())
}

fn random_key_hex() -> Zeroizing<String> {
    let mut bytes = Zeroizing::new([0_u8; 32]);
    OsRng.fill_bytes(bytes.as_mut());
    Zeroizing::new(hex::encode(bytes.as_ref()))
}

fn random_valid_hub_secret() -> HubResult<(Zeroizing<String>, String)> {
    for _ in 0..128 {
        let key = random_key_hex();
        if let Ok(account) = Account::create_by(&key) {
            return Ok((key, account.readable().to_owned()));
        }
    }
    Err(HubError::State(
        "operating-system RNG did not produce a valid Hub signing key".into(),
    ))
}

pub struct DpapiHubIdentity {
    address: String,
    hub_secret_hex: Zeroizing<String>,
    journal_key_hex: Zeroizing<String>,
    state_key_hex: Zeroizing<String>,
}

impl DpapiHubIdentity {
    pub fn into_parts(
        self,
    ) -> (
        String,
        Zeroizing<String>,
        Zeroizing<String>,
        Zeroizing<String>,
    ) {
        (
            self.address,
            self.hub_secret_hex,
            self.journal_key_hex,
            self.state_key_hex,
        )
    }
}

pub fn load_dpapi_hub_identity(path: &Path) -> HubResult<DpapiHubIdentity> {
    let v3 = dpapi_identity_v3_dir(path)?;
    if v3.is_dir() {
        return load_dpapi_hub_identity_v3(path);
    }
    load_dpapi_hub_identity_v2(path)
}

/// Reads only the public descriptor from a split v3 identity. This function
/// never opens or decrypts the signer, journal or state components.
pub fn load_dpapi_hub_public(path: &Path) -> HubResult<String> {
    let directory = dpapi_identity_v3_dir(path)?;
    if !directory.is_dir() {
        return Err(HubError::State(
            "DPAPI v3 identity is required for signer-free public inspection; migrate the legacy v2 identity first"
                .into(),
        ));
    }
    Ok(load_dpapi_identity_component(&directory, IdentityComponentKind::Public)?.address)
}

/// Reads only the public descriptor and state-authentication key from a split
/// v3 identity. The signing key and journal key are never decrypted.
pub fn load_dpapi_hub_state_key(path: &Path) -> HubResult<(String, Zeroizing<String>)> {
    let directory = dpapi_identity_v3_dir(path)?;
    if !directory.is_dir() {
        return Err(HubError::State(
            "DPAPI v3 identity is required for signer-free state inspection; migrate the legacy v2 identity first"
                .into(),
        ));
    }
    let public = load_dpapi_identity_component(&directory, IdentityComponentKind::Public)?;
    let state = load_dpapi_identity_component(&directory, IdentityComponentKind::State)?;
    require_same_component_binding(&public, &state)?;
    Ok((
        public.address,
        state
            .key_hex
            .ok_or_else(|| HubError::State("DPAPI v3 state key is missing".into()))?,
    ))
}

/// Atomically creates a split v3 identity from a legacy v2 DPAPI blob. The
/// original v2 file is retained byte-for-byte as a rollback backup.
pub fn migrate_dpapi_hub_identity_to_v3(path: &Path) -> HubResult<PathBuf> {
    if !path.is_file() {
        return Err(HubError::State(
            "legacy DPAPI v2 identity file does not exist".into(),
        ));
    }
    let target = dpapi_identity_v3_dir(path)?;
    if target.exists() {
        return Err(HubError::State(
            "refusing to overwrite an existing DPAPI v3 Hub identity".into(),
        ));
    }
    let legacy_bytes = std::fs::read(path)
        .map_err(|error| HubError::State(format!("cannot read legacy DPAPI identity: {error}")))?;
    let legacy = load_dpapi_hub_identity_v2(path)?;
    let expected_address = legacy.address.clone();
    let expected_secret = legacy.hub_secret_hex.clone();
    let expected_journal = legacy.journal_key_hex.clone();
    let expected_state = legacy.state_key_hex.clone();
    let installed = write_dpapi_hub_identity_v3(path, &legacy)?;
    let verified = load_dpapi_hub_identity_v3(path)?;
    if verified.address != expected_address
        || verified.hub_secret_hex != expected_secret
        || verified.journal_key_hex != expected_journal
        || verified.state_key_hex != expected_state
    {
        let _ = std::fs::remove_dir_all(&installed);
        return Err(HubError::State(
            "DPAPI v3 migration verification failed".into(),
        ));
    }
    let after = std::fs::read(path)
        .map_err(|error| HubError::State(format!("cannot verify legacy DPAPI backup: {error}")))?;
    if after != legacy_bytes {
        let _ = std::fs::remove_dir_all(&installed);
        return Err(HubError::State(
            "legacy DPAPI v2 identity changed during migration".into(),
        ));
    }
    Ok(installed)
}

fn load_dpapi_hub_identity_v2(path: &Path) -> HubResult<DpapiHubIdentity> {
    let clear = unprotect_dpapi_file(path)?;
    let text = std::str::from_utf8(&clear)
        .map_err(|_| HubError::State("DPAPI Hub identity is not UTF-8".into()))?;
    parse_identity_payload(text)
}

fn parse_identity_payload(payload: &str) -> HubResult<DpapiHubIdentity> {
    let mut format_version = None;
    let mut secret = None;
    let mut journal = None;
    let mut state = None;
    for line in payload.lines() {
        let (name, value) = line
            .split_once('=')
            .ok_or_else(|| HubError::State("DPAPI Hub identity line is malformed".into()))?;
        if name == "format_version" {
            if format_version.replace(value).is_some() || value != "2" {
                return Err(HubError::State(
                    "DPAPI Hub identity format version is invalid".into(),
                ));
            }
            continue;
        }
        let target = match name {
            "hub_secret_hex" => &mut secret,
            "journal_key_hex" => &mut journal,
            "state_key_hex" => &mut state,
            _ => {
                return Err(HubError::State(
                    "DPAPI Hub identity contains an unknown field".into(),
                ));
            }
        };
        if target.is_some() {
            return Err(HubError::State(
                "DPAPI Hub identity contains a duplicate field".into(),
            ));
        }
        if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(HubError::State(
                "DPAPI Hub identity contains an invalid key".into(),
            ));
        }
        *target = Some(Zeroizing::new(value.to_ascii_lowercase()));
    }
    if format_version != Some("2") {
        return Err(HubError::State(
            "DPAPI Hub identity requires explicit format_version=2 migration".into(),
        ));
    }
    let hub_secret_hex = secret
        .ok_or_else(|| HubError::State("DPAPI Hub identity is missing the signer key".into()))?;
    let journal_key_hex = journal
        .ok_or_else(|| HubError::State("DPAPI Hub identity is missing the journal key".into()))?;
    let state_key_hex = state
        .ok_or_else(|| HubError::State("DPAPI Hub identity is missing the state key".into()))?;
    validate_independent_keys(&hub_secret_hex, &journal_key_hex, &state_key_hex)?;
    let account = Account::create_by(&hub_secret_hex)
        .map_err(|error| HubError::State(format!("DPAPI Hub signer key is invalid: {error}")))?;
    Ok(DpapiHubIdentity {
        address: account.readable().to_owned(),
        hub_secret_hex,
        journal_key_hex,
        state_key_hex,
    })
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plaintext_parser_rejects_ambiguous_or_reused_keys() {
        let key = "11".repeat(32);
        assert!(parse_identity_payload("unknown=00\n").is_err());
        assert!(
            parse_identity_payload(&format!(
                "format_version=2\nhub_secret_hex={key}\nhub_secret_hex={key}\njournal_key_hex={}\nstate_key_hex={}\n",
                "22".repeat(32),
                "33".repeat(32)
            ))
            .is_err()
        );
        assert!(
            parse_identity_payload(&format!(
                "format_version=2\nhub_secret_hex={key}\njournal_key_hex={key}\nstate_key_hex={}\n",
                "33".repeat(32)
            ))
            .is_err()
        );
    }

    #[test]
    fn plaintext_parser_derives_only_the_public_address() {
        let secret = "11".repeat(32);
        let identity = parse_identity_payload(&format!(
            "format_version=2\nhub_secret_hex={secret}\njournal_key_hex={}\nstate_key_hex={}\n",
            "22".repeat(32),
            "33".repeat(32)
        ))
        .unwrap();
        assert_eq!(
            identity.address,
            Account::create_by(&secret).unwrap().readable()
        );
    }

    #[test]
    fn dpapi_creation_is_loadable_and_never_overwrites() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("hub.identity.dpapi");
        let address = create_dpapi_hub_identity(&path).unwrap();
        assert!(!path.exists());
        assert!(dpapi_identity_v3_dir(&path).unwrap().is_dir());
        let loaded = load_dpapi_hub_identity(&path).unwrap();
        assert_eq!(loaded.address, address);
        assert_ne!(loaded.hub_secret_hex, loaded.journal_key_hex);
        assert_ne!(loaded.hub_secret_hex, loaded.state_key_hex);
        assert_ne!(loaded.journal_key_hex, loaded.state_key_hex);
        assert_eq!(load_dpapi_hub_public(&path).unwrap(), address);
        let (state_address, state_key) = load_dpapi_hub_state_key(&path).unwrap();
        assert_eq!(state_address, address);
        assert_eq!(state_key, loaded.state_key_hex);
        assert!(create_dpapi_hub_identity(&path).is_err());
        assert!(migrate_dpapi_hub_identity_to_v3(&path).is_err());
    }

    #[test]
    fn selective_readers_do_not_depend_on_the_signer_blob() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("hub.identity.dpapi");
        let address = create_dpapi_hub_identity(&path).unwrap();
        let (_, expected_state_key) = load_dpapi_hub_state_key(&path).unwrap();
        let signer_path = dpapi_identity_v3_dir(&path).unwrap().join(V3_SIGNER_FILE);
        std::fs::write(&signer_path, b"corrupt signer component").unwrap();

        assert_eq!(load_dpapi_hub_public(&path).unwrap(), address);
        let (state_address, state_key) = load_dpapi_hub_state_key(&path).unwrap();
        assert_eq!(state_address, address);
        assert_eq!(state_key, expected_state_key);
        assert!(load_dpapi_hub_identity(&path).is_err());
    }

    #[test]
    fn v2_migration_is_exact_atomic_and_keeps_the_legacy_backup() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("hub.identity.dpapi");
        let address = create_dpapi_hub_identity_v2(&path).unwrap();
        let before = std::fs::read(&path).unwrap();
        let legacy = load_dpapi_hub_identity_v2(&path).unwrap();

        let installed = migrate_dpapi_hub_identity_to_v3(&path).unwrap();
        assert_eq!(installed, dpapi_identity_v3_dir(&path).unwrap());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        let migrated = load_dpapi_hub_identity(&path).unwrap();
        assert_eq!(migrated.address, address);
        assert_eq!(migrated.hub_secret_hex, legacy.hub_secret_hex);
        assert_eq!(migrated.journal_key_hex, legacy.journal_key_hex);
        assert_eq!(migrated.state_key_hex, legacy.state_key_hex);
        assert_eq!(load_dpapi_hub_public(&path).unwrap(), address);
        assert!(migrate_dpapi_hub_identity_to_v3(&path).is_err());
    }

    #[test]
    fn component_swapping_is_rejected_by_the_common_identity_binding() {
        let directory = tempfile::tempdir().unwrap();
        let first = directory.path().join("first.identity.dpapi");
        let second = directory.path().join("second.identity.dpapi");
        create_dpapi_hub_identity(&first).unwrap();
        create_dpapi_hub_identity(&second).unwrap();
        let first_v3 = dpapi_identity_v3_dir(&first).unwrap();
        let second_v3 = dpapi_identity_v3_dir(&second).unwrap();

        std::fs::copy(second_v3.join(V3_STATE_FILE), first_v3.join(V3_STATE_FILE)).unwrap();
        assert!(load_dpapi_hub_state_key(&first).is_err());
        assert!(load_dpapi_hub_identity(&first).is_err());
    }

    #[test]
    fn v3_parser_rejects_unknown_duplicate_and_noncanonical_fields() {
        let secret = "11".repeat(32);
        let address = Account::create_by(&secret).unwrap().readable().to_owned();
        let identity_id = "ab".repeat(32);
        let valid = format!(
            "format_version=3\nidentity_id={identity_id}\naddress={address}\nkind=signer\nkey_hex={secret}\n"
        );
        assert!(parse_identity_component(&valid, IdentityComponentKind::Signer).is_ok());
        assert!(
            parse_identity_component(
                &(valid.clone() + "unexpected=value\n"),
                IdentityComponentKind::Signer
            )
            .is_err()
        );
        assert!(
            parse_identity_component(
                &(valid.clone() + &format!("identity_id={identity_id}\n")),
                IdentityComponentKind::Signer
            )
            .is_err()
        );
        assert!(
            parse_identity_component(
                &valid.replace(&identity_id, &identity_id.to_ascii_uppercase()),
                IdentityComponentKind::Signer
            )
            .is_err()
        );
        assert!(
            parse_identity_component(
                &valid.replace("kind=signer", "kind=public"),
                IdentityComponentKind::Signer
            )
            .is_err()
        );
    }
}
