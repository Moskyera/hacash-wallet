use std::collections::HashMap;
use std::future::Future;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/// GitHub releases source for in-app updates (desktop + mobile).
pub const GITHUB_REPO: &str = "Moskyera/hacash-wallet";
#[path = "update_download.rs"]
mod download;

pub use download::{
    download_update_file, run_windows_installer, validate_apk_file, validate_downloaded_update,
    validate_release_download_url, validate_windows_exe, validate_windows_msi,
    verify_downloaded_update,
};
use download::{max_update_size, trusted_redirect_url, validate_release_asset_url};

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum AppUpdateInfo {
    UpToDate {
        current_version: String,
        latest_version: String,
        release_notes: Option<String>,
        release_page: Option<String>,
        target_os: String,
        target_arch: String,
    },
    AvailableTrusted {
        current_version: String,
        latest_version: String,
        release_notes: Option<String>,
        release_page: String,
        target_os: String,
        target_arch: String,
        offer_id: String,
        asset_name: String,
        download_size: u64,
    },
    AvailableManual {
        current_version: String,
        latest_version: String,
        release_notes: Option<String>,
        release_page: String,
        target_os: String,
        target_arch: String,
    },
    AvailableUntrusted {
        current_version: String,
        latest_version: String,
        release_notes: Option<String>,
        release_page: String,
        target_os: String,
        target_arch: String,
    },
}

#[derive(Debug, Clone, Deserialize)]
struct GhRelease {
    tag_name: String,
    name: Option<String>,
    body: Option<String>,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    prerelease: bool,
    assets: Vec<GhAsset>,
}

#[derive(Debug, Clone, Deserialize)]
struct GhAsset {
    name: String,
    browser_download_url: String,
    size: u64,
    digest: Option<String>,
    state: String,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UpdateChannel {
    Desktop,
    Mobile,
}

impl UpdateChannel {
    fn as_str(self) -> &'static str {
        match self {
            Self::Desktop => "desktop",
            Self::Mobile => "mobile",
        }
    }

    fn tag_suffix(self) -> &'static str {
        match self {
            Self::Desktop => "-desktop",
            Self::Mobile => "-mobile",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UpdateTarget {
    os: String,
    arch: String,
}

impl UpdateTarget {
    pub(crate) fn current() -> Self {
        Self::from_parts(std::env::consts::OS, std::env::consts::ARCH)
    }

    fn from_parts(os: &str, arch: &str) -> Self {
        Self {
            os: os.to_ascii_lowercase(),
            arch: arch.to_ascii_lowercase(),
        }
    }

    pub(crate) fn channel(&self) -> UpdateChannel {
        if matches!(self.os.as_str(), "android" | "ios") {
            UpdateChannel::Mobile
        } else {
            UpdateChannel::Desktop
        }
    }

    pub(crate) fn supports_automatic_install(&self) -> bool {
        matches!(
            (self.os.as_str(), self.arch.as_str()),
            ("windows", "x86_64") | ("android", "aarch64")
        )
    }
}

#[derive(Debug, Clone)]
pub(crate) struct TrustedUpdate {
    pub channel: UpdateChannel,
    pub download_url: String,
    pub asset_name: String,
    pub download_size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone)]
enum OfferPhase {
    Ready,
    Downloading,
    Downloaded(PathBuf),
}

#[derive(Debug, Clone)]
struct StoredUpdateOffer {
    update: TrustedUpdate,
    phase: OfferPhase,
    expires_at: Instant,
}

const UPDATE_OFFER_TTL: Duration = Duration::from_secs(30 * 60);
const MAX_STORED_UPDATE_OFFERS: usize = 8;

#[derive(Default)]
pub struct UpdateOfferStore {
    inner: Mutex<HashMap<String, StoredUpdateOffer>>,
}

impl UpdateOfferStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub(crate) fn register(&self, update: TrustedUpdate) -> String {
        self.register_at(update, Instant::now())
    }

    fn register_at(&self, update: TrustedUpdate, now: Instant) -> String {
        let mut offers = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Self::purge_expired(&mut offers, now);
        while offers.len() >= MAX_STORED_UPDATE_OFFERS {
            let oldest = offers
                .iter()
                .min_by_key(|(_, offer)| offer.expires_at)
                .map(|(id, _)| id.clone());
            let Some(oldest) = oldest else { break };
            offers.remove(&oldest);
        }
        let id = uuid::Uuid::new_v4().to_string();
        offers.insert(
            id.clone(),
            StoredUpdateOffer {
                update,
                phase: OfferPhase::Ready,
                expires_at: now + UPDATE_OFFER_TTL,
            },
        );
        id
    }

    pub(crate) fn begin_download(&self, id: &str) -> Result<TrustedUpdate, String> {
        self.begin_download_at(id, Instant::now())
    }

    fn begin_download_at(&self, id: &str, now: Instant) -> Result<TrustedUpdate, String> {
        let mut offers = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Self::purge_expired(&mut offers, now);
        let offer = offers.get_mut(id).ok_or_else(|| {
            "update offer is missing or expired; check for updates again".to_string()
        })?;
        if !matches!(offer.phase, OfferPhase::Ready) {
            return Err("update offer is already downloading or downloaded".into());
        }
        offer.phase = OfferPhase::Downloading;
        Ok(offer.update.clone())
    }

    pub(crate) fn download_failed(&self, id: &str) {
        let mut offers = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(offer) = offers.get_mut(id)
            && matches!(offer.phase, OfferPhase::Downloading)
        {
            offer.phase = OfferPhase::Ready;
        }
    }

    pub(crate) fn download_complete(&self, id: &str, path: PathBuf) -> Result<(), String> {
        self.download_complete_at(id, path, Instant::now())
    }

    fn download_complete_at(&self, id: &str, path: PathBuf, now: Instant) -> Result<(), String> {
        let mut offers = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Self::purge_expired(&mut offers, now);
        let offer = offers
            .get_mut(id)
            .ok_or_else(|| "update offer expired during download".to_string())?;
        if !matches!(offer.phase, OfferPhase::Downloading) {
            return Err("update offer is not downloading".into());
        }
        offer.phase = OfferPhase::Downloaded(path);
        offer.expires_at = now + UPDATE_OFFER_TTL;
        Ok(())
    }

    pub(crate) fn downloaded(
        &self,
        id: &str,
        channel: UpdateChannel,
    ) -> Result<(TrustedUpdate, PathBuf), String> {
        self.downloaded_at(id, channel, Instant::now())
    }

    fn downloaded_at(
        &self,
        id: &str,
        channel: UpdateChannel,
        now: Instant,
    ) -> Result<(TrustedUpdate, PathBuf), String> {
        let mut offers = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Self::purge_expired(&mut offers, now);
        let offer = offers.get(id).ok_or_else(|| {
            "update offer is missing or expired; check for updates again".to_string()
        })?;
        if offer.update.channel != channel {
            return Err("update offer belongs to a different platform".into());
        }
        let OfferPhase::Downloaded(path) = &offer.phase else {
            return Err("update has not been downloaded and verified".into());
        };
        Ok((offer.update.clone(), path.clone()))
    }

    fn purge_expired(offers: &mut HashMap<String, StoredUpdateOffer>, now: Instant) {
        offers.retain(|_, offer| offer.expires_at > now);
    }
}

pub fn parse_semver_triplet(raw: &str) -> Option<(u32, u32, u32)> {
    let raw = raw.trim();
    let raw = raw.strip_prefix('v').unwrap_or(raw);
    let base = raw
        .strip_suffix("-desktop")
        .or_else(|| raw.strip_suffix("-mobile"))
        .unwrap_or(raw);
    let mut parts = base.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((major, minor, patch))
}

fn is_newer(latest: (u32, u32, u32), current: (u32, u32, u32)) -> bool {
    latest > current
}

fn update_asset_priority(target: &UpdateTarget, version: &str, name: &str) -> Option<u8> {
    match (target.os.as_str(), target.arch.as_str()) {
        ("android", "aarch64") if name == format!("hacash-wallet-mobile-v{version}-arm64.apk") => {
            Some(0)
        }
        ("windows", "x86_64")
            if name == format!("hacash-wallet-desktop-v{version}-x64-setup.exe") =>
        {
            Some(1)
        }
        ("windows", "x86_64") if name == format!("hacash-wallet-desktop-v{version}-x64.msi") => {
            Some(0)
        }
        _ => None,
    }
}

fn parse_release_triplet(tag: &str, channel: UpdateChannel) -> Option<(u32, u32, u32)> {
    let version = tag.strip_prefix('v')?.strip_suffix(channel.tag_suffix())?;
    let triplet = parse_semver_triplet(version)?;
    (tag == format!(
        "v{}.{}.{}{}",
        triplet.0,
        triplet.1,
        triplet.2,
        channel.tag_suffix()
    ))
    .then_some(triplet)
}

fn version_text(version: (u32, u32, u32)) -> String {
    format!("{}.{}.{}", version.0, version.1, version.2)
}

fn release_page(tag: &str) -> String {
    format!("https://github.com/{GITHUB_REPO}/releases/tag/{tag}")
}

#[derive(Debug, Clone)]
struct EligibleAsset {
    priority: u8,
    channel: UpdateChannel,
    asset: GhAsset,
}

fn eligible_assets(
    release: &GhRelease,
    target: &UpdateTarget,
    version: (u32, u32, u32),
) -> Vec<EligibleAsset> {
    let version = version_text(version);
    let channel = target.channel();
    let max_size = match max_update_size(channel.as_str()) {
        Ok(size) => size,
        Err(_) => return Vec::new(),
    };
    let mut candidates = release
        .assets
        .iter()
        .filter_map(|asset| {
            let priority = update_asset_priority(target, &version, &asset.name)?;
            if asset.state != "uploaded"
                || !(100_000..=max_size).contains(&asset.size)
                || validate_release_asset_url(
                    &asset.browser_download_url,
                    &release.tag_name,
                    &asset.name,
                )
                .is_err()
            {
                return None;
            }
            Some(EligibleAsset {
                priority,
                channel,
                asset: asset.clone(),
            })
        })
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| {
        left.priority
            .cmp(&right.priority)
            .then_with(|| left.asset.name.cmp(&right.asset.name))
    });
    candidates
}

async fn resolve_trusted_asset<F, Fut>(
    candidates: Vec<EligibleAsset>,
    load_sums: F,
) -> Option<TrustedUpdate>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<HashMap<String, String>, String>>,
{
    let mut loader = Some(load_sums);
    let mut sums: Option<HashMap<String, String>> = None;
    let mut sums_attempted = false;
    for candidate in candidates {
        let sha256 = if let Some(digest) = normalized_asset_digest(&candidate.asset) {
            Some(digest)
        } else {
            if !sums_attempted {
                sums_attempted = true;
                if let Some(load) = loader.take() {
                    sums = load().await.ok();
                }
            }
            sums.as_ref()
                .and_then(|values| values.get(&candidate.asset.name).cloned())
        };
        if let Some(sha256) = sha256 {
            return Some(TrustedUpdate {
                channel: candidate.channel,
                download_url: candidate.asset.browser_download_url,
                asset_name: candidate.asset.name,
                download_size: candidate.asset.size,
                sha256,
            });
        }
    }
    None
}

pub async fn check_app_update(
    current_version: &str,
    offers: &UpdateOfferStore,
) -> Result<AppUpdateInfo, String> {
    check_app_update_for_target(current_version, offers, UpdateTarget::current()).await
}

async fn check_app_update_for_target(
    current_version: &str,
    offers: &UpdateOfferStore,
    target: UpdateTarget,
) -> Result<AppUpdateInfo, String> {
    let channel = target.channel();
    let current_triplet = parse_semver_triplet(current_version)
        .ok_or_else(|| format!("invalid current version: {current_version}"))?;

    let url = format!("https://api.github.com/repos/{GITHUB_REPO}/releases?per_page=40");
    let client = updater_http_client()?;
    let releases: Vec<GhRelease> = client
        .get(&url)
        .send()
        .await
        .map_err(|error| format!("release check: {error}"))?
        .error_for_status()
        .map_err(|error| format!("release check: {error}"))?
        .json()
        .await
        .map_err(|error| format!("release check: {error}"))?;

    let mut best: Option<(GhRelease, (u32, u32, u32))> = None;
    for release in releases {
        if release.draft || release.prerelease {
            continue;
        }
        let Some(triplet) = parse_release_triplet(&release.tag_name, channel) else {
            continue;
        };
        if best
            .as_ref()
            .map(|(_, value)| triplet > *value)
            .unwrap_or(true)
        {
            best = Some((release, triplet));
        }
    }

    let Some((release, latest_triplet)) = best else {
        return Err(format!(
            "no compatible {} release was found in the official repository",
            channel.as_str()
        ));
    };

    let latest_version = format!("v{}", version_text(latest_triplet));
    let notes = release.body.clone().or(release.name.clone());
    let page = release_page(&release.tag_name);
    if !is_newer(latest_triplet, current_triplet) {
        return Ok(AppUpdateInfo::UpToDate {
            current_version: current_version.to_string(),
            latest_version,
            release_notes: notes,
            release_page: Some(page),
            target_os: target.os,
            target_arch: target.arch,
        });
    }

    if !target.supports_automatic_install() {
        return Ok(AppUpdateInfo::AvailableManual {
            current_version: current_version.to_string(),
            latest_version,
            release_notes: notes,
            release_page: page,
            target_os: target.os,
            target_arch: target.arch,
        });
    }

    let candidates = eligible_assets(&release, &target, latest_triplet);
    let trusted = resolve_trusted_asset(candidates, || {
        load_sha256_from_release_sums(&client, &release, channel, latest_triplet)
    })
    .await;

    let Some(trusted) = trusted else {
        return Ok(AppUpdateInfo::AvailableUntrusted {
            current_version: current_version.to_string(),
            latest_version,
            release_notes: notes,
            release_page: page,
            target_os: target.os,
            target_arch: target.arch,
        });
    };
    let asset_name = trusted.asset_name.clone();
    let download_size = trusted.download_size;
    let offer_id = offers.register(trusted);
    Ok(AppUpdateInfo::AvailableTrusted {
        current_version: current_version.to_string(),
        latest_version,
        release_notes: notes,
        release_page: page,
        target_os: target.os,
        target_arch: target.arch,
        offer_id,
        asset_name,
        download_size,
    })
}

/// Download and parse the exact channel checksum file only when an eligible asset has no digest.
async fn load_sha256_from_release_sums(
    client: &reqwest::Client,
    release: &GhRelease,
    channel: UpdateChannel,
    version: (u32, u32, u32),
) -> Result<HashMap<String, String>, String> {
    const MAX_SUMS_BYTES: u64 = 64 * 1024;
    let name = format!(
        "SHA256SUMS-v{}-{}.txt",
        version_text(version),
        channel.as_str()
    );
    let sums = release
        .assets
        .iter()
        .find(|asset| asset.name == name)
        .ok_or_else(|| "release checksum file is missing".to_string())?;
    if sums.state != "uploaded" || !(1..=MAX_SUMS_BYTES).contains(&sums.size) {
        return Err("release checksum file has an invalid state or size".into());
    }
    validate_release_asset_url(&sums.browser_download_url, &release.tag_name, &sums.name)?;
    let mut response = client
        .get(&sums.browser_download_url)
        .send()
        .await
        .map_err(|error| format!("checksum download: {error}"))?
        .error_for_status()
        .map_err(|error| format!("checksum download: {error}"))?;
    if !trusted_redirect_url(response.url()) {
        return Err("checksum download ended on an untrusted host".into());
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_SUMS_BYTES)
    {
        return Err("release checksum file is too large".into());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| format!("checksum download: {error}"))?
    {
        if body.len().saturating_add(chunk.len()) > MAX_SUMS_BYTES as usize {
            return Err("release checksum file exceeded the size limit".into());
        }
        body.extend_from_slice(&chunk);
    }
    let body =
        String::from_utf8(body).map_err(|_| "release checksum file is not UTF-8".to_string())?;
    parse_sha256_sums(&body)
}

fn parse_sha256_sums(body: &str) -> Result<HashMap<String, String>, String> {
    let mut map = HashMap::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let hex = parts
            .next()
            .ok_or_else(|| "malformed checksum line".to_string())?;
        let name = parts
            .next()
            .ok_or_else(|| "malformed checksum line".to_string())?;
        if parts.next().is_some() || !valid_asset_filename(name) {
            return Err("malformed checksum filename".into());
        }
        let hex = hex.to_ascii_lowercase();
        if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err("malformed SHA-256 checksum".into());
        }
        if map.insert(name.to_string(), hex).is_some() {
            return Err("duplicate filename in release checksum file".into());
        }
    }
    if map.is_empty() {
        Err("release checksum file is empty".into())
    } else {
        Ok(map)
    }
}
fn valid_asset_filename(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 160
        && name.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_')
        })
}

fn updater_http_client() -> Result<reqwest::Client, String> {
    let redirect = reqwest::redirect::Policy::custom(|attempt| {
        if attempt.previous().len() >= 5 {
            return attempt.error(std::io::Error::other("too many updater redirects"));
        }
        if trusted_redirect_url(attempt.url()) {
            attempt.follow()
        } else {
            attempt.error(std::io::Error::other("untrusted updater redirect"))
        }
    });
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(45))
        .user_agent(concat!(
            "HacashWallet/",
            env!("CARGO_PKG_VERSION"),
            " updater"
        ))
        .redirect(redirect)
        .build()
        .map_err(|error| format!("updater HTTP client: {error}"))
}
fn normalized_asset_digest(asset: &GhAsset) -> Option<String> {
    let digest = asset.digest.as_deref()?.strip_prefix("sha256:")?;
    if digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Some(digest.to_ascii_lowercase())
    } else {
        None
    }
}

#[cfg(test)]
#[path = "update_tests.rs"]
mod tests;
