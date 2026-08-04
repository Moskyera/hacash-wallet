use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{CompanionError, CompanionResult};

pub(super) const MAX_LAN_ENDPOINTS: usize = 8;
const MAX_LAN_ENDPOINT_BYTES: usize = 80;
const SCHEME_PREFIX: &str = "hpay-lan://";

/// Canonical, same-LAN discovery endpoint carried by a pairing QR.
///
/// Only literal RFC1918/IPv4 link-local or IPv6 ULA addresses are
/// accepted. No hostname resolution or URL path semantics exist in this type.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LanEndpoint {
    ip: IpAddr,
    port: u16,
}

impl LanEndpoint {
    pub fn parse(value: &str) -> CompanionResult<Self> {
        if value.is_empty()
            || value.len() > MAX_LAN_ENDPOINT_BYTES
            || !value.is_ascii()
            || value.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(CompanionError::PairingMismatch);
        }
        let authority = value
            .strip_prefix(SCHEME_PREFIX)
            .ok_or(CompanionError::PairingMismatch)?;
        if authority.is_empty()
            || authority.contains(['@', '/', '?', '#', '%'])
            || authority.chars().any(char::is_whitespace)
        {
            return Err(CompanionError::PairingMismatch);
        }
        let (host, port) = parse_authority(authority)?;
        let ip = IpAddr::from_str(host).map_err(|_| CompanionError::PairingMismatch)?;
        if !allowed_lan_ip(ip) {
            return Err(CompanionError::PairingMismatch);
        }
        let endpoint = Self { ip, port };
        if endpoint.to_string() != value {
            return Err(CompanionError::PairingMismatch);
        }
        Ok(endpoint)
    }

    pub fn ip(&self) -> IpAddr {
        self.ip
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}

impl fmt::Display for LanEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.ip {
            IpAddr::V4(ip) => write!(formatter, "{SCHEME_PREFIX}{ip}:{}", self.port),
            IpAddr::V6(ip) => write!(formatter, "{SCHEME_PREFIX}[{ip}]:{}", self.port),
        }
    }
}

impl FromStr for LanEndpoint {
    type Err = CompanionError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl Serialize for LanEndpoint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for LanEndpoint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

fn parse_authority(authority: &str) -> CompanionResult<(&str, u16)> {
    let (host, port_text) = if let Some(bracketed) = authority.strip_prefix('[') {
        let close = bracketed.find(']').ok_or(CompanionError::PairingMismatch)?;
        let host = &bracketed[..close];
        let port_text = bracketed[close + 1..]
            .strip_prefix(':')
            .ok_or(CompanionError::PairingMismatch)?;
        if port_text.contains(':') {
            return Err(CompanionError::PairingMismatch);
        }
        (host, port_text)
    } else {
        let (host, port_text) = authority
            .rsplit_once(':')
            .ok_or(CompanionError::PairingMismatch)?;
        if host.contains(':') {
            return Err(CompanionError::PairingMismatch);
        }
        (host, port_text)
    };
    if host.is_empty()
        || port_text.is_empty()
        || (port_text.len() > 1 && port_text.starts_with('0'))
        || !port_text.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(CompanionError::PairingMismatch);
    }
    let port = port_text
        .parse::<u16>()
        .map_err(|_| CompanionError::PairingMismatch)?;
    if port == 0 {
        return Err(CompanionError::PairingMismatch);
    }
    Ok((host, port))
}

fn allowed_lan_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => allowed_v4(ip),
        IpAddr::V6(ip) => allowed_v6(ip),
    }
}

fn allowed_v4(ip: Ipv4Addr) -> bool {
    let [a, b, _, _] = ip.octets();
    let private = a == 10 || (a == 172 && (16..=31).contains(&b)) || (a == 192 && b == 168);
    let link_local = a == 169 && b == 254;
    (private || link_local)
        && !ip.is_unspecified()
        && !ip.is_loopback()
        && !ip.is_multicast()
        && !ip.is_broadcast()
}

fn allowed_v6(ip: Ipv6Addr) -> bool {
    let first = ip.segments()[0];
    let unique_local = first & 0xfe00 == 0xfc00;
    unique_local && !ip.is_unspecified() && !ip.is_loopback() && !ip.is_multicast()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_canonical_literal_private_or_link_local_endpoints() {
        for value in [
            "hpay-lan://10.1.2.3:443",
            "hpay-lan://172.16.1.2:65535",
            "hpay-lan://192.168.1.7:8080",
            "hpay-lan://169.254.2.3:1",
            "hpay-lan://192.168.0.0:443",
            "hpay-lan://192.168.1.255:443",
            "hpay-lan://[fd00::1]:443",
        ] {
            let endpoint = LanEndpoint::parse(value).unwrap();
            assert_eq!(endpoint.to_string(), value);
            let json = serde_json::to_string(&endpoint).unwrap();
            assert_eq!(
                serde_json::from_str::<LanEndpoint>(&json).unwrap(),
                endpoint
            );
        }
    }

    #[test]
    fn rejects_non_lan_and_url_semantics() {
        for value in [
            "http://192.168.1.2:443",
            "hpay-lan://example.com:443",
            "hpay-lan://8.8.8.8:443",
            "hpay-lan://127.0.0.1:443",
            "hpay-lan://0.0.0.0:443",
            "hpay-lan://224.0.0.1:443",
            "hpay-lan://255.255.255.255:443",
            "hpay-lan://192.168.1.2:0",
            "hpay-lan://192.168.1.2:0443",
            "hpay-lan://user@192.168.1.2:443",
            "hpay-lan://192.168.1.2:443/path",
            "hpay-lan://192.168.1.2:443?query",
            "hpay-lan://192.168.1.2:443#fragment",
            "hpay-lan://[::]:443",
            "hpay-lan://[::1]:443",
            "hpay-lan://[ff02::1]:443",
            "hpay-lan://[fe80::1]:443",
            "hpay-lan://[fe80::1%3]:443",
            "hpay-lan://[FD00::1]:443",
        ] {
            assert!(
                LanEndpoint::parse(value).is_err(),
                "unexpectedly accepted {value}"
            );
        }
    }
}
