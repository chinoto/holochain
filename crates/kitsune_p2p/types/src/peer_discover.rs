//! This module holds some kitsune peer discovery types and serialization logic

use byteorder::ByteOrder;

fn timestamp() -> i64 {
    chrono::Utc::now().naive_utc().timestamp()
}

fn b64(b: &[u8]) -> String {
    base64::encode_config(b, base64::URL_SAFE_NO_PAD)
}

const KITSUNE_QUIC_4: u16 = 0xc210;
const KITSUNE_QUIC_6: u16 = 0xc211;
const KITSUNE_HOSTED: u16 = 0xc250;

#[repr(u16)]
enum PeerType {
    KitsuneQuic4 = KITSUNE_QUIC_4,
    KitsuneQuic6 = KITSUNE_QUIC_6,
    KitsuneHosted = KITSUNE_HOSTED,
}

impl From<u16> for PeerType {
    fn from(u: u16) -> Self {
        match u {
            KITSUNE_QUIC_4 => Self::KitsuneQuic4,
            KITSUNE_QUIC_6 => Self::KitsuneQuic6,
            KITSUNE_HOSTED => Self::KitsuneHosted,
            _ => panic!("invalid PeerType {}", u),
        }
    }
}

const PEER_SIG_LEN: usize = 64;
const PEER_SIG_RANGE: std::ops::Range<usize> = 0..PEER_SIG_LEN;
const PEER_TYPE_LEN: usize = 2;
const PEER_TYPE_RANGE: std::ops::Range<usize> =
    PEER_SIG_RANGE.end..PEER_SIG_RANGE.end + PEER_TYPE_LEN;
const PEER_AGENT_LEN: usize = 32;
const PEER_AGENT_RANGE: std::ops::Range<usize> =
    PEER_TYPE_RANGE.end..PEER_TYPE_RANGE.end + PEER_AGENT_LEN;
const PEER_EXPIRES_LEN: usize = 8;
const PEER_EXPIRES_RANGE: std::ops::Range<usize> =
    PEER_AGENT_RANGE.end..PEER_AGENT_RANGE.end + PEER_EXPIRES_LEN;

const PEER_CUSTOM_START: usize = PEER_EXPIRES_RANGE.end;

const HQ4_IP_LEN: usize = 4;
const HQ4_IP_RANGE: std::ops::Range<usize> = PEER_CUSTOM_START..PEER_CUSTOM_START + HQ4_IP_LEN;
const HQ4_PORT_LEN: usize = 2;
const HQ4_PORT_RANGE: std::ops::Range<usize> = HQ4_IP_RANGE.end..HQ4_IP_RANGE.end + HQ4_PORT_LEN;
const HQ4_CERT_DIGEST_LEN: usize = 16;
const HQ4_CERT_DIGEST_RANGE: std::ops::Range<usize> =
    HQ4_PORT_RANGE.end..HQ4_PORT_RANGE.end + HQ4_CERT_DIGEST_LEN;

const PEER_DISCOVER_KITSUNE_QUIC_4_LEN: usize = HQ4_CERT_DIGEST_RANGE.end;

/// Peer Discovery Entry for a Kitsune Quic IPv4 connection
#[derive(Clone, Copy)]
pub struct PeerDiscoverKitsuneQuic4(pub [u8; PEER_DISCOVER_KITSUNE_QUIC_4_LEN]);

impl std::fmt::Debug for PeerDiscoverKitsuneQuic4 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerDiscoverKitsuneQuic4")
            .field("addr", &self.get_addr())
            .field("cert_digest", &b64(self.get_cert_digest()))
            .field("signing_agent", &b64(self.get_signing_agent()))
            .field("signature", &b64(self.get_signature()))
            .field("expires", &self.get_expires())
            .finish()
    }
}

impl PeerDiscoverKitsuneQuic4 {
    /// Construct a new KitsuneQuic4 PeerDiscover Entry
    pub fn new(
        addr: std::net::SocketAddrV4,
        cert_digest: &[u8],
        expires_in_secs: i64,
    ) -> PeerDiscover {
        let mut this = Self([0; PEER_DISCOVER_KITSUNE_QUIC_4_LEN]);

        this.set_expires(timestamp() + expires_in_secs);
        this.0[HQ4_IP_RANGE].copy_from_slice(&addr.ip().octets());
        byteorder::LittleEndian::write_u16(&mut this.0[HQ4_PORT_RANGE], addr.port());
        this.0[HQ4_CERT_DIGEST_RANGE].copy_from_slice(cert_digest);

        this.into()
    }

    /// Get the IPv4 address/port of this entry
    pub fn get_addr(&self) -> std::net::SocketAddrV4 {
        let port = byteorder::LittleEndian::read_u16(&self.0[HQ4_PORT_RANGE]);
        let mut ip = [0_u8; 4];
        ip.copy_from_slice(&self.0[HQ4_IP_RANGE]);
        let ip = std::net::Ipv4Addr::from(ip);
        std::net::SocketAddrV4::new(ip, port)
    }

    /// Get the TLS cert digest of this entry
    pub fn get_cert_digest(&self) -> &[u8] {
        &self.0[HQ4_CERT_DIGEST_RANGE]
    }
}

const HQ6_IP_LEN: usize = 16;
const HQ6_IP_RANGE: std::ops::Range<usize> = PEER_CUSTOM_START..PEER_CUSTOM_START + HQ6_IP_LEN;
const HQ6_PORT_LEN: usize = 2;
const HQ6_PORT_RANGE: std::ops::Range<usize> = HQ6_IP_RANGE.end..HQ6_IP_RANGE.end + HQ6_PORT_LEN;
const HQ6_CERT_DIGEST_LEN: usize = 16;
const HQ6_CERT_DIGEST_RANGE: std::ops::Range<usize> =
    HQ6_PORT_RANGE.end..HQ6_PORT_RANGE.end + HQ6_CERT_DIGEST_LEN;

const PEER_DISCOVER_KITSUNE_QUIC_6_LEN: usize = HQ6_CERT_DIGEST_RANGE.end;

/// Peer Discovery Entry for a Kitsune Quic IPv6 connection
#[derive(Clone, Copy)]
pub struct PeerDiscoverKitsuneQuic6(pub [u8; PEER_DISCOVER_KITSUNE_QUIC_6_LEN]);

impl std::fmt::Debug for PeerDiscoverKitsuneQuic6 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerDiscoverKitsuneQuic6")
            .field("addr", &self.get_addr())
            .field("cert_digest", &b64(self.get_cert_digest()))
            .field("signing_agent", &b64(self.get_signing_agent()))
            .field("signature", &b64(self.get_signature()))
            .field("expires", &self.get_expires())
            .finish()
    }
}

impl PeerDiscoverKitsuneQuic6 {
    /// Construct a new KitsuneQuic4 PeerDiscover Entry
    pub fn new(
        addr: std::net::SocketAddrV6,
        cert_digest: &[u8],
        expires_in_secs: i64,
    ) -> PeerDiscover {
        let mut this = Self([0; PEER_DISCOVER_KITSUNE_QUIC_6_LEN]);

        this.set_expires(timestamp() + expires_in_secs);
        this.0[HQ6_IP_RANGE].copy_from_slice(&addr.ip().octets());
        byteorder::LittleEndian::write_u16(&mut this.0[HQ6_PORT_RANGE], addr.port());
        this.0[HQ6_CERT_DIGEST_RANGE].copy_from_slice(cert_digest);

        this.into()
    }

    /// Get the IPv6 address/port of this entry
    pub fn get_addr(&self) -> std::net::SocketAddrV6 {
        let port = byteorder::LittleEndian::read_u16(&self.0[HQ6_PORT_RANGE]);
        let mut ip = [0_u8; 16];
        ip.copy_from_slice(&self.0[HQ6_IP_RANGE]);
        let ip = std::net::Ipv6Addr::from(ip);
        std::net::SocketAddrV6::new(ip, port, 0, 0)
    }

    /// Get the TLS cert digest of this entry
    pub fn get_cert_digest(&self) -> &[u8] {
        &self.0[HQ6_CERT_DIGEST_RANGE]
    }
}

const HH_A1_RANGE: std::ops::Range<usize> = PEER_CUSTOM_START..PEER_CUSTOM_START + PEER_AGENT_LEN;
const HH_A2_RANGE: std::ops::Range<usize> = HH_A1_RANGE.end..HH_A1_RANGE.end + PEER_AGENT_LEN;
const HH_A3_RANGE: std::ops::Range<usize> = HH_A2_RANGE.end..HH_A2_RANGE.end + PEER_AGENT_LEN;
const HH_A4_RANGE: std::ops::Range<usize> = HH_A3_RANGE.end..HH_A3_RANGE.end + PEER_AGENT_LEN;
const HH_A5_RANGE: std::ops::Range<usize> = HH_A4_RANGE.end..HH_A4_RANGE.end + PEER_AGENT_LEN;

const PEER_DISCOVER_KITSUNE_HOSTED_LEN: usize = HH_A5_RANGE.end;

/// Peer Discovery Entry for a Kitsune Hosted connection
#[derive(Clone, Copy)]
pub struct PeerDiscoverKitsuneHosted(pub [u8; PEER_DISCOVER_KITSUNE_HOSTED_LEN]);

impl std::fmt::Debug for PeerDiscoverKitsuneHosted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerDiscoverKitsuneHosted")
            .field("signing_agent", &b64(self.get_signing_agent()))
            .field("signature", &b64(self.get_signature()))
            .field("expires", &self.get_expires())
            .finish()
    }
}

/// Indicates that a type is a verifiable kitsune peer discover entry
pub trait PeerDiscoverVerifiable: AsRef<[u8]> {
    /// get the signature portion of this entry
    fn get_signature(&self) -> &[u8];

    /// set the signature portion of this entry
    fn set_signature(&mut self, sig: &[u8]);

    /// get the full content that is validated by signature
    fn get_signature_content(&self) -> &[u8];

    /// get the signing agent portion of this entry
    fn get_signing_agent(&self) -> &[u8];

    /// set the signing agent portion of this entry
    fn set_signing_agent(&mut self, agent: &[u8]);

    /// get the expires portion of this entry
    fn get_expires(&self) -> i64;

    /// set the expires portion of this entry
    fn set_expires(&mut self, ts: i64);

    /// set the signing agent portion from a private agent seed
    fn set_signing_agent_from_seed(&mut self, seed: &[u8]) {
        let key_pair = ring::signature::Ed25519KeyPair::from_seed_unchecked(seed).unwrap();
        let pub_key = ring::signature::KeyPair::public_key(&key_pair).as_ref();
        self.set_signing_agent(pub_key);
    }

    /// generate a new agent keypair, setting the agent, and returning the
    /// secret seed
    fn set_signing_agent_from_entropy(&mut self) -> Vec<u8> {
        let mut seed = vec![0; PEER_AGENT_LEN];
        let rng = ring::rand::SystemRandom::new();
        ring::rand::SecureRandom::fill(&rng, &mut seed).unwrap();
        self.set_signing_agent_from_seed(&seed);
        seed
    }

    /// given the private keypair seed, generate a signature for
    /// the agent over the signature_content
    fn sign(&mut self, seed: &[u8]) {
        let key_pair = ring::signature::Ed25519KeyPair::from_seed_unchecked(seed).unwrap();
        let pub_key = ring::signature::KeyPair::public_key(&key_pair).as_ref();
        assert_eq!(pub_key, self.get_signing_agent());
        let sig = key_pair.sign(self.get_signature_content());
        self.set_signature(sig.as_ref());
    }

    /// verify the included signature in this entry is valid for the
    /// agent / content
    fn verify_signature(&self) -> bool {
        let pub_key = ring::signature::UnparsedPublicKey::new(
            &ring::signature::ED25519,
            self.get_signing_agent(),
        );
        pub_key
            .verify(self.get_signature_content(), self.get_signature())
            .is_ok()
    }

    /// verify the entry has not yet expired
    fn verify_not_expired(&self) -> bool {
        self.get_expires() > timestamp()
    }
}

macro_rules! common_impl {
    ($($i:ident)*) => {$(
        impl AsRef<[u8]> for $i {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl PeerDiscoverVerifiable for $i {
            fn get_signature(&self) -> &[u8] {
                &self.0[PEER_SIG_RANGE]
            }

            fn set_signature(&mut self, sig: &[u8]) {
                assert_eq!(PEER_SIG_LEN, sig.len());
                self.0[PEER_SIG_RANGE].copy_from_slice(sig);
            }

            fn get_signature_content(&self) -> &[u8] {
                &self.0[PEER_SIG_RANGE.end..]
            }

            fn get_signing_agent(&self) -> &[u8] {
                &self.0[PEER_AGENT_RANGE]
            }

            fn set_signing_agent(&mut self, agent: &[u8]) {
                assert_eq!(PEER_AGENT_LEN, agent.len());
                self.0[PEER_AGENT_RANGE].copy_from_slice(agent);
            }

            fn get_expires(&self) -> i64 {
                byteorder::LittleEndian::read_i64(
                    &self.0[PEER_EXPIRES_RANGE]
                )
            }

            fn set_expires(&mut self, ts: i64) {
                byteorder::LittleEndian::write_i64(
                    &mut self.0[PEER_EXPIRES_RANGE],
                    ts,
                );
            }
        }
    )*};
}

common_impl!(PeerDiscoverKitsuneQuic4 PeerDiscoverKitsuneQuic6 PeerDiscoverKitsuneHosted);

/// An enum unioning the various Kitsune PeerDiscover types
#[derive(Clone, Copy)]
pub enum PeerDiscover {
    /// Peer Discovery Entry for a Kitsune Quic IPv4 connection
    KitsuneQuic4(PeerDiscoverKitsuneQuic4),
    /// Peer Discovery Entry for a Kitsune Quic IPv6 connection
    KitsuneQuic6(PeerDiscoverKitsuneQuic6),
    /// Peer Discovery Entry for a Kitsune Hosted connection
    KitsuneHosted(PeerDiscoverKitsuneHosted),
}

impl From<PeerDiscoverKitsuneQuic4> for PeerDiscover {
    fn from(q4: PeerDiscoverKitsuneQuic4) -> Self {
        Self::KitsuneQuic4(q4)
    }
}

impl From<PeerDiscoverKitsuneQuic6> for PeerDiscover {
    fn from(q6: PeerDiscoverKitsuneQuic6) -> Self {
        Self::KitsuneQuic6(q6)
    }
}

impl From<PeerDiscoverKitsuneHosted> for PeerDiscover {
    fn from(h: PeerDiscoverKitsuneHosted) -> Self {
        Self::KitsuneHosted(h)
    }
}

macro_rules! match_peer_discover {
    ($h:ident => |$i:ident| { $($t:tt)* }) => {
        match $h {
            PeerDiscover::KitsuneQuic4($i) => { $($t)* }
            PeerDiscover::KitsuneQuic6($i) => { $($t)* }
            PeerDiscover::KitsuneHosted($i) => { $($t)* }
        }
    };
}

impl std::fmt::Debug for PeerDiscover {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match_peer_discover!(self => |i| { i.fmt(f) })
    }
}

impl AsRef<[u8]> for PeerDiscover {
    fn as_ref(&self) -> &[u8] {
        match_peer_discover!(self => |i| { i.as_ref() })
    }
}

impl PeerDiscoverVerifiable for PeerDiscover {
    fn get_signature(&self) -> &[u8] {
        match_peer_discover!(self => |i| { i.get_signature() })
    }
    fn set_signature(&mut self, sig: &[u8]) {
        match_peer_discover!(self => |i| { i.set_signature(sig) })
    }
    fn get_signature_content(&self) -> &[u8] {
        match_peer_discover!(self => |i| { i.get_signature_content() })
    }
    fn get_signing_agent(&self) -> &[u8] {
        match_peer_discover!(self => |i| { i.get_signing_agent() })
    }
    fn set_signing_agent(&mut self, agent: &[u8]) {
        match_peer_discover!(self => |i| { i.set_signing_agent(agent) })
    }
    fn get_expires(&self) -> i64 {
        match_peer_discover!(self => |i| { i.get_expires() })
    }
    fn set_expires(&mut self, ts: i64) {
        match_peer_discover!(self => |i| { i.set_expires(ts) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_discover_struct_sizes() {
        assert_eq!(128, std::mem::size_of::<PeerDiscoverKitsuneQuic4>());
        let _ = PeerDiscoverKitsuneQuic4([0; 128]);
        assert_eq!(140, std::mem::size_of::<PeerDiscoverKitsuneQuic6>());
        let _ = PeerDiscoverKitsuneQuic6([0; 140]);
        assert_eq!(266, std::mem::size_of::<PeerDiscoverKitsuneHosted>());
        let _ = PeerDiscoverKitsuneHosted([0; 266]);
    }

    #[test]
    fn quic_v4_api() {
        let entry = {
            let mut entry = PeerDiscoverKitsuneQuic4::new(
                std::net::SocketAddrV4::new(std::net::Ipv4Addr::new(127, 0, 0, 1), 12345),
                &[0xdb; 16],
                40,
            );
            let seed = entry.set_signing_agent_from_entropy();
            entry.sign(&seed);
            entry
        };
        println!("{:#?}", entry);
        assert!(entry.verify_signature());
        assert!(entry.verify_not_expired());
        match entry {
            PeerDiscover::KitsuneQuic4(entry) => {
                assert_eq!(&[0xdb; 16], entry.get_cert_digest());
                assert_eq!(
                    &std::net::Ipv4Addr::new(127, 0, 0, 1),
                    entry.get_addr().ip(),
                );
                assert_eq!(12345, entry.get_addr().port());
            }
            _ => panic!("invalid type: {:?}", entry),
        }
    }
}
