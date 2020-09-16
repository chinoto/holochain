//! KitsuneP2p Proxy Wire Protocol Items.

use crate::*;

/// Proxy Wire Protocol Top-Level Enum.
#[derive(Debug, PartialEq)]
#[non_exhaustive]
pub enum ProxyWire {
    /// Generic proxy request failure.
    Failure(Failure),

    /// We want to be proxied by the remote end.
    RequestProxyService(RequestProxyService),

    /// The accept response to our request for proxy service.
    RequestProxyServiceAccepted(RequestProxyServiceAccepted),

    /// Create a proxy channel.
    CreateChannel(CreateChannel),

    /// Channel create success.
    CreateChannelSuccess(CreateChannelSuccess),

    /// Forward a message through the proxy.
    ProxyRequest(ProxyRequest),

    /// Receive a success response to a proxy request.
    ProxyResponseSuccess(ProxyResponseSuccess),
}

/// The accept response to our request for proxy service.
#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct Failure(
    /// The reason why the proxy request failed.
    pub String,
);

impl Failure {
    /// Get the rejection reason referenced by this message.
    pub fn reason(&self) -> &str {
        &self.0
    }
}

/// We want to be proxied by the remote end.
#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct RequestProxyService(
    /// cert digest
    #[serde(with = "serde_bytes")]
    pub Vec<u8>,
);

impl RequestProxyService {
    /// Get the certificate digest referenced by this message.
    pub fn into_cert_digest(self) -> CertDigest {
        self.0.into()
    }
}

/// The accept response to our request for proxy service.
#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct RequestProxyServiceAccepted(
    /// The granted proxy address you can now be reached at.
    pub String,
);

impl RequestProxyServiceAccepted {
    /// Get the proxy address referenced by this message.
    pub fn into_proxy_address(self) -> url2::Url2 {
        url2::url2!("{}", self.0)
    }
}

/// Create a proxy channel.
#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct CreateChannel(
    /// The cert_digest identified destination for this channel.
    #[serde(with = "serde_bytes")]
    pub Vec<u8>,
);

/// Channel Create success.
#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct CreateChannelSuccess(
    /// channel id
    pub u32,
);

impl CreateChannelSuccess {
    /// channel id
    pub fn channel_id(&self) -> u32 {
        self.0
    }
}

/// Forward a message through the proxy.
#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct ProxyRequest(
    /// channel id
    pub u32,
    /// The content of this request.
    #[serde(with = "serde_bytes")]
    pub Vec<u8>,
);

impl ProxyRequest {
    /// Get the channel id / content of this request.
    pub fn into_inner(self) -> (u32, Vec<u8>) {
        (self.0, self.1)
    }
}

/// Receive a success response to a proxy request.
#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct ProxyResponseSuccess(
    /// The content of this request.
    #[serde(with = "serde_bytes")]
    pub Vec<u8>,
);

impl ProxyResponseSuccess {
    /// Get the content of this success response.
    pub fn into_content(self) -> Vec<u8> {
        self.0
    }
}

const FAILURE: u8 = 0x02;
const REQUEST_PROXY_SERVICE: u8 = 0x10;
const REQUEST_PROXY_SERVICE_ACCEPTED: u8 = 0x11;
const CREATE_CHANNEL: u8 = 0x20;
const CREATE_CHANNEL_SUCCESS: u8 = 0x21;
const PROXY_REQUEST: u8 = 0x30;
const PROXY_RESPONSE_SUCCESS: u8 = 0x31;

impl ProxyWire {
    /// Generic proxy request failure.
    pub fn failure(reason: String) -> Self {
        Self::Failure(Failure(reason))
    }

    /// We want to be proxied by the remote end.
    pub fn request_proxy_service(cert_digest: CertDigest) -> Self {
        Self::RequestProxyService(RequestProxyService(cert_digest.0.to_vec()))
    }

    /// The accept response to our request for proxy service.
    pub fn request_proxy_service_accepted(proxy_address: url2::Url2) -> Self {
        Self::RequestProxyServiceAccepted(RequestProxyServiceAccepted(format!("{}", proxy_address)))
    }

    /// Create a proxy channel.
    pub fn create_channel(cert_digest: CertDigest) -> Self {
        Self::CreateChannel(CreateChannel(cert_digest.0.to_vec()))
    }

    /// Channel create success.
    pub fn create_channel_success(channel_id: u32) -> Self {
        Self::CreateChannelSuccess(CreateChannelSuccess(channel_id))
    }

    /// Forward a message through the proxy.
    pub fn proxy_request(channel_id: u32, content: Vec<u8>) -> Self {
        Self::ProxyRequest(ProxyRequest(channel_id, content))
    }

    /// Receive a success response to a proxy request.
    pub fn proxy_response_success(content: Vec<u8>) -> Self {
        Self::ProxyResponseSuccess(ProxyResponseSuccess(content))
    }

    /// Encode this wire message.
    pub fn encode(&self) -> TransportResult<Vec<u8>> {
        use serde::Serialize;
        let mut se = rmp_serde::encode::Serializer::new(Vec::new())
            .with_struct_map()
            .with_string_variants();
        let (s, u) = match self {
            Self::Failure(s) => (s.serialize(&mut se), FAILURE),
            Self::RequestProxyService(s) => (s.serialize(&mut se), REQUEST_PROXY_SERVICE),
            Self::RequestProxyServiceAccepted(s) => {
                (s.serialize(&mut se), REQUEST_PROXY_SERVICE_ACCEPTED)
            }
            Self::CreateChannel(s) => (s.serialize(&mut se), CREATE_CHANNEL),
            Self::CreateChannelSuccess(s) => (s.serialize(&mut se), CREATE_CHANNEL_SUCCESS),
            Self::ProxyRequest(s) => (s.serialize(&mut se), PROXY_REQUEST),
            Self::ProxyResponseSuccess(s) => (s.serialize(&mut se), PROXY_RESPONSE_SUCCESS),
        };
        s.map_err(TransportError::other)?;
        let mut out = se.into_inner();
        out.insert(0, u);
        Ok(out)
    }

    /// Decode a wire message.
    pub fn decode(data: &[u8]) -> TransportResult<Self> {
        Ok(match data[0] {
            FAILURE => {
                Self::Failure(rmp_serde::from_read_ref(&data[1..]).map_err(TransportError::other)?)
            }
            REQUEST_PROXY_SERVICE => Self::RequestProxyService(
                rmp_serde::from_read_ref(&data[1..]).map_err(TransportError::other)?,
            ),
            REQUEST_PROXY_SERVICE_ACCEPTED => Self::RequestProxyServiceAccepted(
                rmp_serde::from_read_ref(&data[1..]).map_err(TransportError::other)?,
            ),
            CREATE_CHANNEL => Self::CreateChannel(
                rmp_serde::from_read_ref(&data[1..]).map_err(TransportError::other)?,
            ),
            CREATE_CHANNEL_SUCCESS => Self::CreateChannelSuccess(
                rmp_serde::from_read_ref(&data[1..]).map_err(TransportError::other)?,
            ),
            PROXY_REQUEST => Self::ProxyRequest(
                rmp_serde::from_read_ref(&data[1..]).map_err(TransportError::other)?,
            ),
            PROXY_RESPONSE_SUCCESS => Self::ProxyResponseSuccess(
                rmp_serde::from_read_ref(&data[1..]).map_err(TransportError::other)?,
            ),
            _ => return Err("corrupt wire message".into()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! enc_dec_test {
        ($t:ident { $e:expr }) => {
            #[test]
            fn $t() {
                let msg: ProxyWire = $e;
                let enc = msg.encode().unwrap();
                let dec = ProxyWire::decode(&enc).unwrap();
                assert_eq!(msg, dec);
            }
        };
    }

    enc_dec_test!(can_encode_decode_failure {
        ProxyWire::failure("test".to_string())
    });

    enc_dec_test!(can_encode_decode_request_proxy_service {
        ProxyWire::request_proxy_service(vec![0xdb; 32].into())
    });

    enc_dec_test!(can_encode_decode_request_proxy_service_accepted {
        ProxyWire::request_proxy_service_accepted(url2::url2!("test://yo"))
    });

    enc_dec_test!(can_encode_decode_create_channel {
        ProxyWire::create_channel(vec![0xdb; 32].into())
    });

    enc_dec_test!(can_encode_decode_create_channel_success {
        ProxyWire::create_channel_success(42)
    });

    enc_dec_test!(can_encode_decode_proxy_request {
        ProxyWire::proxy_request(42, b"test".to_vec())
    });

    enc_dec_test!(can_encode_decode_proxy_response_success {
        ProxyWire::proxy_response_success(b"test".to_vec())
    });
}
