//! KitsuneP2p Proxy Wire Protocol Items.

use crate::*;
use lair_keystore_api::actor::*;

/// Proxy Wire Protocol Top-Level Enum.
#[derive(Debug, PartialEq)]
#[non_exhaustive]
pub enum ProxyWire {
    /// We want to be proxied by the remote end.
    RequestProxyService(RequestProxyService),

    /// The accept response to our request for proxy service.
    RequestProxyServiceAccepted(RequestProxyServiceAccepted),

    /// The accept response to our request for proxy service.
    RequestProxyServiceRejected(RequestProxyServiceRejected),

    /// Forward a message through the proxy.
    ProxyRequest(ProxyRequest),

    /// Receive a success response to a proxy request.
    ProxyResponseSuccess(ProxyResponseSuccess),

    /// Receive a failure response to a proxy request.
    ProxyResponseFailure(ProxyResponseFailure),
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

/// The accept response to our request for proxy service.
#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct RequestProxyServiceRejected(
    /// The reason why the proxy request was rejected.
    pub String,
);

impl RequestProxyServiceRejected {
    /// Get the rejection reason referenced by this message.
    pub fn reason(&self) -> &str {
        &self.0
    }
}

/// Forward a message through the proxy.
#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct ProxyRequest(
    /// The cert_digest identified destination for this message.
    #[serde(with = "serde_bytes")]
    pub Vec<u8>,
    /// The content of this request.
    #[serde(with = "serde_bytes")]
    pub Vec<u8>,
);

impl ProxyRequest {
    /// Get the digest / content of this request.
    pub fn into_inner(self) -> (CertDigest, Vec<u8>) {
        (self.0.into(), self.1)
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

/// Receive a failure response to a proxy request.
#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct ProxyResponseFailure(
    /// The reason why the proxy request failed.
    pub String,
);

impl ProxyResponseFailure {
    /// Get the rejection reason referenced by this message.
    pub fn reason(&self) -> &str {
        &self.0
    }
}

const REQUEST_PROXY_SERVICE: u8 = 0x10;
const REQUEST_PROXY_SERVICE_ACCEPTED: u8 = 0x11;
const REQUEST_PROXY_SERVICE_REJECTED: u8 = 0x12;
const PROXY_REQUEST: u8 = 0x20;
const PROXY_RESPONSE_SUCCESS: u8 = 0x21;
const PROXY_RESPONSE_FAILURE: u8 = 0x22;

impl ProxyWire {
    /// We want to be proxied by the remote end.
    pub fn request_proxy_service(cert_digest: CertDigest) -> Self {
        Self::RequestProxyService(RequestProxyService(cert_digest.0.to_vec()))
    }

    /// The accept response to our request for proxy service.
    pub fn request_proxy_service_accepted(proxy_address: url2::Url2) -> Self {
        Self::RequestProxyServiceAccepted(RequestProxyServiceAccepted(format!("{}", proxy_address)))
    }

    /// The accept response to our request for proxy service.
    pub fn request_proxy_service_rejected(reason: String) -> Self {
        Self::RequestProxyServiceRejected(RequestProxyServiceRejected(reason))
    }

    /// Forward a message through the proxy.
    pub fn proxy_request(cert_digest: CertDigest, content: Vec<u8>) -> Self {
        Self::ProxyRequest(ProxyRequest(cert_digest.0.to_vec(), content))
    }

    /// Receive a success response to a proxy request.
    pub fn proxy_response_success(content: Vec<u8>) -> Self {
        Self::ProxyResponseSuccess(ProxyResponseSuccess(content))
    }

    /// Receive a failure response to a proxy request.
    pub fn proxy_response_failure(reason: String) -> Self {
        Self::ProxyResponseFailure(ProxyResponseFailure(reason))
    }

    /// Encode this wire message.
    pub fn encode(&self) -> TransportResult<Vec<u8>> {
        use serde::Serialize;
        let mut se = rmp_serde::encode::Serializer::new(Vec::new())
            .with_struct_map()
            .with_string_variants();
        let (s, u) = match self {
            Self::RequestProxyService(s) => (s.serialize(&mut se), REQUEST_PROXY_SERVICE),
            Self::RequestProxyServiceAccepted(s) => {
                (s.serialize(&mut se), REQUEST_PROXY_SERVICE_ACCEPTED)
            }
            Self::RequestProxyServiceRejected(s) => {
                (s.serialize(&mut se), REQUEST_PROXY_SERVICE_REJECTED)
            }
            Self::ProxyRequest(s) => (s.serialize(&mut se), PROXY_REQUEST),
            Self::ProxyResponseSuccess(s) => (s.serialize(&mut se), PROXY_RESPONSE_SUCCESS),
            Self::ProxyResponseFailure(s) => (s.serialize(&mut se), PROXY_RESPONSE_FAILURE),
        };
        s.map_err(TransportError::other)?;
        let mut out = se.into_inner();
        out.insert(0, u);
        Ok(out)
    }

    /// Decode a wire message.
    pub fn decode(data: &[u8]) -> TransportResult<Self> {
        Ok(match data[0] {
            REQUEST_PROXY_SERVICE => Self::RequestProxyService(
                rmp_serde::from_read_ref(&data[1..]).map_err(TransportError::other)?,
            ),
            REQUEST_PROXY_SERVICE_ACCEPTED => Self::RequestProxyServiceAccepted(
                rmp_serde::from_read_ref(&data[1..]).map_err(TransportError::other)?,
            ),
            REQUEST_PROXY_SERVICE_REJECTED => Self::RequestProxyServiceRejected(
                rmp_serde::from_read_ref(&data[1..]).map_err(TransportError::other)?,
            ),
            PROXY_REQUEST => Self::ProxyRequest(
                rmp_serde::from_read_ref(&data[1..]).map_err(TransportError::other)?,
            ),
            PROXY_RESPONSE_SUCCESS => Self::ProxyResponseSuccess(
                rmp_serde::from_read_ref(&data[1..]).map_err(TransportError::other)?,
            ),
            PROXY_RESPONSE_FAILURE => Self::ProxyResponseFailure(
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

    enc_dec_test!(can_encode_decode_request_proxy_service {
        ProxyWire::request_proxy_service(vec![0xdb; 32].into())
    });

    enc_dec_test!(can_encode_decode_request_proxy_service_accepted {
        ProxyWire::request_proxy_service_accepted(url2::url2!("test://yo"))
    });

    enc_dec_test!(can_encode_decode_request_proxy_service_rejected {
        ProxyWire::request_proxy_service_rejected("test".to_string())
    });

    enc_dec_test!(can_encode_decode_proxy_request {
        ProxyWire::proxy_request(vec![0xdb; 32].into(), b"test".to_vec())
    });

    enc_dec_test!(can_encode_decode_proxy_response_success {
        ProxyWire::proxy_response_success(b"test".to_vec())
    });

    enc_dec_test!(can_encode_decode_proxy_response_failure {
        ProxyWire::proxy_response_failure("test".to_string())
    });
}
