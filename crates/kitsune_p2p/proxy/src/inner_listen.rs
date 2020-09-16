use crate::*;

const ALPN_HC_PROXY_0: &[u8] = b"hc-proxy/0";
static CIPHER_SUITES: &[&rustls::SupportedCipherSuite] = &[
    &rustls::ciphersuite::TLS13_CHACHA20_POLY1305_SHA256,
    &rustls::ciphersuite::TLS13_AES_256_GCM_SHA384,
];

#[allow(dead_code)]
pub(crate) struct InnerListen {
    accept_proxy_cb: AcceptProxyCallback,
    sender: ghost_actor::GhostSender<TransportListener>,
    evt_send: futures::channel::mpsc::Sender<TransportListenerEvent>,
    tls: TlsConfig,
    tls_server_config: Arc<rustls::ServerConfig>,
    tls_client_config: Arc<rustls::ClientConfig>,
}

impl InnerListen {
    pub fn new(
        tls: TlsConfig,
        accept_proxy_cb: AcceptProxyCallback,
        sender: ghost_actor::GhostSender<TransportListener>,
        evt_send: futures::channel::mpsc::Sender<TransportListenerEvent>,
    ) -> TransportResult<Self> {
        let cert = rustls::Certificate(tls.cert.0.to_vec());
        let cert_priv_key = rustls::PrivateKey(tls.cert_priv_key.0.to_vec());

        let mut tls_server_config =
            rustls::ServerConfig::with_ciphersuites(rustls::NoClientAuth::new(), CIPHER_SUITES);
        tls_server_config
            .set_single_cert(vec![cert], cert_priv_key)
            .map_err(TransportError::other)?;
        tls_server_config.set_protocols(&[ALPN_HC_PROXY_0.to_vec()]);
        let tls_server_config = Arc::new(tls_server_config);

        let mut tls_client_config = rustls::ClientConfig::with_ciphersuites(CIPHER_SUITES);
        tls_client_config
            .dangerous()
            .set_certificate_verifier(TlsServerVerifier::new());
        tls_client_config.set_protocols(&[ALPN_HC_PROXY_0.to_vec()]);
        let tls_client_config = Arc::new(tls_client_config);

        Ok(Self {
            accept_proxy_cb,
            sender,
            evt_send,
            tls,
            tls_server_config,
            tls_client_config,
        })
    }
}

impl ghost_actor::GhostControlHandler for InnerListen {}

impl ghost_actor::GhostHandler<TransportListener> for InnerListen {}

impl TransportListenerHandler for InnerListen {
    fn handle_bound_url(&mut self) -> TransportListenerHandlerResult<url2::Url2> {
        // TODO translate url
        let fut = self.sender.bound_url();
        Ok(async move { fut.await }.boxed().into())
    }

    fn handle_connect(
        &mut self,
        url: url2::Url2,
    ) -> TransportListenerHandlerResult<(
        ghost_actor::GhostSender<TransportConnection>,
        TransportConnectionEventReceiver,
    )> {
        let accept_proxy_cb = self.accept_proxy_cb.clone();
        // TODO translate url
        let fut = self.sender.connect(url);
        let tls = self.tls.clone();
        let tls_server_config = self.tls_server_config.clone();
        let tls_client_config = self.tls_client_config.clone();
        Ok(async move {
            let (sender, receiver) = fut.await?;
            let (sender, receiver) = proxy_wrap_transport_connection(
                sender,
                receiver,
                tls,
                tls_server_config,
                tls_client_config,
            )
            .await?;
            if !accept_proxy_cb(vec![0; 32].into()).await {
                return Err("Refusing to proxy".into());
            }
            Ok((sender, receiver))
        }
        .boxed()
        .into())
    }
}

impl ghost_actor::GhostHandler<TransportListenerEvent> for InnerListen {}

impl TransportListenerEventHandler for InnerListen {
    fn handle_incoming_connection(
        &mut self,
        sender: ghost_actor::GhostSender<TransportConnection>,
        receiver: TransportConnectionEventReceiver,
    ) -> TransportListenerEventHandlerResult<()> {
        let evt_send = self.evt_send.clone();
        let tls = self.tls.clone();
        let tls_server_config = self.tls_server_config.clone();
        let tls_client_config = self.tls_client_config.clone();
        Ok(async move {
            let (sender, receiver) = proxy_wrap_transport_connection(
                sender,
                receiver,
                tls,
                tls_server_config,
                tls_client_config,
            )
            .await?;
            evt_send.incoming_connection(sender, receiver).await?;
            Ok(())
        }
        .boxed()
        .into())
    }
}

struct TlsServerVerifier;

impl TlsServerVerifier {
    fn new() -> Arc<Self> {
        Arc::new(Self)
    }
}

impl rustls::ServerCertVerifier for TlsServerVerifier {
    fn verify_server_cert(
        &self,
        _roots: &rustls::RootCertStore,
        _presented_certs: &[rustls::Certificate],
        _dns_name: webpki::DNSNameRef,
        _ocsp_response: &[u8],
    ) -> Result<rustls::ServerCertVerified, rustls::TLSError> {
        // TODO - check acceptable cert digest

        Ok(rustls::ServerCertVerified::assertion())
    }
}
