#![deny(missing_docs)]
//! Proxy transport module for kitsune-p2p

use futures::future::FutureExt;
use ghost_actor::dependencies::must_future::MustBoxFuture;
use kitsune_p2p_types::{
    dependencies::{ghost_actor, url2},
    transport::{transport_connection::*, transport_listener::*, *},
};
use lair_keystore_api::actor::*;
use std::sync::Arc;

pub mod wire;

/// Callback type for proxy accept/deny.
pub type AcceptProxyCallback = Arc<
    dyn Fn(lair_keystore_api::actor::CertDigest) -> MustBoxFuture<'static, bool>
        + 'static
        + Send
        + Sync,
>;

/// Tls Configuration for proxy.
#[derive(Clone)]
pub struct TlsConfig {
    /// Cert
    pub cert: Cert,

    /// Cert SNI
    pub sni: CertSni,

    /// Cert Priv Key
    pub cert_priv_key: CertPrivKey,

    /// Cert Digest
    pub cert_digest: CertDigest,
}

/// Configuration for proxy binding.
pub enum ProxyConfig {
    /// We want to be hosted at a remote proxy location.
    RemoteProxyClient {
        /// The Tls config for this proxy endpoint.
        tls: TlsConfig,

        /// The remote proxy url to be hosted at.
        proxy_url: url2::Url2,
    },

    /// We want to be a proxy server for others.
    LocalProxyServer {
        /// The Tls config for this proxy endpoint.
        tls: TlsConfig,

        /// Return true if we should take on proxying for the
        /// requesting client.
        accept_proxy_cb: AcceptProxyCallback,
    },
}

/// Wrap a transport listener sender/receiver in kitsune proxy logic.
pub async fn proxy_wrap_transport_listener(
    proxy_config: ProxyConfig,
    sender: ghost_actor::GhostSender<TransportListener>,
    receiver: TransportListenerEventReceiver,
) -> TransportResult<(
    ghost_actor::GhostSender<TransportListener>,
    TransportListenerEventReceiver,
)> {
    if let ProxyConfig::RemoteProxyClient { proxy_url, .. } = &proxy_config {
        // TODO - request proxying at proxy_url:
        println!("TODO - request proxying at: {}", proxy_url);
    }

    let (tls, accept_proxy_cb): (TlsConfig, AcceptProxyCallback) = match proxy_config {
        ProxyConfig::RemoteProxyClient { tls, .. } => {
            (tls, Arc::new(|_| async move { false }.boxed().into()))
        }
        ProxyConfig::LocalProxyServer {
            tls,
            accept_proxy_cb,
            ..
        } => (tls, accept_proxy_cb),
    };

    let builder = ghost_actor::actor_builder::GhostActorBuilder::new();

    let new_sender = builder
        .channel_factory()
        .create_channel::<TransportListener>()
        .await?;

    builder.channel_factory().attach_receiver(receiver).await?;

    let (evt_send, evt_recv) = futures::channel::mpsc::channel(10);

    tokio::task::spawn(builder.spawn(InnerListen::new(tls, accept_proxy_cb, sender, evt_send)?));

    Ok((new_sender, evt_recv))
}

mod inner_con;
pub(crate) use inner_con::*;

mod inner_listen;
pub(crate) use inner_listen::*;
