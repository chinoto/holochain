use crate::*;

pub(crate) async fn proxy_wrap_transport_connection(
    sender: ghost_actor::GhostSender<TransportConnection>,
    receiver: TransportConnectionEventReceiver,
    tls: TlsConfig,
    tls_server_config: Arc<rustls::ServerConfig>,
    tls_client_config: Arc<rustls::ClientConfig>,
) -> TransportResult<(
    ghost_actor::GhostSender<TransportConnection>,
    TransportConnectionEventReceiver,
)> {
    let builder = ghost_actor::actor_builder::GhostActorBuilder::new();

    let new_sender = builder
        .channel_factory()
        .create_channel::<TransportConnection>()
        .await?;

    builder.channel_factory().attach_receiver(receiver).await?;

    let (evt_send, evt_recv) = futures::channel::mpsc::channel(10);

    tokio::task::spawn(builder.spawn(InnerCon::new(
        tls,
        tls_server_config,
        tls_client_config,
        sender,
        evt_send,
    )?));

    Ok((new_sender, evt_recv))
}

#[allow(dead_code)]
pub(crate) struct InnerCon {
    tls: TlsConfig,
    tls_server_config: Arc<rustls::ServerConfig>,
    tls_client_config: Arc<rustls::ClientConfig>,
    sender: ghost_actor::GhostSender<TransportConnection>,
    evt_send: futures::channel::mpsc::Sender<TransportConnectionEvent>,
}

impl InnerCon {
    pub fn new(
        tls: TlsConfig,
        tls_server_config: Arc<rustls::ServerConfig>,
        tls_client_config: Arc<rustls::ClientConfig>,
        sender: ghost_actor::GhostSender<TransportConnection>,
        evt_send: futures::channel::mpsc::Sender<TransportConnectionEvent>,
    ) -> TransportResult<Self> {
        Ok(Self {
            tls,
            tls_server_config,
            tls_client_config,
            sender,
            evt_send,
        })
    }
}

impl ghost_actor::GhostControlHandler for InnerCon {}

impl ghost_actor::GhostHandler<TransportConnection> for InnerCon {}

impl TransportConnectionHandler for InnerCon {
    fn handle_remote_url(&mut self) -> TransportConnectionHandlerResult<url2::Url2> {
        unimplemented!()
    }

    fn handle_create_channel(
        &mut self,
    ) -> TransportConnectionHandlerResult<(TransportChannelWrite, TransportChannelRead)> {
        unimplemented!()
    }
}

impl ghost_actor::GhostHandler<TransportConnectionEvent> for InnerCon {}

impl TransportConnectionEventHandler for InnerCon {
    fn handle_incoming_channel(
        &mut self,
        _url: url2::Url2,
        _send: TransportChannelWrite,
        _recv: TransportChannelRead,
    ) -> TransportConnectionEventHandlerResult<()> {
        unimplemented!()
    }
}
