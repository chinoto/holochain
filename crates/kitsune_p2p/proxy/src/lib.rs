#![deny(missing_docs)]
//! Proxy transport module for kitsune-p2p

use kitsune_p2p_types::{
    dependencies::{ghost_actor, url2},
    transport::{
        *,
        transport_connection::*,
        transport_listener::*,
    }
};
use futures::future::FutureExt;

/// Wrap a transport listener sender/receiver in kitsune proxy logic.
pub async fn proxy_wrap_transport_listener(
    sender: ghost_actor::GhostSender<TransportListener>,
    receiver: TransportListenerEventReceiver,
) -> TransportResult<(
    ghost_actor::GhostSender<TransportListener>,
    TransportListenerEventReceiver,
)> {
    let builder = ghost_actor::actor_builder::GhostActorBuilder::new();

    let new_sender = builder
        .channel_factory()
        .create_channel::<TransportListener>()
        .await?;

    builder
        .channel_factory()
        .attach_receiver(receiver)
        .await?;

    let (evt_send, evt_recv) = futures::channel::mpsc::channel(10);

    tokio::task::spawn(builder.spawn(InnerListen::new(sender, evt_send)));

    Ok((new_sender, evt_recv))
}

struct InnerListen {
    sender: ghost_actor::GhostSender<TransportListener>,
    evt_send: futures::channel::mpsc::Sender<TransportListenerEvent>,
}

impl InnerListen {
    pub fn new(
        sender: ghost_actor::GhostSender<TransportListener>,
        evt_send: futures::channel::mpsc::Sender<TransportListenerEvent>,
    ) -> Self {
        Self {
            sender,
            evt_send,
        }
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
        // TODO translate url
        let fut = self.sender.connect(url);
        Ok(async move {
            let (sender, receiver) = fut.await?;
            let (sender, receiver) = proxy_wrap_transport_connection(sender, receiver).await?;
            Ok((sender, receiver))
        }.boxed().into())
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
        Ok(async move {
            let (sender, receiver) = proxy_wrap_transport_connection(sender, receiver).await?;
            evt_send.incoming_connection(sender, receiver).await?;
            Ok(())
        }.boxed().into())
    }
}

async fn proxy_wrap_transport_connection(
    _sender: ghost_actor::GhostSender<TransportConnection>,
    _receiver: TransportConnectionEventReceiver,
) -> TransportResult<(
    ghost_actor::GhostSender<TransportConnection>,
    TransportConnectionEventReceiver,
)> {
    unimplemented!()
}
