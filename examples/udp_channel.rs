//! To communicate with a local instance of Python RNS should use a config like:
//!
//! ```text
//! [[UDP Interface]]
//! type = UDPInterface
//! enabled = yes
//! listen_ip = 0.0.0.0
//! listen_port = 4242
//! forward_ip = 127.0.0.1
//! forward_port = 4243
//! ```

use std::collections::HashMap;
use std::sync::Arc;

use rand_core::OsRng;
use tokio::sync::Mutex;
use tokio::time::{Duration, /*sleep*/};

use reticulum::channel::WrappedLink;
use reticulum::destination::{DestinationName, SingleInputDestination};
use reticulum::destination::link::{LinkEvent, LinkStatus};
use reticulum::hash::AddressHash;
use reticulum::identity::PrivateIdentity;
use reticulum::iface::udp::UdpInterface;
use reticulum::transport::{Transport, TransportConfig};

mod channel_util;
use channel_util::ExampleMessage;

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace")).init();

    log::info!(">>> UDP LINK APP <<<");

    let id = PrivateIdentity::new_from_rand(OsRng);
    let destination = SingleInputDestination::new(id.clone(), DestinationName::new("example", "app"));
    let transport = Transport::new(TransportConfig::new("server", &id, true));

    let _ = transport.iface_manager().lock().await.spawn(
        UdpInterface::new("0.0.0.0:4243", Some("127.0.0.1:4242")),
        UdpInterface::spawn);

    let dest = Arc::new(tokio::sync::Mutex::new(destination));

    let mut announce_recv = transport.recv_announces().await;
    let mut out_link_events = transport.out_link_events();

    let mut channels = HashMap::<AddressHash, Arc<Mutex<WrappedLink<ExampleMessage>>>>::new();
    let arc_transport = Arc::new(Mutex::new(transport));

    loop {
        while let Ok(announce) = announce_recv.try_recv() {
            let destination = announce.destination.lock().await;
            //println!("ANNOUNCE: {}", destination.desc.address_hash);
            let channel = match channels.get(&destination.desc.address_hash) {
                Some(channel) => channel.clone(),
                None => {
                    let link = arc_transport.lock().await.link(destination.desc).await;
                    let wrapped = Arc::new(tokio::sync::Mutex::new(WrappedLink::<ExampleMessage>::new(link).await));
                    log::info!("channel created");
                    channels.insert(destination.desc.address_hash, wrapped.clone());
                    wrapped
                }
            };
            let mut channel = channel.lock().await;
            let link = channel.get_link();
            let link = link.lock().await;
            log::info!("link {}: {:?}", link.id(), link.status());
            if link.status() == LinkStatus::Active {
                drop(link);
                let message = ExampleMessage::new_text("foo");
                match channel.get_channel().send(&message, &arc_transport).await {
                    Ok(_envelope) => log::info!("sent message on channel"),
                    Err(err) => log::info!("Sending message: Channel not ready: {err:?}")
                }
                //sleep(Duration::from_secs(1)).await;
            } else {
                println!("LINK STATUS: {:?}", link.status());
            }
        }
        while let Ok(link_event) = out_link_events.try_recv() {
            match link_event.event {
                LinkEvent::Activated => log::info!("link {} activated", link_event.id),
                LinkEvent::Closed => log::info!("link {} closed", link_event.id),
                LinkEvent::Data(payload) => log::info!("link {} data payload: {}", link_event.id,
                    std::str::from_utf8(payload.as_slice())
                        .map(str::to_string)
                        .unwrap_or_else(|_| format!("{:?}", payload.as_slice()))),
            }
        }
        arc_transport.lock().await
            .send_announce(&dest, None)
            .await;
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    //log::info!("exit");
}
