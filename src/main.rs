use anyhow::{Context, Result};
use crossterm::{cursor, execute, QueueableCommand};
use futures::StreamExt;
use libp2p::{
    core::{
        either::EitherTransport,
        muxing::StreamMuxerBox,
        transport,
        upgrade::{self, Version},
    },
    floodsub::{self, Floodsub, FloodsubEvent},
    identity,
    mdns::{Mdns, MdnsEvent},
    mplex,
    noise,
    pnet::{PnetConfig, PreSharedKey},
    swarm::{
        dial_opts::DialOpts, NetworkBehaviour, NetworkBehaviourEventProcess, SwarmBuilder,
        SwarmEvent,
    },
    // `TokioTcpConfig` is available through the `tcp-tokio` feature.
    tcp::{TcpConfig, TokioTcpConfig},
    yamux::YamuxConfig,
    Multiaddr,
    NetworkBehaviour,
    PeerId,
    Transport,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    error::Error,
    io::{stdout, Stdout, Write},
    str::FromStr,
    sync::Arc,
    time::Duration,
};
use systemstat::Platform;
use tokio::{
    io::{self, AsyncBufReadExt},
    sync::Mutex,
    time::sleep,
};

/// Builds the transport that serves as a common ground for all connections.
pub fn build_transport(
    key_pair: identity::Keypair,
    psk: Option<PreSharedKey>,
) -> transport::Boxed<(PeerId, StreamMuxerBox)> {
    let noise_keys = noise::Keypair::<noise::X25519Spec>::new()
        .into_authentic(&key_pair)
        .unwrap();
    let noise_config = noise::NoiseConfig::xx(noise_keys).into_authenticated();
    let yamux_config = YamuxConfig::default();

    let base_transport = TcpConfig::new().nodelay(true);
    let maybe_encrypted = match psk {
        Some(psk) => EitherTransport::Left(
            base_transport.and_then(move |socket, _| PnetConfig::new(psk).handshake(socket)),
        ),
        None => EitherTransport::Right(base_transport),
    };
    maybe_encrypted
        .upgrade(Version::V1)
        .authenticate(noise_config)
        .multiplex(yamux_config)
        .timeout(Duration::from_secs(20))
        .boxed()
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let psk_bytes = if let Some(secret) = std::env::args().nth(1) {
        let mut bytes = [0u8; 32];
        for (i, c) in secret.chars().enumerate() {
            bytes[i] = c as u8;
        }
        bytes
    } else {
        *b"this is a secret psk padding paz"
    };

    // Create the private shared key to ensure safety on the network.
    let psk: PreSharedKey = PreSharedKey::new(psk_bytes);
    println!("using swarm key with fingerprint: {}", psk.fingerprint());

    // Create a random PeerId
    let id_keys = identity::Keypair::generate_ed25519();
    let peer_id = PeerId::from(id_keys.public());
    println!("Local peer id: {}", peer_id);

    let transport = build_transport(id_keys.clone(), Some(psk));

    // Create a Floodsub topic
    let floodsub_topic = floodsub::Topic::new("chat");

    // We create a custom network behaviour that combines floodsub and mDNS.
    // The derive generates a delegating `NetworkBehaviour` impl which in turn
    // requires the implementations of `NetworkBehaviourEventProcess` for
    // the events of each behaviour.
    #[derive(NetworkBehaviour)]
    #[behaviour(event_process = true)]
    struct MyBehaviour {
        floodsub: Floodsub,
        mdns: Mdns,

        #[behaviour(ignore)]
        #[allow(dead_code)]
        db: HashMap<String, SystemInfo>,
    }

    impl NetworkBehaviourEventProcess<FloodsubEvent> for MyBehaviour {
        // Called when `floodsub` produces an event.
        fn inject_event(&mut self, message: FloodsubEvent) {
            if let FloodsubEvent::Message(message) = message {
                // Update our database of system infos.
                if let Ok(system_info) = serde_json::from_slice::<SystemInfo>(&message.data) {
                    self.db.insert(system_info.hostname.clone(), system_info);
                }
            }
        }
    }

    impl NetworkBehaviourEventProcess<MdnsEvent> for MyBehaviour {
        // Called when `mdns` produces an event.
        fn inject_event(&mut self, event: MdnsEvent) {
            match event {
                MdnsEvent::Discovered(list) => {
                    for (peer, _) in list {
                        self.floodsub.add_node_to_partial_view(peer);
                    }
                }
                MdnsEvent::Expired(list) => {
                    for (peer, _) in list {
                        if !self.mdns.has_node(&peer) {
                            self.floodsub.remove_node_from_partial_view(&peer);
                        }
                    }
                }
            }
        }
    }

    // Create a Swarm to manage peers and events.
    let mut swarm = {
        let mdns = Mdns::new(Default::default()).await?;
        let mut behaviour = MyBehaviour {
            floodsub: Floodsub::new(peer_id.clone()),
            mdns,
            db: HashMap::new(),
        };

        behaviour.floodsub.subscribe(floodsub_topic.clone());

        SwarmBuilder::new(transport, behaviour, peer_id)
            // We want the connection background tasks to be spawned
            // onto the tokio runtime.
            .executor(Box::new(|fut| {
                tokio::spawn(fut);
            }))
            .build()
    };

    // Reach out to another node if specified
    // if let Some(to_dial) = std::env::args().nth(1) {
    //     let addr: Multiaddr = to_dial.parse()?;
    //     swarm.dial(addr)?;
    //     println!("Dialed {:?}", to_dial)
    // }

    // Listen on all interfaces and whatever port the OS assigns
    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

    let mut stdout = stdout();

    // Kick it off
    loop {
        tokio::select! {
            delay = sleep(Duration::from_secs(1)) => {


                let sys = systemstat::System::new();
                let uptime = sys.uptime()?.as_secs();

                let hostname = hostname::get()?.into_string().ok().context("Failed to convert OsString to String")?;
                let peer_id = peer_id.clone().to_string();
                let sys_info = SystemInfo { hostname, peer_id, uptime, cpu_temp: sys.cpu_temp().ok(), memory:
                    get_memory(&sys)
                 };

                let sys_info_json_str = serde_json::to_string(&sys_info)?;

                swarm.behaviour_mut().floodsub.publish(floodsub_topic.clone(), sys_info_json_str.as_bytes());

                // Also insert ourselves into the db.
                swarm.behaviour_mut().db.insert(sys_info.hostname.clone(), sys_info);

                render_db(&swarm.behaviour().db);

            }

            event = swarm.select_next_some() => {
                if let SwarmEvent::NewListenAddr { address, .. } = event {
                    println!("Listening on {:?}", address);
                }
            }
        }
    }
}

fn render_db(db: &HashMap<String, SystemInfo>) {
    use comfy_table::modifiers::UTF8_ROUND_CORNERS;
    use comfy_table::presets::UTF8_FULL;
    use comfy_table::*;

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_table_width(80)
        .set_header(vec![
            "Hostname",
            "Uptime",
            "Cpu Temp(c)",
            "Memory(free GB/total GB)",
        ]);

    for (hostname, sys_info) in db {
        let human_uptime = humantime::format_duration(Duration::new(sys_info.uptime.into(), 0));
        table.add_row(vec![
            Cell::new(hostname.clone()),
            Cell::new(human_uptime),
            Cell::new(
                sys_info
                    .cpu_temp
                    .map(|temp| format!("{:.1}", temp))
                    .unwrap_or_else(|| "".into()),
            ),
            Cell::new(
                sys_info
                    .memory
                    .as_ref()
                    .map(|mem| {
                        format!(
                            "{:.1}/{:.1}",
                            mem.free as f64 / 1024.0 / 1024.0 / 1024.0,
                            mem.total as f64 / 1024.0 / 1024.0 / 1024.0
                        )
                    })
                    .unwrap_or_else(|| "".into()),
            ),
        ]);
    }

    println!("{}", table);
}

fn get_memory(sys: &systemstat::System) -> Option<Memory> {
    sys.memory().ok().map(|mem| Memory {
        free: mem.free.as_u64(),
        total: mem.total.as_u64(),
    })
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
struct SystemInfo {
    hostname: String,
    peer_id: String,
    uptime: u64,
    cpu_temp: Option<f32>,

    memory: Option<Memory>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
struct Memory {
    total: u64,
    free: u64,
}
