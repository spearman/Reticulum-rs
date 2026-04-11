
pub mod cache_set;

use crate::buffer::OutputBuffer;
use crate::packet::{HeaderType, Packet, PacketType};
use crate::serde::Serialize;

pub fn show_packet(packet: &Packet) {
    const BUFFER_SIZE: usize = core::mem::size_of::<Packet>() * 3;
    let mut buffer = [0u8; BUFFER_SIZE];
    let mut output = OutputBuffer::new(&mut buffer);
    let _ = packet.serialize(&mut output).unwrap();
    let data = output.as_slice();
    let to_hex = |s: &[u8]| s.iter().map(|b| format!("{:0x}", b)).collect::<String>();
    println!("-----------------------------------------------------------------------------------");
    println!("PACKET {:?}[{:?}][{:?}][{:?}] ({} bytes):", packet.header.packet_type, packet.context,
        packet.header.propagation_type, packet.header.destination_type, data.len());
    println!("  flags: {:08b}", data[0]);
    println!("  hops: {}", data[1]);
    // skip possibility of ifac for now
    debug_assert!(data[0] & 0x80 != 0x80);
    println!("  address: {}", to_hex(&data[2..18]));
    let mut b = 18;
    if packet.header.header_type == HeaderType::Type2 {
        println!("  address2: {}", to_hex(&data[b..34]));
        b = 34;
    }
    println!("  context: {}", data[b]);
    b += 1;
    println!("  data: {} bytes", data[b..].len());
    println!("  ---");
    if packet.header.packet_type == PacketType::Announce {
        println!("  pubkey: {}", to_hex(&data[b..b+32]));
        b += 32;
        println!("  verifykey: {}", to_hex(&data[b..b+32]));
        b += 32;
        println!("  name hash: {}", to_hex(&data[b..b+10]));
        b += 10;
        println!("  random hash: {}", to_hex(&data[b..b+10]));
        b += 10;
        println!("  signature: {}", to_hex(&data[b..b+64]));
        b += 64;
        println!("  application data: {} bytes", data[b..].len());
    } else if packet.header.packet_type == PacketType::LinkRequest {
        println!("  pubkey: {}", to_hex(&data[b..b+32]));
        b += 32;
        println!("  verifykey: {}", to_hex(&data[b..b+32]));
        //b += 32;
    } else if packet.header.packet_type == PacketType::Proof {
        println!("  signature: {}", to_hex(&data[b..b+64]));
        b += 64;
        println!("  pubkey: {}", to_hex(&data[b..b+32]));
        //b += 32;
    }
    println!("-----------------------------------------------------------------------------------");
}
