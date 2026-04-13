
pub mod cache_set;

use crate::buffer::OutputBuffer;
use crate::packet::{HeaderType, Packet, PacketType};
use crate::serde::Serialize;

pub fn show_packet(packet: &Packet) -> String {
    use std::fmt::Write;
    const BUFFER_SIZE: usize = core::mem::size_of::<Packet>() * 3;
    let mut buffer = [0u8; BUFFER_SIZE];
    let mut output = OutputBuffer::new(&mut buffer);
    let _ = packet.serialize(&mut output).unwrap();
    let data = output.as_slice();
    let to_hex = |s: &[u8]| s.iter().map(|b| format!("{:0x}", b)).collect::<String>();
    let mut s = String::new();
    writeln!(&mut s, "-----------------------------------------------------------------------------------")
        .unwrap();
    writeln!(&mut s, "PACKET {:?}[{:?}][{:?}][{:?}] ({} bytes):", packet.header.packet_type,
        packet.context, packet.header.propagation_type, packet.header.destination_type, data.len())
        .unwrap();
    writeln!(&mut s, "  flags: {:08b}", data[0]).unwrap();
    writeln!(&mut s, "  hops: {}", data[1]).unwrap();
    // skip possibility of ifac for now
    debug_assert!(data[0] & 0x80 != 0x80);
    writeln!(&mut s, "  address: {}", to_hex(&data[2..18])).unwrap();
    let mut b = 18;
    if packet.header.header_type == HeaderType::Type2 {
        writeln!(&mut s, "  address2: {}", to_hex(&data[b..34])).unwrap();
        b = 34;
    }
    writeln!(&mut s, "  context: {}", data[b]).unwrap();
    b += 1;
    writeln!(&mut s, "  data: {} bytes", data[b..].len()).unwrap();
    writeln!(&mut s, "  ---").unwrap();
    if packet.header.packet_type == PacketType::Announce {
        writeln!(&mut s, "  pubkey: {}", to_hex(&data[b..b+32])).unwrap();
        b += 32;
        writeln!(&mut s, "  verifykey: {}", to_hex(&data[b..b+32])).unwrap();
        b += 32;
        writeln!(&mut s, "  name hash: {}", to_hex(&data[b..b+10])).unwrap();
        b += 10;
        writeln!(&mut s, "  random hash: {}", to_hex(&data[b..b+10])).unwrap();
        b += 10;
        writeln!(&mut s, "  signature: {}", to_hex(&data[b..b+64])).unwrap();
        b += 64;
        writeln!(&mut s, "  application data: {} bytes", data[b..].len()).unwrap();
    } else if packet.header.packet_type == PacketType::LinkRequest {
        writeln!(&mut s, "  pubkey: {}", to_hex(&data[b..b+32])).unwrap();
        b += 32;
        writeln!(&mut s, "  verifykey: {}", to_hex(&data[b..b+32])).unwrap();
        //b += 32;
    } else if packet.header.packet_type == PacketType::Proof {
        writeln!(&mut s, "  signature: {}", to_hex(&data[b..b+64])).unwrap();
        b += 64;
        writeln!(&mut s, "  pubkey: {}", to_hex(&data[b..b+32])).unwrap();
        //b += 32;
    }
    writeln!(&mut s, "-----------------------------------------------------------------------------------")
        .unwrap();
    s
}
