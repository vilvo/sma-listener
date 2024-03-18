use nom::number;
use nom::IResult;
use std::net::Ipv4Addr;

#[derive(Debug)]
pub struct SMAHMMulticast {
    pub a1: u32,
    pub a2: u32,
    pub b: u64,
    pub protocol_id: u16,
    pub todo1: u64,
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub todo2: u32,
    pub s: u8,
    pub m: u8,
    pub a: u8,
    pub todo3: u64,
    pub todo4: u64,
    pub todo5: u64,
    pub todo6: u32,
    pub todo7: u8,
    pub total_power_in: f64,
}

pub fn parse_packet(input: &[u8]) -> IResult<&[u8], SMAHMMulticast> {
    let (input, a1) = number::complete::be_u32(input)?;           // 4 bytes
    let (input, a2) = number::complete::be_u32(input)?;           // 8 bytes

    let (input, b) = number::complete::be_u64(input)?;           // 16 bytes
    let (input, protocol_id) = number::complete::be_u16(input)?; // 18 bytes
    let (input, todo1) = number::complete::be_u64(input)?;       // 26 bytes

    let (input, srca) = number::complete::be_u8(input)?;         // 27 bytes
    let (input, srcb) = number::complete::be_u8(input)?;         // 28 bytes
    let (input, srcc) = number::complete::be_u8(input)?;         // 29 bytes
    let (input, srcd) = number::complete::be_u8(input)?;         // 30 bytes

    let (input, dsta) = number::complete::be_u8(input)?;         // 31 bytes
    let (input, dstb) = number::complete::be_u8(input)?;         // 32 bytes
    let (input, dstc) = number::complete::be_u8(input)?;         // 33 bytes
    let (input, dstd) = number::complete::be_u8(input)?;         // 34 bytes

    let src = Ipv4Addr::new(srca, srcb, srcc, srcd);
    let dst = Ipv4Addr::new(dsta, dstb, dstc, dstd);

    let (input, src_port) = number::complete::be_u16(input)?;    // 36 bytes
    let (input, dst_port) = number::complete::be_u16(input)?;    // 38 bytes

    let (input, todo2) = number::complete::be_u32(input)?;       // 42 bytes

    let (input, s) = number::complete::be_u8(input)?;            // 43 bytes
    let (input, m) = number::complete::be_u8(input)?;            // 44 bytes
    let (input, a) = number::complete::be_u8(input)?;            // 45 bytes

    let (input, todo3) = number::complete::be_u64(input)?;       // 53 bytes
    let (input, todo4) = number::complete::be_u64(input)?;       // 61 bytes
    let (input, todo5) = number::complete::be_u64(input)?;       // 69 bytes
    let (input, todo6) = number::complete::be_u32(input)?;       // 73 bytes
    let (input, todo7) = number::complete::be_u8(input)?;        // 74 bytes
    let (input, tpi) = number::complete::be_u32(input)?;         // 78 bytes
    let total_power_in = tpi as f64 * 0.1;

    Ok((
        input,
        SMAHMMulticast {
            a1, a2,
            b,
            protocol_id,
            todo1,
            src,
            dst,
            src_port,
            dst_port,
            todo2,
            s, m, a,
            todo3,
            todo4,
            todo5,
            todo6,
            todo7,
            total_power_in,
        },
    ))
}

fn main() {

    let mut capture = pcap::Capture::from_device("wlp1s0f0")
        .unwrap()
        .immediate_mode(true)
        .open().unwrap();

    let filter_str: &str = "udp dst port 9522";
    capture.filter(filter_str, true).unwrap();

    //let mut savefile = capture.savefile("test.pcap").unwrap();

    while let Ok(packet) = capture.next_packet() {
        if packet.data[42] == b'S' &&
            packet.data[43] == b'M' &&
            packet.data[44] == b'A' &&
            packet.len() == 100
        {
            //println!("{}:{:?}", "SMA", packet);
            println!("");
            println!("{}:{:?}", "SMA", packet.header);
            println!("{}:{:?}", "SMA", packet.data);

            //println!("{:?}", packet.header);
            //println!("{:?}", packet.data);
            let parsed = parse_packet(&packet).unwrap();
            println!("{}:{:?}", "input", parsed.0);
            println!("{:#?}", parsed.1);
            //println!("{}:{:?}", "packet.header",
            //         parse_packet(packet.header));
            //println!("{}:{:?}", "packet.data", parse_packet(packet.data));
            /*
            let mut items_per_line = 0;
            for i in 0..packet.data.len()-1 {
                print!("{:3} ", packet.data[i]);
                items_per_line += 1;
                if items_per_line == 8 {
                    items_per_line = 0;
                    println!("");
                }
            };
            println!("");
            */
            //savefile.write(&packet);
            //break;
        }
    }
}
