
fn main() {

    let mut capture = pcap::Capture::from_device("wlp1s0f0")
        .unwrap()
        .immediate_mode(true)
        .open().unwrap();

    let filter_str: &str = "udp dst port 9522";
    capture.filter(filter_str, true).unwrap();

    let mut savefile = capture.savefile("test.pcap").unwrap();

    while let Ok(packet) = capture.next_packet() {
        if packet.data[42] == b'S' &&
            packet.data[43] == b'M' &&
            packet.data[44] == b'A'
        {
            println!("{}", "SMA");
            savefile.write(&packet);
            break;
        }
    }
}
