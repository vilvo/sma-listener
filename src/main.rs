
fn main() {

    let mut capture = pcap::Capture::from_device("wlp1s0f0")
        .unwrap()
        .immediate_mode(true)
        .open().unwrap();

    let filter_str: &str = "udp dst port 9522";
    capture.filter(filter_str, true).unwrap();

    while let Ok(packet) = capture.next_packet() {
        println!("{:?}", packet);
    }
}
