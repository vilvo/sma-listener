
fn setup() -> pcap::Capture<pcap::Offline> {
    pcap::Capture::from_file("./tests/test.pcap").unwrap()
}

#[test]
fn test_open_pcap_packet() ->
    Result<(), Box<dyn std::error::Error>> {
    let mut cap = setup();
    let p = cap.next_packet().unwrap();
    // debug contents with cargo test -- --nocapture
    println!("p = {:?}", p);
    Ok(())
}
