
fn main() {
    for device in pcap::Device::list().expect("device lookup failed")
    {   
        println!("Found device {:?}", device);
    }
}
