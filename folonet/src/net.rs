pub fn get_interafce_index(ifce: String) -> Option<u32> {
    pnet::datalink::interfaces()
        .iter()
        .find(|i| i.name == ifce)
        .map(|i| i.index)
}
