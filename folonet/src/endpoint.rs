use aya::Pod;
use folonet_common::{KConnection, KEndpoint};

#[derive(Clone, Copy, Debug)]
pub struct Endpoint(KEndpoint);

unsafe impl Pod for Endpoint {}

impl Endpoint {
    pub fn new(endpoint: KEndpoint) -> Self {
        Endpoint(endpoint)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Connection(KConnection);

unsafe impl Pod for Connection {}
