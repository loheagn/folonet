use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct GlobalConfig {
    pub services: Vec<ServiceConfig>,
    pub interfaces: Vec<InterfaceConfig>,
    pub ip_mac_list: Vec<IpMac>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct ServiceConfig {
    pub name: String,
    pub local_endpoint: String,
    pub servers: Vec<String>,
    pub is_tcp: bool,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct InterfaceConfig {
    pub name: String,
    pub local_ips: Vec<String>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct IpMac {
    pub ip: String,
    pub mac: String,
}
