/* Configuration file for dns client */

pub static RESOLVER_IP_PORT: &'static str = "192.168.1.90:58396";
pub static CLIENT_IP_PORT: &'static str = "192.168.1.90:58397";

// Nic Computer
//pub static RESOLVER_IP_PORT: &'static str = "200.7.6.141:58396";
//pub static CLIENT_IP_PORT: &'static str = "200.7.6.141:58397";

/* Dns query configuration */

pub static HOST_NAME: &'static str = "uchile.cl";
pub static QTYPE: u16 = 1;
pub static QCLASS: u16 = 1;
pub static TRANSPORT: &'static str = "UDP";
pub static TIMEOUT: u64 = 15;
