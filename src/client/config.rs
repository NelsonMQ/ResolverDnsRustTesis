/* Configuration file for dns client */

pub static RESOLVER_IP_PORT: &'static str = "192.168.1.87:58396";
pub static CLIENT_IP_PORT: &'static str = "192.168.1.87:58397";

/* Dns query configuration */

pub static HOST_NAME: &'static str = "twitter.com";
pub static QTYPE: u16 = 1;
pub static QCLASS: u16 = 1;
pub static TRANSPORT: &'static str = "UDP";
pub static TIMEOUT: u64 = 5;
