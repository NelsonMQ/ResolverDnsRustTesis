/* Configuration file for dns */

// ------------- Resolver Config --------------------
pub static RESOLVER_IP_PORT: &'static str = "192.168.1.90:58396";

// Add at least 2 root servers and 2 host server (for local network).
pub static SBELT_ROOT_IPS: [&str; 13] = [
    "198.41.0.4:53",
    "199.9.14.201",
    "192.33.4.12",
    "199.7.91.13",
    "192.203.230.10",
    "192.5.5.241",
    "192.112.36.4",
    "198.97.190.53",
    "192.36.148.17",
    "192.58.128.30",
    "193.0.14.129",
    "199.7.83.42",
    "202.12.27.33",
];

pub static SBELT_ROOT_NAMES: [&str; 13] = [
    "a.root-servers.net",
    "b.root-servers.net",
    "c.root-servers.net",
    "d.root-servers.net",
    "e.root-servers.net",
    "f.root-servers.net",
    "g.root-servers.net",
    "h.root-servers.net",
    "i.root-servers.net",
    "j.root-servers.net",
    "k.root-servers.net",
    "l.root-servers.net",
    "m.root-servers.net",
];

// Queries quantity for each query, before the resolver panic in a Temporary Error
pub static QUERIES_FOR_CLIENT_REQUEST: u16 = 20;

// Cache
pub static USE_CACHE: bool = true;
pub static CACHE_MAX_SIZE: u32 = 10000;
// --------------------------------------------------

// ------------- NameServer Config -------------------
pub static NAME_SERVER_IP: &'static str = "192.168.1.90";
pub static MASTER_FILES: [&str; 1] = ["test.txt"];
pub static RECURSIVE_AVAILABLE: bool = false;
// recursive name server available as default
// ---------------------------------------------------
