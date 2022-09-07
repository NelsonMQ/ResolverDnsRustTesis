/* Configuration file for dns */

/* ----------- Options ---------------------*/
// CacheMaxSize: max size for the cache (in number of domain names saved)

// ------------- Resolver Config --------------------
// Nic Computer
//pub static RESOLVER_IP_PORT: &'static str = "200.7.6.141:58396";
pub static RESOLVER_IP_PORT: &'static str = "192.168.1.90:58396";

// Add at least 2 root servers and 2 host server (for local network).
//pub static SBELT_ROOT_IPS: [&str; 1] = ["192.168.1.90:58398"];
pub static SBELT_ROOT_IPS: [&str; 2] = ["192.33.4.12:53", "198.41.0.4:53"];

// Queries quantity for each query, before the resolver panic in a Temporary Error
pub static QUERIES_FOR_CLIENT_REQUEST: u16 = 50;

// Cache
pub static USE_CACHE: bool = true;
pub static CACHE_MAX_SIZE: u32 = 10000;
// --------------------------------------------------

// ------------- NameServer Config -------------------
//pub static NAME_SERVER_IP: &'static str = "192.168.1.90";
pub static MASTER_FILES: [&str; 1] = ["test.txt"];
pub static RECURSIVE_AVAILABLE: bool = false; // recursive name server available as default
                                              // ---------------------------------------------------
