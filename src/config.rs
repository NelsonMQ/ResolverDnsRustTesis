/* Configuration file for dns */

/* ----------- Options ---------------------*/
// CacheMaxSize: max size for the cache (in number of domain names saved)

// ------------- Resolver Config --------------------
pub static RESOLVER_IP_PORT: &'static str = "192.168.1.90:58396";

// Add at least 2 root servers and 2 host server (for local network).
pub static SBELT_ROOT_IPS: [&str; 3] = ["198.41.0.4:53", "199.9.14.201:53", "192.33.4.12:53"];

// Queries quantity for each query, before the resolver panic in a Temporary Error
pub static QUERIES_FOR_CLIENT_REQUEST: u16 = 10;

// Cache
pub static USE_CACHE: bool = true;
pub static CACHE_MAX_SIZE: u32 = 1000;
// --------------------------------------------------

// ------------- NameServer Config -------------------
//pub static NAME_SERVER_IP: &'static str = "192.168.1.90";
pub static MASTER_FILES: [&str; 1] = ["test.txt"];
pub static RECURSIVE_AVAILABLE: bool = true; // recursive name server available as default
                                             // ---------------------------------------------------
