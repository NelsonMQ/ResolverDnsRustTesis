use crate::dns_cache::DnsCache;
use crate::message::rdata::txt_rdata::TxtRdata;
use crate::message::rdata::Rdata;
use crate::message::resource_record::ResourceRecord;
use crate::message::DnsMessage;
use crate::name_server::zone::NSZone;
use crate::name_server::NameServer;
use crate::resolver::slist::Slist;
use crate::resolver::Resolver;

use crate::config::QUERIES_FOR_CLIENT_REQUEST;
use crate::config::RESOLVER_IP_PORT;
use crate::config::USE_CACHE;

use chrono::Utc;
use rand::seq::index;
use rand::{thread_rng, Rng};
use std::cmp;
use std::collections::HashMap;
use std::io::Write;
use std::net::TcpStream;
use std::net::UdpSocket;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::mpsc;
use std::sync::mpsc::Receiver;
use std::sync::mpsc::Sender;
use std::thread;
use std::thread::JoinHandle;
use std::time::Duration;
use std::vec::Vec;

// IP Config in order to ask ns and slist queries
pub static IP_FOR_SLIST_NS_QUERIES: &'static str = "192.168.1.90";

#[derive(Clone)]
/// This struct represents a resolver query
pub struct ResolverQuery {
    timestamp: u32,
    sname: String,
    stype: u16,
    sclass: u16,
    op_code: u8,
    rd: bool,
    slist: Slist,
    sbelt: Slist,
    cache: DnsCache,
    ns_data: HashMap<u16, HashMap<String, NSZone>>,
    main_query_id: u16,
    old_id: u16,
    src_address: String,
    // Channel to share cache data between threads
    add_channel_udp: Sender<(String, ResourceRecord, u8, bool, bool, String)>,
    // Channel to share cache data between threads
    delete_channel_udp: Sender<(String, String)>,
    // Channel to share cache data between threads
    add_channel_tcp: Sender<(String, ResourceRecord, u8, bool, bool, String)>,
    // Channel to share cache data between threads
    delete_channel_tcp: Sender<(String, String)>,
    // Channel to share cache data between name server and resolver
    add_channel_ns_udp: Sender<(String, ResourceRecord)>,
    // Channel to delete cache data in name server and resolver
    delete_channel_ns_udp: Sender<(String, String)>,
    // Channel to share cache data between name server and resolver
    add_channel_ns_tcp: Sender<(String, ResourceRecord)>,
    // Channel to delete cache data in name server and resolver
    delete_channel_ns_tcp: Sender<(String, String)>,
    // Channel to update response time in cache data in name server and resolver
    update_cache_sender_udp: Sender<(String, String, u32)>,
    // Channel to update response time in cache data in name server and resolver
    update_cache_sender_tcp: Sender<(String, String, u32)>,
    // Channel to update response time in cache data in name server and resolver
    update_cache_sender_ns_udp: Sender<(String, String, u32)>,
    // Channel to update response time in cache data in name server and resolver
    update_cache_sender_ns_tcp: Sender<(String, String, u32)>,
    // Number of queries that the resolver do before send temporary error
    queries_before_temporary_error: u16,
    // Sender to update ResolverQuery struct in the resolver
    tx_update_query: Sender<ResolverQuery>,
    // Sender to delete ResolverQuery struct in the resolver
    tx_delete_query: Sender<ResolverQuery>,
    // Client msg
    client_msg: DnsMessage,
    // Index to choose from Slist
    index_to_choose: u16,
    // Timeout
    timeout: u32,
    // Last query timestamp
    last_query_timestamp: u64,
    // Last query host name
    last_query_hostname: String,
    // New algorithm
    new_algorithm: bool,
}

impl ResolverQuery {
    // Creates a new ResolverQuery struct with default values
    pub fn new(
        add_channel_udp: Sender<(String, ResourceRecord, u8, bool, bool, String)>,
        delete_channel_udp: Sender<(String, String)>,
        add_channel_tcp: Sender<(String, ResourceRecord, u8, bool, bool, String)>,
        delete_channel_tcp: Sender<(String, String)>,
        add_channel_ns_udp: Sender<(String, ResourceRecord)>,
        delete_channel_ns_udp: Sender<(String, String)>,
        add_channel_ns_tcp: Sender<(String, ResourceRecord)>,
        delete_channel_ns_tcp: Sender<(String, String)>,
        tx_update_query: Sender<ResolverQuery>,
        tx_delete_query: Sender<ResolverQuery>,
        client_msg: DnsMessage,
        update_cache_sender_udp: Sender<(String, String, u32)>,
        update_cache_sender_tcp: Sender<(String, String, u32)>,
        update_cache_sender_ns_udp: Sender<(String, String, u32)>,
        update_cache_sender_ns_tcp: Sender<(String, String, u32)>,
        new_algorithm: bool,
    ) -> Self {
        let mut rng = thread_rng();
        let now = Utc::now();
        let timestamp = now.timestamp() as u32;
        let queries_before_temporary_error = QUERIES_FOR_CLIENT_REQUEST;

        let query = ResolverQuery {
            timestamp: timestamp,
            sname: "".to_string(),
            stype: 0 as u16,
            sclass: 0 as u16,
            op_code: 0 as u8,
            rd: false,
            slist: Slist::new(),
            sbelt: Slist::new(),
            cache: DnsCache::new(),
            ns_data: HashMap::<u16, HashMap<String, NSZone>>::new(),
            main_query_id: rng.gen(),
            old_id: 0,
            src_address: "".to_string(),
            add_channel_udp: add_channel_udp,
            delete_channel_udp: delete_channel_udp,
            add_channel_tcp: add_channel_tcp,
            delete_channel_tcp: delete_channel_tcp,
            add_channel_ns_udp: add_channel_ns_udp,
            delete_channel_ns_udp: delete_channel_ns_udp,
            add_channel_ns_tcp: add_channel_ns_tcp,
            delete_channel_ns_tcp: delete_channel_ns_tcp,
            queries_before_temporary_error: queries_before_temporary_error,
            tx_update_query: tx_update_query,
            tx_delete_query: tx_delete_query,
            client_msg: client_msg,
            index_to_choose: 0,
            last_query_timestamp: now.timestamp() as u64 * 1000,
            timeout: 2000,
            last_query_hostname: "".to_string(),
            update_cache_sender_udp: update_cache_sender_udp,
            update_cache_sender_tcp: update_cache_sender_tcp,
            update_cache_sender_ns_udp: update_cache_sender_ns_udp,
            update_cache_sender_ns_tcp: update_cache_sender_ns_tcp,
            new_algorithm: new_algorithm,
        };

        query
    }

    // Initializes the resolver query
    pub fn initialize(
        &mut self,
        sname: String,
        stype: u16,
        sclass: u16,
        op_code: u8,
        rd: bool,
        sbelt: Slist,
        cache: DnsCache,
        ns_data: HashMap<u16, HashMap<String, NSZone>>,
        src_address: String,
        old_id: u16,
    ) {
        self.set_sname(sname);
        self.set_stype(stype);
        self.set_sclass(sclass);
        self.set_op_code(op_code);
        self.set_rd(rd);
        self.set_sbelt(sbelt);
        self.set_cache(cache);
        self.set_ns_data(ns_data);
        self.set_src_address(src_address);
        self.set_old_id(old_id);
    }

    // Initialize the slist for UDP
    pub fn initialize_slist_udp(
        &mut self,
        sbelt: Slist,
        start_look_up_host_name: String,
        socket: UdpSocket,
    ) {
        // Gets info to initialize slist
        let host_name = start_look_up_host_name;
        let mut cache = self.get_cache();
        let ns_type = "NS".to_string();
        let host_name_copy = host_name.clone();
        let mut labels: Vec<&str> = host_name_copy.split('.').collect();
        let mut new_slist = Slist::new();

        // While there are labels
        while labels.len() > 0 {
            // Sets parent host name
            let mut parent_host_name = "".to_string();

            for label in labels.iter() {
                parent_host_name.push_str(label);
                parent_host_name.push_str(".");
            }

            // Deletes last dot
            parent_host_name.pop();

            // Gets a vector of NS RR for host_name
            let ns_parent_host_name = cache.get(parent_host_name.to_string(), ns_type.clone());

            // NXDOMAIN or NODATA
            if ns_parent_host_name.len() > 0 {
                let first_ns_cache = ns_parent_host_name[0].clone();

                if first_ns_cache.get_nxdomain() == true || first_ns_cache.get_no_data() == true {
                    // Creates a new slist from the parent domain
                    labels.remove(0);
                    continue;
                }
            }

            if ns_parent_host_name.len() == 0 {
                labels.remove(0);
                continue;
            }

            // Variable to save ips found
            let mut ip_found = 0;

            // Iters over ns rr's found
            for ns in ns_parent_host_name.clone() {
                // Gets the info inside rr
                if ns.get_resource_record().get_type_code() != 2 {
                    continue;
                }

                let rr_rdata = match ns.get_resource_record().get_rdata() {
                    Rdata::SomeNsRdata(val) => val.clone(),
                    _ => unreachable!(),
                };

                // Gets the NS domain name
                let ns_parent_host_name_string = rr_rdata.get_nsdname().get_name().to_lowercase();

                // Sets zone name equivalent
                new_slist.set_zone_name_equivalent(labels.len() as i32);

                // Gets list of ip addresses A
                let ns_ip_address = cache.get(ns_parent_host_name_string.clone(), "A".to_string());

                // Gets list of ip addresses A
                let ns_ip_address_txt =
                    cache.get(ns_parent_host_name_string.clone(), "TXT".to_string());

                // If there is no ip addresses
                if ns_ip_address.len() == 0 && ns_ip_address_txt.len() == 0 {
                    new_slist.insert(ns_parent_host_name_string, "".to_string(), 6000);
                    continue;
                }

                // Iters over ip addresses found
                for ip in ns_ip_address.clone() {
                    // Gets the rdata from RR
                    let ns_ip_address_rdata = match ip.get_resource_record().get_rdata() {
                        Rdata::SomeARdata(val) => val.clone(),
                        _ => unreachable!(),
                    };

                    // Gets the ip address
                    let ip_address = ns_ip_address_rdata.get_string_address();

                    // Gets response time from cache
                    let response_time = cache.get_response_time(
                        ns_parent_host_name_string.clone(),
                        "A".to_string(),
                        ip_address.clone(),
                    );

                    // Inserts ip address in slist
                    new_slist.insert(
                        ns_parent_host_name_string.clone(),
                        ip_address.to_string(),
                        response_time as u32,
                    );

                    ip_found = ip_found + 1;
                }

                for ip in ns_ip_address_txt.clone() {
                    // Gets the ip address
                    let ip_address = "192.54.54.3";

                    // Inserts ip address in slist
                    new_slist.insert(
                        ns_parent_host_name_string.clone(),
                        ip_address.to_string(),
                        2000000 as u32,
                    );

                    ip_found = ip_found + 1;
                }
            }

            // If there is no ip address in any NS RR
            if ip_found == 0 {
                // If there are empties NS RR in slist
                if new_slist.len() > 0
                    && new_slist
                        .get_first()
                        .get(&"name".to_string())
                        .unwrap()
                        .contains(&parent_host_name)
                        == false
                {
                    new_slist.set_zone_name_equivalent(labels.len() as i32);
                } else {
                    // If not, creates a new slist from the parent domain
                    new_slist = Slist::new();
                    labels.remove(0);
                    continue;
                }
            }

            break;
        }

        // If zone name equivalent is -1, initialize slist from sbelt
        if new_slist.get_zone_name_equivalent() == -1 {
            self.set_slist(sbelt.clone());
        } else {
            self.set_slist(new_slist.clone());
        }
    }

    // Initializes slist in TCP
    pub fn initialize_slist_tcp(&mut self, sbelt: Slist, start_look_up_host_name: String) {
        // Gets info to initialize slist
        let host_name = start_look_up_host_name;
        let mut cache = self.get_cache();
        let ns_type = "NS".to_string();
        let host_name_copy = host_name.clone();
        let mut labels: Vec<&str> = host_name_copy.split('.').collect();
        let mut new_slist = Slist::new();

        // While there are labels
        while labels.len() > 0 {
            // Sets parent host name
            let mut parent_host_name = "".to_string();

            for label in labels.iter() {
                parent_host_name.push_str(label);
                parent_host_name.push_str(".");
            }

            // Deletes last dot
            parent_host_name.pop();

            // Gets a vector of NS RR for host_name
            let ns_parent_host_name = cache.get(parent_host_name.to_string(), ns_type.clone());

            if ns_parent_host_name.len() == 0 {
                labels.remove(0);
                continue;
            }

            // NXDOMAIN or NODATA
            if ns_parent_host_name.len() > 0 {
                let first_ns_cache = ns_parent_host_name[0].clone();

                if first_ns_cache.get_nxdomain() == true || first_ns_cache.get_no_data() == true {
                    // Creates a new slist from the parent domain
                    labels.remove(0);
                    continue;
                }
            }

            // Variable to save ips found
            let mut ip_found = 0;

            // Iters over ns rr's found
            for ns in ns_parent_host_name.clone() {
                // Gets the info inside rr
                let rr_rdata = match ns.get_resource_record().get_rdata() {
                    Rdata::SomeNsRdata(val) => val.clone(),
                    _ => unreachable!(),
                };

                // Gets the NS domain name
                let ns_parent_host_name_string = rr_rdata.get_nsdname().get_name();

                // Sets zone name equivalent
                new_slist.set_zone_name_equivalent(labels.len() as i32);

                // Gets list of ip addresses
                let ns_ip_address = cache.get(ns_parent_host_name_string.clone(), "A".to_string());

                // If there is no ip addresses
                if ns_ip_address.len() == 0 {
                    new_slist.insert(ns_parent_host_name_string, "".to_string(), 6000);
                    continue;
                }

                // Iters over ip addresses found
                for ip in ns_ip_address.clone() {
                    // Gets the rdata from RR
                    let ns_ip_address_rdata = match ip.get_resource_record().get_rdata() {
                        Rdata::SomeARdata(val) => val.clone(),
                        _ => unreachable!(),
                    };

                    // Gets the ip address
                    let ip_address = ns_ip_address_rdata.get_string_address();

                    // Gets response time from cache
                    let response_time = cache.get_response_time(
                        ns_parent_host_name_string.clone(),
                        "A".to_string(),
                        ip_address.clone(),
                    );

                    // Inserts ip address in slist
                    new_slist.insert(
                        ns_parent_host_name_string.clone(),
                        ip_address.to_string(),
                        response_time as u32,
                    );

                    ip_found = ip_found + 1;
                }
            }

            // If there is no ip address in any NS RR
            if ip_found == 0 {
                // If there are empties NS RR in slist
                if new_slist.len() > 0
                    && new_slist
                        .get_first()
                        .get(&"name".to_string())
                        .unwrap()
                        .contains(&parent_host_name)
                        == false
                {
                    break;
                }

                // If not, creates a new slist from the parent domain
                new_slist = Slist::new();
                labels.remove(0);
                continue;
            }

            break;
        }

        // If zone name equivalent is -1, initialize slist from sbelt
        if new_slist.get_zone_name_equivalent() == -1 {
            self.set_slist(sbelt);
        } else {
            self.set_slist(new_slist);
        }
    }

    // Looks for local info in name server zone and cache
    pub fn look_for_local_info(&mut self) -> (Vec<ResourceRecord>, bool, bool) {
        // Gets necessary info
        let s_type = match self.get_stype() {
            1 => "A".to_string(),
            2 => "NS".to_string(),
            5 => "CNAME".to_string(),
            6 => "SOA".to_string(),
            11 => "WKS".to_string(),
            12 => "PTR".to_string(),
            13 => "HINFO".to_string(),
            14 => "MINFO".to_string(),
            15 => "MX".to_string(),
            16 => "TXT".to_string(),
            255 => "*".to_string(),
            _ => unreachable!(),
        };
        let s_name = self.get_sname();
        let s_class = self.get_sclass();

        // Class is *
        if s_class == 255 {
            // Vector to save answers
            let mut all_answers = Vec::new();

            for (class, hashzone) in self.get_ns_data().iter() {
                // Gets the zone by class and sname
                let (main_zone, available) = NameServer::search_nearest_ancestor_zone(
                    self.get_ns_data(),
                    s_name.clone(),
                    *class,
                );

                // If the zone exists
                if available == true {
                    let mut sname_without_zone_label = s_name.replace(&main_zone.get_name(), "");

                    // We were looking for the first node
                    if sname_without_zone_label == "".to_string() {
                        let mut rrs_by_type = main_zone.get_rrs_by_type(self.get_stype());
                        let soa_rr = main_zone.get_rrs_by_type(6)[0].clone();
                        let soa_minimun_ttl = match soa_rr.get_rdata() {
                            Rdata::SomeSoaRdata(val) => val.get_minimum(),
                            _ => unreachable!(),
                        };

                        // Sets TTL to max between RR ttl and SOA min.
                        for rr in rrs_by_type.iter_mut() {
                            let rr_ttl = rr.get_ttl();

                            rr.set_ttl(cmp::max(rr_ttl, soa_minimun_ttl));
                        }

                        return (rrs_by_type, false, false);
                    }

                    // Delete last dot
                    sname_without_zone_label.pop().unwrap();

                    // Sets info to find the zone
                    let mut labels: Vec<&str> = sname_without_zone_label.split(".").collect();
                    labels.reverse();
                    let mut last_label = "";
                    let mut zone = main_zone.clone();

                    // We look for the zone
                    for label in labels {
                        let exist_child = zone.exist_child(label.to_string());

                        if exist_child == true {
                            zone = zone.get_child(label.to_string()).0;
                            last_label = label.clone();
                            continue;
                        }
                    }

                    // If the label is the same as the zone's name
                    if last_label == zone.get_name() {
                        // Gets the RR's
                        let mut rrs_by_type = zone.get_rrs_by_type(self.get_stype());

                        // Finds the TTL in Soa RR
                        let soa_rr = main_zone.get_rrs_by_type(6)[0].clone();
                        let soa_minimun_ttl = match soa_rr.get_rdata() {
                            Rdata::SomeSoaRdata(val) => val.get_minimum(),
                            _ => unreachable!(),
                        };

                        // Sets TTL to max between RR ttl and SOA min.
                        for rr in rrs_by_type.iter_mut() {
                            let rr_ttl = rr.get_ttl();

                            rr.set_ttl(cmp::max(rr_ttl, soa_minimun_ttl));
                        }

                        // Adds the answer
                        all_answers.append(&mut rrs_by_type);
                    }
                }
            }

            // If answers exist, return
            if all_answers.len() > 0 {
                return (all_answers, false, false);
            }
        }
        // Class is not *
        else {
            // Searchs the zone
            let (main_zone, available) = NameServer::search_nearest_ancestor_zone(
                self.get_ns_data(),
                s_name.clone(),
                s_class,
            );

            // If the zone exists
            if available == true {
                let mut sname_without_zone_label = s_name.replace(&main_zone.get_name(), "");

                // We were looking for the first node
                if sname_without_zone_label == "".to_string() {
                    let mut rrs_by_type = main_zone.get_rrs_by_type(self.get_stype());
                    let soa_rr = main_zone.get_rrs_by_type(6)[0].clone();
                    let soa_minimun_ttl = match soa_rr.get_rdata() {
                        Rdata::SomeSoaRdata(val) => val.get_minimum(),
                        _ => unreachable!(),
                    };

                    // Sets TTL to max between RR ttl and SOA min.
                    for rr in rrs_by_type.iter_mut() {
                        let rr_ttl = rr.get_ttl();

                        rr.set_ttl(cmp::max(rr_ttl, soa_minimun_ttl));
                    }

                    return (rrs_by_type, false, false);
                }

                // Delete last dot
                sname_without_zone_label.pop().unwrap();

                // Sets info to find the zone
                let mut labels: Vec<&str> = sname_without_zone_label.split(".").collect();
                labels.reverse();
                let mut last_label = "";
                let mut zone = main_zone.clone();

                // We look for the zone
                for label in labels {
                    let exist_child = zone.exist_child(label.to_string());

                    if exist_child == true {
                        zone = zone.get_child(label.to_string()).0;
                        last_label = label.clone();
                        continue;
                    }
                }

                // If the label is the same as the zone's name
                if last_label == zone.get_name() {
                    // Gets the RR's
                    let mut rrs_by_type = zone.get_rrs_by_type(self.get_stype());

                    // Finds Soa TTL
                    let soa_rr = main_zone.get_rrs_by_type(6)[0].clone();
                    let soa_minimun_ttl = match soa_rr.get_rdata() {
                        Rdata::SomeSoaRdata(val) => val.get_minimum(),
                        _ => unreachable!(),
                    };

                    // Sets TTL to max between RR ttl and SOA min.
                    for rr in rrs_by_type.iter_mut() {
                        let rr_ttl = rr.get_ttl();

                        rr.set_ttl(cmp::max(rr_ttl, soa_minimun_ttl));
                    }

                    return (rrs_by_type, false, false);
                }
            }
        }

        // If there is no RR's in zone
        let mut rr_vec = Vec::<ResourceRecord>::new();

        let mut nxdomain = false;
        let mut no_data = false;

        // We look for RR's in cache
        if USE_CACHE == true {
            // Gets the cache
            let mut cache = self.get_cache();

            let mut rrs_cache_answer = Vec::new();

            let mut cache_answer = Vec::new();

            //Check if exist nxdomain for domain_name and its subdomains
            let (nxdomain_subdomain_and_parent_domains, answer) =
                cache.check_nxdomain_cache(s_name.clone(), s_type.clone());

            if nxdomain_subdomain_and_parent_domains == true {
                cache_answer = answer.clone();
            } else {
                // Gets RR's in cache
                cache_answer = cache.get(s_name.clone(), s_type.clone());
            }

            // NXDOMAIN or NODATA
            if cache_answer.len() > 0 {
                let first_cache = cache_answer[0].clone();

                if first_cache.get_nxdomain() == true {
                    nxdomain = true;

                    rrs_cache_answer.push(first_cache.clone());
                }
                if first_cache.get_no_data() == true {
                    no_data = true;
                }
            }

            // Filters RR's by class
            if s_class != 255 {
                for rr in cache_answer {
                    let rr_class = rr.get_resource_record().get_class();

                    if rr_class == s_class {
                        rrs_cache_answer.push(rr);
                    }
                }
            }

            // If RR's exist
            if rrs_cache_answer.len() > 0 {
                // Sets TTL
                for answer in rrs_cache_answer.iter() {
                    let mut rr = answer.get_resource_record();
                    let rr_ttl = rr.get_ttl();
                    let relative_ttl = rr_ttl - self.get_timestamp();

                    if relative_ttl > 0 {
                        rr.set_ttl(relative_ttl);
                        rr_vec.push(rr);
                    }
                }

                // Deletes RR's with relative TTL < 0
                if rr_vec.len() < rrs_cache_answer.len() {
                    self.remove_from_cache(
                        s_name,
                        rrs_cache_answer[0].get_resource_record().get_string_type(),
                    );
                }
            }
        }

        return (rr_vec, nxdomain, no_data);
    }
}

// Util for TCP and UDP
impl ResolverQuery {
    // Step 4a from RFC 1034
    pub fn step_4a(&mut self, msg: DnsMessage) -> DnsMessage {
        // Get the answer, rcode and AA bit
        let mut answer = msg.get_answer();
        let mut additional = msg.get_additional();
        let rcode = msg.get_header().get_rcode();
        let aa = msg.get_header().get_aa();

        // If there is no error
        if rcode == 0 {
            // Get qname
            let qname = msg.get_question().get_qname().get_name();

            // Check if qname contains *, if its true dont cache the data
            if qname.contains("*") == false {
                // If the answers are autorative, we cache them
                if aa == true {
                    // We check if cache exist for the answer
                    let (exist_in_cache, data_ranking) = self.exist_cache_data(
                        msg.get_question().get_qname().get_name(),
                        answer[0].clone(),
                    );

                    if (exist_in_cache == false || data_ranking > 3) {
                        if exist_in_cache == true {
                            self.remove_from_cache(
                                answer[0].clone().get_name().get_name(),
                                answer[0].clone().get_string_type(),
                            )
                        };

                        for an in answer.iter_mut() {
                            if an.get_ttl() > 0 {
                                an.set_ttl(an.get_ttl() + self.get_timestamp());

                                // Add new Cache
                                self.add_to_cache(
                                    an.get_name().get_name(),
                                    an.clone(),
                                    3,
                                    false,
                                    false,
                                    "".to_string(),
                                );
                            }
                        }
                    }

                    let mut last_domain_saved = "".to_string();

                    for ad in additional.iter_mut() {
                        // We check if cache exist for the additionals
                        let (exist_in_cache, data_ranking) =
                            self.exist_cache_data(ad.get_name().get_name(), ad.clone());

                        // If cache does not exist, we cache the data
                        if (exist_in_cache == false) {
                            if ad.get_ttl() > 0 {
                                ad.set_ttl(ad.get_ttl() + self.get_timestamp());

                                // Cache
                                self.add_to_cache(
                                    ad.get_name().get_name(),
                                    ad.clone(),
                                    6,
                                    false,
                                    false,
                                    "".to_string(),
                                );
                                last_domain_saved = ad.get_name().get_name();
                            }
                        } else {
                            if (data_ranking >= 7) {
                                if ad.get_ttl() > 0 {
                                    ad.set_ttl(ad.get_ttl() + self.get_timestamp());

                                    // Cache
                                    if (last_domain_saved != ad.get_name().get_name()) {
                                        self.remove_from_cache(
                                            ad.get_name().get_name(),
                                            ad.clone().get_string_type(),
                                        );
                                    }

                                    // Adds to cache
                                    self.add_to_cache(
                                        ad.get_name().get_name(),
                                        ad.clone(),
                                        6,
                                        false,
                                        false,
                                        "".to_string(),
                                    );
                                    last_domain_saved = ad.get_name().get_name();
                                }
                            }
                        }
                    }
                } else {
                    // We check if cache exist for the answer
                    let (exist_in_cache, data_ranking) = self.exist_cache_data(
                        msg.get_question().get_qname().get_name(),
                        answer[0].clone(),
                    );

                    // If cache does not exist, we cache the data
                    if (exist_in_cache == false) {
                        for an in answer.iter_mut() {
                            if an.get_ttl() > 0 && an.get_type_code() == self.get_stype() {
                                an.set_ttl(an.get_ttl() + self.get_timestamp());

                                // Cache
                                self.add_to_cache(
                                    an.get_name().get_name(),
                                    an.clone(),
                                    6,
                                    false,
                                    false,
                                    "".to_string(),
                                );
                            }
                        }
                    } else {
                        if (data_ranking > 6) {
                            self.remove_from_cache(
                                answer[0].clone().get_name().get_name(),
                                answer[0].clone().get_string_type(),
                            );

                            for an in answer.iter_mut() {
                                if an.get_ttl() > 0 && an.get_type_code() == self.get_stype() {
                                    an.set_ttl(an.get_ttl() + self.get_timestamp());

                                    // Cache
                                    self.add_to_cache(
                                        an.get_name().get_name(),
                                        an.clone(),
                                        6,
                                        false,
                                        false,
                                        "".to_string(),
                                    );
                                }
                            }
                        }
                    }

                    let mut last_domain_saved = "".to_string();

                    for ad in additional.iter_mut() {
                        // We check if cache exist for the additionals
                        let (exist_in_cache, data_ranking) =
                            self.exist_cache_data(ad.get_name().get_name(), ad.clone());

                        // If cache does not exist, we cache the data
                        if (exist_in_cache == false) {
                            if ad.get_ttl() > 0 {
                                ad.set_ttl(ad.get_ttl() + self.get_timestamp());

                                // Cache
                                self.add_to_cache(
                                    ad.get_name().get_name(),
                                    ad.clone(),
                                    6,
                                    false,
                                    false,
                                    "".to_string(),
                                );
                                last_domain_saved = ad.get_name().get_name();
                            }
                        } else {
                            if (data_ranking >= 6) {
                                if ad.get_ttl() > 0 {
                                    ad.set_ttl(ad.get_ttl() + self.get_timestamp());

                                    // Cache
                                    if (last_domain_saved != ad.get_name().get_name()) {
                                        self.remove_from_cache(
                                            ad.get_name().get_name(),
                                            ad.clone().get_string_type(),
                                        );
                                    }
                                    self.add_to_cache(
                                        ad.get_name().get_name(),
                                        ad.clone(),
                                        6,
                                        false,
                                        false,
                                        "".to_string(),
                                    );
                                    last_domain_saved = ad.get_name().get_name();
                                }
                            }
                        }
                    }
                }
            }
        } else {
            let mut authority = msg.get_authority();

            if authority.len() > 0 {
                let mut first_authority = authority[0].clone();

                if first_authority.get_type_code() == 6 {
                    first_authority.set_ttl(first_authority.get_ttl() + self.get_timestamp());

                    self.remove_from_cache(
                        msg.get_question().get_qname().get_name(),
                        "NS".to_string(),
                    );
                    self.remove_from_cache(
                        msg.get_question().get_qname().get_name(),
                        "A".to_string(),
                    );
                    self.remove_from_cache(
                        msg.get_question().get_qname().get_name(),
                        "AAAA".to_string(),
                    );
                    self.remove_from_cache(
                        msg.get_question().get_qname().get_name(),
                        "SOA".to_string(),
                    );
                    self.remove_from_cache(
                        msg.get_question().get_qname().get_name(),
                        "MX".to_string(),
                    );
                    self.remove_from_cache(
                        msg.get_question().get_qname().get_name(),
                        "CNAME".to_string(),
                    );

                    self.add_to_cache(
                        msg.get_question().get_qname().get_name(),
                        first_authority.clone(),
                        3,
                        true,
                        false,
                        "NS".to_string(),
                    );

                    self.add_to_cache(
                        msg.get_question().get_qname().get_name(),
                        first_authority.clone(),
                        3,
                        true,
                        false,
                        "A".to_string(),
                    );

                    self.add_to_cache(
                        msg.get_question().get_qname().get_name(),
                        first_authority.clone(),
                        3,
                        true,
                        false,
                        "AAAA".to_string(),
                    );

                    self.add_to_cache(
                        msg.get_question().get_qname().get_name(),
                        first_authority,
                        3,
                        true,
                        false,
                        "CNAME".to_string(),
                    );
                }
            }
        }

        return msg;
    }
}

// Utils for Udp
impl ResolverQuery {
    // Sends a udp msg
    fn send_udp_query(&self, msg: &[u8], ip_address: String, socket: UdpSocket) {
        socket
            .send_to(msg, ip_address)
            .expect("failed to send message");
    }

    // Step 1 from RFC 1034 UDP version
    pub fn step_1_udp(
        &mut self,
        socket: UdpSocket,
        use_cache_for_answering: bool,
    ) -> Option<(Vec<ResourceRecord>, bool, bool)> {
        let mut local_info = (Vec::new(), false, false);

        if use_cache_for_answering {
            // Gets local info
            local_info = self.look_for_local_info();
        }

        let cache_info = local_info.0;
        let nxdomain = local_info.1;
        let no_data = local_info.2;

        // If local info exists, return those data
        if (cache_info.len() > 0 || no_data == true) {
            return Some((cache_info, nxdomain, no_data));
        }
        // In other case, we send a query to name servers
        else {
            self.step_2_udp(socket.try_clone().unwrap());
            self.step_3_udp(socket);
            return None;
        }
    }

    // Step 2 RFC 1034 UDP
    pub fn step_2_udp(&mut self, socket: UdpSocket) {
        // Initializes slist
        let sbelt = self.get_sbelt();
        let sname = self.get_sname();
        self.initialize_slist_udp(sbelt, sname, socket);

        // Sorts slist
        let mut slist = self.get_slist();
        slist.sort();

        // Sets the slist
        self.set_slist(slist);

        // Updates the query
        self.get_tx_update_query().send(self.clone());
    }

    // Step 3 from RFC 1034 UDP version
    pub fn step_3_udp(&mut self, socket: UdpSocket) {
        let queries_left = self.get_queries_before_temporary_error();

        // Temporary Error
        if queries_left <= 0 {
            self.get_tx_delete_query().send(self.clone());
            return;
        }

        // Gets slist
        let mut slist = self.get_slist();
        let mut slist_len = slist.len();

        if slist_len <= 0 {
            self.get_tx_delete_query().send(self.clone());
            return;
        }

        // Gets the index to choose in slist
        let mut index_to_choose = self.get_index_to_choose() % slist_len as u16;

        // Gets the best server to ask
        let mut best_server_to_ask = slist.get(index_to_choose);
        let mut best_server_ip = best_server_to_ask
            .get(&"ip_address".to_string())
            .unwrap()
            .clone();

        // Counter to know if all records in slist were used
        let mut counter = 0;

        while &best_server_ip == "" {
            // If all records do not have ip, we update slist
            if counter > slist.len() {
                let new_slist = self.send_internal_queries_for_slist_udp(
                    self.get_slist(),
                    socket.try_clone().unwrap(),
                );
                self.set_slist(new_slist.clone());

                if new_slist.len() <= 0 {
                    self.get_tx_delete_query().send(self.clone());
                    return;
                }
            }

            // We choose the next record in slist
            slist = self.get_slist();
            self.set_index_to_choose((index_to_choose + 1) % slist.len() as u16);
            index_to_choose = self.get_index_to_choose();

            best_server_to_ask = slist.get(index_to_choose);
            best_server_ip = best_server_to_ask
                .get(&"ip_address".to_string())
                .unwrap()
                .clone();

            counter = counter + 1;
        }

        // Set query timeout
        let response_time = best_server_to_ask
            .get(&"response_time".to_string())
            .unwrap();

        self.set_timeout(cmp::min(
            response_time.parse::<u32>().unwrap() * 5 as u32,
            5000,
        ));

        //

        if (best_server_ip.contains(":") == false) {
            // Sets 53 port
            best_server_ip.push_str(":53");
        }

        // Update the index to choose
        self.set_index_to_choose((index_to_choose + 1) % slist.len() as u16);
        //

        // Creates query msg
        let query_msg = self.create_query_message();
        let msg_to_bytes = query_msg.to_bytes();

        let best_server_name = best_server_to_ask.get(&"name".to_string()).unwrap().clone();

        // Update the queries count before temporary error
        self.set_queries_before_temporary_error(queries_left - 1);

        //

        // Set query timestamp
        let now = Utc::now();
        let timestamp_query = now.timestamp_millis();

        self.set_last_query_timestamp(timestamp_query as u64);
        //

        // Set last host name asked
        let host_name = best_server_to_ask.get(&"name".to_string()).unwrap().clone();
        self.set_last_query_hostname(host_name);
        //

        // Send the resolver query to the resolver for update
        self.get_tx_update_query().send(self.clone());
        //

        // Sends the query
        self.send_udp_query(&msg_to_bytes, best_server_ip, socket);
    }

    // Step 4 from RFC 1034 UDP version
    pub fn step_4_udp(
        &mut self,
        msg_from_response: DnsMessage,
        socket: UdpSocket,
    ) -> Option<DnsMessage> {
        // Gets answer and rcode
        let rcode = msg_from_response.get_header().get_rcode();
        let answer = msg_from_response.get_answer();
        let aa = msg_from_response.get_header().get_aa();

        // Step 4a
        if (answer.len() > 0
            && rcode == 0
            && answer[answer.len() - 1].get_type_code() == self.get_stype())
            || rcode == 3
        {
            return Some(self.step_4a(msg_from_response));
        }

        let authority = msg_from_response.get_authority();

        // Step 4b
        // If there is authority and it is NS type
        if (authority.len() > 0) && (authority[0].get_type_code() == 2) && answer.len() == 0 {
            self.step_4b_udp(msg_from_response, socket);
            return None;
        }

        // Step 4c
        // If the answer is CName and the user dont want CName
        if answer.len() > 0
            && answer[0].get_type_code() == 5
            && answer[0].get_type_code() != self.get_stype()
        {
            return self.step_4c_udp(msg_from_response, socket);
        }

        // No data answer
        if answer.len() == 0 && rcode == 0 && aa == true {
            let question_name = msg_from_response.get_question().get_qname().get_name();
            let question_type = match msg_from_response.get_question().get_qtype() {
                1 => "A".to_string(),
                2 => "NS".to_string(),
                5 => "CNAME".to_string(),
                6 => "SOA".to_string(),
                11 => "WKS".to_string(),
                12 => "PTR".to_string(),
                13 => "HINFO".to_string(),
                14 => "MINFO".to_string(),
                15 => "MX".to_string(),
                16 => "TXT".to_string(),
                //////////////////////// Replace the next line when AAAA is implemented /////////////////
                28 => "TXT".to_string(),
                /////////////////////////////////////////////////////////////////////////////////////////
                _ => unreachable!(),
            };

            let txt_rdata = TxtRdata::new(Vec::new());
            let empty_txt_rdata = Rdata::SomeTxtRdata(txt_rdata);
            let empty_rr = ResourceRecord::new(empty_txt_rdata);

            self.add_to_cache(question_name, empty_rr, 3, false, true, question_type);

            return Some(msg_from_response);
        }

        // Step 4d
        return self.step_4d_udp(self.get_last_query_hostname(), socket);
    }

    // Step 4b from RFC 1034 UDP version
    pub fn step_4b_udp(&mut self, msg: DnsMessage, socket: UdpSocket) {
        let mut authority = msg.get_authority();
        let mut additional = msg.get_additional();

        let qname = authority[0].get_name().get_name();

        // We check if cache exist for the ns
        let (exist_in_cache, data_ranking) =
            self.exist_cache_data(qname.clone(), authority[0].clone());

        if (exist_in_cache == false || data_ranking > 4) {
            if exist_in_cache == true {
                // Delete cache
                self.remove_from_cache(
                    authority[0].clone().get_name().get_name(),
                    authority[0].clone().get_string_type(),
                );
            }

            for ns in authority.iter_mut() {
                if self.compare_match_count(ns.get_name().get_name()) {
                    ns.set_ttl(ns.get_ttl() + self.get_timestamp());

                    // Add new cache
                    self.add_to_cache(
                        ns.get_name().get_name(),
                        ns.clone(),
                        4,
                        false,
                        false,
                        "".to_string(),
                    );
                    //

                    // Get the NS domain name
                    let ns_domain_name = match ns.get_rdata() {
                        Rdata::SomeNsRdata(val) => val.get_nsdname().get_name(),
                        _ => unreachable!(),
                    };
                    //

                    let mut first_ip_delete_cache = true;

                    // Adds and remove ip addresses
                    for ip in additional.iter_mut() {
                        if ns_domain_name == ip.get_name().get_name() {
                            // We check if cache exist for the ip

                            let (exist_in_cache, data_ranking) =
                                self.exist_cache_data(ip.get_name().get_name(), ip.clone());

                            if exist_in_cache == false
                                || data_ranking > 5
                                || first_ip_delete_cache == false
                            {
                                ip.set_ttl(ip.get_ttl() + self.get_timestamp());

                                if exist_in_cache == true && first_ip_delete_cache == true {
                                    // Remove old cache
                                    self.remove_from_cache(
                                        ip.get_name().get_name(),
                                        ip.clone().get_string_type(),
                                    );

                                    first_ip_delete_cache = false;
                                }

                                // Cache
                                self.add_to_cache(
                                    ip.get_name().get_name(),
                                    ip.clone(),
                                    5,
                                    false,
                                    false,
                                    "".to_string(),
                                );
                                //

                                first_ip_delete_cache = false;
                            }
                        }
                    }
                }
            }
        }

        // Continue the delegation
        self.step_2_udp(socket.try_clone().unwrap());
        self.step_3_udp(socket.try_clone().unwrap());

        if self.new_algorithm == true && data_ranking > 3 {
            self.send_internal_queries_for_child_ns_udp(socket.try_clone().unwrap(), qname);
        }
    }

    // Step 4c from RFC 1034 UDP version
    pub fn step_4c_udp(&mut self, mut msg: DnsMessage, socket: UdpSocket) -> Option<DnsMessage> {
        // Gets answer, and rdata from the first answer
        let answers = msg.get_answer();
        let mut resource_record = answers[0].clone();
        let rdata = resource_record.get_rdata();

        // Checks if the answer is a CName
        let rr_data = match rdata {
            Rdata::SomeCnameRdata(val) => val.clone(),
            _ => unreachable!(),
        };

        // Sets the TTL
        let cname = rr_data.get_cname();
        resource_record.set_ttl(resource_record.get_ttl() + self.get_timestamp());

        // We check if cache exist for the ip
        let (exist_in_cache, data_ranking) = self.exist_cache_data(
            resource_record.get_name().get_name(),
            resource_record.clone(),
        );

        if exist_in_cache == false || data_ranking > 3 {
            if exist_in_cache == true {
                self.remove_from_cache(
                    resource_record.get_name().get_name(),
                    resource_record.clone().get_string_type(),
                );
            }

            self.add_to_cache(
                resource_record.get_name().get_name(),
                resource_record,
                3,
                false,
                false,
                "".to_string(),
            );
            //
        }

        // Check if contains the answer for cname
        if answers.len() > 1 {
            let cname_name = cname.get_name();
            let mut answers_found = 0;
            let qtype = self.get_stype();

            let mut answers_for_cname = Vec::<ResourceRecord>::new();

            for answer in answers[1..].into_iter() {
                let answer_name = answer.get_name().get_name();
                let answer_type = answer.get_type_code();

                if answer_name == cname_name && answer_type == qtype {
                    answers_found = answers_found + 1;
                    answers_for_cname.push(answer.clone());
                }
            }

            // Add to cache and return msg
            if answers_found > 0 {
                let mut msg_without_answer_cname = msg.clone();
                msg_without_answer_cname.set_answer(answers_for_cname);
                msg_without_answer_cname.update_header_counters();

                self.step_4a(msg_without_answer_cname);

                return Some(msg);
            }
        }
        //

        // Updates sname in query
        self.set_sname(cname.get_name());

        // Checks local info, and send the query if there is no local info
        match self.step_1_udp(socket, true) {
            Some(val) => {
                let cache_info = val.0;
                let nxdomain = val.1;
                let no_data = val.2;

                let mut query_msg = msg.clone();

                if cache_info.len() > 0 && nxdomain == false {
                    // Sets the msg's info
                    query_msg.set_answer(cache_info.clone());
                    query_msg.set_authority(Vec::new());
                    query_msg.set_additional(Vec::new());

                    let mut header = query_msg.get_header();
                    header.set_ancount(cache_info.len() as u16);
                    header.set_nscount(0);
                    header.set_arcount(0);
                    header.set_id(self.get_old_id());
                    header.set_qr(true);

                    query_msg.set_header(header);

                    return Some(query_msg);
                }
                if nxdomain == true {
                    // Sets the msg's info
                    query_msg.set_answer(Vec::new());
                    query_msg.set_authority(cache_info.clone());
                    query_msg.set_additional(Vec::new());

                    let mut header = query_msg.get_header();
                    header.set_ancount(0);
                    header.set_nscount(cache_info.len() as u16);
                    header.set_arcount(0);
                    header.set_id(self.get_old_id());
                    header.set_qr(true);
                    header.set_rcode(3);

                    query_msg.set_header(header);

                    return Some(query_msg);
                }

                if no_data == true {
                    // Sets the msg's info
                    query_msg.set_answer(Vec::new());
                    query_msg.set_authority(Vec::new());
                    query_msg.set_additional(Vec::new());

                    let mut header = query_msg.get_header();
                    header.set_ancount(0);
                    header.set_nscount(0);
                    header.set_arcount(0);
                    header.set_id(self.get_old_id());
                    header.set_qr(true);

                    query_msg.set_header(header);

                    return Some(query_msg);
                }

                return Some(query_msg);
            }
            None => {
                return None;
            }
        }
    }

    // Step 4d from RFC 1034 UDP version
    pub fn step_4d_udp(
        &mut self,
        host_name_asked: String,
        socket: UdpSocket,
    ) -> Option<DnsMessage> {
        // Gets slist and deletes the host name
        let mut slist = self.get_slist();
        slist.delete(host_name_asked.clone());

        if slist.len() == 0 {
            match host_name_asked.find(".") {
                // If there is parent domain
                Some(index) => {
                    // Initialize slist from parent
                    let parent_host_name = &host_name_asked[index + 1..];
                    self.initialize_slist_udp(
                        self.get_sbelt(),
                        parent_host_name.to_string(),
                        socket.try_clone().unwrap(),
                    );
                    self.set_index_to_choose(0);
                }
                // If there is no parent
                None => {
                    // Initialize from root
                    self.initialize_slist_udp(
                        self.get_sbelt(),
                        ".".to_string(),
                        socket.try_clone().unwrap(),
                    );
                    self.set_index_to_choose(0);
                }
            }
        } else {
            // Selects next from slist
            self.set_index_to_choose(self.get_index_to_choose() % slist.len() as u16);
            self.set_slist(slist);
        }

        // Update the query data in resolver
        self.get_tx_update_query().send(self.clone());
        //

        self.step_3_udp(socket);
        return None;
    }

    // Sends internal querie to obtain NS child records
    fn send_internal_queries_for_child_ns_udp(&self, socket: UdpSocket, qname: String) {
        thread::spawn(move || {
            // Creates an UDP socket
            let ip = IP_FOR_SLIST_NS_QUERIES.to_string();
            let mut rng = thread_rng();

            let slist_socket = Self::initilize_socket_udp(ip).unwrap();

            // Create query id
            let query_id: u16 = rng.gen();

            // Create msg
            let query_msg = DnsMessage::new_query_message(qname.clone(), 2, 1, 0, false, query_id);

            let msg_to_bytes = query_msg.to_bytes();

            slist_socket.send_to(&msg_to_bytes, RESOLVER_IP_PORT);
        });
    }

    // Sends internal querie to obtain NS child records
    fn send_internal_queries_for_child_ns_tcp(&self, qname: String) {
        let queries_left = self.get_queries_before_temporary_error();
        let new_algorithm = self.new_algorithm;

        thread::spawn(move || {
            let ip = IP_FOR_SLIST_NS_QUERIES.to_string();
            let mut rng = thread_rng();

            let slist_socket = TcpStream::connect(RESOLVER_IP_PORT.to_string()).unwrap();

            // Create query id
            let query_id: u16 = rng.gen();

            // Create msg
            let query_msg = DnsMessage::new_query_message(qname.clone(), 1, 1, 0, false, query_id);

            Resolver::send_answer_by_tcp(
                query_msg,
                RESOLVER_IP_PORT.to_string(),
                slist_socket.try_clone().unwrap(),
            );
        });
    }

    // Sends internal queries to obtain ip address for slist
    fn send_internal_queries_for_slist_udp(&self, mut slist: Slist, socket: UdpSocket) -> Slist {
        // Gets NS from slist
        let mut ns_list = slist.get_ns_list();

        for ns in &ns_list {
            let queries_left = self.get_queries_before_temporary_error();

            let ip_addr = ns.get(&"ip_address".to_string()).unwrap().to_string();
            let qname = ns
                .get(&"name".to_string())
                .unwrap()
                .to_lowercase()
                .to_string();

            // If there is no ip address, we send a query to obtain it
            if ip_addr == "".to_string() {
                // Creates an UDP socket
                let ip = "192.168.1.90".to_string();
                let mut rng = thread_rng();

                let slist_socket = Self::initilize_socket_udp(ip).unwrap();
                slist_socket.set_read_timeout(Some(Duration::from_millis(5000)));

                // Create query id
                let query_id: u16 = rng.gen();

                // Create msg
                let query_msg =
                    DnsMessage::new_query_message(qname.clone(), 1, 1, 0, false, query_id);

                let msg_to_bytes = query_msg.to_bytes();

                slist_socket.send_to(&msg_to_bytes, RESOLVER_IP_PORT);

                // Wait the response
                let response_result = Resolver::receive_udp_msg(slist_socket.try_clone().unwrap());

                let msg_response;

                match response_result {
                    Some(val) => {
                        msg_response = val.0.clone();
                    }
                    None => {
                        slist.delete(qname.clone());
                        continue;
                    }
                }

                if msg_response.get_answer().len() > 0 {
                    let answers = msg_response.get_answer();
                    let answer = answers[answers.len() - 1].clone();
                    let rdata = answer.get_rdata();

                    let new_ip = match rdata {
                        Rdata::SomeARdata(val) => val.get_address(),
                        _ => unreachable!(),
                    };

                    let mut ip_string = "".to_string();

                    for number in new_ip {
                        ip_string.push_str(&number.to_string());
                        ip_string.push_str(".");
                    }

                    ip_string.pop();

                    slist.delete(qname.clone());

                    slist.insert(qname.clone(), ip_string.to_string(), 5000 as u32);

                    break;
                }
                if (msg_response.get_header().get_rcode() != 0) {
                    slist.delete(qname.clone());
                    continue;
                }
            }
        }
        return slist;
    }
}

// Utils for tcp
impl ResolverQuery {
    fn send_tcp_query(&mut self, msg: &[u8], ip_address: String) -> DnsMessage {
        // Adds the two bytes needs for tcp
        let msg_length: u16 = msg.len() as u16;
        let tcp_bytes_length = [(msg_length >> 8) as u8, msg_length as u8];
        let full_msg = [&tcp_bytes_length, msg].concat();

        // Timeout config
        let timeout = self.get_timeout();
        //

        let split_ip_port: Vec<&str> = ip_address.split(":").collect();
        let ip = split_ip_port[0];
        let port = split_ip_port[1];
        let ip_split: Vec<&str> = ip.split(".").collect();
        let ip_v4_socket = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(
                ip_split[0].parse::<u8>().unwrap(),
                ip_split[1].parse::<u8>().unwrap(),
                ip_split[2].parse::<u8>().unwrap(),
                ip_split[3].parse::<u8>().unwrap(),
            )),
            port.parse::<u16>().unwrap(),
        );

        let mut stream_result =
            TcpStream::connect_timeout(&ip_v4_socket, Duration::from_millis(timeout as u64));
        let mut stream_bool: bool = match stream_result {
            Ok(_) => true,
            Err(_) => false,
        };

        if stream_bool == false {
            return self.step_3_tcp();
        }

        let mut stream = stream_result.unwrap();

        // Set timeout for read
        stream.set_read_timeout(Some(Duration::from_millis(timeout as u64)));

        // Sends msg
        stream.write(&full_msg);

        match Resolver::receive_tcp_msg(stream) {
            // If there is answer
            Some(val) => {
                // Parses the msg
                let dns_response_result = DnsMessage::from_bytes(&val);

                // Checks parsed msg
                match dns_response_result {
                    Ok(_) => {}
                    Err(e) => {
                        return DnsMessage::format_error_msg();
                    }
                }

                let dns_response = dns_response_result.unwrap();

                // Update response time in cache
                let last_query_timestamp = self.get_last_query_timestamp();
                let now = Utc::now();
                let timestamp_ms = now.timestamp_millis() as u64;

                let response_time = (timestamp_ms - last_query_timestamp) as u32;

                // Send request to update cache to resolver and name server
                self.get_update_cache_udp().send((
                    self.get_last_query_hostname(),
                    ip_address.clone(),
                    response_time,
                ));

                self.get_update_cache_tcp().send((
                    self.get_last_query_hostname(),
                    ip_address.clone(),
                    response_time,
                ));

                self.get_update_cache_ns_udp().send((
                    self.get_last_query_hostname(),
                    ip_address.clone(),
                    response_time,
                ));

                self.get_update_cache_ns_tcp().send((
                    self.get_last_query_hostname(),
                    ip_address.clone(),
                    response_time,
                ));
                //

                // Process the answer
                return self.step_4_tcp(dns_response);
            }
            // Sends query to another name server
            None => {
                self.step_2_tcp();
                return self.step_3_tcp();
            }
        };
    }

    // Step 1 from RFC 1034 TCP version
    pub fn step_1_tcp(
        &mut self,
        mut query_msg: DnsMessage,
        use_cache_for_answering: bool,
    ) -> DnsMessage {
        let mut local_info = (Vec::new(), false, false);

        if use_cache_for_answering {
            // Gets local info
            local_info = self.look_for_local_info();
        }

        let cache_info = local_info.0;
        let nxdomain = local_info.1;
        let no_data = local_info.2;

        if cache_info.len() > 0 && nxdomain == false {
            // Sets the msg's info
            query_msg.set_answer(cache_info.clone());
            query_msg.set_authority(Vec::new());
            query_msg.set_additional(Vec::new());

            let mut header = query_msg.get_header();
            header.set_ancount(cache_info.len() as u16);
            header.set_nscount(0);
            header.set_arcount(0);
            header.set_id(self.get_old_id());
            header.set_qr(true);

            query_msg.set_header(header);

            return query_msg;
        } else if nxdomain == true {
            // Sets the msg's info
            query_msg.set_answer(Vec::new());
            query_msg.set_authority(cache_info.clone());
            query_msg.set_additional(Vec::new());

            let mut header = query_msg.get_header();
            header.set_ancount(0);
            header.set_nscount(cache_info.len() as u16);
            header.set_arcount(0);
            header.set_id(self.get_old_id());
            header.set_qr(true);
            header.set_rcode(3);

            query_msg.set_header(header);

            return query_msg;
        } else if no_data == true {
            // Sets the msg's info
            query_msg.set_answer(Vec::new());
            query_msg.set_authority(Vec::new());
            query_msg.set_additional(Vec::new());

            let mut header = query_msg.get_header();
            header.set_ancount(0);
            header.set_nscount(0);
            header.set_arcount(0);
            header.set_id(self.get_old_id());
            header.set_qr(true);

            query_msg.set_header(header);

            return query_msg;
        } else {
            // Initializes slist and sends the query
            self.step_2_tcp();
            return self.step_3_tcp();
        }
    }

    // Step 2 RFC 1034 TCP
    pub fn step_2_tcp(&mut self) {
        // Initializes slist
        let sbelt = self.get_sbelt();
        let sname = self.get_sname();
        self.initialize_slist_tcp(sbelt, sname);

        // Sorts slist
        let mut slist = self.get_slist();
        slist.sort();

        // Sets the slist
        self.set_slist(slist);
    }

    // Step 3 from RFC 1034 TCP version
    pub fn step_3_tcp(&mut self) -> DnsMessage {
        let queries_left = self.get_queries_before_temporary_error();

        // Temporary Error
        if queries_left <= 0 {
            panic!("Temporary Error");
        }

        // Gets index to choose a name server in slist
        let mut slist = self.get_slist();
        let mut index_to_choose = self.get_index_to_choose() % slist.len() as u16;

        // Gets the best server to ask
        let mut best_server_to_ask = slist.get(index_to_choose);
        let mut best_server_ip = best_server_to_ask
            .get(&"ip_address".to_string())
            .unwrap()
            .clone();

        // Counter to know if all records in slist were used
        let mut counter = 0;

        while &best_server_ip == "" {
            // If all records do not have ip, we update slist
            if counter > slist.len() {
                let new_slist = self.send_internal_queries_for_slist_tcp(self.get_slist());
                self.set_slist(new_slist.clone());

                if new_slist.len() <= 0 {
                    self.get_tx_delete_query().send(self.clone());
                    panic!("Temporary Error");
                }
            }

            // Selects the next record in slist
            slist = self.get_slist();
            self.set_index_to_choose((index_to_choose + 1) % slist.len() as u16);
            index_to_choose = self.get_index_to_choose();

            // Gets the ip adress
            best_server_to_ask = slist.get(index_to_choose);
            best_server_ip = best_server_to_ask
                .get(&"ip_address".to_string())
                .unwrap()
                .clone();

            counter = counter + 1;
        }

        // Set query timeout
        let response_time = best_server_to_ask
            .get(&"response_time".to_string())
            .unwrap();

        self.set_timeout(response_time.parse::<u32>().unwrap() * 1.5 as u32);

        //

        // Adds port to the ip adress
        if (best_server_ip.contains(":") == false) {
            // Sets 53 port
            best_server_ip.push_str(":53");
        }

        // Update the index to choose
        self.set_index_to_choose((index_to_choose + 1) % slist.len() as u16);
        //

        let query_msg = self.create_query_message();
        let msg_to_bytes = query_msg.to_bytes();

        // Update the queries count before temporary error
        self.set_queries_before_temporary_error(queries_left - 1);

        //

        // Set query timestamp
        let now = Utc::now();
        let timestamp_query = now.timestamp_millis();
        self.set_last_query_timestamp(timestamp_query as u64);
        //

        // Set last host name asked
        let host_name = best_server_to_ask.get(&"name".to_string()).unwrap().clone();
        self.set_last_query_hostname(host_name);
        //

        return self.send_tcp_query(&msg_to_bytes, best_server_ip);
    }

    // Step 4 from RFC 1034 TCP version
    pub fn step_4_tcp(&mut self, msg_from_response: DnsMessage) -> DnsMessage {
        // Gets the answer and rcode
        let rcode = msg_from_response.get_header().get_rcode();
        let answer = msg_from_response.get_answer();
        let aa = msg_from_response.get_header().get_aa();

        // Step 4a
        if (answer.len() > 0 && rcode == 0 && answer[0].get_type_code() == self.get_stype())
            || rcode == 3
        {
            return self.step_4a(msg_from_response);
        }

        let authority = msg_from_response.get_authority();
        let additional = msg_from_response.get_additional();

        // Step 4b
        // If there is authority and it is NS type
        if (authority.len() > 0) && (authority[0].get_type_code() == 2 && answer.len() == 0) {
            return self.step_4b_tcp(msg_from_response);
        }

        // Step 4c
        // If the answer is CName and the user dont want CName
        if answer.len() > 0
            && answer[0].get_type_code() == 5
            && answer[0].get_type_code() != self.get_stype()
        {
            return self.step_4c_tcp(msg_from_response);
        }

        // No data answer
        if answer.len() == 0 && rcode == 0 && aa == true {
            let question_name = msg_from_response.get_question().get_qname().get_name();
            let question_type = match msg_from_response.get_question().get_qtype() {
                1 => "A".to_string(),
                2 => "NS".to_string(),
                5 => "CNAME".to_string(),
                6 => "SOA".to_string(),
                11 => "WKS".to_string(),
                12 => "PTR".to_string(),
                13 => "HINFO".to_string(),
                14 => "MINFO".to_string(),
                15 => "MX".to_string(),
                16 => "TXT".to_string(),
                //////////////////////// Replace the next line when AAAA is implemented /////////////////
                28 => "TXT".to_string(),
                /////////////////////////////////////////////////////////////////////////////////////////
                _ => unreachable!(),
            };

            let txt_rdata = TxtRdata::new(Vec::new());
            let empty_txt_rdata = Rdata::SomeTxtRdata(txt_rdata);
            let empty_rr = ResourceRecord::new(empty_txt_rdata);

            self.add_to_cache(question_name, empty_rr, 3, false, true, question_type);

            return msg_from_response;
        }

        // Gets the last used slist record
        let slist = self.get_slist();

        let mut last_index_to_choose = self.get_index_to_choose();

        if last_index_to_choose != 0 {
            last_index_to_choose = (self.get_index_to_choose() - 1) % slist.len() as u16;
        }

        let best_server = slist.get(last_index_to_choose);
        let best_server_hostname = best_server.get(&"name".to_string()).unwrap();

        // Step 4d
        return self.step_4d_tcp(best_server_hostname.to_string());
    }

    // Step 4b from RFC 1034 TCP version
    pub fn step_4b_tcp(&mut self, msg: DnsMessage) -> DnsMessage {
        let mut authority = msg.get_authority();
        let mut additional = msg.get_additional();

        // We check if cache exist for the ns
        let (exist_in_cache, data_ranking) = self.exist_cache_data(
            msg.get_question().get_qname().get_name(),
            authority[0].clone(),
        );

        if (exist_in_cache == false || data_ranking > 4) {
            if exist_in_cache == true {
                //Remove old cache
                self.remove_from_cache(
                    authority[0].clone().get_name().get_name(),
                    authority[0].clone().get_string_type(),
                );
            }

            // Adds NS and A RRs to cache if these can help
            for ns in authority.iter_mut() {
                if self.compare_match_count(ns.get_name().get_name()) {
                    ns.set_ttl(ns.get_ttl() + self.get_timestamp());

                    // Cache
                    // Add new cache
                    self.add_to_cache(
                        ns.get_name().get_name(),
                        ns.clone(),
                        4,
                        false,
                        false,
                        "".to_string(),
                    );

                    //

                    // Get the NS domain name
                    let ns_domain_name = match ns.get_rdata() {
                        Rdata::SomeNsRdata(val) => val.get_nsdname().get_name(),
                        _ => unreachable!(),
                    };
                    //

                    let mut first_ip_delete_cache = true;

                    // Removes and adds the ip addresses
                    for ip in additional.iter_mut() {
                        if ns_domain_name == ip.get_name().get_name() {
                            // We check if cache exist for the ip
                            let (exist_in_cache, data_ranking) =
                                self.exist_cache_data(ip.get_name().get_name(), ip.clone());

                            if exist_in_cache == false
                                || data_ranking > 5
                                || first_ip_delete_cache == false
                            {
                                ip.set_ttl(ip.get_ttl() + self.get_timestamp());

                                if exist_in_cache && first_ip_delete_cache == true {
                                    self.remove_from_cache(
                                        ip.get_name().get_name(),
                                        ip.clone().get_string_type(),
                                    );

                                    first_ip_delete_cache = false;
                                }

                                // Cache
                                self.add_to_cache(
                                    ip.get_name().get_name(),
                                    ip.clone(),
                                    7,
                                    false,
                                    false,
                                    "".to_string(),
                                );

                                first_ip_delete_cache = false;
                            }
                        }
                    }
                }
            }
        }

        // NS set from child
        if self.new_algorithm == true && data_ranking > 3 {
            self.send_internal_queries_for_child_ns_tcp(msg.get_question().get_qname().get_name());
        }

        // Continue the delegation
        self.step_2_tcp();
        return self.step_3_tcp();
    }

    // Step 4c from RFC 1034 TCP version
    pub fn step_4c_tcp(&mut self, mut msg: DnsMessage) -> DnsMessage {
        // Gets the first rdata from the answer
        let answer = msg.get_answer();
        let resource_record = answer[0].clone();
        let rdata = resource_record.get_rdata();

        // Checks if it is a Cname record
        let rr_data = match rdata {
            Rdata::SomeCnameRdata(val) => val.clone(),
            _ => unreachable!(),
        };

        let cname = rr_data.get_cname();

        // We check if cache exist for the ip
        let (exist_in_cache, data_ranking) = self.exist_cache_data(
            resource_record.get_name().get_name(),
            resource_record.clone(),
        );

        if exist_in_cache == false || data_ranking > 3 {
            if exist_in_cache == true {
                self.remove_from_cache(
                    resource_record.get_name().get_name(),
                    resource_record.clone().get_string_type(),
                );
            }

            self.add_to_cache(
                resource_record.get_name().get_name(),
                resource_record,
                3,
                false,
                false,
                "".to_string(),
            );
            //
        }

        // Updates sname in query
        self.set_sname(cname.get_name());

        return self.step_1_tcp(msg, true);
    }

    // Step 4d from RFC 1034 TCP version
    pub fn step_4d_tcp(&mut self, host_name_asked: String) -> DnsMessage {
        // Deletes last name server used
        let mut slist = self.get_slist();
        slist.delete(host_name_asked.clone());

        // If slist is empty
        if slist.len() == 0 {
            match host_name_asked.find(".") {
                Some(index) => {
                    // Initializes slist from parent domain
                    let parent_host_name = &host_name_asked[index + 1..];
                    self.initialize_slist_tcp(self.get_sbelt(), parent_host_name.to_string());
                    self.set_index_to_choose(0);
                }
                None => {
                    // Initializes slist from root
                    self.initialize_slist_tcp(self.get_sbelt(), ".".to_string());
                    self.set_index_to_choose(0);
                }
            }
        } else {
            // Selects a new index to use
            self.set_index_to_choose(self.get_index_to_choose() % slist.len() as u16);
            self.set_slist(slist);
        }

        return self.step_3_tcp();
    }

    // Sends internal queries to obtain NS ip addresses
    fn send_internal_queries_for_slist_tcp(&self, mut slist: Slist) -> Slist {
        let ns_list = slist.get_ns_list();

        for ns in ns_list {
            let queries_left = self.get_queries_before_temporary_error();

            let ip_addr = ns.get(&"ip_address".to_string()).unwrap().to_string();
            let qname = ns
                .get(&"name".to_string())
                .unwrap()
                .to_lowercase()
                .to_string();

            // If the ns does not have ip
            if ip_addr == "".to_string() {
                let ip = IP_FOR_SLIST_NS_QUERIES.to_string();
                let mut rng = thread_rng();

                let slist_socket = TcpStream::connect(RESOLVER_IP_PORT.to_string()).unwrap();
                slist_socket.set_read_timeout(Some(Duration::from_millis(5000)));

                // Create query id
                let query_id: u16 = rng.gen();

                // Create msg
                let query_msg =
                    DnsMessage::new_query_message(qname.clone(), 1, 1, 0, false, query_id);

                Resolver::send_answer_by_tcp(
                    query_msg,
                    RESOLVER_IP_PORT.to_string(),
                    slist_socket.try_clone().unwrap(),
                );

                // Wait the response
                let response_result = Resolver::receive_tcp_msg(slist_socket.try_clone().unwrap());

                let mut msg_response;

                match response_result {
                    Some(val) => {
                        msg_response = DnsMessage::from_bytes(&val);
                    }
                    None => {
                        slist.delete(qname.clone());
                        continue;
                    }
                }

                let msg = match msg_response {
                    Ok(val) => val,
                    Err(_) => DnsMessage::format_error_msg(),
                };

                if msg.get_answer().len() > 0 {
                    let answers = msg.get_answer();
                    let answer = answers[answers.len() - 1].clone();
                    let rdata = answer.get_rdata();

                    let new_ip = match rdata {
                        Rdata::SomeARdata(val) => val.get_address(),
                        _ => unreachable!(),
                    };

                    let mut ip_string = "".to_string();

                    for number in new_ip {
                        ip_string.push_str(&number.to_string());
                        ip_string.push_str(".");
                    }

                    ip_string.pop();

                    slist.delete(qname.clone());

                    slist.insert(qname.clone(), ip_string.to_string(), 5000 as u32);

                    break;
                }
            }
        }

        return slist;
    }
}

// Others utils
impl ResolverQuery {
    // Add a new element to cache
    pub fn add_to_cache(
        &mut self,
        domain_name: String,
        resource_record: ResourceRecord,
        data_ranking: u8,
        nxdomain: bool,
        no_data: bool,
        rr_type: String,
    ) {
        // Gets the cache
        let mut cache = self.get_cache();

        // Sends info to update cache
        self.get_add_channel_udp()
            .send((
                domain_name.clone(),
                resource_record.clone(),
                data_ranking,
                nxdomain,
                no_data,
                rr_type.clone(),
            ))
            .unwrap_or(());
        self.get_add_channel_tcp()
            .send((
                domain_name.clone(),
                resource_record.clone(),
                data_ranking,
                nxdomain,
                no_data,
                rr_type.clone(),
            ))
            .unwrap_or(());
        self.get_add_channel_ns_udp()
            .send((domain_name.clone(), resource_record.clone()))
            .unwrap_or(());
        self.get_add_channel_ns_tcp()
            .send((domain_name.clone(), resource_record.clone()))
            .unwrap_or(());

        // Adds to cache
        cache.add(
            domain_name,
            resource_record,
            data_ranking,
            nxdomain,
            no_data,
            rr_type,
        );

        // Sets the cache
        self.set_cache(cache);
    }

    // Removes an element from cache
    pub fn remove_from_cache(&mut self, domain_name: String, rr_type: String) {
        // Gets cache
        let mut cache = self.get_cache();

        // Sends info to update the cache
        self.get_delete_channel_udp()
            .send((domain_name.clone(), rr_type.clone()))
            .unwrap();
        self.get_delete_channel_tcp()
            .send((domain_name.clone(), rr_type.clone()))
            .unwrap();
        self.get_delete_channel_ns_udp()
            .send((domain_name.clone(), rr_type.clone()));
        self.get_delete_channel_ns_tcp()
            .send((domain_name.clone(), rr_type.clone()));

        // Removes the element
        cache.remove(domain_name, rr_type);

        self.set_cache(cache);
    }

    // See if data exist in cache
    pub fn exist_cache_data(
        &mut self,
        domain_name: String,
        resource_record: ResourceRecord,
    ) -> (bool, u8) {
        let mut cache = self.get_cache();
        let rr_type = resource_record.get_string_type();

        // Gets the data
        let data_in_cache = cache.get(domain_name, rr_type);

        // Returns boolean
        if data_in_cache.len() > 0 {
            return (true, data_in_cache[0].clone().get_data_ranking());
        } else {
            return (false, 8);
        }
    }

    // Creates a new query dns message
    pub fn create_query_message(&mut self) -> DnsMessage {
        let sname = self.get_sname();
        let stype = self.get_stype();
        let sclass = self.get_sclass();
        let op_code = self.get_op_code();
        let rd = self.get_rd();
        let id = self.get_main_query_id();

        // Creates the msg
        let query_message = DnsMessage::new_query_message(sname, stype, sclass, op_code, rd, id);

        query_message
    }

    // Compares the match count from slist with the given hostname
    pub fn compare_match_count(&self, name: String) -> bool {
        let slist_match_count = self.get_slist().get_zone_name_equivalent();
        let s_name_labels: String = self.get_sname();
        let mut s_name_labels_vec: Vec<&str> = s_name_labels.split('.').collect();
        let mut name_labels: Vec<&str> = name.split('.').collect();
        let min_len = cmp::min(s_name_labels.len(), name_labels.len());

        let mut name_match_count = 0;

        // Iterates over the labels
        for _i in 0..min_len {
            let s_name_last_element = s_name_labels_vec[s_name_labels_vec.len() - 1];
            let name_last_element = name_labels[name_labels.len() - 1];
            if s_name_last_element == name_last_element {
                name_match_count = name_match_count + 1;
                s_name_labels_vec.pop();
                name_labels.pop();
            } else {
                break;
            }
        }

        // If name match count > slist match count
        if name_match_count > slist_match_count {
            return true;
        }

        return false;
    }

    pub fn initilize_socket_udp(ip_addr: String) -> Option<UdpSocket> {
        // Create randon generator
        let mut ip = ip_addr;
        let mut rng = thread_rng();
        let mut port = rng.gen_range(50000..65000);

        let mut port_ok = false;

        while port_ok == false {
            let mut ip_port = "".to_string();

            ip_port.push_str(&ip);
            ip_port.push_str(":");
            ip_port.push_str(&port.to_string());

            let slist_socket = UdpSocket::bind(&ip_port);

            match slist_socket {
                Ok(val) => {
                    return Some(val);
                }
                Err(_) => {
                    port = port + 1;
                    continue;
                }
            }
        }

        return None;
    }
}

// Getters
impl ResolverQuery {
    /// Gets the timestamp
    pub fn get_timestamp(&self) -> u32 {
        self.timestamp.clone()
    }

    /// Gets the sname
    pub fn get_sname(&self) -> String {
        self.sname.clone()
    }

    /// Gets the stype
    pub fn get_stype(&self) -> u16 {
        self.stype
    }

    /// Gets the sclass
    pub fn get_sclass(&self) -> u16 {
        self.sclass
    }

    /// Gets the op_code
    pub fn get_op_code(&self) -> u8 {
        self.op_code
    }

    /// Gets the recursion desired bit
    pub fn get_rd(&self) -> bool {
        self.rd
    }

    /// Gets the slist
    pub fn get_slist(&self) -> Slist {
        self.slist.clone()
    }

    /// Gets the sbelt
    pub fn get_sbelt(&self) -> Slist {
        self.sbelt.clone()
    }

    /// Gets the cache
    pub fn get_cache(&self) -> DnsCache {
        self.cache.clone()
    }

    /// Gets the ns_data
    pub fn get_ns_data(&self) -> HashMap<u16, HashMap<String, NSZone>> {
        self.ns_data.clone()
    }

    /// Gets the main_query_id
    pub fn get_main_query_id(&self) -> u16 {
        self.main_query_id
    }

    /// Gets the old id
    pub fn get_old_id(&self) -> u16 {
        self.old_id
    }

    /// Get the owner's query address
    pub fn get_src_address(&self) -> String {
        self.src_address.clone()
    }

    /// Get the owner's query address
    pub fn get_add_channel_udp(&self) -> Sender<(String, ResourceRecord, u8, bool, bool, String)> {
        self.add_channel_udp.clone()
    }

    /// Get the owner's query address
    pub fn get_add_channel_tcp(&self) -> Sender<(String, ResourceRecord, u8, bool, bool, String)> {
        self.add_channel_tcp.clone()
    }

    /// Get the owner's query address
    pub fn get_delete_channel_udp(&self) -> Sender<(String, String)> {
        self.delete_channel_udp.clone()
    }

    /// Get the owner's query address
    pub fn get_delete_channel_tcp(&self) -> Sender<(String, String)> {
        self.delete_channel_tcp.clone()
    }

    /// Get the owner's query address
    pub fn get_add_channel_ns_udp(&self) -> Sender<(String, ResourceRecord)> {
        self.add_channel_ns_udp.clone()
    }

    /// Get the owner's query address
    pub fn get_add_channel_ns_tcp(&self) -> Sender<(String, ResourceRecord)> {
        self.add_channel_ns_tcp.clone()
    }

    /// Get the owner's query address
    pub fn get_delete_channel_ns_udp(&self) -> Sender<(String, String)> {
        self.delete_channel_ns_udp.clone()
    }

    /// Get the owner's query address
    pub fn get_delete_channel_ns_tcp(&self) -> Sender<(String, String)> {
        self.delete_channel_ns_tcp.clone()
    }

    /// Gets the queries before temporary error field
    pub fn get_queries_before_temporary_error(&self) -> u16 {
        self.queries_before_temporary_error
    }

    /// Gets the sender to update the resolver query in the resolver
    pub fn get_tx_update_query(&self) -> Sender<ResolverQuery> {
        self.tx_update_query.clone()
    }

    /// Gets the sender to delete the resolver query in the resolver
    pub fn get_tx_delete_query(&self) -> Sender<ResolverQuery> {
        self.tx_delete_query.clone()
    }

    /// Gets the index to choose from slist
    pub fn get_index_to_choose(&self) -> u16 {
        self.index_to_choose
    }

    /// Gets the last query timestamp
    pub fn get_last_query_timestamp(&self) -> u64 {
        self.last_query_timestamp
    }

    /// Gets the timeout for the actual query to name server
    pub fn get_timeout(&self) -> u32 {
        self.timeout
    }

    ///Gets the last query hostname
    pub fn get_last_query_hostname(&self) -> String {
        self.last_query_hostname.clone()
    }

    /// Gets the sender for updating cache
    pub fn get_update_cache_udp(&self) -> Sender<(String, String, u32)> {
        self.update_cache_sender_udp.clone()
    }

    /// Gets the sender for updating cache
    pub fn get_update_cache_tcp(&self) -> Sender<(String, String, u32)> {
        self.update_cache_sender_tcp.clone()
    }

    /// Gets the sender for updating cache
    pub fn get_update_cache_ns_udp(&self) -> Sender<(String, String, u32)> {
        self.update_cache_sender_ns_udp.clone()
    }

    /// Gets the sender for updating cache
    pub fn get_update_cache_ns_tcp(&self) -> Sender<(String, String, u32)> {
        self.update_cache_sender_ns_tcp.clone()
    }
}

// Setters
impl ResolverQuery {
    /// Sets the timestamp attribute with a new value
    pub fn set_timestamp(&mut self, timestamp: u32) {
        self.timestamp = timestamp;
    }

    /// Sets the sname attribute with a new value
    pub fn set_sname(&mut self, sname: String) {
        self.sname = sname;
    }

    /// Sets the stype attribute with a new value
    pub fn set_stype(&mut self, stype: u16) {
        self.stype = stype;
    }

    /// Sets the sclass attribute with a new value
    pub fn set_sclass(&mut self, sclass: u16) {
        self.sclass = sclass;
    }

    /// Sets the op_code attribute with a new value
    pub fn set_op_code(&mut self, op_code: u8) {
        self.op_code = op_code;
    }

    /// Sets the rd attribute with a new value
    pub fn set_rd(&mut self, rd: bool) {
        self.rd = rd;
    }

    /// Sets the slist attribute with a new value
    pub fn set_slist(&mut self, slist: Slist) {
        self.slist = slist;
    }

    /// Sets the sbelt attribute with a new value
    pub fn set_sbelt(&mut self, sbelt: Slist) {
        self.sbelt = sbelt;
    }

    /// Sets the cache attribute with a new value
    pub fn set_cache(&mut self, cache: DnsCache) {
        self.cache = cache;
    }

    /// Sets the ns_data attribute with a new value
    pub fn set_ns_data(&mut self, ns_data: HashMap<u16, HashMap<String, NSZone>>) {
        self.ns_data = ns_data;
    }

    /// Sets the old id attribute with a new id
    pub fn set_main_query_id(&mut self, query_id: u16) {
        self.main_query_id = query_id;
    }

    /// Sets the old id attribute with a new id
    pub fn set_old_id(&mut self, query_id: u16) {
        self.old_id = query_id;
    }

    /// Sets the owner's query address
    pub fn set_src_address(&mut self, address: String) {
        self.src_address = address;
    }

    /// Sets the queries before temporary error field with a new value
    pub fn set_queries_before_temporary_error(&mut self, queries_before_temporary_error: u16) {
        self.queries_before_temporary_error = queries_before_temporary_error;
    }

    /// Sets the index to choose from slist with a new value
    pub fn set_index_to_choose(&mut self, index_to_choose: u16) {
        self.index_to_choose = index_to_choose;
    }

    /// Sets the timestamp for the last query for the request
    pub fn set_last_query_timestamp(&mut self, last_query_timestamp: u64) {
        self.last_query_timestamp = last_query_timestamp;
    }

    /// Sets the timeout for a query to name server
    pub fn set_timeout(&mut self, timeout: u32) {
        self.timeout = timeout;
    }

    /// Sets the host name for the last query
    pub fn set_last_query_hostname(&mut self, last_query_hostname: String) {
        self.last_query_hostname = last_query_hostname;
    }
}

mod resolver_query_tests {
    use crate::dns_cache::DnsCache;
    use crate::domain_name::DomainName;
    use crate::message::rdata::a_rdata::ARdata;
    use crate::message::rdata::ns_rdata::NsRdata;
    use crate::message::rdata::Rdata;
    use crate::message::resource_record::ResourceRecord;
    use crate::message::DnsMessage;
    use crate::resolver::resolver_query::ResolverQuery;
    use crate::resolver::slist::Slist;

    use chrono::Utc;
    use std::collections::HashMap;
    use std::sync::mpsc;
    use std::vec::Vec;

    #[test]
    fn constructor_test() {
        /// Channels
        let (add_sender_udp, add_recv_udp) = mpsc::channel();
        let (delete_sender_udp, delete_recv_udp) = mpsc::channel();
        let (add_sender_tcp, add_recv_tcp) = mpsc::channel();
        let (delete_sender_tcp, delete_recv_tcp) = mpsc::channel();
        let (add_sender_ns_udp, add_recv_ns_udp) = mpsc::channel();
        let (delete_sender_ns_udp, delete_recv_ns_udp) = mpsc::channel();
        let (add_sender_ns_tcp, add_recv_ns_tcp) = mpsc::channel();
        let (delete_sender_ns_tcp, delete_recv_ns_tcp) = mpsc::channel();

        let (tx_update_query, rx_update_query) = mpsc::channel();
        let (tx_delete_query, rx_delete_query) = mpsc::channel();

        let (tx_update_cache_udp, rx_update_cache_udp) = mpsc::channel();
        let (tx_update_cache_tcp, rx_update_cache_tcp) = mpsc::channel();
        let (tx_update_cache_ns_udp, rx_update_cache_ns_udp) = mpsc::channel();
        let (tx_update_cache_ns_tcp, rx_update_cache_ns_tcp) = mpsc::channel();

        let (tx_update_slist_tcp, rx_update_slist_tcp) = mpsc::channel();

        let mut resolver_query = ResolverQuery::new(
            add_sender_udp,
            delete_sender_udp,
            add_sender_tcp,
            delete_sender_tcp,
            add_sender_ns_udp,
            delete_sender_ns_udp,
            add_sender_ns_tcp,
            delete_sender_ns_tcp,
            tx_update_query,
            tx_delete_query,
            DnsMessage::new(),
            tx_update_cache_udp,
            tx_update_cache_tcp,
            tx_update_cache_ns_udp,
            tx_update_cache_ns_tcp,
            tx_update_slist_tcp,
        );

        assert_eq!(resolver_query.sname, "".to_string());
        assert_eq!(resolver_query.stype, 0);
        assert_eq!(resolver_query.sclass, 0);
        assert_eq!(resolver_query.slist.get_ns_list().len(), 0);
        assert_eq!(resolver_query.cache.clone().get_size(), 0);
    }

    #[test]
    fn set_and_get_timestamp() {
        /// Channels
        let (add_sender_udp, add_recv_udp) = mpsc::channel();
        let (delete_sender_udp, delete_recv_udp) = mpsc::channel();
        let (add_sender_tcp, add_recv_tcp) = mpsc::channel();
        let (delete_sender_tcp, delete_recv_tcp) = mpsc::channel();
        let (add_sender_ns_udp, add_recv_ns_udp) = mpsc::channel();
        let (delete_sender_ns_udp, delete_recv_ns_udp) = mpsc::channel();
        let (add_sender_ns_tcp, add_recv_ns_tcp) = mpsc::channel();
        let (delete_sender_ns_tcp, delete_recv_ns_tcp) = mpsc::channel();

        let (tx_update_query, rx_update_query) = mpsc::channel();
        let (tx_delete_query, rx_delete_query) = mpsc::channel();

        let (tx_update_cache_udp, rx_update_cache_udp) = mpsc::channel();
        let (tx_update_cache_tcp, rx_update_cache_tcp) = mpsc::channel();
        let (tx_update_cache_ns_udp, rx_update_cache_ns_udp) = mpsc::channel();
        let (tx_update_cache_ns_tcp, rx_update_cache_ns_tcp) = mpsc::channel();

        let (tx_update_slist_tcp, rx_update_slist_tcp) = mpsc::channel();

        let mut resolver_query = ResolverQuery::new(
            add_sender_udp,
            delete_sender_udp,
            add_sender_tcp,
            delete_sender_tcp,
            add_sender_ns_udp,
            delete_sender_ns_udp,
            add_sender_ns_tcp,
            delete_sender_ns_tcp,
            tx_update_query,
            tx_delete_query,
            DnsMessage::new(),
            tx_update_cache_udp,
            tx_update_cache_tcp,
            tx_update_cache_ns_udp,
            tx_update_cache_ns_tcp,
            tx_update_slist_tcp,
        );

        let now = Utc::now();
        let now_timestamp = now.timestamp() as u32;

        resolver_query.set_timestamp(now_timestamp);

        assert_eq!(resolver_query.get_timestamp(), now_timestamp);
    }

    #[test]
    fn set_and_get_sname() {
        /// Channels
        let (add_sender_udp, add_recv_udp) = mpsc::channel();
        let (delete_sender_udp, delete_recv_udp) = mpsc::channel();
        let (add_sender_tcp, add_recv_tcp) = mpsc::channel();
        let (delete_sender_tcp, delete_recv_tcp) = mpsc::channel();
        let (add_sender_ns_udp, add_recv_ns_udp) = mpsc::channel();
        let (delete_sender_ns_udp, delete_recv_ns_udp) = mpsc::channel();
        let (add_sender_ns_tcp, add_recv_ns_tcp) = mpsc::channel();
        let (delete_sender_ns_tcp, delete_recv_ns_tcp) = mpsc::channel();

        let (tx_update_query, rx_update_query) = mpsc::channel();
        let (tx_delete_query, rx_delete_query) = mpsc::channel();

        let (tx_update_cache_udp, rx_update_cache_udp) = mpsc::channel();
        let (tx_update_cache_tcp, rx_update_cache_tcp) = mpsc::channel();
        let (tx_update_cache_ns_udp, rx_update_cache_ns_udp) = mpsc::channel();
        let (tx_update_cache_ns_tcp, rx_update_cache_ns_tcp) = mpsc::channel();

        let (tx_update_slist_tcp, rx_update_slist_tcp) = mpsc::channel();

        let mut resolver_query = ResolverQuery::new(
            add_sender_udp,
            delete_sender_udp,
            add_sender_tcp,
            delete_sender_tcp,
            add_sender_ns_udp,
            delete_sender_ns_udp,
            add_sender_ns_tcp,
            delete_sender_ns_tcp,
            tx_update_query,
            tx_delete_query,
            DnsMessage::new(),
            tx_update_cache_udp,
            tx_update_cache_tcp,
            tx_update_cache_ns_udp,
            tx_update_cache_ns_tcp,
            tx_update_slist_tcp,
        );

        assert_eq!(resolver_query.sname, "".to_string());

        resolver_query.set_sname("test.com".to_string());

        assert_eq!(resolver_query.get_sname(), "test.com".to_string());
    }

    #[test]
    fn set_and_get_stype() {
        /// Channels
        let (add_sender_udp, add_recv_udp) = mpsc::channel();
        let (delete_sender_udp, delete_recv_udp) = mpsc::channel();
        let (add_sender_tcp, add_recv_tcp) = mpsc::channel();
        let (delete_sender_tcp, delete_recv_tcp) = mpsc::channel();
        let (add_sender_ns_udp, add_recv_ns_udp) = mpsc::channel();
        let (delete_sender_ns_udp, delete_recv_ns_udp) = mpsc::channel();
        let (add_sender_ns_tcp, add_recv_ns_tcp) = mpsc::channel();
        let (delete_sender_ns_tcp, delete_recv_ns_tcp) = mpsc::channel();

        let (tx_update_query, rx_update_query) = mpsc::channel();
        let (tx_delete_query, rx_delete_query) = mpsc::channel();

        let (tx_update_cache_udp, rx_update_cache_udp) = mpsc::channel();
        let (tx_update_cache_tcp, rx_update_cache_tcp) = mpsc::channel();
        let (tx_update_cache_ns_udp, rx_update_cache_ns_udp) = mpsc::channel();
        let (tx_update_cache_ns_tcp, rx_update_cache_ns_tcp) = mpsc::channel();

        let (tx_update_slist_tcp, rx_update_slist_tcp) = mpsc::channel();

        let mut resolver_query = ResolverQuery::new(
            add_sender_udp,
            delete_sender_udp,
            add_sender_tcp,
            delete_sender_tcp,
            add_sender_ns_udp,
            delete_sender_ns_udp,
            add_sender_ns_tcp,
            delete_sender_ns_tcp,
            tx_update_query,
            tx_delete_query,
            DnsMessage::new(),
            tx_update_cache_udp,
            tx_update_cache_tcp,
            tx_update_cache_ns_udp,
            tx_update_cache_ns_tcp,
            tx_update_slist_tcp,
        );

        assert_eq!(resolver_query.stype, 0);

        resolver_query.set_stype(1);

        assert_eq!(resolver_query.get_stype(), 1);
    }

    #[test]
    fn set_and_get_sclass() {
        /// Channels
        let (add_sender_udp, add_recv_udp) = mpsc::channel();
        let (delete_sender_udp, delete_recv_udp) = mpsc::channel();
        let (add_sender_tcp, add_recv_tcp) = mpsc::channel();
        let (delete_sender_tcp, delete_recv_tcp) = mpsc::channel();
        let (add_sender_ns_udp, add_recv_ns_udp) = mpsc::channel();
        let (delete_sender_ns_udp, delete_recv_ns_udp) = mpsc::channel();
        let (add_sender_ns_tcp, add_recv_ns_tcp) = mpsc::channel();
        let (delete_sender_ns_tcp, delete_recv_ns_tcp) = mpsc::channel();

        let (tx_update_query, rx_update_query) = mpsc::channel();
        let (tx_delete_query, rx_delete_query) = mpsc::channel();

        let (tx_update_cache_udp, rx_update_cache_udp) = mpsc::channel();
        let (tx_update_cache_tcp, rx_update_cache_tcp) = mpsc::channel();
        let (tx_update_cache_ns_udp, rx_update_cache_ns_udp) = mpsc::channel();
        let (tx_update_cache_ns_tcp, rx_update_cache_ns_tcp) = mpsc::channel();

        let (tx_update_slist_tcp, rx_update_slist_tcp) = mpsc::channel();

        let mut resolver_query = ResolverQuery::new(
            add_sender_udp,
            delete_sender_udp,
            add_sender_tcp,
            delete_sender_tcp,
            add_sender_ns_udp,
            delete_sender_ns_udp,
            add_sender_ns_tcp,
            delete_sender_ns_tcp,
            tx_update_query,
            tx_delete_query,
            DnsMessage::new(),
            tx_update_cache_udp,
            tx_update_cache_tcp,
            tx_update_cache_ns_udp,
            tx_update_cache_ns_tcp,
            tx_update_slist_tcp,
        );

        assert_eq!(resolver_query.sclass, 0);

        resolver_query.set_sclass(1);

        assert_eq!(resolver_query.get_sclass(), 1);
    }

    #[test]
    fn set_and_get_op_code() {
        /// Channels
        let (add_sender_udp, add_recv_udp) = mpsc::channel();
        let (delete_sender_udp, delete_recv_udp) = mpsc::channel();
        let (add_sender_tcp, add_recv_tcp) = mpsc::channel();
        let (delete_sender_tcp, delete_recv_tcp) = mpsc::channel();
        let (add_sender_ns_udp, add_recv_ns_udp) = mpsc::channel();
        let (delete_sender_ns_udp, delete_recv_ns_udp) = mpsc::channel();
        let (add_sender_ns_tcp, add_recv_ns_tcp) = mpsc::channel();
        let (delete_sender_ns_tcp, delete_recv_ns_tcp) = mpsc::channel();

        let (tx_update_query, rx_update_query) = mpsc::channel();
        let (tx_delete_query, rx_delete_query) = mpsc::channel();

        let (tx_update_cache_udp, rx_update_cache_udp) = mpsc::channel();
        let (tx_update_cache_tcp, rx_update_cache_tcp) = mpsc::channel();
        let (tx_update_cache_ns_udp, rx_update_cache_ns_udp) = mpsc::channel();
        let (tx_update_cache_ns_tcp, rx_update_cache_ns_tcp) = mpsc::channel();

        let (tx_update_slist_tcp, rx_update_slist_tcp) = mpsc::channel();

        let mut resolver_query = ResolverQuery::new(
            add_sender_udp,
            delete_sender_udp,
            add_sender_tcp,
            delete_sender_tcp,
            add_sender_ns_udp,
            delete_sender_ns_udp,
            add_sender_ns_tcp,
            delete_sender_ns_tcp,
            tx_update_query,
            tx_delete_query,
            DnsMessage::new(),
            tx_update_cache_udp,
            tx_update_cache_tcp,
            tx_update_cache_ns_udp,
            tx_update_cache_ns_tcp,
            tx_update_slist_tcp,
        );

        assert_eq!(resolver_query.op_code, 0);

        resolver_query.set_op_code(1);

        assert_eq!(resolver_query.get_op_code(), 1);
    }

    #[test]
    fn set_and_get_rd() {
        /// Channels
        let (add_sender_udp, add_recv_udp) = mpsc::channel();
        let (delete_sender_udp, delete_recv_udp) = mpsc::channel();
        let (add_sender_tcp, add_recv_tcp) = mpsc::channel();
        let (delete_sender_tcp, delete_recv_tcp) = mpsc::channel();
        let (add_sender_ns_udp, add_recv_ns_udp) = mpsc::channel();
        let (delete_sender_ns_udp, delete_recv_ns_udp) = mpsc::channel();
        let (add_sender_ns_tcp, add_recv_ns_tcp) = mpsc::channel();
        let (delete_sender_ns_tcp, delete_recv_ns_tcp) = mpsc::channel();

        let (tx_update_query, rx_update_query) = mpsc::channel();
        let (tx_delete_query, rx_delete_query) = mpsc::channel();

        let (tx_update_cache_udp, rx_update_cache_udp) = mpsc::channel();
        let (tx_update_cache_tcp, rx_update_cache_tcp) = mpsc::channel();
        let (tx_update_cache_ns_udp, rx_update_cache_ns_udp) = mpsc::channel();
        let (tx_update_cache_ns_tcp, rx_update_cache_ns_tcp) = mpsc::channel();

        let (tx_update_slist_tcp, rx_update_slist_tcp) = mpsc::channel();

        let mut resolver_query = ResolverQuery::new(
            add_sender_udp,
            delete_sender_udp,
            add_sender_tcp,
            delete_sender_tcp,
            add_sender_ns_udp,
            delete_sender_ns_udp,
            add_sender_ns_tcp,
            delete_sender_ns_tcp,
            tx_update_query,
            tx_delete_query,
            DnsMessage::new(),
            tx_update_cache_udp,
            tx_update_cache_tcp,
            tx_update_cache_ns_udp,
            tx_update_cache_ns_tcp,
            tx_update_slist_tcp,
        );

        assert_eq!(resolver_query.rd, false);

        resolver_query.set_rd(true);

        assert_eq!(resolver_query.get_rd(), true);
    }

    #[test]
    fn set_and_get_slist() {
        /// Channels
        let (add_sender_udp, add_recv_udp) = mpsc::channel();
        let (delete_sender_udp, delete_recv_udp) = mpsc::channel();
        let (add_sender_tcp, add_recv_tcp) = mpsc::channel();
        let (delete_sender_tcp, delete_recv_tcp) = mpsc::channel();
        let (add_sender_ns_udp, add_recv_ns_udp) = mpsc::channel();
        let (delete_sender_ns_udp, delete_recv_ns_udp) = mpsc::channel();
        let (add_sender_ns_tcp, add_recv_ns_tcp) = mpsc::channel();
        let (delete_sender_ns_tcp, delete_recv_ns_tcp) = mpsc::channel();

        let (tx_update_query, rx_update_query) = mpsc::channel();
        let (tx_delete_query, rx_delete_query) = mpsc::channel();

        let (tx_update_cache_udp, rx_update_cache_udp) = mpsc::channel();
        let (tx_update_cache_tcp, rx_update_cache_tcp) = mpsc::channel();
        let (tx_update_cache_ns_udp, rx_update_cache_ns_udp) = mpsc::channel();
        let (tx_update_cache_ns_tcp, rx_update_cache_ns_tcp) = mpsc::channel();

        let (tx_update_slist_tcp, rx_update_slist_tcp) = mpsc::channel();

        let mut resolver_query = ResolverQuery::new(
            add_sender_udp,
            delete_sender_udp,
            add_sender_tcp,
            delete_sender_tcp,
            add_sender_ns_udp,
            delete_sender_ns_udp,
            add_sender_ns_tcp,
            delete_sender_ns_tcp,
            tx_update_query,
            tx_delete_query,
            DnsMessage::new(),
            tx_update_cache_udp,
            tx_update_cache_tcp,
            tx_update_cache_ns_udp,
            tx_update_cache_ns_tcp,
            tx_update_slist_tcp,
        );

        let mut slist = Slist::new();

        assert_eq!(resolver_query.slist.get_ns_list().len(), 0);

        slist.insert("test.com".to_string(), "127.0.0.1".to_string(), 5000);
        resolver_query.set_slist(slist);

        assert_eq!(resolver_query.get_slist().get_ns_list().len(), 1);
    }

    #[test]
    fn set_and_get_sbelt() {
        /// Channels
        let (add_sender_udp, add_recv_udp) = mpsc::channel();
        let (delete_sender_udp, delete_recv_udp) = mpsc::channel();
        let (add_sender_tcp, add_recv_tcp) = mpsc::channel();
        let (delete_sender_tcp, delete_recv_tcp) = mpsc::channel();
        let (add_sender_ns_udp, add_recv_ns_udp) = mpsc::channel();
        let (delete_sender_ns_udp, delete_recv_ns_udp) = mpsc::channel();
        let (add_sender_ns_tcp, add_recv_ns_tcp) = mpsc::channel();
        let (delete_sender_ns_tcp, delete_recv_ns_tcp) = mpsc::channel();

        let (tx_update_query, rx_update_query) = mpsc::channel();
        let (tx_delete_query, rx_delete_query) = mpsc::channel();

        let (tx_update_cache_udp, rx_update_cache_udp) = mpsc::channel();
        let (tx_update_cache_tcp, rx_update_cache_tcp) = mpsc::channel();
        let (tx_update_cache_ns_udp, rx_update_cache_ns_udp) = mpsc::channel();
        let (tx_update_cache_ns_tcp, rx_update_cache_ns_tcp) = mpsc::channel();

        let (tx_update_slist_tcp, rx_update_slist_tcp) = mpsc::channel();

        let mut resolver_query = ResolverQuery::new(
            add_sender_udp,
            delete_sender_udp,
            add_sender_tcp,
            delete_sender_tcp,
            add_sender_ns_udp,
            delete_sender_ns_udp,
            add_sender_ns_tcp,
            delete_sender_ns_tcp,
            tx_update_query,
            tx_delete_query,
            DnsMessage::new(),
            tx_update_cache_udp,
            tx_update_cache_tcp,
            tx_update_cache_ns_udp,
            tx_update_cache_ns_tcp,
            tx_update_slist_tcp,
        );

        let mut sbelt = Slist::new();

        assert_eq!(resolver_query.sbelt.get_ns_list().len(), 0);

        sbelt.insert("test.com".to_string(), "127.0.0.1".to_string(), 5000);
        resolver_query.set_sbelt(sbelt);

        assert_eq!(resolver_query.get_sbelt().get_ns_list().len(), 1);
    }

    #[test]
    fn set_and_get_cache() {
        /// Channels
        let (add_sender_udp, add_recv_udp) = mpsc::channel();
        let (delete_sender_udp, delete_recv_udp) = mpsc::channel();
        let (add_sender_tcp, add_recv_tcp) = mpsc::channel();
        let (delete_sender_tcp, delete_recv_tcp) = mpsc::channel();
        let (add_sender_ns_udp, add_recv_ns_udp) = mpsc::channel();
        let (delete_sender_ns_udp, delete_recv_ns_udp) = mpsc::channel();
        let (add_sender_ns_tcp, add_recv_ns_tcp) = mpsc::channel();
        let (delete_sender_ns_tcp, delete_recv_ns_tcp) = mpsc::channel();

        let (tx_update_query, rx_update_query) = mpsc::channel();
        let (tx_delete_query, rx_delete_query) = mpsc::channel();

        let (tx_update_cache_udp, rx_update_cache_udp) = mpsc::channel();
        let (tx_update_cache_tcp, rx_update_cache_tcp) = mpsc::channel();
        let (tx_update_cache_ns_udp, rx_update_cache_ns_udp) = mpsc::channel();
        let (tx_update_cache_ns_tcp, rx_update_cache_ns_tcp) = mpsc::channel();

        let (tx_update_slist_tcp, rx_update_slist_tcp) = mpsc::channel();

        let mut resolver_query = ResolverQuery::new(
            add_sender_udp,
            delete_sender_udp,
            add_sender_tcp,
            delete_sender_tcp,
            add_sender_ns_udp,
            delete_sender_ns_udp,
            add_sender_ns_tcp,
            delete_sender_ns_tcp,
            tx_update_query,
            tx_delete_query,
            DnsMessage::new(),
            tx_update_cache_udp,
            tx_update_cache_tcp,
            tx_update_cache_ns_udp,
            tx_update_cache_ns_tcp,
            tx_update_slist_tcp,
        );

        let mut cache = DnsCache::new();
        cache.set_max_size(1);

        assert_eq!(resolver_query.cache.get_size(), 0);

        let ip_address: [u8; 4] = [127, 0, 0, 0];
        let mut a_rdata = ARdata::new();

        a_rdata.set_address(ip_address);

        let rdata = Rdata::SomeARdata(a_rdata);
        let mut resource_record = ResourceRecord::new(rdata);
        resource_record.set_type_code(1);

        cache.add("127.0.0.0".to_string(), resource_record);
        resolver_query.set_cache(cache);

        assert_eq!(resolver_query.get_cache().get_size(), 1);
    }

    #[test]
    fn create_query_message_test() {
        /// Channels
        let (add_sender_udp, add_recv_udp) = mpsc::channel();
        let (delete_sender_udp, delete_recv_udp) = mpsc::channel();
        let (add_sender_tcp, add_recv_tcp) = mpsc::channel();
        let (delete_sender_tcp, delete_recv_tcp) = mpsc::channel();
        let (add_sender_ns_udp, add_recv_ns_udp) = mpsc::channel();
        let (delete_sender_ns_udp, delete_recv_ns_udp) = mpsc::channel();
        let (add_sender_ns_tcp, add_recv_ns_tcp) = mpsc::channel();
        let (delete_sender_ns_tcp, delete_recv_ns_tcp) = mpsc::channel();

        let (tx_update_query, rx_update_query) = mpsc::channel();
        let (tx_delete_query, rx_delete_query) = mpsc::channel();

        let (tx_update_cache_udp, rx_update_cache_udp) = mpsc::channel();
        let (tx_update_cache_tcp, rx_update_cache_tcp) = mpsc::channel();
        let (tx_update_cache_ns_udp, rx_update_cache_ns_udp) = mpsc::channel();
        let (tx_update_cache_ns_tcp, rx_update_cache_ns_tcp) = mpsc::channel();

        let (tx_update_slist_tcp, rx_update_slist_tcp) = mpsc::channel();

        let mut resolver_query = ResolverQuery::new(
            add_sender_udp,
            delete_sender_udp,
            add_sender_tcp,
            delete_sender_tcp,
            add_sender_ns_udp,
            delete_sender_ns_udp,
            add_sender_ns_tcp,
            delete_sender_ns_tcp,
            tx_update_query,
            tx_delete_query,
            DnsMessage::new(),
            tx_update_cache_udp,
            tx_update_cache_tcp,
            tx_update_cache_ns_udp,
            tx_update_cache_ns_tcp,
            tx_update_slist_tcp,
        );

        resolver_query.set_sname("test.com".to_string());
        resolver_query.set_rd(true);
        resolver_query.set_stype(1);
        resolver_query.set_sclass(1);

        let dns_message = resolver_query.create_query_message();

        assert_eq!(dns_message.get_header().get_rd(), true);
        assert_eq!(dns_message.get_question().get_qtype(), 1);
        assert_eq!(dns_message.get_question().get_qclass(), 1);
        assert_eq!(
            dns_message.get_question().get_qname().get_name(),
            "test.com".to_string()
        );
    }

    #[test]
    fn initialize_slist_test() {
        /// Channels
        let (add_sender_udp, add_recv_udp) = mpsc::channel();
        let (delete_sender_udp, delete_recv_udp) = mpsc::channel();
        let (add_sender_tcp, add_recv_tcp) = mpsc::channel();
        let (delete_sender_tcp, delete_recv_tcp) = mpsc::channel();
        let (add_sender_ns_udp, add_recv_ns_udp) = mpsc::channel();
        let (delete_sender_ns_udp, delete_recv_ns_udp) = mpsc::channel();
        let (add_sender_ns_tcp, add_recv_ns_tcp) = mpsc::channel();
        let (delete_sender_ns_tcp, delete_recv_ns_tcp) = mpsc::channel();

        let (tx_update_query, rx_update_query) = mpsc::channel();
        let (tx_delete_query, rx_delete_query) = mpsc::channel();

        let (tx_update_cache_udp, rx_update_cache_udp) = mpsc::channel();
        let (tx_update_cache_tcp, rx_update_cache_tcp) = mpsc::channel();
        let (tx_update_cache_ns_udp, rx_update_cache_ns_udp) = mpsc::channel();
        let (tx_update_cache_ns_tcp, rx_update_cache_ns_tcp) = mpsc::channel();

        let (tx_update_slist_tcp, rx_update_slist_tcp) = mpsc::channel();

        let mut resolver_query = ResolverQuery::new(
            add_sender_udp,
            delete_sender_udp,
            add_sender_tcp,
            delete_sender_tcp,
            add_sender_ns_udp,
            delete_sender_ns_udp,
            add_sender_ns_tcp,
            delete_sender_ns_tcp,
            tx_update_query,
            tx_delete_query,
            DnsMessage::new(),
            tx_update_cache_udp,
            tx_update_cache_tcp,
            tx_update_cache_ns_udp,
            tx_update_cache_ns_tcp,
            tx_update_slist_tcp,
        );

        resolver_query.set_sname("test.test2.com".to_string());
        resolver_query.set_rd(true);
        resolver_query.set_stype(1);
        resolver_query.set_sclass(1);

        let mut cache = DnsCache::new();
        cache.set_max_size(4);

        let mut domain_name = DomainName::new();
        domain_name.set_name("test2.com".to_string());

        let mut ns_rdata = NsRdata::new();
        ns_rdata.set_nsdname(domain_name);

        let r_data = Rdata::SomeNsRdata(ns_rdata);
        let mut ns_resource_record = ResourceRecord::new(r_data);
        ns_resource_record.set_type_code(2);

        let mut a_rdata = ARdata::new();
        a_rdata.set_address([127, 0, 0, 1]);

        let r_data = Rdata::SomeARdata(a_rdata);

        let mut a_resource_record = ResourceRecord::new(r_data);
        a_resource_record.set_type_code(1);

        cache.add("test2.com".to_string(), ns_resource_record);

        cache.add("test2.com".to_string(), a_resource_record);

        resolver_query.set_cache(cache);

        assert_eq!(resolver_query.get_slist().get_ns_list().len(), 0);

        let mut sbelt = Slist::new();
        sbelt.insert("test4.com".to_string(), "190.0.0.1".to_string(), 5000);

        resolver_query.initialize_slist_tcp(sbelt, resolver_query.get_sname());

        assert_eq!(resolver_query.get_slist().get_ns_list().len(), 1);

        assert_eq!(
            resolver_query
                .get_slist()
                .get_first()
                .get(&"name".to_string())
                .unwrap(),
            &"test2.com".to_string()
        );
    }

    #[test]
    fn initialize_slist_empty_test() {
        /// Channels
        let (add_sender_udp, add_recv_udp) = mpsc::channel();
        let (delete_sender_udp, delete_recv_udp) = mpsc::channel();
        let (add_sender_tcp, add_recv_tcp) = mpsc::channel();
        let (delete_sender_tcp, delete_recv_tcp) = mpsc::channel();
        let (add_sender_ns_udp, add_recv_ns_udp) = mpsc::channel();
        let (delete_sender_ns_udp, delete_recv_ns_udp) = mpsc::channel();
        let (add_sender_ns_tcp, add_recv_ns_tcp) = mpsc::channel();
        let (delete_sender_ns_tcp, delete_recv_ns_tcp) = mpsc::channel();

        let (tx_update_query, rx_update_query) = mpsc::channel();
        let (tx_delete_query, rx_delete_query) = mpsc::channel();

        let (tx_update_cache_udp, rx_update_cache_udp) = mpsc::channel();
        let (tx_update_cache_tcp, rx_update_cache_tcp) = mpsc::channel();
        let (tx_update_cache_ns_udp, rx_update_cache_ns_udp) = mpsc::channel();
        let (tx_update_cache_ns_tcp, rx_update_cache_ns_tcp) = mpsc::channel();

        let (tx_update_slist_tcp, rx_update_slist_tcp) = mpsc::channel();

        let mut resolver_query = ResolverQuery::new(
            add_sender_udp,
            delete_sender_udp,
            add_sender_tcp,
            delete_sender_tcp,
            add_sender_ns_udp,
            delete_sender_ns_udp,
            add_sender_ns_tcp,
            delete_sender_ns_tcp,
            tx_update_query,
            tx_delete_query,
            DnsMessage::new(),
            tx_update_cache_udp,
            tx_update_cache_tcp,
            tx_update_cache_ns_udp,
            tx_update_cache_ns_tcp,
            tx_update_slist_tcp,
        );

        resolver_query.set_sname("test6.test4.com".to_string());
        resolver_query.set_rd(true);
        resolver_query.set_stype(1);
        resolver_query.set_sclass(1);

        let mut cache = DnsCache::new();
        cache.set_max_size(2);

        let mut domain_name = DomainName::new();
        domain_name.set_name("test2.com".to_string());

        let mut ns_rdata = NsRdata::new();
        ns_rdata.set_nsdname(domain_name);

        let r_data = Rdata::SomeNsRdata(ns_rdata);
        let mut ns_resource_record = ResourceRecord::new(r_data);
        ns_resource_record.set_type_code(2);

        let mut a_rdata = ARdata::new();
        a_rdata.set_address([127, 0, 0, 1]);

        let r_data = Rdata::SomeARdata(a_rdata);

        let mut a_resource_record = ResourceRecord::new(r_data);
        a_resource_record.set_type_code(1);

        cache.add("test2.com".to_string(), ns_resource_record);

        cache.add("test2.com".to_string(), a_resource_record);

        resolver_query.set_cache(cache);

        assert_eq!(resolver_query.get_slist().get_ns_list().len(), 0);

        let mut sbelt = Slist::new();
        sbelt.insert("test4.com".to_string(), "190.0.0.1".to_string(), 5000);

        resolver_query.initialize_slist_tcp(sbelt, resolver_query.get_sname());

        assert_eq!(resolver_query.get_slist().get_ns_list().len(), 1);
        assert_eq!(
            resolver_query
                .get_slist()
                .get_first()
                .get(&"name".to_string())
                .unwrap(),
            &"test4.com".to_string()
        );
    }

    #[test]
    fn set_and_get_ns_data_test() {
        let mut domain_name = DomainName::new();
        domain_name.set_name("test2.com".to_string());

        let mut ns_rdata = NsRdata::new();
        ns_rdata.set_nsdname(domain_name);

        let r_data = Rdata::SomeNsRdata(ns_rdata);
        let mut ns_resource_record = ResourceRecord::new(r_data);
        ns_resource_record.set_type_code(2);

        let mut resource_record_vec = Vec::<ResourceRecord>::new();

        resource_record_vec.push(ns_resource_record);

        let mut host_names_hash = HashMap::<String, Vec<ResourceRecord>>::new();

        host_names_hash.insert("test.com".to_string(), resource_record_vec);

        let mut rr_type_hash = HashMap::<String, HashMap<String, Vec<ResourceRecord>>>::new();

        rr_type_hash.insert("NS".to_string(), host_names_hash);

        /// Channels
        let (add_sender_udp, add_recv_udp) = mpsc::channel();
        let (delete_sender_udp, delete_recv_udp) = mpsc::channel();
        let (add_sender_tcp, add_recv_tcp) = mpsc::channel();
        let (delete_sender_tcp, delete_recv_tcp) = mpsc::channel();
        let (add_sender_ns_udp, add_recv_ns_udp) = mpsc::channel();
        let (delete_sender_ns_udp, delete_recv_ns_udp) = mpsc::channel();
        let (add_sender_ns_tcp, add_recv_ns_tcp) = mpsc::channel();
        let (delete_sender_ns_tcp, delete_recv_ns_tcp) = mpsc::channel();

        let (tx_update_query, rx_update_query) = mpsc::channel();
        let (tx_delete_query, rx_delete_query) = mpsc::channel();

        let (tx_update_cache_udp, rx_update_cache_udp) = mpsc::channel();
        let (tx_update_cache_tcp, rx_update_cache_tcp) = mpsc::channel();
        let (tx_update_cache_ns_udp, rx_update_cache_ns_udp) = mpsc::channel();
        let (tx_update_cache_ns_tcp, rx_update_cache_ns_tcp) = mpsc::channel();

        let (tx_update_slist_tcp, rx_update_slist_tcp) = mpsc::channel();

        let mut resolver_query_test = ResolverQuery::new(
            add_sender_udp,
            delete_sender_udp,
            add_sender_tcp,
            delete_sender_tcp,
            add_sender_ns_udp,
            delete_sender_ns_udp,
            add_sender_ns_tcp,
            delete_sender_ns_tcp,
            tx_update_query,
            tx_delete_query,
            DnsMessage::new(),
            tx_update_cache_udp,
            tx_update_cache_tcp,
            tx_update_cache_ns_udp,
            tx_update_cache_ns_tcp,
            tx_update_slist_tcp,
        );

        assert_eq!(resolver_query_test.get_ns_data().len(), 0);

        //resolver_query_test.set_ns_data(rr_type_hash);

        //assert_eq!(resolver_query_test.get_ns_data().len(), 1);
    }

    #[test]
    fn set_and_get_main_query_id() {
        /// Channels
        let (add_sender_udp, add_recv_udp) = mpsc::channel();
        let (delete_sender_udp, delete_recv_udp) = mpsc::channel();
        let (add_sender_tcp, add_recv_tcp) = mpsc::channel();
        let (delete_sender_tcp, delete_recv_tcp) = mpsc::channel();
        let (add_sender_ns_udp, add_recv_ns_udp) = mpsc::channel();
        let (delete_sender_ns_udp, delete_recv_ns_udp) = mpsc::channel();
        let (add_sender_ns_tcp, add_recv_ns_tcp) = mpsc::channel();
        let (delete_sender_ns_tcp, delete_recv_ns_tcp) = mpsc::channel();

        let (tx_update_query, rx_update_query) = mpsc::channel();
        let (tx_delete_query, rx_delete_query) = mpsc::channel();

        let (tx_update_cache_udp, rx_update_cache_udp) = mpsc::channel();
        let (tx_update_cache_tcp, rx_update_cache_tcp) = mpsc::channel();
        let (tx_update_cache_ns_udp, rx_update_cache_ns_udp) = mpsc::channel();
        let (tx_update_cache_ns_tcp, rx_update_cache_ns_tcp) = mpsc::channel();

        let (tx_update_slist_tcp, rx_update_slist_tcp) = mpsc::channel();

        let mut resolver_query = ResolverQuery::new(
            add_sender_udp,
            delete_sender_udp,
            add_sender_tcp,
            delete_sender_tcp,
            add_sender_ns_udp,
            delete_sender_ns_udp,
            add_sender_ns_tcp,
            delete_sender_ns_tcp,
            tx_update_query,
            tx_delete_query,
            DnsMessage::new(),
            tx_update_cache_udp,
            tx_update_cache_tcp,
            tx_update_cache_ns_udp,
            tx_update_cache_ns_tcp,
            tx_update_slist_tcp,
        );

        resolver_query.set_main_query_id(0);

        assert_eq!(resolver_query.get_main_query_id(), 0);
    }

    #[test]
    fn set_and_get_old_id() {
        /// Channels
        let (add_sender_udp, add_recv_udp) = mpsc::channel();
        let (delete_sender_udp, delete_recv_udp) = mpsc::channel();
        let (add_sender_tcp, add_recv_tcp) = mpsc::channel();
        let (delete_sender_tcp, delete_recv_tcp) = mpsc::channel();
        let (add_sender_ns_udp, add_recv_ns_udp) = mpsc::channel();
        let (delete_sender_ns_udp, delete_recv_ns_udp) = mpsc::channel();
        let (add_sender_ns_tcp, add_recv_ns_tcp) = mpsc::channel();
        let (delete_sender_ns_tcp, delete_recv_ns_tcp) = mpsc::channel();

        let (tx_update_query, rx_update_query) = mpsc::channel();
        let (tx_delete_query, rx_delete_query) = mpsc::channel();

        let (tx_update_cache_udp, rx_update_cache_udp) = mpsc::channel();
        let (tx_update_cache_tcp, rx_update_cache_tcp) = mpsc::channel();
        let (tx_update_cache_ns_udp, rx_update_cache_ns_udp) = mpsc::channel();
        let (tx_update_cache_ns_tcp, rx_update_cache_ns_tcp) = mpsc::channel();

        let (tx_update_slist_tcp, rx_update_slist_tcp) = mpsc::channel();

        let mut resolver_query = ResolverQuery::new(
            add_sender_udp,
            delete_sender_udp,
            add_sender_tcp,
            delete_sender_tcp,
            add_sender_ns_udp,
            delete_sender_ns_udp,
            add_sender_ns_tcp,
            delete_sender_ns_tcp,
            tx_update_query,
            tx_delete_query,
            DnsMessage::new(),
            tx_update_cache_udp,
            tx_update_cache_tcp,
            tx_update_cache_ns_udp,
            tx_update_cache_ns_tcp,
            tx_update_slist_tcp,
        );

        assert_eq!(resolver_query.get_old_id(), 0);

        resolver_query.set_old_id(5);

        assert_eq!(resolver_query.get_old_id(), 5);
    }

    #[test]
    fn set_and_get_src_address() {
        /// Channels
        let (add_sender_udp, add_recv_udp) = mpsc::channel();
        let (delete_sender_udp, delete_recv_udp) = mpsc::channel();
        let (add_sender_tcp, add_recv_tcp) = mpsc::channel();
        let (delete_sender_tcp, delete_recv_tcp) = mpsc::channel();
        let (add_sender_ns_udp, add_recv_ns_udp) = mpsc::channel();
        let (delete_sender_ns_udp, delete_recv_ns_udp) = mpsc::channel();
        let (add_sender_ns_tcp, add_recv_ns_tcp) = mpsc::channel();
        let (delete_sender_ns_tcp, delete_recv_ns_tcp) = mpsc::channel();

        let (tx_update_query, rx_update_query) = mpsc::channel();
        let (tx_delete_query, rx_delete_query) = mpsc::channel();

        let (tx_update_cache_udp, rx_update_cache_udp) = mpsc::channel();
        let (tx_update_cache_tcp, rx_update_cache_tcp) = mpsc::channel();
        let (tx_update_cache_ns_udp, rx_update_cache_ns_udp) = mpsc::channel();
        let (tx_update_cache_ns_tcp, rx_update_cache_ns_tcp) = mpsc::channel();

        let (tx_update_slist_tcp, rx_update_slist_tcp) = mpsc::channel();

        let mut resolver_query = ResolverQuery::new(
            add_sender_udp,
            delete_sender_udp,
            add_sender_tcp,
            delete_sender_tcp,
            add_sender_ns_udp,
            delete_sender_ns_udp,
            add_sender_ns_tcp,
            delete_sender_ns_tcp,
            tx_update_query,
            tx_delete_query,
            DnsMessage::new(),
            tx_update_cache_udp,
            tx_update_cache_tcp,
            tx_update_cache_ns_udp,
            tx_update_cache_ns_tcp,
            tx_update_slist_tcp,
        );

        assert_eq!(resolver_query.get_src_address(), "".to_string());

        resolver_query.set_src_address(String::from("test.com"));

        assert_eq!(resolver_query.get_src_address(), "test.com".to_string());
    }
}
