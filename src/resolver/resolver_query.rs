use crate::dns_cache::DnsCache;
use crate::message::rdata::a_rdata::ARdata;
use crate::message::rdata::txt_rdata::TxtRdata;
use crate::message::rdata::Rdata;
use crate::message::resource_record::ResourceRecord;
use crate::message::DnsMessage;
use crate::resolver::slist::Slist;
use crate::resolver::Resolver;
use crate::rr_cache::RRCache;

use crate::config::QUERIES_FOR_CLIENT_REQUEST;
use crate::config::RESOLVER_IP_PORT;
use crate::config::USE_CACHE;

use chrono::Utc;
use rand::seq::SliceRandom;
use rand::{thread_rng, Rng};
use std::cmp;
use std::collections::HashMap;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::BufRead;
use std::io::BufReader;
use std::io::Write;
use std::net::TcpStream;
use std::net::UdpSocket;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::mpsc::Sender;
use std::thread;
use std::time::Duration;
use std::vec::Vec;

// IP Config in order to ask ns and slist queries
pub static IP_FOR_SLIST_NS_QUERIES: &'static str = "192.168.1.90";

pub static SAVE_TRACE: &'static bool = &true;

pub static SORT_NS_SLIST: &'static bool = &false;

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
    main_query_id: u16,
    old_id: u16,
    src_address: String,
    // Channel to share cache data between threads
    add_channel_udp: Sender<(String, Vec<ResourceRecord>, u8, bool, bool, String)>,
    // Channel to share cache data between threads
    delete_channel_udp: Sender<(String, String)>,
    // Channel to update response time in cache data in name server and resolver
    update_cache_sender_udp: Sender<(String, String, u32)>,
    // Number of queries that the resolver do before send temporary error
    queries_before_temporary_error: u16,
    // Sender to update ResolverQuery struct in the resolver
    tx_update_query: Sender<ResolverQuery>,
    // Sender to delete ResolverQuery struct in the resolver
    tx_delete_query: Sender<ResolverQuery>,
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
        add_channel_udp: Sender<(String, Vec<ResourceRecord>, u8, bool, bool, String)>,
        delete_channel_udp: Sender<(String, String)>,
        tx_update_query: Sender<ResolverQuery>,
        tx_delete_query: Sender<ResolverQuery>,
        update_cache_sender_udp: Sender<(String, String, u32)>,
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
            main_query_id: rng.gen(),
            old_id: 0,
            src_address: "".to_string(),
            add_channel_udp: add_channel_udp,
            delete_channel_udp: delete_channel_udp,
            queries_before_temporary_error: queries_before_temporary_error,
            tx_update_query: tx_update_query,
            tx_delete_query: tx_delete_query,
            index_to_choose: 0,
            last_query_timestamp: now.timestamp() as u64 * 1000,
            timeout: 2000,
            last_query_hostname: "".to_string(),
            update_cache_sender_udp: update_cache_sender_udp,
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
        self.set_src_address(src_address);
        self.set_old_id(old_id);
    }

    // Initialize the slist for UDP
    pub fn initialize_slist_udp(&mut self, mut sbelt: Slist, start_look_up_host_name: String) {
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
            let mut ns_parent_host_name = cache.get(parent_host_name.to_string(), ns_type.clone());

            if *SORT_NS_SLIST {
                // Sort ns by name
                ns_parent_host_name.sort_by(|a, b| b.get_domain_name().cmp(&a.get_domain_name()));
            }

            // NXDOMAIN or NODATA
            if ns_parent_host_name.len() > 0 {
                let first_ns_cache = ns_parent_host_name[0].clone();

                if first_ns_cache.get_nxdomain() == true || first_ns_cache.get_no_data() == true {
                    println!("NODATA o NXDOMAIN en slist en {}", parent_host_name.clone());

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
                        Rdata::SomeTxtRdata(val2) => {
                            println!("No data en ip slist");
                            ARdata::new()
                        }
                        _ => unreachable!(),
                    };

                    // Gets the ip address
                    let ip_address = ns_ip_address_rdata.get_string_address();

                    // Inserts ip address in slist
                    new_slist.insert(
                        ns_parent_host_name_string.clone(),
                        ip_address.to_string(),
                        2000 as u32,
                    );

                    ip_found = ip_found + 1;
                }

                // Case to fix AAAA not implemented
                for _ip in ns_ip_address_txt.clone() {
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

            //println!("IP found: {}", ip_found);

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
            if *SORT_NS_SLIST == false {
                let mut ns_list = sbelt.get_ns_list();
                ns_list.shuffle(&mut thread_rng());

                sbelt.set_ns_list(ns_list);
            }

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
            let mut ns_parent_host_name = cache.get(parent_host_name.to_string(), ns_type.clone());

            if ns_parent_host_name.len() == 0 {
                labels.remove(0);
                continue;
            }

            if *SORT_NS_SLIST {
                // Sort ns by name
                ns_parent_host_name.sort_by(|a, b| b.get_domain_name().cmp(&a.get_domain_name()));
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

                    // Inserts ip address in slist
                    new_slist.insert(
                        ns_parent_host_name_string.clone(),
                        ip_address.to_string(),
                        2000 as u32,
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

        // If there is no RR's in zone
        let mut rr_vec = Vec::<ResourceRecord>::new();

        let mut nxdomain = false;
        let mut no_data = false;

        // We look for RR's in cache
        if USE_CACHE == true {
            // Gets the cache
            let mut cache = self.get_cache();

            let mut rrs_cache_answer = Vec::new();

            let cache_answer;

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

            //println!("Step 4a for {}", qname.clone());

            // Check if qname contains *, if its true dont cache the data
            if qname.contains("*") == false {
                // If the answers are autorative, we cache them
                if aa == true {
                    for an in answer.iter_mut() {
                        if an.get_ttl() > 0 {
                            an.set_ttl(an.get_ttl() + self.get_timestamp());
                        }
                    }

                    // Add new Cache
                    self.add_to_cache(
                        answer[0].get_name().get_name(),
                        answer.clone(),
                        3,
                        false,
                        false,
                        answer[0].get_string_type(),
                    );

                    let mut last_domain_saved = "".to_string();
                    let mut ad_to_cache: Vec<ResourceRecord> = Vec::new();

                    for ad in additional.iter_mut() {
                        if ad.get_ttl() > 0 {
                            ad.set_ttl(ad.get_ttl() + self.get_timestamp());

                            // Cache
                            if last_domain_saved != ad.get_name().get_name()
                                && ad_to_cache.len() > 0
                            {
                                self.add_to_cache(
                                    ad_to_cache[0].get_name().get_name(),
                                    ad_to_cache.clone(),
                                    6,
                                    false,
                                    false,
                                    ad_to_cache[0].get_string_type(),
                                );
                                ad_to_cache = Vec::new();
                            }

                            if ad.get_string_type() == "A".to_string() {
                                ad_to_cache.push(ad.clone());
                                last_domain_saved = ad.get_name().get_name();
                            }
                        }
                    }

                    if ad_to_cache.len() > 0 {
                        // Adds last chunk
                        self.add_to_cache(
                            ad_to_cache[0].get_name().get_name(),
                            ad_to_cache.clone(),
                            6,
                            false,
                            false,
                            ad_to_cache[0].get_string_type(),
                        );
                    }
                } else {
                    for an in answer.iter_mut() {
                        if an.get_ttl() > 0 && an.get_type_code() == self.get_stype() {
                            an.set_ttl(an.get_ttl() + self.get_timestamp());
                        }
                    }

                    // Cache
                    self.add_to_cache(
                        answer[0].get_name().get_name(),
                        answer.clone(),
                        6,
                        false,
                        false,
                        answer[0].get_string_type(),
                    );

                    let mut last_domain_saved = "".to_string();
                    let mut ad_to_cache: Vec<ResourceRecord> = Vec::new();

                    for ad in additional.iter_mut() {
                        if ad.get_ttl() > 0 {
                            ad.set_ttl(ad.get_ttl() + self.get_timestamp());

                            // Cache
                            if last_domain_saved != ad.get_name().get_name()
                                && ad_to_cache.len() > 0
                            {
                                self.add_to_cache(
                                    ad_to_cache[0].get_name().get_name(),
                                    ad_to_cache.clone(),
                                    6,
                                    false,
                                    false,
                                    ad_to_cache[0].get_string_type(),
                                );
                                ad_to_cache = Vec::new();
                            }

                            ad_to_cache.push(ad.clone());
                            last_domain_saved = ad.get_name().get_name();
                        }
                    }
                }
            }
        } else {
            let authority = msg.get_authority();

            if authority.len() > 0 {
                let mut first_authority = authority[0].clone();

                if first_authority.get_type_code() == 6 {
                    println!("NXDOMAIN!!!!");
                    first_authority.set_ttl(first_authority.get_ttl() + self.get_timestamp());

                    self.add_to_cache(
                        msg.get_question().get_qname().get_name(),
                        [first_authority.clone()].to_vec(),
                        3,
                        true,
                        false,
                        "NS".to_string(),
                    );

                    self.add_to_cache(
                        msg.get_question().get_qname().get_name(),
                        [first_authority.clone()].to_vec(),
                        3,
                        true,
                        false,
                        "A".to_string(),
                    );

                    self.add_to_cache(
                        msg.get_question().get_qname().get_name(),
                        [first_authority.clone()].to_vec(),
                        3,
                        true,
                        false,
                        "AAAA".to_string(),
                    );

                    self.add_to_cache(
                        msg.get_question().get_qname().get_name(),
                        [first_authority].to_vec(),
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
        if cache_info.len() > 0 || no_data == true {
            return Some((cache_info, nxdomain, no_data));
        }
        // In other case, we send a query to name servers
        else {
            self.step_2_udp();
            self.step_3_udp(socket);
            return None;
        }
    }

    // Step 2 RFC 1034 UDP
    pub fn step_2_udp(&mut self) {
        // Initializes slist
        let sbelt = self.get_sbelt();
        let sname = self.get_sname();
        self.initialize_slist_udp(sbelt, sname);

        self.set_index_to_choose(0);

        // Updates the query
        self.get_tx_update_query().send(self.clone()).unwrap_or(());
    }

    // Step 3 from RFC 1034 UDP version
    pub fn step_3_udp(&mut self, socket: UdpSocket) {
        let queries_left = self.get_queries_before_temporary_error();

        //println!("Queries left: {}", queries_left);

        // Temporary Error
        if queries_left <= 0 {
            self.get_tx_delete_query().send(self.clone()).unwrap_or(());
            return;
        }

        // Gets slist
        let mut slist = self.get_slist();
        let slist_len = slist.len();

        if slist_len <= 0 {
            self.get_tx_delete_query().send(self.clone()).unwrap_or(());
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
                let new_slist = self.send_internal_queries_for_slist_udp(self.get_slist());
                self.set_slist(new_slist.clone());
                //println!("Llega respuesta internal slist");

                if new_slist.len() <= 0 {
                    self.get_tx_delete_query().send(self.clone()).unwrap_or(());
                    return;
                }

                if new_slist.len() < 2 {
                    index_to_choose = slist.len() as u16 - 1;
                } else {
                    index_to_choose = slist.len() as u16 - 2;
                }
            }

            // We choose the next record in slist
            slist = self.get_slist();
            self.set_index_to_choose((index_to_choose + 1) % slist.len() as u16);
            index_to_choose = self.get_index_to_choose();

            //println!("index to choose: {}, slist_len: {}", index_to_choose, slist.len());

            best_server_to_ask = slist.get(index_to_choose);
            best_server_ip = best_server_to_ask
                .get(&"ip_address".to_string())
                .unwrap()
                .clone();

            counter = counter + 1;
        }

        // Set query timeout

        self.set_timeout(2000);

        //

        if best_server_ip.contains(":") == false {
            // Sets 53 port
            best_server_ip.push_str(":53");
        }

        // Update the index to choose
        self.set_index_to_choose((index_to_choose + 1) % slist.len() as u16);
        //

        // Creates query msg
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
        self.set_last_query_hostname(host_name.clone());
        //

        // Send the resolver query to the resolver for update
        self.get_tx_update_query().send(self.clone()).unwrap_or(());
        //

        if *SAVE_TRACE {
            let ip_to_ask = best_server_ip.clone();
            let ns_name = host_name.clone();
            let stype = self.get_stype();
            let sname = self.get_sname();

            // Open the file to append
            let mut file = OpenOptions::new()
                .write(true)
                .append(true)
                .open("resolver_traces.txt")
                .unwrap();

            // Write info
            write!(
                file,
                "{} {} {} {}\n",
                ns_name,
                ip_to_ask,
                sname.clone(),
                stype.clone()
            )
            .expect("Couldn't write file");
        }

        println!("Ip a preguntar: {}", best_server_ip.clone());

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
            println!("NODATA Answer: {}", aa.clone());
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

            self.add_to_cache(
                question_name,
                [empty_rr].to_vec(),
                3,
                false,
                true,
                question_type,
            );

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

        let mut ip_ns_names = Vec::new();

        for ns in authority.iter_mut() {
            if self.compare_match_count(ns.get_name().get_name()) {
                ns.set_ttl(ns.get_ttl() + self.get_timestamp());

                // Get the NS domain name
                let ns_domain_name = match ns.get_rdata() {
                    Rdata::SomeNsRdata(val) => val.get_nsdname().get_name(),
                    _ => unreachable!(),
                };
                //

                ip_ns_names.push(ns_domain_name);
            }
        }

        // Add new cache
        self.add_to_cache(
            authority[0].get_name().get_name(),
            authority.clone(),
            4,
            false,
            false,
            authority[0].get_string_type(),
        );
        //

        // Adds and remove ip addresses
        for name in ip_ns_names {
            let mut chunk_cache = Vec::new();

            for ip in additional.iter_mut() {
                if name == ip.get_name().get_name() && ip.get_string_type() == "A".to_string() {
                    // We check if cache exist for the ip
                    ip.set_ttl(ip.get_ttl() + self.get_timestamp());
                    chunk_cache.push(ip.clone());
                }
            }

            if chunk_cache.len() > 0 {
                // Cache
                self.add_to_cache(
                    name.clone(),
                    chunk_cache.clone(),
                    5,
                    false,
                    false,
                    chunk_cache[0].get_string_type(),
                );
                //
            }
        }

        // Continue the delegation
        self.step_2_udp();
        self.step_3_udp(socket.try_clone().unwrap());

        // We check if cache exist for the ns
        let (_, data_ranking) = self.exist_cache_data(
            msg.get_question().get_qname().get_name(),
            authority[0].clone(),
        );

        if self.new_algorithm == true && data_ranking > 3 {
            self.send_internal_queries_for_child_ns_udp(qname);
        }
    }

    // Step 4c from RFC 1034 UDP version
    pub fn step_4c_udp(&mut self, msg: DnsMessage, socket: UdpSocket) -> Option<DnsMessage> {
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

        self.add_to_cache(
            resource_record.get_name().get_name(),
            [resource_record.clone()].to_vec(),
            3,
            false,
            false,
            resource_record.get_string_type(),
        );

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
                    self.initialize_slist_udp(self.get_sbelt(), parent_host_name.to_string());
                    self.set_index_to_choose(0);
                }
                // If there is no parent
                None => {
                    // Initialize from root
                    self.initialize_slist_udp(self.get_sbelt(), ".".to_string());
                    self.set_index_to_choose(0);
                }
            }
        } else {
            // Selects next from slist
            self.set_index_to_choose(self.get_index_to_choose() % slist.len() as u16);
            self.set_slist(slist);
        }

        // Update the query data in resolver
        self.get_tx_update_query().send(self.clone()).unwrap_or(());
        //

        self.step_3_udp(socket);
        return None;
    }

    // Sends internal querie to obtain NS child records
    fn send_internal_queries_for_child_ns_udp(&self, qname: String) {
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

            slist_socket
                .send_to(&msg_to_bytes, RESOLVER_IP_PORT)
                .expect("Couldn't send child NS query");

        });
    }

    // Sends internal queries to obtain ip address for slist
    fn send_internal_queries_for_slist_udp(&self, mut slist: Slist) -> Slist {
        // Gets NS from slist
        let ns_list = slist.get_ns_list();

        for ns in &ns_list {
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
                slist_socket
                    .set_read_timeout(Some(Duration::from_millis(5000)))
                    .expect("Couldn't set read timeout");

                // Create query id
                let query_id: u16 = rng.gen();

                // Create msg
                let query_msg =
                    DnsMessage::new_query_message(qname.clone(), 1, 1, 0, false, query_id);

                let msg_to_bytes = query_msg.to_bytes();

                slist_socket
                    .send_to(&msg_to_bytes, RESOLVER_IP_PORT)
                    .expect("Couldn't send child NS query");

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

                    slist.insert(qname.clone(), ip_string.to_string().clone(), 5000 as u32);

                    return slist;
                }
                if msg_response.get_header().get_rcode() != 0 {
                    slist.delete(qname.clone());
                    continue;
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
        resource_record: Vec<ResourceRecord>,
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

        let (cache_exist, data_ranking_exist) =
            self.exist_cache_data(domain_name.clone(), resource_record[0].clone());

        if cache_exist == false || data_ranking_exist > data_ranking {
            cache.remove(domain_name.clone(), rr_type.clone());
            for rr in resource_record {
                cache.add(
                    domain_name.clone(),
                    rr,
                    data_ranking,
                    nxdomain,
                    no_data,
                    rr_type.clone(),
                );
            }
        }

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
            .unwrap_or(());

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

    // Initializes an udp socket
    pub fn initilize_socket_udp(ip_addr: String) -> Option<UdpSocket> {
        // Create randon generator
        let ip = ip_addr;
        let mut rng = thread_rng();
        let mut port = rng.gen_range(50000..65000);

        let port_ok = false;

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
    pub fn get_add_channel_udp(
        &self,
    ) -> Sender<(String, Vec<ResourceRecord>, u8, bool, bool, String)> {
        self.add_channel_udp.clone()
    }

    /// Get the owner's query address
    pub fn get_delete_channel_udp(&self) -> Sender<(String, String)> {
        self.delete_channel_udp.clone()
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
