use crate::dns_cache::DnsCache;
use crate::message::header::Header;
use crate::message::question::Question;
use crate::message::resource_record::ResourceRecord;
use crate::message::DnsMessage;
use crate::resolver::resolver_query::ResolverQuery;
use crate::resolver::slist::Slist;
use crate::config::RESOLVER_IP_PORT;

use chrono::Utc;
use core::num;
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Read;
use std::io::Write;
use std::net::UdpSocket;
use std::sync::mpsc;
use std::sync::mpsc::Receiver;
use std::sync::mpsc::Sender;
use std::thread;
use std::time::Duration;
use std::vec::Vec;

pub mod resolver_query;
pub mod slist;

pub static SAVE_TRACE: &'static bool = &false;

#[derive(Clone)]
/// Struct that represents a dns resolver
pub struct Resolver {
    /// Ip address and port where the resolver will run
    ip_address: String,
    // Struct that contains a default server list to ask
    sbelt: Slist,
    // Cache for the resolver
    cache: DnsCache,
    // Channel to share cache data between threads
    add_sender_udp: Sender<(String, Vec<ResourceRecord>, u8, bool, bool, String)>,
    // Channel to share cache data between threads
    delete_sender_udp: Sender<(String, String)>,
    // Channel to update response time in cache data in name server and resolver
    update_cache_sender_udp: Sender<(String, String, u32)>,
    // Algorithm to use
    new_algorithm: bool,
}

impl Resolver {
    /// Creates a new Resolver with default values
    pub fn new(
        add_sender_udp: Sender<(String, Vec<ResourceRecord>, u8, bool, bool, String)>,
        delete_sender_udp: Sender<(String, String)>,
        update_cache_sender_udp: Sender<(String, String, u32)>,
        new_algorithm: bool,
    ) -> Self {
        // Creates a new cache
        let cache = DnsCache::new();

        // Creates a Resolver instance
        let resolver = Resolver {
            ip_address: String::from(""),
            sbelt: Slist::new(),
            cache: cache,
            add_sender_udp: add_sender_udp,
            delete_sender_udp: delete_sender_udp,
            update_cache_sender_udp: update_cache_sender_udp,
            new_algorithm: new_algorithm,
        };

        resolver
    }

    //Runs a tcp and udp resolver
    pub fn run_resolver(
        &mut self,
        rx_add_udp: Receiver<(String, Vec<ResourceRecord>, u8, bool, bool, String)>,
        rx_delete_udp: Receiver<(String, String)>,
        rx_update_cache_udp: Receiver<(String, String, u32)>,
        use_cache_for_answering: bool,
    ) {
        // Copy the resolver instance to use it in udp resolver
        let mut resolver_copy = self.clone();

        // Runs an udp resolver
        resolver_copy.run_resolver_udp(
            rx_add_udp,
            rx_delete_udp,
            rx_update_cache_udp,
            use_cache_for_answering,
        );
    }

    // Runs a udp resolver
    pub fn run_resolver_udp(
        &mut self,
        rx_add_udp: Receiver<(String, Vec<ResourceRecord>, u8, bool, bool, String)>,
        rx_delete_udp: Receiver<(String, String)>,
        rx_update_cache_udp: Receiver<(String, String, u32)>,
        use_cache_for_answering: bool,
    ) {
        // Hashmap to save the queries in process
        let mut queries_hash_by_id = HashMap::<u16, ResolverQuery>::new();

        // Channels to send cache data between threads, resolvers and name server
        let tx_add_udp = self.get_add_sender_udp();
        let tx_delete_udp = self.get_delete_sender_udp();
        let tx_update_cache_udp = self.get_update_cache_udp();

        // Channel to delete queries ids from queries already response
        let (tx_delete_query, rx_delete_query): (Sender<ResolverQuery>, Receiver<ResolverQuery>) =
            mpsc::channel();

        // Channel to update resolver queries from queries in progress
        let (tx_update_query, rx_update_query): (Sender<ResolverQuery>, Receiver<ResolverQuery>) =
            mpsc::channel();

        // Create ip and port str
        let host_address_and_port = self.get_ip_address();

        // Creates an UDP socket
        let socket = UdpSocket::bind(&host_address_and_port).expect("Failed to bind host socket");
        socket
            .set_read_timeout(Some(Duration::from_millis(1000)))
            .expect("Failed to set timeout");

        // Receives messages
        loop {
            // Updates queries
            let mut queries_to_update = rx_update_query.try_iter();
            let mut next_query_to_update = queries_to_update.next();

            while next_query_to_update.is_none() == false {
                let resolver_query_to_update = next_query_to_update.unwrap();

                let id: u16 = resolver_query_to_update.get_main_query_id();

                queries_hash_by_id.insert(id, resolver_query_to_update);

                next_query_to_update = queries_to_update.next();
            }

            //

            // Delete queries already answered

            let mut queries_to_delete = rx_delete_query.try_iter();

            let mut next_query_value = queries_to_delete.next();

            while next_query_value.is_none() == false {
                let resolver_query_to_delete = next_query_value.unwrap();
                let id: u16 = resolver_query_to_delete.get_main_query_id();

                //println!("Deleting query: {}", id);

                queries_hash_by_id.remove(&id);

                next_query_value = queries_to_delete.next();
            }

            //

            // Delete from cache

            let mut received_delete = rx_delete_udp.try_iter();

            let mut next_value = received_delete.next();

            let mut cache = self.get_cache();

            while next_value.is_none() == false {
                let (name, rr_type) = next_value.unwrap();
                cache.remove(name, rr_type);
                next_value = received_delete.next();
            }

            self.set_cache(cache);

            //

            // Adding to Cache

            let mut received_add = rx_add_udp.try_iter();

            let mut next_value = received_add.next();

            let mut cache = self.get_cache();

            while next_value.is_none() == false {
                let (name, rrs, data_ranking, nxdomain, no_data, rr_type) = next_value.unwrap();

                let (cache_exist, data_ranking_exist) =
                    self.exist_cache_data(name.clone(), rrs[0].clone());

                if cache_exist == false || data_ranking_exist > data_ranking {
                    //println!("Eliminando {}", name.clone());
                    cache.remove(name.clone(), rr_type.clone());
                    for rr in rrs {
                        cache.add(
                            name.clone(),
                            rr,
                            data_ranking,
                            nxdomain.clone(),
                            no_data.clone(),
                            rr_type.clone(),
                        );
                    }
                }
                next_value = received_add.next();
            }

            self.set_cache(cache);
            //

            // Check queries for timeout

            for (_, val) in queries_hash_by_id.clone() {
                let mut query = val.clone();

                let timeout = query.get_timeout();
                let last_query_timestamp = query.get_last_query_timestamp();
                let now = Utc::now();
                let timestamp_ms = now.timestamp_millis() as u64;

                if timestamp_ms > (timeout as u64 + last_query_timestamp) {
                    // Copy sockets
                    let timeout_socket = socket.try_clone().unwrap();

                    // Update cache
                    query.set_cache(self.cache.clone());

                    // Set query timestamp
                    let now = Utc::now();
                    let timestamp_query = now.timestamp_millis();

                    query.set_last_query_timestamp(timestamp_query as u64);

                    // Delete last host
                    let last_query_hostname = query.get_last_query_hostname();
                    let mut slist = query.get_slist();

                    slist.delete(last_query_hostname);
                    query.set_slist(slist);

                    // Temporary error
                    if query.get_queries_before_temporary_error() <= 0 {
                        continue;
                    } else {
                        query.set_queries_before_temporary_error(
                            query.get_queries_before_temporary_error() - 1,
                        );
                    }

                    // Update query info
                    queries_hash_by_id.insert(query.get_main_query_id(), query.clone());

                    // Send query to another name server in slist
                    thread::spawn(move || {
                        query.step_3_udp(timeout_socket);
                    });
                }
            }

            // We receive the msg
            let dns_message_option = Resolver::receive_udp_msg(socket.try_clone().unwrap());

            // Creates an empty msg and address
            let (dns_message, src_address);

            // Check if it is all the message
            match dns_message_option {
                Some(val) => {
                    dns_message = val.0;
                    src_address = val.1;
                }
                None => {
                    continue;
                }
            }

            // Format Error
            if dns_message.get_header().get_rcode() == 1 {
                let answer_id = dns_message.get_query_id();
                queries_hash_by_id.remove(&answer_id);

                continue;
            }

            // We get the msg type, it can be query or answer
            let msg_type = dns_message.get_header().get_qr();

            // We create all necessary to create a resolver query instance

            let resolver = self.clone();

            let tx_add_udp_copy = tx_add_udp.clone();
            let tx_delete_udp_copy = tx_delete_udp.clone();

            let tx_update_query_copy = tx_update_query.clone();
            let tx_delete_query_copy = tx_delete_query.clone();

            let tx_update_cache_udp_copy = tx_update_cache_udp.clone();

            let src_address_copy = src_address.clone();

            // If the message is a query
            if msg_type == false {
                // Gets hte information to initialize a resolver query instance
                let sname = dns_message.get_question().get_qname().get_name();
                let stype = dns_message.get_question().get_qtype();
                let sclass = dns_message.get_question().get_qclass();
                let op_code = dns_message.get_header().get_op_code();
                let rd = dns_message.get_header().get_rd();
                let id = dns_message.get_query_id();

                // Creates the resolver query instance
                let mut resolver_query = ResolverQuery::new(
                    tx_add_udp_copy,
                    tx_delete_udp_copy,
                    tx_update_query_copy,
                    tx_delete_query_copy.clone(),
                    tx_update_cache_udp_copy.clone(),
                    self.new_algorithm,
                );

                // Initializes the query data struct
                resolver_query.initialize(
                    sname,
                    stype,
                    sclass,
                    op_code,
                    rd,
                    resolver.get_sbelt(),
                    resolver.get_cache(),
                    src_address.clone().to_string(),
                    id,
                );

                // Save the query info
                queries_hash_by_id
                    .insert(resolver_query.get_main_query_id(), resolver_query.clone());

                // Get copies from some data
                let socket_copy = socket.try_clone().unwrap();
                let dns_msg_copy = dns_message.clone();
                let tx_query_delete_clone = tx_delete_query_copy.clone();

                // Creates the thread to process the query
                thread::spawn(move || {
                    // Get local answer if it exists, or send the query to name server in other case
                    let answer_local = resolver_query
                        .step_1_udp(socket_copy.try_clone().unwrap(), use_cache_for_answering);

                    // Checks if there was a local answer
                    match answer_local {
                        // If there was a local answer, we send the response to the client
                        Some(val) => {
                            let mut query_msg = dns_msg_copy.clone();
                            let cache_info = val.0;
                            let nxdomain = val.1;
                            let no_data = val.2;

                            if cache_info.len() > 0 && nxdomain == false {
                                // Sets the msg's info
                                query_msg.set_answer(cache_info.clone());
                                query_msg.set_authority(Vec::new());
                                query_msg.set_additional(Vec::new());

                                let mut header = query_msg.get_header();
                                header.set_ancount(cache_info.len() as u16);
                                header.set_nscount(0);
                                header.set_arcount(0);
                                header.set_id(resolver_query.get_old_id());
                                header.set_qr(true);

                                query_msg.set_header(header);
                            } else if nxdomain == true {
                                // Sets the msg's info
                                query_msg.set_answer(Vec::new());
                                query_msg.set_authority(cache_info.clone());
                                query_msg.set_additional(Vec::new());

                                let mut header = query_msg.get_header();
                                header.set_ancount(0);
                                header.set_nscount(cache_info.len() as u16);
                                header.set_arcount(0);
                                header.set_id(resolver_query.get_old_id());
                                header.set_qr(true);
                                header.set_rcode(3);

                                query_msg.set_header(header);
                            } else if no_data == true {
                                // Sets the msg's info
                                query_msg.set_answer(Vec::new());
                                query_msg.set_authority(Vec::new());
                                query_msg.set_additional(Vec::new());

                                let mut header = query_msg.get_header();
                                header.set_ancount(0);
                                header.set_nscount(0);
                                header.set_arcount(0);
                                header.set_id(resolver_query.get_old_id());
                                header.set_qr(true);

                                query_msg.set_header(header);
                            }

                            tx_query_delete_clone
                                .send(resolver_query.clone())
                                .unwrap_or(());

                            Resolver::send_answer_by_udp(
                                query_msg,
                                src_address.clone().to_string(),
                                &socket_copy,
                            );
                        }
                        // We do nothing
                        None => {}
                    }
                });
            }

            // If the message is a response
            if msg_type == true {
                let socket_copy = socket.try_clone().unwrap();
                let answer_id = dns_message.get_query_id();
                let queries_hash_by_id_copy = queries_hash_by_id.clone();

                // Checks the id from the message
                if queries_hash_by_id_copy.contains_key(&answer_id) {
                    // Create necessary channels
                    let tx_query_delete_clone = tx_delete_query.clone();

                    // Creates thread to procces the response
                    thread::spawn(move || {
                        let resolver_query =
                            queries_hash_by_id_copy.get(&answer_id).unwrap().clone();

                        // Process message
                        match resolver_query
                            .clone()
                            .step_4_udp(dns_message, socket_copy.try_clone().unwrap())
                        {
                            // Checks the answer
                            Some(val) => {
                                // Gets the info to creates a response msg
                                let mut msg = val.clone();
                                let mut header = msg.get_header();
                                let old_id = resolver_query.get_old_id();
                                let answer = msg.get_answer();
                                let authority = msg.get_authority();
                                let additional = msg.get_additional();

                                // Sets the response msg
                                header.set_id(old_id);
                                header.set_ancount(answer.len() as u16);
                                header.set_nscount(authority.len() as u16);
                                header.set_arcount(additional.len() as u16);
                                msg.set_header(header);

                                // Deletes the query from query_id list
                                tx_query_delete_clone
                                    .send(resolver_query.clone())
                                    .unwrap_or(());

                                if *SAVE_TRACE && answer[0].get_type_code() == 1 {
                                    // Open the file to append
                                    let mut file = OpenOptions::new()
                                        .write(true)
                                        .append(true)
                                        .open("resolver_traces.txt")
                                        .unwrap();

                                    // Write info
                                    write!(file, "--------------------\n")
                                        .expect("Couldn't write file");
                                }

                                // Sends the response to the client
                                Resolver::send_answer_by_udp(
                                    msg,
                                    resolver_query.get_src_address(),
                                    &socket_copy,
                                );
                            }
                            // We do nothing
                            None => {}
                        };
                    });
                }
            }
        }
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
}

// Utils
impl Resolver {
    // Receives and UDP message
    pub fn receive_udp_msg(socket: UdpSocket) -> Option<(DnsMessage, String)> {
        // 4096 bytes buffer
        let mut msg = [0; 4096];

        // receives a msg
        let (number_of_bytes_msg, address) = match socket.recv_from(&mut msg) {
            Ok((bytes, addr)) => (bytes, addr.to_string()),
            Err(_) => (0, "".to_string()),
        };

        let mut kill_resolver = true;

        // Check kill resolver msg
        for i in 0..30 {
            if msg[i] != 1 {
                kill_resolver = false;
                break;
            }
        }

        if kill_resolver {
            panic!("Killing resolver");
        }

        // If there is a empty msg
        if number_of_bytes_msg == 0 {
            return None;
        }

        let dns_msg_parsed_result;

        // Parse the msg
        dns_msg_parsed_result = DnsMessage::from_bytes(&msg);

        // Returns a format error msg if the parse is not right
        match dns_msg_parsed_result {
            Ok(_) => {}
            Err(_) => {
                return Some((DnsMessage::format_error_msg(), address));
            }
        }

        // Gets the parsed msg and the query id
        let dns_msg_parsed = dns_msg_parsed_result.unwrap();

        return Some((dns_msg_parsed, address));
    }

    // Sends the response to the address by udp
    fn send_answer_by_udp(response: DnsMessage, src_address: String, socket: &UdpSocket) {
        // Msg to bytes
        let bytes = response.to_bytes();

        // Send the message
        if bytes.len() <= 4096 {
            socket
                .send_to(&bytes, src_address)
                .expect("failed to send message");
        }
        // Send the message in parts
        else {
            // Sets TC bit
            let mut header = response.get_header();
            header.set_tc(true);

            let mut response_copy = response.clone();
            response_copy.set_header(header);

            // Msg to bytes
            let response_bytes = response_copy.to_bytes();

            socket
                .send_to(&response_bytes[0..4096], src_address)
                .expect("failed to send message");
        }
    }
}

// Getters
impl Resolver {
    // Gets the ip address
    pub fn get_ip_address(&self) -> String {
        self.ip_address.clone()
    }

    // Gets the list of default servers to ask
    pub fn get_sbelt(&self) -> Slist {
        self.sbelt.clone()
    }

    // Gets the cache
    pub fn get_cache(&self) -> DnsCache {
        self.cache.clone()
    }

    /// Get the owner's query address
    pub fn get_add_sender_udp(
        &self,
    ) -> Sender<(String, Vec<ResourceRecord>, u8, bool, bool, String)> {
        self.add_sender_udp.clone()
    }

    /// Get the owner's query address
    pub fn get_delete_sender_udp(&self) -> Sender<(String, String)> {
        self.delete_sender_udp.clone()
    }

    /// Gets the sender for updating cache
    pub fn get_update_cache_udp(&self) -> Sender<(String, String, u32)> {
        self.update_cache_sender_udp.clone()
    }
}

//Setters
impl Resolver {
    // Sets the ip address attribute with a value
    pub fn set_ip_address(&mut self, ip_address: String) {
        self.ip_address = ip_address;
    }

    // Sets the sbelt attribute with a value
    pub fn set_sbelt(&mut self, sbelt: Slist) {
        self.sbelt = sbelt;
    }

    // Sets the cache attribute with a value
    pub fn set_cache(&mut self, cache: DnsCache) {
        self.cache = cache;
    }
}
