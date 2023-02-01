use crate::dns_cache::DnsCache;
use crate::message::header::Header;
use crate::message::question::Question;
use crate::message::resource_record::ResourceRecord;
use crate::message::DnsMessage;
use crate::name_server::zone::NSZone;
use crate::resolver::resolver_query::ResolverQuery;
use crate::resolver::slist::Slist;

use crate::config::RESOLVER_IP_PORT;

use chrono::Utc;
use std::collections::HashMap;
use std::io::Read;
use std::io::Write;
use std::net::UdpSocket;
use std::fs::OpenOptions;
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::sync::mpsc::Receiver;
use std::sync::mpsc::Sender;
use std::thread;
use std::time::Duration;
use std::vec::Vec;

pub mod resolver_query;
pub mod slist;

pub static SAVE_TRACE: &'static bool = &true;

#[derive(Clone)]
/// Struct that represents a dns resolver
pub struct Resolver {
    /// Ip address and port where the resolver will run
    ip_address: String,
    // Struct that contains a default server list to ask
    sbelt: Slist,
    // Cache for the resolver
    cache: DnsCache,
    // Name server data
    ns_data: HashMap<u16, HashMap<String, NSZone>>,
    // Channel to share cache data between threads
    add_sender_udp: Sender<(String, ResourceRecord, u8, bool, bool, String)>,
    // Channel to share cache data between threads
    delete_sender_udp: Sender<(String, String)>,
    // Channel to share cache data between threads
    add_sender_tcp: Sender<(String, ResourceRecord, u8, bool, bool, String)>,
    // Channel to share cache data between threads
    delete_sender_tcp: Sender<(String, String)>,
    // Channel to share cache data between name server and resolver
    add_sender_ns_udp: Sender<(String, ResourceRecord)>,
    // Channel to delete cache data in name server and resolver
    delete_sender_ns_udp: Sender<(String, String)>,
    // Channel to share cache data between name server and resolver
    add_sender_ns_tcp: Sender<(String, ResourceRecord)>,
    // Channel to delete cache data in name server and resolver
    delete_sender_ns_tcp: Sender<(String, String)>,
    // Channel to update response time in cache data in name server and resolver
    update_cache_sender_udp: Sender<(String, String, u32)>,
    // Channel to update response time in cache data in name server and resolver
    update_cache_sender_tcp: Sender<(String, String, u32)>,
    // Channel to update response time in cache data in name server and resolver
    update_cache_sender_ns_udp: Sender<(String, String, u32)>,
    // Channel to update response time in cache data in name server and resolver
    update_cache_sender_ns_tcp: Sender<(String, String, u32)>,
    // Algorithm to use
    new_algorithm: bool,
}

impl Resolver {
    /// Creates a new Resolver with default values
    pub fn new(
        add_sender_udp: Sender<(String, ResourceRecord, u8, bool, bool, String)>,
        delete_sender_udp: Sender<(String, String)>,
        add_sender_tcp: Sender<(String, ResourceRecord, u8, bool, bool, String)>,
        delete_sender_tcp: Sender<(String, String)>,
        add_sender_ns_udp: Sender<(String, ResourceRecord)>,
        delete_sender_ns_udp: Sender<(String, String)>,
        add_sender_ns_tcp: Sender<(String, ResourceRecord)>,
        delete_sender_ns_tcp: Sender<(String, String)>,
        update_cache_sender_udp: Sender<(String, String, u32)>,
        update_cache_sender_tcp: Sender<(String, String, u32)>,
        update_cache_sender_ns_udp: Sender<(String, String, u32)>,
        update_cache_sender_ns_tcp: Sender<(String, String, u32)>,
        new_algorithm: bool,
    ) -> Self {
        // Creates a new cache
        let cache = DnsCache::new();

        // Creates a Resolver instance
        let resolver = Resolver {
            ip_address: String::from(""),
            sbelt: Slist::new(),
            cache: cache,
            ns_data: HashMap::<u16, HashMap<String, NSZone>>::new(),
            add_sender_udp: add_sender_udp,
            delete_sender_udp: delete_sender_udp,
            add_sender_tcp: add_sender_tcp,
            delete_sender_tcp: delete_sender_tcp,
            add_sender_ns_udp: add_sender_ns_udp,
            delete_sender_ns_udp: delete_sender_ns_udp,
            add_sender_ns_tcp: add_sender_ns_tcp,
            delete_sender_ns_tcp: delete_sender_ns_tcp,
            update_cache_sender_udp: update_cache_sender_udp,
            update_cache_sender_tcp: update_cache_sender_tcp,
            update_cache_sender_ns_udp: update_cache_sender_ns_udp,
            update_cache_sender_ns_tcp: update_cache_sender_ns_tcp,
            new_algorithm: new_algorithm,
        };

        resolver
    }

    //Runs a tcp and udp resolver
    pub fn run_resolver(
        &mut self,
        rx_add_udp: Receiver<(String, ResourceRecord, u8, bool, bool, String)>,
        rx_delete_udp: Receiver<(String, String)>,
        rx_add_tcp: Receiver<(String, ResourceRecord, u8, bool, bool, String)>,
        rx_delete_tcp: Receiver<(String, String)>,
        rx_update_cache_udp: Receiver<(String, String, u32)>,
        rx_update_cache_tcp: Receiver<(String, String, u32)>,
        use_cache_for_answering: bool,
    ) {
        // Copy the resolver instance to use it in udp resolver
        let mut resolver_copy = self.clone();

        // Runs an udp resolver
        thread::spawn(move || {
            resolver_copy.run_resolver_udp(
                rx_add_udp,
                rx_delete_udp,
                rx_update_cache_udp,
                use_cache_for_answering,
            );
        });

        // Runs a tcp resolver
        self.run_resolver_tcp(
            rx_add_tcp,
            rx_delete_tcp,
            rx_update_cache_tcp,
            use_cache_for_answering,
        );
    }

    // Runs a udp resolver
    pub fn run_resolver_udp(
        &mut self,
        rx_add_udp: Receiver<(String, ResourceRecord, u8, bool, bool, String)>,
        rx_delete_udp: Receiver<(String, String)>,
        rx_update_cache_udp: Receiver<(String, String, u32)>,
        use_cache_for_answering: bool,
    ) {
        // Hashmap to save the queries in process
        let mut queries_hash_by_id = HashMap::<u16, ResolverQuery>::new();

        // Channels to send cache data between threads, resolvers and name server
        let tx_add_udp = self.get_add_sender_udp();
        let tx_delete_udp = self.get_delete_sender_udp();
        let tx_add_tcp = self.get_add_sender_tcp();
        let tx_delete_tcp = self.get_delete_sender_tcp();
        let tx_add_ns_udp = self.get_add_sender_ns_udp();
        let tx_delete_ns_udp = self.get_delete_sender_ns_udp();
        let tx_add_ns_tcp = self.get_add_sender_ns_tcp();
        let tx_delete_ns_tcp = self.get_delete_sender_ns_tcp();
        let tx_update_cache_udp = self.get_update_cache_udp();
        let tx_update_cache_tcp = self.get_update_cache_tcp();
        let tx_update_cache_ns_udp = self.get_update_cache_ns_udp();
        let tx_update_cache_ns_tcp = self.get_update_cache_ns_tcp();

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
            .set_read_timeout(Some(Duration::from_millis(50000)))
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

            // Update response time cache
            let mut received_update = rx_update_cache_udp.try_iter();

            let mut next_value = received_update.next();

            let mut cache = self.get_cache();

            while next_value.is_none() == false {
                let (host_name, address, response_time) = next_value.unwrap();
                cache.update_response_time(host_name, "A".to_string(), response_time, address);
                next_value = received_update.next();
            }

            self.set_cache(cache);

            //

            // Adding to Cache

            let mut received_add = rx_add_udp.try_iter();

            let mut next_value = received_add.next();

            let mut cache = self.get_cache();

            while next_value.is_none() == false {
                let (name, rr, data_ranking, nxdomain, no_data, rr_type) = next_value.unwrap();
                //println!("Agregando al cache: {} {} {}", name.clone(), data_ranking.clone(), rr_type.clone());
                cache.add(name, rr, data_ranking, nxdomain, no_data, rr_type);
                next_value = received_add.next();
            }

            //println!("set cache");

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

            //println!("Esperando Mensaje en resolver principal");

            // We receive the msg
            let dns_message_option = Resolver::receive_udp_msg(socket.try_clone().unwrap());

            // Adding to Cache

            let mut received_add = rx_add_udp.try_iter();

            let mut next_value = received_add.next();

            let mut cache = self.get_cache();

            while next_value.is_none() == false {
                let (name, rr, data_ranking, nxdomain, no_data, rr_type) = next_value.unwrap();
                //println!("Agregando al cache: {} {} {}", name.clone(), data_ranking.clone(), rr_type.clone());
                cache.add(name, rr, data_ranking, nxdomain, no_data, rr_type);
                next_value = received_add.next();
            }

            //println!("set cache");

            self.set_cache(cache);
            //

            //println!("Mensaje en resolver principal");

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
            let tx_add_tcp_copy = tx_add_tcp.clone();
            let tx_delete_tcp_copy = tx_delete_tcp.clone();
            let tx_add_ns_udp_copy = tx_add_ns_udp.clone();
            let tx_delete_ns_udp_copy = tx_delete_ns_udp.clone();
            let tx_add_ns_tcp_copy = tx_add_ns_tcp.clone();
            let tx_delete_ns_tcp_copy = tx_delete_ns_tcp.clone();

            let tx_update_query_copy = tx_update_query.clone();
            let tx_delete_query_copy = tx_delete_query.clone();

            let tx_update_cache_udp_copy = tx_update_cache_udp.clone();
            let tx_update_cache_tcp_copy = tx_update_cache_tcp.clone();
            let tx_update_cache_ns_udp_copy = tx_update_cache_ns_udp.clone();
            let tx_update_cache_ns_tcp_copy = tx_update_cache_ns_tcp.clone();

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
                    tx_add_tcp_copy,
                    tx_delete_tcp_copy,
                    tx_add_ns_udp_copy,
                    tx_delete_ns_udp_copy,
                    tx_add_ns_tcp_copy,
                    tx_delete_ns_tcp_copy,
                    tx_update_query_copy,
                    tx_delete_query_copy.clone(),
                    tx_update_cache_udp_copy.clone(),
                    tx_update_cache_tcp_copy.clone(),
                    tx_update_cache_ns_udp_copy.clone(),
                    tx_update_cache_ns_tcp_copy.clone(),
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
                    resolver.get_ns_data(),
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

                        // Calculates the response time
                        let last_query_timestamp = resolver_query.get_last_query_timestamp();
                        let now = Utc::now();
                        let timestamp_ms = now.timestamp_millis() as u64;

                        let response_time: u32 = (timestamp_ms - last_query_timestamp) as u32;

                        // Send request to update resolver and name server cache
                        tx_update_cache_udp_copy
                            .send((
                                resolver_query.get_last_query_hostname(),
                                src_address_copy.clone(),
                                response_time,
                            ))
                            .unwrap_or(());

                        tx_update_cache_tcp_copy
                            .send((
                                resolver_query.get_last_query_hostname(),
                                src_address_copy.clone(),
                                response_time,
                            ))
                            .unwrap_or(());

                        tx_update_cache_ns_udp_copy
                            .send((
                                resolver_query.get_last_query_hostname(),
                                src_address_copy.clone(),
                                response_time,
                            ))
                            .unwrap_or(());

                        tx_update_cache_ns_tcp_copy
                            .send((
                                resolver_query.get_last_query_hostname(),
                                src_address_copy.clone(),
                                response_time,
                            ))
                            .unwrap_or(());
                        //

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
                                    write!(file, "--------------------\n").expect("Couldn't write file");
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

    // Runs a tcp resolver
    pub fn run_resolver_tcp(
        &mut self,
        rx_add_tcp: Receiver<(String, ResourceRecord, u8, bool, bool, String)>,
        rx_delete_tcp: Receiver<(String, String)>,
        rx_update_cache_tcp: Receiver<(String, String, u32)>,
        use_cache_for_answering: bool,
    ) {
        // Channels to send data between threads, resolvers and name server
        let tx_add_udp = self.get_add_sender_udp();
        let tx_delete_udp = self.get_delete_sender_udp();
        let tx_add_tcp = self.get_add_sender_tcp();
        let tx_delete_tcp = self.get_delete_sender_tcp();
        let tx_add_ns_udp = self.get_add_sender_ns_udp();
        let tx_delete_ns_udp = self.get_delete_sender_ns_udp();
        let tx_add_ns_tcp = self.get_add_sender_ns_tcp();
        let tx_delete_ns_tcp = self.get_delete_sender_ns_tcp();
        let tx_update_cache_udp = self.get_update_cache_udp();
        let tx_update_cache_tcp = self.get_update_cache_tcp();
        let tx_update_cache_ns_udp = self.get_update_cache_ns_udp();
        let tx_update_cache_ns_tcp = self.get_update_cache_ns_tcp();

        // Channel to delete queries ids from queries already response
        let (tx_delete_query, _rx_delete_query) = mpsc::channel();

        // Channel to update resolver queries from queries in progress
        let (tx_update_query, _rx_update_query) = mpsc::channel();

        // Gets ip and port str
        let host_address_and_port = self.get_ip_address();

        // Creates a TCP Listener
        let listener = TcpListener::bind(&host_address_and_port).expect("Could not bind");

        // Receives messages
        loop {
            // Accept connection
            match listener.accept() {
                Ok((stream, src_address)) => {
                    // Delete from cache

                    let mut received_delete = rx_delete_tcp.try_iter();

                    let mut next_value = received_delete.next();

                    let mut cache = self.get_cache();

                    while next_value.is_none() == false {
                        let (name, rr_type) = next_value.unwrap();
                        cache.remove(name, rr_type);
                        next_value = received_delete.next();
                    }

                    self.set_cache(cache);

                    //

                    // Update response time cache

                    let mut received_update = rx_update_cache_tcp.try_iter();

                    let mut next_value = received_update.next();

                    let mut cache = self.get_cache();

                    while next_value.is_none() == false {
                        let (host_name, address, response_time) = next_value.unwrap();
                        cache.update_response_time(
                            host_name,
                            "A".to_string(),
                            response_time,
                            address,
                        );
                        next_value = received_update.next();
                    }

                    self.set_cache(cache);

                    //

                    // Adding to Cache

                    let mut received_add = rx_add_tcp.try_iter();

                    let mut next_value = received_add.next();

                    let mut cache = self.get_cache();

                    while next_value.is_none() == false {
                        let (name, rr, data_ranking, nxdomain, no_data, rr_type) =
                            next_value.unwrap();
                        cache.add(name, rr, data_ranking, nxdomain, no_data, rr_type);
                        next_value = received_add.next();
                    }

                    self.set_cache(cache);

                    /////////////////////////////////

                    // We receive the msg
                    let received_msg =
                        Resolver::receive_tcp_msg(stream.try_clone().unwrap()).unwrap();

                    // Create necessary channels
                    let tx_add_udp_copy = tx_add_udp.clone();
                    let tx_delete_udp_copy = tx_delete_udp.clone();
                    let tx_add_tcp_copy = tx_add_tcp.clone();
                    let tx_delete_tcp_copy = tx_delete_tcp.clone();
                    let tx_add_ns_udp_copy = tx_add_ns_udp.clone();
                    let tx_delete_ns_udp_copy = tx_delete_ns_udp.clone();
                    let tx_add_ns_tcp_copy = tx_add_ns_tcp.clone();
                    let tx_delete_ns_tcp_copy = tx_delete_ns_tcp.clone();

                    let tx_update_cache_udp_copy = tx_update_cache_udp.clone();
                    let tx_update_cache_tcp_copy = tx_update_cache_tcp.clone();
                    let tx_update_cache_ns_udp_copy = tx_update_cache_ns_udp.clone();
                    let tx_update_cache_ns_tcp_copy = tx_update_cache_ns_tcp.clone();

                    let tx_update_query_copy = tx_update_query.clone();
                    let tx_delete_query_copy = tx_delete_query.clone();

                    let resolver = self.clone();

                    // Parse the message
                    let dns_message_parse_result = DnsMessage::from_bytes(&received_msg);

                    // Checks the parse
                    match dns_message_parse_result {
                        // We do nothing if it's right
                        Ok(_) => {}
                        // We send a format error in other case
                        Err(_) => {
                            // Creates a format error msg
                            let dns_format_error_msg = DnsMessage::format_error_msg();

                            // Sends the answer
                            Resolver::send_answer_by_tcp(dns_format_error_msg, stream);

                            continue;
                        }
                    }

                    let new_algorithm = self.new_algorithm;
                    
                    //println!("TCP!!!!");

                    // Creates a new thread to process the msg
                    thread::spawn(move || {
                        let dns_message = dns_message_parse_result.unwrap();

                        // We get the msg type, it can be query or answer
                        let msg_type = dns_message.get_header().get_qr();

                        // If the msg is a query
                        if msg_type == false {
                            // Gets the info to create a resolver query
                            let sname = dns_message.get_question().get_qname().get_name();
                            let stype = dns_message.get_question().get_qtype();
                            let sclass = dns_message.get_question().get_qclass();
                            let op_code = dns_message.get_header().get_op_code();
                            let rd = dns_message.get_header().get_rd();
                            let id = dns_message.get_query_id();

                            // Creates a resolver query instance
                            let mut resolver_query = ResolverQuery::new(
                                tx_add_udp_copy,
                                tx_delete_udp_copy,
                                tx_add_tcp_copy,
                                tx_delete_tcp_copy,
                                tx_add_ns_udp_copy,
                                tx_delete_ns_udp_copy,
                                tx_add_ns_tcp_copy,
                                tx_delete_ns_tcp_copy,
                                tx_update_query_copy,
                                tx_delete_query_copy,
                                tx_update_cache_udp_copy,
                                tx_update_cache_tcp_copy,
                                tx_update_cache_ns_udp_copy,
                                tx_update_cache_ns_tcp_copy,
                                new_algorithm,
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
                                resolver.get_ns_data(),
                                src_address.clone().to_string(),
                                id,
                            );

                            // Process the query and gets the answer
                            let mut answer_msg =
                                resolver_query.step_1_tcp(dns_message, use_cache_for_answering);

                            answer_msg.set_query_id(resolver_query.get_old_id());

                            // Sends the answer to the client
                            Resolver::send_answer_by_tcp(answer_msg, stream);
                        }
                    });
                }
                Err(_) => {}
            }
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

        // Get TC bit
        //let tc = (msg[2] as u8 & 0b00000010) >> 1;

        let tc = 0;

        //println!("TC bit: {}", tc.clone());

        let dns_msg_parsed_result;

        if tc == 1 {
            // Parse the question
            let msg_question = Question::from_bytes(&msg[12..], &msg).unwrap().0;

            // Parse header
            let msg_header = Header::from_bytes(&msg[0..12]);

            let query_msg = DnsMessage::new_query_message(
                msg_question.get_qname().get_name(),
                msg_question.get_qtype(),
                msg_question.get_qclass(),
                msg_header.get_op_code(),
                msg_header.get_rd(),
                msg_header.get_id(),
            );

            let stream = TcpStream::connect(RESOLVER_IP_PORT.to_string())
                .expect("Couldn't connect to the server...");

            Resolver::send_answer_by_tcp(query_msg, stream.try_clone().unwrap());

            let bytes_response = Resolver::receive_tcp_msg(stream).unwrap();

            // Parse the msg
            dns_msg_parsed_result = DnsMessage::from_bytes(&bytes_response);
        } else {
            // Parse the msg
            dns_msg_parsed_result = DnsMessage::from_bytes(&msg);
        }

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

    // Receives a TCP message
    pub fn receive_tcp_msg(mut stream: TcpStream) -> Option<Vec<u8>> {
        let mut received_msg = [0; 2];

        // Receive a msg
        let result = stream.read(&mut received_msg);

        let number_of_bytes = match result {
            Ok(val) => val,
            Err(_) => {
                return None;
            }
        };

        // If it was an empty msg
        if number_of_bytes == 0 {
            return None;
        }

        // Gets the msg size and create the buffer
        let mut tcp_msg_len = (received_msg[0] as u16) << 8 | received_msg[1] as u16;
        let mut vec_msg: Vec<u8> = Vec::new();

        tcp_msg_len = tcp_msg_len - number_of_bytes as u16 + 2;

        // Receive all the msg
        while tcp_msg_len > 0 {
            let mut msg = [0; 4096];
            let number_of_bytes_msg = stream.read(&mut msg).expect("No data received");

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

            tcp_msg_len = tcp_msg_len - number_of_bytes_msg as u16;
            vec_msg.append(&mut msg.to_vec());
        }

        return Some(vec_msg);
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

    // Sends the response to the address by tcp
    fn send_answer_by_tcp(response: DnsMessage, mut stream: TcpStream) {
        // Msg to bytes
        let bytes = response.to_bytes();

        // Get the msg length
        let msg_length: u16 = bytes.len() as u16;

        // Set the size of msg in bytes and concats the msg
        let tcp_bytes_length = [(msg_length >> 8) as u8, msg_length as u8];
        let full_msg = [&tcp_bytes_length, bytes.as_slice()].concat();

        // Sends the message
        stream.write(&full_msg).expect("Couldn't send response");
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

    // Gets the ns_data
    pub fn get_ns_data(&self) -> HashMap<u16, HashMap<String, NSZone>> {
        self.ns_data.clone()
    }

    /// Get the owner's query address
    pub fn get_add_sender_udp(&self) -> Sender<(String, ResourceRecord, u8, bool, bool, String)> {
        self.add_sender_udp.clone()
    }

    /// Get the owner's query address
    pub fn get_add_sender_tcp(&self) -> Sender<(String, ResourceRecord, u8, bool, bool, String)> {
        self.add_sender_tcp.clone()
    }

    /// Get the owner's query address
    pub fn get_delete_sender_udp(&self) -> Sender<(String, String)> {
        self.delete_sender_udp.clone()
    }

    /// Get the owner's query address
    pub fn get_delete_sender_tcp(&self) -> Sender<(String, String)> {
        self.delete_sender_tcp.clone()
    }

    /// Get the owner's query address
    pub fn get_add_sender_ns_udp(&self) -> Sender<(String, ResourceRecord)> {
        self.add_sender_ns_udp.clone()
    }

    /// Get the owner's query address
    pub fn get_add_sender_ns_tcp(&self) -> Sender<(String, ResourceRecord)> {
        self.add_sender_ns_tcp.clone()
    }

    /// Get the owner's query address
    pub fn get_delete_sender_ns_udp(&self) -> Sender<(String, String)> {
        self.delete_sender_ns_udp.clone()
    }

    /// Get the owner's query address
    pub fn get_delete_sender_ns_tcp(&self) -> Sender<(String, String)> {
        self.delete_sender_ns_tcp.clone()
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

    // Sets the ns_data attribute with a new value
    pub fn set_ns_data(&mut self, ns_data: HashMap<u16, HashMap<String, NSZone>>) {
        self.ns_data = ns_data;
    }
}

mod test {
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

        let (tx_update_cache_udp, rx_update_cache_udp) = mpsc::channel();
        let (tx_update_cache_tcp, rx_update_cache_tcp) = mpsc::channel();
        let (tx_update_cache_ns_udp, rx_update_cache_ns_udp) = mpsc::channel();
        let (tx_update_cache_ns_tcp, rx_update_cache_ns_tcp) = mpsc::channel();

        let mut resolver = Resolver::new(
            add_sender_udp,
            delete_sender_udp,
            add_sender_tcp,
            delete_sender_tcp,
            add_sender_ns_udp,
            delete_sender_ns_udp,
            add_sender_ns_tcp,
            delete_sender_ns_tcp,
            tx_update_cache_udp,
            tx_update_cache_tcp,
            tx_update_cache_ns_udp,
            tx_update_cache_ns_tcp,
        );

        assert_eq!(resolver.ip_address, "".to_string());
        assert_eq!(resolver.sbelt.get_ns_list().len(), 0);
        assert_eq!(resolver.cache.get_size(), 0);
    }

    #[test]
    fn set_and_get_ip_address() {
        /// Channels
        let (add_sender_udp, add_recv_udp) = mpsc::channel();
        let (delete_sender_udp, delete_recv_udp) = mpsc::channel();
        let (add_sender_tcp, add_recv_tcp) = mpsc::channel();
        let (delete_sender_tcp, delete_recv_tcp) = mpsc::channel();
        let (add_sender_ns_udp, add_recv_ns_udp) = mpsc::channel();
        let (delete_sender_ns_udp, delete_recv_ns_udp) = mpsc::channel();
        let (add_sender_ns_tcp, add_recv_ns_tcp) = mpsc::channel();
        let (delete_sender_ns_tcp, delete_recv_ns_tcp) = mpsc::channel();

        let (tx_update_cache_udp, rx_update_cache_udp) = mpsc::channel();
        let (tx_update_cache_tcp, rx_update_cache_tcp) = mpsc::channel();
        let (tx_update_cache_ns_udp, rx_update_cache_ns_udp) = mpsc::channel();
        let (tx_update_cache_ns_tcp, rx_update_cache_ns_tcp) = mpsc::channel();

        let mut resolver = Resolver::new(
            add_sender_udp,
            delete_sender_udp,
            add_sender_tcp,
            delete_sender_tcp,
            add_sender_ns_udp,
            delete_sender_ns_udp,
            add_sender_ns_tcp,
            delete_sender_ns_tcp,
            tx_update_cache_udp,
            tx_update_cache_tcp,
            tx_update_cache_ns_udp,
            tx_update_cache_ns_tcp,
        );

        assert_eq!(resolver.get_ip_address(), "".to_string());

        resolver.set_ip_address("127.0.0.1".to_string());

        assert_eq!(resolver.get_ip_address(), "127.0.0.1".to_string());
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

        let (tx_update_cache_udp, rx_update_cache_udp) = mpsc::channel();
        let (tx_update_cache_tcp, rx_update_cache_tcp) = mpsc::channel();
        let (tx_update_cache_ns_udp, rx_update_cache_ns_udp) = mpsc::channel();
        let (tx_update_cache_ns_tcp, rx_update_cache_ns_tcp) = mpsc::channel();

        let mut resolver = Resolver::new(
            add_sender_udp,
            delete_sender_udp,
            add_sender_tcp,
            delete_sender_tcp,
            add_sender_ns_udp,
            delete_sender_ns_udp,
            add_sender_ns_tcp,
            delete_sender_ns_tcp,
            tx_update_cache_udp,
            tx_update_cache_tcp,
            tx_update_cache_ns_udp,
            tx_update_cache_ns_tcp,
        );
        let mut sbelt_test = Slist::new();

        sbelt_test.insert("test.com".to_string(), "127.0.0.1".to_string(), 5000);

        resolver.set_sbelt(sbelt_test);

        assert_eq!(resolver.get_sbelt().get_ns_list().len(), 1);
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

        let (tx_update_cache_udp, rx_update_cache_udp) = mpsc::channel();
        let (tx_update_cache_tcp, rx_update_cache_tcp) = mpsc::channel();
        let (tx_update_cache_ns_udp, rx_update_cache_ns_udp) = mpsc::channel();
        let (tx_update_cache_ns_tcp, rx_update_cache_ns_tcp) = mpsc::channel();

        let mut resolver = Resolver::new(
            add_sender_udp,
            delete_sender_udp,
            add_sender_tcp,
            delete_sender_tcp,
            add_sender_ns_udp,
            delete_sender_ns_udp,
            add_sender_ns_tcp,
            delete_sender_ns_tcp,
            tx_update_cache_udp,
            tx_update_cache_tcp,
            tx_update_cache_ns_udp,
            tx_update_cache_ns_tcp,
        );

        let mut cache_test = DnsCache::new();
        let ip_address: [u8; 4] = [127, 0, 0, 0];
        let mut a_rdata = ARdata::new();

        cache_test.set_max_size(1);

        a_rdata.set_address(ip_address);

        let rdata = Rdata::SomeARdata(a_rdata);
        let mut resource_record = ResourceRecord::new(rdata);
        resource_record.set_type_code(1);

        cache_test.add("127.0.0.0".to_string(), resource_record);

        resolver.set_cache(cache_test);

        assert_eq!(resolver.get_cache().get_size(), 1);
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
}
