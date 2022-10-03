use crate::config::RECURSIVE_AVAILABLE;
use crate::dns_cache::DnsCache;
use crate::message::rdata::Rdata;
use crate::message::resource_record::ResourceRecord;
use crate::message::DnsMessage;
use crate::name_server::zone::NSZone;
use crate::resolver::Resolver;

use chrono::Utc;
use rand::{thread_rng, Rng};
use std::cmp;
use std::collections::HashMap;
use std::io::Write;
use std::net::UdpSocket;
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::sync::mpsc::Receiver;
use std::sync::mpsc::Sender;
use std::thread;

pub mod master_file;
pub mod zone;

#[derive(Clone)]
/// Structs that represents a name server
pub struct NameServer {
    // Name server zones
    zones: HashMap<u16, HashMap<String, NSZone>>,
    // Name server cache
    cache: DnsCache,
    // Ids from queries
    queries_id: HashMap<u16, Vec<(u16, String)>>,
    // Channel to share cache data between threads
    delete_sender_udp: Sender<(String, String)>,
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
}

impl NameServer {
    /// Creates a new name server
    pub fn new(
        delete_channel_udp: Sender<(String, String)>,
        delete_channel_tcp: Sender<(String, String)>,
        add_channel_ns_udp: Sender<(String, ResourceRecord)>,
        delete_channel_ns_udp: Sender<(String, String)>,
        add_channel_ns_tcp: Sender<(String, ResourceRecord)>,
        delete_channel_ns_tcp: Sender<(String, String)>,
    ) -> Self {
        let name_server = NameServer {
            zones: HashMap::<u16, HashMap<String, NSZone>>::new(),
            cache: DnsCache::new(),
            queries_id: HashMap::<u16, Vec<(u16, String)>>::new(),
            delete_sender_udp: delete_channel_udp,
            delete_sender_tcp: delete_channel_tcp,
            add_sender_ns_udp: add_channel_ns_udp,
            delete_sender_ns_udp: delete_channel_ns_udp,
            add_sender_ns_tcp: add_channel_ns_tcp,
            delete_sender_ns_tcp: delete_channel_ns_tcp,
        };

        name_server
    }

    pub fn run_name_server(
        &mut self,
        name_server_ip_address: String,
        local_resolver_ip_and_port: String,
        rx_add_ns_udp: Receiver<(String, ResourceRecord)>,
        rx_delete_ns_udp: Receiver<(String, String)>,
        rx_add_ns_tcp: Receiver<(String, ResourceRecord)>,
        rx_delete_ns_tcp: Receiver<(String, String)>,
        rx_update_cache_ns_udp: Receiver<(String, String, u32)>,
        rx_update_cache_ns_tcp: Receiver<(String, String, u32)>,
    ) {
        // Copies the info to run udp and tcp nameservers
        let mut name_server_copy = self.clone();
        let name_server_ip_address_copy = name_server_ip_address.clone();
        let local_resolver_ip_and_port_copy = local_resolver_ip_and_port.clone();

        // Runs udp name server
        thread::spawn(move || {
            name_server_copy.run_name_server_udp(
                name_server_ip_address_copy,
                local_resolver_ip_and_port_copy,
                rx_add_ns_udp,
                rx_delete_ns_udp,
                rx_update_cache_ns_udp,
            );
        });

        // Runs tcp name server
        self.run_name_server_tcp(
            name_server_ip_address,
            local_resolver_ip_and_port,
            rx_add_ns_tcp,
            rx_delete_ns_tcp,
            rx_update_cache_ns_tcp,
        );
    }

    // Runs an udp name server
    pub fn run_name_server_udp(
        &mut self,
        name_server_ip_address: String,
        local_resolver_ip_and_port: String,
        rx_add_ns_udp: Receiver<(String, ResourceRecord)>,
        rx_delete_ns_udp: Receiver<(String, String)>,
        rx_update_cache_ns_udp: Receiver<(String, String, u32)>,
    ) {
        // Chanel to share the ids queries
        let (tx, rx) = mpsc::channel();

        // Channels to send data between threads, resolvers and name server
        let tx_delete_udp = self.get_delete_channel_udp();
        let tx_delete_tcp = self.get_delete_channel_tcp();
        let tx_delete_ns_udp = self.get_delete_channel_ns_udp();
        let tx_delete_ns_tcp = self.get_delete_channel_ns_tcp();

        // Creates an UDP socket
        let socket = UdpSocket::bind(&name_server_ip_address).expect("Failed to bind host socket");

        loop {
            // We receive the msg
            let dns_message_option = Resolver::receive_udp_msg(socket.try_clone().unwrap());

            // Creates an empty msg and address
            let (mut dns_message, src_address);

            // Checks the message
            match dns_message_option {
                Some(val) => {
                    dns_message = val.0;
                    src_address = val.1;
                }
                // If no msg
                None => {
                    continue;
                }
            }
            //

            // Delete from cache
            let mut received_delete = rx_delete_ns_udp.try_iter();

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
            let mut received_update = rx_update_cache_ns_udp.try_iter();

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
            let mut received_add = rx_add_ns_udp.try_iter();

            let mut next_value = received_add.next();

            let mut cache = self.get_cache();

            while next_value.is_none() == false {
                let (name, rr) = next_value.unwrap();
                cache.add(name, rr, 7, false, false, "".to_string());
                next_value = received_add.next();
            }

            self.set_cache(cache);
            ////////////////////////////////////////////////////////////////////

            // Update queries ids
            let mut received = rx.try_iter();

            let mut next_value = received.next();

            let mut queries_id = self.get_queries_id();

            while next_value.is_none() == false {
                let (old, new) = next_value.unwrap();
                queries_id.insert(new, old);
                next_value = received.next();
            }

            self.set_queries_id(queries_id);
            //

            let socket_copy = socket.try_clone().unwrap();

            // If the msg is a query
            if dns_message.get_header().get_qr() == false {
                let op_code = dns_message.get_header().get_op_code();

                // If is an inverse query, we send a Not Implemented message
                if op_code == 1 {
                    let not_implemented_msg = DnsMessage::not_implemented_msg(dns_message.clone());

                    NameServer::send_response_by_udp(
                        not_implemented_msg,
                        src_address.to_string(),
                        &socket_copy,
                    );

                    continue;
                }
                //

                // Necessary info to process the query
                let zones = self.get_zones();
                let cache = self.get_cache();
                let tx_clone = tx.clone();
                let resolver_ip_clone = local_resolver_ip_and_port.clone();
                let tx_delete_udp_copy = tx_delete_udp.clone();
                let tx_delete_tcp_copy = tx_delete_tcp.clone();
                let tx_delete_ns_udp_copy = tx_delete_ns_udp.clone();
                let tx_delete_ns_tcp_copy = tx_delete_ns_tcp.clone();

                // Creates a new thread to process the query
                thread::spawn(move || {
                    // Default RA bit to 1
                    let mut ra = true;
                    let mut new_msg = NameServer::set_ra(dns_message.clone(), true);

                    // RA bit to 0
                    if RECURSIVE_AVAILABLE == false {
                        new_msg = NameServer::set_ra(dns_message, false);
                        ra = false;
                    }

                    let rd = new_msg.get_header().get_rd();

                    // If recursion available and recursion desired
                    if rd == true && ra == true {
                        // We use our internal resolver to answer the query
                        NameServer::step_5_udp(
                            resolver_ip_clone,
                            new_msg,
                            socket_copy,
                            tx_clone,
                            src_address,
                        );
                    } else {
                        // We answer the query with local info
                        let mut response_dns_msg = NameServer::step_2(
                            new_msg,
                            zones,
                            cache,
                            tx_delete_udp_copy,
                            tx_delete_tcp_copy,
                            tx_delete_ns_udp_copy,
                            tx_delete_ns_tcp_copy,
                        );

                        // Sets query type to response
                        let mut header = response_dns_msg.get_header();
                        header.set_qr(true);
                        response_dns_msg.set_header(header);

                        // Sends the answer to the client (or resolver)
                        NameServer::send_response_by_udp(
                            response_dns_msg,
                            src_address.to_string(),
                            &socket_copy,
                        );
                    }
                });
            }
            // If the msg is a response
            else {
                let mut queries_id = self.get_queries_id();
                let new_id = dns_message.get_query_id();

                // Checks query id
                match queries_id.get(&new_id.clone()) {
                    // If the query id matches
                    Some(val) => {
                        let val_copy = val.clone();

                        // Sets headers
                        let mut header = dns_message.get_header();
                        header.set_id(val_copy[0].clone().0);
                        dns_message.set_header(header);
                        queries_id.remove(&new_id);

                        // Sends response
                        NameServer::send_response_by_udp(
                            dns_message,
                            val_copy[0].clone().1,
                            &socket_copy,
                        );
                    }
                    // Query id does not match
                    None => {}
                }
            }
        }
    }

    pub fn run_name_server_tcp(
        &mut self,
        name_server_ip_address: String,
        local_resolver_ip_and_port: String,
        rx_add_ns_tcp: Receiver<(String, ResourceRecord)>,
        rx_delete_ns_tcp: Receiver<(String, String)>,
        rx_update_cache_ns_tcp: Receiver<(String, String, u32)>,
    ) {
        // Channels to send data between threads, resolvers and name server
        let tx_delete_udp = self.get_delete_channel_udp();
        let tx_delete_tcp = self.get_delete_channel_tcp();
        let tx_delete_ns_udp = self.get_delete_channel_ns_udp();
        let tx_delete_ns_tcp = self.get_delete_channel_ns_tcp();

        // Creates a TCP Listener
        let listener = TcpListener::bind(&name_server_ip_address).expect("Could not bind");

        loop {
            // Accepts the connection
            match listener.accept() {
                Ok((stream, _)) => {
                    // We receive the msg
                    let received_msg =
                        Resolver::receive_tcp_msg(stream.try_clone().unwrap()).unwrap();

                    // Delete from cache

                    let mut received_delete = rx_delete_ns_tcp.try_iter();

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

                    let mut received_update = rx_update_cache_ns_tcp.try_iter();

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

                    let mut received_add = rx_add_ns_tcp.try_iter();

                    let mut next_value = received_add.next();

                    let mut cache = self.get_cache();

                    while next_value.is_none() == false {
                        let (name, rr) = next_value.unwrap();
                        cache.add(name, rr, 7, false, false, "".to_string());
                        next_value = received_add.next();
                    }

                    self.set_cache(cache);

                    ////////////////////////////////////////////////////////////////////

                    // Msg parsed
                    let dns_message_parse_result = DnsMessage::from_bytes(&received_msg);

                    // Checks parsed msg
                    match dns_message_parse_result {
                        Ok(_) => {}
                        Err(_) => {
                            // Sends a format error if the msg is not correctly parsed
                            let dns_msg_format_error = DnsMessage::format_error_msg();

                            NameServer::send_response_by_tcp(dns_msg_format_error, stream);

                            continue;
                        }
                    }

                    let dns_message = dns_message_parse_result.unwrap();

                    // If the msg is a query
                    if dns_message.get_header().get_qr() == false {
                        let op_code = dns_message.get_header().get_op_code();

                        // If is an inverse query
                        if op_code == 1 {
                            // Creates a not implemented msg
                            let not_implemented_msg =
                                DnsMessage::not_implemented_msg(dns_message.clone());

                            // Sends the Not Implemented msg
                            NameServer::send_response_by_tcp(not_implemented_msg, stream);

                            continue;
                        }
                        //

                        // Gets the necessary info to process the query
                        let zones = self.get_zones();
                        let cache = self.get_cache();
                        let resolver_ip_clone = local_resolver_ip_and_port.clone();
                        let tx_delete_udp_copy = tx_delete_udp.clone();
                        let tx_delete_tcp_copy = tx_delete_tcp.clone();
                        let tx_delete_ns_udp_copy = tx_delete_ns_udp.clone();
                        let tx_delete_ns_tcp_copy = tx_delete_ns_tcp.clone();

                        // Creates a new thread to process the msg
                        thread::spawn(move || {
                            let query_id = dns_message.get_query_id();

                            // Set RA bit to 1
                            let mut ra = true;
                            let mut new_msg = NameServer::set_ra(dns_message.clone(), true);

                            // RA bit to 0
                            if RECURSIVE_AVAILABLE == false {
                                new_msg = NameServer::set_ra(dns_message, false);
                                ra = false;
                            }

                            // Gets recursion desired bit
                            let rd = new_msg.get_header().get_rd();

                            // If recursion
                            if rd == true && ra == true {
                                // Gets the answer
                                let mut response_dns_msg = NameServer::step_5_tcp(
                                    resolver_ip_clone,
                                    new_msg,
                                    cache.clone(),
                                    zones.clone(),
                                );

                                // Set the query id
                                response_dns_msg.set_query_id(query_id.clone());

                                // Sends the response
                                NameServer::send_response_by_tcp(
                                    response_dns_msg,
                                    stream.try_clone().unwrap(),
                                );
                            } else {
                                // Answers with local info
                                let mut response_dns_msg = NameServer::step_2(
                                    new_msg,
                                    zones,
                                    cache,
                                    tx_delete_udp_copy,
                                    tx_delete_tcp_copy,
                                    tx_delete_ns_udp_copy,
                                    tx_delete_ns_tcp_copy,
                                );

                                // Sets the query id
                                response_dns_msg.set_query_id(query_id);

                                // Sends the answer
                                NameServer::send_response_by_tcp(response_dns_msg, stream);
                            }
                        });
                    }
                }
                Err(_) => {}
            }
        }
    }
}

// Utils for TCP and UDP
impl NameServer {
    // Step 2 from RFC 1034
    pub fn search_nearest_ancestor_zone(
        zones: HashMap<u16, HashMap<String, NSZone>>,
        mut qname: String,
        qclass: u16,
    ) -> (NSZone, bool) {
        // Get the zone by class
        let zones_by_class_option = zones.get(&qclass);

        match zones_by_class_option {
            Some(_) => {}
            None => return (NSZone::new(), false),
        }
        //

        let zones_by_class = zones_by_class_option.unwrap();

        // If there are a zone
        let (zone, available) = match zones_by_class.get(&qname) {
            Some(val) => (val.clone(), true),
            None => (NSZone::new(), false),
        };

        // If we found a zone
        if zone.get_name() != "" && zone.get_active() == true {
            return (zone, available);
        }
        // We found the next ancestor zone
        else {
            let dot_position = qname.find(".").unwrap_or(0);

            if dot_position > 0 {
                qname.replace_range(..dot_position + 1, "");
                return NameServer::search_nearest_ancestor_zone(zones, qname, qclass);
            } else {
                return (zone, available);
            }
        }
    }

    //Step 3 from RFC 1034
    fn search_in_zone(
        zone: NSZone,
        qname: String,
        msg: DnsMessage,
        zones: HashMap<u16, HashMap<String, NSZone>>,
        cache: DnsCache,
        tx_delete_resolver_udp: Sender<(String, String)>,
        tx_delete_resolver_tcp: Sender<(String, String)>,
        tx_delete_ns_udp: Sender<(String, String)>,
        tx_delete_ns_tcp: Sender<(String, String)>,
    ) -> DnsMessage {
        let mut qname_without_zone_label = qname.replace(&zone.get_name(), "");
        let mut zone = zone.clone();

        // We were looking for the first node
        if qname_without_zone_label == "".to_string() {
            return NameServer::step_3a(
                zone,
                msg,
                zones,
                cache,
                tx_delete_resolver_udp,
                tx_delete_resolver_tcp,
                tx_delete_ns_udp,
                tx_delete_ns_tcp,
            );
        }

        // Delete last dot
        qname_without_zone_label.pop().unwrap();

        // Splits domain name
        let mut labels: Vec<&str> = qname_without_zone_label.split(".").collect();

        labels.reverse();

        for label in labels {
            let exist_child = zone.exist_child(label.to_string());

            // If a child exists
            if exist_child == true {
                zone = zone.get_child(label.to_string()).0.clone();

                // Referal zone
                if zone.get_subzone() == true {
                    return NameServer::step_3b(
                        zone,
                        msg,
                        cache,
                        zones,
                        tx_delete_resolver_udp,
                        tx_delete_resolver_tcp,
                        tx_delete_ns_udp,
                        tx_delete_ns_tcp,
                    );
                } else {
                    continue;
                }
            } else {
                // Impossible match
                return NameServer::step_3c(zone, msg, cache, zones);
            }
        }

        // We found the node
        return NameServer::step_3a(
            zone,
            msg,
            zones,
            cache,
            tx_delete_resolver_udp,
            tx_delete_resolver_tcp,
            tx_delete_ns_udp,
            tx_delete_ns_tcp,
        );
    }

    // Step 2 from RFC 1034
    pub fn step_2(
        mut msg: DnsMessage,
        zones: HashMap<u16, HashMap<String, NSZone>>,
        cache: DnsCache,
        tx_delete_resolver_udp: Sender<(String, String)>,
        tx_delete_resolver_tcp: Sender<(String, String)>,
        tx_delete_ns_udp: Sender<(String, String)>,
        tx_delete_ns_tcp: Sender<(String, String)>,
    ) -> DnsMessage {
        let qname = msg.get_question().get_qname().get_name();
        let qclass = msg.get_question().get_qclass();

        // Class is *
        if qclass == 255 {
            let mut all_answers = Vec::new();

            // Gets all answers for all classes
            for (class, _hashzones) in zones.iter() {
                let (zone, available) = NameServer::search_nearest_ancestor_zone(
                    zones.clone(),
                    qname.clone(),
                    class.clone(),
                );

                if available == true {
                    let new_msg = NameServer::search_in_zone(
                        zone,
                        qname.clone(),
                        msg.clone(),
                        zones.clone(),
                        cache.clone(),
                        tx_delete_resolver_udp.clone(),
                        tx_delete_resolver_tcp.clone(),
                        tx_delete_ns_udp.clone(),
                        tx_delete_ns_tcp.clone(),
                    );

                    all_answers.append(&mut new_msg.get_answer());
                }
            }
            //

            // If answers were found
            if all_answers.len() > 0 {
                // Set answers
                msg.set_answer(all_answers);

                // Set AA to 0
                let mut header = msg.get_header();
                header.set_aa(false);
                msg.set_header(header);

                // Update header coutners
                msg.update_header_counters();

                return msg;
            } else {
                return NameServer::step_4(
                    msg,
                    cache,
                    zones,
                    tx_delete_resolver_udp,
                    tx_delete_resolver_tcp,
                    tx_delete_ns_udp,
                    tx_delete_ns_tcp,
                );
            }
            //
        } else {
            let (zone, available) = NameServer::search_nearest_ancestor_zone(
                zones.clone(),
                qname.clone(),
                qclass.clone(),
            );

            if available == true {
                // Step 3 RFC 1034
                return NameServer::search_in_zone(
                    zone,
                    qname.clone(),
                    msg.clone(),
                    zones,
                    cache,
                    tx_delete_resolver_udp,
                    tx_delete_resolver_tcp,
                    tx_delete_ns_udp,
                    tx_delete_ns_tcp,
                );
            } else {
                // Step 4 RFC 1034
                return NameServer::step_4(
                    msg,
                    cache,
                    zones,
                    tx_delete_resolver_udp,
                    tx_delete_resolver_tcp,
                    tx_delete_ns_udp,
                    tx_delete_ns_tcp,
                );
            }
        }
    }

    // Step 3 from RFC 1034
    pub fn step_3a(
        zone: NSZone,
        mut msg: DnsMessage,
        zones: HashMap<u16, HashMap<String, NSZone>>,
        cache: DnsCache,
        tx_delete_resolver_udp: Sender<(String, String)>,
        tx_delete_resolver_tcp: Sender<(String, String)>,
        tx_delete_ns_udp: Sender<(String, String)>,
        tx_delete_ns_tcp: Sender<(String, String)>,
    ) -> DnsMessage {
        // Step 3.a
        let qtype = msg.get_question().get_qtype();
        let qclass = msg.get_question().get_qclass();
        let mut rrs_by_type = zone.get_rrs_by_type(qtype);

        if rrs_by_type.len() > 0 {
            // Set the ttl from SOA RR
            let (main_zone, _available) = NameServer::search_nearest_ancestor_zone(
                zones.clone(),
                msg.get_question().get_qname().get_name(),
                qclass,
            );

            let soa_rr = main_zone.get_rrs_by_type(6)[0].clone();
            let soa_rdata = match soa_rr.get_rdata() {
                Rdata::SomeSoaRdata(val) => val,
                _ => unreachable!(),
            };

            let soa_minimun_ttl = soa_rdata.get_minimum();

            for rr in rrs_by_type.iter_mut() {
                let rr_ttl = rr.get_ttl();

                rr.set_ttl(cmp::max(rr_ttl, soa_minimun_ttl));
            }
            //

            msg.set_answer(rrs_by_type);

            let mut header = msg.get_header();

            header.set_aa(true);
            msg.set_header(header);

            return NameServer::step_6(msg, cache, zones);
        } else {
            let rr = zone.get_value()[0].clone();
            if rr.get_type_code() == 5 && qtype != 5 {
                rrs_by_type.push(rr.clone());
                msg.set_answer(rrs_by_type);

                let mut header = msg.get_header();
                header.set_aa(true);

                msg.set_header(header);

                let canonical_name = match rr.get_rdata() {
                    Rdata::SomeCnameRdata(val) => val.get_cname(),
                    _ => unreachable!(),
                };

                let mut question = msg.get_question();

                question.set_qname(canonical_name);
                msg.set_question(question);

                return NameServer::step_2(
                    msg,
                    zones,
                    cache,
                    tx_delete_resolver_udp,
                    tx_delete_resolver_tcp,
                    tx_delete_ns_udp,
                    tx_delete_ns_tcp,
                );
            } else {
                let mut header = msg.get_header();
                header.set_aa(true);

                msg.set_header(header);
                return NameServer::step_6(msg, cache, zones);
            }
        }
        //
    }

    // Step 3b from RFC 1034
    pub fn step_3b(
        zone: NSZone,
        mut msg: DnsMessage,
        mut cache: DnsCache,
        zones: HashMap<u16, HashMap<String, NSZone>>,
        tx_delete_resolver_udp: Sender<(String, String)>,
        tx_delete_resolver_tcp: Sender<(String, String)>,
        tx_delete_ns_udp: Sender<(String, String)>,
        tx_delete_ns_tcp: Sender<(String, String)>,
    ) -> DnsMessage {
        let ns_rrs = zone.get_value();

        msg.set_authority(ns_rrs.clone());
        let mut additional = Vec::<ResourceRecord>::new();

        for ns_rr in ns_rrs {
            let name_ns = match ns_rr.get_rdata() {
                Rdata::SomeNsRdata(val) => val.get_nsdname().get_name(),
                _ => unreachable!(),
            };

            let rrs = cache.get(name_ns.clone(), "A".to_string());

            if rrs.len() > 0 {
                for rr in rrs {
                    additional.push(rr.get_resource_record());
                }
            } else {
                match name_ns.find(&zone.get_name()) {
                    Some(index) => {
                        let new_ns_name = name_ns[..index - 1].to_string();

                        let labels: Vec<&str> = new_ns_name.split(".").collect();
                        let mut a_glue_rrs;
                        let mut glue_zone = zone.clone();

                        // Goes down for the tree looking for the zone with glue rrs
                        for label in labels {
                            let exist_child = glue_zone.exist_child(label.to_string());

                            if exist_child == true {
                                glue_zone = glue_zone.get_child(label.to_string()).0;
                            } else {
                                break;
                            }
                        }

                        // Gets the rrs from the zone
                        let glue_rrs = glue_zone.get_value();

                        // Gets the glue rrs for the ns rr
                        a_glue_rrs = NameServer::look_for_type_records(name_ns, glue_rrs, 1);

                        additional.append(&mut a_glue_rrs);
                    }
                    None => {}
                }
            }
        }

        msg.set_additional(additional);

        return NameServer::step_4(
            msg,
            cache,
            zones,
            tx_delete_resolver_udp,
            tx_delete_resolver_tcp,
            tx_delete_ns_udp,
            tx_delete_ns_tcp,
        );
    }

    // Step 3c from RFC 1034
    pub fn step_3c(
        zone: NSZone,
        mut msg: DnsMessage,
        cache: DnsCache,
        zones: HashMap<u16, HashMap<String, NSZone>>,
    ) -> DnsMessage {
        let exist = zone.exist_child("*".to_string());

        if exist == true {
            // Gets the * records
            let (new_zone, _available) = zone.get_child("*".to_string());
            let rrs = new_zone.get_value();
            let qtype = msg.get_question().get_qtype();
            let mut answer = Vec::<ResourceRecord>::new();

            for mut rr in rrs {
                if rr.get_type_code() == qtype {
                    rr.set_name(msg.get_question().get_qname());
                    answer.push(rr);
                }
            }

            msg.set_answer(answer);

            let mut header = msg.get_header();
            header.set_aa(true);

            msg.set_header(header);

            return NameServer::step_6(msg, cache, zones);
        } else {
            // Domain do not exist in the zone
            let mut header = msg.get_header();
            header.set_rcode(3);

            if msg.get_answer().len() == 0 {
                header.set_aa(true);
            }

            msg.set_header(header);

            return msg;
        }
    }

    // Step 4 from RFC 1034
    pub fn step_4(
        mut msg: DnsMessage,
        mut cache: DnsCache,
        zones: HashMap<u16, HashMap<String, NSZone>>,
        tx_delete_resolver_udp: Sender<(String, String)>,
        tx_delete_resolver_tcp: Sender<(String, String)>,
        tx_delete_ns_udp: Sender<(String, String)>,
        tx_delete_ns_tcp: Sender<(String, String)>,
    ) -> DnsMessage {
        let qtype = msg.get_question_qtype();
        let qclass = msg.get_question().get_qclass();
        let mut domain_name = msg.get_question().get_qname().get_name();
        let mut answer = Vec::<ResourceRecord>::new();

        let rrs_by_type = cache.get(domain_name.clone(), qtype);
        let mut rrs = Vec::new();

        // Get the rrs for qname and qclass
        if qclass != 255 {
            // Get rrs for qclass
            for rr in rrs_by_type {
                let rr_class = rr.get_resource_record().get_class();

                if rr_class == qclass {
                    rrs.push(rr);
                }
            }
            //
        } else {
            rrs = rrs_by_type;
        }
        //

        let now = Utc::now();
        let timestamp = now.timestamp() as u32;

        // We check the ttls from the RR's

        for rr_cache in rrs.clone() {
            let mut rr = rr_cache.get_resource_record();
            let rr_ttl = rr.get_ttl();
            let relative_ttl = rr_ttl - timestamp;

            if relative_ttl > 0 {
                rr.set_ttl(relative_ttl);
                answer.push(rr);
            }
        }

        // If there are RR's with TTL < 0, we remove the RR's from the cache
        if rrs.len() > 0 && answer.len() < rrs.len() {
            NameServer::remove_from_cache(
                domain_name.clone(),
                rrs[0].clone().get_resource_record().get_string_type(),
                tx_delete_resolver_udp,
                tx_delete_resolver_tcp,
                tx_delete_ns_udp,
                tx_delete_ns_tcp,
            );
        }

        //

        // Sets the answer
        if answer.len() > 0 {
            msg.set_answer(answer);
            let mut header = msg.get_header();
            header.set_aa(false);
            msg.set_header(header);
        }

        // Adds additional records
        if msg.get_authority().len() > 0 {
            return NameServer::step_6(msg, cache, zones);
        } else {
            let mut authority = Vec::<ResourceRecord>::new();

            // Looks for authoritive data in cache
            while domain_name != "".to_string() {
                let rrs = cache.get(domain_name.clone(), "NS".to_string());

                if rrs.len() > 0 {
                    for rr in rrs {
                        authority.push(rr.get_resource_record());
                    }

                    msg.set_authority(authority);

                    break;
                } else {
                    let dot_index = domain_name.find(".").unwrap_or(domain_name.len());

                    if dot_index == domain_name.len() {
                        break;
                    } else {
                        domain_name.replace_range(..dot_index + 1, "");
                    }
                }
            }
        }

        return NameServer::step_6(msg, cache, zones);
    }

    /// Adds addittional information to response - Step 6 RFC 1034
    fn step_6(
        mut msg: DnsMessage,
        mut cache: DnsCache,
        zones: HashMap<u16, HashMap<String, NSZone>>,
    ) -> DnsMessage {
        let answers = msg.get_answer();
        let mut additional = msg.get_additional();
        let aa = msg.get_header().get_aa();
        let qclass = msg.get_question().get_qclass();

        for answer in answers {
            let answer_type = answer.get_type_code();

            match answer_type {
                // Adds additional for MX data
                15 => {
                    let exchange = match answer.get_rdata() {
                        Rdata::SomeMxRdata(val) => val.get_exchange().get_name(),
                        _ => unreachable!(),
                    };

                    if aa == true {
                        let (zone, _available) = NameServer::search_nearest_ancestor_zone(
                            zones.clone(),
                            exchange,
                            qclass.clone(),
                        );

                        let mut rrs = zone.get_rrs_by_type(1);

                        additional.append(&mut rrs);
                    } else {
                        let rrs = cache.get(exchange, "A".to_string());

                        for rr in rrs {
                            additional.push(rr.get_resource_record());
                        }
                    }
                }
                // Adds additional for NS data
                2 => {
                    let name_ns = match answer.get_rdata() {
                        Rdata::SomeNsRdata(val) => val.get_nsdname().get_name(),
                        _ => unreachable!(),
                    };

                    let (zone, _available) = NameServer::search_nearest_ancestor_zone(
                        zones.clone(),
                        name_ns.clone(),
                        qclass.clone(),
                    );

                    let labels: Vec<&str> = name_ns.split(".").collect();
                    let mut last_zone = zone.clone();

                    // Goes down for the tree looking for the zone with glue rrs
                    for label in labels {
                        let exist_child = last_zone.exist_child(label.to_string());

                        if exist_child == true {
                            last_zone = last_zone.get_child(label.to_string()).0;
                        } else {
                            break;
                        }
                    }

                    if last_zone.get_subzone() == true {
                        let glue_rrs = last_zone.get_glue_rrs();

                        let mut a_glue_rrs =
                            NameServer::look_for_type_records(name_ns, glue_rrs, 1);

                        additional.append(&mut a_glue_rrs);
                    } else {
                        // In zone
                        let rrs_zone = last_zone.get_rrs_by_type(1);

                        for rr_zone in rrs_zone {
                            additional.push(rr_zone);
                        }

                        // In cache
                        let rrs = cache.get(name_ns, "A".to_string());

                        for rr in rrs {
                            additional.push(rr.get_resource_record());
                        }
                    }
                }
                _ => {}
            }
        }

        msg.set_additional(additional);

        return msg;
    }
}

// Utils for UDP
impl NameServer {
    // Step 5 for UDP
    fn step_5_udp(
        resolver_ip_and_port: String,
        mut msg: DnsMessage,
        socket: UdpSocket,
        tx: Sender<(Vec<(u16, String)>, u16)>,
        src_address: String,
    ) {
        let old_id = msg.get_query_id();
        let mut rng = thread_rng();
        let new_id: u16 = rng.gen();

        // Sets the header
        let mut header = msg.get_header();
        header.set_id(new_id);
        msg.set_header(header);

        tx.send((vec![(old_id, src_address)], new_id))
            .expect("Error sending data");

        // Send request to resolver
        socket
            .send_to(&msg.to_bytes(), resolver_ip_and_port)
            .expect("Couldn't send data");
    }

    // Sends the response to the address by udp
    fn send_response_by_udp(mut response: DnsMessage, src_address: String, socket: &UdpSocket) {
        response.update_header_counters();

        // Msg to bytes
        let bytes = response.to_bytes();

        // Msg size < 512
        if bytes.len() <= 512 {
            socket
                .send_to(&bytes, src_address)
                .expect("failed to send message");
        } else {
            let mut response_header = response.get_header();
            response_header.set_tc(true);
            response.set_header(response_header);

            socket
                .send_to(&bytes, src_address)
                .expect("failed to send message");
        }
    }
}

//Utils for TCP
impl NameServer {
    // Step 5 for TCP
    fn step_5_tcp(
        resolver_ip_and_port: String,
        mut msg: DnsMessage,
        cache: DnsCache,
        zones: HashMap<u16, HashMap<String, NSZone>>,
    ) -> DnsMessage {
        let mut rng = thread_rng();
        let new_id: u16 = rng.gen();

        let mut header = msg.get_header();
        header.set_id(new_id);

        msg.set_header(header);

        let bytes = msg.to_bytes();

        // Adds the two bytes needs for tcp
        let msg_length: u16 = bytes.len() as u16;
        let tcp_bytes_length = [(msg_length >> 8) as u8, msg_length as u8];
        let full_msg = [&tcp_bytes_length, bytes.as_slice()].concat();

        // Send query to local resolver
        let mut stream = TcpStream::connect(resolver_ip_and_port).unwrap();
        stream
            .write(&full_msg)
            .expect("Couldn't send query to resolver");

        // Receives the response
        let received_msg = Resolver::receive_tcp_msg(stream).unwrap();

        // Parse the response
        let dns_response_result = DnsMessage::from_bytes(&received_msg);

        // Checks the parse
        match dns_response_result {
            Ok(_) => {}
            Err(_) => {
                return DnsMessage::format_error_msg();
            }
        }

        let dns_response = dns_response_result.unwrap();

        // Adds additionals
        return NameServer::step_6(dns_response, cache, zones);
    }

    // Sends response by TCP
    fn send_response_by_tcp(mut msg: DnsMessage, mut stream: TcpStream) {
        // Updates headers counters
        msg.update_header_counters();

        // Msg to bytes
        let bytes = msg.to_bytes();

        // Adds the length bytes to the msg
        let msg_length: u16 = bytes.len() as u16;
        let tcp_bytes_length = [(msg_length >> 8) as u8, msg_length as u8];
        let full_msg = [&tcp_bytes_length, bytes.as_slice()].concat();

        // Sends the msg
        stream.write(&full_msg).expect("Couldn't send response");
    }
}

// Utils
impl NameServer {
    // Gets the RR for an especific type
    fn look_for_type_records(
        name_ns: String,
        rrs: Vec<ResourceRecord>,
        rr_type: u16,
    ) -> Vec<ResourceRecord> {
        let mut a_rrs = Vec::<ResourceRecord>::new();

        for rr in rrs {
            let rr_type_glue = rr.get_type_code();
            let rr_name = rr.get_name().get_name();

            if rr_type_glue == rr_type && rr_name == name_ns {
                a_rrs.push(rr);
            }
        }

        return a_rrs;
    }

    // Sets RA bit in header
    fn set_ra(mut msg: DnsMessage, ra: bool) -> DnsMessage {
        let mut header = msg.get_header();
        header.set_ra(ra);

        msg.set_header(header);

        msg
    }

    // Adds a zone from a master file
    pub fn add_zone_from_master_file(&mut self, file_name: String, ip_address_for_refresh: String) {
        let new_zone = NSZone::from_file(file_name, ip_address_for_refresh);
        let mut zones = self.get_zones();
        let zone_class = new_zone.get_class();

        // Create the new zone hash
        let mut new_zone_hash = HashMap::<String, NSZone>::new();
        new_zone_hash.insert(new_zone.get_name(), new_zone);

        // Insert the new zone by class
        zones.insert(zone_class, new_zone_hash);

        self.set_zones(zones);
    }

    // Removes records from the cache
    pub fn remove_from_cache(
        domain_name: String,
        resource_record: String,
        tx_resolver_udp: Sender<(String, String)>,
        tx_resolver_tcp: Sender<(String, String)>,
        tx_ns_udp: Sender<(String, String)>,
        tx_ns_tcp: Sender<(String, String)>,
    ) {
        // For error handling
        let default = ();

        tx_resolver_udp
            .send((domain_name.clone(), resource_record.clone()))
            .unwrap_or(default);
        tx_resolver_tcp
            .send((domain_name.clone(), resource_record.clone()))
            .unwrap_or(default);
        tx_ns_udp
            .send((domain_name.clone(), resource_record.clone()))
            .unwrap_or(default);
        tx_ns_tcp
            .send((domain_name.clone(), resource_record.clone()))
            .unwrap_or(default);
    }
}

// Getters
impl NameServer {
    // Gets the zones data from the name server
    pub fn get_zones(&self) -> HashMap<u16, HashMap<String, NSZone>> {
        self.zones.clone()
    }

    // Gets the cache from the name server
    pub fn get_cache(&self) -> DnsCache {
        self.cache.clone()
    }

    pub fn get_queries_id(&self) -> HashMap<u16, Vec<(u16, String)>> {
        self.queries_id.clone()
    }

    /// Get the owner's query address
    pub fn get_delete_channel_udp(&self) -> Sender<(String, String)> {
        self.delete_sender_udp.clone()
    }

    /// Get the owner's query address
    pub fn get_delete_channel_tcp(&self) -> Sender<(String, String)> {
        self.delete_sender_tcp.clone()
    }

    /// Get the owner's query address
    pub fn get_add_channel_ns_udp(&self) -> Sender<(String, ResourceRecord)> {
        self.add_sender_ns_udp.clone()
    }

    /// Get the owner's query address
    pub fn get_add_channel_ns_tcp(&self) -> Sender<(String, ResourceRecord)> {
        self.add_sender_ns_tcp.clone()
    }

    /// Get the owner's query address
    pub fn get_delete_channel_ns_udp(&self) -> Sender<(String, String)> {
        self.delete_sender_ns_udp.clone()
    }

    /// Get the owner's query address
    pub fn get_delete_channel_ns_tcp(&self) -> Sender<(String, String)> {
        self.delete_sender_ns_tcp.clone()
    }
}

// Setters
impl NameServer {
    // Sets the zones with a new value
    pub fn set_zones(&mut self, zones: HashMap<u16, HashMap<String, NSZone>>) {
        self.zones = zones;
    }

    // Sets the cache with a new cache
    pub fn set_cache(&mut self, cache: DnsCache) {
        self.cache = cache;
    }

    // Sets the queries ids with a new value
    pub fn set_queries_id(&mut self, queries_id: HashMap<u16, Vec<(u16, String)>>) {
        self.queries_id = queries_id;
    }
}
