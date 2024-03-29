pub mod config;

use crate::client::config::CLIENT_IP_PORT;
use crate::client::config::RESOLVER_IP_PORT;
use crate::client::config::TIMEOUT;
use crate::client::config::TRANSPORT;

use crate::message::rdata::Rdata;
use crate::message::DnsMessage;
use crate::resolver::Resolver;

use rand::{thread_rng, Rng};
use std::net::UdpSocket;
use std::time::{Duration, Instant};

pub fn run_client(
    host_name: String,
    qclass: u16,
    qtype: u16,
) -> (Duration, Vec<String>, bool, Vec<String>) {
    //Start timestamp
    let now = Instant::now();

    // Create randon generator
    let mut rng = thread_rng();

    // Create query id
    let query_id: u16 = rng.gen();

    // Create query msg
    let query_msg = DnsMessage::new_query_message(host_name, qtype, qclass, 0, false, query_id);

    // Create response buffer
    let mut dns_message = DnsMessage::new();

    // Send query by UDP
    if TRANSPORT == "UDP" {
        let socket = UdpSocket::bind(CLIENT_IP_PORT).expect("No connection");
        let msg_to_bytes = query_msg.to_bytes();

        socket
            .send_to(&msg_to_bytes, RESOLVER_IP_PORT)
            .expect("Query could't send");
        socket
            .set_read_timeout(Some(Duration::from_millis(TIMEOUT * 1000)))
            .expect("Set client readtimeout failed");

        let response_result = Resolver::receive_udp_msg(socket.try_clone().unwrap());

        match response_result {
            Some(val) => {
                dns_message = val.0;
            }
            None => {
                // Temporary Error
                return (Duration::from_millis(0), Vec::new(), true, Vec::new());
            }
        }
    }

    let elapsed = now.elapsed();
    println!("{}", elapsed.as_millis());
    // Get the message and print the information
    let header = dns_message.get_header();
    let answers = dns_message.get_answer();

    let answer_count = header.get_ancount();

    // Not data found error
    if answer_count == 0 && header.get_qr() == true && header.get_aa() == true {
        return (Duration::from_millis(100000), Vec::new(), false, Vec::new());
    } else {
        // Vec to save ns rr's data
        let mut answer_ns_data_vec = Vec::new();

        // Vec to save answers
        let mut answers_ips = Vec::new();

        for answer in answers {
            match answer.get_rdata() {
                Rdata::SomeNsRdata(val) => {
                    answer_ns_data_vec.push(val.get_nsdname().get_name());
                }
                Rdata::SomeARdata(val) => {
                    answers_ips.push(val.get_string_address());
                }
                _ => {}
            }
        }

        return (elapsed, answer_ns_data_vec, false, answers_ips);
    }
}
