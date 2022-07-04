use crate::client;
use crate::name_server::NameServer;
use crate::resolver::slist::Slist;
use crate::resolver::Resolver;

use crate::config::RESOLVER_IP_PORT;
use crate::config::SBELT_ROOT_IPS;

use std::collections::HashMap;
use std::fs::write;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::BufRead;
use std::io::BufReader;
use std::io::Write;
use std::net::TcpStream;
use std::net::UdpSocket;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

/// Execute the response time experiment
pub fn response_time_experiment(filename: String) {
    // Hash to save response times
    let mut response_times = HashMap::<String, Vec<u128>>::new();

    // Open file
    let file = File::open(filename).expect("file not found!");
    let mut reader = BufReader::new(file);
    let mut lines: Vec<String> = Vec::new();

    // Read lines
    for line in reader.lines() {
        let line = line.unwrap();
        let mut times_vec = Vec::new();

        // Add an empty vec to hashmap
        response_times.insert(line.clone(), times_vec);

        // Ask for the website ip 10 times
        let mut i = 0;

        while i < 10 {
            println!("Iteración: {}", i);

            // Sleep

            let ten_millis = Duration::from_millis(1000);

            thread::sleep(ten_millis);

            // Run the resolver (the resolver should not save cache)
            // Channels
            let (add_sender_udp, add_recv_udp) = mpsc::channel();
            let (delete_sender_udp, delete_recv_udp) = mpsc::channel();
            let (add_sender_tcp, add_recv_tcp) = mpsc::channel();
            let (delete_sender_tcp, delete_recv_tcp) = mpsc::channel();
            let (add_sender_ns_udp, add_recv_ns_udp) = mpsc::channel();
            let (delete_sender_ns_udp, delete_recv_ns_udp) = mpsc::channel();
            let (add_sender_ns_tcp, add_recv_ns_tcp) = mpsc::channel();
            let (delete_sender_ns_tcp, delete_recv_ns_tcp) = mpsc::channel();
            let (update_cache_sender_udp, rx_update_cache_udp) = mpsc::channel();
            let (update_cache_sender_tcp, rx_update_cache_tcp) = mpsc::channel();
            let (update_cache_sender_ns_udp, rx_update_cache_ns_udp) = mpsc::channel();
            let (update_cache_sender_ns_tcp, rx_update_cache_ns_tcp) = mpsc::channel();

            let mut resolver = Resolver::new(
                add_sender_udp.clone(),
                delete_sender_udp.clone(),
                add_sender_tcp.clone(),
                delete_sender_tcp.clone(),
                add_sender_ns_udp.clone(),
                delete_sender_ns_udp.clone(),
                add_sender_ns_tcp.clone(),
                delete_sender_ns_tcp.clone(),
                update_cache_sender_udp.clone(),
                update_cache_sender_tcp.clone(),
                update_cache_sender_ns_udp.clone(),
                update_cache_sender_ns_tcp.clone(),
            );

            resolver.set_ip_address(RESOLVER_IP_PORT.to_string());

            let mut sbelt = Slist::new();

            for ip in SBELT_ROOT_IPS {
                sbelt.insert(".".to_string(), ip.to_string(), 5000);
            }

            resolver.set_sbelt(sbelt);

            thread::spawn(move || {
                resolver.run_resolver(
                    add_recv_udp,
                    delete_recv_udp,
                    add_recv_tcp,
                    delete_recv_tcp,
                    rx_update_cache_udp,
                    rx_update_cache_tcp,
                    false,
                );
            });

            ///////
            ///
            // Sleep
            let ten_millis = Duration::from_millis(1000);

            thread::sleep(ten_millis);

            let response_time = client::run_client(line.clone(), 1, 1);

            // Sending Udp msg to kill resolver
            let socket = UdpSocket::bind("192.168.1.90:58402").expect("couldn't bind to address");
            socket
                .send_to(&[1; 50], RESOLVER_IP_PORT)
                .expect("couldn't send data");

            // Sending TCP msg to kill resolver

            let mut stream =
                TcpStream::connect(RESOLVER_IP_PORT).expect("couldn't connect to address");

            stream.write(&[1; 50]);

            // Save response time

            let mut times_vec = response_times.get(&line).unwrap().clone();

            times_vec.push(response_time.as_millis());

            response_times.insert(line.clone(), times_vec.to_vec());

            i = i + 1;
        }
    }

    // Add the results to a new file
    let mut new_file = File::create("response_time_results.txt");

    // Iterate results.
    for (domain, result_vec) in &response_times {
        for time in result_vec {
            println!("Guardando: {} -- {}", domain, time);
            let mut new_line = String::new();
            new_line.push_str(domain.as_str());
            new_line.push_str(" ");
            new_line.push_str(time.to_string().as_str());
            new_line.push_str("\n");

            let mut file = OpenOptions::new()
                .write(true)
                .append(true)
                .open("response_time_results.txt")
                .unwrap();

            write!(file, "{}", new_line.as_str());
        }
    }
}
