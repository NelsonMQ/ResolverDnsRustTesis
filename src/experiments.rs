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

pub fn missconfigured_experiments(case: u8, master_files_names: Vec<String>) {
    let ROOT_IP_PORT = "192.168.1.90:58398";
    let CHILD_IP_PORT = "192.168.1.90:58399";
    let ROOT_MASTER_FILE = master_files_names[0].clone();
    let CHILD_MASTER_FILE = master_files_names[1].clone();
    let FIRST_QUERY = "dcc.cl".to_string();
    let SECOND_QUERY = "uchile.dcc.cl".to_string();

    // Hash to save response times (0 response time means Temporary Error)
    let mut response_times = HashMap::<String, Vec<u128>>::new();
    let mut times_vec = Vec::new();

    // Add an empty vec to hashmap
    response_times.insert(FIRST_QUERY.clone(), times_vec.clone());
    response_times.insert(SECOND_QUERY.clone(), times_vec);

    // Run name servers

    // Channels
    let (delete_sender_udp, delete_recv_udp) = mpsc::channel();
    let (delete_sender_tcp, delete_recv_tcp) = mpsc::channel();
    let (add_sender_ns_udp, add_recv_ns_udp) = mpsc::channel();
    let (delete_sender_ns_udp, delete_recv_ns_udp) = mpsc::channel();
    let (add_sender_ns_tcp, add_recv_ns_tcp) = mpsc::channel();
    let (delete_sender_ns_tcp, delete_recv_ns_tcp) = mpsc::channel();
    let (update_cache_sender_ns_udp, rx_update_cache_ns_udp) = mpsc::channel();
    let (update_cache_sender_ns_tcp, rx_update_cache_ns_tcp) = mpsc::channel();

    /// Root name server
    let mut name_server = NameServer::new(
        false,
        delete_sender_udp.clone(),
        delete_sender_tcp.clone(),
        add_sender_ns_udp.clone(),
        delete_sender_ns_udp.clone(),
        add_sender_ns_tcp.clone(),
        delete_sender_ns_tcp.clone(),
    );

    name_server.add_zone_from_master_file(ROOT_MASTER_FILE.to_string(), "".to_string());

    thread::spawn(move || {
        name_server.run_name_server(
            ROOT_IP_PORT.to_string(),
            RESOLVER_IP_PORT.to_string(),
            add_recv_ns_udp,
            delete_recv_ns_udp,
            add_recv_ns_tcp,
            delete_recv_ns_tcp,
            rx_update_cache_ns_udp,
            rx_update_cache_ns_tcp,
        );
    });

    /// Child name server
    // Channels
    let (delete_sender_udp, delete_recv_udp) = mpsc::channel();
    let (delete_sender_tcp, delete_recv_tcp) = mpsc::channel();
    let (add_sender_ns_udp, add_recv_ns_udp) = mpsc::channel();
    let (delete_sender_ns_udp, delete_recv_ns_udp) = mpsc::channel();
    let (add_sender_ns_tcp, add_recv_ns_tcp) = mpsc::channel();
    let (delete_sender_ns_tcp, delete_recv_ns_tcp) = mpsc::channel();
    let (update_cache_sender_ns_udp, rx_update_cache_ns_udp) = mpsc::channel();
    let (update_cache_sender_ns_tcp, rx_update_cache_ns_tcp) = mpsc::channel();

    let mut name_server = NameServer::new(
        false,
        delete_sender_udp.clone(),
        delete_sender_tcp.clone(),
        add_sender_ns_udp.clone(),
        delete_sender_ns_udp.clone(),
        add_sender_ns_tcp.clone(),
        delete_sender_ns_tcp.clone(),
    );

    name_server.add_zone_from_master_file(CHILD_MASTER_FILE.to_string(), "".to_string());

    thread::spawn(move || {
        name_server.run_name_server(
            CHILD_IP_PORT.to_string(),
            RESOLVER_IP_PORT.to_string(),
            add_recv_ns_udp,
            delete_recv_ns_udp,
            add_recv_ns_tcp,
            delete_recv_ns_tcp,
            rx_update_cache_ns_udp,
            rx_update_cache_ns_tcp,
        );
    });

    for i in 0..5 {
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
                true,
            );
        });

        // Sleep
        let ten_millis = Duration::from_millis(1000);

        thread::sleep(ten_millis);

        let response_time_first = client::run_client(FIRST_QUERY.clone(), 1, 1);

        // Case 5 is case 3 for new algorithm
        if case == 5 {
            // Sending Udp msg to kill child name server
            let socket = UdpSocket::bind("192.168.1.90:58402").expect("couldn't bind to address");
            socket
                .send_to(&[1; 50], CHILD_IP_PORT)
                .expect("couldn't send data");

            // Sending TCP msg to kill child name server
            let mut stream =
                TcpStream::connect(CHILD_IP_PORT).expect("couldn't connect to address");

            stream.write(&[1; 50]);

            // Sleep
            let ten_millis = Duration::from_millis(1000);

            thread::sleep(ten_millis);

            /// Child name server
            // Channels
            let (delete_sender_udp, delete_recv_udp) = mpsc::channel();
            let (delete_sender_tcp, delete_recv_tcp) = mpsc::channel();
            let (add_sender_ns_udp, add_recv_ns_udp) = mpsc::channel();
            let (delete_sender_ns_udp, delete_recv_ns_udp) = mpsc::channel();
            let (add_sender_ns_tcp, add_recv_ns_tcp) = mpsc::channel();
            let (delete_sender_ns_tcp, delete_recv_ns_tcp) = mpsc::channel();
            let (update_cache_sender_ns_udp, rx_update_cache_ns_udp) = mpsc::channel();
            let (update_cache_sender_ns_tcp, rx_update_cache_ns_tcp) = mpsc::channel();

            let mut name_server = NameServer::new(
                false,
                delete_sender_udp.clone(),
                delete_sender_tcp.clone(),
                add_sender_ns_udp.clone(),
                delete_sender_ns_udp.clone(),
                add_sender_ns_tcp.clone(),
                delete_sender_ns_tcp.clone(),
            );

            name_server.add_zone_from_master_file(master_files_names[2].clone(), "".to_string());

            thread::spawn(move || {
                name_server.run_name_server(
                    CHILD_IP_PORT.to_string(),
                    RESOLVER_IP_PORT.to_string(),
                    add_recv_ns_udp,
                    delete_recv_ns_udp,
                    add_recv_ns_tcp,
                    delete_recv_ns_tcp,
                    rx_update_cache_ns_udp,
                    rx_update_cache_ns_tcp,
                );
            });

            // Sleep
            let ten_millis = Duration::from_millis(1000);

            thread::sleep(ten_millis);
        }

        let response_time_second = client::run_client(SECOND_QUERY.clone(), 1, 1);

        // Sending Udp msg to kill resolver
        let socket = UdpSocket::bind("192.168.1.90:58402").expect("couldn't bind to address");
        socket
            .send_to(&[1; 50], RESOLVER_IP_PORT)
            .expect("couldn't send data");

        // Sending TCP msg to kill resolver

        let mut stream = TcpStream::connect(RESOLVER_IP_PORT).expect("couldn't connect to address");

        stream.write(&[1; 50]);

        // Save response time

        let mut times_vec = response_times.get(&FIRST_QUERY).unwrap().clone();
        times_vec.push(response_time_first.as_millis());
        response_times.insert(FIRST_QUERY.clone(), times_vec.to_vec());

        let mut times_vec = response_times.get(&SECOND_QUERY).unwrap().clone();
        times_vec.push(response_time_second.as_millis());
        response_times.insert(SECOND_QUERY.clone(), times_vec.to_vec());
    }

    // Sending Udp msg to kill child name server
    let socket = UdpSocket::bind("192.168.1.90:58402").expect("couldn't bind to address");
    socket
        .send_to(&[1; 50], CHILD_IP_PORT)
        .expect("couldn't send data");

    // Sending TCP msg to kill child name server
    let mut stream = TcpStream::connect(CHILD_IP_PORT).expect("couldn't connect to address");

    stream.write(&[1; 50]);

    // Sleep
    let ten_millis = Duration::from_millis(1000);

    thread::sleep(ten_millis);

    // Add the results to a new file
    let mut new_file_name = "missconfigured_case_".to_string();
    new_file_name.push_str(case.to_string().as_str());
    new_file_name.push_str("_results.txt");

    // Creates file
    let mut new_file = File::create(new_file_name.as_str());

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
                .open(new_file_name.as_str())
                .unwrap();

            write!(file, "{}", new_line.as_str());
        }
    }
}
