use crate::client;
use crate::resolver::resolver_query::ResolverQuery;
use crate::resolver::slist::Slist;
use crate::resolver::Resolver;

use crate::config::RESOLVER_IP_PORT;
use crate::config::SBELT_ROOT_IPS;
use crate::config::SBELT_ROOT_NAMES;

use std::collections::HashMap;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::BufRead;
use std::io::BufReader;
use std::io::Write;
use std::net::TcpStream;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

// IP Config in order to kill resolvers
pub static IP_TO_KILL_RESOLVER: &'static str = "192.168.1.90";
pub static ROOT_NAMESERVER_IP_PORT: &'static str = "192.168.1.90:58398";
pub static CHILD_NAMESERVER_IP_PORT: &'static str = "192.168.1.90:58399";

// Numero iteraciones
pub static ITERATIONS_NUMBER: i32 = 384;

/// Execute the response time experiment
pub fn response_time_experiment(filename: String, new_algorithm: bool, new_file_name: String) {
    // Open file
    let file = File::open(filename).expect("file not found!");
    let reader = BufReader::new(file);

    // Read lines
    for line in reader.lines() {
        let line = line.unwrap();

        // Ask for the website ip 10 times
        let mut i = 0;

        while i < ITERATIONS_NUMBER {
            // Sleep
            let ten_millis = Duration::from_millis(100);
            thread::sleep(ten_millis);

            // Run the resolver (the resolver should not save cache)
            // Channels
            let (add_sender_udp, add_recv_udp) = mpsc::channel();
            let (delete_sender_udp, delete_recv_udp) = mpsc::channel();

            let (update_cache_sender_udp, rx_update_cache_udp) = mpsc::channel();

            let mut resolver = Resolver::new(
                add_sender_udp.clone(),
                delete_sender_udp.clone(),
                update_cache_sender_udp.clone(),
                new_algorithm,
            );

            resolver.set_ip_address(RESOLVER_IP_PORT.to_string());

            let mut sbelt = Slist::new();

            for i in 0..SBELT_ROOT_IPS.len() {
                sbelt.insert(
                    SBELT_ROOT_NAMES[i].to_string(),
                    SBELT_ROOT_IPS[i].to_string(),
                    5000,
                );
            }

            resolver.set_sbelt(sbelt);

            thread::spawn(move || {
                resolver.run_resolver(add_recv_udp, delete_recv_udp, rx_update_cache_udp, true);
            });

            ///////

            // Sleep
            let ten_millis = Duration::from_millis(100);

            thread::sleep(ten_millis);

            let (response_time, _, _, mut answers_ip) = client::run_client(line.clone(), 1, 1);

            // Sending Udp msg to kill resolver
            let socket =
                ResolverQuery::initilize_socket_udp(IP_TO_KILL_RESOLVER.to_string()).unwrap();

            socket
                .send_to(&[1; 50], RESOLVER_IP_PORT)
                .expect("Couldn't send data to kill resolver");

            // Sleep
            //let ten_millis = Duration::from_millis(1000);
            //thread::sleep(ten_millis);

            // Save response time
            // Open the file to append
            let mut file = OpenOptions::new()
                .write(true)
                .append(true)
                .open(new_file_name.as_str())
                .unwrap();

            // Write domain name and response time
            write!(file, "{} {}", line.clone(), response_time.as_micros())
                .expect("Couldn't write file");

            // Sort answers
            answers_ip.sort();

            // Write answers
            for answer in &answers_ip {
                write!(file, " {}", answer).expect("Couldn't write file");
            }

            // Write new line
            write!(file, "\n").expect("Couldn't write file");

            i = i + 1;

            println!("Fin iteración");
        }
    }
}

// Tests the missconfigured cases
pub fn missconfigured_experiments(case: u8, master_files_names: Vec<String>, new_algorithm: bool) {
    let root_master_file = master_files_names[0].clone();
    let child_master_file = master_files_names[1].clone();
    let first_query = "dcc.cl".to_string();
    let second_query = "dcc.cl".to_string();

    // Hash to save response times (0 response time means Temporary Error)
    let mut response_times = HashMap::<String, Vec<u128>>::new();
    let times_vec = Vec::new();

    // Add an empty vec to hashmap
    response_times.insert(first_query.clone(), times_vec.clone());
    response_times.insert(second_query.clone(), times_vec);

    for i in 0..5 {
        if new_algorithm {}

        // Sleep
        let ten_millis = Duration::from_millis(1000);
        thread::sleep(ten_millis);

        // Run the resolver (the resolver should not save cache)
        // Channels
        let (add_sender_udp, add_recv_udp) = mpsc::channel();
        let (delete_sender_udp, delete_recv_udp) = mpsc::channel();

        let (update_cache_sender_udp, rx_update_cache_udp) = mpsc::channel();

        let mut resolver = Resolver::new(
            add_sender_udp.clone(),
            delete_sender_udp.clone(),
            update_cache_sender_udp.clone(),
            new_algorithm,
        );

        resolver.set_ip_address(RESOLVER_IP_PORT.to_string());

        let mut sbelt = Slist::new();

        for i in 0..SBELT_ROOT_IPS.len() {
            sbelt.insert(
                SBELT_ROOT_NAMES[i].to_string(),
                SBELT_ROOT_IPS[i].to_string(),
                5000,
            );
        }

        resolver.set_sbelt(sbelt);

        thread::spawn(move || {
            resolver.run_resolver(add_recv_udp, delete_recv_udp, rx_update_cache_udp, false);
        });

        // Sleep
        let ten_millis = Duration::from_millis(1000);
        thread::sleep(ten_millis);

        let (response_time_first, _, _, _) = client::run_client(first_query.clone(), 1, 1);

        // Case 5 is case 3 for new algorithm
        if case == 5 {
            thread::sleep(ten_millis);

            // Sending Udp msg to kill child name server
            let socket =
                ResolverQuery::initilize_socket_udp(IP_TO_KILL_RESOLVER.to_string()).unwrap();
            socket
                .send_to(&[1; 50], CHILD_NAMESERVER_IP_PORT)
                .expect("Couldn't kill udp child nameserver");

            // Sleep
            let ten_millis = Duration::from_millis(1000);
            thread::sleep(ten_millis);
        }
        // Sleep
        let ten_millis = Duration::from_millis(2000);
        thread::sleep(ten_millis);

        let (response_time_second, _, _, _) = client::run_client(second_query.clone(), 1, 1);

        // Sending Udp msg to kill resolver
        let socket = ResolverQuery::initilize_socket_udp(IP_TO_KILL_RESOLVER.to_string()).unwrap();
        socket
            .send_to(&[1; 50], RESOLVER_IP_PORT)
            .expect("couldn't send data");

        // Sending Udp msg to kill child name server
        let socket = ResolverQuery::initilize_socket_udp(IP_TO_KILL_RESOLVER.to_string()).unwrap();
        socket
            .send_to(&[1; 50], CHILD_NAMESERVER_IP_PORT)
            .expect("couldn't send data");

        // Save response time

        let mut times_vec = response_times.get(&first_query).unwrap().clone();
        times_vec.push(response_time_first.as_millis());
        response_times.insert(first_query.clone(), times_vec.to_vec());

        let mut times_vec = response_times.get(&second_query).unwrap().clone();
        times_vec.push(response_time_second.as_millis());
        response_times.insert(second_query.clone(), times_vec.to_vec());
    }

    // Sleep
    let ten_millis = Duration::from_millis(1000);
    thread::sleep(ten_millis);

    // Add the results to a new file
    let mut new_file_name = "missconfigured_case_".to_string();
    new_file_name.push_str(case.to_string().as_str());

    if new_algorithm {
        new_file_name.push_str("_na_");
    }

    new_file_name.push_str("_results.txt");

    // Creates file
    File::create(new_file_name.as_str()).expect("Couldn't create new file");

    // Iterate results.
    for (domain, result_vec) in &response_times {
        for time in result_vec {
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

            write!(file, "{}", new_line.as_str()).expect("Couldn't write file");
        }
    }
}

pub fn missconfigured_experiment_nxdomain(case: u8, new_algorithm: bool) {
    let first_query = "test-ns-validation-iegae8ey.cl".to_string();
    let second_query = "sub.test-ns-validation-iegae8ey.cl".to_string();

    // Hash to save response times (0 response time means Temporary Error)
    let mut response_times = HashMap::<String, Vec<u128>>::new();
    let times_vec = Vec::new();

    // Add an empty vec to hashmap
    response_times.insert(first_query.clone(), times_vec.clone());
    response_times.insert(second_query.clone(), times_vec);

    for _i in 0..5 {
        // Run the resolver (the resolver should not save cache)
        // Channels
        let (add_sender_udp, add_recv_udp) = mpsc::channel();
        let (delete_sender_udp, delete_recv_udp) = mpsc::channel();

        let (update_cache_sender_udp, rx_update_cache_udp) = mpsc::channel();

        let mut resolver = Resolver::new(
            add_sender_udp.clone(),
            delete_sender_udp.clone(),
            update_cache_sender_udp.clone(),
            new_algorithm,
        );

        resolver.set_ip_address(RESOLVER_IP_PORT.to_string());

        let mut sbelt = Slist::new();

        for i in 0..SBELT_ROOT_IPS.len() {
            sbelt.insert(
                SBELT_ROOT_NAMES[i].to_string(),
                SBELT_ROOT_IPS[i].to_string(),
                5000,
            );
        }

        resolver.set_sbelt(sbelt);

        thread::spawn(move || {
            resolver.run_resolver(add_recv_udp, delete_recv_udp, rx_update_cache_udp, false);
        });

        // Sleep
        let ten_millis = Duration::from_millis(1000);
        thread::sleep(ten_millis);

        let (response_time_first, _, _, _) = client::run_client(first_query.clone(), 1, 1);

        // Sleep
        let ten_millis = Duration::from_millis(1000);
        thread::sleep(ten_millis);

        let (response_time_second, _, _, _) = client::run_client(second_query.clone(), 1, 1);

        // Sending Udp msg to kill resolver
        let socket = ResolverQuery::initilize_socket_udp(IP_TO_KILL_RESOLVER.to_string()).unwrap();
        socket
            .send_to(&[1; 50], RESOLVER_IP_PORT)
            .expect("couldn't send data");

        // Save response time

        let mut times_vec = response_times.get(&first_query).unwrap().clone();
        times_vec.push(response_time_first.as_millis());
        response_times.insert(first_query.clone(), times_vec.to_vec());

        let mut times_vec = response_times.get(&second_query).unwrap().clone();
        times_vec.push(response_time_second.as_millis());
        response_times.insert(second_query.clone(), times_vec.to_vec());
    }

    // Sleep
    let ten_millis = Duration::from_millis(1000);
    thread::sleep(ten_millis);

    // Add the results to a new file
    let mut new_file_name = "missconfigured_case_".to_string();
    new_file_name.push_str(case.to_string().as_str());

    if new_algorithm {
        new_file_name.push_str("_na_");
    }

    new_file_name.push_str("_results.txt");

    // Creates file
    File::create(new_file_name.as_str()).expect("Could't create new file");

    // Iterate results.
    for (domain, result_vec) in &response_times {
        for time in result_vec {
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

            write!(file, "{}", new_line.as_str()).expect("Couldn't write file");
        }
    }
}

// Writes a file with the domains and their ns records from a zone file
pub fn get_domains_and_ns_records_from_zone_file(filename: String, new_file_name: String) {
    // Open file
    let file = File::open(filename).expect("file not found!");
    let reader = BufReader::new(file);

    // Save last domain
    let mut last_domain = "".to_string();

    let mut first_line = true;

    // Read lines
    for line in reader.lines() {
        let new_line = line.unwrap();

        //Split whitespace
        let elements: Vec<String> = new_line.split_whitespace().map(String::from).collect();

        // Domain name
        let domain_name = elements[0].clone();

        // Record type
        let record_type = elements[3].clone();

        // NS data
        let ns_data = elements[4].clone();

        // Save NS only
        if record_type == "NS".to_string() {
            // Open the file to append
            let mut file = OpenOptions::new()
                .write(true)
                .append(true)
                .open(new_file_name.clone())
                .unwrap();

            // Just write the last ns data
            if domain_name == last_domain {
                write!(file, " {}", ns_data.to_string()).expect("Couldn't write file");
            } else {
                // Add the domain and ns data
                last_domain = domain_name.clone();

                if first_line {
                    first_line = false;
                    write!(file, "{} {}", domain_name.to_string(), ns_data.to_string())
                        .expect("Couldn't write file");
                } else {
                    write!(
                        file,
                        "\n{} {}",
                        domain_name.to_string(),
                        ns_data.to_string()
                    )
                    .expect("Couldn't write file");
                }
            }
        }
    }
}

// Gets and writes the ns records from the child zone for each domain
pub fn get_ns_records_from_child_zone(domains_file: String, save_file: String) {
    // Open file
    let file = File::open(domains_file).expect("file not found!");
    let reader = BufReader::new(file);

    // Run resolver
    // Channels
    let (add_sender_udp, add_recv_udp) = mpsc::channel();
    let (delete_sender_udp, delete_recv_udp) = mpsc::channel();

    let (update_cache_sender_udp, rx_update_cache_udp) = mpsc::channel();

    let mut resolver = Resolver::new(
        add_sender_udp.clone(),
        delete_sender_udp.clone(),
        update_cache_sender_udp.clone(),
        false,
    );

    resolver.set_ip_address(RESOLVER_IP_PORT.to_string());

    let mut sbelt = Slist::new();

    for i in 0..SBELT_ROOT_IPS.len() {
        sbelt.insert(
            SBELT_ROOT_NAMES[i].to_string(),
            SBELT_ROOT_IPS[i].to_string(),
            5000,
        );
    }

    resolver.set_sbelt(sbelt);

    thread::spawn(move || {
        resolver.run_resolver(add_recv_udp, delete_recv_udp, rx_update_cache_udp, true);
    });

    // Sleep
    let ten_millis = Duration::from_millis(1000);
    thread::sleep(ten_millis);

    let mut first_line = true;

    // Read lines
    for line in reader.lines() {
        let new_line = line.unwrap();

        //Split whitespace
        let elements: Vec<String> = new_line.split_whitespace().map(String::from).collect();

        // Domain name
        let mut domain_name = elements[0].clone();

        // Pop last dot
        domain_name.pop();

        // Get NS records
        let (_, ns_records, temporary_error, _) = client::run_client(domain_name.clone(), 1, 2);

        if !temporary_error {
            // Open the file to append
            let mut file = OpenOptions::new()
                .write(true)
                .append(true)
                .open(save_file.clone())
                .unwrap();

            if first_line {
                // Write domain
                write!(file, "{}", domain_name.clone()).expect("Couldn't write file");

                first_line = false;
            } else {
                // Write domain
                write!(file, "\n{}", domain_name.clone()).expect("Couldn't write file");
            }

            for ns in ns_records {
                // Write ns records
                write!(file, " {}", ns.to_string()).expect("Couldn't write file");
            }
        } else {
            // Open the file to append
            let mut file = OpenOptions::new()
                .write(true)
                .append(true)
                .open("ns_temporary_error.txt".clone())
                .unwrap();

            write!(file, "{}\n", domain_name.clone()).expect("Couldn't write file");

            // Sending Udp msg to kill child name server
            let socket =
                ResolverQuery::initilize_socket_udp(IP_TO_KILL_RESOLVER.to_string()).unwrap();
            socket
                .send_to(&[1; 50], RESOLVER_IP_PORT)
                .expect("couldn't send data");

            // Sleep
            let ten_millis = Duration::from_millis(1000);
            thread::sleep(ten_millis);

            // Run resolver
            // Channels
            let (add_sender_udp, add_recv_udp) = mpsc::channel();
            let (delete_sender_udp, delete_recv_udp) = mpsc::channel();
            let (update_cache_sender_udp, rx_update_cache_udp) = mpsc::channel();

            let mut resolver = Resolver::new(
                add_sender_udp.clone(),
                delete_sender_udp.clone(),
                update_cache_sender_udp.clone(),
                false,
            );

            resolver.set_ip_address(RESOLVER_IP_PORT.to_string());

            let mut sbelt = Slist::new();

            for i in 0..SBELT_ROOT_IPS.len() {
                sbelt.insert(
                    SBELT_ROOT_NAMES[i].to_string(),
                    SBELT_ROOT_IPS[i].to_string(),
                    5000,
                );
            }

            resolver.set_sbelt(sbelt);

            thread::spawn(move || {
                resolver.run_resolver(add_recv_udp, delete_recv_udp, rx_update_cache_udp, true);
            });

            // Sleep
            let ten_millis = Duration::from_millis(1000);
            thread::sleep(ten_millis);
        }
    }
}

//Compares the ns records from the parent zone with the child zone
pub fn compare_parent_and_child_ns_records(
    parent_ns_file: String,
    child_ns_file: String,
    save_file: String,
) {
    // Open parent ns file
    let parent_file = File::open(parent_ns_file).expect("file not found!");
    let mut parent_reader = BufReader::new(parent_file);

    // Open child ns file
    let child_file = File::open(child_ns_file).expect("file not found!");
    let mut child_reader = BufReader::new(child_file);

    // Creates a buffer to save lines
    let mut parent_line = String::new();
    let mut child_line = String::new();

    // Read the first line for each file
    let mut len_parent_line = parent_reader.read_line(&mut parent_line).unwrap();
    let mut len_child_line = child_reader.read_line(&mut child_line).unwrap();

    while len_parent_line != 0 && len_child_line != 0 {
        // Split lines
        let parent_elements: Vec<String> =
            parent_line.split_whitespace().map(String::from).collect();
        let child_elements: Vec<String> = child_line.split_whitespace().map(String::from).collect();

        // Get Domain names
        let domain_name_from_parent_file = parent_elements[0].clone();
        let domain_name_from_child_file = child_elements[0].clone();

        // Get ns records
        let mut ns_records_from_parent = parent_elements[1..].to_vec().clone();
        let mut ns_records_from_child = child_elements[1..].to_vec().clone();

        // Sort vectors
        ns_records_from_parent.sort();
        ns_records_from_child.sort();

        // Remove duplicates
        ns_records_from_parent.dedup();
        ns_records_from_child.dedup();

        // Get vectors len
        let parent_ns_len = ns_records_from_parent.len();
        let child_ns_len = ns_records_from_child.len();

        if parent_ns_len != child_ns_len {
            // Open the file to append
            let mut file = OpenOptions::new()
                .write(true)
                .append(true)
                .open(save_file.clone())
                .unwrap();

            write!(
                file,
                "{} {}\n",
                domain_name_from_parent_file, domain_name_from_child_file
            )
            .expect("Couldn't write file");
        } else {
            for ns in ns_records_from_child {
                if ns_records_from_parent.contains(&ns) == false {
                    // Open the file to append
                    let mut file = OpenOptions::new()
                        .write(true)
                        .append(true)
                        .open(save_file.clone())
                        .unwrap();

                    write!(
                        file,
                        "{} {}\n",
                        domain_name_from_parent_file, domain_name_from_child_file
                    )
                    .expect("Couldn't write file");

                    break;
                }
            }
        }

        // Clear buffer
        parent_line = String::new();
        child_line = String::new();

        // Read following lines
        len_parent_line = parent_reader.read_line(&mut parent_line).unwrap();
        len_child_line = child_reader.read_line(&mut child_line).unwrap();
    }
}

// Asks fro the domains and save the affected domains
pub fn find_affected_domains_experiment(
    input_domains_file: String,
    output_affected_domains_file: String,
    new_algorithm: bool,
) {
    // Read the domains file
    // Open file
    let file = File::open(input_domains_file).expect("file not found!");
    let reader = BufReader::new(file);

    // Read lines
    for line in reader.lines() {
        // Run the resolver (the resolver should not save cache)
        // Channels

        let (add_sender_udp, add_recv_udp) = mpsc::channel();
        let (delete_sender_udp, delete_recv_udp) = mpsc::channel();
        let (update_cache_sender_udp, rx_update_cache_udp) = mpsc::channel();

        let mut resolver = Resolver::new(
            add_sender_udp.clone(),
            delete_sender_udp.clone(),
            update_cache_sender_udp.clone(),
            new_algorithm,
        );

        resolver.set_ip_address(RESOLVER_IP_PORT.to_string());

        let mut sbelt = Slist::new();

        for i in 0..SBELT_ROOT_IPS.len() {
            sbelt.insert(
                SBELT_ROOT_NAMES[i].to_string(),
                SBELT_ROOT_IPS[i].to_string(),
                5000,
            );
        }

        resolver.set_sbelt(sbelt);

        thread::spawn(move || {
            resolver.run_resolver(add_recv_udp, delete_recv_udp, rx_update_cache_udp, false);
        });

        // Sleep
        let ten_millis = Duration::from_millis(500);
        thread::sleep(ten_millis);

        let new_line = line.unwrap();

        //Split whitespace
        let elements: Vec<String> = new_line.split_whitespace().map(String::from).collect();

        // Domain name
        let domain_name = elements[0].clone();

        // Query to get NS records from parent zone
        let (response_time_first, _, _, _) = client::run_client(domain_name.clone(), 1, 1);

        if new_algorithm {
            // Sleep
            let ten_millis = Duration::from_millis(5000);

            thread::sleep(ten_millis);
        }

        // Second query to test the missconfigured domain
        let (response_time_second, _, _, _) = client::run_client(domain_name.clone(), 1, 1);

        // Sending Udp msg to kill resolver
        let socket = ResolverQuery::initilize_socket_udp(IP_TO_KILL_RESOLVER.to_string()).unwrap();
        socket
            .send_to(&[1; 50], RESOLVER_IP_PORT)
            .expect("couldn't send data");

        // Open the file to append
        let mut file = OpenOptions::new()
            .write(true)
            .append(true)
            .open(output_affected_domains_file.clone())
            .unwrap();

        // Write info
        write!(
            file,
            "{} {} {}\n",
            domain_name,
            response_time_first.as_millis(),
            response_time_second.as_millis()
        )
        .expect("Couldn't write file");

        // Sleep
        let ten_millis = Duration::from_millis(3000);
        thread::sleep(ten_millis);
    }
}

// Asks for the domain with the especific resolver algorithm
fn test_affected_domain_algorithm(domain_name: String, new_algorithm: bool) -> Vec<Duration> {
    let (add_sender_udp, add_recv_udp) = mpsc::channel();
    let (delete_sender_udp, delete_recv_udp) = mpsc::channel();
    let (update_cache_sender_udp, rx_update_cache_udp) = mpsc::channel();

    let mut resolver = Resolver::new(
        add_sender_udp.clone(),
        delete_sender_udp.clone(),
        update_cache_sender_udp.clone(),
        new_algorithm,
    );

    resolver.set_ip_address(RESOLVER_IP_PORT.to_string());

    let mut sbelt = Slist::new();

    for i in 0..SBELT_ROOT_IPS.len() {
        sbelt.insert(
            SBELT_ROOT_NAMES[i].to_string(),
            SBELT_ROOT_IPS[i].to_string(),
            5000,
        );
    }

    resolver.set_sbelt(sbelt);

    thread::spawn(move || {
        resolver.run_resolver(add_recv_udp, delete_recv_udp, rx_update_cache_udp, false);
    });

    // Sleep
    let ten_millis = Duration::from_millis(500);
    thread::sleep(ten_millis);

    // Query to get NS records from parent zone
    let (response_time_first, _, _, _) = client::run_client(domain_name.clone(), 1, 1);

    if new_algorithm {
        // Sleep
        let ten_millis = Duration::from_millis(5000);
        thread::sleep(ten_millis);
    }

    // Second query to test the missconfigured domain
    let (response_time_second, _, _, _) = client::run_client(domain_name.clone(), 1, 1);

    // Sending Udp msg to kill resolver
    let socket = ResolverQuery::initilize_socket_udp(IP_TO_KILL_RESOLVER.to_string()).unwrap();
    socket
        .send_to(&[1; 50], RESOLVER_IP_PORT)
        .expect("couldn't send data");

    // Sleep
    let ten_millis = Duration::from_millis(3000);
    thread::sleep(ten_millis);

    // Response times vector
    let mut times_vector = Vec::new();

    times_vector.push(response_time_first);
    times_vector.push(response_time_second);

    return times_vector;
}

// Checks if a domain will be an affected domain
pub fn is_affected_domain(domain_name: String) -> bool {
    //let times_parent_algorithm = test_affected_domain_algorithm(domain_name.clone(), false);
    let times_child_algorithm = test_affected_domain_algorithm(domain_name.clone(), true);

    if times_child_algorithm[1].is_zero() {
        return true;
    } else {
        return false;
    }
}

pub fn check_affected_domains(first_file: String, second_file: String, new_file: String) {
    // Read the domains file
    // Open file
    let file = File::open(first_file).expect("file not found!");
    let reader = BufReader::new(file);

    let mut domains: Vec<String> = Vec::new();

    // Read lines
    for line in reader.lines() {
        let new_line = line.unwrap();

        domains.push(new_line);
    }

    /*
    // Read the domains file
    // Open file
    let file = File::open(second_file).expect("file not found!");
    let reader = BufReader::new(file);

    // Read lines
    for line in reader.lines() {
        let new_line = line.unwrap();

        domains.push(new_line);
    }
     */

    for i in domains {
        let affected = is_affected_domain(i.clone());

        // Open the file to append
        let mut file = OpenOptions::new()
            .write(true)
            .append(true)
            .open(new_file.clone())
            .unwrap();

        // Write info
        write!(file, "{} {}\n", i.clone(), affected).expect("Couldn't write file");
    }
}
