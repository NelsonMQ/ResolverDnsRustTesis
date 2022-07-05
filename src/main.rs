pub mod client;
pub mod config;
pub mod dns_cache;
pub mod domain_name;
pub mod experiments;
pub mod global_tests;
pub mod message;
pub mod name_server;
pub mod resolver;
pub mod rr_cache;

use crate::name_server::NameServer;
use crate::resolver::slist::Slist;
use crate::resolver::Resolver;

use std::sync::mpsc;
use std::thread;

use crate::config::MASTER_FILES;
//use crate::config::NAME_SERVER_IP;
use crate::config::RESOLVER_IP_PORT;
use crate::config::SBELT_ROOT_IPS;

pub fn main() {
    // Users input
    let mut input_line = String::new();
    println!("Enter program to run [C/R/N/TRE/MCC]: ");
    std::io::stdin().read_line(&mut input_line).unwrap();

    let trim_input_line = input_line.trim();

    if trim_input_line == "C" {
        // Users input
        let mut input_line = String::new();
        println!("Enter domain: ");
        std::io::stdin().read_line(&mut input_line).unwrap();

        let host_name = input_line.trim();

        let mut input_line = String::new();
        println!("Enter qtype (u16): ");
        std::io::stdin().read_line(&mut input_line).unwrap();

        let qtype = input_line.trim().parse::<u16>().unwrap();

        let mut input_line = String::new();
        println!("Enter qclass (u16): ");
        std::io::stdin().read_line(&mut input_line).unwrap();

        let qclass = input_line.trim().parse::<u16>().unwrap();

        client::run_client(host_name.to_string(), qtype, qclass);
    } else if trim_input_line == "TRE" {
        let mut input_line = String::new();
        println!("Enter file with websites domains: ");
        std::io::stdin().read_line(&mut input_line).unwrap();

        let file_name_experiment = input_line.trim();

        experiments::response_time_experiment(file_name_experiment.to_string());
    } else if trim_input_line == "MCC1" {
        let master_files_case_1 = [
            "root_case_1.txt".to_string(),
            "child_case_1.txt".to_string(),
        ]
        .to_vec();

        experiments::missconfigured_experiments(1, master_files_case_1);
    } else if trim_input_line == "MCC2" {
        let master_files_case_2 = [
            "root_case_2.txt".to_string(),
            "child_case_2.txt".to_string(),
        ]
        .to_vec();

        experiments::missconfigured_experiments(2, master_files_case_2);
    } else if trim_input_line == "MCC3" {
        let master_files_case_3 = [
            "root_case_3.txt".to_string(),
            "child_case_3.txt".to_string(),
            "second_child_case_3.txt".to_string(),
        ]
        .to_vec();

        experiments::missconfigured_experiments(3, master_files_case_3);
    } else if trim_input_line == "MCC4" {
        let master_files_case_4 = [
            "root_case_4.txt".to_string(),
            "child_case_4.txt".to_string(),
        ]
        .to_vec();

        experiments::missconfigured_experiments(4, master_files_case_4);
    } else {
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

        if trim_input_line == "R" {
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

            resolver.run_resolver(
                add_recv_udp,
                delete_recv_udp,
                add_recv_tcp,
                delete_recv_tcp,
                rx_update_cache_udp,
                rx_update_cache_tcp,
                true,
            );
        } else if trim_input_line == "N" {
            let mut input_line = String::new();
            println!("Enter Ip and port: ");
            std::io::stdin().read_line(&mut input_line).unwrap();

            let trim_input_line = input_line.trim();

            let mut name_server = NameServer::new(
                false,
                delete_sender_udp.clone(),
                delete_sender_tcp.clone(),
                add_sender_ns_udp.clone(),
                delete_sender_ns_udp.clone(),
                add_sender_ns_tcp.clone(),
                delete_sender_ns_tcp.clone(),
            );

            let mut input_line = String::new();
            println!("Insert MasterFile name: ");
            std::io::stdin().read_line(&mut input_line).unwrap();

            let master_file = input_line.trim();

            name_server.add_zone_from_master_file(master_file.to_string(), "".to_string());

            name_server.run_name_server(
                trim_input_line.to_string(),
                RESOLVER_IP_PORT.to_string(),
                add_recv_ns_udp,
                delete_recv_ns_udp,
                add_recv_ns_tcp,
                delete_recv_ns_tcp,
                rx_update_cache_ns_udp,
                rx_update_cache_ns_tcp,
            );
        }
    }
}
