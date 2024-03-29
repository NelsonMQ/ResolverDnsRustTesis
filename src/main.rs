pub mod client;
pub mod config;
pub mod dns_cache;
pub mod domain_name;
pub mod experiments;
pub mod message;
pub mod resolver;
pub mod rr_cache;

use crate::resolver::slist::Slist;
use crate::resolver::Resolver;

use std::sync::mpsc;

use crate::config::RESOLVER_IP_PORT;
use crate::config::SBELT_ROOT_IPS;
use crate::config::SBELT_ROOT_NAMES;

pub fn main() {
    // Users input
    let mut input_line = String::new();
    println!("Enter program to run [C/R/TRE/MCC1/MCC2/MCC3/MCC4/MCCZ1/MCCZ2/MCCZ3/MCD]\n - C: Dns client \n - R: Dns resolver \n - TRE: Time Response Experiment \n - MCCX: MissConfigured Case X \n - MCCZX: MissConfigured Zone Experiment number X \n - MCD: MissConfigured Domains Experiment");
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

        client::run_client(host_name.to_string(), qclass, qtype);
    } else if trim_input_line == "TRE" {
        experiments::response_time_experiment(
            "websites.txt".to_string(),
            false,
            "time_results.txt".to_string(),
        );
    } else if trim_input_line == "TRENA" {
        experiments::response_time_experiment(
            "websites.txt".to_string(),
            true,
            "time_results_na.txt".to_string(),
        );
    } else if trim_input_line == "MCC1" {
        let master_files_case_1 = [
            "root_case_1.txt".to_string(),
            "child_case_1.txt".to_string(),
        ]
        .to_vec();

        experiments::missconfigured_experiments(1, master_files_case_1, false);
    } else if trim_input_line == "MCC1NA" {
        let master_files_case_1 = [
            "root_case_1.txt".to_string(),
            "child_case_1.txt".to_string(),
        ]
        .to_vec();

        experiments::missconfigured_experiments(1, master_files_case_1, true);
    } else if trim_input_line == "MCC2" {
        let master_files_case_2 = [
            "root_case_2.txt".to_string(),
            "child_case_2.txt".to_string(),
        ]
        .to_vec();

        experiments::missconfigured_experiments(2, master_files_case_2, false);
    } else if trim_input_line == "MCC2NA" {
        let master_files_case_2 = [
            "root_case_2.txt".to_string(),
            "child_case_2.txt".to_string(),
        ]
        .to_vec();

        experiments::missconfigured_experiments(2, master_files_case_2, true);
    } else if trim_input_line == "MCC3" {
        let master_files_case_3 = [
            "root_case_3.txt".to_string(),
            "child_case_3.txt".to_string(),
            "second_child_case_3.txt".to_string(),
        ]
        .to_vec();

        experiments::missconfigured_experiments(3, master_files_case_3, false);
    } else if trim_input_line == "MCC3NA" {
        let master_files_case_3 = [
            "root_case_3.txt".to_string(),
            "child_case_3.txt".to_string(),
            "second_child_case_3.txt".to_string(),
        ]
        .to_vec();

        experiments::missconfigured_experiments(5, master_files_case_3, true);
    } else if trim_input_line == "MCC4" {
        let master_files_case_4 = [
            "root_case_4.txt".to_string(),
            "child_case_4.txt".to_string(),
        ]
        .to_vec();

        experiments::missconfigured_experiments(4, master_files_case_4, false);
    } else if trim_input_line == "MCC4NA" {
        let master_files_case_4 = [
            "root_case_4.txt".to_string(),
            "child_case_4.txt".to_string(),
        ]
        .to_vec();

        experiments::missconfigured_experiments(4, master_files_case_4, true);
    } else if trim_input_line == "MCC5" {
        let master_files_case_5 = [
            "root_case_5.txt".to_string(),
            "child_case_5.txt".to_string(),
        ]
        .to_vec();

        experiments::missconfigured_experiments(6, master_files_case_5, false);
    } else if trim_input_line == "MCC5NA" {
        let master_files_case_5 = [
            "root_case_5.txt".to_string(),
            "child_case_5.txt".to_string(),
        ]
        .to_vec();

        experiments::missconfigured_experiments(6, master_files_case_5, true);
    } else if trim_input_line == "MCC6" {
        experiments::missconfigured_experiment_nxdomain(7, false);
    } else if trim_input_line == "MCC6NA" {
        experiments::missconfigured_experiment_nxdomain(7, true);
    } else if trim_input_line == "MCCZ1" {
        experiments::get_domains_and_ns_records_from_zone_file(
            "CL-20220725.zone".to_string(),
            "zone_ns_records.txt".to_string(),
        );
    } else if trim_input_line == "MCCZ2" {
        experiments::get_ns_records_from_child_zone(
            "zone_ns_records.txt".to_string(),
            "zone_ns_records_child.txt".to_string(),
        );
    } else if trim_input_line == "MCCZ3" {
        experiments::compare_parent_and_child_ns_records(
            "zone_ns_records.txt".to_string(),
            "zone_ns_records_child.txt".to_string(),
            "missconfigured_domains.txt".to_string(),
        );
    } else if trim_input_line == "MCD" {
        experiments::find_affected_domains_experiment(
            "missconfigured_domains.txt".to_string(),
            "affected_domains_results.txt".to_string(),
            false,
        );
    } else if trim_input_line == "MCDNA" {
        experiments::find_affected_domains_experiment(
            "missconfigured_domains.txt".to_string(),
            "affected_domains_results_na.txt".to_string(),
            true,
        );
    } else if trim_input_line == "TEST" {
        let mut input_line = String::new();
        println!("Enter domain: ");
        std::io::stdin().read_line(&mut input_line).unwrap();

        let host_name = input_line.trim();

        let affected = experiments::is_affected_domain(host_name.to_string());
        println!("{}", affected);
    } else if trim_input_line == "VDA" {
        experiments::check_affected_domains(
            "affected_domains_upgrade_ns_credibility_final.txt".to_string(),
            "domain_no_data_response_final.txt".to_string(),
            "verificacion_affected_domains.txt".to_string(),
        );
    } else {
        // Channels
        let (add_sender_udp, add_recv_udp) = mpsc::channel();
        let (delete_sender_udp, delete_recv_udp) = mpsc::channel();
        let (update_cache_sender_udp, rx_update_cache_udp) = mpsc::channel();

        if trim_input_line == "R" {
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

            resolver.run_resolver(add_recv_udp, delete_recv_udp, rx_update_cache_udp, true);
        } else if trim_input_line == "RNA" {
            let mut resolver = Resolver::new(
                add_sender_udp.clone(),
                delete_sender_udp.clone(),
                update_cache_sender_udp.clone(),
                true,
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

            resolver.run_resolver(add_recv_udp, delete_recv_udp, rx_update_cache_udp, false);
        }
    }
}
