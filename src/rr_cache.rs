use crate::message::rdata::Rdata;
use crate::message::resource_record::ResourceRecord;
use chrono::prelude::*;

#[derive(Clone)]
/// An structs that represents one element in the dns cache.
pub struct RRCache {
    // Resource Records of the domain name
    resource_record: ResourceRecord,
    // Mean of response time of the ip address
    response_time: u32,
    // Last use of the rr
    last_use: DateTime<Utc>,
    // Data ranking from RFC 2181
    data_ranking: u8,
    // NXDOMAIN
    nxdomain: bool,
    // NODATA
    no_data: bool,
    //Domain name
    domain_name: String,
}

impl RRCache {
    /// Creates a new RRCache struct
    ///
    /// # Examples
    /// '''
    /// let rr_cache = RRCache::new();
    ///
    /// assert_eq!(rr_cache.resource_records.len(), 0);
    /// assert_eq!(rr_cache.response_time, 5);
    /// '''
    ///
    pub fn new(
        resource_record: ResourceRecord,
        data_ranking: u8,
        nxdomain: bool,
        no_data: bool,
    ) -> Self {
        let mut rdata = "".to_string();
        if resource_record.get_type_code() == 2 {
            let rdata_object = match resource_record.get_rdata() {
                Rdata::SomeNsRdata(val) => val.clone(),
                _ => unreachable!(),
            };

            rdata = rdata_object.get_nsdname().get_name();
        }

        let rr_cache = RRCache {
            resource_record: resource_record,
            response_time: 5000,
            last_use: Utc::now(),
            data_ranking: data_ranking,
            nxdomain: nxdomain,
            no_data: no_data,
            domain_name: rdata.to_string(),
        };

        rr_cache
    }
}

// Getters
impl RRCache {
    // Gets the resource record from the domain cache
    pub fn get_resource_record(&self) -> ResourceRecord {
        self.resource_record.clone()
    }

    // Gets the mean response time of the ip address of the domain name
    pub fn get_response_time(&self) -> u32 {
        self.response_time
    }

    // Gets the last use of the domain in cache
    pub fn get_last_use(&self) -> DateTime<Utc> {
        self.last_use
    }

    // Gets the data ranking in cache
    pub fn get_data_ranking(&self) -> u8 {
        self.data_ranking
    }

    // Gets nxdomain field
    pub fn get_nxdomain(&self) -> bool {
        self.nxdomain
    }

    // Gets no_data field
    pub fn get_no_data(&self) -> bool {
        self.no_data
    }

    // Gets domain_name field
    pub fn get_domain_name(&self) -> String {
        self.domain_name.clone()
    }
}

// Setters
impl RRCache {
    // Sets the resource record attribute with new value
    pub fn set_resource_record(&mut self, resource_record: ResourceRecord) {
        self.resource_record = resource_record;
    }

    // Sets the response time attribute with new value
    pub fn set_response_time(&mut self, response_time: u32) {
        self.response_time = response_time;
    }

    // Sets the last use attribute with new value
    pub fn set_last_use(&mut self, last_use: DateTime<Utc>) {
        self.last_use = last_use;
    }

    // Sets the data ranking attribute with new value
    pub fn set_data_ranking(&mut self, data_ranking: u8) {
        self.data_ranking = data_ranking;
    }

    // Sets nxdomain attribute
    pub fn set_nxdomain(&mut self, nxdomain: bool) {
        self.nxdomain = nxdomain;
    }

    // Sets no_data attribute
    pub fn set_no_data(&mut self, no_data: bool) {
        self.no_data = no_data;
    }
}
