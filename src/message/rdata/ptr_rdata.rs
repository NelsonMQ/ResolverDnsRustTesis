use crate::domain_name::DomainName;
use crate::message::rdata::Rdata;
use crate::message::resource_record::{FromBytes, ResourceRecord, ToBytes};
use std::str::SplitWhitespace;

#[derive(Clone)]
/// An struct that represents the rdata for ptr type
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// /                   PTRDNAME                    /
/// /                                               /
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///
pub struct PtrRdata {
    // A domain name which points to some location in the
    // domain name space.
    ptrdname: DomainName,
}

impl ToBytes for PtrRdata {
    /// Return a vec of bytes that represents the ptr rdata
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::new();
        let ptrdname = self.get_ptrdname();
        let ptrdname_bytes = ptrdname.to_bytes();

        for byte in ptrdname_bytes.as_slice() {
            bytes.push(*byte);
        }

        bytes
    }
}

impl FromBytes<Result<Self, &'static str>> for PtrRdata {
    /// Creates a new PtrRdata from an array of bytes
    fn from_bytes(bytes: &[u8], full_msg: &[u8]) -> Result<Self, &'static str> {
        let bytes_len = bytes.len();

        if bytes_len < 2 {
            return Err("Format Error");
        }

        let domain_name_result = DomainName::from_bytes(bytes, full_msg);

        match domain_name_result {
            Ok(_) => {}
            Err(e) => {
                return Err(e);
            }
        }

        let mut ptr_rdata = PtrRdata::new();
        let (domain_name, _) = domain_name_result.unwrap();

        ptr_rdata.set_ptrdname(domain_name);

        Ok(ptr_rdata)
    }
}

impl PtrRdata {
    /// Creates a new PtrRdata with default values.
    ///
    /// # Examples
    /// ```
    /// let ptr_rdata = PtrRdata::new();
    ///
    /// assert_eq!(ptr_rdata.ptrdname.get_name(), String::from(""));
    /// ```
    ///
    pub fn new() -> Self {
        let ptr_rdata = PtrRdata {
            ptrdname: DomainName::new(),
        };

        ptr_rdata
    }

    // Creates an RR from a master file
    pub fn rr_from_master_file(
        mut values: SplitWhitespace,
        ttl: u32,
        class: u16,
        host_name: String,
        origin: String,
    ) -> ResourceRecord {
        let mut ptr_rdata = PtrRdata::new();
        let name = values.next().unwrap();
        let domain_name = DomainName::from_master_file(name.to_string(), origin);

        ptr_rdata.set_ptrdname(domain_name);

        let rdata = Rdata::SomePtrRdata(ptr_rdata);

        let mut resource_record = ResourceRecord::new(rdata);

        let mut domain_name = DomainName::new();
        domain_name.set_name(host_name);

        resource_record.set_name(domain_name);
        resource_record.set_type_code(12);
        resource_record.set_class(class);
        resource_record.set_ttl(ttl);
        resource_record.set_rdlength(name.len() as u16 + 2);

        resource_record
    }
}

// Getters
impl PtrRdata {
    // Gets the ptrdname attribute from PtrRdata
    pub fn get_ptrdname(&self) -> DomainName {
        self.ptrdname.clone()
    }
}

// Setters
impl PtrRdata {
    // Sets the ptrdname attibute with a value
    pub fn set_ptrdname(&mut self, ptrdname: DomainName) {
        self.ptrdname = ptrdname;
    }
}
