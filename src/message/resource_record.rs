use crate::domain_name::DomainName;
use crate::message::rdata::Rdata;

use std::vec::Vec;

#[derive(Clone)]
/// An struct that represents the resource record secction from a dns message
///                               1  1  1  1  1  1
/// 0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                                               |
/// /                                               /
/// /                      NAME                     /
/// |                                               |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                      TYPE                     |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                     CLASS                     |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                      TTL                      |
/// |                                               |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                   RDLENGTH                    |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
/// /                     RDATA                     /
/// /                                               /
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///
pub struct ResourceRecord {
    // Domain Name
    name: DomainName,
    // Specifies the meaning of the data in the RDATA
    type_code: u16,
    // Specifies the class of the data in the RDATA
    class: u16,
    // Specifies the time interval (in seconds) that the resource record may be cached before it should be discarded.
    ttl: u32,
    // Specifies the length in octets of the RDATA field
    rdlength: u16,
    // The format of this information varies according to the TYPE and CLASS of the resource record
    rdata: Rdata,
}

/// Trait to convert struct in bytes
pub trait ToBytes {
    fn to_bytes(&self) -> Vec<u8>;
}

/// Trait to create an struct from bytes
pub trait FromBytes<T> {
    fn from_bytes(bytes: &[u8], full_msg: &[u8]) -> T;
}

// Methods
impl ResourceRecord {
    /// Given a rdata, creates a new ResourceRecord with default values and the rdata.
    /// # Examples
    /// ```
    /// let txt_rdata = Rdata::SomeTxtRdata(TxtRdata::new(String::from("dcc")));
    /// let mut resource_record = ResourceRecord::new(txt_rdata);
    ///
    /// assert_eq!(resource_record.name.get_name(), String::from(""));
    /// assert_eq!(resource_record.type_code, 0);
    /// assert_eq!(resource_record.class, 0);
    /// assert_eq!(resource_record.ttl, 0);
    /// assert_eq!(resource_record.rdlength, 0);
    /// assert_eq!(
    ///    resource_record.rdata.unwrap().get_text(),
    ///    String::from("dcc")
    /// );
    /// ```
    ///

    pub fn new(rdata: Rdata) -> ResourceRecord {
        match rdata {
            Rdata::SomeARdata(val) => ResourceRecord {
                name: DomainName::new(),
                type_code: 1 as u16,
                class: 0 as u16,
                ttl: 0 as u32,
                rdlength: 0 as u16,
                rdata: Rdata::SomeARdata(val),
            },

            Rdata::SomeNsRdata(val) => ResourceRecord {
                name: DomainName::new(),
                type_code: 2 as u16,
                class: 0 as u16,
                ttl: 0 as u32,
                rdlength: 0 as u16,
                rdata: Rdata::SomeNsRdata(val),
            },
            Rdata::SomeCnameRdata(val) => ResourceRecord {
                name: DomainName::new(),
                type_code: 5 as u16,
                class: 0 as u16,
                ttl: 0 as u32,
                rdlength: 0 as u16,
                rdata: Rdata::SomeCnameRdata(val),
            },
            Rdata::SomeSoaRdata(val) => ResourceRecord {
                name: DomainName::new(),
                type_code: 6 as u16,
                class: 0 as u16,
                ttl: 0 as u32,
                rdlength: 0 as u16,
                rdata: Rdata::SomeSoaRdata(val),
            },
            Rdata::SomePtrRdata(val) => ResourceRecord {
                name: DomainName::new(),
                type_code: 12 as u16,
                class: 0 as u16,
                ttl: 0 as u32,
                rdlength: 0 as u16,
                rdata: Rdata::SomePtrRdata(val),
            },
            Rdata::SomeHinfoRdata(val) => ResourceRecord {
                name: DomainName::new(),
                type_code: 13 as u16,
                class: 0 as u16,
                ttl: 0 as u32,
                rdlength: 0 as u16,
                rdata: Rdata::SomeHinfoRdata(val),
            },
            Rdata::SomeMxRdata(val) => ResourceRecord {
                name: DomainName::new(),
                type_code: 15 as u16,
                class: 0 as u16,
                ttl: 0 as u32,
                rdlength: 0 as u16,
                rdata: Rdata::SomeMxRdata(val),
            },
            Rdata::SomeTxtRdata(val) => ResourceRecord {
                name: DomainName::new(),
                type_code: 16 as u16,
                class: 0 as u16,
                ttl: 0 as u32,
                rdlength: 0 as u16,
                rdata: Rdata::SomeTxtRdata(val),
            },
            _ => ResourceRecord {
                name: DomainName::new(),
                type_code: 0 as u16,
                class: 0 as u16,
                ttl: 0 as u32,
                rdlength: 0 as u16,
                rdata: rdata,
            },
        }
    }

    /// Given an array of bytes, creates a new ResourceRecord
    /// # Examples
    /// ```
    /// let bytes_msg: [u8; 23] = [
    ///     3, 100, 99, 99, 2, 99, 108, 0, 0, 16, 0, 1, 0, 0, 0b00010110, 0b00001010, 0, 5, 104,
    ///     101, 108, 108, 111,
    /// ];
    ///
    /// let resource_record_test = ResourceRecord::<Rdata>::from_bytes(&bytes_msg);
    ///
    /// assert_eq!(resource_record_test.get_name().get_name(), String::from("dcc.cl"));
    /// assert_eq!(resource_record_test.get_type_code(), 16);
    /// assert_eq!(resource_record_test.get_class(), 1);
    /// assert_eq!(resource_record_test.get_ttl(), 5642);
    /// assert_eq!(resource_record_test.get_rdlength(), 5);
    /// assert_eq!(
    ///     resource_record_test.get_rdata().unwrap().get_text(),
    ///     String::from("hello")
    /// );
    /// ```
    ///
    pub fn from_bytes<'a>(
        bytes: &'a [u8],
        full_msg: &'a [u8],
    ) -> Result<(ResourceRecord, &'a [u8]), &'static str> {
        let domain_name_result = DomainName::from_bytes(bytes, full_msg.clone());

        match domain_name_result {
            Ok(_) => {}
            Err(e) => return Err(e),
        }

        let (name, bytes_without_name) = domain_name_result.unwrap();

        if bytes_without_name.len() < 10 {
            return Err("Format Error");
        }

        let type_code = ((bytes_without_name[0] as u16) << 8) | bytes_without_name[1] as u16;
        let class = ((bytes_without_name[2] as u16) << 8) | bytes_without_name[3] as u16;
        let ttl = ((bytes_without_name[4] as u32) << 24)
            | ((bytes_without_name[5] as u32) << 16)
            | ((bytes_without_name[6] as u32) << 8)
            | bytes_without_name[7] as u32;
        let rdlength = ((bytes_without_name[8] as u16) << 8) | bytes_without_name[9] as u16;

        let end_rr_byte = 10 + rdlength as usize;

        if bytes_without_name.len() < end_rr_byte {
            return Err("Format Error");
        }

        let mut rdata_bytes_vec = bytes_without_name[10..].to_vec();
        rdata_bytes_vec.push(bytes_without_name[0]);
        rdata_bytes_vec.push(bytes_without_name[1]);
        rdata_bytes_vec.push(bytes_without_name[2]);
        rdata_bytes_vec.push(bytes_without_name[3]);

        let rdata_result = Rdata::from_bytes(rdata_bytes_vec.as_slice(), full_msg);

        match rdata_result {
            Ok(_) => {}
            Err(e) => {
                return Err(e);
            }
        }

        let rdata = rdata_result.unwrap();

        let resource_record = ResourceRecord {
            name: name,
            type_code: type_code,
            class: class,
            ttl: ttl,
            rdlength: rdlength,
            rdata: rdata,
        };

        Ok((resource_record, &bytes_without_name[end_rr_byte..]))
    }

    /// Returns a byte that represents the first byte from type code in the dns message.
    fn get_first_type_code_byte(&self) -> u8 {
        let type_code = self.get_type_code();
        let first_byte = (type_code >> 8) as u8;

        first_byte
    }

    /// Returns a byte that represents the second byte from type code in the dns message.
    fn get_second_type_code_byte(&self) -> u8 {
        let type_code = self.get_type_code();
        let second_byte = type_code as u8;

        second_byte
    }

    /// Returns a byte that represents the first byte from class in the dns message.
    fn get_first_class_byte(&self) -> u8 {
        let class = self.get_class();
        let first_byte = (class >> 8) as u8;

        first_byte
    }

    /// Returns a byte that represents the second byte from class in the dns message.
    fn get_second_class_byte(&self) -> u8 {
        let class = self.get_class();
        let second_byte = class as u8;

        second_byte
    }

    /// Returns a byte that represents the first byte from ttl in the dns message.
    fn get_first_ttl_byte(&self) -> u8 {
        let ttl = self.get_ttl();
        let first_byte = (ttl >> 24) as u8;

        first_byte
    }

    /// Returns a byte that represents the second byte from ttl in the dns message.
    fn get_second_ttl_byte(&self) -> u8 {
        let ttl = self.get_ttl();
        let second_byte = (ttl >> 16) as u8;

        second_byte
    }

    /// Returns a byte that represents the third byte from ttl in the dns message.
    fn get_third_ttl_byte(&self) -> u8 {
        let ttl = self.get_ttl();
        let third_byte = (ttl >> 8) as u8;

        third_byte
    }

    /// Returns a byte that represents the fourth byte from ttl in the dns message.
    fn get_fourth_ttl_byte(&self) -> u8 {
        let ttl = self.get_ttl();
        let fourth_byte = ttl as u8;

        fourth_byte
    }

    /// Returns a vec of bytes that represents the rdata in the dns message.
    fn rdata_to_bytes(&self) -> Vec<u8> {
        let rdata = self.get_rdata();

        rdata.to_bytes()
    }

    /// Returns a vec fo bytes that represents the resource record
    ///
    /// # Example
    /// ```
    /// let txt_rdata = Rdata::SomeTxtRdata(TxtRdata::new(String::from("dcc")));
    /// let mut resource_record = ResourceRecord::new(txt_rdata);
    /// let mut domain_name = DomainName::new();
    /// domain_name.set_name(String::from("dcc.cl"));
    ///
    /// resource_record.set_name(domain_name);
    /// resource_record.set_type_code(2);
    /// resource_record.set_class(1);
    /// resource_record.set_ttl(5642);
    /// resource_record.set_rdlength(3);
    ///
    /// let bytes_msg = [
    ///     3, 100, 99, 99, 2, 99, 108, 0, 0, 2, 0, 1, 0, 0, 0b00010110, 0b00001010, 0, 3, 100, 99,
    ///     99,
    /// ];
    ///
    /// let rr_to_bytes = resource_record.to_bytes();
    ///
    /// let mut i = 0;
    ///
    /// for value in rr_to_bytes.as_slice() {
    ///     assert_eq!(*value, bytes_msg[i]);
    ///     i += 1;
    /// }
    /// ```
    ///
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut rr_bytes: Vec<u8> = Vec::new();

        let name_bytes = self.get_name().to_bytes();

        for byte in name_bytes.as_slice() {
            rr_bytes.push(*byte);
        }

        rr_bytes.push(self.get_first_type_code_byte());
        rr_bytes.push(self.get_second_type_code_byte());
        rr_bytes.push(self.get_first_class_byte());
        rr_bytes.push(self.get_second_class_byte());
        rr_bytes.push(self.get_first_ttl_byte());
        rr_bytes.push(self.get_second_ttl_byte());
        rr_bytes.push(self.get_third_ttl_byte());
        rr_bytes.push(self.get_fourth_ttl_byte());

        let rdata_bytes = self.rdata_to_bytes();
        let rd_length: u16 = rdata_bytes.len() as u16;

        rr_bytes.push((rd_length >> 8) as u8);
        rr_bytes.push(rd_length as u8);

        for byte in rdata_bytes.as_slice() {
            rr_bytes.push(*byte);
        }

        rr_bytes
    }

    // Gets the String RR type
    pub fn get_string_type(&self) -> String {
        let qtype = match self.get_type_code() {
            1 => "A".to_string(),
            2 => "NS".to_string(),
            5 => "CNAME".to_string(),
            6 => "SOA".to_string(),
            11 => "WKS".to_string(),
            12 => "PTR".to_string(),
            13 => "HINFO".to_string(),
            14 => "MINFO".to_string(),
            15 => "MX".to_string(),
            16 => "TXT".to_string(),
            28 => "AAAA".to_string(),
            _ => unreachable!(),
        };

        qtype
    }
}

// Setters
impl ResourceRecord {
    /// Sets the ame attribute with a value
    pub fn set_name(&mut self, name: DomainName) {
        self.name = name;
    }

    /// Sets the type_code attribute with a value
    pub fn set_type_code(&mut self, type_code: u16) {
        self.type_code = type_code;
    }

    /// Sets the class attribute with a value
    pub fn set_class(&mut self, class: u16) {
        self.class = class;
    }

    /// Sets the ttl attribute with a value
    pub fn set_ttl(&mut self, ttl: u32) {
        self.ttl = ttl;
    }

    /// Sets the rdlength attribute with a value
    pub fn set_rdlength(&mut self, rdlength: u16) {
        self.rdlength = rdlength;
    }

    /// Sets the rdata attribute with a value
    pub fn set_rdata(&mut self, rdata: Rdata) {
        self.rdata = rdata.clone();
    }
}

// Getters
impl ResourceRecord {
    /// Gets the name attribute value
    pub fn get_name(&self) -> DomainName {
        self.name.clone()
    }

    /// Gets the type_code attribute value
    pub fn get_type_code(&self) -> u16 {
        self.type_code
    }

    /// Gets the class attribute value
    pub fn get_class(&self) -> u16 {
        self.class
    }

    /// Gets the ttl attribute value
    pub fn get_ttl(&self) -> u32 {
        self.ttl
    }

    /// Gets the rdlength attribute value
    pub fn get_rdlength(&self) -> u16 {
        self.rdlength
    }

    /// Gets the rdata attribute value
    pub fn get_rdata(&self) -> Rdata {
        self.rdata.clone()
    }
}
