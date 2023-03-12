pub mod header;
pub mod question;
pub mod rdata;
pub mod resource_record;

use crate::domain_name::DomainName;
use crate::message::header::Header;
use crate::message::question::Question;
use crate::message::resource_record::ResourceRecord;

use rand::thread_rng;
use rand::Rng;
use std::vec::Vec;

#[derive(Clone)]
/// Structs that represents a dns message
pub struct DnsMessage {
    header: Header,
    question: Question,
    answer: Vec<ResourceRecord>,
    authority: Vec<ResourceRecord>,
    additional: Vec<ResourceRecord>,
}

impl DnsMessage {
    /// Creates a new query message
    ///
    /// # Examples
    /// '''
    /// let dns_query_message =
    /// DnsMessage::new_query_message("test.com".to_string(), 1, 1, 0, false);
    ///
    /// assert_eq!(dns_query_message.header.get_rd(), false);
    /// assert_eq!(dns_query_message.question.get_qtype(), 1);
    /// assert_eq!(dns_query_message.question.get_qclass(), 1);
    /// assert_eq!(
    ///     dns_query_message.question.get_qname().get_name(),
    ///     "test.com".to_string()
    /// );
    /// '''
    ///
    pub fn new_query_message(
        qname: String,
        qtype: u16,
        qclass: u16,
        op_code: u8,
        rd: bool,
        id: u16,
    ) -> Self {
        let qr = false;
        let qdcount = 1;
        let mut header = Header::new();

        header.set_id(id);
        header.set_qr(qr);
        header.set_op_code(op_code);
        header.set_rd(rd);
        header.set_qdcount(qdcount);

        let mut question = Question::new();
        let mut domain_name = DomainName::new();

        domain_name.set_name(qname);

        question.set_qname(domain_name);
        question.set_qtype(qtype);
        question.set_qclass(qclass);

        let dns_message = DnsMessage {
            header: header,
            question: question,
            answer: Vec::new(),
            authority: Vec::new(),
            additional: Vec::new(),
        };

        dns_message
    }

    // Creates an empty dnsmessage
    pub fn new() -> Self {
        let msg = DnsMessage {
            header: Header::new(),
            question: Question::new(),
            answer: Vec::new(),
            authority: Vec::new(),
            additional: Vec::new(),
        };

        msg
    }

    // Creates a response dns message
    pub fn new_response_message(
        qname: String,
        qtype: u16,
        qclass: u16,
        op_code: u8,
        rd: bool,
        id: u16,
    ) -> Self {
        let qr = true;
        let qdcount = 1;
        let mut header = Header::new();

        header.set_id(id);
        header.set_qr(qr);
        header.set_op_code(op_code);
        header.set_rd(rd);
        header.set_qdcount(qdcount);

        let mut question = Question::new();
        let mut domain_name = DomainName::new();

        domain_name.set_name(qname);

        question.set_qname(domain_name);
        question.set_qtype(qtype);
        question.set_qclass(qclass);

        let dns_message = DnsMessage {
            header: header,
            question: question,
            answer: Vec::new(),
            authority: Vec::new(),
            additional: Vec::new(),
        };

        dns_message
    }

    // Creates a format error message
    pub fn format_error_msg() -> Self {
        let mut msg = DnsMessage::new();
        let mut header = msg.get_header();

        header.set_rcode(1);
        msg.set_header(header);

        msg
    }

    // Creates an axfr query message
    pub fn axfr_query_message(qname: String) -> Self {
        let mut rng = thread_rng();
        let msg_id = rng.gen();

        let msg = DnsMessage::new_query_message(qname, 252, 1, 0, false, msg_id);

        msg
    }

    // Creates a not implemented message
    pub fn not_implemented_msg(mut msg: DnsMessage) -> Self {
        let mut header = msg.get_header();
        header.set_rcode(4);

        msg.set_header(header);

        msg
    }

    // Creates a DnsMessage from an array of bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        let bytes_len = bytes.len();

        if bytes_len < 12 {
            return Err("Format Error");
        }

        // Header
        let header = Header::from_bytes(&bytes[0..12]);

        // Question
        let q_count = header.get_qdcount();

        if bytes_len < 13 {
            return Err("Format Error");
        }

        let (mut question, mut no_question_bytes) = (Question::new(), &bytes[12..]);

        if q_count > 0 {
            let question_result = Question::from_bytes(&bytes[12..], bytes);

            match question_result {
                Ok(_) => {}
                Err(e) => {
                    return Err(e);
                }
            }

            let question_and_bytes = question_result.unwrap();
            question = question_and_bytes.0;
            no_question_bytes = question_and_bytes.1;
        }

        // ResourceRecords

        let mut answer = Vec::<ResourceRecord>::new();
        let mut authority = Vec::<ResourceRecord>::new();
        let mut additional = Vec::<ResourceRecord>::new();

        let answer_rr_size = header.get_ancount();
        let authority_rr_size = header.get_nscount();
        let additional_rr_size = header.get_arcount();

        // Answers
        for _i in 0..answer_rr_size {
            let rr_result = ResourceRecord::from_bytes(no_question_bytes, bytes);

            match rr_result {
                Ok(_) => {}
                Err(e) => {
                    return Err(e);
                }
            }

            let (resource_record, other_rr_bytes) = rr_result.unwrap();

            answer.push(resource_record);
            no_question_bytes = other_rr_bytes;
        }

        // Authorities
        for _i in 0..authority_rr_size {
            let rr_result = ResourceRecord::from_bytes(no_question_bytes, bytes);

            match rr_result {
                Ok(_) => {}
                Err(e) => {
                    return Err(e);
                }
            }

            let (resource_record, other_rr_bytes) = rr_result.unwrap();

            authority.push(resource_record);
            no_question_bytes = other_rr_bytes;
        }

        // Additional
        for _i in 0..additional_rr_size {
            let rr_result = ResourceRecord::from_bytes(no_question_bytes, bytes);

            match rr_result {
                Ok(_) => {}
                Err(e) => {
                    return Err(e);
                }
            }

            let (resource_record, other_rr_bytes) = rr_result.unwrap();

            additional.push(resource_record);
            no_question_bytes = other_rr_bytes;
        }

        // Create message
        let dns_message = DnsMessage {
            header: header,
            question: question,
            answer: answer,
            authority: authority,
            additional: additional,
        };

        Ok(dns_message)
    }

    // Converts a DnsMessage to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut header_bytes = self.get_header().to_bytes().to_vec();
        let mut question_bytes = self.get_question().to_bytes();
        let mut answer_bytes: Vec<u8> = Vec::new();
        let mut authority_bytes: Vec<u8> = Vec::new();
        let mut additional_bytes: Vec<u8> = Vec::new();

        for answer in self.get_answer() {
            answer_bytes.append(&mut answer.to_bytes());
        }

        for authority in self.get_authority() {
            authority_bytes.append(&mut authority.to_bytes());
        }

        for additional in self.get_additional() {
            additional_bytes.append(&mut additional.to_bytes());
        }

        let mut dns_msg_bytes = Vec::<u8>::new();

        dns_msg_bytes.append(&mut header_bytes);
        dns_msg_bytes.append(&mut question_bytes);
        dns_msg_bytes.append(&mut answer_bytes);
        dns_msg_bytes.append(&mut authority_bytes);
        dns_msg_bytes.append(&mut additional_bytes);

        dns_msg_bytes
    }

    // Update the header
    pub fn update_header_counters(&mut self) {
        let answer = self.get_answer();
        let authority = self.get_authority();
        let additional = self.get_additional();

        let mut header = self.get_header();
        header.set_ancount(answer.len() as u16);
        header.set_nscount(authority.len() as u16);
        header.set_arcount(additional.len() as u16);

        self.set_header(header);
    }

    // Adds an answer
    pub fn add_answers(&mut self, mut answers: Vec<ResourceRecord>) {
        let mut msg_answers = self.get_answer();

        msg_answers.append(&mut answers);
        self.set_answer(msg_answers);
    }

    // Adds an authority
    pub fn add_authorities(&mut self, mut authorities: Vec<ResourceRecord>) {
        let mut msg_authorities = self.get_authority();

        msg_authorities.append(&mut authorities);
        self.set_answer(msg_authorities);
    }

    // Adds an additional
    pub fn add_additionals(&mut self, mut additionals: Vec<ResourceRecord>) {
        let mut msg_additionals = self.get_additional();

        msg_additionals.append(&mut additionals);
        self.set_answer(msg_additionals);
    }
}

// Getters
impl DnsMessage {
    /// Gets the header field
    pub fn get_header(&self) -> Header {
        self.header.clone()
    }

    /// Gets the question field
    pub fn get_question(&self) -> Question {
        self.question.clone()
    }

    /// Gets the answer field
    pub fn get_answer(&self) -> Vec<ResourceRecord> {
        self.answer.clone()
    }

    /// Gets the authority field
    pub fn get_authority(&self) -> Vec<ResourceRecord> {
        self.authority.clone()
    }

    /// Gets the additional field
    pub fn get_additional(&self) -> Vec<ResourceRecord> {
        self.additional.clone()
    }

    /// Gets the id from the header
    pub fn get_query_id(&self) -> u16 {
        self.get_header().get_id()
    }

    // Gets the String qtype
    pub fn get_question_qtype(&self) -> String {
        let qtype = match self.get_question().get_qtype() {
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
            _ => unreachable!(),
        };

        qtype
    }
}

// Setters
impl DnsMessage {
    /// Sets the header field with a new Header
    pub fn set_header(&mut self, header: Header) {
        self.header = header;
    }

    /// Sets the question field with a new Question
    pub fn set_question(&mut self, question: Question) {
        self.question = question;
    }

    /// Sets the answer field with a new Vec<ResourceRecord>
    pub fn set_answer(&mut self, answer: Vec<ResourceRecord>) {
        self.answer = answer;
    }

    /// Sets the authority field with a new Vec<ResourceRecord>
    pub fn set_authority(&mut self, authority: Vec<ResourceRecord>) {
        self.authority = authority;
    }

    /// Sets the additional field with a new Vec<ResourceRecord>
    pub fn set_additional(&mut self, additional: Vec<ResourceRecord>) {
        self.additional = additional;
    }

    /// Sets the id from the header with new value
    pub fn set_query_id(&mut self, id: u16) {
        let mut header = self.get_header();
        header.set_id(id);
        self.set_header(header);
    }
}
