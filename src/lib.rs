use std::collections::HashMap;
use std::mem;

mod buffer;

use buffer::{Buffer, WriterBuffer};

static TYPE_A: u16 = 1;
static CLASS_IN: u16 = 1;
static QUERY: u16 = 0x0000;
static RESPONSE: u16 = 0x8000;


// A trait for packing structs into byte arrays
trait Packable {
    fn pack(&self) -> Vec<u8>;

    fn packed_size(&self) -> usize {
        mem::size_of_val(&self.pack())
    }
}

// A trait for unpacking byte arrays into structs
trait UnPackable {
    fn unpack(bytes: &mut Buffer) -> Self;
}

fn encode_domain_name(name: String) -> Vec<u8> {
    if name.is_empty() {
        return vec![]
    }

    let parts = name.split('.');
    let part_count = parts.clone().count();
    let mut name = Vec::with_capacity(name.len() + part_count);
    for part in parts {
        let part_len = part.len();
        let encoded = [part_len as u8].into_iter().chain(part.to_owned().into_bytes());
        name.extend(encoded)
    }
    name
}

// an enum used to indicate whether the next step in a domain name is
// a contiuation via pointer or the end
enum CompressionDirective {
    Continue((String, usize)),
    End(String)
}

// Given a message and an offset, decode the domain name at that offset
fn decode_domain_name(bytes: &mut Buffer) -> String {
    let mut name = String::new();
    match inner_decode_domain_name(bytes) {
        CompressionDirective::Continue((name_part, ptr)) => {
            name.push_str(&name_part);
            let original_position = bytes.position();
            bytes.seek(ptr);

            let next_part = decode_domain_name(bytes);

            bytes.seek(original_position);
            name.push_str(&next_part);
        },
        CompressionDirective::End(string) => {
            name.push_str(&string)
        }
    }
    name
}

// helper method used by decode name to handle jumping to other parts of a message
// during decompression
fn inner_decode_domain_name(bytes: &mut Buffer) -> CompressionDirective {
    let pointer_or_label = bytes.read_u8();
    let mut name = read_part(bytes, pointer_or_label as usize);
    loop {
        let pointer_or_label = bytes.read_u8();
        // if the top two bits are set, then we have a pointer to another
        // part of the message. Return a Continue directive with the name
        // and the pointer
        if pointer_or_label & 0xc0 == 0xc0 {
            // 0x3fff == 0011 1111. This gets the last 6 pits of the
            // u16 to get the offset we need to jump to
            bytes.seek(bytes.position() - 1);
            let ptr = (bytes.read_u16() & 0x3fff) as usize;
            name.push('.');
            return CompressionDirective::Continue((
                name,
                ptr,
            ))
        }

        // if the pointer_or_label is 0, then we have reached the end of the
        // domain name. Return an End directive with the name
        if pointer_or_label == 0 {
            return CompressionDirective::End(name)
        }

        // otherwise, we have a new part of the domain name to read
        name.push('.');
        name.push_str(&read_part(bytes, pointer_or_label as usize));
    }

}

// read a part of a domain name and advance the messgage pointer
fn read_part(bytes: &mut Buffer, bytes_to_read: usize) -> String {
    String::from_utf8_lossy(bytes.read(bytes_to_read)).into()
}

// Struct hold DNS header data
#[derive(Default, Copy, Clone, Debug)]
pub struct DNSHeader {
    id: u16,
    flags: u16,
    num_questions: u16,
    num_answers: u16,
    num_authorities: u16,
    num_additionals: u16,
}

impl DNSHeader {

    // create a new DnsHeader struct
    pub fn new(
       id: u16,
       flags: u16,
       num_questions: u16,
       num_answers: u16,
       num_authorities: u16,
       num_additionals: u16,
    ) -> Self {
        Self {
            id,
            flags,
            num_questions,
            num_answers,
            num_authorities,
            num_additionals
        }
    }
}


// Implement Packable for DNSHeader
impl Packable for DNSHeader {
    fn pack(&self) -> Vec<u8> {
        let mut packed: WriterBuffer = WriterBuffer::new(12);
        packed.reserve(12);
        packed.write_u16_unchecked(self.id);
        packed.write_u16_unchecked(self.flags);
        packed.write_u16_unchecked(self.num_questions);
        packed.write_u16_unchecked(self.num_answers);
        packed.write_u16_unchecked(self.num_authorities);
        packed.write_u16_unchecked(self.num_additionals);
        packed.into_bytes()
    }

    // return the size of the packed struct. override the default implementation as this will
    // always be a constant size
    fn packed_size(&self) -> usize {
        12
    }
}

// Implement UnPackable for DNSHeader
impl UnPackable for DNSHeader {
    fn unpack(bytes: &mut Buffer) -> Self {
        let id = bytes.read_u16();
        let flags = bytes.read_u16();
        let num_questions = bytes.read_u16();
        let num_answers = bytes.read_u16();
        let num_authorities = bytes.read_u16();
        let num_additionals = bytes.read_u16();

        DNSHeader::new(
            id, flags, num_questions, num_answers, num_authorities, num_additionals
        )
    }
}

// A struct to hold DNS question data
#[derive(Default, Clone)]
pub struct DNSQuestion {
    qname: String,
    qtype: u16,
    qclass: u16,
}

impl DNSQuestion {
    // Create a new DNSQuestion struct
    pub fn new(qname: String, qtype: u16, qclass: u16) -> Self {
        assert!(qname.is_ascii());
        DNSQuestion {
            qname,
            qtype,
            qclass,
        }
    }
}

// Implement Packable for DNSQuestion
impl Packable for DNSQuestion {
    fn pack(&self) -> Vec<u8> {
        let mut name = encode_domain_name(self.qname.to_owned());
        name.push(0);

        let name_len = name.len();
        let mut packed =  WriterBuffer::new(name_len + 4);
        packed.write(&name);

        packed.write_u16(self.qtype);
        packed.write_u16(self.qclass);

        packed.into_bytes()
    }
}

// Implement UnPackable for DNSQuestion
impl UnPackable for DNSQuestion {
    fn unpack(bytes: &mut Buffer) -> Self {
        let qname = decode_domain_name(bytes);
        let qtype = bytes.read_u16();
        let qclass = bytes.read_u16();

        DNSQuestion::new(qname, qtype, qclass)
    }
}

// A struct to hold DNS record data
#[derive(Default, Clone)]
pub struct DNSRecord {
    name: String,
    r#type: u16,
    class: u16,
    ttl: u32,
    data: Vec<u8>,
}

impl DNSRecord {
    fn new(name: String, r#type: u16, class: u16, ttl: u32, data: Vec<u8>) -> Self {
        assert!(name.is_ascii());
        DNSRecord {
            name,
            r#type,
            class,
            ttl,
            data,
        }
    }
}


// Implement UnPackable for DNSRecord
impl UnPackable for DNSRecord {
    fn unpack(bytes: &mut Buffer) -> Self {
        let name = decode_domain_name(bytes);
        let r#type = bytes.read_u16();
        let class = bytes.read_u16();
        let ttl = bytes.read_u32();
        let data_len = bytes.read_u16() as usize;
        let data = bytes.read(data_len).to_vec();

        DNSRecord::new(name, r#type, class, ttl, data)
    }
}




// A struct to hold a DNS message
#[derive(Default, Clone)]
struct DNSMessage<'a> {
    raw_message: Buffer<'a>,
    pointer: usize,
    header: DNSHeader,
    questions: Vec<DNSQuestion>,
    answers: Vec<DNSRecord>,
    authorities: Vec<DNSRecord>,
    additionals: Vec<DNSRecord>,
}

impl<'a> DNSMessage<'a> {

    // Create a new DNSMessage struct from a raw byte array
    fn deserialize(raw_message: &'a [u8]) -> Self {
        let buffer = Buffer::new(raw_message);
        let mut message = DNSMessage {
            raw_message: buffer,
            ..Default::default()
        };

        message.header = message.unpack_header();
        message.questions = message.unpack_questions();
        message.answers = message.unpack_records(message.header.num_answers as usize);
        message.authorities = message.unpack_records(message.header.num_authorities as usize);
        message.additionals = message.unpack_records(message.header.num_additionals as usize);

        message
    }
    // Unpack the header of a dns message from a raw byte array
    fn unpack_header(&mut self) -> DNSHeader {
        DNSHeader::unpack(&mut self.raw_message)
    }

    // Unpack the questions of a dns message from a raw byte array
    fn unpack_questions(&mut self) -> Vec<DNSQuestion> {
        let mut questions = Vec::with_capacity(self.header.num_questions as usize);
        for _ in 0..self.header.num_questions {
            let question = DNSQuestion::unpack(&mut self.raw_message);
            questions.push(question);
        }
        questions
    }

    // Serialize a dns message struct into a byte array
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(1024);
        let mut existing_names: HashMap<&str, u16> = HashMap::new();

        data.extend(self.header.pack());
        data.extend(self.questions.iter().cloned().flat_map(|q| q.pack()));
        data.extend(DNSMessage::compress_records(&self.answers, &mut existing_names, data.len()));
        data.extend(DNSMessage::compress_records(&self.authorities, &mut existing_names, data.len()));
        data.extend(DNSMessage::compress_records(&self.additionals, &mut existing_names, data.len()));

        data
    }

    fn compress_records<'b, 'c: 'b>(
        records: &'c [DNSRecord],
        existing_names: &mut HashMap<&'b str, u16>,
        mut total_offset: usize,
    ) -> Vec<u8> {
        let mut compressed_records = WriterBuffer::new(1024);
        for record in records {
            let name_len = record.name.len();
            let mut offset = 0;

            loop {
                if offset == name_len {
                    let encoded_name = encode_domain_name(record.name.to_owned());
                    compressed_records.write(&encoded_name);
                    compressed_records.write_u8(0);
                    break
                }
                let partial_name = &record.name[offset..];
                if let Some(ptr) = existing_names.get(partial_name) {
                    let encoded_name =  if offset == 0 {
                        encode_domain_name(String::from(""))
                    } else {
                        encode_domain_name(record.name[..offset-1].to_owned())
                    };
                    compressed_records.write(&encoded_name);

                    compressed_records.write_u16(*ptr | 0xc000);
                    break
                } else {
                    existing_names.insert(partial_name, (total_offset + offset) as u16);
                    if let Some(idx) = partial_name.find('.') {
                        offset += idx + 1;
                    } else {
                        offset += partial_name.len();
                    }
                }

            }

            compressed_records.reserve(10);
            compressed_records.write_u16_unchecked(record.r#type);
            compressed_records.write_u16_unchecked(record.class);
            compressed_records.write_u32_unchecked(record.ttl);
            compressed_records.write_u16_unchecked(record.data.len() as u16);

            compressed_records.write(&record.data);
            total_offset += compressed_records.position();
        }

        compressed_records.into_bytes()

    }

    // Unpack the records of a dns message from a raw byte array
    fn unpack_records(&mut self, count: usize) -> Vec<DNSRecord> {
        let mut records = Vec::with_capacity(count);
        for _ in 0..count {
            let record = DNSRecord::unpack(&mut self.raw_message);
            records.push(record);
        }
        records
    }

    // Add a header to a dns message struct
    fn add_header(&mut self, id: u16, flags: u16) -> Self {
        let header = DNSHeader::new(
            id,
            flags, // flags
            0, // num_questions
            0, // num_answers
            0, // num_authorities
            0, // num_additionals
        );
        self.header = header;

        mem::take(self)
    }

    // Add a question to a dns message struct and increment the question count
    fn add_question(&mut self, qname: String, qtype: u16, qclass: u16) -> Self {
        let question = DNSQuestion::new(qname, qtype, qclass);
        self.questions.push(question);
        self.header.num_questions += 1;

        mem::take(self)
    }

    // Add a answer to a dns message struct and increment the answer count
    fn add_answer(&mut self, name: String, r#type: u16, class: u16, ttl: u32, data: Vec<u8>) -> Self {
        let answer = DNSRecord {
            name,
            r#type,
            class,
            ttl,
            data,
        };
        self.answers.push(answer);
        self.header.num_answers += 1;

        mem::take(self)
    }

    // Add a authority to a dns message struct and increment the authority count
    fn add_authority(&mut self, name: String, r#type: u16, class: u16, ttl: u32, data: Vec<u8>) -> Self {
        let authority = DNSRecord {
            name,
            r#type,
            class,
            ttl,
            data,
        };
        self.authorities.push(authority);
        self.header.num_authorities += 1;

        mem::take(self)
    }

    // Add a additional to a dns message struct and increment the additional count
    fn add_additional(&mut self, name: String, r#type: u16, class: u16, ttl: u32, data: Vec<u8>) -> Self {
        let additional = DNSRecord {
            name,
            r#type,
            class,
            ttl,
            data,
        };
        self.additionals.push(additional);
        self.header.num_additionals += 1;

        mem::take(self)
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use std::net::{UdpSocket, SocketAddrV4, Ipv4Addr};

    #[test]
    fn test_encode_name() {
        let name = "this.is.a.subdomain.google.com";
        let encoded = encode_domain_name(name.to_owned());
        let expected = Vec::from_iter(
            b"\x04this\x02is\x01a\x09subdomain\x06google\x03com".iter().copied()
        );

        assert_eq!(
            encoded,
            expected,
        )
    }

    #[test]
    fn test_decode_name_uncompressed() {
        let name_bytes = Vec::from_iter(
            b"\x04this\x02is\x01a\x09subdomain\x06google\x03com\x00".iter().copied()
        );
        let mut buffer = Buffer::new(&name_bytes);
        let decoded = decode_domain_name(&mut buffer);
        let expected = "this.is.a.subdomain.google.com";
        assert_eq!(
            decoded,
            expected,
        )
    }

    #[test]
    fn test_decode_name_compressed() {
        // create a buffer with a pointer to the end of a name at a 4 byte offset
        let name_bytes = Vec::from_iter(
            b"\x00\x00\x00\x00\x06google\x03com\x00\x04this\x02is\x01a\x09subdomain\xc0\x04".iter().copied()
        );
        let mut buffer = Buffer::new(&name_bytes);
        // jump to the start of name \x04this...
        buffer.seek(16);
        let decoded = decode_domain_name(&mut buffer);
        let expected = "this.is.a.subdomain.google.com";
        assert_eq!(
            decoded,
            expected,
        )
    }

    #[test]
    fn test_unpack_record_uncompressed() {
        let record_bytes = Vec::from_iter(
            b"\x04this\x02is\x01a\x09subdomain\x06google\x03com\x00".iter().copied()
        );
    }

    #[test]
    fn test_pack_header() {
        let header =  DNSHeader::new(
            1, 0x0000, 1, 0, 0, 0
        );

        let packed = header.pack();
        let expected = Vec::from_iter(
            b"\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00".iter().copied(),
        );
        assert_eq!(packed, expected)
    }

    #[test]
    fn test_pack_question() {
        let name = "this.is.a.subdomain.google.com";
        let question = DNSQuestion::new(
            name.to_owned(),
            0x01,
            0x0fff,
        );

        let packed = question.pack();
        let expected = Vec::from_iter(
            b"\x04this\x02is\x01a\x09subdomain\x06google\x03com\x00\x00\x01\x0f\xff".iter().copied()
        );

        assert_eq!(
            packed,
            expected,
        )
    }

    #[test]
    fn test_build_query() {
        let query = DNSMessage::default().add_header(1, QUERY).add_question("google.com".to_owned(), TYPE_A, CLASS_IN).serialize();
        let expected = Vec::from_iter(
            b"\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01".iter().copied(),
        );
        assert_eq!(query, expected)
    }

    #[test]
    fn test_build_response_no_compression() {
        let response = DNSMessage::default()
            .add_header(1, RESPONSE)
            .add_answer("google.com".to_owned(), 1, 2, 3, [0; 4].to_vec())
            .add_answer("some.yahoo.net".to_owned(), 1, 2, 3, [0; 4].to_vec())
            .serialize();

        let expected = Vec::from_iter(
            b"\x00\x01\x80\x00\x00\x00\x00\x02\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x02\x00\x00\x00\x03\x00\x04\x00\x00\x00\x00\x04some\x05yahoo\x03net\x00\x00\x01\x00\x02\x00\x00\x00\x03\x00\x04\x00\x00\x00\x00".iter().copied(),
        );

        assert_eq!(response, expected)
    }

    #[test]
    fn test_build_response_with_compression() {
        let response = DNSMessage::default()
            .add_header(1, RESPONSE)
            .add_answer("google.com".to_owned(), 1, 2, 3, [0; 4].to_vec())
            .add_answer("some.google.com".to_owned(), 1, 2, 3, [1; 5].to_vec())
            .add_answer("google.com".to_owned(), 1, 2, 3, [0; 4].to_vec())
            .serialize();

        let expected = Vec::from_iter(
            b"\x00\x01\x80\x00\x00\x00\x00\x03\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x02\x00\x00\x00\x03\x00\x04\x00\x00\x00\x00\x04some\xc0\x0c\x00\x01\x00\x02\x00\x00\x00\x03\x00\x05\x01\x01\x01\x01\x01\xc0\x0c\x00\x01\x00\x02\x00\x00\x00\x03\x00\x04\x00\x00\x00\x00".iter().copied(),
        );

        assert_eq!(response, expected)
    }


    #[test]
    fn test_query() {
        let message = DNSMessage::default().add_header(1, QUERY).add_question("google.com".to_owned(), TYPE_A, CLASS_IN);
        let query = message.serialize();
        let local_ip_addr = Ipv4Addr::new(0,0,0,0);
        let local_sock_addr = SocketAddrV4::new(local_ip_addr, 0);
        let remote_ip_addr = Ipv4Addr::new(8,8,8,8);
        let remote_sock_addr = SocketAddrV4::new(remote_ip_addr, 53);
        let sock = UdpSocket::bind(local_sock_addr).expect("Failed to bind to port");
        println!("Sending query: {:?}", query);
        sock.send_to(&query, remote_sock_addr).expect("Failed to send query");

        let mut buf = [0; 1024];
        print!("Waiting for response...");
        let _ = sock.recv_from(&mut buf).expect("Failed to receive response");
    }

}
