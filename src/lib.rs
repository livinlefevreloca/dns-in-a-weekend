use byteorder::{BigEndian, ByteOrder};
use std::mem;

static TYPE_A: u16 = 1;
static CLASS_IN: u16 = 1;



// A trait for packing structs into byte arrays
trait Packable {
    fn pack(&self) -> Vec<u8>;

    fn packed_size(&self) -> usize {
        mem::size_of_val(&self.pack())
    }
}

// A trait for unpacking byte arrays into structs
trait UnPackable {
    fn unpack(bytes: &[u8], offset: &mut usize) -> Self;
}

fn encode_domain_name(name: String) -> Vec<u8> {
    let parts = name.split('.');
    let part_count = parts.clone().count();
    let mut name = Vec::with_capacity(name.len() + part_count);
    for part in parts {
        let part_len = part.len();
        let encoded = [part_len as u8].into_iter().chain(part.to_owned().into_bytes());
        name.extend(encoded)
    }
    name.push(0x00);
    name
}

// an enum used to indicate whether the next step in a domain name is
// a contiuation via pointer or the end
enum CompressionDirective {
    Cont((String, usize)),
    End(String)
}

fn inner_decode_domain_name(bytes: &[u8], offset: &mut usize) -> CompressionDirective {
    let mut pointer: usize = 0;
    let mut name = read_part(bytes, &mut pointer);
    let pointer_or_count = BigEndian::read_u16(&bytes[pointer..]);
    loop {
        *offset += pointer;
        if pointer_or_count == 0 {
            return CompressionDirective::End(name)
        } else if pointer_or_count  & 0xc000 == 0xc000 {
            return CompressionDirective::Cont((name, (pointer_or_count & 0x3fff) as usize))
        }
        name.push('.');
        name.push_str(&read_part(bytes, &mut pointer))
    }

}

fn decode_domain_name(bytes: &[u8], offset: &mut usize) -> String {
    let start = &bytes[*offset..];
    let mut name = String::new();
    match inner_decode_domain_name(start, offset) {
        CompressionDirective::Cont((name_part, mut ptr)) => {
            name.push_str(&name_part);
            let next_part = decode_domain_name(bytes, &mut ptr);
            name.push_str(&next_part);
        },
        CompressionDirective::End(string) => {
            name.push_str(&string)
        }
    }
    name
}

fn read_part(bytes: &[u8], pointer: &mut usize) -> String {
    let bytes_to_read = bytes[*pointer] as usize;
    let new_pointer = *pointer + bytes_to_read;
    let part = String::from_utf8_lossy(&bytes[*pointer..new_pointer]).into();
    *pointer = new_pointer;
    part
}

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


impl Packable for DNSHeader {
    fn pack(&self) -> Vec<u8> {
        let mut packed: Vec<u8> = vec![0; 12];
        BigEndian::write_u16(&mut packed, self.id);
        BigEndian::write_u16(&mut packed[2..], self.flags);
        BigEndian::write_u16(&mut packed[4..], self.num_questions);
        BigEndian::write_u16(&mut packed[6..], self.num_answers);
        BigEndian::write_u16(&mut packed[8..], self.num_authorities);
        BigEndian::write_u16(&mut packed[10..], self.num_additionals);
        packed
    }

    fn packed_size(&self) -> usize {
        12
    }
}

impl UnPackable for DNSHeader {
    fn unpack(bytes: &[u8], offset: &mut usize) -> Self {
        let data = &bytes[*offset..];
        let id = BigEndian::read_u16(data);
        let flags = BigEndian::read_u16(&data[2..]);
        let num_questions = BigEndian::read_u16(&data[4..]);
        let num_answers = BigEndian::read_u16(&data[6..]);
        let num_authorities = BigEndian::read_u16(&data[8..]);
        let num_additionals = BigEndian::read_u16(&data[10..]);

        let header = DNSHeader::new(
            id, flags, num_questions, num_answers, num_authorities, num_additionals
        );
        *offset += header.packed_size();
        header
    }
}


#[derive(Default, Clone)]
pub struct DNSQuestion {
    qname: String,
    qtype: u16,
    qclass: u16,
}

impl DNSQuestion {

    pub fn new(qname: String, qtype: u16, qclass: u16) -> Self {
        assert!(qname.is_ascii());
        DNSQuestion {
            qname,
            qtype,
            qclass,
        }
    }


}

impl Packable for DNSQuestion {
    fn pack(&self) -> Vec<u8> {
        let name = encode_domain_name(self.qname.to_owned());
        let name_len = name.len() - 1;

        let mut bytes =  Vec::with_capacity(name_len + 2 + 2);
        bytes.extend(name);
        bytes.extend_from_slice(&[0; 4]);

        let offset = name_len + 1;

        BigEndian::write_u16(&mut bytes[offset..], self.qtype);
        BigEndian::write_u16(&mut bytes[offset+2..], self.qclass);

        bytes
    }
}

impl UnPackable for DNSQuestion {
    fn unpack(bytes: &[u8], offset: &mut usize) -> Self {
        let qname = decode_domain_name(bytes, offset);
        let name_len = qname.len() as usize;
        let qtype = BigEndian::read_u16(&bytes[name_len..]);
        let qclass = BigEndian::read_u16(&bytes[name_len+2..]);

        let question = DNSQuestion::new(qname, qtype, qclass);
        *offset += question.packed_size();
        question
    }
}

#[derive(Default, Clone)]
pub struct DNSRecord {
    name: String,
    r#type: u16,
    class: u16,
    ttl: u32,
    data: Vec<u8>,
}

impl Packable for DNSRecord {
    fn pack(&self) -> Vec<u8> {
        todo!()
    }
}


impl UnPackable for DNSRecord {
    fn unpack(bytes: &[u8], offset: &mut usize) -> Self {
        let name = decode_domain_name(bytes, offset);

        todo!()
    }
}

#[derive(Default, Clone)]
struct DNSMessage<'a> {
    raw_message: &'a [u8],
    pointer: usize,
    header: DNSHeader,
    questions: Vec<DNSQuestion>,
    answers: Vec<DNSRecord>,
    authorities: Vec<DNSRecord>,
    additionals: Vec<DNSRecord>,
}

impl<'a> DNSMessage<'a> {

    fn from_raw_message(raw_message: &'a [u8]) -> Self {
        let mut message = DNSMessage {
            raw_message,
            ..Default::default()
        };

        message.header = message.unpack_header();
        message.questions = message.unpack_questions();
        message.answers = message.unpack_records(message.header.num_answers as usize);
        message.authorities = message.unpack_records(message.header.num_authorities as usize);
        message.additionals = message.unpack_records(message.header.num_additionals as usize);

        message
    }

    fn unpack_header(&mut self) -> DNSHeader {
        DNSHeader::unpack(self.raw_message, &mut self.pointer)
    }

    fn unpack_questions(&mut self) -> Vec<DNSQuestion> {
        let mut questions = Vec::with_capacity(self.header.num_questions as usize);
        for _ in 0..self.header.num_questions {
            let question = DNSQuestion::unpack(self.raw_message, &mut self.pointer);
            questions.push(question);
        }
        questions
    }

    fn unpack_records(&mut self, count: usize) -> Vec<DNSRecord> {
        let mut records = Vec::with_capacity(count);
        for _ in 0..count {
            let record = DNSRecord::unpack(self.raw_message, &mut self.pointer);
            records.push(record);
        }
        records
    }

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

    fn add_question(&mut self, qname: String, qtype: u16, qclass: u16) -> Self {
        let question = DNSQuestion::new(qname, qtype, qclass);
        self.questions.push(question);
        self.header.num_questions += 1;

        mem::take(self)
    }

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

    pub fn serialize(&self) -> Vec<u8> {
        self.header.pack().into_iter().chain(
            self.questions.iter().cloned().flat_map(|q| q.pack())
        ).chain(
            self.answers.iter().cloned().flat_map(|a| a.pack())
        ).chain(
            self.authorities.iter().cloned().flat_map(|a| a.pack())
        ).chain(
            self.additionals.iter().cloned().flat_map(|a| a.pack())
        ).collect()
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
            b"\x04this\x02is\x01a\x09subdomain\x06google\x03com\x00".iter().copied()
        );

        assert_eq!(
            encoded,
            expected,
        )
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
    fn test_build_query() {
        let query = DNSMessage::default().add_header(1, 0x0000).add_question("google.com".to_owned(), TYPE_A, CLASS_IN).serialize();
        let expected = Vec::from_iter(
            b"\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01".iter().copied(),
        );
        assert_eq!(query, expected)
    }

    #[test]
    fn test_query() {
        let message = DNSMessage::default().add_header(1, 0x0000).add_question("google.com".to_owned(), TYPE_A, CLASS_IN);
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
