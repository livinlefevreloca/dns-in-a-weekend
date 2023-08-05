use byteorder::{BigEndian, ByteOrder};

#[derive(Default, Debug, Clone)]
pub struct Buffer {
    bytes: Vec<u8>,
    pointer: usize,
}

impl Buffer {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes, pointer: 0 }
    }

    pub fn read_u8(&mut self) -> u8 {
        let byte = self.bytes[self.pointer];
        self.pointer += 1;
        byte
    }

    pub fn read_u16(&mut self) -> u16 {
        let bytes = &self.bytes[self.pointer..self.pointer + 2];
        self.pointer += 2;
        BigEndian::read_u16(bytes)
    }

    pub fn read_u32(&mut self) -> u32 {
        let bytes = &self.bytes[self.pointer..self.pointer + 4];
        self.pointer += 4;
        BigEndian::read_u32(bytes)
    }

    pub fn read(&mut self, len: usize) -> &[u8] {
        let bytes = &self.bytes[self.pointer..self.pointer + len];
        self.pointer += len;
        bytes
    }

    pub fn seek(&mut self, offset: usize) {
        self.pointer = offset;
    }

    pub fn skip(&mut self, len: usize) {
        self.pointer += len;
    }

    pub fn peek(&self) -> u8 {
        self.bytes[self.pointer]
    }

    pub fn position(&self) -> usize {
        self.pointer
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[self.pointer..]
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

pub struct WriterBuffer {
    bytes: Vec<u8>,
    pointer: usize,
}

impl WriterBuffer {
    pub fn new(capacity: usize) -> Self {
        let bytes = if capacity > 0 {
            Vec::with_capacity(capacity)
        } else {
            Vec::new()
        };

        Self { bytes, pointer: 0 }
    }

    pub fn write_u8(&mut self, byte: u8) {
        self.bytes.push(byte);
        self.pointer += 1;
    }

    pub fn write_u16(&mut self, value: u16) {
        let mut bytes = [0; 2];
        BigEndian::write_u16(&mut bytes, value);
        self.bytes.extend_from_slice(&bytes);
        self.pointer += 2;
    }

    pub fn write_u16_unchecked(&mut self, value: u16) {
        BigEndian::write_u16(&mut self.bytes[self.pointer..], value);
        self.pointer += 2;
    }

    pub fn write_u32(&mut self, value: u32) {
        let mut bytes = [0; 4];
        BigEndian::write_u32(&mut bytes, value);
        self.bytes.extend_from_slice(&bytes);
        self.pointer += 4;
    }

    pub fn write_u32_unchecked(&mut self, value: u32) {
        BigEndian::write_u32(&mut self.bytes[self.pointer..], value);
        self.pointer += 4;
    }

    pub fn write(&mut self, bytes: &[u8]) {
        self.bytes.extend_from_slice(bytes);
        self.pointer += bytes.len();
    }

    pub fn position(&self) -> usize {
        self.pointer
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    pub fn seek(&mut self, offset: usize) {
        self.pointer = offset;
    }

    pub fn reserve(&mut self, additional: usize) {
        let bytes = vec![0; additional];
        self.bytes.extend_from_slice(&bytes);
    }
}
