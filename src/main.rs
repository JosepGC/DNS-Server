use std::fs::File;
use std::io::Read;
use std::net::Ipv4Addr;

type Error = Box<dyn std::error::Error>;
type Result<T> = std::result::Result<T, Error>;


pub struct BytePacketBuffer {
    pub buf: [u8; 512],
    pub pos: usize,
}

impl BytePacketBuffer {

    /// This gives us a fresh buffer for holding the packet contents, and a
    /// field for keeping track of where we are.
    pub fn new() -> BytePacketBuffer {
        BytePacketBuffer {
            buf: [0; 512],
            pos: 0,
        }
    }

    /// Current position within buffer
    fn pos(&self) -> usize {
        self.pos
    }

    /// Step the buffer position forward a specific number of steps
    fn step(&mut self, steps: usize) -> Result<()> {
        self.pos += steps;

        Ok(())
    }

    /// Change the buffer position
    fn seek(&mut self, pos: usize) -> Result<()> {
        self.pos = pos;

        Ok(())
    }

    /// Read a single byte and move the position one step forward
    fn read(&mut self) -> Result<u8> {
        if self.pos >= 512 {
            return Err("End of buffer".into());
        }
        let res = self.buf[self.pos];
        self.pos += 1;

        Ok(res)
    }

    /// Get a single byte, without changing the buffer position
    fn get(&mut self, pos: usize) -> Result<u8> {
        if pos >= 512 {
            return Err("End of buffer".into());
        }
        Ok(self.buf[pos])
    }

    /// Get a range of bytes
    fn get_range(&mut self, start: usize, len: usize) -> Result<&[u8]> {
        if start + len >= 512 {
            return Err("End of buffer".into());
        }
        Ok(&self.buf[start..start + len as usize])
    }

    /// Read two bytes, stepping two steps forward
    fn read_u16(&mut self) -> Result<u16> {
        let res = ((self.read()? as u16) << 8) | (self.read()? as u16);

        Ok(res)
    }

    /// Read four bytes, stepping four steps forward
    fn read_u32(&mut self) -> Result<u32> {
        let res = ((self.read()? as u32) << 24)
            | ((self.read()? as u32) << 16)
            | ((self.read()? as u32) << 8)
            | ((self.read()? as u32) << 0);

        Ok(res)
    }


    /// Read a qname
    ///
    /// The tricky part: Reading domain names, taking labels into consideration.
    /// Will take something like [3]www[6]google[3]com[0] and append
    /// www.google.com to outstr.
    fn read_qname(&mut self, outstr: &mut String) -> Result<()> {
        // Since we might encounter jumps, we'll keep track of our position
        // locally as opposed to using the position within the struct. This
        // allows us to move the shared position to a point past our current
        // qname, while keeping track of our progress on the current qname
        // using this variable.
        let mut pos = self.pos();

        // track whether or not we've jumped
        let mut jumped = false;
        let max_jumps = 5;
        let mut jumps_performed = 0;

        // Our delimiter which we append for each label. Since we don't want a
        // dot at the beginning of the domain name we'll leave it empty for now
        // and set it to "." at the end of the first iteration.
        let mut delim = "";
        loop {
            // Dns Packets are untrusted data, so we need to be paranoid. Someone
            // can craft a packet with a cycle in the jump instructions. This guards
            // against such packets.
            if jumps_performed > max_jumps {
                return Err(format!("Limit of {} jumps exceeded", max_jumps).into());
            }

            // At this point, we're always at the beginning of a label. Recall
            // that labels start with a length byte.
            let len = self.get(pos)?;

            // If len has the two most significant bit are set, it represents a
            // jump to some other offset in the packet:
            if (len & 0xC0) == 0xC0 {
                // Update the buffer position to a point past the current
                // label. We don't need to touch it any further.
                if !jumped {
                    self.seek(pos + 2)?;
                }

                // Read another byte, calculate offset and perform the jump by
                // updating our local position variable
                let b2 = self.get(pos + 1)? as u16;
                let offset = (((len as u16) ^ 0xC0) << 8) | b2;
                pos = offset as usize;

                // Indicate that a jump was performed.
                jumped = true;
                jumps_performed += 1;

                continue;
            }
            // The base scenario, where we're reading a single label and
            // appending it to the output:
            else {
                // Move a single byte forward to move past the length byte.
                pos += 1;

                // Domain names are terminated by an empty label of length 0,
                // so if the length is zero we're done.
                if len == 0 {
                    break;
                }

                // Append the delimiter to our output buffer first.
                outstr.push_str(delim);

                // Extract the actual ASCII bytes for this label and append them
                // to the output buffer.
                let str_buffer = self.get_range(pos, len as usize)?;
                outstr.push_str(&String::from_utf8_lossy(str_buffer).to_lowercase());

                delim = ".";

                // Move forward the full length of the label.
                pos += len as usize;
            }
        }

        if !jumped {
            self.seek(pos)?;
        }

        Ok(())
    }

    fn write(&mut self, num: u8) -> Result<()>{
        if self.pos + 1 >= 512 {
            return Err("End of buffer".into());
        }
        self.buf[self.pos] = num;
        self.pos += 1;
        Ok(())
    }

    fn write_u8(&mut self, num: u8) -> Result<()>{
        self.write(num)?;
        Ok(())
    }

    fn write_u16(&mut self, num: u16) -> Result<()>{
        self.write((num >> 8) as u8)?;
        self.write((num & 0xFF) as u8)?;
        Ok(())
    }
    
    fn write_u32(&mut self, num: u32) -> Result<()>{
        self.write(((num >> 24) & 0xFF) as u8)?;
        self.write(((num >> 16) & 0xFF) as u8)?;
        self.write(((num >> 8) & 0xFF) as u8)?;
        self.write(((num >> 0) & 0xFF) as u8)?;
        Ok(())
    }

    fn write_qname(&self, nom: &str) -> Result<()>{
        for label in qname.split(".") {
            let len = label.len();
            if len > 0x3f {
                return Err("Single label exceeds 63 characters of length".into());
            }
            self.write(len as u8)?;
            for b in label {
                self.write(*b)?;                
            }
        }
        self.write(0)?;
        Ok(())
    }
}
//Result code
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
 pub enum ResultCode{
    NOERROR = 0,
    FORMERR = 1,
    SERVFAIL = 2,
    NXDOMAIN = 3,
    NOTIMP = 4,
    REFUSED = 5,
}

impl ResultCode {
    pub fn from_num(num: u8) -> ResultCode{
            match num{
                1 => ResultCode::FORMERR,
                2 => ResultCode::SERVFAIL,
                3 => ResultCode::NXDOMAIN, 
                4 => ResultCode::NOTIMP, 
                5 => ResultCode::REFUSED, 
                0 | _ => ResultCode::NOERROR,
            }
    }
}

//DNSHeader
#[derive(Clone, Debug)]
pub struct DnsHeader {
    pub id: u16, //16 bits
    pub QR: bool,
    pub OPCODE: u8,
    pub AA: bool,
    pub TC: bool,
    pub RD: bool,
    pub RA: bool,
    pub Z: bool,
    pub CD: bool,
    pub AD: bool,
    pub RCODE: ResultCode,
    pub QDCOUNT: u16,
    pub ANCOUNT: u16,
    pub NSCOUNT: u16,
    pub ARCOUNT: u16,
}

impl DnsHeader {
    pub fn new () -> DnsHeader {
        DnsHeader {
            id: 0, //16 bits
            QR: false,
            OPCODE: 0,
            AA: false,
            TC: false,
            RD: false,
            RA: false,
            Z: false,
            CD: false,
            AD: false,
            RCODE: ResultCode::NOERROR, 
            QDCOUNT: 0,
            ANCOUNT: 0,
            NSCOUNT: 0,
            ARCOUNT: 0,
        }
    }

    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
        self.id = buffer.read_u16()?;

        let bits = buffer.read_u16()?; //b_aaaaaaaa-bbbbbbbb
        let primera = (bits & 0xFF) as u8; //b_bbbbbbbb
        let segona = (bits >> 8) as u8; //b_aaaaaaaa
        self.QR = segona & (1 << 7) > 0;
        self.OPCODE = (primera >> 3) & 0x0F; //b_0111-1000
        self.AA = segona & (1 << 2) > 0;
        self.TC = segona & (1 << 1) > 0;
        self.RD = segona & (1 << 0) > 0;
        self.RA = primera & (1 << 7) > 0;
        self.Z = primera & (1 << 6) > 0;
        self.CD = primera & (1 << 5) > 0;
        self.AD = primera & (1 << 4) > 0;
        self.RCODE = ResultCode::from_num(primera & 0x0F);
        
        self.QDCOUNT = buffer.read_u16()?;
        self.ANCOUNT = buffer.read_u16()?;
        self.NSCOUNT = buffer.read_u16()?;
        self.ARCOUNT = buffer.read_u16()?;
        Ok(())

    }
}

//QueryType
#[derive(PartialEq, Eq, Debug, Clone, Hash, Copy)]
pub enum QueryType {
    UNKNOWN(u16),
    A, //1
}

impl QueryType {
    pub fn to_num(&self) -> u16{
        match *self {
            QueryType::UNKNOWN(x) => x,
            QueryType::A => 1,
        }
    }
    pub fn from_num(num:u16) -> QueryType {
        match num {
            1 => QueryType::A,
            _ => QueryType::UNKNOWN(num),
        }
    }
}

//DnsQuestion
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: QueryType,
}

impl DnsQuestion {
    pub fn new(name: String, qtype: QueryType) -> DnsQuestion {
        DnsQuestion {
            name: name,
            qtype: qtype,
        }
    }
    
    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
        buffer.read_qname(&mut self.name)?;
        self.qtype = QueryType::from_num(buffer.read_u16()?);
        let _ = buffer.read_u16()?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[allow(dead_code)]
pub enum DnsRecord {
    UNKNOWN {
        domain: String,
        qtype: u16,
        data_len: u16,
        ttl: u32,
        //Len: u16,
    }, //0
    A {
        domain: String,
        addr: Ipv4Addr,
        ttl: u32,
    }
}

impl DnsRecord {
    pub fn read(buffer: &mut BytePacketBuffer) -> Result<DnsRecord> {
        let mut domain = String::new();
        buffer.read_qname(&mut domain)?;

        let qtype_num = buffer.read_u16()?;
        let qtype = QueryType::from_num(qtype_num);
        let _ = buffer.read_u16()?;
        let ttl = buffer.read_u32()?;
        let data_len = buffer.read_u16()?;

        match qtype {
            QueryType::A => {
                let raw_addr = buffer.read_u32()?;
                let addr = Ipv4Addr::new(
                    ((raw_addr << 24) & 0xFF) as u8,
                    ((raw_addr << 16) & 0xFF) as u8,
                    ((raw_addr << 8) & 0xFF) as u8,
                    ((raw_addr << 0) & 0xFF) as u8,
                );
                Ok(
                    DnsRecord::A{
                    domain: domain,
                    addr: addr,
                    ttl: ttl,
                    }
                )
            }
            QueryType::UNKNOWN(_) => {
                buffer.step(data_len as usize)?;
                Ok(
                    DnsRecord::UNKNOWN {
                        domain: domain,
                        qtype: qtype_num,
                        data_len: data_len,
                        ttl: ttl,
                    }
                )
                
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answer: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub resources: Vec<DnsRecord>,
}

impl DnsPacket {
    pub fn new() -> DnsPacket{
        DnsPacket {
            header: DnsHeader::new(),
            questions: Vec::new(),
            answer: Vec::new(),
            authorities: Vec::new(),
            resources: Vec::new(),
        }
    }

    pub fn from_buffer(buffer: &mut BytePacketBuffer) -> Result<DnsPacket> {
        let mut result = DnsPacket::new();
        result.header.read(buffer);

        for _ in 0..result.header.QDCOUNT {
            let mut question = DnsQuestion::new("".to_string(), QueryType::UNKNOWN(0));
            question.read(buffer)?;
            result.questions.push(question);
        }

        for _ in 0..result.header.ANCOUNT{
            let answer = DnsRecord::read(buffer)?;
            result.answer.push(answer);
        }

        for _ in 0..result.header.NSCOUNT{
            let answer = DnsRecord::read(buffer)?;
            result.authorities.push(answer);
        }

        for _ in 0..result.header.ARCOUNT{
            let answer = DnsRecord::read(buffer)?;
            result.resources.push(answer);
        }

        Ok(result)
    }
}

fn main() -> Result<()> {
    let mut f = File::open("response_packet.txt")?;
    let mut buffer = BytePacketBuffer::new();
    f.read(&mut buffer.buf)?;

    let packet = DnsPacket::from_buffer(&mut buffer)?;
    println!("{:#?}", packet.header);

    for q in packet.questions {
        println!("{:#?}", q);
    }
    for rec in packet.answer {
        println!("{:#?}", rec);
    }
    for rec in packet.authorities {
        println!("{:#?}", rec);
    }
    for rec in packet.resources {
        println!("{:#?}", rec);
    }

    Ok(())
}