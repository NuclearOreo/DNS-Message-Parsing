use std::net::Ipv6Addr;
use std::num::ParseIntError;

fn main() {
    let ss = [
            "a01d81800001000100000000076578616d706c6503636f6d0000010001c00c0001000100001bbc00045db8d822",
            "9b4c84000001000200000000037777770a636c6f7564666c61726503636f6d0000010001c00c000100010000012c000468107c60c00c000100010000012c000468107b60", 
            "7ebd84000001000200000000037777770a636c6f7564666c61726503636f6d00001c0001c00c001c00010000012c001026064700000000000000000068107c60c00c001c00010000012c001026064700000000000000000068107b60",
            "762081800001000200000000037777770773706f7469667903636f6d0000010001c00c0005000100000102001f12656467652d7765622d73706c69742d67656f096475616c2d67736c62c010c02d000100010000006c000423bae019",
            "619381800001000100000000076578616d706c6503636f6d00001c0001c00c001c000100001bf9001026062800022000010248189325c81946", 
            ];

    for &s in ss.iter() {
        let msg = decode_hex(s).unwrap();
        let dns_message = parse_message(&msg);

        println!("{:?}\n", dns_message);
    }
}

#[derive(Debug, Clone)]
struct DnsMessage {
    id: u16,
    qr: u8,
    opcode: u8,
    aa: u8,
    tc: u8,
    rd: u8,
    ra: u8,
    zero: u8,
    r_code: u8,
    questions: Vec<Question>,
    answers: Vec<Response>,
    authority: Vec<Response>,
    additional: Vec<Response>,
}

#[derive(Debug, Clone)]
struct Question {
    name: String,
    q_type: u16,
    q_class: u16,
}

#[derive(Debug, Clone)]
struct Response {
    name: String,
    r_type: u16,
    r_class: u16,
    ttl: u32,
    r_size: u16,
    r_data: String,
}

fn decode_hex(s: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

fn parse_message(bytes: &[u8]) -> DnsMessage {
    // Parse DNS header
    let (
        mut dns_message,
        (number_of_question, number_of_answers_rr, number_of_authority_rr, number_of_additional_rr),
    ) = parse_header(&bytes[0..12]);

    // Parse DNS Message
    let (questions, answers, authority, additional) = parse_body(
        number_of_question,
        number_of_answers_rr,
        number_of_authority_rr,
        number_of_additional_rr,
        &bytes[12..],
    );

    // Package everything in a struct
    dns_message.questions = questions;
    dns_message.answers = answers;
    dns_message.authority = authority;
    dns_message.additional = additional;

    dns_message
}

fn parse_body(
    number_of_question: u16,
    number_of_answers_rr: u16,
    number_of_authority_rr: u16,
    number_of_additional_rr: u16,
    bytes: &[u8],
) -> (Vec<Question>, Vec<Response>, Vec<Response>, Vec<Response>) {
    let mut questions = vec![];
    let mut offset = 0;

    // Iterate through the number of questions
    for _ in 0..number_of_question {
        // Grab Name
        let (new_offset, name) = _get_name(offset, bytes);
        offset = new_offset + 1;

        // Get Question Type
        let q_type = (bytes[offset] as u16) << 8 | (bytes[offset + 1] as u16);
        offset += 2;

        // Get Question Class
        let q_class = (bytes[offset] as u16) << 8 | (bytes[offset + 1] as u16);
        offset += 2;

        // Append those results into a list
        questions.push(Question {
            name,
            q_type,
            q_class,
        });
    }

    // Get answers
    let (answer_offset, answers) = parse_responses(offset, number_of_answers_rr, bytes);

    // Get authority RR
    let (authority_offset, authority) =
        parse_responses(answer_offset, number_of_authority_rr, bytes);

    // Get additional RR
    let (_, additional) = parse_responses(authority_offset, number_of_additional_rr, bytes);

    (questions, answers, authority, additional)
}

fn parse_responses(mut offset: usize, count: u16, bytes: &[u8]) -> (usize, Vec<Response>) {
    let mut responses = vec![];

    for _ in 0..count {
        // Get Name
        let (_, name) = _get_name(offset, bytes);
        offset += 2;

        // Get Type
        let r_type = (bytes[offset] as u16) << 8 | (bytes[offset + 1] as u16);
        offset += 2;

        // Get Class
        let r_class = (bytes[offset] as u16) << 8 | (bytes[offset + 1] as u16);
        offset += 2;

        // Get TTL
        let ttl = (bytes[offset] as u32) << 24
            | (bytes[offset + 1] as u32) << 16
            | (bytes[offset + 2] as u32) << 8
            | bytes[offset + 3] as u32;
        offset += 4;

        // Get R Size
        let r_size = (bytes[offset] as u16) << 8 | (bytes[offset + 1] as u16);
        offset += 2;

        // Get R Data
        let r_data = match r_type {
            // A Record
            1 => {
                let ip: Vec<String> = (0..4).map(|i| format!("{}", bytes[offset + i])).collect();
                ip.join(".")
            }
            // CNAME Record
            5 => {
                let (_, cname) = _get_name(offset, bytes);
                cname
            }
            // AAAA Record
            28 => {
                let mut hextets = vec![];
                let mut i = offset;

                for _ in 0..8 {
                    let hextet = (bytes[i] as u16) << 8 | (bytes[i + 1] as u16);
                    hextets.push(hextet);
                    i += 2;
                }

                let ip = Ipv6Addr::new(
                    hextets[0], hextets[1], hextets[2], hextets[3], hextets[4], hextets[5],
                    hextets[6], hextets[7],
                );

                ip.to_string()
            }
            // If record not support return out hex bytes
            _ => {
                let tokens: Vec<String> = (offset..offset + r_size as usize)
                    .map(|i| format!("{:X}", bytes[i]))
                    .collect();
                tokens.join("")
            }
        };

        offset += r_size as usize;

        // Push record
        responses.push(Response {
            name,
            r_type,
            r_size,
            r_data,
            r_class,
            ttl,
        });
    }

    (offset, responses)
}

fn _get_name(mut offset: usize, bytes: &[u8]) -> (usize, String) {
    let mut strings = vec![];
    while bytes[offset] != 0 {
        // If pointer jump
        if bytes[offset] == 192 {
            let (_, string) = _get_name(bytes[offset + 1] as usize - 12, bytes);
            strings.push(string);
            offset += 2;
            break;
        // else count by size
        } else {
            let mut token = vec![];
            for i in 0..bytes[offset] {
                let byte = bytes[offset + i as usize + 1];
                token.push(byte);
            }
            let string = String::from_utf8(token).unwrap();
            strings.push(string);
            offset += bytes[offset] as usize + 1;
        }
    }

    let name = strings.join(".");
    (offset, name)
}

fn parse_header(bytes: &[u8]) -> (DnsMessage, (u16, u16, u16, u16)) {
    // Mask to filter out
    let mask_4 = (1 << 4) as u16 - 1;
    let mask_3 = (1 << 3) as u16 - 1;

    // DNS Message ID
    let id = (bytes[0] as u16) << 8 | (bytes[1] as u16);

    // All DNS flags in 2 bytes
    let mut flags = (bytes[2] as u16) << 8 | (bytes[3] as u16);

    // Grabbing rCode and bit shifting down 4
    let r_code = (flags & mask_4) as u8;
    flags = flags >> 4;

    // Grabbing Zero and bit shifting down
    let zero_flag = (flags & mask_3) as u8;
    flags = flags >> 3;

    // Grabbing ra flag and bit shifting down
    let ra_flag = (flags & 1) as u8;
    flags = flags >> 1;

    // Grabbing rd flag and bit shifting down
    let rd_flag = (flags & 1) as u8;
    flags = flags >> 1;

    // Grabbing tc flag and bit shifting down
    let tc_flag = (flags & 1) as u8;
    flags = flags >> 1;

    // Grabbing aa flag and bit shifting down
    let aa_flag = (flags & 1) as u8;
    flags = flags >> 1;

    // Grabbing opcode and bit shifting down
    let opcode = (flags & mask_4) as u8;
    flags = flags >> 4;

    // Grabbing qr flag and bit shifting down
    let qr_flag = (flags & 1) as u8;

    // The rest of the header
    let number_of_question = (bytes[4] as u16) << 8 | (bytes[5] as u16);
    let number_of_answers_rr = (bytes[6] as u16) << 8 | (bytes[7] as u16);
    let number_of_authority_rr = (bytes[8] as u16) << 8 | (bytes[9] as u16);
    let number_of_additional_rr = (bytes[10] as u16) << 8 | (bytes[11] as u16);

    (
        DnsMessage {
            id,
            qr: qr_flag,
            opcode: opcode,
            aa: aa_flag,
            tc: tc_flag,
            rd: rd_flag,
            ra: ra_flag,
            zero: zero_flag,
            r_code,
            questions: Vec::new(),
            answers: Vec::new(),
            authority: Vec::new(),
            additional: Vec::new(),
        },
        (
            number_of_question,
            number_of_answers_rr,
            number_of_authority_rr,
            number_of_additional_rr,
        ),
    )
}
