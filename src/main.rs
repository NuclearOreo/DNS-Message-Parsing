use bytes::Bytes;
use core::num;
use dns_message_parser::{Dns, Flags};
use std::num::ParseIntError;

fn decode_hex(s: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

fn parse_header(bytes: &[u8]) {
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

    println!(
        "Id: {}, rCode: {:04b}, zero: {:03b}, ra: {:01b}, rd: {:01b}, tc: {:01b}, aa: {:01b}, opcode: {:04b}, qr: {:01b}, 
        number_of_question: {}, number_of_answers_rr: {}, number_of_authority_rr: {}, number_of_additional_rr: {} \n",
        id, r_code, zero_flag, ra_flag, rd_flag, tc_flag, aa_flag, opcode, qr_flag, number_of_question, number_of_answers_rr, number_of_authority_rr, number_of_additional_rr 
    );
}

fn main() {
    let ss = ["a01d81800001000100000000076578616d706c6503636f6d0000010001c00c0001000100001bbc00045db8d822",
            "9b4c84000001000200000000037777770a636c6f7564666c61726503636f6d0000010001c00c000100010000012c000468107c60c00c000100010000012c000468107b60", 
            "7ebd84000001000200000000037777770a636c6f7564666c61726503636f6d00001c0001c00c001c00010000012c001026064700000000000000000068107c60c00c001c00010000012c001026064700000000000000000068107b60",
            "762081800001000200000000037777770773706f7469667903636f6d0000010001c00c0005000100000102001f12656467652d7765622d73706c69742d67656f096475616c2d67736c62c010c02d000100010000006c000423bae019",
            "619381800001000100000000076578616d706c6503636f6d00001c0001c00c001c000100001bf9001026062800022000010248189325c81946", 
            ];

    for &s in ss.iter() {
        let msg = decode_hex(s).unwrap();
        parse_header(&msg[0..12]);
    }

    // let s = "a01d81800001000100000000076578616d706c6503636f6d0000010001c00c0001000100001bbc00045db8d822";
    // let s = "9b4c84000001000200000000037777770a636c6f7564666c61726503636f6d0000010001c00c000100010000012c000468107c60c00c000100010000012c000468107b60";
    // let s = "7ebd84000001000200000000037777770a636c6f7564666c61726503636f6d00001c0001c00c001c00010000012c001026064700000000000000000068107c60c00c001c00010000012c001026064700000000000000000068107b60";
    // let s = "762081800001000200000000037777770773706f7469667903636f6d0000010001c00c0005000100000102001f12656467652d7765622d73706c69742d67656f096475616c2d67736c62c010c02d000100010000006c000423bae019";
    // let s = "619381800001000100000000076578616d706c6503636f6d00001c0001c00c001c000100001bf9001026062800022000010248189325c81946";
    // for v in msg.iter() {
    //     println!("{:x}", v);
    // }

    // let bytes = Bytes::copy_from_slice(&msg[..]);

    // println!("{:?}", bytes);

    // let dns = Dns::decode(bytes).unwrap();
    // println!("{:?}", dns);
}
