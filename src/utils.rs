use std::mem::size_of;

use anyhow::{bail, Result};
use lzma_rs::lzma_decompress;
use regex::bytes::Regex;

use crate::structs::EfiGuidDefinedSection;

const AGESA_PATTERN: &str = r"(AGESA![0-9a-zA-Z]{0,10}\x00{0,1}[0-9a-zA-Z .\-]+)";
const AGESA_SECTION_PATTERN: &str = r"\x93\xFD\x21\x9E\x72\x9C\x15\x4C\x8C\x4B\xE7\x7F\x1D\xB2\xD7\x92.{8}(.{4}\x98\x58\x4E\xEE\x14\x39\x59\x42\x9D\x6E\xDC\x7B\xD7\x94\x03\xCF.{4})";

pub fn find_pattern<'a>(data: &'a [u8], pattern: &str) -> Vec<(usize, &'a [u8])> {
    let regex_string = &["(?s-u)", pattern].concat();
    let regex = Regex::new(regex_string).expect("Invalid regex");

    regex
        .captures_iter(data)
        .filter_map(|capture| (1..capture.len()).find_map(|x| capture.get(x)))
        .map(|match_| (match_.start(), match_.as_bytes()))
        .collect()
}

pub fn resolve_location(location: usize, offset: usize) -> usize {
    (location & 0x00FFFFFF) + offset
}

pub fn try_find_agesa(data: &[u8]) -> Result<Vec<String>> {
    let agesa = find_pattern(&data, AGESA_PATTERN)
        .into_iter()
        .map(|(_, x)| x.iter().map(|&x| if x == 0 { ' ' } else { x as char }).collect::<String>())
        .collect::<Vec<_>>();
    if !agesa.is_empty() {
        return Ok(agesa);
    }

    let section_pat = find_pattern(&data, AGESA_SECTION_PATTERN);
    if section_pat.is_empty() {
        bail!("Could not find section pattern")
    }

    let mut agesa: Vec<String> = Vec::new();

    for (addr, bytes) in section_pat {
        let guid_section_header = match EfiGuidDefinedSection::new(&bytes) {
            Ok(header) => header,
            Err(err) => {
                log::error!("{}", err);
                continue;
            },
        };

        let mut enc_body = match data
            .get(addr + size_of::<EfiGuidDefinedSection>()..)
            .and_then(|x| x.get(..guid_section_header.get_body_size()))
        {
            Some(body) => body,
            None => {
                log::error!("Could not fetch compressed body at {:08X}", addr);
                continue;
            },
        };

        let mut dec_body: Vec<u8> = Vec::new();

        if lzma_decompress(&mut enc_body, &mut dec_body).is_err() {
            log::error!("Could not decompress section at {:08X}", addr);
            continue;
        }

        match find_pattern(&dec_body, AGESA_PATTERN).first().map(|(_, x)| {
            x.iter().map(|&x| if x == 0 { ' ' } else { x as char }).collect::<String>()
        }) {
            Some(x) => agesa.push(x),
            None => {
                log::error!("Could not find agesa in volumes from section at {:08X}", addr);
                continue;
            },
        }
    }

    Ok(agesa)
}
