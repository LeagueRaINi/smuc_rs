use bytemuck::{Pod, Zeroable};
use regex::bytes::Regex;
use std::fmt;

pub fn find_pattern<'a>(data: &'a [u8], pattern: &str) -> Vec<(usize, &'a [u8])> {
    let regex_string = &["(?s-u)", pattern].concat();
    let regex = Regex::new(regex_string).expect("Invalid regex");

    regex
        .captures_iter(data)
        .filter_map(|capture| (1..capture.len()).find_map(|x| capture.get(x)))
        .map(|match_| (match_.start(), match_.as_bytes()))
        .collect()
}

// amd saves the address memory aligned so we need to convert them
pub fn resolve_location(location: usize, offset: usize) -> usize {
    (location & 0x00FFFFFF) + offset
}

#[derive(Debug, Copy, Clone, Pod, Zeroable)]
#[repr(C)]
pub struct Version {
    pub build: u8,
    pub micro: u8,
    pub minor: u8,
    pub major: u8,
}

impl Version {
    pub fn is_zero(&self) -> bool {
        self.build == 0 && self.micro == 0 && self.minor == 0 && self.major == 0
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}.{}.{}.{}", self.major, self.minor, self.micro, self.build)
    }
}

impl fmt::LowerHex for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{:02x}.{:02x}.{:02x}.{:02x}", self.major, self.minor, self.micro, self.build)
    }
}

impl fmt::UpperHex for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{:02X}.{:02X}.{:02X}.{:02X}", self.major, self.minor, self.micro, self.build)
    }
}
