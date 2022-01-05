use std::mem::size_of;
use std::path::Path;
use std::{env, fs};

use bytemuck::{try_from_bytes, Pod, Zeroable};
use regex::bytes::Regex;

#[derive(Debug, Copy, Clone, Pod, Zeroable)]
#[repr(C)]
struct FirmwareEntryTable {
    pub signature: [u8; 0x04],
    pub rsv_04: [u8; 0x10],
    pub psp: u32,
}

#[derive(Debug, Copy, Clone, Pod, Zeroable)]
#[repr(C)]
struct DirectoryHeader {
    pub signature: [u8; 0x4],
    pub checksum: u32,
    pub entries: u32,
    pub rsvd_0c: [u8; 0x4],
}

#[derive(Debug, Copy, Clone, Pod, Zeroable)]
#[repr(C)]
struct ComboDirectoryHeader {
    pub signature: [u8; 0x4],
    pub checksum: u32,
    pub entries: u32,
    pub look_up_mode: u32,
    pub rsvd_10: [u8; 0x10],
}

#[derive(Debug, Copy, Clone, Pod, Zeroable)]
#[repr(C)]
struct PspDirectoryEntry {
    pub kind: u8,
    pub rsvd_02: [u8; 0x3],
    pub size: u32,
    pub location: u64,
}

#[derive(Debug, Copy, Clone, Pod, Zeroable)]
#[repr(C)]
struct ComboDirectoryEntry {
    pub id_select: u32,
    pub id: u32,
    pub location: u64,
}

pub fn find_pattern<'a>(data: &'a [u8], pattern: &str) -> Vec<(usize, &'a [u8])> {
    let regex_string = &["(?s-u)", pattern].concat();
    let regex = Regex::new(regex_string).expect("Invalid regex");

    regex
        .captures_iter(data)
        .filter_map(|capture| (1..capture.len()).find_map(|x| capture.get(x)))
        .map(|match_| (match_.start(), match_.as_bytes()))
        .collect()
}

pub fn get_processor(ver1: u8, ver2: u8) -> Option<&'static str> {
    match [ver1, ver2] {
        [0x00, 0x38] => Some("Vermeer"),        // Ryzen 5XXX
        [0x00, 0x2E] => Some("Matisse"),        // Ryzen 3XXX
        [0x00, 0x2B] => Some("Pinnacle Ridge"), // Ryzen 2XXX
        [0x00, 0x19] => Some("Summit Ridge"),   // Ryzen 1XXX

        [0x00, 0x40] => Some("Cezanne"),        // Ryzen 5XXX (APU)
        [0x00, 0x37] => Some("Renoir"),         // Ryzen 4XXX (APU)
        [0x04, 0x1E] => Some("Picasso"),        // Ryzen 3XXX (APU)
        [0x00, 0x25] => Some("Raven Ridge 2"),  // Ryzen 2XXX (APU - Refresh)
        [0x00, 0x1E] => Some("Raven Ridge"),    // Ryzen 2XXX (APU)

        [0x04, 0x24] => Some("Castle Peak"),    // Threadripper 3XXX
        [0x04, 0x2B] => Some("Colfax"),         // Threadripper 2XXX
        [0x04, 0x19] => Some("Whitehaven"),     // Threadripper 1XXX (also matches Naples - EPYC 7001)

        [0x00, 0x24] => Some("Rome"),           // EPYC 7003
        [0x00, 0x2D] => Some("Milan"),          // EPYC 7002
        _ => None,
    }
}

pub fn parse_directory(data: &[u8], address: usize, offset: usize, smus: &mut Vec<usize>) {
    let calc_address = |address: usize| (address & 0x00FFFFFF) + offset;

    let address = calc_address(address);

    match &data[address..][..4] {
        b"2PSP" => {
            let header = match try_from_bytes::<ComboDirectoryHeader>(
                &data[address..][..size_of::<ComboDirectoryHeader>()],
            ) {
                Ok(header) => header,
                _ => {
                    log::error!("Failed to parse 2PSP at {:08X}", address);
                    return;
                },
            };

            let entries = &data[address + size_of::<ComboDirectoryHeader>()..]
                [..size_of::<ComboDirectoryEntry>() * header.entries as usize];

            entries
                .chunks_exact(size_of::<ComboDirectoryEntry>())
                .filter_map(|x| try_from_bytes::<ComboDirectoryEntry>(x).ok())
                .for_each(|entry| parse_directory(data, entry.location as usize, offset, smus));
        },
        b"$PSP" | b"$PL2" => {
            let header = match try_from_bytes::<DirectoryHeader>(
                &data[address..][..size_of::<DirectoryHeader>()],
            ) {
                Ok(header) => header,
                _ => {
                    log::error!("Failed to parse $PSP/$PL2 at {:08X}", address);
                    return;
                },
            };

            let entries = &data[address + size_of::<DirectoryHeader>()..]
                [..size_of::<PspDirectoryEntry>() * header.entries as usize];

            entries
                .chunks_exact(size_of::<PspDirectoryEntry>())
                .filter_map(|x| try_from_bytes::<PspDirectoryEntry>(x).ok())
                .for_each(|entry| {
                    match entry.kind {
                        // SMU Firmware
                        0x08 | 0x12 => {
                            let location = calc_address(entry.location as usize);

                            if smus.contains(&location) {
                                return;
                            }

                            let version = {
                                let bytes = &data[location + 0x60..][..4];
                                if bytes == [0x00, 0x00, 0x00, 0x00] {
                                    &data[location..][..0x4]
                                } else {
                                    bytes
                                }
                            };

                            let processor = get_processor(version[0x3], version[0x2])
                                .unwrap_or("Unknown");

                            log::info!(
                                "Location {:08X}, Size {:08X} ({:<3} KB) // {} {}",
                                location,
                                entry.size,
                                entry.size / 1024,
                                format!("{:02}.{:02}.{:02}.{:02} ({:02X}.{:02X}.{:02X}.{:02X})",
                                    version[0x3], version[0x2], version[0x1], version[0x00],
                                    version[0x3], version[0x2], version[0x1], version[0x00]),
                                processor,
                            );

                            smus.push(location);
                        },
                        // PSP Level 2 Directory
                        0x40 | 0x70 => parse_directory(data, entry.location as usize, offset, smus),
                        _ => (),
                    }
                });
        },
        _ => (),
    }
}

fn main() {
    env::set_var("RUST_LOG", env::var("RUST_LOG").unwrap_or_else(|_| "info".into()));

    pretty_env_logger::init();

    let args: Vec<String> = env::args().collect();

    let path = Path::new(&args[1]);
    let file_name = path.file_name().unwrap().to_str().unwrap();

    let data = fs::read(path).unwrap();

    log::info!("BIOS: {}", file_name);

    let agesa = find_pattern(&data, r"(AGESA![0-9a-zA-Z]{0,10}\x00{0,1}[0-9a-zA-Z .\-]+)")
        .into_iter()
        .map(|(_, x)| x.iter().map(|&x| if x == 0 { ' ' } else { x as char }).collect::<String>())
        .collect::<Vec<String>>();

    if !agesa.is_empty() {
        log::info!("AGESA: {:?}", agesa);
    }

    let fet_headers = find_pattern(&data, r"\xFF{16}(\xAA\x55\xAA\x55.{76})\xFF{16}");
    if fet_headers.is_empty() {
        panic!("Could not find FET header(s)!");
    }

    let mut smus: Vec<usize> = Vec::new();

    for (addr, bytes) in fet_headers {
        let fet =
            match try_from_bytes::<FirmwareEntryTable>(&bytes[..size_of::<FirmwareEntryTable>()]) {
                Ok(x) => x,
                _ => {
                    log::error!("Could not parse FET header at {:08X}", addr);
                    continue;
                },
            };

        parse_directory(&data, fet.psp as usize, addr - 0x20000, &mut smus);
    }
}
