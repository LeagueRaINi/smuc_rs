use std::mem::size_of;
use std::path::Path;
use std::{env, fs};

use bytemuck::{try_from_bytes, Pod, Zeroable};
use regex::bytes::Regex;

macro_rules! make_dir {
    ($visibility:vis $name:ident, $header_type:ty, $entry_type:ty) => {
        #[allow(dead_code)]
        $visibility struct $name<'a> {
            address: usize,
            header: &'a $header_type,
            entries: Vec<&'a $entry_type>,
        }

        impl $name<'_> {
            pub fn new(address: usize, data: &[u8]) -> Option<$name> {
                let data = &data[address..];

                const HEADER_SIZE: usize = size_of::<$header_type>();
                const ENTRY_SIZE: usize = size_of::<$entry_type>();

                try_from_bytes::<$header_type>(&data[..HEADER_SIZE])
                    .and_then(|header| {
                        Ok($name {
                            address,
                            header,
                            entries: data[HEADER_SIZE..][..header.entries as usize * ENTRY_SIZE]
                                .chunks_exact(ENTRY_SIZE)
                                .filter_map(|chunk| try_from_bytes::<$entry_type>(chunk).ok())
                                .collect::<Vec<_>>(),
                        })
                    })
                    .ok()
            }
        }
    }
}

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
    pub sub_program: u8,
    pub rom_id: u8,
    pub rsvd_03: u8,
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

make_dir!(ComboDirectory, ComboDirectoryHeader, ComboDirectoryEntry);
make_dir!(PspDirectory, DirectoryHeader, PspDirectoryEntry);

pub fn find_pattern<'a>(data: &'a [u8], pattern: &str) -> Vec<(usize, &'a [u8])> {
    let regex_string = &["(?s-u)", pattern].concat();
    let regex = Regex::new(regex_string).expect("Invalid regex");

    regex
        .captures_iter(data)
        .filter_map(|capture| (1..capture.len()).find_map(|x| capture.get(x)))
        .map(|match_| (match_.start(), match_.as_bytes()))
        .collect()
}

pub fn get_processor_arch(ver1: u8, ver2: u8) -> Option<&'static str> {
    match [ver1, ver2] {
        [0x00, 0x38] => Some("Vermeer"),        // Ryzen 5XXX
        [0x00, 0x2E] => Some("Matisse"),        // Ryzen 3XXX
        [0x00, 0x2B] => Some("Pinnacle Ridge"), // Ryzen 2XXX
        [0x00, 0x19] => Some("Summit Ridge"),   // Ryzen 1XXX

        [0x00, 0x40] => Some("Cezanne"),       // Ryzen 5XXX (APU)
        [0x00, 0x37] => Some("Renoir"),        // Ryzen 4XXX (APU)
        [0x04, 0x1E] => Some("Picasso"),       // Ryzen 3XXX (APU)
        [0x00, 0x25] => Some("Raven Ridge 2"), // Ryzen 2XXX (APU - Refresh)
        [0x00, 0x1E] => Some("Raven Ridge"),   // Ryzen 2XXX (APU)

        [0x04, 0x24] => Some("Castle Peak"), // Threadripper 3XXX
        [0x04, 0x2B] => Some("Colfax"),      // Threadripper 2XXX
        [0x04, 0x19] => Some("Whitehaven"),  // Threadripper 1XXX (also matches Naples - EPYC 7001)

        [0x00, 0x24] => Some("Rome"),  // EPYC 7003
        [0x00, 0x2D] => Some("Milan"), // EPYC 7002
        _ => None,
    }
}

pub fn parse_directory(data: &[u8], address: usize, offset: usize, smus: &mut Vec<usize>) {
    // amd saves the address memory aligned so we need to convert them
    let convert_address = |address: usize| (address & 0x00FFFFFF) + offset;

    let address = convert_address(address);

    match &data[address..][..4] {
        b"2PSP" => {
            let directory = match ComboDirectory::new(address, data) {
                Some(directory) => directory,
                None => {
                    log::error!("Failed to parse combo directory at {:08X}", address);
                    return;
                },
            };

            directory
                .entries
                .iter()
                .for_each(|entry| parse_directory(data, entry.location as usize, offset, smus))
        },
        b"$PSP" | b"$PL2" => {
            let directory = match PspDirectory::new(address, data) {
                Some(directory) => directory,
                None => {
                    log::error!("Failed to parse psp directory at {:08X}", address);
                    return;
                },
            };

            directory.entries.iter().for_each(|entry| {
                match entry.kind {
                    // SMU Firmware
                    0x08 | 0x12 => {
                        let location = convert_address(entry.location as usize);

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

                        log::info!(
                            "Location {:08X}, Size {:08X} ({:<3} KB) // {} {}",
                            location,
                            entry.size,
                            entry.size / 1024,
                            format!(
                                "{:02}.{:02}.{:02}.{:02} ({0:02X}.{1:02X}.{2:02X}.{3:02X})",
                                version[0x3], version[0x2], version[0x1], version[0x00]
                            ),
                            get_processor_arch(version[0x3], version[0x2]).unwrap_or("Unknown"),
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
    let path = if cfg!(debug_assertions) {
        Path::new("./resources/E7B78AMS.2H6")
    } else {
        if args.len() < 2 {
            log::error!("No file specified");
            return;
        }

        Path::new(&args[1])
    };

    let file_name = path.file_name().expect("Could not get file name");
    let data = fs::read(path).expect("Could not read file");

    log::info!("BIOS: {} ({} KB)", file_name.to_str().unwrap(), data.len() / 1024);

    // TODO!: this doesnt detect all smu strings
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

    // TODO!: get rid of this by making a parse_smus method that recursively parses the directories and
    // returns Vec<PspDirectoryEntry>
    let mut smus: Vec<usize> = Vec::new();

    for (addr, bytes) in fet_headers {
        let fet =
            match try_from_bytes::<FirmwareEntryTable>(&bytes[..size_of::<FirmwareEntryTable>()]) {
                Ok(x) => x,
                _ => {
                    log::error!("Could not parse fet header at {:08X}", addr);
                    continue;
                },
            };

        parse_directory(&data, fet.psp as usize, addr - 0x20000, &mut smus);
    }
}
