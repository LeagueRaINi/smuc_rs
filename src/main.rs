mod macros;
mod parsers;
mod structs;
mod utils;
mod version;

use std::mem::size_of;
use std::path::Path;
use std::{env, fs};

use bytemuck::try_from_bytes;

use crate::parsers::parse_directories;
use crate::structs::FirmwareEntryTable;
use crate::utils::find_pattern;

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

    // TODO!: this doesnt detect all smu strings (tho in the roms where it doesnt i also couldnt find any tbh)
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

    for (addr, bytes) in fet_headers {
        let fet =
            match try_from_bytes::<FirmwareEntryTable>(&bytes[..size_of::<FirmwareEntryTable>()]) {
                Ok(x) => x,
                _ => {
                    log::error!("Could not parse fet header at {:08X}", addr);
                    continue;
                },
            };

        for (location, entry) in parse_directories(&data, fet.psp as usize, addr - 0x20000) {
            log::info!(
                "Location {:08X}, Size {:08X} ({:>3} KB) // {:X} {}",
                location,
                entry.packed_size,
                entry.packed_size / 1024,
                entry.get_version(),
                entry.try_get_processor_arch().unwrap_or("Unknown"),
            );
        }
    }
}
