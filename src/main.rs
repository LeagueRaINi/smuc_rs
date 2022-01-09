mod macros;
mod parsers;
mod structs;
mod utils;
mod version;

use std::cmp::Ordering;
use std::mem::size_of;
use std::path::Path;
use std::{env, fs};

use anyhow::{bail, Result};
use bytemuck::try_from_bytes;

use crate::parsers::parse_directories;
use crate::structs::FirmwareEntryTable;
use crate::utils::find_pattern;

fn main() -> Result<()> {
    env::set_var("RUST_LOG", env::var("RUST_LOG").unwrap_or_else(|_| "info".into()));
    pretty_env_logger::init();

    let args: Vec<String> = env::args().collect();
    let path = if cfg!(debug_assertions) {
        Path::new("./resources/E7B78AMS.2H6")
    } else {
        if args.len() < 2 {
            bail!("No file specified");
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
        bail!("Could not find FET header(s)!");
    }

    for (addr, bytes) in fet_headers {
        let bytes = match bytes.get(..size_of::<FirmwareEntryTable>()) {
            Some(bytes) => bytes,
            None => {
                log::error!("Could not fetch FET header at {:08X}", addr);
                continue;
            },
        };

        let fet = match try_from_bytes::<FirmwareEntryTable>(bytes) {
            Ok(fet) => fet,
            Err(e) => {
                log::error!("Could not parse FET header at {:08X} ({:?})", addr, e);
                continue;
            },
        };

        // TODO: Collect entries from all FET headers before sorting and printing them?
        let mut entries = parse_directories(&data, fet.psp as usize, addr - 0x20000);

        // Sort entries
        entries.sort_by(|(l_loc, l_res), (r_loc, r_res)| match (l_res, r_res) {
            // Sort by version, then by location (lower first)
            (Ok(l), Ok(r)) => l.get_version().cmp(&r.get_version()).then(l_loc.cmp(r_loc)),
            // Sort valid entries before errors
            (Ok(_), Err(_)) => Ordering::Less,
            (Err(_), Ok(_)) => Ordering::Greater,
            // Sort errors by location (lower first)
            (Err(_), Err(_)) => l_loc.cmp(r_loc),
        });

        // Print entries and errors
        for (location, entry) in entries {
            match entry {
                Err(error) => log::error!("Location {:08X}, {:?}", location, error),
                Ok(entry) => {
                    log::info!(
                        "Location {:08X}, Size {:08X} ({:>3} KB) // {:X} {}",
                        location,
                        entry.packed_size,
                        entry.packed_size / 1024,
                        entry.get_version(),
                        entry.try_get_processor_arch().unwrap_or("Unknown"),
                    );
                },
            }
        }
    }

    Ok(())
}
