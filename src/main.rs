mod macros;
mod parsers;
mod structs;
mod utils;

use std::io::Read;
use std::mem::size_of;
use std::path::PathBuf;
use std::{env, fs, io};

use anyhow::{bail, Result};
use bytemuck::try_from_bytes;
use clap::Parser;

use crate::parsers::parse_directories;
use crate::structs::FirmwareEntryTable;
use crate::utils::{find_pattern, try_find_agesa};

#[derive(Parser, Debug)]
#[clap(about, author, version)]
struct Opt {
    path: PathBuf,
}

fn main() -> Result<()> {
    env::set_var("RUST_LOG", env::var("RUST_LOG").unwrap_or_else(|_| "info".into()));

    pretty_env_logger::init();

    let Opt { path } = Opt::parse();

    let file_name = path.file_name().expect("Could not get file name");
    let data = fs::read(&path).expect("Could not read file");

    let fet_headers = find_pattern(&data, r"\xFF{16}(\xAA\x55\xAA\x55.{76})\xFF{16}");
    if fet_headers.is_empty() {
        bail!("Could not find FET header(s)!");
    }

    let agesa = try_find_agesa(&data);

    log::info!(" FILE: {} ({} MB)", file_name.to_str().unwrap(), data.len() / 1024 / 1024);
    log::info!("AGESA: {:?}", agesa);

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

        log::info!("");
        log::info!("[{:08X}] FirmwareEntryTable", addr);

        for (location, entry, generation) in
            parse_directories(&data, fet.psp as usize, addr - 0x20000)
        {
            match entry {
                Err(error) => log::error!("Location {:08X}, {:?}", location, error),
                Ok(entry) => log::info!(
                    "   Location {:08X}, Size {:08X} ({:>3} KB) // {:?} {} {}",
                    location,
                    entry.packed_size,
                    entry.packed_size / 1024,
                    generation,
                    entry.get_version(),
                    entry.try_get_processor_arch().unwrap_or("Unknown"),
                ),
            }
        }
    }

    // TODO!: less ghetto readline
    let _ = io::stdin().read(&mut [0u8]).unwrap();

    Ok(())
}
