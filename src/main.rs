mod macros;
mod parsers;
mod structs;
mod utils;

use std::cmp::Ordering;
use std::mem::size_of;
use std::path::PathBuf;
use std::{env, fs};

use anyhow::{bail, Result};
use bytemuck::try_from_bytes;
use clap::Parser;
use lzma_rs::lzma_decompress;

use crate::parsers::parse_directories;
use crate::structs::{EfiGuidDefinedSection, FirmwareEntryTable};
use crate::utils::find_pattern;

#[derive(Parser, Debug)]
#[clap(about, author, version)]
struct Opt {
    #[cfg_attr(debug_assertions, structopt(default_value = "./resources/E7B78AMS.2H6"))]
    path: PathBuf,
}

fn try_find_agesa(data: &[u8]) -> Result<Vec<String>> {
    let section_pat = find_pattern(
        &data,
        r"\x93\xFD\x21\x9E\x72\x9C\x15\x4C\x8C\x4B\xE7\x7F\x1D\xB2\xD7\x92.{8}(.{4}\x98\x58\x4E\xEE\x14\x39\x59\x42\x9D\x6E\xDC\x7B\xD7\x94\x03\xCF.{4})",
    );
    if section_pat.is_empty() {
        bail!("Could not find dxe volume pattern")
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

        let mut enc_body = &data[addr + size_of::<EfiGuidDefinedSection>()..]
            [..guid_section_header.get_body_size()];
        let mut dec_body: Vec<u8> = Vec::new();

        if lzma_decompress(&mut enc_body, &mut dec_body).is_err() {
            log::error!("Could not decompress section");
            continue;
        }

        // TODO!: pray to god that the agesa strings in this decompressed section are all the same
        match find_pattern(&dec_body, r"(AGESA![0-9a-zA-Z]{0,10}\x00{0,1}[0-9a-zA-Z .\-]+)")
            .first()
            .map(|(_, x)| {
                x.iter().map(|&x| if x == 0 { ' ' } else { x as char }).collect::<String>()
            }) {
            Some(x) => agesa.push(x),
            None => {
                log::error!("Could not find agesa in volume");
                continue;
            },
        }
    }

    Ok(agesa)
}

fn main() -> Result<()> {
    env::set_var("RUST_LOG", env::var("RUST_LOG").unwrap_or_else(|_| "info".into()));

    pretty_env_logger::init();

    let Opt { path } = Opt::parse();

    let file_name = path.file_name().expect("Could not get file name");
    let data = fs::read(&path).expect("Could not read file");

    log::info!("FILE: {} ({} MB)", file_name.to_str().unwrap(), data.len() / 1024 / 1024);

    let fet_headers = find_pattern(&data, r"\xFF{16}(\xAA\x55\xAA\x55.{76})\xFF{16}");
    if fet_headers.is_empty() {
        bail!("Could not find FET header(s)!");
    }

    let agesa = try_find_agesa(&data)?;

    log::info!("AGESA: {:?}", agesa);

    if fet_headers.len() != agesa.len() {
        log::warn!("Found more FET headers than AGESA versions!");
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

        log::info!("FirmwareEntryTable: {:08X} ({} entries)", addr, entries.len());

        // Print entries and errors
        for (location, entry) in entries {
            match entry {
                Err(error) => log::error!("Location {:08X}, {:?}", location, error),
                Ok(entry) => {
                    log::info!(
                        "  Location {:08X}, Size {:08X} ({:>3} KB) // {:X} {}",
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
