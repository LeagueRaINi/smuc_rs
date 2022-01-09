use std::collections::BTreeMap;
use std::iter;

use crate::structs::{ComboDirectory, PspDirectory, PspDirectoryEntry, PspEntryHeader};
use crate::utils::resolve_location;

type EntryIter<'a> = Box<dyn Iterator<Item = (usize, &'a PspEntryHeader)> + 'a>;

fn parse_combo_directory(data: &[u8], address: usize, offset: usize) -> EntryIter<'_> {
    let directory = match ComboDirectory::new(address, data) {
        Some(directory) => directory,
        None => {
            log::error!("Failed to parse combo directory at {:08X}", address);
            return Box::new(iter::empty());
        },
    };

    Box::new(
        directory
            .entries
            .into_iter()
            .flat_map(move |e| parse_directory(data, e.location as usize, offset)),
    )
}

fn parse_psp_entry<'a>(data: &'a [u8], entry: &PspDirectoryEntry, offset: usize) -> EntryIter<'a> {
    match entry.kind {
        // PSP Level 2 Directory
        0x40 | 0x70 => parse_directory(data, entry.location as usize, offset),
        // SMU Firmware
        0x08 | 0x12 => {
            let location = resolve_location(entry.location as usize, offset);

            match PspEntryHeader::new(&data[location..]) {
                Some(entry_header) => Box::new(iter::once((location, entry_header))),
                None => {
                    log::error!("Failed to parse psp entry header at {:08X}", location);
                    Box::new(iter::empty())
                },
            }
        },
        _ => Box::new(iter::empty()),
    }
}

fn parse_psp_directory(data: &[u8], address: usize, offset: usize) -> EntryIter<'_> {
    match PspDirectory::new(address, data) {
        Some(directory) => Box::new(
            directory
                .entries
                .into_iter()
                .flat_map(move |entry| parse_psp_entry(data, entry, offset)),
        ),
        None => {
            log::error!("Failed to parse psp directory at {:08X}", address);
            Box::new(iter::empty())
        },
    }
}

fn parse_directory(data: &[u8], address: usize, offset: usize) -> EntryIter<'_> {
    let address = resolve_location(address, offset);

    match &data[address..][..4] {
        b"2PSP" => parse_combo_directory(data, address, offset),
        b"$PSP" | b"$PL2" => parse_psp_directory(data, address, offset),
        header => unimplemented!("Unknown directory header at {:08X}: {:?}", address, header),
    }
}

pub fn parse_directories(
    data: &[u8],
    address: usize,
    offset: usize,
) -> BTreeMap<usize, &PspEntryHeader> {
    parse_directory(data, address, offset).collect()
}
