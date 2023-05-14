use anyhow::{anyhow, Error, Result};
use std::iter;

use crate::structs::{ComboDirectory, Generation, PspDirectory, PspDirectoryEntry, PspEntryHeader};
use crate::utils::resolve_location;

type Iter<'a> =
    Box<dyn Iterator<Item = (usize, Result<&'a PspEntryHeader>, Option<Generation>)> + 'a>;

fn header(location: usize, header: &PspEntryHeader, generation: Option<Generation>) -> Iter<'_> {
    Box::new(iter::once((location, Ok(header), generation)))
}

fn error<'a>(location: usize, error: Error, generation: Option<Generation>) -> Iter<'a> {
    Box::new(iter::once((location, Err(error), generation)))
}

fn parse_combo_directory(data: &[u8], address: usize, offset: usize) -> Iter<'_> {
    let directory = match ComboDirectory::new(address, data) {
        Err(err) => return error(address, err, None),
        Ok(directory) => directory,
    };
    let entries = directory.entries.into_iter();
    Box::new(entries.flat_map(move |e| {
        parse_directory(data, e.location as usize, offset, Some(e.try_get_gen()))
    }))
}

fn parse_psp_entry<'a>(
    data: &'a [u8],
    entry: &PspDirectoryEntry,
    offset: usize,
    generation: Option<Generation>,
) -> Iter<'a> {
    match entry.kind {
        0x40 | 0x70 => parse_directory(data, entry.location as usize, offset, generation),
        0x08 | 0x12 => {
            let location = resolve_location(entry.location as usize, offset);

            let data = match data.get(location..) {
                None => {
                    return error(location, anyhow!("Could not fetch PSP entry header"), generation)
                },
                Some(data) => data,
            };

            let entry_header = match PspEntryHeader::new(data) {
                Err(err) => return error(location, err, generation),
                Ok(entry_header) => entry_header,
            };

            header(location, entry_header, generation)
        },
        _ => Box::new(iter::empty()),
    }
}

fn parse_psp_directory(
    data: &[u8],
    address: usize,
    offset: usize,
    generation: Option<Generation>,
) -> Iter<'_> {
    let directory = match PspDirectory::new(address, data) {
        Ok(directory) => directory,
        Err(err) => return error(address, err, generation),
    };
    Box::new(
        directory
            .entries
            .into_iter()
            .flat_map(move |e| parse_psp_entry(data, e, offset, generation)),
    )
}

pub fn parse_directory(
    data: &[u8],
    address: usize,
    offset: usize,
    generation: Option<Generation>,
) -> Iter<'_> {
    let address = resolve_location(address, offset);
    match &data[address..][..4] {
        b"2PSP" | b"2BHD" => parse_combo_directory(data, address, offset),
        b"$PSP" | b"$PL2" => parse_psp_directory(data, address, offset, generation),
        sig => error(
            address,
            anyhow!(
                "Unknown PSP entry signature: {} ({:#x})",
                std::str::from_utf8(sig).unwrap_or("<invalid>"),
                u32::from_be_bytes([sig[0], sig[1], sig[2], sig[3]]),
            ),
            generation,
        ),
    }
}

pub fn parse_directories(
    data: &[u8],
    address: usize,
    offset: usize,
) -> Vec<(usize, Result<&PspEntryHeader>, Option<Generation>)> {
    let mut vec = parse_directory(data, address, offset, None).collect::<Vec<_>>();
    vec.sort_by_key(|&(location, _, _)| location);
    vec.dedup_by_key(|&mut (location, _, _)| location);
    vec.sort_by(|(_, res1, _), (_, res2, _)| match (res1, res2) {
        (Ok(h1), Ok(h2)) => h1.packed_size.cmp(&h2.packed_size),
        (Ok(_), Err(_)) => std::cmp::Ordering::Less,
        (Err(_), Ok(_)) => std::cmp::Ordering::Greater,
        (Err(_), Err(_)) => std::cmp::Ordering::Equal,
    });
    vec.sort_by(|(_, res1, _), (_, res2, _)| match (res1, res2) {
        (Ok(h1), Ok(h2)) => h1.get_version().cmp(&h2.get_version()),
        (Ok(_), Err(_)) => std::cmp::Ordering::Less,
        (Err(_), Ok(_)) => std::cmp::Ordering::Greater,
        (Err(_), Err(_)) => std::cmp::Ordering::Equal,
    });
    // INFO: havent decided yet if we wanna only show unique entries
    // vec.dedup_by(|(_, res1), (_, res2)| {
    //     matches!((res1, res2), (Ok(h1), Ok(h2)) if h1.get_version() == h2.get_version() && h1.packed_size == h2.packed_size)
    // });
    vec
}
