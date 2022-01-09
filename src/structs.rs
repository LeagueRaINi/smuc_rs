use std::mem::size_of;

use bytemuck::{try_from_bytes, Pod, Zeroable};
use static_assertions::assert_eq_size;

use crate::make_dir;
use crate::utils::Version;

#[derive(Debug, Copy, Clone, Pod, Zeroable)]
#[repr(C)]
pub struct FirmwareEntryTable {
    pub signature: [u8; 0x04],
    pub rsv_04: [u8; 0x10],
    pub psp: u32,
}

#[derive(Debug, Copy, Clone, Pod, Zeroable)]
#[repr(C)]
pub struct DirectoryHeader {
    pub signature: [u8; 0x4],
    pub checksum: [u8; 0x4],
    pub entries: u32,
    pub rsvd_0c: [u8; 0x4],
}

#[derive(Debug, Copy, Clone, Pod, Zeroable)]
#[repr(C)]
pub struct ComboDirectoryHeader {
    pub signature: [u8; 0x4],
    pub checksum: [u8; 0x4],
    pub entries: u32,
    pub look_up_mode: u32,
    pub rsvd_10: [u8; 0x10],
}

#[derive(Debug, Copy, Clone, Pod, Zeroable)]
#[repr(C)]
pub struct PspDirectoryEntry {
    pub kind: u8,
    pub sub_program: u8,
    pub rom_id: u8,
    pub rsvd_03: u8,
    pub size: u32,
    pub location: u64,
}

#[derive(Debug, Copy, Clone, Pod, Zeroable)]
#[repr(C)]
pub struct ComboDirectoryEntry {
    pub id_select: u32,
    pub id: u32,
    pub location: u64,
}

#[derive(Debug, Copy, Clone, Pod, Zeroable)]
#[repr(C)]
pub struct PspEntryHeader {
    pub rsvd_0: [u8; 0x10],
    pub signature: [u8; 0x4],
    pub rsvd_14: [u8; 0x4c],
    pub version: Version,
    pub rsvd_64: [u8; 0x8],
    pub packed_size: u32,
    pub rsvd_70: [u8; 0x90],
}

impl PspEntryHeader {
    pub fn new(data: &[u8]) -> Option<&PspEntryHeader> {
        try_from_bytes::<PspEntryHeader>(data.get(..size_of::<Self>())?).ok()
    }

    pub fn get_version(&self) -> Version {
        if self.version.is_zero() {
            Version {
                build: self.rsvd_0[0],
                micro: self.rsvd_0[1],
                minor: self.rsvd_0[2],
                major: self.rsvd_0[3],
            }
        } else {
            self.version
        }
    }

    #[rustfmt::skip]
    pub fn try_get_processor_arch(&self) -> Option<&'static str> {
        let Version { major, minor, .. } = self.get_version();
        match [major, minor] {
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
}

make_dir!(pub ComboDirectory, ComboDirectoryHeader, ComboDirectoryEntry);
make_dir!(pub PspDirectory, DirectoryHeader, PspDirectoryEntry);

assert_eq_size!([u8; 0x10], PspDirectoryEntry);
assert_eq_size!([u8; 0x10], DirectoryHeader);
assert_eq_size!([u8; 0x20], ComboDirectoryHeader);
assert_eq_size!([u8; 0x10], ComboDirectoryEntry);
assert_eq_size!([u8; 0x100], PspEntryHeader);
