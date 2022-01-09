#[macro_export]
macro_rules! make_dir {
    ($visibility:vis $name:ident, $header_type:ty, $entry_type:ty) => {
        #[allow(dead_code)]
        $visibility struct $name<'a> {
            $visibility address: usize,
            $visibility header: &'a $header_type,
            $visibility entries: Vec<&'a $entry_type>,
        }

        impl $name<'_> {
            pub fn new(address: usize, data: &[u8]) -> Option<$name> {
                let data = &data[address..];

                const HEADER_SIZE: usize = size_of::<$header_type>();
                const ENTRY_SIZE: usize = size_of::<$entry_type>();

                try_from_bytes::<$header_type>(data.get(..HEADER_SIZE)?)
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
