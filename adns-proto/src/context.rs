use std::collections::HashMap;

use smallvec::{smallvec, SmallVec};

use crate::{maybe_concat::MaybeConcat, Header, Name, PacketParseError};

#[derive(Default)]
pub struct SerializeContext {
    current_packet: Vec<u8>,
    // map of `.` concatenated labels to ptr index
    known_labels: HashMap<MaybeConcat<'static>, u16>,
}

impl SerializeContext {
    pub fn capture_len_u16(&mut self, mut func: impl FnMut(&mut Self)) {
        let len_index = self.current_packet.len();
        // reserved room for length
        self.write_blob([0u8; 2]);
        let start = self.current_packet.len();

        func(self);
        let length: u16 = (self.current_packet.len() - start).try_into().unwrap();
        self.current_packet[len_index..start].copy_from_slice(&length.to_be_bytes());
    }

    pub fn write_blob(&mut self, blob: impl AsRef<[u8]>) {
        self.current_packet.extend(blob.as_ref());
    }

    pub fn write_cstring(&mut self, blob: impl AsRef<str>) {
        self.current_packet
            .push(blob.as_ref().len().try_into().expect("oversize cstring"));
        self.current_packet.extend(blob.as_ref().as_bytes());
    }

    pub fn wipe_compression(&mut self) {
        self.known_labels.clear();
    }

    pub fn write_name(&mut self, name: &Name) {
        let segments = name.segments().collect::<SmallVec<[&str; 6]>>();
        for (i, segment) in segments.iter().enumerate() {
            if let Some(ptr) = self
                .known_labels
                .get(&MaybeConcat::Concat(&segments[i..]))
                .copied()
            {
                let ref_ptr = ptr | 0b1100000000000000;
                self.current_packet.extend(ref_ptr.to_be_bytes());
                return;
            } else {
                if segment.len() > 63 {
                    panic!("name segment too long");
                }
                let ptr = self.current_packet.len() as u16;
                self.known_labels.insert(
                    MaybeConcat::UnConcat(Name::from_segments(&segments[i..]).unwrap()),
                    ptr,
                );
                self.current_packet.push(segment.len() as u8);
                self.current_packet.extend(segment.as_bytes());
            }
        }
        self.current_packet.push(0u8);
    }

    pub fn current(&self) -> &[u8] {
        &self.current_packet
    }

    pub fn finalize(self) -> Vec<u8> {
        self.current_packet
    }
}

pub struct DeserializeContext<'a> {
    packet: &'a [u8],
    index: usize,
    max_length: usize,
}

const MAX_NAME_INDIRECTION: usize = 32;

impl<'a> DeserializeContext<'a> {
    pub fn new_post_header(packet: &'a [u8]) -> Self {
        DeserializeContext {
            packet,
            index: Header::LENGTH,
            max_length: packet.len(),
        }
    }

    pub fn restrict<T>(
        &mut self,
        length: usize,
        mut func: impl FnMut(&mut Self) -> Result<T, PacketParseError>,
    ) -> Result<T, PacketParseError> {
        if self.index + length > self.max_length {
            return Err(PacketParseError::UnexpectedEOF);
        }
        let old_length = self.max_length;
        let end = self.index + length;
        self.max_length = end;
        let out = func(self);
        self.max_length = old_length;
        self.index = end;
        out
    }

    pub fn attempt<T>(&mut self, mut func: impl FnMut(&mut Self) -> Option<T>) -> Option<T> {
        let index = self.index;
        match func(self) {
            Some(out) => Some(out),
            None => {
                self.index = index;
                None
            }
        }
    }

    pub fn read_u8(&mut self) -> Result<u8, PacketParseError> {
        if self.index + 1 > self.max_length {
            return Err(PacketParseError::UnexpectedEOF);
        }
        let out = self.packet[self.index];
        self.index += 1;
        Ok(out)
    }

    pub fn read_n<const N: usize>(&mut self) -> Result<[u8; N], PacketParseError> {
        if self.index + N > self.max_length {
            return Err(PacketParseError::UnexpectedEOF);
        }
        let out = self.packet[self.index..self.index + N].try_into().unwrap();
        self.index += N;
        Ok(out)
    }

    pub fn read_all(&mut self, data: &mut [u8]) -> Result<(), PacketParseError> {
        if self.index + data.len() > self.max_length {
            return Err(PacketParseError::UnexpectedEOF);
        }
        data.copy_from_slice(&self.packet[self.index..self.index + data.len()]);
        self.index += data.len();
        Ok(())
    }

    pub fn read_cstring(&mut self) -> Result<String, PacketParseError> {
        let len = self.read_u8()?;
        let mut raw = vec![0u8; len as usize];
        self.read_all(&mut raw)?;
        Ok(String::from_utf8(raw).map_err(|e| e.utf8_error())?)
    }

    pub fn remaining(&self) -> usize {
        self.max_length - self.index
    }

    pub fn index(&self) -> usize {
        self.index
    }

    pub fn read<const N: usize, T, F: FnOnce([u8; N]) -> T>(
        &mut self,
        func: F,
    ) -> Result<T, PacketParseError> {
        Ok(func(self.read_n::<N>()?))
    }

    pub fn read_name(&mut self) -> Result<Name, PacketParseError> {
        let mut out = Name::default();
        let start_index = self.index;
        let mut continue_index = None::<usize>;
        let mut indirection_count = 0usize;
        loop {
            let start = self.read_u8()?;
            if start >> 6 == 0b11 {
                // pointer
                self.index -= 1;
                let new_index = (self.read(u16::from_be_bytes)? & 0b0011111111111111) as usize;
                if new_index >= start_index || new_index > self.max_length {
                    return Err(PacketParseError::CorruptName);
                }
                if continue_index.is_none() {
                    continue_index = Some(self.index);
                }
                self.index = new_index;
            } else if start == 0 {
                // end of segments
                break;
            } else if start >> 6 == 0 {
                // raw segment
                let mut segment: SmallVec<[u8; 64]> = smallvec![0u8; start as usize];
                self.read_all(&mut segment)?;
                let segment = std::str::from_utf8(&segment)?;
                out.push_segment(segment).unwrap();
            } else {
                return Err(PacketParseError::CorruptName);
            }
            indirection_count += 1;
            if indirection_count > MAX_NAME_INDIRECTION {
                return Err(PacketParseError::CorruptName);
            }
        }
        if let Some(continue_index) = continue_index {
            self.index = continue_index;
        }
        Ok(out)
    }
}
