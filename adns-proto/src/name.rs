use core::fmt;
use std::{
    hash::{Hash, Hasher},
    str::FromStr,
};

use smallvec::SmallVec;
use thiserror::Error;

#[derive(Clone, Debug, Default, Eq)]
pub struct Name {
    full: String,
    segment_indices: SmallVec<[u16; 8]>,
}

#[cfg(feature = "serde")]
impl serde::Serialize for Name {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.full.serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Name {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        raw.parse().map_err(serde::de::Error::custom)
    }
}

impl PartialEq for Name {
    fn eq(&self, other: &Self) -> bool {
        self.full == other.full
    }
}

impl PartialOrd for Name {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.full.partial_cmp(&other.full)
    }
}

impl Ord for Name {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.full.cmp(&other.full)
    }
}

impl AsRef<str> for Name {
    fn as_ref(&self) -> &str {
        &self.full
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.full)
    }
}

impl Hash for Name {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.full.hash(state);
    }
}

#[derive(Error, Debug)]
pub enum NameParseError {
    #[error("name label segment over 63 char long")]
    NameLabelTooLong,
    #[error("name over 255 char long")]
    NameTooLong,
}

impl FromStr for Name {
    type Err = NameParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() > 255 {
            return Err(NameParseError::NameTooLong);
        }
        let mut out = Name {
            full: String::with_capacity(s.len() + 1),
            segment_indices: Default::default(),
        };
        for x in s.split('.') {
            out.push_segment(x)?;
        }
        Ok(out)
    }
}

impl Name {
    pub fn ends_with(&self, other: &Name) -> bool {
        if self.full == other.full {
            return true;
        }
        if self.segment_indices.len() < other.segment_indices.len() {
            return false;
        }
        for (self_segment, other_segment) in self.segments().rev().zip(other.segments().rev()) {
            if self_segment != other_segment {
                return false;
            }
        }
        true
    }

    /// matches ** -> any number of segments (prefix only), *+ -> matches one or more segments, * -> any one segment, @ -> empty
    pub fn contains(&self, other: &Name) -> bool {
        if self.full == other.full {
            return true;
        }

        let mut segments = self.segments().peekable();

        // wildcard prefix
        if segments.peek().copied() == Some("**") {
            segments.next().unwrap();
            if other.segment_indices.len() < self.segment_indices.len().saturating_sub(1) {
                return false;
            }
            for (other, ours) in other.segments().rev().zip(segments.rev()) {
                if ours != "*" && other != ours {
                    return false;
                }
            }
        } else if segments.peek().copied() == Some("*+") {
            segments.next().unwrap();
            if other.segment_indices.len() < self.segment_indices.len() {
                return false;
            }
            for (other, ours) in other.segments().rev().zip(segments.rev()) {
                if ours != "*" && other != ours {
                    return false;
                }
            }
        } else {
            if other.segment_indices.len() != self.segment_indices.len() {
                return false;
            }
            for (other, ours) in other.segments().zip(segments) {
                if ours != "*" && other != ours {
                    return false;
                }
            }
        }

        true
    }

    pub fn from_segments<S: AsRef<str>>(
        segments: impl IntoIterator<Item = S>,
    ) -> Result<Self, NameParseError> {
        let mut out = Self::default();
        for segment in segments {
            out.push_segment(segment.as_ref())?;
        }
        if out.full.len() > 255 {
            return Err(NameParseError::NameTooLong);
        }
        Ok(out)
    }

    pub fn push_segment(&mut self, segment: impl AsRef<str>) -> Result<(), NameParseError> {
        let segment = segment.as_ref();
        if segment.is_empty() {
            return Ok(());
        }
        if segment.len() > 63 {
            return Err(NameParseError::NameLabelTooLong);
        }
        self.full.reserve(segment.len() + 1);
        if !self.full.is_empty() {
            self.full.push('.');
        }
        let start = self.full.len();
        self.full.push_str(segment);
        self.full[start..].make_ascii_lowercase();
        if self.full.len() > 255 {
            return Err(NameParseError::NameTooLong);
        }
        self.segment_indices.push(start.try_into().unwrap());
        Ok(())
    }

    pub fn segments(&self) -> SegmentIterator<'_> {
        SegmentIterator {
            name: self,
            index: 0,
            end_index: self.segment_indices.len(),
        }
    }
}

pub struct SegmentIterator<'a> {
    name: &'a Name,
    index: usize,
    end_index: usize,
}

impl<'a> Iterator for SegmentIterator<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.end_index {
            return None;
        }
        let index = *self.name.segment_indices.get(self.index)?;
        let end = self
            .name
            .segment_indices
            .get(self.index + 1)
            .map(|x| x.saturating_sub(1))
            .unwrap_or(self.name.full.len() as u16);
        self.index += 1;
        self.name.full.get(index as usize..end as usize)
    }
}

impl<'a> DoubleEndedIterator for SegmentIterator<'a> {
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.index >= self.end_index {
            return None;
        }
        let end = if self.end_index >= self.name.segment_indices.len() {
            self.name.full.len() as u16
        } else {
            self.name
                .segment_indices
                .get(self.end_index)
                .unwrap()
                .saturating_sub(1)
        };
        let index = self
            .end_index
            .checked_sub(1)
            .map(|x| self.name.segment_indices.get(x).unwrap())
            .copied()
            .unwrap_or_default();
        self.end_index = self.end_index.checked_sub(1).unwrap();
        self.name.full.get(index as usize..end as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_name() {
        let name: Name = "test.com".parse().unwrap();
        {
            let mut iter = name.segments();
            assert_eq!(iter.next(), Some("test"));
            assert_eq!(iter.next(), Some("com"));
            assert_eq!(iter.next(), None);
        }
        {
            let mut iter = name.segments().rev();
            assert_eq!(iter.next(), Some("com"));
            assert_eq!(iter.next(), Some("test"));
            assert_eq!(iter.next(), None);
        }

        let name_container: Name = "**.test.com".parse().unwrap();
        assert!(name_container.contains(&name));
        let name_container: Name = "*+.test.com".parse().unwrap();
        assert!(!name_container.contains(&name));
        let name2: Name = "west.test.com".parse().unwrap();
        assert!(name_container.contains(&name2));
        let name_container: Name = "west.*.com".parse().unwrap();
        assert!(name_container.contains(&name2));
        assert!(!name_container.contains(&name));

        assert!(name2.ends_with(&name));
        assert!(!name.ends_with(&name2));
    }
}
