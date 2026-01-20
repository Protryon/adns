use std::hash::{Hash, Hasher};

use crate::Name;

#[derive(Debug, Eq, Clone)]
pub enum MaybeConcat<'a> {
    Concat(&'a [&'a str]),
    UnConcat(Name),
}

impl<'a, 'b> PartialEq<MaybeConcat<'b>> for MaybeConcat<'a> {
    fn eq(&self, other: &MaybeConcat<'b>) -> bool {
        match (self, other) {
            (MaybeConcat::Concat(x), MaybeConcat::Concat(y)) => {
                x.len() == y.len()
                    && x.iter()
                        .zip(y.iter())
                        .all(|(x, y)| x.eq_ignore_ascii_case(y))
            }
            (MaybeConcat::UnConcat(x), MaybeConcat::UnConcat(y)) => x == y,
            (MaybeConcat::UnConcat(unconcat), MaybeConcat::Concat(concat))
            | (MaybeConcat::Concat(concat), MaybeConcat::UnConcat(unconcat)) => {
                let mut index = 0usize;
                for component in concat.iter().copied() {
                    if index != 0 {
                        if !unconcat
                            .raw()
                            .get(index..index + 1)
                            .map(|x| x == ".")
                            .unwrap_or_default()
                        {
                            return false;
                        }
                        index += 1;
                    }
                    if !unconcat
                        .raw()
                        .get(index..index + component.len())
                        .map(|x| x.eq_ignore_ascii_case(component))
                        .unwrap_or_default()
                    {
                        return false;
                    }
                    index += component.len();
                }
                index == unconcat.len()
            }
        }
    }
}

impl<'a> Hash for MaybeConcat<'a> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            MaybeConcat::Concat(components) => {
                for component in components.iter() {
                    state.write_u8(component.len() as u8);
                    for b in component.as_bytes() {
                        state.write_u8(b.to_ascii_lowercase());
                    }
                }
            }
            MaybeConcat::UnConcat(name) => {
                for segment in name.segments() {
                    state.write_u8(segment.len() as u8);
                    for b in segment.as_bytes() {
                        state.write_u8(b.to_ascii_lowercase());
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::hash_map::DefaultHasher;

    use super::*;

    fn hash(h: &impl Hash) -> u64 {
        let mut hasher = DefaultHasher::new();
        h.hash(&mut hasher);
        hasher.finish()
    }

    #[test]
    fn test_maybe_concat() {
        assert_eq!(
            MaybeConcat::Concat(&["test", "com"]),
            MaybeConcat::UnConcat("test.com".parse().unwrap())
        );
        assert_eq!(
            MaybeConcat::Concat(&["tEst", "com"]),
            MaybeConcat::UnConcat("test.cOm".parse().unwrap())
        );
        assert_eq!(
            MaybeConcat::Concat(&["test"]),
            MaybeConcat::UnConcat("test".parse().unwrap())
        );
        assert_eq!(
            MaybeConcat::Concat(&[]),
            MaybeConcat::UnConcat("".parse().unwrap())
        );

        assert_eq!(
            hash(&MaybeConcat::Concat(&["test", "com"])),
            hash(&MaybeConcat::UnConcat("test.com".parse().unwrap()))
        );
        assert_eq!(
            hash(&MaybeConcat::Concat(&["tEst", "com"])),
            hash(&MaybeConcat::UnConcat("test.cOm".parse().unwrap()))
        );
        assert_eq!(
            hash(&MaybeConcat::Concat(&["test"])),
            hash(&MaybeConcat::UnConcat("test".parse().unwrap()))
        );
        assert_eq!(
            hash(&MaybeConcat::Concat(&[])),
            hash(&MaybeConcat::UnConcat("".parse().unwrap()))
        );
    }
}
