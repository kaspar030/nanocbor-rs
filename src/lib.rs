//#![cfg_attr(not(test), no_std)]

use core::convert::TryFrom;
use core::convert::TryInto;

use byteorder::{BigEndian, ByteOrder};

pub mod constants {
    pub const NANOCBOR_TYPE_OFFSET: usize = 5; // Bit shift for CBOR major types
    pub const NANOCBOR_TYPE_MASK: u8 = 0xE0; // Mask for CBOR major types
    pub const NANOCBOR_VALUE_MASK: u8 = 0x1F; // Mask for CBOR values

    pub const NANOCBOR_TYPE_UINT: u8 = 0x00u8; // positive integer type
    pub const NANOCBOR_TYPE_NINT: u8 = 0x01u8; // negative integer type
    pub const NANOCBOR_TYPE_BSTR: u8 = 0x02u8; // byte string type
    pub const NANOCBOR_TYPE_TSTR: u8 = 0x03u8; // text string type
    pub const NANOCBOR_TYPE_ARR: u8 = 0x04u8; // array type
    pub const NANOCBOR_TYPE_MAP: u8 = 0x05u8; // map type
    pub const NANOCBOR_TYPE_TAG: u8 = 0x06u8; // tag type
    pub const NANOCBOR_TYPE_FLOAT: u8 = 0x07u8; // float type

    // CBOR simple data types
    pub const NANOCBOR_SIMPLE_FALSE: u8 = 20u8; // False
    pub const NANOCBOR_SIMPLE_TRUE: u8 = 21u8; // True
    pub const NANOCBOR_SIMPLE_NULL: u8 = 22u8; // NULL
    pub const NANOCBOR_SIMPLE_UNDEF: u8 = 23u8; // Undefined

    pub const NANOCBOR_SIZE_BYTE: u8 = 24u8; // Value contained in a byte
    pub const NANOCBOR_SIZE_SHORT: u8 = 25u8; // Value contained in a short
    pub const NANOCBOR_SIZE_WORD: u8 = 26u8; // Value contained in a word
    pub const NANOCBOR_SIZE_LONG: u8 = 27u8; // Value contained in a long
    pub const NANOCBOR_SIZE_INDEFINITE: u8 = 31u8; // Indefinite sized container
}

#[derive(Debug)]
pub enum DecodeError {
    Unknown,
    AtEnd,
    Overflow,
    ResultTooLarge,
    WrongType,
}

#[derive(Debug, PartialEq)]
#[repr(u8)]
pub enum CborType {
    Uint,
    Nint,
    Bstr,
    Tstr,
    Array,
    Map,
    Tag,
    Float,
}

/// main trait for Decoder to decode a requested type
pub trait CborDecodable<'a>: Sized {
    /// decode from cbor bytes. return is a tuple of (Self, bytes taken)
    fn from_cbor_bytes(cbor_bytes: &'a [u8]) -> Result<(Self, usize), DecodeError>;
}

pub struct Decoder<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    /// create a new decoder from a given byte slice
    pub fn new(bytes: &'a [u8]) -> Decoder<'a> {
        Decoder { bytes, pos: 0 }
    }

    /// Get a typed value from Decoder instance.
    /// The decoder will move past the read value (on success).
    ///
    /// Example:
    /// ```
    /// let mut decoder = Decoder::new(bytes);
    /// let value = decoder.get::<u32>().unwrap();
    /// ```
    pub fn get<T: CborDecodable<'a>>(&mut self) -> Result<T, DecodeError> {
        match T::from_cbor_bytes(&self.bytes[self.pos..]) {
            Ok((val, len)) => {
                self.pos += len;
                Ok(val)
            }
            Err(e) => Err(e),
        }
    }

    /// check if decoder has any values left
    pub fn at_end(&self) -> bool {
        self.pos >= self.bytes.len()
    }

    /// get type of next value in decoder
    pub fn get_type(&self) -> Result<CborType, DecodeError> {
        if self.at_end() {
            Err(DecodeError::AtEnd)
        } else {
            Ok(get_type(self.bytes[self.pos]))
        }
    }

    /// assert that next value is of certain type
    ///
    /// Example:
    /// ```
    /// let mut decoder = Decoder::new(bytes);
    /// decoder.assert_type(CborType::Uint)?; // passes on error if not an Uint
    /// let value = decoder.get::<u32>().unwrap(); // unwrap is safe now
    /// ```
    pub fn assert_type(&self, type_: CborType) -> Result<(), DecodeError> {
        if self.get_type()? == type_ {
            Ok(())
        } else {
            Err(DecodeError::WrongType)
        }
    }

    pub fn enter_container(&self) -> Result<Decoder, DecodeError> {
        todo!();
        // match self.get_type()? {
        //     CborType::Map => Ok(Decoder::new(&self.bytes[self.pos..])),
        //     _ => Err(DecodeError::WrongType),
        // }
    }
}

/// helper to decode the cbor type from byte
fn get_type(byte: u8) -> CborType {
    let val = (byte & constants::NANOCBOR_TYPE_MASK) >> constants::NANOCBOR_TYPE_OFFSET;
    // safety: CborType has repr(u8) and values 0..7. above masking & shifting
    // ensures that number range.
    unsafe { core::mem::transmute(val) }
}

/// helper to decode the length from a given byte
fn get_len(byte: u8) -> u8 {
    byte & constants::NANOCBOR_VALUE_MASK
}

/// helper to assert the next byte is of a certyin type
fn assert_type(bytes: &[u8], type_: CborType) -> Result<(), DecodeError> {
    if get_type(bytes[0]) != type_ {
        println!("{:?} {:?}", get_type(bytes[0]), type_);
        return Err(DecodeError::WrongType);
    }
    Ok(())
}

pub trait CborInteger: funty::IsInteger + From<u8> + TryFrom<u64> + TryFrom<i64> {}
impl CborInteger for i64 {}
impl CborInteger for i32 {}
impl CborInteger for i16 {}
//impl CborInteger for i8 {}
impl CborInteger for isize {}
impl CborInteger for u64 {}
impl CborInteger for u32 {}
impl CborInteger for u16 {}
impl CborInteger for u8 {}
impl CborInteger for usize {}

fn integer_from_cbor_bytes<T: CborInteger>(
    bytes: &[u8],
    type_: CborType,
) -> Result<(T, usize), DecodeError> {
    assert_type(bytes, type_)?;

    let len = get_len(bytes[0]);
    if len < constants::NANOCBOR_SIZE_BYTE {
        return Ok(((len & constants::NANOCBOR_VALUE_MASK).into(), 1));
    }

    let byte_len = 1 << (len - constants::NANOCBOR_SIZE_BYTE);
    let bytes = &bytes[1..];

    if bytes.len() < byte_len {
        return Err(DecodeError::Overflow);
    }

    if byte_len > core::mem::size_of::<T>() {
        return Err(DecodeError::ResultTooLarge);
    }

    match T::min_value() == 0.into() {
        false => match BigEndian::read_int(bytes, byte_len).try_into() {
            Ok(val) => Ok((val, byte_len + 1)),
            Err(_) => Err(DecodeError::Overflow),
        },
        true => match BigEndian::read_uint(bytes, byte_len).try_into() {
            Ok(val) => Ok((val, byte_len + 1)),
            Err(_) => Err(DecodeError::Overflow),
        },
    }
}

impl<'a, T> CborDecodable<'a> for T
where
    T: CborInteger,
{
    fn from_cbor_bytes(bytes: &[u8]) -> Result<(Self, usize), DecodeError> {
        let signed = T::MIN != 0.into();
        let type_ = match signed {
            true => CborType::Nint,
            false => CborType::Uint,
        };

        integer_from_cbor_bytes(bytes, type_)
    }
}

impl<'a> CborDecodable<'a> for &'a [u8] {
    fn from_cbor_bytes(bytes: &'a [u8]) -> Result<(Self, usize), DecodeError> {
        let type_ = get_type(bytes[0]);
        if !(type_ == CborType::Bstr || type_ == CborType::Tstr) {
            println!("type: {:?}", type_);
            return Err(DecodeError::WrongType);
        }

        let (size, skip): (usize, usize) = integer_from_cbor_bytes(bytes, type_)?;
        println!("size:{} skip:{}", size, skip);
        Ok((&bytes[skip..skip + size], skip + size))
    }
}

pub trait CborFloat: funty::IsFloat + From<u8> + TryFrom<f64> {}
impl CborFloat for f64 {}
impl<'a> CborDecodable<'a> for f64 {
    fn from_cbor_bytes(_bytes: &[u8]) -> Result<(Self, usize), DecodeError> {
        //float_from_cbor_bytes(bytes, type_)
        Ok((0f64, 0))
    }
}

#[cfg(test)]
mod tests {
    use crate::Decoder;

    #[test]
    fn test_uint_u32() {
        let test_values: [(&[u8], u32); 7] = [
            (&[0x00], 0),
            (&[0x01], 1),
            (&[0x0a], 10),
            (&[0x17], 23),
            (&[0x18, 0x18], 24),
            (&[0x18, 0x19], 25),
            (&[0x18, 0x64], 100),
        ];
        for (cbor, res) in test_values.iter() {
            println!("testing {:?}={}", cbor, res);
            let mut decoder = Decoder::new(&cbor[..]);
            let val = decoder.get::<u32>();
            assert_eq!(val.unwrap(), *res);
        }
    }

    #[test]
    fn test_bstr() {
        let test_values: [(&[u8], &[u8]); 1] = [(&[0x64, 0x49, 0x45, 0x54, 0x46], b"IETF")];

        for (cbor, res) in test_values.iter() {
            println!("testing {:x?}={:x?}", cbor, res);
            let mut decoder = Decoder::new(&cbor[..]);
            let val = decoder.get::<&[u8]>();
            assert_eq!(val.unwrap(), *res);
        }
    }

    use serde::Deserialize;
    use serde_json::value::Value;
    #[derive(Deserialize, Debug)]
    struct TestVector {
        cbor: String,
        hex: String,
        roundtrip: bool,
        decoded: Option<Value>,
    }

    #[test]
    fn test_appendix_a() {
        use crate::CborType;
        let test_vectors_json = include_str!("../appendix_a.json");
        let test_vectors: Vec<TestVector> = serde_json::from_str(&test_vectors_json).unwrap();
        for test_vector in test_vectors {
            let cbor = base64::decode(test_vector.cbor.clone()).unwrap();
            let mut decoder = Decoder::new(&cbor[..]);
            match decoder.get_type().unwrap() {
                CborType::Uint => {
                    println!("testing {:#?} -> CborType::Uint", &test_vector);
                    let decoded_int = decoder.get::<u64>().unwrap();
                    assert_eq!(
                        format!("{}", decoded_int),
                        test_vector.decoded.unwrap().to_string()
                    );
                }
                CborType::Nint => {
                    println!("testing {:#?} -> CborType::Nint", &test_vector);
                    let decoded_int = decoder.get::<i64>().unwrap();
                    assert_eq!(
                        format!("{}", decoded_int),
                        test_vector.decoded.unwrap().to_string()
                    );
                }
                _ => {
                    println!(
                        "skipped currently not understood type of {:#?}",
                        &test_vector
                    );
                    ()
                }
            }
        }
    }
}
