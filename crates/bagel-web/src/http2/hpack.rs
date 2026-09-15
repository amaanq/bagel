use std::{
   borrow::Cow,
   collections::VecDeque,
   fmt::{
      Display,
      Formatter,
      Result as FmtResult,
   },
};

use httlib_huffman::DecoderSpeed;

use crate::{
   fingerprint::CaptureError,
   wire::Cursor,
};

const MAX_BLOCK: usize = 65536;
const MAX_DECODED: usize = 65536;
const MAX_HEADERS: usize = 256;
const MAX_TABLE: usize = 4096;
const ENTRY_OVERHEAD: usize = 32;

const STATIC_TABLE: [(&str, &str); 61] = [
   (":authority", ""),
   (":method", "GET"),
   (":method", "POST"),
   (":path", "/"),
   (":path", "/index.html"),
   (":scheme", "http"),
   (":scheme", "https"),
   (":status", "200"),
   (":status", "204"),
   (":status", "206"),
   (":status", "304"),
   (":status", "400"),
   (":status", "404"),
   (":status", "500"),
   ("accept-charset", ""),
   ("accept-encoding", "gzip, deflate"),
   ("accept-language", ""),
   ("accept-ranges", ""),
   ("accept", ""),
   ("access-control-allow-origin", ""),
   ("age", ""),
   ("allow", ""),
   ("authorization", ""),
   ("cache-control", ""),
   ("content-disposition", ""),
   ("content-encoding", ""),
   ("content-language", ""),
   ("content-length", ""),
   ("content-location", ""),
   ("content-range", ""),
   ("content-type", ""),
   ("cookie", ""),
   ("date", ""),
   ("etag", ""),
   ("expect", ""),
   ("expires", ""),
   ("from", ""),
   ("host", ""),
   ("if-match", ""),
   ("if-modified-since", ""),
   ("if-none-match", ""),
   ("if-range", ""),
   ("if-unmodified-since", ""),
   ("last-modified", ""),
   ("link", ""),
   ("location", ""),
   ("max-forwards", ""),
   ("proxy-authenticate", ""),
   ("proxy-authorization", ""),
   ("range", ""),
   ("referer", ""),
   ("refresh", ""),
   ("retry-after", ""),
   ("server", ""),
   ("set-cookie", ""),
   ("strict-transport-security", ""),
   ("transfer-encoding", ""),
   ("user-agent", ""),
   ("vary", ""),
   ("via", ""),
   ("www-authenticate", ""),
];

struct TableEntry {
   name: Vec<u8>,
   size: usize,
}

struct DynamicTable {
   entries:  VecDeque<TableEntry>,
   size:     usize,
   capacity: usize,
}

impl Default for DynamicTable {
   fn default() -> Self {
      Self {
         entries:  VecDeque::new(),
         size:     0,
         capacity: MAX_TABLE,
      }
   }
}

impl DynamicTable {
   fn get(&self, index: usize) -> Result<(&[u8], usize), CaptureError> {
      let offset = index.checked_sub(1).ok_or(CaptureError::Invalid)?;
      if let Some(&(name, value)) = STATIC_TABLE.get(offset) {
         return Ok((name.as_bytes(), name.len() + value.len() + ENTRY_OVERHEAD));
      }
      let entry = self
         .entries
         .get(offset - STATIC_TABLE.len())
         .ok_or(CaptureError::Invalid)?;
      Ok((&entry.name, entry.size))
   }

   fn resize(&mut self, capacity: usize) -> Result<(), CaptureError> {
      if capacity > MAX_TABLE {
         return Err(CaptureError::Invalid);
      }
      self.capacity = capacity;
      self.evict_to(capacity);
      Ok(())
   }

   fn insert(&mut self, entry: TableEntry) {
      let Some(available) = self.capacity.checked_sub(entry.size) else {
         self.evict_to(0);
         return;
      };
      self.evict_to(available);
      self.size += entry.size;
      self.entries.push_front(entry);
   }

   fn evict_to(&mut self, limit: usize) {
      while self.size > limit {
         let removed = self.entries.pop_back().expect("table size tracks entries");
         self.size -= removed.size;
      }
   }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PseudoHeader {
   Method,
   Authority,
   Scheme,
   Path,
   Protocol,
}

impl TryFrom<&[u8]> for PseudoHeader {
   type Error = CaptureError;

   fn try_from(name: &[u8]) -> Result<Self, Self::Error> {
      match name {
         b":method" => Ok(Self::Method),
         b":authority" => Ok(Self::Authority),
         b":scheme" => Ok(Self::Scheme),
         b":path" => Ok(Self::Path),
         b":protocol" => Ok(Self::Protocol),
         _ => Err(CaptureError::Invalid),
      }
   }
}

#[derive(Clone, Debug)]
pub struct PseudoHeaderOrder(Vec<PseudoHeader>);

impl TryFrom<&[u8]> for PseudoHeaderOrder {
   type Error = CaptureError;

   fn try_from(block: &[u8]) -> Result<Self, Self::Error> {
      if block.len() > MAX_BLOCK {
         return Err(CaptureError::Limited);
      }
      let mut decoder = Decoder {
         input: Cursor::from(block),
      };
      let mut table = DynamicTable::default();
      let mut decoded_total = 0;
      let mut header_count = 0;
      let mut order = Vec::new();
      let mut seen_regular = false;

      while let Some(&first) = decoder.input.remaining().first() {
         let representation = Representation::from(first);
         if matches!(representation, Representation::TableSize) {
            if header_count != 0 {
               return Err(CaptureError::Invalid);
            }
            table.resize(decoder.integer(IntegerPrefix::Five)?)?;
            continue;
         }
         header_count += 1;
         if header_count > MAX_HEADERS {
            return Err(CaptureError::Limited);
         }
         let index = decoder.integer(representation.prefix())?;
         let (name, size) = if matches!(representation, Representation::Indexed) {
            let (stored_name, stored_size) = table.get(index)?;
            (Cow::Borrowed(stored_name), stored_size)
         } else {
            let literal_name = if index == 0 {
               decoder.string()?
            } else {
               Cow::Borrowed(table.get(index)?.0)
            };
            let value = decoder.string()?;
            let entry_size = literal_name.len() + value.len() + ENTRY_OVERHEAD;
            (literal_name, entry_size)
         };
         decoded_total += size;
         if decoded_total > MAX_DECODED {
            return Err(CaptureError::Limited);
         }
         if name.is_empty() {
            return Err(CaptureError::Invalid);
         }
         if name.starts_with(b":") {
            let header = PseudoHeader::try_from(name.as_ref())?;
            if seen_regular || order.contains(&header) {
               return Err(CaptureError::Invalid);
            }
            order.push(header);
         } else {
            seen_regular = true;
         }
         if matches!(representation, Representation::LiteralIndexed) {
            let entry = TableEntry {
               name: name.into_owned(),
               size,
            };
            table.insert(entry);
         }
      }
      Ok(Self(order))
   }
}

impl Display for PseudoHeaderOrder {
   #[expect(
      clippy::renamed_function_params,
      reason = "formatter keeps the argument name descriptive"
   )]
   fn fmt(&self, formatter: &mut Formatter<'_>) -> FmtResult {
      for (index, header) in self.0.iter().enumerate() {
         if index != 0 {
            formatter.write_str(",")?;
         }
         formatter.write_str(match header {
            PseudoHeader::Method => "m",
            PseudoHeader::Authority => "a",
            PseudoHeader::Scheme => "s",
            PseudoHeader::Path => "p",
            PseudoHeader::Protocol => "r",
         })?;
      }
      Ok(())
   }
}

enum Representation {
   Indexed,
   LiteralIndexed,
   Literal,
   TableSize,
}

impl From<u8> for Representation {
   fn from(first: u8) -> Self {
      match first {
         0x80..=0xFF => Self::Indexed,
         0x40..=0x7F => Self::LiteralIndexed,
         0x20..=0x3F => Self::TableSize,
         0x00..=0x1F => Self::Literal,
      }
   }
}

impl Representation {
   const fn prefix(&self) -> IntegerPrefix {
      match self {
         Self::Indexed => IntegerPrefix::Seven,
         Self::LiteralIndexed => IntegerPrefix::Six,
         Self::Literal => IntegerPrefix::Four,
         Self::TableSize => IntegerPrefix::Five,
      }
   }
}

#[derive(Clone, Copy)]
enum IntegerPrefix {
   Four,
   Five,
   Six,
   Seven,
}

impl IntegerPrefix {
   const fn mask(self) -> usize {
      match self {
         Self::Four => 15,
         Self::Five => 31,
         Self::Six => 63,
         Self::Seven => 127,
      }
   }
}

struct Decoder<'data> {
   input: Cursor<'data>,
}

impl<'data> Decoder<'data> {
   fn integer(&mut self, prefix: IntegerPrefix) -> Result<usize, CaptureError> {
      let mask = prefix.mask();
      let mut value = usize::from(self.input.byte()?) & mask;
      if value < mask {
         return Ok(value);
      }
      let mut shift = 0;
      loop {
         let byte = self.input.byte()?;
         let factor = 1_usize.checked_shl(shift).ok_or(CaptureError::Invalid)?;
         let part = usize::from(byte & 0x7F)
            .checked_mul(factor)
            .ok_or(CaptureError::Invalid)?;
         value = value.checked_add(part).ok_or(CaptureError::Invalid)?;
         if byte & 0x80 == 0 {
            return Ok(value);
         }
         shift += 7;
      }
   }

   fn string(&mut self) -> Result<Cow<'data, [u8]>, CaptureError> {
      let huffman = self
         .input
         .remaining()
         .first()
         .ok_or(CaptureError::Invalid)?
         & 0x80
         != 0;
      let length = self.integer(IntegerPrefix::Seven)?;
      let raw = self.input.take(length)?;
      if !huffman {
         return Ok(Cow::Borrowed(raw));
      }
      let mut decoded = Vec::with_capacity(raw.len());
      httlib_huffman::decode(raw, &mut decoded, DecoderSpeed::FiveBits)
         .map_err(|_| CaptureError::Invalid)?;
      Ok(Cow::Owned(decoded))
   }
}
