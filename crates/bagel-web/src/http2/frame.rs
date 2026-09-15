use std::{
   fmt::{
      Display,
      Formatter,
      Result as FmtResult,
   },
   num::NonZeroU32,
};

use crate::{
   fingerprint::CaptureError,
   wire::Cursor,
};

pub enum Frame<'data> {
   Settings(Settings),
   SettingsAck,
   WindowUpdate {
      stream:    u32,
      increment: NonZeroU32,
   },
   Priority(Priority),
   Headers(HeaderFragment<'data>),
   Continuation(HeaderFragment<'data>),
   Other,
}

impl<'data> Frame<'data> {
   pub fn decode(data: &'data [u8]) -> Result<Option<(Self, usize)>, CaptureError> {
      if data.len() < 9 {
         return Ok(None);
      }
      let mut input = Cursor::from(data);
      let length = input.u24()?;
      if length > 16384 {
         return Err(CaptureError::Limited);
      }
      let kind = input.byte()?;
      let flags = input.byte()?;
      let stream = input.u32()? & 0x7FFF_FFFF;
      let Ok(payload) = input.take(length) else {
         return Ok(None);
      };
      let mut body = Cursor::from(payload);

      let frame = match kind {
         4 => {
            if stream != 0 {
               return Err(CaptureError::Invalid);
            }
            if flags & 1 == 0 {
               Self::Settings(Settings::try_from(payload)?)
            } else {
               body.finish()?;
               Self::SettingsAck
            }
         },
         8 => {
            let increment =
               NonZeroU32::new(body.u32()? & 0x7FFF_FFFF).ok_or(CaptureError::Invalid)?;
            body.finish()?;
            Self::WindowUpdate { stream, increment }
         },
         2 => {
            let priority = Priority::decode(stream, &mut body)?;
            body.finish()?;
            Self::Priority(priority)
         },
         1 | 9 => {
            let request_stream = NonZeroU32::new(stream)
               .filter(|value| !value.get().is_multiple_of(2))
               .ok_or(CaptureError::Invalid)?;
            if kind == 1 && flags & 8 != 0 {
               let padding = usize::from(body.byte()?);
               let length_without_padding = body
                  .remaining()
                  .len()
                  .checked_sub(padding)
                  .ok_or(CaptureError::Invalid)?;
               body = Cursor::from(body.take(length_without_padding)?);
            }
            if kind == 1 && flags & 0x20 != 0 {
               Priority::decode(stream, &mut body)?;
            }
            let fragment = HeaderFragment {
               stream:   request_stream,
               block:    body.remaining(),
               complete: flags & 4 != 0,
            };
            if kind == 1 {
               Self::Headers(fragment)
            } else {
               Self::Continuation(fragment)
            }
         },
         0 | 5 => return Err(CaptureError::Invalid),
         _ => Self::Other,
      };
      Ok(Some((frame, 9 + length)))
   }
}

pub struct HeaderFragment<'data> {
   stream:   NonZeroU32,
   block:    &'data [u8],
   complete: bool,
}

impl<'data> HeaderFragment<'data> {
   pub const fn stream(&self) -> NonZeroU32 {
      self.stream
   }
   pub const fn block(&self) -> &'data [u8] {
      self.block
   }
   pub const fn is_complete(&self) -> bool {
      self.complete
   }
}

#[derive(Clone, Debug)]
pub struct Settings(Vec<(u16, u32)>);

impl TryFrom<&[u8]> for Settings {
   type Error = CaptureError;

   fn try_from(payload: &[u8]) -> Result<Self, Self::Error> {
      let mut input = Cursor::from(payload);
      let mut entries = Vec::new();
      while !input.is_empty() {
         let identifier = input.u16()?;
         let value = input.u32()?;
         if matches!(identifier, 2 | 8 | 9) && value > 1
            || identifier == 4 && value > 0x7FFF_FFFF
            || identifier == 5 && !(16384..=0x00FF_FFFF).contains(&value)
         {
            return Err(CaptureError::Invalid);
         }
         entries.push((identifier, value));
      }
      Ok(Self(entries))
   }
}

impl Display for Settings {
   #[expect(
      clippy::renamed_function_params,
      reason = "formatter keeps the argument name descriptive"
   )]
   fn fmt(&self, formatter: &mut Formatter<'_>) -> FmtResult {
      for (index, (identifier, value)) in self.0.iter().enumerate() {
         if index != 0 {
            formatter.write_str(";")?;
         }
         write!(formatter, "{identifier}:{value}")?;
      }
      Ok(())
   }
}

#[derive(Clone, Debug)]
pub struct Priority {
   stream:    NonZeroU32,
   exclusive: bool,
   parent:    u32,
   weight:    u8,
}

impl Priority {
   fn decode(stream: u32, input: &mut Cursor<'_>) -> Result<Self, CaptureError> {
      let dependency = input.u32()?;
      let parent = dependency & 0x7FFF_FFFF;
      let stream_id = NonZeroU32::new(stream)
         .filter(|value| value.get() != parent)
         .ok_or(CaptureError::Invalid)?;
      Ok(Self {
         stream: stream_id,
         exclusive: dependency >> 31 != 0,
         parent,
         weight: input.byte()?,
      })
   }
}

impl Display for Priority {
   #[expect(
      clippy::renamed_function_params,
      reason = "formatter keeps the argument name descriptive"
   )]
   fn fmt(&self, formatter: &mut Formatter<'_>) -> FmtResult {
      write!(
         formatter,
         "{}:{}:{}:{}",
         self.stream,
         u8::from(self.exclusive),
         self.parent,
         u16::from(self.weight) + 1
      )
   }
}
