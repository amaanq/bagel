use crate::fingerprint::CaptureError;

pub struct Cursor<'data> {
   remaining: &'data [u8],
}

impl<'data> From<&'data [u8]> for Cursor<'data> {
   fn from(remaining: &'data [u8]) -> Self {
      Self { remaining }
   }
}

impl<'data> Cursor<'data> {
   pub(crate) const fn is_empty(&self) -> bool {
      self.remaining.is_empty()
   }

   pub(crate) const fn remaining(&self) -> &'data [u8] {
      self.remaining
   }

   pub(crate) fn take(&mut self, length: usize) -> Result<&'data [u8], CaptureError> {
      let (value, tail) = self
         .remaining
         .split_at_checked(length)
         .ok_or(CaptureError::Invalid)?;
      self.remaining = tail;
      Ok(value)
   }

   pub(crate) fn array<const SIZE: usize>(&mut self) -> Result<[u8; SIZE], CaptureError> {
      Ok(*self
         .take(SIZE)?
         .first_chunk()
         .expect("take returns the requested size"))
   }

   pub(crate) fn byte(&mut self) -> Result<u8, CaptureError> {
      let [value] = self.array()?;
      Ok(value)
   }

   pub(crate) fn u16(&mut self) -> Result<u16, CaptureError> {
      self.array().map(u16::from_be_bytes)
   }

   pub(crate) fn u24(&mut self) -> Result<usize, CaptureError> {
      let [high, middle, low] = self.array()?;
      Ok((usize::from(high) << 16) | (usize::from(middle) << 8) | usize::from(low))
   }

   pub(crate) fn vector_u8(&mut self) -> Result<&'data [u8], CaptureError> {
      let length = usize::from(self.byte()?);
      self.take(length)
   }

   pub(crate) fn vector_u16(&mut self) -> Result<&'data [u8], CaptureError> {
      let length = usize::from(self.u16()?);
      self.take(length)
   }

   pub(crate) const fn finish(self) -> Result<(), CaptureError> {
      if self.is_empty() {
         Ok(())
      } else {
         Err(CaptureError::Invalid)
      }
   }
}
