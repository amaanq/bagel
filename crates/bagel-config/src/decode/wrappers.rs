use knead::{
   decode::{
      Decode,
      DecodeScalar,
      Decoder,
   },
   errors::{
      Error,
      ErrorKind,
   },
   span::Spanned,
};

/// A node whose whole payload is one scalar argument.
pub struct Argument<Decoded>(pub Decoded);

impl<Decoded: DecodeScalar> Decode for Argument<Decoded> {
   fn decode(decoder: &mut Decoder<'_>) -> Result<Self, Error> {
      let value = decoder.argument().ok_or_else(|| {
         Error::new(
            ErrorKind::Missing,
            decoder.span(),
            "one argument is required",
         )
      })?;
      Decoded::decode(value).map(Self)
   }
}

/// A node whose whole payload is a list of scalar arguments.
pub struct Arguments<Decoded>(pub Vec<Decoded>);

impl<Decoded: DecodeScalar> Decode for Arguments<Decoded> {
   fn decode(decoder: &mut Decoder<'_>) -> Result<Self, Error> {
      let mut arguments = Vec::new();
      while let Some(value) = decoder.argument() {
         arguments.push(Decoded::decode(value)?);
      }
      Ok(Self(arguments))
   }
}

pub struct Named<Decoded> {
   pub name:  String,
   pub value: Decoded,
}

impl<Decoded: Decode> Decode for Named<Decoded> {
   fn decode(decoder: &mut Decoder<'_>) -> Result<Self, Error> {
      let argument = decoder.argument().ok_or_else(|| {
         Error::new(
            ErrorKind::Missing,
            decoder.span(),
            "name argument is required",
         )
      })?;
      let name = String::decode(argument)?;
      let value = Decoded::decode(decoder)?;
      Ok(Self { name, value })
   }
}

pub struct Tagged<Decoded>(pub Decoded);

impl<Decoded: Decode> Decode for Tagged<Decoded> {
   fn decode(decoder: &mut Decoder<'_>) -> Result<Self, Error> {
      let kind = decoder.property("kind").ok_or_else(|| {
         Error::new(
            ErrorKind::Missing,
            decoder.span(),
            "kind property is required",
         )
      })?;
      let name = String::decode(kind)?;
      let kind_span = kind.span;
      decoder.set_name(Spanned::new(name, kind_span));
      Decoded::decode(decoder).map(Self).map_err(|error| {
         if error.kind() == ErrorKind::Conversion && error.span() == kind_span {
            Error::new(
               ErrorKind::Conversion,
               kind_span,
               format!("unknown kind {:?}, {error}", decoder.name().value),
            )
         } else {
            error
         }
      })
   }
}
