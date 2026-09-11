use knead::{
   decode::{
      Decode,
      Decoder,
   },
   errors::{
      Error,
      ErrorKind,
   },
};

use super::Tagged;
use crate::{
   Action,
   BanSchedule,
   Detector,
   Policy,
};

#[derive(knead_derive::Decode)]
pub struct PolicyInput {
   #[knead(property)]
   source:          String,
   #[knead(property, default = crate::default_max_attempts())]
   max_attempts:    u32,
   #[knead(property, default = crate::default_findtime_secs())]
   findtime_secs:   u64,
   #[knead(child, unwrap(arguments), default)]
   ignore_networks: Vec<String>,
   #[knead(child)]
   detector:        Tagged<DetectorInput>,
   #[knead(child, default)]
   ban:             BanSchedule,
   #[knead(child)]
   action:          Tagged<Action>,
}

impl From<PolicyInput> for Policy {
   fn from(input: PolicyInput) -> Self {
      Self {
         source:          input.source,
         detector:        input.detector.0.into(),
         ignore_networks: input.ignore_networks,
         max_attempts:    input.max_attempts,
         findtime_secs:   input.findtime_secs,
         ban:             input.ban,
         action:          input.action.0,
      }
   }
}

#[derive(knead_derive::Decode)]
enum DetectorInput {
   Regex {
      #[knead(property)]
      prefilter:           Option<String>,
      #[knead(children(name = "pattern"), unwrap(argument))]
      patterns:            Vec<String>,
      #[knead(children(name = "context-pattern"), unwrap(argument))]
      context_patterns:    Vec<String>,
      #[knead(property, default)]
      max_context_lines:   usize,
      #[knead(property, default = crate::default_context_window_secs())]
      context_window_secs: u64,
      #[knead(children(name = "ignore-pattern"), unwrap(argument))]
      ignore_patterns:     Vec<String>,
      #[knead(property, default = crate::default_address_capture())]
      address_capture:     String,
      #[knead(property)]
      timestamp_capture:   Option<String>,
      #[knead(property)]
      timestamp_format:    Option<String>,
   },
   Json {
      #[knead(children(name = "equals"))]
      equals:            Vec<Equality>,
      #[knead(property)]
      address_pointer:   String,
      #[knead(property)]
      timestamp_pointer: Option<String>,
      #[knead(property)]
      group_key_pointer: Option<String>,
      #[knead(property)]
      timestamp_format:  Option<String>,
   },
}

#[derive(knead_derive::Decode)]
struct Equality {
   #[knead(argument)]
   pointer: String,
   #[knead(argument)]
   literal: String,
}

impl From<DetectorInput> for Detector {
   fn from(input: DetectorInput) -> Self {
      match input {
         DetectorInput::Regex {
            prefilter,
            patterns,
            context_patterns,
            max_context_lines,
            context_window_secs,
            ignore_patterns,
            address_capture,
            timestamp_capture,
            timestamp_format,
         } => {
            Self::Regex {
               prefilter,
               patterns,
               context_patterns,
               max_context_lines,
               context_window_secs,
               ignore_patterns,
               address_capture,
               timestamp_capture,
               timestamp_format,
            }
         },
         DetectorInput::Json {
            equals,
            address_pointer,
            timestamp_pointer,
            group_key_pointer,
            timestamp_format,
         } => {
            Self::Json {
               equals: equals
                  .into_iter()
                  .map(|equal| (equal.pointer, equal.literal))
                  .collect(),
               address_pointer,
               timestamp_pointer,
               group_key_pointer,
               timestamp_format,
            }
         },
      }
   }
}

#[derive(knead_derive::Decode)]
struct BanInput {
   #[knead(property)]
   duration_secs:     Option<u64>,
   #[knead(property, default)]
   permanent:         bool,
   #[knead(property, default = BanSchedule::default().factor)]
   factor:            u64,
   #[knead(child, unwrap(arguments), default = BanSchedule::default().multipliers)]
   multipliers:       Vec<u64>,
   #[knead(property, default = BanSchedule::default().jitter_secs)]
   jitter_secs:       u64,
   #[knead(property, default = BanSchedule::default().max_duration_secs)]
   max_duration_secs: u64,
   #[knead(property, default = BanSchedule::default().overall)]
   overall:           bool,
}

impl Decode for BanSchedule {
   fn decode(decoder: &mut Decoder<'_>) -> Result<Self, Error> {
      let input = BanInput::decode(decoder)?;
      if input.permanent && input.duration_secs.is_some() {
         return Err(Error::new(
            ErrorKind::Unexpected,
            decoder.name().span,
            "duration-secs and permanent are exclusive",
         ));
      }
      Ok(Self {
         duration_secs:     if input.permanent {
            None
         } else {
            input
               .duration_secs
               .or_else(|| Self::default().duration_secs)
         },
         factor:            input.factor,
         multipliers:       input.multipliers,
         jitter_secs:       input.jitter_secs,
         max_duration_secs: input.max_duration_secs,
         overall:           input.overall,
      })
   }
}
