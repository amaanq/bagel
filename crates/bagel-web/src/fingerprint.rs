use std::fmt::{
   Display,
   Formatter,
   Result as FmtResult,
};

use thiserror::Error;

#[derive(Clone, Copy, Debug, Error)]
pub enum CaptureError {
   #[error("incomplete")]
   Incomplete,
   #[error("invalid")]
   Invalid,
   #[error("limited")]
   Limited,
   #[error("untrusted")]
   Untrusted,
}

#[derive(Clone, Debug, Default)]
pub enum Capture<Value> {
   #[default]
   Unavailable,
   Failed(CaptureError),
   Complete(Value),
}

impl<Value> From<Result<Value, CaptureError>> for Capture<Value> {
   fn from(result: Result<Value, CaptureError>) -> Self {
      match result {
         Ok(value) => Self::Complete(value),
         Err(error) => Self::Failed(error),
      }
   }
}

impl<Value> Display for Capture<Value> {
   #[expect(
      clippy::renamed_function_params,
      reason = "formatter keeps the argument name descriptive"
   )]
   fn fmt(&self, formatter: &mut Formatter<'_>) -> FmtResult {
      match self {
         Self::Unavailable => formatter.write_str("unavailable"),
         Self::Failed(error) => Display::fmt(error, formatter),
         Self::Complete(_) => formatter.write_str("complete"),
      }
   }
}
