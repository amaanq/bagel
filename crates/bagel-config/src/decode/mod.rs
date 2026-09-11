use bagel_core::{
   Error,
   Result,
};
use knead::{
   ast::Node,
   decode::Decode,
};

pub mod defense;
mod wrappers;

pub use wrappers::{
   Argument,
   Arguments,
   Named,
   Tagged,
};

pub fn node<Decoded: Decode>(node: &Node) -> Result<Decoded> {
   Decoded::decode_node(node).map_err(|error| {
      Error::config_at(
         error.span().offset(),
         format!("invalid {} config, {error}", node.name.value),
      )
   })
}

#[cfg(test)] mod tests;
