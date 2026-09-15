use std::{
   array,
   error::Error,
   io,
};

use bagel_solver::{
   codec,
   scratch,
   sha256,
};
use vela::{
   config::{
      Config,
      FunctionSelector,
   },
   verify,
   worker::Verifier,
};

#[must_use]
pub fn config(seed: u64) -> Config {
   Config {
      seed,
      functions: vec![
         FunctionSelector::Name("unpack".to_owned()),
         FunctionSelector::Name("seal".to_owned()),
      ],
      include_callees: true,
      exclude_reachable: vec![FunctionSelector::Name("solve".to_owned())],
      flatten: true,
      flatten_ratio: 100u32.try_into().expect("flatten ratio 100 is valid"),
      markers_all: true,
      indirect_ratio: 100u32.try_into().expect("indirect ratio 100 is valid"),
      opaque: false,
      ..Config::default()
   }
}

pub fn rewrite(
   verifier: &Verifier,
   input: &[u8],
   config: &Config,
) -> Result<Vec<u8>, Box<dyn Error>> {
   let (output, _report) = vela::transform(input, config)?;
   validate(verifier, input, &output)?;
   Ok(output)
}

fn call(name: &str, arguments: Vec<verify::Value>) -> verify::Action {
   verify::Action::Call {
      name: name.to_owned(),
      arguments,
   }
}

pub fn validate(verifier: &Verifier, first: &[u8], second: &[u8]) -> Result<(), Box<dyn Error>> {
   let host = verify::HostConfig {
      limits: verify::Limits {
         fuel:           20_000_000_000,
         memory_bytes:   4 * 1024 * 1024,
         table_elements: 4096,
         read_bytes:     4096,
      },
      ..verify::HostConfig::default()
   };
   let probe = vec![call("buf", Vec::new())];
   let found = verifier.compare_scenario(first, first, &probe, host)?;
   let base = found
      .iter()
      .find_map(|entry| {
         match entry {
            verify::Comparison::Export {
               name,
               before: verify::CallOutcome::Returned(values),
               ..
            } if name == "buf" && entry.agrees() => {
               match values.as_slice() {
                  [verify::Value::I32(value)] => Some(value.cast_unsigned() as usize),
                  _ => None,
               }
            },
            _ => None,
         }
      })
      .ok_or_else(|| io::Error::other("solver buf export missing or trapped"))?;
   let mut actions = vec![call("buf", Vec::new())];
   let mut expected = vec![(
      "buf",
      verify::CallOutcome::Returned(vec![verify::Value::I32(base as i32)]),
   )];
   for length in [0, 38, 40, 65, -1] {
      actions.push(call("unpack", vec![verify::Value::I32(length)]));
      expected.push((
         "unpack",
         verify::CallOutcome::Returned(vec![verify::Value::I32(-1)]),
      ));
   }
   let mut sealed = Vec::new();
   for (case, kind, difficulty, blocks) in [
      (0u8, codec::Kind::Sha256, 8u8, 0u8),
      (1u8, codec::Kind::Sha256, 4u8, 0u8),
      (2u8, codec::Kind::Scratch, 1u8, 11u8),
   ] {
      let key: [u8; 32] =
         array::from_fn(|index| (index as u8).wrapping_mul(7).wrapping_add(13 + case));
      let handoff = codec::pack_handoff([5, 7, 11, case], &codec::Handoff {
         key,
         kind,
         difficulty,
         blocks_log2: blocks,
      });
      let mut block = sha256::KeyBlock::new(&key);
      let mut pad = vec![[0u8; 32]; 1 << blocks];
      let nonce = (0..100_000u64)
         .find(|nonce| {
            match kind {
               codec::Kind::Sha256 => block.satisfies(*nonce, u32::from(difficulty)),
               codec::Kind::Scratch => {
                  scratch::satisfies(&mut pad, &mut block, *nonce, blocks, u32::from(difficulty))
               },
            }
         })
         .ok_or_else(|| io::Error::other("solver native nonce search exhausted"))?;
      actions.push(verify::Action::WriteMemory {
         name:   "memory".to_owned(),
         offset: base,
         bytes:  handoff.to_vec(),
      });
      actions.push(call("unpack", vec![verify::Value::I32(
         codec::HANDOFF_LEN as i32,
      )]));
      expected.push((
         "unpack",
         verify::CallOutcome::Returned(vec![verify::Value::I32(i32::from(difficulty))]),
      ));
      for (start, count, found) in [
         (0, 0, -1),
         (0, nonce as i32 + 1, nonce as i64),
         (nonce as i64, 1, nonce as i64),
         (-1, 10, -1),
      ] {
         actions.push(call("solve", vec![
            verify::Value::I64(start),
            verify::Value::I32(count),
         ]));
         expected.push((
            "solve",
            verify::CallOutcome::Returned(vec![verify::Value::I64(found)]),
         ));
      }
      actions.push(call("seal", vec![
         verify::Value::I64(nonce as i64),
         verify::Value::I32(i32::from_le_bytes([7; 4])),
      ]));
      expected.push((
         "seal",
         verify::CallOutcome::Returned(vec![verify::Value::I32(codec::SOLUTION_LEN as i32)]),
      ));
      actions.push(verify::Action::ReadMemory {
         name:   "memory".to_owned(),
         offset: base,
         len:    codec::SOLUTION_LEN,
      });
      sealed.push(
         codec::pack_solution([7; 4], &codec::Solution {
            key,
            nonce,
            difficulty,
         })
         .to_vec(),
      );
   }
   let observations = verifier.compare_scenario(first, second, &actions, host)?;
   let mut calls = expected.iter();
   let mut bodies = sealed.iter();
   let mut memory_seen = false;
   for (at, entry) in observations.iter().enumerate() {
      let last = at + 1 == observations.len();
      match entry {
         verify::Comparison::Export {
            name,
            before: got_first,
            after: got_second,
         } => {
            let Some((want_name, want)) = calls.next() else {
               return Err(io::Error::other("solver scenario has extra exports").into());
            };
            if memory_seen || name != *want_name || got_first != want || got_second != want {
               return Err(
                  io::Error::other(format!(
                     "solver {name} differs from native proof, expected {want:?}, original \
                      {got_first:?}, rewritten {got_second:?}"
                  ))
                  .into(),
               );
            }
         },
         verify::Comparison::Bytes {
            name,
            offset,
            before: got_first,
            after: got_second,
         } => {
            let Some(want) = bodies.next() else {
               return Err(io::Error::other("solver scenario has extra memory reads").into());
            };
            if memory_seen
               || name != "memory"
               || *offset != base
               || got_first != want
               || got_second != want
            {
               return Err(
                  io::Error::other("solver sealed bytes differ from native codec output").into(),
               );
            }
         },
         verify::Comparison::Memory { .. } => {
            if memory_seen || !last || !entry.agrees() {
               return Err(io::Error::other("solver memory digest differs after rewrite").into());
            }
            memory_seen = true;
         },
         _ => {
            return Err(io::Error::other("solver comparison has an unsupported kind").into());
         },
      }
   }
   if !memory_seen || calls.next().is_some() || bodies.next().is_some() {
      return Err(io::Error::other("solver scenario missed native expectations").into());
   }
   Ok(())
}

#[cfg(test)]
mod tests {
   use std::{
      error::Error,
      io,
   };

   use vela::worker::{
      Limits,
      Verifier,
   };

   use crate::solver::{
      config,
      rewrite,
      validate,
   };

   #[test]
   fn solver_rewrites_match_native() -> Result<(), Box<dyn Error>> {
      let verifier = Verifier::new(env!("BAGEL_VERIFY_WORKER").as_ref(), Limits::default())?;
      let input = include_bytes!(concat!(env!("OUT_DIR"), "/solver.input.wasm"));
      let shipped = include_bytes!(concat!(env!("OUT_DIR"), "/solver.wasm"));
      if input.is_empty() || shipped.is_empty() {
         return Err(io::Error::other("solver fixtures are missing or empty").into());
      }
      validate(&verifier, input, shipped)?;
      for seed in [0, 1, 42, u64::MAX] {
         rewrite(&verifier, input, &config(seed))?;
         let mut aggressive = config(seed);
         aggressive.functions.clear();
         aggressive.include_callees = false;
         aggressive.exclude_reachable.clear();
         aggressive.markers_all = true;
         aggressive.opaque = true;
         aggressive.indirect_ratio = 100u32.try_into().map_err(io::Error::other)?;
         aggressive.opaque_ratio = 100u32.try_into().map_err(io::Error::other)?;
         rewrite(&verifier, input, &aggressive)?;
      }
      Ok(())
   }
}
