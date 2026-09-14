use std::{
   env,
   fs,
   path::PathBuf,
   process::Command,
};

/// The browser solver is a wasm build of `bagel-solver`, embedded into the
/// binary. `BAGEL_SOLVER_WASM` points at a prebuilt module.
fn main() {
   let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR is set by cargo"));
   let dest = out_dir.join("solver.wasm");
   println!("cargo:rerun-if-env-changed=BAGEL_SOLVER_WASM");

   if let Ok(prebuilt) = env::var("BAGEL_SOLVER_WASM") {
      println!("cargo:rerun-if-changed={prebuilt}");
      fs::copy(&prebuilt, &dest).expect("copy prebuilt solver module");
      return;
   }

   let crates = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is set"))
      .parent()
      .expect("bagel-web lives under crates/")
      .to_path_buf();
   let solver = crates.join("bagel-solver");
   println!("cargo:rerun-if-changed={}", solver.display());

   let target_dir = out_dir.join("solver-target");
   let status = Command::new(env::var("CARGO").expect("CARGO is set by cargo"))
      .args([
         "build",
         "--offline",
         "--profile",
         "solver",
         "--target",
         "wasm32v1-none",
      ])
      .arg("--manifest-path")
      .arg(solver.join("Cargo.toml"))
      .arg("--target-dir")
      .arg(&target_dir)
      .env_remove("RUSTFLAGS")
      .env_remove("CARGO_ENCODED_RUSTFLAGS")
      .env_remove("CARGO_BUILD_RUSTFLAGS")
      .env_remove("CARGO_BUILD_TARGET")
      .env_remove("CARGO_TARGET_DIR")
      .status()
      .expect("run cargo for the solver module");
   assert!(
      status.success(),
      "building bagel-solver for wasm32v1-none failed"
   );

   let built = target_dir
      .join("wasm32v1-none")
      .join("solver")
      .join("bagel_solver.wasm");
   let shrunk = Command::new("wasm-opt")
      .args(["-Oz", "--strip-debug", "--strip-producers"])
      .arg(&built)
      .arg("-o")
      .arg(&dest)
      .status();
   match shrunk {
      Ok(status) => assert!(status.success(), "wasm-opt failed on the solver module"),
      Err(err) => {
         assert!(
            err.kind() == std::io::ErrorKind::NotFound,
            "run wasm-opt: {err}"
         );
         fs::copy(&built, &dest).expect("copy built solver module");
      },
   }
}
